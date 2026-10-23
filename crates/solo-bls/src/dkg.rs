//! Dealerless key generation and resharing (spec 12 §5–§6): a synchronous
//! Joint-Feldman DKG with complaints, written as a pure state machine over
//! broadcast messages so that a consensus driver can run it with the
//! messages carried in blocks.
//!
//! Every participant feeds its machine the same messages in the same
//! phases (its own included, when they come back) and calls [`Dkg::advance`]
//! at the same phase boundaries; every honest machine then reaches the same
//! [`Output::key_set`] and [`Output::qualified`]. Senders are authenticated
//! by the transport: a message names its sender and the caller vouches for it.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::fmt;

use bls12_381::{G1Affine, G2Affine, G2Projective, Scalar};
use solo_abi::{Decode, DecodeError, Decoder, Encode, Encoder};
use zeroize::Zeroize;

use crate::poly::{self, Polynomial};
use crate::sig::SecretKey;
use crate::threshold::{PublicKeySet, SecretShare};
use crate::{Error, hash, point};

/// Domain separation tag of a dealer's ephemeral encryption scalar.
pub const DST_EPHEMERAL: &[u8] = b"SOLO-V01-DKG-EPHEMERAL_XMD:SHA-256";

/// Domain separation tag of the one-time pads that encrypt shares.
pub const DST_PAD: &[u8] = b"SOLO-V01-DKG-PAD_XMD:SHA-256";

/// `KeyGen` key info of a participant's decryption key.
pub const KEY_INFO_ENCRYPTION: &[u8] = b"SOLO-DKG-ENCRYPTION";

/// A participant's secret key for receiving shares. Zeroed on drop.
pub struct DecryptionKey(Scalar);

impl fmt::Debug for DecryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DecryptionKey(..)")
    }
}

impl Drop for DecryptionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl DecryptionKey {
    /// `KeyGen(ikm, KEY_INFO_ENCRYPTION)` (spec 12 §3).
    ///
    /// # Errors
    /// [`Error::ShortKeyMaterial`] if `ikm` is shorter than 32 bytes.
    pub fn generate(ikm: &[u8]) -> Result<DecryptionKey, Error> {
        let key = SecretKey::generate(ikm, KEY_INFO_ENCRYPTION)?;
        Ok(DecryptionKey(key.0))
    }

    /// The public encryption key `dk · g1` that dealers encrypt to.
    #[must_use]
    pub fn encryption_key(&self) -> EncryptionKey {
        EncryptionKey((G1Affine::generator() * self.0).into())
    }
}

/// A participant's public key for receiving shares: a G1 point other than
/// the identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptionKey(G1Affine);

impl EncryptionKey {
    /// Decodes a compressed G1 point, rejecting the identity.
    ///
    /// # Errors
    /// [`Error::InvalidPoint`].
    pub fn from_bytes(bytes: &[u8; 48]) -> Result<EncryptionKey, Error> {
        match point::g1(bytes) {
            Some(p) if !bool::from(p.is_identity()) => Ok(EncryptionKey(p)),
            _ => Err(Error::InvalidPoint),
        }
    }

    /// The compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 48] {
        self.0.to_compressed()
    }
}

/// The public parameters of one run, identical at every participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Distinguishes this run from every other; it is mixed into every
    /// encryption pad and checked on every message. A driver derives it
    /// from the chain id and the epoch.
    pub session: [u8; 32],
    /// Threshold `t` of the key being produced.
    pub threshold: u32,
    /// Number of dealers, indexed `1..=dealers`.
    pub dealers: u32,
    /// Recipients' encryption keys: recipient `j` has index `j` and key
    /// `recipients[j − 1]`.
    pub recipients: Vec<EncryptionKey>,
    /// Shares per recipient (spec 12 §4): recipient `j` holds `shares[j − 1]`
    /// consecutive share indices, after those of the recipients before it.
    /// Empty means one share each, so that share `j` is recipient `j`'s.
    pub shares: Vec<u32>,
    /// Each dealer's weight (spec 12 §5): a fresh key needs qualified
    /// dealers whose weights sum to the threshold. Empty means one each;
    /// a resharing takes no weights.
    pub weights: Vec<u32>,
    /// For a resharing, the current key set: the dealers are its
    /// shareholders and the group key stays the same.
    pub previous: Option<PublicKeySet>,
}

/// This node's dealer role.
pub struct Dealer {
    /// Dealer index.
    pub index: u32,
    /// Fresh secret randomness for this run. Zeroed on drop.
    pub seed: [u8; 32],
    /// For a resharing, this dealer's current share (with the same index).
    pub share: Option<SecretShare>,
}

impl Drop for Dealer {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// This node's recipient role.
#[derive(Debug)]
pub struct Recipient {
    /// Recipient index; the recipient holds the share indices
    /// [`Config::shares`] assigns it.
    pub index: u32,
    /// The key matching `Config::recipients[index − 1]`.
    pub key: DecryptionKey,
}

/// Phases of a run, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Dealers broadcast their dealings.
    Dealing,
    /// Recipients broadcast complaints against dealers whose share to them
    /// fails the Feldman check.
    Complaining,
    /// Accused dealers broadcast the disputed shares in the clear.
    Justifying,
    /// The run is over.
    Finished,
}

/// Why a message was rejected or a run failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkgError {
    /// Parameters or roles that do not fit together.
    InvalidConfig,
    /// A message from another run.
    WrongSession,
    /// A message for a phase other than the current one, or `advance`
    /// after the run finished.
    WrongPhase,
    /// A sender index outside the dealer or recipient range.
    UnknownSender,
    /// A second message from the same sender in one phase.
    Duplicate,
    /// A dealing of the wrong shape or with a bad point or scalar.
    Malformed,
    /// A resharing dealing whose constant term is not the dealer's current
    /// public key share.
    ConstantTermMismatch,
    /// Fewer qualified dealers than the run requires.
    TooFewQualified,
}

/// A dealer's broadcast: its Feldman commitment and every share,
/// encrypted to the recipient that holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dealing {
    /// Run.
    pub session: [u8; 32],
    /// Dealer index.
    pub dealer: u32,
    /// `t` compressed G2 points `a_k · g2`.
    pub commitment: Vec<[u8; 96]>,
    /// The compressed G1 point `e · g1` for the dealer's ephemeral scalar `e`.
    pub ephemeral: [u8; 48],
    /// Share `x` plus its pad, as a big-endian scalar, at `x − 1`.
    pub shares: Vec<[u8; 32]>,
}

/// A recipient's broadcast naming the dealers whose shares failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Complaints {
    /// Run.
    pub session: [u8; 32],
    /// Recipient index.
    pub accuser: u32,
    /// Accused dealer indices.
    pub dealers: Vec<u32>,
}

/// A share revealed in answer to a complaint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevealedShare {
    /// The share index, one of the accuser's.
    pub index: u32,
    /// The share in the clear, as a big-endian scalar.
    pub share: [u8; 32],
}

/// An accused dealer's broadcast revealing the disputed shares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Justification {
    /// Run.
    pub session: [u8; 32],
    /// Dealer index.
    pub dealer: u32,
    /// Every share of every accuser, ascending by index.
    pub shares: Vec<RevealedShare>,
}

/// Every message of the protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Phase [`Phase::Dealing`].
    Dealing(Dealing),
    /// Phase [`Phase::Complaining`].
    Complaints(Complaints),
    /// Phase [`Phase::Justifying`].
    Justification(Justification),
}

/// What [`Dkg::advance`] asks of the caller.
#[derive(Debug)]
pub enum Step {
    /// Broadcast this message (and hand it back to this machine).
    Broadcast(Message),
    /// Nothing to send in the new phase.
    Idle,
    /// The run is over.
    Finished(Output),
}

/// The result of a run.
#[derive(Debug)]
pub struct Output {
    /// The new key set; for a resharing its group key is the previous one.
    pub key_set: PublicKeySet,
    /// This node's shares, ascending by index, if it is a recipient and holds
    /// a verified share from every qualified dealer for each of them; empty
    /// otherwise.
    pub shares: Vec<SecretShare>,
    /// The qualified dealers, ascending. Every other dealer was absent or
    /// disqualified.
    pub qualified: Vec<u32>,
}

/// A dealing that passed the structural checks.
struct Received {
    commitment: Vec<G2Affine>,
    ephemeral: G1Affine,
    shares: Vec<Scalar>,
}

/// One participant's run.
pub struct Dkg {
    config: Config,
    /// Share count of each recipient, one each when the config gives none.
    shares: Vec<u32>,
    /// Weight of each dealer, one each when the config gives none.
    weights: Vec<u32>,
    dealer: Option<(u32, Polynomial)>,
    recipient: Option<Recipient>,
    phase: Phase,
    dealings: BTreeMap<u32, Received>,
    /// This recipient's verified shares from each dealer, ascending by index.
    mine: BTreeMap<u32, Vec<Scalar>>,
    /// Accusers per accused dealer.
    complaints: BTreeMap<u32, BTreeSet<u32>>,
    accusers: BTreeSet<u32>,
    justified: BTreeSet<u32>,
    /// Valid revealed shares by `(dealer, share index)`.
    revealed: BTreeMap<(u32, u32), Scalar>,
}

/// The share indices recipient `j` holds: `first..first + count`.
fn range_of(shares: &[u32], j: u32) -> core::ops::Range<u32> {
    let first = 1 + shares[..j as usize - 1].iter().sum::<u32>();
    first..first + shares[j as usize - 1]
}

/// The recipient holding share index `x`, or `None` for zero or past the
/// last share.
fn owner_of(shares: &[u32], x: u32) -> Option<u32> {
    let mut end = 0u32;
    for (j, &m) in (1u32..).zip(shares) {
        end += m;
        if x != 0 && x <= end {
            return Some(j);
        }
    }
    None
}

impl Dkg {
    /// Starts a run in [`Phase::Dealing`]; returns this node's dealing when
    /// it is a dealer.
    ///
    /// # Errors
    /// [`DkgError::InvalidConfig`] unless the share counts, if given, are
    /// one per recipient and each at least 1, with fewer than `2^32` shares
    /// in all, `1 ≤ threshold ≤` that number of shares, the weights, if
    /// given, are one per dealer, each at least 1, and not for a resharing,
    /// the dealers number at least one (for a resharing, at least the
    /// previous threshold), the roles' indices are in range, and a dealer
    /// carries a current share with its own index exactly when resharing.
    pub fn new(
        config: Config,
        dealer: Option<Dealer>,
        recipient: Option<Recipient>,
    ) -> Result<(Dkg, Option<Message>), DkgError> {
        let n = u32::try_from(config.recipients.len()).ok();
        let resharing = config.previous.is_some();
        let min_dealers = config.previous.as_ref().map_or(1, PublicKeySet::threshold);
        let shares = if config.shares.is_empty() {
            alloc::vec![1; config.recipients.len()]
        } else {
            config.shares.clone()
        };
        let weights = if config.weights.is_empty() {
            alloc::vec![1; config.dealers as usize]
        } else {
            config.weights.clone()
        };
        let total = shares.iter().try_fold(
            0u32,
            |sum, &m| if m == 0 { None } else { sum.checked_add(m) },
        );
        let counts_ok = shares.len() == config.recipients.len()
            && weights.len() == config.dealers as usize
            && weights.iter().all(|&w| w >= 1)
            && (!resharing || config.weights.is_empty());
        let config_ok = n.is_some()
            && counts_ok
            && total.is_some_and(|m| config.threshold >= 1 && config.threshold <= m)
            && config.dealers >= min_dealers;
        let dealer_ok = dealer.as_ref().is_none_or(|d| {
            d.index >= 1
                && d.index <= config.dealers
                && d.share.as_ref().map(SecretShare::index) == resharing.then_some(d.index)
        });
        let recipient_ok = recipient
            .as_ref()
            .is_none_or(|r| r.index >= 1 && Some(r.index) <= n);
        if !(config_ok && dealer_ok && recipient_ok) {
            return Err(DkgError::InvalidConfig);
        }
        let (dealer, message) = match dealer {
            Some(d) => {
                let context = [config.session.as_slice(), &d.index.to_be_bytes()].concat();
                let constant = d.share.as_ref().map(|s| s.secret);
                let f = Polynomial::derive(&d.seed, &context, config.threshold, constant);
                let ephemeral = hash::to_scalar(&[&d.seed, &context], DST_EPHEMERAL);
                let dealing = make_dealing(&config, &shares, d.index, &f, ephemeral);
                (Some((d.index, f)), Some(Message::Dealing(dealing)))
            }
            None => (None, None),
        };
        let dkg = Dkg {
            config,
            shares,
            weights,
            dealer,
            recipient,
            phase: Phase::Dealing,
            dealings: BTreeMap::new(),
            mine: BTreeMap::new(),
            complaints: BTreeMap::new(),
            accusers: BTreeSet::new(),
            justified: BTreeSet::new(),
            revealed: BTreeMap::new(),
        };
        Ok((dkg, message))
    }

    /// The current phase.
    #[must_use]
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Takes one message of the current phase.
    ///
    /// # Errors
    /// Why the message was ignored; see [`DkgError`]. A rejected dealing
    /// leaves its dealer absent, which excludes it.
    pub fn handle(&mut self, message: &Message) -> Result<(), DkgError> {
        match message {
            Message::Dealing(d) => self.on_dealing(d),
            Message::Complaints(c) => self.on_complaints(c),
            Message::Justification(j) => self.on_justification(j),
        }
    }

    /// Ends the current phase and moves to the next. Ending
    /// [`Phase::Dealing`] decrypts and checks this recipient's shares and may
    /// produce complaints; ending [`Phase::Complaining`] may produce this
    /// dealer's justification; ending [`Phase::Justifying`] disqualifies
    /// every dealer with an unanswered complaint and finishes.
    ///
    /// # Errors
    /// [`DkgError::TooFewQualified`] when fewer dealers qualify than the
    /// threshold (for a resharing, the previous threshold), and
    /// [`DkgError::WrongPhase`] after the run finished.
    pub fn advance(&mut self) -> Result<Step, DkgError> {
        match self.phase {
            Phase::Dealing => {
                self.phase = Phase::Complaining;
                Ok(self.complain())
            }
            Phase::Complaining => {
                self.phase = Phase::Justifying;
                Ok(self.justify())
            }
            Phase::Justifying => {
                self.phase = Phase::Finished;
                self.finish().map(Step::Finished)
            }
            Phase::Finished => Err(DkgError::WrongPhase),
        }
    }

    fn check(&self, phase: Phase, session: &[u8; 32]) -> Result<(), DkgError> {
        if self.phase != phase {
            return Err(DkgError::WrongPhase);
        }
        if *session != self.config.session {
            return Err(DkgError::WrongSession);
        }
        Ok(())
    }

    fn known_dealer(&self, dealer: u32) -> Result<(), DkgError> {
        if dealer == 0 || dealer > self.config.dealers {
            return Err(DkgError::UnknownSender);
        }
        Ok(())
    }

    fn on_dealing(&mut self, d: &Dealing) -> Result<(), DkgError> {
        self.check(Phase::Dealing, &d.session)?;
        self.known_dealer(d.dealer)?;
        if self.dealings.contains_key(&d.dealer) {
            return Err(DkgError::Duplicate);
        }
        let total: u32 = self.shares.iter().sum();
        let shape_ok = d.commitment.len() == self.config.threshold as usize
            && d.shares.len() == total as usize;
        let commitment: Option<Vec<G2Affine>> = d.commitment.iter().map(point::g2).collect();
        let shares: Option<Vec<Scalar>> = d.shares.iter().map(point::scalar).collect();
        let (true, Some(commitment), Some(ephemeral), Some(shares)) =
            (shape_ok, commitment, point::g1(&d.ephemeral), shares)
        else {
            return Err(DkgError::Malformed);
        };
        if let Some(previous) = &self.config.previous {
            let expected = poly::evaluate_commitment(&previous.commitment, d.dealer);
            if G2Projective::from(commitment[0]) != expected {
                return Err(DkgError::ConstantTermMismatch);
            }
        }
        let received = Received {
            commitment,
            ephemeral,
            shares,
        };
        self.dealings.insert(d.dealer, received);
        Ok(())
    }

    fn complain(&mut self) -> Step {
        let Some(recipient) = &self.recipient else {
            return Step::Idle;
        };
        let me = recipient.index;
        let mine = range_of(&self.shares, me);
        let mut accused = Vec::new();
        for (&dealer, received) in &self.dealings {
            let shared: G1Affine = (received.ephemeral * recipient.key.0).into();
            let mut verified = Vec::new();
            for x in mine.clone() {
                let pad = pad(
                    &self.config.session,
                    dealer,
                    x,
                    &received.ephemeral,
                    &shared,
                );
                let share = received.shares[x as usize - 1] - pad;
                if !poly::share_matches(&received.commitment, x, &share) {
                    break;
                }
                verified.push(share);
            }
            if verified.len() == mine.len() {
                self.mine.insert(dealer, verified);
            } else {
                accused.push(dealer);
            }
        }
        if accused.is_empty() {
            return Step::Idle;
        }
        Step::Broadcast(Message::Complaints(Complaints {
            session: self.config.session,
            accuser: me,
            dealers: accused,
        }))
    }

    fn on_complaints(&mut self, c: &Complaints) -> Result<(), DkgError> {
        self.check(Phase::Complaining, &c.session)?;
        if c.accuser == 0 || c.accuser as usize > self.config.recipients.len() {
            return Err(DkgError::UnknownSender);
        }
        if !self.accusers.insert(c.accuser) {
            return Err(DkgError::Duplicate);
        }
        for dealer in &c.dealers {
            if self.dealings.contains_key(dealer) {
                self.complaints
                    .entry(*dealer)
                    .or_default()
                    .insert(c.accuser);
            }
        }
        Ok(())
    }

    fn justify(&self) -> Step {
        let Some((index, f)) = &self.dealer else {
            return Step::Idle;
        };
        let Some(accusers) = self.complaints.get(index) else {
            return Step::Idle;
        };
        let shares = accusers
            .iter()
            .flat_map(|&accuser| range_of(&self.shares, accuser))
            .map(|index| RevealedShare {
                index,
                share: point::scalar_bytes(&f.evaluate(index)),
            })
            .collect();
        Step::Broadcast(Message::Justification(Justification {
            session: self.config.session,
            dealer: *index,
            shares,
        }))
    }

    fn on_justification(&mut self, j: &Justification) -> Result<(), DkgError> {
        self.check(Phase::Justifying, &j.session)?;
        self.known_dealer(j.dealer)?;
        if !self.justified.insert(j.dealer) {
            return Err(DkgError::Duplicate);
        }
        let (Some(received), Some(accusers)) =
            (self.dealings.get(&j.dealer), self.complaints.get(&j.dealer))
        else {
            return Ok(());
        };
        for revealed in &j.shares {
            let share = point::scalar(&revealed.share);
            let accused =
                owner_of(&self.shares, revealed.index).is_some_and(|o| accusers.contains(&o));
            if let (true, Some(share)) = (accused, share)
                && poly::share_matches(&received.commitment, revealed.index, &share)
            {
                self.revealed.insert((j.dealer, revealed.index), share);
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<Output, DkgError> {
        let me = self.recipient.as_ref().map(|r| r.index);
        for (dealer, accusers) in &self.complaints {
            let answered = accusers.iter().all(|&a| {
                range_of(&self.shares, a).all(|x| self.revealed.contains_key(&(*dealer, x)))
            });
            if answered {
                if let Some(me) = me.filter(|m| accusers.contains(m)) {
                    let revealed = range_of(&self.shares, me)
                        .map(|x| self.revealed[&(*dealer, x)])
                        .collect();
                    self.mine.insert(*dealer, revealed);
                }
            } else {
                self.dealings.remove(dealer);
            }
        }
        let qualified: Vec<u32> = self.dealings.keys().copied().collect();
        let required = self
            .config
            .previous
            .as_ref()
            .map_or(self.config.threshold, PublicKeySet::threshold);
        let weight: u64 = qualified
            .iter()
            .map(|&i| u64::from(self.weights[i as usize - 1]))
            .sum();
        if weight < u64::from(required) {
            return Err(DkgError::TooFewQualified);
        }
        // A fresh key sums the qualified dealings; a resharing interpolates
        // them at zero, which keeps the constant term, the group secret.
        let weights = self.config.previous.as_ref().map(|_| {
            poly::lagrange_at_zero(&qualified).expect("dealer indices are distinct and nonzero")
        });
        let mut sum = alloc::vec![G2Projective::identity(); self.config.threshold as usize];
        for (k, received) in self.dealings.values().enumerate() {
            for (acc, c) in sum.iter_mut().zip(&received.commitment) {
                *acc += match &weights {
                    None => G2Projective::from(c),
                    Some(w) => c * w[k],
                };
            }
        }
        let shares = me
            .and_then(|me| self.my_shares(me, weights.as_deref()))
            .unwrap_or_default();
        Ok(Output {
            key_set: PublicKeySet {
                commitment: poly::normalize(&sum),
            },
            shares,
            qualified,
        })
    }

    /// This recipient's new shares, or `None` if a qualified dealer's shares
    /// to it never verified (its complaint was lost).
    fn my_shares(&self, me: u32, weights: Option<&[Scalar]>) -> Option<Vec<SecretShare>> {
        let range = range_of(&self.shares, me);
        let mut secrets = alloc::vec![Scalar::zero(); range.len()];
        for (k, dealer) in self.dealings.keys().enumerate() {
            let shares = self.mine.get(dealer)?;
            for (secret, s) in secrets.iter_mut().zip(shares) {
                *secret += match weights {
                    None => *s,
                    Some(w) => s * w[k],
                };
            }
        }
        Some(
            range
                .zip(secrets)
                .map(|(index, secret)| SecretShare { index, secret })
                .collect(),
        )
    }
}

/// Builds a dealing: commitment, ephemeral point, and every share
/// encrypted to the recipient holding it.
fn make_dealing(
    config: &Config,
    counts: &[u32],
    index: u32,
    f: &Polynomial,
    ephemeral: Scalar,
) -> Dealing {
    let r: G1Affine = (G1Affine::generator() * ephemeral).into();
    let mut encrypted = Vec::new();
    let mut x = 0u32;
    for (key, &m) in config.recipients.iter().zip(counts) {
        let dh: G1Affine = (key.0 * ephemeral).into();
        for _ in 0..m {
            x += 1;
            let pad = pad(&config.session, index, x, &r, &dh);
            encrypted.push(point::scalar_bytes(&(f.evaluate(x) + pad)));
        }
    }
    Dealing {
        session: config.session,
        dealer: index,
        commitment: f.commit().iter().map(G2Affine::to_compressed).collect(),
        ephemeral: r.to_compressed(),
        shares: encrypted,
    }
}

/// The pad that encrypts dealer `dealer`'s share `index` to the recipient
/// holding it: a hash of the run, the dealer and share indices, the
/// ephemeral point and the shared point `e · ek = dk · R`.
fn pad(
    session: &[u8; 32],
    dealer: u32,
    index: u32,
    ephemeral: &G1Affine,
    shared: &G1Affine,
) -> Scalar {
    hash::to_scalar(
        &[
            session,
            &dealer.to_be_bytes(),
            &index.to_be_bytes(),
            &ephemeral.to_compressed(),
            &shared.to_compressed(),
        ],
        DST_PAD,
    )
}

fn put_all<T: Encode>(e: &mut Encoder, items: &[T]) {
    e.write_len(items.len());
    for item in items {
        e.put(item);
    }
}

fn get_all<T: Decode>(d: &mut Decoder<'_>) -> Result<Vec<T>, DecodeError> {
    let n = d.read_len()?;
    let mut items = Vec::new();
    for _ in 0..n {
        items.push(d.get()?);
    }
    Ok(items)
}

impl Encode for RevealedShare {
    fn encode(&self, e: &mut Encoder) {
        e.put(&self.index).put(&self.share);
    }
}

impl Decode for RevealedShare {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(RevealedShare {
            index: d.get()?,
            share: d.get()?,
        })
    }
}

impl Encode for Message {
    fn encode(&self, e: &mut Encoder) {
        match self {
            Message::Dealing(d) => {
                e.put(&0u8).put(&d.session).put(&d.dealer);
                put_all(e, &d.commitment);
                e.put(&d.ephemeral);
                put_all(e, &d.shares);
            }
            Message::Complaints(c) => {
                e.put(&1u8).put(&c.session).put(&c.accuser);
                put_all(e, &c.dealers);
            }
            Message::Justification(j) => {
                e.put(&2u8).put(&j.session).put(&j.dealer);
                put_all(e, &j.shares);
            }
        }
    }
}

impl Decode for Message {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        match d.get::<u8>()? {
            0 => Ok(Message::Dealing(Dealing {
                session: d.get()?,
                dealer: d.get()?,
                commitment: get_all(d)?,
                ephemeral: d.get()?,
                shares: get_all(d)?,
            })),
            1 => Ok(Message::Complaints(Complaints {
                session: d.get()?,
                accuser: d.get()?,
                dealers: get_all(d)?,
            })),
            2 => Ok(Message::Justification(Justification {
                session: d.get()?,
                dealer: d.get()?,
                shares: get_all(d)?,
            })),
            tag => Err(DecodeError::BadTag(tag)),
        }
    }
}
