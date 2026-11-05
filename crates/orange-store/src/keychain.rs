//! Following the chain's threshold key through its handoffs (spec 22 §7.5).
//!
//! A chain with a threshold key makes a fresh key set every epoch, and the
//! active one hands off to it by signing the rotation message to its id and
//! group key (spec 15 §6.6). A node that trusts one key set, by id and group
//! key, reaches every later one through those handoffs, each verified under
//! the key it replaces, as a light client does (spec 17 §5.3). Its trust
//! reaches no further than the trusted key set's *horizon*, the last epoch
//! through which its shareholders are still slashable when that epoch's
//! snapshot is served.

use std::collections::BTreeMap;

use orange_abi::rotation::Handoff;
use orange_bls::certificate::rotation_message;
use orange_bls::{PublicKey, Signature};

/// Most handoffs one answer holds (spec 22 §7.5): about 45 KB.
pub const MAX_HANDOFFS: usize = 256;

/// Most handoffs a node verifies in one sync, whatever the chain's
/// unbonding period allows.
pub const MAX_CHAIN: usize = 4_096;

/// Why a handoff chain was refused: its first handoff goes out of another
/// key set than the highest one reached.
pub const NOT_FROM_REACHED: &str = "a handoff chain that does not start at the key set reached";
/// A handoff to a key set whose id is not above the one it leaves.
pub const NOT_INCREASING: &str = "a handoff chain whose ids do not increase";
/// A handoff whose key does not decode as a group key.
pub const NOT_A_KEY: &str = "a handoff whose key is not a group key";
/// A handoff whose signature does not verify under the key it replaces.
pub const BAD_SIGNATURE: &str = "a handoff whose signature does not verify";
/// A trusted key that is not a group key, so that no handoff verifies under it.
pub const NOT_TRUSTED_KEY: &str = "the trusted key is not a group key";
/// More handoffs than [`MAX_CHAIN`].
pub const TOO_LONG: &str = "a handoff chain longer than MAX_CHAIN";

/// A trusted key set and the key sets reached from it by verified handoffs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyChain {
    id: u64,
    key: [u8; 96],
    unbonding_epochs: u64,
    /// The key sets reached above the trusted one, with their group keys.
    reached: BTreeMap<u64, [u8; 96]>,
    /// The handoffs that reached them, in chain order.
    handoffs: Vec<Handoff>,
}

impl KeyChain {
    /// Trusts key set `id` with group key `key`, on a chain whose stake
    /// unbonds over `unbonding_epochs` epochs (spec 15 §2).
    #[must_use]
    pub fn new(id: u64, key: [u8; 96], unbonding_epochs: u64) -> KeyChain {
        KeyChain {
            id,
            key,
            unbonding_epochs,
            reached: BTreeMap::new(),
            handoffs: Vec::new(),
        }
    }

    /// The trusted key set's id.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The last epoch whose snapshot the trust reaches:
    /// `id + unbonding_epochs − 1`.
    #[must_use]
    pub fn horizon(&self) -> u64 {
        self.id
            .saturating_add(self.unbonding_epochs)
            .saturating_sub(1)
    }

    /// The highest key set reached.
    #[must_use]
    pub fn tip(&self) -> u64 {
        self.reached.keys().next_back().copied().unwrap_or(self.id)
    }

    /// The group key of key set `id`, if it is reached.
    #[must_use]
    pub fn key(&self, id: u64) -> Option<&[u8; 96]> {
        if id == self.id {
            return Some(&self.key);
        }
        self.reached.get(&id)
    }

    /// The handoffs verified so far, in chain order.
    #[must_use]
    pub fn handoffs(&self) -> &[Handoff] {
        &self.handoffs
    }

    /// Follows `handoffs` from the highest key set reached, verifying each
    /// over chain `chain_id`'s rotation message under the key it replaces
    /// (spec 22 §7.5): all of them are taken, or none.
    ///
    /// # Errors
    /// The check the first failing handoff fails.
    pub fn extend(&mut self, chain_id: u64, handoffs: &[Handoff]) -> Result<(), &'static str> {
        if self.handoffs.len() + handoffs.len() > MAX_CHAIN {
            return Err(TOO_LONG);
        }
        let (mut at, mut key) = self
            .reached
            .iter()
            .next_back()
            .map_or((self.id, self.key), |(id, key)| (*id, *key));
        let mut reached = Vec::new();
        for h in handoffs {
            if h.from != at {
                return Err(NOT_FROM_REACHED);
            }
            if h.to <= h.from {
                return Err(NOT_INCREASING);
            }
            let next: [u8; 96] = h.key.as_slice().try_into().map_err(|_| NOT_A_KEY)?;
            let next_key = PublicKey::from_bytes(&next).map_err(|_| NOT_A_KEY)?;
            let signature = <&[u8; 48]>::try_from(h.signature.as_slice())
                .ok()
                .and_then(|s| Signature::from_bytes(s).ok())
                .ok_or(BAD_SIGNATURE)?;
            let current = PublicKey::from_bytes(&key).map_err(|_| NOT_TRUSTED_KEY)?;
            if !current.verify(&rotation_message(chain_id, h.to, &next_key), &signature) {
                return Err(BAD_SIGNATURE);
            }
            reached.push((h.to, next));
            (at, key) = (h.to, next);
        }
        self.reached.extend(reached);
        self.handoffs.extend_from_slice(handoffs);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orange_bls::SecretKey;

    const CHAIN: u64 = 5;

    fn secret(i: u64) -> SecretKey {
        let mut ikm = [3u8; 32];
        ikm[..8].copy_from_slice(&i.to_be_bytes());
        SecretKey::generate(&ikm, b"").unwrap()
    }

    /// The handoff key set `from` signs to key set `to`.
    fn handoff(from: u64, to: u64) -> Handoff {
        let next = secret(to).public_key();
        Handoff {
            from,
            to,
            key: next.to_bytes().to_vec(),
            signature: secret(from)
                .sign(&rotation_message(CHAIN, to, &next))
                .to_bytes()
                .to_vec(),
            height: 9,
        }
    }

    fn trusting(id: u64) -> KeyChain {
        KeyChain::new(id, secret(id).public_key().to_bytes(), 4)
    }

    #[test]
    fn handoffs_reach_later_key_sets_within_the_horizon() {
        let mut chain = trusting(2);
        assert_eq!((chain.id(), chain.tip(), chain.horizon()), (2, 2, 5));
        assert_eq!(KeyChain::new(u64::MAX, [0; 96], 4).horizon(), u64::MAX - 1);
        chain
            .extend(CHAIN, &[handoff(2, 3), handoff(3, 5)])
            .unwrap();
        chain.extend(CHAIN, &[]).unwrap();
        assert_eq!(chain.tip(), 5);
        assert_eq!(chain.key(5), Some(&secret(5).public_key().to_bytes()));
        assert_eq!(chain.key(2), Some(&secret(2).public_key().to_bytes()));
        assert_eq!(chain.key(4), None);
        assert_eq!(chain.handoffs(), &[handoff(2, 3), handoff(3, 5)]);
        // A chain continues from the tip.
        chain.extend(CHAIN, &[handoff(5, 6)]).unwrap();
        assert_eq!(chain.tip(), 6);
    }

    #[test]
    fn a_bad_handoff_refuses_the_whole_answer_naming_the_check() {
        let refused = |handoffs: &[Handoff]| {
            let mut chain = trusting(2);
            let why = chain.extend(CHAIN, handoffs).unwrap_err();
            // Nothing of it was taken, not even the handoffs before.
            assert_eq!((chain.tip(), chain.handoffs().len()), (2, 0));
            why
        };
        assert_eq!(refused(&[handoff(1, 3)]), NOT_FROM_REACHED);
        assert_eq!(refused(&[handoff(2, 3), handoff(2, 4)]), NOT_FROM_REACHED);
        assert_eq!(refused(&[handoff(2, 2)]), NOT_INCREASING);
        let mut short = handoff(2, 3);
        short.key.pop();
        assert_eq!(refused(&[short]), NOT_A_KEY);
        let mut off_curve = handoff(2, 3);
        off_curve.key = vec![0xFF; 96];
        assert_eq!(refused(&[off_curve]), NOT_A_KEY);
        let mut short = handoff(2, 3);
        short.signature.pop();
        assert_eq!(refused(&[short]), BAD_SIGNATURE);
        let mut off_curve = handoff(2, 3);
        off_curve.signature = vec![0xFF; 48];
        assert_eq!(refused(&[off_curve]), BAD_SIGNATURE);
        // Signed by another key than the one it replaces, for another chain,
        // or for another key set than it names.
        let signed_by_another = Handoff {
            from: 4,
            ..handoff(1, 5)
        };
        assert_eq!(
            refused(&[handoff(2, 3), handoff(3, 4), signed_by_another]),
            BAD_SIGNATURE
        );
        let mut chain = trusting(2);
        assert_eq!(
            chain.extend(CHAIN + 1, &[handoff(2, 3)]),
            Err(BAD_SIGNATURE)
        );
        let renamed = Handoff {
            to: 4,
            ..handoff(2, 3)
        };
        assert_eq!(refused(&[renamed]), BAD_SIGNATURE);
        // A trusted key that is no key.
        let mut garbage = KeyChain::new(2, [0xFF; 96], 4);
        assert_eq!(
            garbage.extend(CHAIN, &[handoff(2, 3)]),
            Err(NOT_TRUSTED_KEY)
        );
        // Too many handoffs for one sync, however they would verify.
        let long = vec![handoff(2, 3); MAX_CHAIN + 1];
        assert_eq!(refused(&long), TOO_LONG);
    }
}
