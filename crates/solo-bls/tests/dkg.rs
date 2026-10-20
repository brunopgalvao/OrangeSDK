//! Runs of the DKG and of resharing among in-process participants, with
//! honest and misbehaving dealers and recipients.

use solo_abi::{Decode, DecodeError, Encode};
use solo_bls::dkg::{
    Complaints, Config, Dealer, Dealing, DecryptionKey, Dkg, DkgError, EncryptionKey,
    Justification, Message, Output, Phase, Recipient, RevealedShare, Step,
};
use solo_bls::{Certificate, Error, PublicKeySet, SecretShare, certificate, threshold};

const SESSION: [u8; 32] = [0x5e; 32];
const CHAIN_ID: u64 = 1337;

fn byte(i: u32) -> u8 {
    u8::try_from(i).unwrap()
}

fn decryption_key(j: u32) -> DecryptionKey {
    DecryptionKey::generate(&[byte(j); 32]).unwrap()
}

fn encryption_keys(n: u32) -> Vec<EncryptionKey> {
    (1..=n)
        .map(|j| decryption_key(j).encryption_key())
        .collect()
}

fn config(t: u32, dealers: u32, n: u32, previous: Option<PublicKeySet>) -> Config {
    Config {
        session: SESSION,
        threshold: t,
        dealers,
        recipients: encryption_keys(n),
        previous,
    }
}

#[allow(clippy::unnecessary_wraps)] // roles are passed as options
fn dealer(i: u32, share: Option<SecretShare>) -> Option<Dealer> {
    Some(Dealer {
        index: i,
        seed: [byte(i) + 100; 32],
        share,
    })
}

#[allow(clippy::unnecessary_wraps)] // roles are passed as options
fn recipient(j: u32) -> Option<Recipient> {
    Some(Recipient {
        index: j,
        key: decryption_key(j),
    })
}

/// A fresh run in which participant `i` deals and receives as index `i`.
fn fresh(n: u32, t: u32) -> (Vec<Dkg>, Vec<Message>) {
    let mut nodes = Vec::new();
    let mut dealings = Vec::new();
    for i in 1..=n {
        let (dkg, dealing) =
            Dkg::new(config(t, n, n, None), dealer(i, None), recipient(i)).unwrap();
        nodes.push(dkg);
        dealings.push(dealing.unwrap());
    }
    (nodes, dealings)
}

/// Delivers every message to every node in order and returns, per message,
/// what the first node said (every honest node says the same).
fn deliver(nodes: &mut [Dkg], messages: &[Message]) -> Vec<Result<(), DkgError>> {
    let mut first = Vec::new();
    for m in messages {
        let results: Vec<_> = nodes.iter_mut().map(|n| n.handle(m)).collect();
        assert!(
            results.windows(2).all(|w| w[0] == w[1]),
            "nodes disagree on {m:?}"
        );
        first.push(results[0]);
    }
    first
}

/// Ends the current phase everywhere and gathers the broadcasts.
fn advance(nodes: &mut [Dkg]) -> Vec<Message> {
    let mut out = Vec::new();
    for n in nodes.iter_mut() {
        match n.advance().unwrap() {
            Step::Broadcast(m) => out.push(m),
            Step::Idle => {}
            Step::Finished(o) => panic!("finished early: {o:?}"),
        }
    }
    out
}

/// Ends the last phase everywhere.
fn finish(nodes: &mut [Dkg]) -> Vec<Output> {
    nodes
        .iter_mut()
        .map(|n| match n.advance().unwrap() {
            Step::Finished(o) => o,
            other => panic!("not finished: {other:?}"),
        })
        .collect()
}

/// Runs the remaining phases with `edit` applied to each phase's
/// broadcasts before delivery (phase 0 is the dealings).
fn run(
    nodes: &mut [Dkg],
    mut dealings: Vec<Message>,
    mut edit: impl FnMut(usize, &mut Vec<Message>),
) -> Vec<Output> {
    edit(0, &mut dealings);
    deliver(nodes, &dealings);
    let mut complaints = advance(nodes);
    edit(1, &mut complaints);
    deliver(nodes, &complaints);
    let mut justifications = advance(nodes);
    edit(2, &mut justifications);
    deliver(nodes, &justifications);
    finish(nodes)
}

fn dealing_of(messages: &mut [Message], dealer: u32) -> &mut Dealing {
    messages
        .iter_mut()
        .find_map(|m| match m {
            Message::Dealing(d) if d.dealer == dealer => Some(d),
            _ => None,
        })
        .unwrap()
}

/// Every output agrees, every share matches its public share, and any
/// `t` shares sign a certificate valid under the group key.
fn check(outputs: &[Output], qualified: &[u32]) -> PublicKeySet {
    let keys = outputs[0].key_set.clone();
    for o in outputs {
        assert_eq!(o.key_set, keys);
        assert_eq!(o.qualified, qualified);
    }
    let shares: Vec<&SecretShare> = outputs.iter().filter_map(|o| o.share.as_ref()).collect();
    for s in &shares {
        assert_eq!(s.public_key(), keys.public_share(s.index()));
    }
    let t = keys.threshold() as usize;
    for window in shares.windows(t) {
        let partials: Vec<_> = window
            .iter()
            .map(|s| certificate::sign_partial(s, CHAIN_ID, 9, &[7; 32]))
            .collect();
        let cert = Certificate::combine(&keys, CHAIN_ID, 9, &[7; 32], &partials).unwrap();
        assert!(cert.verify(CHAIN_ID, &keys.group_key()));
    }
    keys
}

/// The sum of the constant terms of the given dealers' dealings.
fn sum_of_constants(dealings: &mut [Message], dealers: &[u32]) -> solo_bls::PublicKey {
    let sum: solo_bls::curve::G2Projective = dealers
        .iter()
        .map(|&i| {
            let c = dealing_of(dealings, i).commitment[0];
            solo_bls::curve::G2Projective::from(
                solo_bls::PublicKey::from_bytes(&c).unwrap().point(),
            )
        })
        .sum();
    solo_bls::PublicKey::from_bytes(&solo_bls::curve::G2Affine::from(sum).to_compressed()).unwrap()
}

#[test]
fn honest_run_produces_one_shared_key() {
    let (mut nodes, mut dealings) = fresh(4, 3);
    let expected = sum_of_constants(&mut dealings, &[1, 2, 3, 4]);
    assert_eq!(nodes[0].phase(), Phase::Dealing);
    let outputs = run(&mut nodes, dealings, |_, _| {});
    assert_eq!(nodes[0].phase(), Phase::Finished);
    let keys = check(&outputs, &[1, 2, 3, 4]);
    assert_eq!(keys.group_key(), expected);
    assert_eq!(keys.threshold(), 3);
    assert_eq!(nodes[0].advance().unwrap_err(), DkgError::WrongPhase);
    // The shares interpolate to the group key.
    let pks: Vec<_> = [2u32, 3, 4]
        .iter()
        .map(|&i| (i, keys.public_share(i)))
        .collect();
    assert_eq!(threshold::interpolate_public(&pks), Ok(keys.group_key()));
}

#[test]
fn a_dealer_who_sends_a_bad_share_and_stays_silent_is_excluded() {
    let (mut nodes, mut dealings) = fresh(4, 3);
    let expected = sum_of_constants(&mut dealings, &[1, 3, 4]);
    let mut complaints_seen = Vec::new();
    let outputs = run(&mut nodes, dealings, |phase, msgs| match phase {
        0 => dealing_of(msgs, 2).shares[2][31] ^= 1,
        1 => complaints_seen.clone_from(msgs),
        _ => msgs.retain(|m| !matches!(m, Message::Justification(j) if j.dealer == 2)),
    });
    assert_eq!(
        complaints_seen,
        vec![Message::Complaints(Complaints {
            session: SESSION,
            accuser: 3,
            dealers: vec![2],
        })]
    );
    let keys = check(&outputs, &[1, 3, 4]);
    assert_eq!(keys.group_key(), expected);
}

#[test]
fn a_dealer_who_answers_a_complaint_with_the_right_share_stays() {
    let (mut nodes, dealings) = fresh(4, 3);
    let mut justified = Vec::new();
    let outputs = run(&mut nodes, dealings, |phase, msgs| match phase {
        0 => dealing_of(msgs, 2).shares[2][31] ^= 1,
        2 => justified.clone_from(msgs),
        _ => {}
    });
    assert!(matches!(
        &justified[..],
        [Message::Justification(Justification { dealer: 2, shares, .. })]
            if shares.len() == 1 && shares[0].recipient == 3
    ));
    check(&outputs, &[1, 2, 3, 4]);
    assert!(outputs[2].share.is_some());
}

#[test]
fn a_dealer_who_reveals_a_wrong_share_is_excluded() {
    let (mut nodes, dealings) = fresh(4, 3);
    let outputs = run(&mut nodes, dealings, |phase, msgs| match phase {
        0 => dealing_of(msgs, 2).shares[2][31] ^= 1,
        2 => {
            let Message::Justification(j) = &mut msgs[0] else {
                panic!("expected a justification")
            };
            j.shares[0].share[31] ^= 1;
        }
        _ => {}
    });
    check(&outputs, &[1, 3, 4]);
}

#[test]
fn a_false_complaint_costs_the_honest_dealer_nothing() {
    let (mut nodes, dealings) = fresh(4, 3);
    let outputs = run(&mut nodes, dealings, |phase, msgs| {
        if phase == 1 {
            assert!(msgs.is_empty());
            msgs.push(Message::Complaints(Complaints {
                session: SESSION,
                accuser: 4,
                // Dealer 9 does not exist and is ignored.
                dealers: vec![1, 9],
            }));
        }
    });
    check(&outputs, &[1, 2, 3, 4]);
}

#[test]
fn a_justification_that_dodges_the_complaint_disqualifies() {
    let (mut nodes, dealings) = fresh(4, 3);
    let outputs = run(&mut nodes, dealings, |phase, msgs| match phase {
        0 => dealing_of(msgs, 1).shares[3][31] ^= 1,
        2 => {
            let Message::Justification(j) = &mut msgs[0] else {
                panic!("expected a justification")
            };
            // Reveal recipient 2's share instead, then a garbage scalar.
            j.shares[0].recipient = 2;
            j.shares.push(RevealedShare {
                recipient: 4,
                share: [0xFF; 32],
            });
        }
        _ => {}
    });
    check(&outputs, &[2, 3, 4]);
}

#[test]
fn malformed_and_misaddressed_dealings_are_rejected() {
    let (mut nodes, dealings) = fresh(4, 3);
    let good = dealings[0].clone();
    let Message::Dealing(d) = &good else { panic!() };
    let variants: Vec<(Dealing, DkgError)> = vec![
        (
            Dealing {
                session: [0; 32],
                ..d.clone()
            },
            DkgError::WrongSession,
        ),
        (
            Dealing {
                dealer: 0,
                ..d.clone()
            },
            DkgError::UnknownSender,
        ),
        (
            Dealing {
                dealer: 5,
                ..d.clone()
            },
            DkgError::UnknownSender,
        ),
        (
            Dealing {
                commitment: d.commitment[..2].to_vec(),
                ..d.clone()
            },
            DkgError::Malformed,
        ),
        (
            Dealing {
                shares: d.shares[..3].to_vec(),
                ..d.clone()
            },
            DkgError::Malformed,
        ),
        (
            Dealing {
                ephemeral: [0xFF; 48],
                ..d.clone()
            },
            DkgError::Malformed,
        ),
        (
            Dealing {
                commitment: vec![[0xFF; 96]; 3],
                ..d.clone()
            },
            DkgError::Malformed,
        ),
        (
            Dealing {
                shares: vec![[0xFF; 32]; 4],
                ..d.clone()
            },
            DkgError::Malformed,
        ),
    ];
    for (bad, why) in variants {
        assert_eq!(
            deliver(&mut nodes, &[Message::Dealing(bad)]),
            vec![Err(why)]
        );
    }
    assert_eq!(
        deliver(&mut nodes, &[good.clone(), good]),
        vec![Ok(()), Err(DkgError::Duplicate)]
    );
    // Messages of other phases are refused.
    let complaint = Message::Complaints(Complaints {
        session: SESSION,
        accuser: 1,
        dealers: vec![],
    });
    let justification = Message::Justification(Justification {
        session: SESSION,
        dealer: 1,
        shares: vec![],
    });
    assert_eq!(
        deliver(&mut nodes, &[complaint, justification]),
        vec![Err(DkgError::WrongPhase), Err(DkgError::WrongPhase)]
    );
    // Only dealer 1 dealt: too few qualify.
    advance(&mut nodes);
    advance(&mut nodes);
    for n in &mut nodes {
        assert_eq!(n.advance().unwrap_err(), DkgError::TooFewQualified);
        assert_eq!(n.phase(), Phase::Finished);
    }
    assert_eq!(nodes[0].handle(&dealings[1]), Err(DkgError::WrongPhase));
}

#[test]
fn complaint_and_justification_bookkeeping() {
    let (mut nodes, dealings) = fresh(4, 3);
    deliver(&mut nodes, &dealings);
    assert!(advance(&mut nodes).is_empty());
    let c = |accuser, session| {
        Message::Complaints(Complaints {
            session,
            accuser,
            dealers: vec![3],
        })
    };
    assert_eq!(
        deliver(
            &mut nodes,
            &[
                c(0, SESSION),
                c(5, SESSION),
                c(1, [1; 32]),
                c(1, SESSION),
                c(1, SESSION)
            ]
        ),
        vec![
            Err(DkgError::UnknownSender),
            Err(DkgError::UnknownSender),
            Err(DkgError::WrongSession),
            Ok(()),
            Err(DkgError::Duplicate),
        ]
    );
    let justifications = advance(&mut nodes);
    assert_eq!(justifications.len(), 1);
    let j = |dealer| {
        Message::Justification(Justification {
            session: SESSION,
            dealer,
            shares: vec![],
        })
    };
    // Dealer 2 owes nothing; its empty justification is accepted and ignored.
    let mut all = vec![j(0), j(5), j(2)];
    all.extend(justifications.clone());
    all.extend(justifications);
    assert_eq!(
        deliver(&mut nodes, &all),
        vec![
            Err(DkgError::UnknownSender),
            Err(DkgError::UnknownSender),
            Ok(()),
            Ok(()),
            Err(DkgError::Duplicate),
        ]
    );
    let outputs = finish(&mut nodes);
    check(&outputs, &[1, 2, 3, 4]);
}

#[test]
fn a_lost_complaint_leaves_only_the_accuser_without_a_share() {
    let (mut nodes, dealings) = fresh(4, 3);
    let outputs = run(&mut nodes, dealings, |phase, msgs| match phase {
        0 => dealing_of(msgs, 2).shares[2][31] ^= 1,
        1 => msgs.clear(),
        _ => {}
    });
    check(&outputs, &[1, 2, 3, 4]);
    assert!(outputs[2].share.is_none());
    assert!(outputs.iter().filter(|o| o.share.is_some()).count() == 3);
}

#[test]
fn observers_and_pure_recipients_follow_the_run() {
    let n = 3;
    let mut nodes = Vec::new();
    let mut dealings = Vec::new();
    // Dealers 1..=3 are not recipients; recipients 1..=3 do not deal.
    for i in 1..=n {
        let (dkg, d) = Dkg::new(config(2, n, n, None), dealer(i, None), None).unwrap();
        nodes.push(dkg);
        dealings.push(d.unwrap());
    }
    for j in 1..=n {
        let (dkg, d) = Dkg::new(config(2, n, n, None), None, recipient(j)).unwrap();
        assert!(d.is_none());
        nodes.push(dkg);
    }
    let (observer, _) = Dkg::new(config(2, n, n, None), None, None).unwrap();
    nodes.push(observer);
    let outputs = run(&mut nodes, dealings, |_, _| {});
    check(&outputs, &[1, 2, 3]);
    assert!(outputs[..3].iter().all(|o| o.share.is_none()));
    assert!(outputs[3..6].iter().all(|o| o.share.is_some()));
    assert!(outputs[6].share.is_none());
}

/// Reshares `outputs` (a 3-of-4 key) to `n_new` recipients with threshold
/// `t_new`, dealt by the old shareholders `dealers`.
fn reshare(
    keys: &PublicKeySet,
    outputs: Vec<Output>,
    dealers: &[u32],
    t_new: u32,
    n_new: u32,
) -> (Vec<Dkg>, Vec<Message>) {
    let cfg = config(t_new, 4, n_new, Some(keys.clone()));
    let mut nodes = Vec::new();
    let mut dealings = Vec::new();
    for o in outputs {
        let share = o.share.unwrap();
        let i = share.index();
        if dealers.contains(&i) {
            let (dkg, d) = Dkg::new(cfg.clone(), dealer(i, Some(share)), None).unwrap();
            nodes.push(dkg);
            dealings.push(d.unwrap());
        }
    }
    for j in 1..=n_new {
        nodes.push(Dkg::new(cfg.clone(), None, recipient(j)).unwrap().0);
    }
    (nodes, dealings)
}

#[test]
fn resharing_to_a_new_set_keeps_the_group_key() {
    let (mut nodes, dealings) = fresh(4, 3);
    let outputs = run(&mut nodes, dealings, |_, _| {});
    let keys = check(&outputs, &[1, 2, 3, 4]);
    let (mut next, dealings) = reshare(&keys, outputs, &[1, 2, 3, 4], 4, 5);
    let new_outputs = run(&mut next, dealings, |_, _| {});
    let new_keys = check(&new_outputs[4..], &[1, 2, 3, 4]);
    assert_eq!(new_keys.group_key(), keys.group_key());
    assert_eq!(new_keys.threshold(), 4);
    assert_ne!(new_keys, keys);
    // A certificate from the new set verifies under the old group key.
    let shares: Vec<&SecretShare> = new_outputs[4..]
        .iter()
        .filter_map(|o| o.share.as_ref())
        .collect();
    let partials: Vec<_> = shares[1..]
        .iter()
        .map(|s| certificate::sign_partial(s, CHAIN_ID, 50, &[1; 32]))
        .collect();
    let cert = Certificate::combine(&new_keys, CHAIN_ID, 50, &[1; 32], &partials).unwrap();
    assert!(cert.verify(CHAIN_ID, &keys.group_key()));
}

#[test]
fn a_resharing_dealer_cannot_change_the_group_key() {
    let (mut nodes, dealings) = fresh(4, 3);
    let outputs = run(&mut nodes, dealings, |_, _| {});
    let keys = check(&outputs, &[1, 2, 3, 4]);
    // Dealer 4 deals with a share it does not hold: its own share plus one.
    let cfg = config(2, 4, 3, Some(keys.clone()));
    let mut forged_bytes = outputs[3].share.as_ref().unwrap().to_bytes();
    forged_bytes[31] ^= 1;
    let forged = SecretShare::from_bytes(4, &forged_bytes).unwrap();
    let (_, bad) = Dkg::new(cfg, dealer(4, Some(forged)), None).unwrap();
    let (mut next, mut dealings) = reshare(&keys, outputs, &[1, 2, 3], 2, 3);
    dealings.push(bad.unwrap());
    let results = deliver(&mut next, &dealings);
    assert_eq!(results[3], Err(DkgError::ConstantTermMismatch));
    advance(&mut next);
    advance(&mut next);
    let new_outputs = finish(&mut next);
    let new_keys = check(&new_outputs[3..], &[1, 2, 3]);
    assert_eq!(new_keys.group_key(), keys.group_key());
}

#[test]
fn resharing_needs_the_previous_threshold_of_dealers() {
    let (mut nodes, dealings) = fresh(4, 3);
    let outputs = run(&mut nodes, dealings, |_, _| {});
    let keys = check(&outputs, &[1, 2, 3, 4]);
    let (mut next, dealings) = reshare(&keys, outputs, &[1, 2], 2, 3);
    deliver(&mut next, &dealings);
    advance(&mut next);
    advance(&mut next);
    assert_eq!(next[0].advance().unwrap_err(), DkgError::TooFewQualified);
}

#[test]
fn configurations_that_do_not_fit_are_refused() {
    let keys = threshold::deal(
        &solo_bls::SecretKey::generate(&[1; 32], b"").unwrap(),
        2,
        3,
        &[2; 32],
    )
    .unwrap()
    .0;
    let share = || SecretShare::from_bytes(1, &[1; 32]).ok();
    let cases: Vec<(Config, Option<Dealer>, Option<Recipient>)> = vec![
        (config(0, 3, 3, None), None, None),
        (config(4, 3, 3, None), None, None),
        (config(2, 0, 3, None), None, None),
        (config(2, 1, 3, Some(keys.clone())), None, None),
        (config(2, 3, 3, None), dealer(0, None), None),
        (config(2, 3, 3, None), dealer(4, None), None),
        (config(2, 3, 3, None), dealer(1, share()), None),
        (config(2, 3, 3, Some(keys.clone())), dealer(1, None), None),
        (
            config(2, 3, 3, Some(keys.clone())),
            Some(Dealer {
                index: 2,
                seed: [0; 32],
                share: share(),
            }),
            None,
        ),
        (config(2, 3, 3, None), None, recipient(0)),
        (config(2, 3, 3, None), None, recipient(4)),
    ];
    for (cfg, d, r) in cases {
        assert_eq!(Dkg::new(cfg, d, r).err(), Some(DkgError::InvalidConfig));
    }
    assert!(
        Dkg::new(
            config(2, 3, 3, Some(keys)),
            dealer(1, share()),
            recipient(3)
        )
        .is_ok()
    );
}

#[test]
fn keys_and_messages_have_canonical_encodings() {
    let dk = decryption_key(1);
    let ek = dk.encryption_key();
    assert_eq!(EncryptionKey::from_bytes(&ek.to_bytes()), Ok(ek));
    assert_eq!(
        EncryptionKey::from_bytes(&[0xFF; 48]),
        Err(Error::InvalidPoint)
    );
    let identity = solo_bls::curve::G1Affine::identity().to_compressed();
    assert_eq!(
        EncryptionKey::from_bytes(&identity),
        Err(Error::InvalidPoint)
    );
    assert_eq!(
        DecryptionKey::generate(&[0; 31]).unwrap_err(),
        Error::ShortKeyMaterial
    );
    assert_eq!(format!("{dk:?}"), "DecryptionKey(..)");
    let (_, dealings) = fresh(2, 2);
    let messages = vec![
        dealings[0].clone(),
        Message::Complaints(Complaints {
            session: SESSION,
            accuser: 2,
            dealers: vec![1, 2],
        }),
        Message::Justification(Justification {
            session: SESSION,
            dealer: 1,
            shares: vec![RevealedShare {
                recipient: 2,
                share: [3; 32],
            }],
        }),
    ];
    for m in &messages {
        let bytes = m.to_bytes();
        assert_eq!(Message::from_bytes(&bytes).as_ref(), Ok(m));
        for cut in 0..bytes.len() {
            assert_eq!(
                Message::from_bytes(&bytes[..cut]),
                Err(DecodeError::Truncated),
                "{cut}"
            );
        }
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(Message::from_bytes(&long), Err(DecodeError::Trailing));
    }
    assert_eq!(Message::from_bytes(&[3]), Err(DecodeError::BadTag(3)));
    // The dealing layout: tag, session, dealer, t points, ephemeral, n scalars.
    let bytes = messages[0].to_bytes();
    assert_eq!(bytes.len(), 1 + 32 + 4 + 1 + 2 * 96 + 48 + 1 + 2 * 32);
    assert_eq!(&bytes[..1], &[0]);
    assert_eq!(&bytes[33..37], &1u32.to_le_bytes());
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .concat()
}

/// The 2-of-2 run of spec 12 §9.3: participant `i` has decryption key
/// `KeyGen([i; 32], "SOLO-DKG-ENCRYPTION")` and dealer seed `[100 + i; 32]`,
/// in session `[0x5e; 32]`. Pins the coefficient, ephemeral and pad
/// derivations and the message encoding.
#[test]
fn a_pinned_two_party_run() {
    use sha2::{Digest, Sha256};
    let (mut nodes, dealings) = fresh(2, 2);
    assert_eq!(
        hex(&encryption_keys(1)[0].to_bytes()),
        "96945b435e90ff747ee213c0246c0569388a45fe41b63ddf6360c46ba82a375b35e4cd5ac8fd169f0878fc585a482363"
    );
    let digests: Vec<String> = dealings
        .iter()
        .map(|d| hex(&Sha256::digest(d.to_bytes())))
        .collect();
    assert_eq!(
        digests,
        [
            "b0a2f76c7e3326b430b8805568ea72989da5a8a668c378daadd45df302e7d2f8",
            "4e6f4c171407144dabc9c38cabd742f877ee899d686f41419f243e0f91fd9034",
        ]
    );
    let outputs = run(&mut nodes, dealings, |_, _| {});
    let keys = check(&outputs, &[1, 2]);
    assert_eq!(
        hex(&keys.group_key().to_bytes()),
        "822bbc35275c08f014e718c9f66fe0ac83943afc0cdc3fd07316cb86bdc358d1b69ccc36c50f0ba06f9d2a5c47c18ee81889cd077e07f0854856cfa804d50e210008424da41554c2e4409d089aceae7298f898636df1836bf31b5af73ff64b66"
    );
    let shares: Vec<String> = outputs
        .iter()
        .map(|o| hex(&o.share.as_ref().unwrap().to_bytes()))
        .collect();
    assert_eq!(
        shares,
        [
            "4145a604d607404d85870f2a98a82762f22bd6d84d471b63640b0834beec3ba8",
            "1d90c23af67638a1e5f471c93486d0163ef41c680ee807a57d599431274f522c",
        ]
    );
}
