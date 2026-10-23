//! The threshold keystore behind key role 2 of `sign` (spec 05 §4.3): a
//! DKG and a resharing run through four keystores with the transcript a
//! chain would record, partial signatures and their combination, and the
//! requests it refuses.

use std::cell::RefCell;
use std::rc::Rc;

use k256::ecdsa::SigningKey;
use solo_abi::codec::Seq;
use solo_abi::staking::{
    DkgReply, DkgRequest, KEY_ROLE_THRESHOLD, KeySetVote, KeystoreRequest, PartialShare,
    certificate_message,
};
use solo_abi::{Decode, Encode};
use solo_host::{Executor, Flags, ModuleCache};
use solo_node::ChainState;
use solo_node::keystore::{Keystore, encryption_key};
use solo_node::{NodeExtension, NodeServices};
use solo_vm::builder::ModuleBuilder;
use solo_vm::host::Capability;
use solo_vm::isa::{Instruction, Reg, StoreWidth};
use solo_vm::status::Termination;

fn keys(n: u8) -> Vec<SigningKey> {
    (1..=n)
        .map(|i| SigningKey::from_slice(&[0x50 + i; 32]).unwrap())
        .collect()
}

/// One participant: its key and keystore.
struct Party {
    key: SigningKey,
    store: Keystore,
}

impl Party {
    fn ask(&mut self, request: &KeystoreRequest) -> Option<Vec<u8>> {
        self.store.handle(Some(&self.key), &request.to_bytes())
    }

    fn dkg(&mut self, request: DkgRequest) -> Option<DkgReply> {
        self.weighted(request, &[])
    }

    /// A `WeightedDkg` request with `shares`, or a plain `Dkg` one when empty.
    fn weighted(&mut self, request: DkgRequest, shares: &[u32]) -> Option<DkgReply> {
        let request = if shares.is_empty() {
            KeystoreRequest::Dkg(request)
        } else {
            KeystoreRequest::WeightedDkg {
                request,
                shares: Seq(shares.to_vec()),
            }
        };
        self.ask(&request)
            .map(|r| DkgReply::from_bytes(&r).unwrap())
    }
}

fn parties(keys: &[SigningKey]) -> Vec<Party> {
    keys.iter()
        .map(|key| Party {
            key: key.clone(),
            store: Keystore::default(),
        })
        .collect()
}

fn base(recipients: &[SigningKey], dealers: u32, key_set: u64) -> DkgRequest {
    DkgRequest {
        key_set,
        session: [u8::try_from(key_set).unwrap() + 1; 32],
        threshold: u32::try_from(recipients.len() * 2 / 3 + 1).unwrap(),
        dealers,
        recipients: Seq(recipients
            .iter()
            .map(|k| encryption_key(k).to_vec())
            .collect()),
        ..DkgRequest::default()
    }
}

fn message(reply: Option<DkgReply>) -> Option<Vec<u8>> {
    match reply.unwrap() {
        DkgReply::Message(m) => Some(m),
        DkgReply::Idle => None,
        DkgReply::Finished(_) => panic!("finished early"),
    }
}

fn finished(reply: Option<DkgReply>) -> KeySetVote {
    match reply.unwrap() {
        DkgReply::Finished(vote) => vote,
        other => panic!("not finished: {other:?}"),
    }
}

/// Runs a whole DKG among `parties` (dealers by `dealers`, recipients by
/// `recipients`, both 1-based positions in `parties`), corrupting dealer
/// `bad`'s share to recipient 1 and dropping its justification. Returns
/// every recipient's outcome.
fn run_dkg(
    parties: &mut [Party],
    template: &DkgRequest,
    dealers: &[usize],
    recipients: &[usize],
    bad: Option<usize>,
) -> Vec<KeySetVote> {
    run_weighted(parties, template, &[], dealers, recipients, bad)
}

/// [`run_dkg`] with recipient `j` holding `shares[j − 1]` shares.
fn run_weighted(
    parties: &mut [Party],
    template: &DkgRequest,
    shares: &[u32],
    dealers: &[usize],
    recipients: &[usize],
    bad: Option<usize>,
) -> Vec<KeySetVote> {
    let mut transcript = Vec::new();
    for (i, &p) in dealers.iter().enumerate() {
        let request = DkgRequest {
            dealer: u32::try_from(i + 1).unwrap(),
            upto: 0,
            ..template.clone()
        };
        let mut dealing = message(parties[p].weighted(request, shares)).unwrap();
        if bad == Some(p) {
            // The share to recipient 1 sits right after the commitment and ephemeral point.
            let t = template.threshold as usize;
            let at = 1 + 32 + 4 + 1 + 96 * t + 48 + 1 + 31;
            dealing[at] ^= 1;
        }
        transcript.push(dealing);
    }
    // A message for no phase, which the keystore skips.
    transcript.push(vec![9]);
    for (j, &p) in recipients.iter().enumerate() {
        let request = DkgRequest {
            recipient: u32::try_from(j + 1).unwrap(),
            transcript: Seq(transcript.clone()),
            upto: 1,
            ..template.clone()
        };
        if let Some(complaints) = message(parties[p].weighted(request, shares)) {
            transcript.push(complaints);
        }
    }
    for (i, &p) in dealers.iter().enumerate() {
        let request = DkgRequest {
            dealer: u32::try_from(i + 1).unwrap(),
            transcript: Seq(transcript.clone()),
            upto: 2,
            ..template.clone()
        };
        if let Some(justification) = message(parties[p].weighted(request, shares))
            && bad != Some(p)
        {
            transcript.push(justification);
        }
    }
    recipients
        .iter()
        .enumerate()
        .map(|(j, &p)| {
            let request = DkgRequest {
                recipient: u32::try_from(j + 1).unwrap(),
                transcript: Seq(transcript.clone()),
                upto: 3,
                ..template.clone()
            };
            finished(parties[p].weighted(request, shares))
        })
        .collect()
}

/// Partial signatures of `who`, as `(party, shareholder index)` pairs.
fn partials(
    parties: &mut [Party],
    who: &[(usize, u32)],
    key_set: u64,
    msg: &[u8],
) -> Vec<PartialShare> {
    who.iter()
        .map(|&(p, index)| PartialShare {
            key_set,
            index,
            signature: parties[p]
                .ask(&KeystoreRequest::Sign {
                    key_set,
                    message: msg.to_vec(),
                })
                .unwrap(),
        })
        .collect()
}

fn combine(key_set: &[u8], msg: &[u8], partials: Vec<PartialShare>) -> Option<Vec<u8>> {
    Keystore::default().handle(
        None,
        &KeystoreRequest::Combine {
            key_set: key_set.to_vec(),
            message: msg.to_vec(),
            partials: Seq(partials),
        }
        .to_bytes(),
    )
}

fn verifies(group_key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    let key = solo_bls::PublicKey::from_bytes(group_key.try_into().unwrap()).unwrap();
    let sig = solo_bls::Signature::from_bytes(signature.try_into().unwrap()).unwrap();
    key.verify(msg, &sig)
}

#[test]
fn a_dkg_and_a_resharing_through_keystores() {
    let keys = keys(5);
    let mut parties = parties(&keys);
    let first = &keys[..4];
    // Epoch 0: four dealers and recipients; dealer 4 misbehaves and is disqualified.
    let template = base(first, 4, 0);
    let outcomes = run_dkg(
        &mut parties,
        &template,
        &[0, 1, 2, 3],
        &[0, 1, 2, 3],
        Some(3),
    );
    assert!(outcomes.windows(2).all(|w| w[0] == w[1]));
    let vote = outcomes[0].clone();
    assert_eq!(
        (vote.key_set.len(), vote.public_shares.0.len()),
        (3 * 96, 4)
    );
    assert!(parties.iter().take(4).all(|p| p.store.has_share(0)));
    assert!(!parties[4].store.has_share(0));
    // Each share signs; any three partials combine into the group signature.
    let msg = certificate_message(1337, 5, &[7; 32]);
    let group_key = vote.key_set[..96].to_vec();
    let all = partials(&mut parties, &[(0, 1), (1, 2), (2, 3), (3, 4)], 0, &msg);
    for p in &all {
        let share = &vote.public_shares.0[p.index as usize - 1];
        let key = solo_bls::PublicKey::from_bytes(share.as_slice().try_into().unwrap()).unwrap();
        let sig =
            solo_bls::Signature::from_bytes(p.signature.as_slice().try_into().unwrap()).unwrap();
        assert!(key.verify(&msg, &sig));
    }
    let signature = combine(&vote.key_set, &msg, all[1..].to_vec()).unwrap();
    assert!(verifies(&group_key, &msg, &signature));
    // A bad partial first, a duplicate index, a malformed and a zero-index partial: the
    // combiner falls back to checking each partial and still finds three good ones.
    let mut messy = all.clone();
    messy[0].signature = all[1].signature.clone();
    messy.insert(1, all[2].clone());
    messy.insert(
        0,
        PartialShare {
            key_set: 0,
            index: 0,
            signature: all[3].signature.clone(),
        },
    );
    messy.push(PartialShare {
        key_set: 0,
        index: 9,
        signature: vec![1; 47],
    });
    assert_eq!(combine(&vote.key_set, &msg, messy).unwrap(), signature);
    // Too few good partials, or a key set that does not decode: nothing.
    let mut short = all[..3].to_vec();
    short[0].signature = all[1].signature.clone();
    assert_eq!(combine(&vote.key_set, &msg, short), None);
    assert_eq!(combine(&vote.key_set[..95], &msg, all.clone()), None);
    // Epoch 1: the four shareholders reshare to a set with the fifth key in place of the
    // fourth. The fourth still deals; the fifth joins with a share of the same key.
    let next: Vec<SigningKey> = [0, 1, 2, 4].iter().map(|&i| keys[i].clone()).collect();
    let template = DkgRequest {
        previous: vote.key_set.clone(),
        previous_id: 0,
        ..base(&next, 4, 1)
    };
    // A keystore without a share of the key set being reshared cannot deal.
    let mut stranger = Party {
        key: keys[4].clone(),
        store: Keystore::default(),
    };
    assert_eq!(
        stranger.dkg(DkgRequest {
            dealer: 1,
            ..template.clone()
        }),
        None
    );
    let reshared = run_dkg(&mut parties, &template, &[0, 1, 2, 3], &[0, 1, 2, 4], None);
    assert!(reshared.windows(2).all(|w| w[0] == w[1]));
    assert_eq!(&reshared[0].key_set[..96], group_key.as_slice());
    assert_ne!(reshared[0].key_set, vote.key_set);
    let fresh = partials(&mut parties, &[(0, 1), (1, 2), (4, 4)], 1, &msg);
    assert_eq!(
        combine(&reshared[0].key_set, &msg, fresh).unwrap(),
        signature
    );
}

#[test]
fn a_weighted_dkg_through_keystores() {
    // Three parties holding 1, 3 and 2 shares of a key with threshold 4; dealers weigh
    // their share counts.
    let keys = keys(3);
    let mut parties = parties(&keys);
    let template = DkgRequest {
        threshold: 4,
        ..base(&keys, 3, 0)
    };
    let shares = [1, 3, 2];
    let outcomes = run_weighted(
        &mut parties,
        &template,
        &shares,
        &[0, 1, 2],
        &[0, 1, 2],
        None,
    );
    assert!(outcomes.windows(2).all(|w| w[0] == w[1]));
    let vote = outcomes[0].clone();
    assert_eq!(
        (vote.key_set.len(), vote.public_shares.0.len()),
        (4 * 96, 6)
    );
    let msg = certificate_message(1337, 5, &[7; 32]);
    let sign_all = |party: &mut Party| {
        let reply = party
            .ask(&KeystoreRequest::SignAll {
                key_set: 0,
                message: msg.clone(),
            })
            .unwrap();
        Seq::<PartialShare>::from_bytes(&reply).unwrap().0
    };
    let held: Vec<Vec<PartialShare>> = parties.iter_mut().map(sign_all).collect();
    let indices: Vec<Vec<u32>> = held
        .iter()
        .map(|h| h.iter().map(|p| p.index).collect())
        .collect();
    assert_eq!(indices, [vec![1], vec![2, 3, 4], vec![5, 6]]);
    for p in held.iter().flatten() {
        let share = &vote.public_shares.0[p.index as usize - 1];
        let key = solo_bls::PublicKey::from_bytes(share.as_slice().try_into().unwrap()).unwrap();
        let sig =
            solo_bls::Signature::from_bytes(p.signature.as_slice().try_into().unwrap()).unwrap();
        assert_eq!(p.key_set, 0);
        assert!(key.verify(&msg, &sig));
    }
    // `Sign` answers the partial of the lowest share a party holds.
    assert_eq!(
        partials(&mut parties, &[(1, 2)], 0, &msg),
        held[1][..1].to_vec()
    );
    // Parties 2 and 3 hold five shares and sign; parties 1 and 3 hold three and do not.
    let group_key = vote.key_set[..96].to_vec();
    let signature = combine(
        &vote.key_set,
        &msg,
        [held[1].clone(), held[2].clone()].concat(),
    )
    .unwrap();
    assert!(verifies(&group_key, &msg, &signature));
    assert_eq!(
        combine(
            &vote.key_set,
            &msg,
            [held[0].clone(), held[2].clone()].concat()
        ),
        None
    );
    // `SignAll` needs the node key and a share of the key set.
    let request = KeystoreRequest::SignAll {
        key_set: 0,
        message: msg.clone(),
    }
    .to_bytes();
    assert_eq!(parties[0].store.handle(None, &request), None);
    let other = KeystoreRequest::SignAll {
        key_set: 1,
        message: msg,
    };
    assert_eq!(parties[0].ask(&other), None);
}

#[test]
fn refused_requests() {
    let keys = keys(4);
    let key = &keys[0];
    let mut store = Keystore::default();
    let ask = |store: &mut Keystore, key: Option<&SigningKey>, r: &KeystoreRequest| {
        store.handle(key, &r.to_bytes())
    };
    // The encryption key needs the node key; so do the DKG and signing.
    assert_eq!(
        ask(&mut store, Some(key), &KeystoreRequest::EncryptionKey).unwrap(),
        encryption_key(key).to_vec()
    );
    assert_eq!(ask(&mut store, None, &KeystoreRequest::EncryptionKey), None);
    let template = base(&keys, 4, 0);
    assert_eq!(
        ask(&mut store, None, &KeystoreRequest::Dkg(template.clone())),
        None
    );
    let sign = KeystoreRequest::Sign {
        key_set: 0,
        message: vec![1],
    };
    assert_eq!(ask(&mut store, None, &sign), None);
    // No share for the key set.
    assert_eq!(ask(&mut store, Some(key), &sign), None);
    // Bytes that are no request.
    assert_eq!(store.handle(Some(key), &[9]), None);
    let mut party = Party {
        key: key.clone(),
        store,
    };
    // Recipient keys that are not points, a previous key set that does not decode, a
    // configuration the DKG refuses.
    let mut bad_keys = template.clone();
    bad_keys.recipients.0[1] = vec![0; 48];
    assert_eq!(party.dkg(bad_keys), None);
    let mut short_key = template.clone();
    short_key.recipients.0[1] = vec![0; 47];
    assert_eq!(party.dkg(short_key), None);
    assert_eq!(
        party.dkg(DkgRequest {
            previous: vec![1; 95],
            ..template.clone()
        }),
        None
    );
    assert_eq!(
        party.dkg(DkgRequest {
            threshold: 9,
            ..template.clone()
        }),
        None
    );
    // Not a dealer: nothing to deal. Nothing to complain about: idle.
    assert_eq!(
        party.dkg(DkgRequest {
            upto: 0,
            ..template.clone()
        }),
        Some(DkgReply::Idle)
    );
    assert_eq!(
        party.dkg(DkgRequest {
            recipient: 1,
            upto: 1,
            ..template.clone()
        }),
        Some(DkgReply::Idle)
    );
    // Too few dealings for the threshold: the run fails.
    assert_eq!(
        party.dkg(DkgRequest {
            recipient: 1,
            upto: 3,
            ..template
        }),
        None
    );
}

const BUF: i64 = 0xFFFC_0000;

fn li(r: Reg, imm: i64) -> Instruction {
    Instruction::Li { rd: r, imm }
}

/// A module that calls `sign` with key role 2 on its read-only data and a
/// destination of `cap` bytes, then outputs the result and the written bytes.
fn module(rodata: &[u8], cap: i64) -> Vec<u8> {
    let mut b = ModuleBuilder::new().rodata(rodata);
    b.import("output_write");
    b.import("sign");
    let mut code = vec![
        li(Reg::A0, i64::try_from(KEY_ROLE_THRESHOLD).unwrap()),
        li(Reg::A1, 0x1_0000),
        li(Reg::A2, i64::try_from(rodata.len()).unwrap()),
        li(Reg::A3, BUF + 8),
        li(Reg::A4, cap),
        Instruction::Ecall { import: 1 },
    ];
    code.extend([
        li(Reg::A7, BUF),
        Instruction::Store {
            width: StoreWidth::D,
            rs1: Reg::A7,
            rs2: Reg::A0,
            off: 0,
        },
        li(Reg::A0, BUF),
        li(Reg::A1, 8 + 48),
        Instruction::Ecall { import: 0 },
        Instruction::Halt,
    ]);
    b.block(&code);
    b.export("main", 0).build()
}

#[test]
fn sign_with_role_2_reaches_the_keystore() {
    let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let services = Rc::new(RefCell::new(NodeServices {
        key: Some(key.clone()),
        ..NodeServices::default()
    }));
    let mut exec = Executor::new(ModuleCache::default(), ChainState::default());
    exec.set_extension(Box::new(NodeExtension::new(Rc::clone(&services))));
    let request = KeystoreRequest::EncryptionKey.to_bytes();
    let call = |exec: &mut Executor<ChainState>, rodata: &[u8], cap: i64| {
        let hash = exec
            .load(&module(rodata, cap), Capability::Privileged)
            .unwrap();
        let r = exec.call(
            &hash,
            [0; 32],
            b"",
            1_000_000,
            Capability::Privileged,
            Flags::default(),
        );
        assert_eq!(r.status, Termination::Halt);
        (
            u64::from_le_bytes(r.output[..8].try_into().unwrap()),
            r.output[8..].to_vec(),
        )
    };
    // The whole answer fits: its length, and the key.
    let (len, out) = call(&mut exec, &request, 48);
    assert_eq!((len, out), (48, encryption_key(&key).to_vec()));
    // A smaller buffer gets the start of it, and the full length.
    let (len, out) = call(&mut exec, &request, 16);
    assert_eq!(len, 48);
    assert_eq!(out[..16], encryption_key(&key)[..16]);
    assert!(out[16..].iter().all(|b| *b == 0));
    // A request the keystore refuses returns 0.
    let (len, _) = call(&mut exec, &[9], 48);
    assert_eq!(len, 0);
}
