//! The light client against real Ethereum mainnet data (see
//! `tests/vectors/README.md`): a Fulu bootstrap at the start of period
//! 1888, the period's update with the committee of 1889, then a finality
//! update signed by that committee, whose execution state root a real
//! `eth_getProof` output is checked against.

use std::collections::BTreeMap;

use orange_abi::bridge_in::{BridgeInParams, Fork, InboxLimits, LightClientConfig};
use orange_abi::codec::Seq;
use orange_ethlc::beacon::{Bootstrap, Update};
use orange_ethlc::client::{self, Context, Finalized, Storage, keys};
use orange_ethlc::sync::{self, Rejection, State};
use orange_ethlc::testing::{Native, hex, unhex};
use orange_ethlc::{Crypto, abi, inbox, mpt};

const BOOTSTRAP: &[u8] = include_bytes!("vectors/bootstrap-1888.ssz");
const UPDATE: &[u8] = include_bytes!("vectors/update-1888.ssz");
const FINALITY: &[u8] = include_bytes!("vectors/finality-15475041.ssz");
const PROOF: &str = include_str!("vectors/weth-proof-26235823.json");

fn mainnet() -> LightClientConfig {
    LightClientConfig {
        genesis_validators_root: unhex(
            "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
        )
        .try_into()
        .unwrap(),
        forks: Seq(vec![
            Fork {
                epoch: 364_032,
                version: [5, 0, 0, 0],
            },
            Fork {
                epoch: 411_392,
                version: [6, 0, 0, 0],
            },
        ]),
        sync_committee_size: 512,
        slots_per_epoch: 32,
        epochs_per_period: 256,
    }
}

#[derive(Default)]
struct Map(BTreeMap<Vec<u8>, Vec<u8>>);

impl Storage for Map {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.0.get(key).cloned()
    }

    fn set(&mut self, key: &[u8], value: Option<&[u8]>) {
        match value {
            Some(v) => self.0.insert(key.to_vec(), v.to_vec()),
            None => self.0.remove(key),
        };
    }
}

fn rejected(r: Rejection) -> Vec<u8> {
    abi::encode(abi::UPDATE_REJECTED, &[abi::word(r as u64)])
}

fn finalized(store: &Map) -> Finalized {
    orange_abi::Decode::from_bytes(&store.get(keys::FINALIZED).unwrap()).unwrap()
}

#[test]
fn real_containers_decode_and_hash_to_their_roots() {
    let c = Native;
    let b = Bootstrap::decode(BOOTSTRAP, 512).unwrap();
    assert_eq!(b.header.beacon.slot, 15_466_496);
    assert_eq!(
        hex(&b.header.beacon.root(&c)),
        "5ded74ce1ea2e8e7d5c47e043e207a403c41c70222629989de5b6ba6a1df20b5"
    );
    assert_eq!(b.encode(), BOOTSTRAP);
    assert!(b.header.is_valid(&c));
    assert_eq!(sync::bootstrap(&c, &mainnet(), &b), Ok(()));
    let u = Update::decode_update(UPDATE, 512).unwrap();
    assert_eq!(
        (
            u.attested.beacon.slot,
            u.finalized.beacon.slot,
            u.signature_slot
        ),
        (15_466_561, 15_466_496, 15_466_562)
    );
    assert_eq!(u.encode_update(512), UPDATE);
    assert!(u.next_sync_committee.is_some());
    let f = Update::decode_finality_update(FINALITY, 512).unwrap();
    assert_eq!(f.encode_finality_update(), FINALITY);
    assert_eq!(f.finalized.execution.block_number, 26_235_823);
    assert_eq!(
        hex(&f.finalized.execution.state_root),
        "b6334d8344245c45c5665c261b743258145008ffe261f36b7bbd6a1e72fd828c"
    );
    // The real 512-key aggregate: the vector for `bls12381_fast_aggregate_verify`.
    let keys = u
        .sync_aggregate
        .participant_keys(&b.current_sync_committee.pubkeys);
    let root = sync::signing_root(
        &c,
        &mainnet(),
        &u.attested.beacon.root(&c),
        u.signature_slot,
    )
    .unwrap();
    assert!(u.sync_aggregate.participants() * 3 >= 512 * 2);
    assert!(orange_bls::eth::fast_aggregate_verify(
        &keys,
        &root,
        &u.sync_aggregate.signature
    ));
    assert!(!orange_bls::eth::fast_aggregate_verify(
        &keys[48..],
        &root,
        &u.sync_aggregate.signature
    ));
}

fn params() -> BridgeInParams {
    BridgeInParams {
        light_client: vec![1],
        verifier: vec![2],
        config: mainnet(),
        bootstrap: BOOTSTRAP.to_vec(),
        outbox: [0xAA; 20],
        limits: InboxLimits {
            delay: 600,
            window: 3600,
            max_messages: 10,
        },
    }
}

fn ctx(timestamp: u64) -> Context {
    Context {
        caller: [0x11; 20],
        timestamp,
    }
}

#[test]
fn the_client_follows_mainnet_across_a_period_boundary() {
    let c = Native;
    let mut store = Map::default();
    client::genesis(&c, &mut store, &params(), [0x60; 20]).unwrap();
    assert_eq!(finalized(&store).slot, 15_466_496);
    assert!(store.get(&keys::committee(1888)).is_some());
    // The finality update is signed by the committee of 1889, which the client does not know yet.
    let finality = client::submit_call(FINALITY, true);
    assert_eq!(
        client::call(&c, &mut store, &ctx(1000), &finality),
        Err(rejected(Rejection::WrongPeriod))
    );
    // Tampered versions of the period's update.
    let good = Update::decode_update(UPDATE, 512).unwrap();
    let mut bad_sig = good.clone();
    bad_sig.sync_aggregate.signature[10] ^= 1;
    let mut one_missing = good.clone();
    let first = (0..512)
        .find(|i| one_missing.sync_aggregate.signed(*i))
        .unwrap();
    one_missing.sync_aggregate.bits[first / 8] &= !(1 << (first % 8));
    let mut few = good.clone();
    few.sync_aggregate.bits = vec![0xFF; 40].into_iter().chain(vec![0; 24]).collect();
    let mut bad_finality = good.clone();
    bad_finality.finality_branch[3][0] ^= 1;
    let mut bad_committee = good.clone();
    bad_committee.next_sync_committee.as_mut().unwrap().1[2][0] ^= 1;
    let mut bad_execution = good.clone();
    bad_execution.attested.execution.gas_used += 1;
    for (update, why) in [
        (bad_sig, Rejection::BadSignature),
        (one_missing, Rejection::BadSignature),
        (few, Rejection::LowParticipation),
        (bad_finality, Rejection::BadFinalityBranch),
        (bad_committee, Rejection::BadCommitteeBranch),
        (bad_execution, Rejection::BadExecutionBranch),
    ] {
        let call = client::submit_call(&update.encode_update(512), false);
        assert_eq!(
            client::call(&c, &mut store, &ctx(1000), &call),
            Err(rejected(why)),
            "{why:?}"
        );
    }
    // The real update teaches the client the next committee without moving its header.
    let update = client::submit_call(UPDATE, false);
    assert_eq!(
        client::call(&c, &mut store, &ctx(1000), &update),
        Ok(vec![])
    );
    assert_eq!(finalized(&store).slot, 15_466_496);
    assert!(store.get(&keys::committee(1889)).is_some());
    // Submitting it again changes nothing, so it is refused.
    assert_eq!(
        client::call(&c, &mut store, &ctx(1001), &update),
        Err(rejected(Rejection::NotNewer))
    );
    // The finality update now rotates into period 1889 and finalizes block 26235823.
    assert_eq!(
        client::call(&c, &mut store, &ctx(2000), &finality),
        Ok(vec![])
    );
    let f = finalized(&store);
    assert_eq!((f.slot, f.block_number), (15_474_976, 26_235_823));
    assert!(store.get(&keys::committee(1888)).is_none());
    assert!(store.get(&keys::committee(1889)).is_some());
    assert!(store.get(&keys::committee(1890)).is_none());
    let view = client::query(&store, &client::u64_call(abi::EXECUTION_ROOT, 26_235_823)).unwrap();
    assert_eq!(
        hex(&view[..32]),
        "b6334d8344245c45c5665c261b743258145008ffe261f36b7bbd6a1e72fd828c"
    );
    assert_eq!(view[96 + 24..], 2600u64.to_be_bytes());
    let state = State {
        finalized_slot: f.slot,
        current: store.get(&keys::committee(1889)).unwrap(),
        next: None,
    };
    assert_eq!(
        sync::precheck(
            &mainnet(),
            &state,
            &Update::decode_finality_update(FINALITY, 512).unwrap()
        ),
        Err(Rejection::NotNewer)
    );
}

#[test]
fn a_real_eth_get_proof_verifies_against_the_finalized_state_root() {
    let c = Native;
    let v: serde_json::Value = serde_json::from_str(PROOF).unwrap();
    let state_root: [u8; 32] = unhex(v["stateRoot"].as_str().unwrap()).try_into().unwrap();
    let f = Update::decode_finality_update(FINALITY, 512).unwrap();
    assert_eq!(state_root, f.finalized.execution.state_root);
    let nodes = |list: &serde_json::Value| {
        list.as_array()
            .unwrap()
            .iter()
            .map(|n| unhex(n.as_str().unwrap()))
            .collect::<Vec<_>>()
    };
    let p = &v["proof"];
    let weth: [u8; 20] = unhex(p["address"].as_str().unwrap()).try_into().unwrap();
    let account = nodes(&p["accountProof"]);
    let storage_root = inbox::storage_root(&c, &state_root, &weth, &account).unwrap();
    assert_eq!(
        hex(&storage_root),
        p["storageHash"].as_str().unwrap().trim_start_matches("0x")
    );
    // Slot 0 holds the name, "Wrapped Ether", as a short string.
    let slot0 = &p["storageProof"][0];
    let value = mpt::verify(
        &c,
        &storage_root,
        &c.keccak256(&[0; 32]),
        &nodes(&slot0["proof"]),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        hex(&value[1..]),
        slot0["value"].as_str().unwrap().trim_start_matches("0x")
    );
    // Slot 0xdeadbeef is empty: the proof shows its absence.
    let mut key = [0u8; 32];
    key[28..].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let absent = &p["storageProof"][1];
    assert_eq!(
        mpt::verify(
            &c,
            &storage_root,
            &c.keccak256(&key),
            &nodes(&absent["proof"])
        ),
        Ok(None)
    );
    // The account proof against another root, or for another account, proves nothing.
    assert!(inbox::storage_root(&c, &[1; 32], &weth, &account).is_err());
    assert!(inbox::storage_root(&c, &state_root, &[0x22; 20], &account).is_err());
}
