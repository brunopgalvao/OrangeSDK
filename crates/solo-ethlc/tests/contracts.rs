//! The bridge's contracts: committed fixtures match their sources, and the
//! `EthereumOutbox`, run on revm as Ethereum runs it, stores exactly the
//! message hash the inbox proves, at the slot it proves it.

use solo_ethlc::abi::{address_word, word};
use solo_ethlc::inbox::{self, Message};
use solo_ethlc::testing::{Evm, Native, hex, unhex};
use solo_ethlc::{Crypto, Hash};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts");

fn fixture(name: &str) -> Vec<u8> {
    unhex(&std::fs::read_to_string(format!("{ROOT}/fixtures/{name}")).unwrap())
}

#[test]
fn fixtures_match_their_sources() {
    let manifest = std::fs::read_to_string(format!("{ROOT}/fixtures/sources.sha256")).unwrap();
    let mut files = 0;
    for line in manifest.lines() {
        let (hash, path) = line.split_once("  ").unwrap();
        let source = std::fs::read(format!("{ROOT}/{path}")).unwrap();
        assert_eq!(
            hex(&Native.sha256(&source)),
            hash,
            "{path} changed: run tools/build-contracts.sh"
        );
        files += 1;
    }
    assert_eq!(files, 5);
    for name in ["EthereumOutbox", "SoloInbox", "MessageRecipient"] {
        assert!(!fixture(&format!("{name}.bin")).is_empty());
        assert!(!fixture(&format!("{name}.runtime")).is_empty());
        let abi = std::fs::read_to_string(format!("{ROOT}/fixtures/{name}.abi.json")).unwrap();
        assert!(abi.starts_with('['), "{name}");
    }
}

fn send_call(recipient: &[u8; 20], payload: &[u8]) -> Vec<u8> {
    let mut data = vec![0xc8, 0x9a, 0xcc, 0x86];
    data.extend_from_slice(&address_word(recipient));
    data.extend_from_slice(&word(64));
    data.extend_from_slice(&word(payload.len() as u64));
    data.extend_from_slice(payload);
    data.resize(4 + 96 + payload.len().div_ceil(32) * 32, 0);
    data
}

#[test]
#[allow(clippy::too_many_lines)]
fn the_outbox_stores_the_hash_the_inbox_proves() {
    let c = Native;
    let mut evm = Evm::new();
    let deployer = [0xD0; 20];
    let sender = [0x5E; 20];
    let recipient = [0x7E; 20];
    let mut init = fixture("EthereumOutbox.bin");
    init.extend_from_slice(&word(7));
    let outbox = evm.deploy(deployer, init).unwrap();
    let payloads: [&[u8]; 2] = [b"hello solo", &[0xAB; 100]];
    for (nonce, payload) in payloads.iter().enumerate() {
        let out = evm
            .call(sender, outbox, send_call(&recipient, payload))
            .unwrap();
        assert_eq!(out, word(nonce as u64));
    }
    // A bad call reverts.
    assert!(
        evm.call(sender, outbox, vec![0xc8, 0x9a, 0xcc, 0x86])
            .is_err()
    );
    assert_eq!(evm.storage(&outbox, &word(1)), word(2), "nextNonce");
    let state = evm.state();
    let root = state.root();
    for (nonce, payload) in payloads.iter().enumerate() {
        let message = Message {
            nonce: nonce as u64,
            sender,
            recipient,
            payload: payload.to_vec(),
        };
        let slot = inbox::slot(&c, message.nonce);
        assert_eq!(evm.storage(&outbox, &slot), message.hash(&c, 7));
        let (account_proof, storage_proof) = state.proof(&outbox, &slot);
        assert_eq!(
            inbox::verify(
                &c,
                &root,
                &outbox,
                7,
                &message,
                &account_proof,
                &storage_proof
            ),
            Ok(())
        );
        // Another chain id, payload, sender or recipient is not what was stored.
        assert!(
            inbox::verify(
                &c,
                &root,
                &outbox,
                8,
                &message,
                &account_proof,
                &storage_proof
            )
            .is_err()
        );
        let other = Message {
            payload: b"other".to_vec(),
            ..message.clone()
        };
        assert!(
            inbox::verify(
                &c,
                &root,
                &outbox,
                7,
                &other,
                &account_proof,
                &storage_proof
            )
            .is_err()
        );
        let spoofed = Message {
            sender: recipient,
            ..message.clone()
        };
        assert!(
            inbox::verify(
                &c,
                &root,
                &outbox,
                7,
                &spoofed,
                &account_proof,
                &storage_proof
            )
            .is_err()
        );
        // The proofs of another account do not stand in for the outbox's.
        assert!(
            inbox::verify(
                &c,
                &root,
                &deployer,
                7,
                &message,
                &account_proof,
                &storage_proof
            )
            .is_err()
        );
    }
    // A message never sent: its slot's proof shows absence, which proves nothing.
    let unsent = Message {
        nonce: 2,
        sender,
        recipient,
        payload: vec![],
    };
    let slot: Hash = inbox::slot(&c, 2);
    let (account_proof, storage_proof) = state.proof(&outbox, &slot);
    assert!(
        inbox::verify(
            &c,
            &root,
            &outbox,
            7,
            &unsent,
            &account_proof,
            &storage_proof
        )
        .is_err()
    );
}
