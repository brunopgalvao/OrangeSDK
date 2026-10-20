//! The bridge's contracts: committed fixtures match their sources, and the
//! `EthereumOutbox`, run on revm as Ethereum runs it, stores exactly the
//! message hash the inbox proves, at the slot it proves it.

use solo_ethlc::abi::{self, word};
use solo_ethlc::inbox::{self, Message};
use solo_ethlc::testing::{Evm, Native, hex, unhex};
use solo_ethlc::{Crypto, Hash};

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contracts");

fn fixture(name: &str) -> Vec<u8> {
    unhex(&std::fs::read_to_string(format!("{ROOT}/build/{name}")).unwrap())
}

#[test]
fn fixtures_match_their_sources() {
    let manifest = std::fs::read_to_string(format!("{ROOT}/build/SOURCES")).unwrap();
    let mut files = Vec::new();
    for line in manifest.lines() {
        let (hash, path) = line.split_once("  ").unwrap();
        let source = std::fs::read(format!("{ROOT}/{path}")).unwrap();
        assert_eq!(
            hex(&Native.sha256(&source)),
            hash,
            "{path} changed: run tools/build-contracts.sh"
        );
        files.push(path);
    }
    for path in [
        "IEthereumLightClient.sol",
        "IMessageVerifier.sol",
        "EthereumOutbox.sol",
        "EthereumInbox.sol",
        "test/EthereumMessageRecipient.sol",
    ] {
        assert!(files.contains(&path), "{path} missing from SOURCES");
    }
    for name in [
        "EthereumOutbox",
        "EthereumInbox",
        "EthereumMessageRecipient",
    ] {
        assert!(!fixture(&format!("{name}.bin")).is_empty());
        assert!(!fixture(&format!("{name}.bin-runtime")).is_empty());
        let abi = std::fs::read_to_string(format!("{ROOT}/build/{name}.abi")).unwrap();
        assert!(abi.starts_with('['), "{name}");
    }
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
    let messages: Vec<Message> = payloads
        .iter()
        .enumerate()
        .map(|(nonce, payload)| Message {
            nonce: nonce as u64,
            sender,
            recipient,
            gas_limit: 100_000 + nonce as u64,
            payload: payload.to_vec(),
        })
        .collect();
    for message in &messages {
        let out = evm.call(sender, outbox, message.send_call()).unwrap();
        assert_eq!(out, word(message.nonce));
    }
    // A bad call reverts.
    assert!(evm.call(sender, outbox, abi::SEND.to_vec()).is_err());
    assert_eq!(evm.storage(&outbox, &word(1)), word(2), "nextNonce");
    let state = evm.state();
    let root = state.root();
    for message in &messages {
        let slot = inbox::slot(&c, message.nonce);
        assert_eq!(evm.storage(&outbox, &slot), message.hash(&c, 7));
        let (account_proof, storage_proof) = state.proof(&outbox, &slot);
        assert_eq!(
            inbox::verify(
                &c,
                &root,
                &outbox,
                7,
                message,
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
                message,
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
        let starved = Message {
            gas_limit: 21_000,
            ..message.clone()
        };
        assert!(
            inbox::verify(
                &c,
                &root,
                &outbox,
                7,
                &starved,
                &account_proof,
                &storage_proof
            )
            .is_err()
        );
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
                message,
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
        gas_limit: 0,
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
