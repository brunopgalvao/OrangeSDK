//! EIP-7702 set-code transactions: decoding against alloy's encoding of the
//! same transaction, the authorization payload against alloy's signature
//! hash, the signatures that name no authority, every malformation of the
//! type, and the intrinsic gas.

use alloy_consensus::{SignableTransaction, TxEip7702};
use alloy_eips::eip2718::Encodable2718;
use alloy_eips::eip2930::{AccessList, AccessListItem};
use alloy_eips::eip7702::{Authorization as AlloyAuthorization, SignedAuthorization};
use alloy_primitives::{Address, B256, Bytes, Signature as AlloySignature, U256};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use solo_eth::{AUTHORIZATION_GAS, Authorization, Error, SET_CODE_TX_TYPE, decode};
use solo_rlp::{encode_bytes, encode_list, encode_uint};
use tiny_keccak::{Hasher, Keccak};

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(data);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

fn address_of(key: &VerifyingKey) -> [u8; 20] {
    let point = key.to_encoded_point(false);
    keccak(&point.as_bytes()[1..])[12..].try_into().unwrap()
}

/// Signs `hash` and returns alloy's signature of it.
fn sign(key: &SigningKey, hash: &[u8; 32]) -> AlloySignature {
    let (sig, rid) = key.sign_prehash_recoverable(hash).unwrap();
    AlloySignature::new(
        U256::from_be_slice(&sig.r().to_bytes()),
        U256::from_be_slice(&sig.s().to_bytes()),
        rid.is_y_odd(),
    )
}

/// Recovers the address that produced `sig` over `hash`.
fn recover(hash: &[u8; 32], sig: &[u8; 65]) -> [u8; 20] {
    let key = VerifyingKey::recover_from_prehash(
        hash,
        &Signature::from_slice(&sig[..64]).unwrap(),
        RecoveryId::from_byte(sig[64]).unwrap(),
    )
    .unwrap();
    address_of(&key)
}

fn signed_authorization(
    key: &SigningKey,
    chain_id: u64,
    address: [u8; 20],
    nonce: u64,
) -> SignedAuthorization {
    let auth = AlloyAuthorization {
        chain_id: U256::from(chain_id),
        address: Address::from(address),
        nonce,
    };
    let sig = sign(key, &auth.signature_hash().0);
    auth.into_signed(sig)
}

#[test]
fn decodes_alloys_encoding() {
    let sender = SigningKey::from_slice(&[7; 32]).unwrap();
    let authority = SigningKey::from_slice(&[8; 32]).unwrap();
    let auths = vec![
        signed_authorization(&authority, 1337, [0xAA; 20], 5),
        signed_authorization(&authority, 0, [0xBB; 20], 6),
    ];
    let tx = TxEip7702 {
        chain_id: 1337,
        nonce: 3,
        gas_limit: 100_000,
        max_fee_per_gas: 30,
        max_priority_fee_per_gas: 2,
        to: Address::from([0x44; 20]),
        value: U256::from(9),
        access_list: AccessList(vec![AccessListItem {
            address: Address::from([0x55; 20]),
            storage_keys: vec![B256::from([1; 32])],
        }]),
        authorization_list: auths.clone(),
        input: Bytes::from(vec![0, 1, 2, 3]),
    };
    let signature = sign(&sender, &tx.signature_hash().0);
    let raw = tx.into_signed(signature).encoded_2718();
    assert_eq!(raw[0], SET_CODE_TX_TYPE);
    let decoded = decode(&raw).unwrap();
    assert_eq!(decoded.tx_type, 4);
    assert_eq!(decoded.chain_id, Some(1337));
    assert_eq!(
        (decoded.nonce, decoded.gas_limit, decoded.value),
        (3, 100_000, 9)
    );
    assert_eq!((decoded.gas_price, decoded.priority_fee), (30, Some(2)));
    assert_eq!(decoded.to, Some([0x44; 20]));
    assert_eq!(decoded.input, vec![0, 1, 2, 3]);
    assert_eq!(decoded.access_list.len(), 1);
    assert_eq!(decoded.authorization_list.len(), 2);
    assert_eq!(
        recover(&keccak(&decoded.signing_payload), &decoded.signature()),
        address_of(sender.verifying_key())
    );
    for (ours, theirs) in decoded.authorization_list.iter().zip(&auths) {
        assert_eq!(ours.address, theirs.address.0.0);
        assert_eq!(ours.nonce, theirs.nonce);
        assert_eq!(ours.chain_id, theirs.chain_id.to_be_bytes::<32>());
        assert_eq!(keccak(&ours.signing_payload()), theirs.signature_hash().0);
        let sig = ours.signature().unwrap();
        assert_eq!(
            recover(&keccak(&ours.signing_payload()), &sig),
            address_of(authority.verifying_key())
        );
        assert_eq!(
            theirs.recover_authority().unwrap().0.0,
            address_of(authority.verifying_key())
        );
    }
    // Intrinsic gas: the base, calldata, access list and 25 000 per authorization.
    assert_eq!(
        decoded.intrinsic_gas(),
        21_000 + 4 + 16 * 3 + 2_400 + 1_900 + 2 * AUTHORIZATION_GAS
    );
    assert_eq!(decoded.max_cost(), Some(100_000 * 30 + 9));
}

fn authorization(y_parity: u8, r: [u8; 32], s: [u8; 32]) -> Authorization {
    Authorization {
        chain_id: [0; 32],
        address: [1; 20],
        nonce: 0,
        y_parity,
        r,
        s,
    }
}

#[test]
fn signatures_that_name_no_authority() {
    let mut high = [0xFF; 32];
    high[0] = 0x7F;
    assert!(authorization(0, [1; 32], [1; 32]).signature().is_some());
    assert!(authorization(1, [1; 32], [1; 32]).signature().is_some());
    assert_eq!(authorization(2, [1; 32], [1; 32]).signature(), None);
    assert_eq!(authorization(0, [0; 32], [1; 32]).signature(), None);
    assert_eq!(authorization(0, [1; 32], [0; 32]).signature(), None);
    assert_eq!(authorization(0, [1; 32], high).signature(), None);
    // A chain id is written without leading zeros, and a zero nonce as the empty string.
    let mut chain = [0; 32];
    chain[31] = 1;
    let auth = Authorization {
        chain_id: chain,
        ..authorization(0, [1; 32], [1; 32])
    };
    let mut body = Vec::new();
    encode_uint(1, &mut body);
    encode_bytes(&[1; 20], &mut body);
    encode_uint(0, &mut body);
    let mut expected = vec![0x05];
    encode_list(&body, &mut expected);
    assert_eq!(auth.signing_payload(), expected);
}

/// A set-code transaction from its fields, the authorization list and the
/// recipient given encoded, with a signature that need not verify.
fn set_code(to: &[u8], auths: &[u8], parity: u128) -> Vec<u8> {
    let mut fields = Vec::new();
    for n in [1u128, 0, 1, 2, 50_000] {
        encode_uint(n, &mut fields);
    }
    fields.extend_from_slice(to);
    encode_uint(0, &mut fields);
    encode_bytes(&[], &mut fields);
    encode_list(&[], &mut fields);
    fields.extend_from_slice(auths);
    encode_uint(parity, &mut fields);
    encode_uint(1, &mut fields);
    encode_uint(1, &mut fields);
    let mut out = vec![4];
    encode_list(&fields, &mut out);
    out
}

fn list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_list(&items.concat(), &mut out);
    out
}

fn entry(chain_id: &[u8], address: &[u8], nonce: &[u8], parity: &[u8]) -> Vec<u8> {
    signed_entry(chain_id, address, nonce, parity, &[1], &[1])
}

/// An authorization entry with every field given as its encoded string.
fn signed_entry(
    chain_id: &[u8],
    address: &[u8],
    nonce: &[u8],
    parity: &[u8],
    r: &[u8],
    s: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    for field in [chain_id, address, nonce, parity, r, s] {
        encode_bytes(field, &mut body);
    }
    let mut out = Vec::new();
    encode_list(&body, &mut out);
    out
}

#[test]
fn malformations() {
    let mut to = Vec::new();
    encode_bytes(&[2; 20], &mut to);
    let good = entry(&[1], &[3; 20], &[], &[1]);
    let tx = decode(&set_code(&to, &list(std::slice::from_ref(&good)), 0)).unwrap();
    assert_eq!(tx.authorization_list[0].y_parity, 1);
    assert_eq!(tx.authorization_list[0].chain_id[31], 1);
    // An r and an s of 32 bytes decode, and a short one is left-padded.
    let full = signed_entry(&[1], &[3; 20], &[], &[1], &[0xFF; 32], &[0x7F; 3]);
    let auth = &decode(&set_code(&to, &list(&[full]), 0))
        .unwrap()
        .authorization_list[0];
    let mut s = [0; 32];
    s[29..].copy_from_slice(&[0x7F; 3]);
    assert_eq!((auth.r, auth.s), ([0xFF; 32], s));
    // A parity byte above one decodes; it only names no authority.
    let odd = entry(&[], &[3; 20], &[], &[0x7F]);
    assert_eq!(
        decode(&set_code(&to, &list(&[odd]), 0))
            .unwrap()
            .authorization_list[0]
            .signature(),
        None
    );
    let cases = [
        // No recipient: a set-code transaction cannot create.
        (
            set_code(&[0x80], &list(std::slice::from_ref(&good)), 0),
            Error::Malformed,
        ),
        // An empty authorization list.
        (set_code(&to, &list(&[]), 0), Error::Malformed),
        // Not a list, an entry that is not a list, an entry of five fields.
        (set_code(&to, &[0x80], 0), Error::Malformed),
        (set_code(&to, &list(&[vec![0x80]]), 0), Error::Malformed),
        (
            set_code(&to, &list(&[list(&vec![vec![0x80]; 5])]), 0),
            Error::Malformed,
        ),
        // A chain id over 32 bytes, a short address, a nonce over 64 bits, a parity over 8 bits.
        (
            set_code(&to, &list(&[entry(&[1; 33], &[3; 20], &[], &[])]), 0),
            Error::Malformed,
        ),
        (
            set_code(&to, &list(&[entry(&[1], &[3; 19], &[], &[])]), 0),
            Error::Malformed,
        ),
        (
            set_code(&to, &list(&[entry(&[1], &[3; 20], &[1; 9], &[])]), 0),
            Error::Malformed,
        ),
        (
            set_code(&to, &list(&[entry(&[1], &[3; 20], &[], &[1, 0])]), 0),
            Error::Malformed,
        ),
        // An r or an s over 32 bytes.
        (
            set_code(
                &to,
                &list(&[signed_entry(&[1], &[3; 20], &[], &[], &[1; 33], &[1])]),
                0,
            ),
            Error::Malformed,
        ),
        (
            set_code(
                &to,
                &list(&[signed_entry(&[1], &[3; 20], &[], &[], &[1], &[1; 33])]),
                0,
            ),
            Error::Malformed,
        ),
        // The transaction's own parity is checked as for every typed transaction.
        (set_code(&to, &list(&[good]), 2), Error::BadSignature),
    ];
    for (raw, expected) in cases {
        assert_eq!(decode(&raw), Err(expected), "{raw:02x?}");
    }
    // Eight fields after the fees are a dynamic-fee layout, not a set-code one.
    let mut short = vec![4];
    encode_list(&[0x80; 12], &mut short);
    assert_eq!(decode(&short), Err(Error::Malformed));
}
