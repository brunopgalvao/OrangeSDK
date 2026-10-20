//! Transaction decoding against the EIP-155 example, round trips of every
//! type signed with k256, the malformations each field can have, and the
//! intrinsic-gas rules pinned to numbers.

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use solo_eth::{AccessItem, Error, Tx, decode, legacy_unsigned, logs_bloom};
use solo_rlp::{encode_bytes, encode_list, encode_uint};
use tiny_keccak::{Hasher, Keccak};

fn keccak(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(data);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn address_of(key: &VerifyingKey) -> [u8; 20] {
    let point = key.to_encoded_point(false);
    let mut out = [0u8; 20];
    out.copy_from_slice(&keccak(&point.as_bytes()[1..])[12..]);
    out
}

fn recover(tx: &Tx) -> [u8; 20] {
    let sig = tx.signature();
    let key = VerifyingKey::recover_from_prehash(
        &keccak(&tx.signing_payload),
        &Signature::from_slice(&sig[..64]).unwrap(),
        RecoveryId::from_byte(sig[64]).unwrap(),
    )
    .unwrap();
    address_of(&key)
}

fn strip(b: &[u8]) -> Vec<u8> {
    let skip = b.iter().take_while(|x| **x == 0).count();
    b[skip..].to_vec()
}

#[test]
fn eip155_example() {
    // The worked example in EIP-155.
    let raw = hex(
        "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83",
    );
    let tx = decode(&raw).unwrap();
    assert_eq!(tx.tx_type, 0);
    assert_eq!(tx.chain_id, Some(1));
    assert_eq!(tx.nonce, 9);
    assert_eq!(tx.gas_price, 20_000_000_000);
    assert_eq!(tx.gas_limit, 21_000);
    assert_eq!(tx.to, Some([0x35; 20]));
    assert_eq!(tx.value, 1_000_000_000_000_000_000);
    assert!(tx.input.is_empty());
    assert_eq!(
        tx.signing_payload,
        hex(
            "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080"
        )
    );
    assert_eq!(tx.recovery_id(), 0);
    let key = SigningKey::from_slice(&[0x46; 32]).unwrap();
    assert_eq!(recover(&tx), address_of(key.verifying_key()));
}

fn sign(key: &SigningKey, payload: &[u8]) -> (Vec<u8>, Vec<u8>, u8) {
    let (sig, rid) = key.sign_prehash_recoverable(&keccak(payload)).unwrap();
    (
        strip(&sig.r().to_bytes()),
        strip(&sig.s().to_bytes()),
        rid.to_byte(),
    )
}

fn access_list_rlp(items: &[AccessItem]) -> Vec<u8> {
    let mut body = Vec::new();
    for item in items {
        let mut pair = Vec::new();
        encode_bytes(&item.address, &mut pair);
        let mut keys = Vec::new();
        for k in &item.keys {
            encode_bytes(k, &mut keys);
        }
        encode_list(&keys, &mut pair);
        encode_list(&pair, &mut body);
    }
    let mut out = Vec::new();
    encode_list(&body, &mut out);
    out
}

/// A signed typed transaction: `fields` are the unsigned RLP items, already encoded.
fn typed(key: &SigningKey, tx_type: u8, fields: &[u8]) -> Vec<u8> {
    let mut unsigned = vec![tx_type];
    encode_list(fields, &mut unsigned);
    let (r, s, parity) = sign(key, &unsigned);
    let mut body = fields.to_vec();
    encode_uint(u128::from(parity), &mut body);
    encode_bytes(&r, &mut body);
    encode_bytes(&s, &mut body);
    let mut out = vec![tx_type];
    encode_list(&body, &mut out);
    out
}

#[test]
fn every_type_round_trips() {
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let me = address_of(key.verifying_key());
    let list = vec![AccessItem {
        address: [9; 20],
        keys: vec![[1; 32], [2; 32]],
    }];
    // Pre-EIP-155 legacy creation.
    let body = legacy_unsigned(0, 5, 100_000, None, 0, &[0x60, 0x00]);
    let mut unsigned = Vec::new();
    encode_list(&body, &mut unsigned);
    let (r, s, rid) = sign(&key, &unsigned);
    let mut signed = body.clone();
    encode_uint(27 + u128::from(rid), &mut signed);
    encode_bytes(&r, &mut signed);
    encode_bytes(&s, &mut signed);
    let mut raw = Vec::new();
    encode_list(&signed, &mut raw);
    let tx = decode(&raw).unwrap();
    assert_eq!((tx.tx_type, tx.chain_id, tx.to), (0, None, None));
    // The helper writes the recipient as twenty bytes.
    let with_to = legacy_unsigned(1, 2, 3, Some([5; 20]), 4, &[]);
    assert_eq!(&with_to[3..24], &[[0x94].as_slice(), &[5; 20]].concat()[..]);
    assert_eq!(recover(&tx), me);
    // EIP-2930.
    let mut fields = Vec::new();
    encode_uint(1337, &mut fields);
    encode_uint(3, &mut fields);
    encode_uint(7, &mut fields);
    encode_uint(50_000, &mut fields);
    encode_bytes(&[4; 20], &mut fields);
    encode_uint(11, &mut fields);
    encode_bytes(&[0, 1, 2], &mut fields);
    fields.extend(access_list_rlp(&list));
    let tx = decode(&typed(&key, 1, &fields)).unwrap();
    assert_eq!(tx.tx_type, 1);
    assert_eq!(tx.chain_id, Some(1337));
    assert_eq!(
        (tx.nonce, tx.gas_price, tx.gas_limit, tx.value),
        (3, 7, 50_000, 11)
    );
    assert_eq!(tx.priority_fee, None);
    assert_eq!(tx.access_list, list);
    assert_eq!(tx.input, vec![0, 1, 2]);
    assert_eq!(recover(&tx), me);
    // EIP-1559.
    let mut fields = Vec::new();
    encode_uint(1337, &mut fields);
    encode_uint(4, &mut fields);
    encode_uint(2, &mut fields);
    encode_uint(30, &mut fields);
    encode_uint(60_000, &mut fields);
    encode_bytes(&[], &mut fields);
    encode_uint(0, &mut fields);
    encode_bytes(&[0xFE], &mut fields);
    fields.extend(access_list_rlp(&[]));
    let tx = decode(&typed(&key, 2, &fields)).unwrap();
    assert_eq!(tx.tx_type, 2);
    assert_eq!((tx.gas_price, tx.priority_fee), (30, Some(2)));
    assert_eq!(tx.to, None);
    assert_eq!(recover(&tx), me);
    assert_eq!(tx.effective_gas_price(10), Some(12));
    assert_eq!(tx.effective_gas_price(29), Some(30));
    assert_eq!(tx.effective_gas_price(31), None);
    assert_eq!(tx.max_cost(), Some(60_000 * 30));
}

#[test]
#[allow(clippy::too_many_lines)]
fn malformations() {
    let cases: Vec<(Vec<u8>, Error)> = vec![
        (vec![], Error::Malformed),
        (vec![0x03, 0xC0], Error::Unsupported),
        (vec![0x04], Error::Unsupported),
        (vec![0x01, 0xC0], Error::Malformed),
        (vec![0x02, 0xC0], Error::Malformed),
        (vec![0x01, 0x80], Error::Malformed),
        (vec![0xC0], Error::Malformed),
        (vec![0x80], Error::Malformed),
        (vec![0xC1], Error::Malformed),
    ];
    for (raw, expected) in cases {
        assert_eq!(decode(&raw), Err(expected), "{raw:02x?}");
    }
    // Field-by-field: start from a valid legacy body and break one field at a time.
    let good = |v: u128, r: &[u8], s: &[u8], to: &[u8], nonce: &[u8]| {
        let mut body = Vec::new();
        body.extend_from_slice(nonce);
        encode_uint(1, &mut body);
        encode_uint(21_000, &mut body);
        encode_bytes(to, &mut body);
        encode_uint(0, &mut body);
        encode_bytes(&[], &mut body);
        encode_uint(v, &mut body);
        encode_bytes(r, &mut body);
        encode_bytes(s, &mut body);
        let mut out = Vec::new();
        encode_list(&body, &mut out);
        out
    };
    let n = {
        let mut x = Vec::new();
        encode_uint(0, &mut x);
        x
    };
    assert!(decode(&good(37, &[1], &[1], &[2; 20], &n)).is_ok());
    assert_eq!(
        decode(&good(30, &[1], &[1], &[2; 20], &n)),
        Err(Error::BadSignature)
    );
    assert_eq!(
        decode(&good(37, &[0], &[1], &[2; 20], &n)),
        Err(Error::Malformed),
        "leading zero"
    );
    assert_eq!(
        decode(&good(37, &[], &[1], &[2; 20], &n)),
        Err(Error::BadSignature),
        "r zero"
    );
    assert_eq!(
        decode(&good(37, &[1], &[], &[2; 20], &n)),
        Err(Error::BadSignature),
        "s zero"
    );
    assert_eq!(
        decode(&good(37, &[1], &[0xFF; 32], &[2; 20], &n)),
        Err(Error::BadSignature),
        "high s"
    );
    assert_eq!(
        decode(&good(37, &[1], &[1], &[2; 5], &n)),
        Err(Error::Malformed),
        "short to"
    );
    assert_eq!(
        decode(&good(37, &[1], &[1], &[2; 20], &[0xC0])),
        Err(Error::Malformed),
        "list nonce"
    );
    // Typed: bad parity, bad access lists.
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let typed_with = |list: &[u8], parity: u128| {
        let mut fields = Vec::new();
        encode_uint(1, &mut fields);
        encode_uint(0, &mut fields);
        encode_uint(1, &mut fields);
        encode_uint(21_000, &mut fields);
        encode_bytes(&[1; 20], &mut fields);
        encode_uint(0, &mut fields);
        encode_bytes(&[], &mut fields);
        fields.extend_from_slice(list);
        let mut unsigned = vec![1];
        encode_list(&fields, &mut unsigned);
        let (r, s, _) = sign(&key, &unsigned);
        encode_uint(parity, &mut fields);
        encode_bytes(&r, &mut fields);
        encode_bytes(&s, &mut fields);
        let mut out = vec![1];
        encode_list(&fields, &mut out);
        out
    };
    let empty = access_list_rlp(&[]);
    assert!(decode(&typed_with(&empty, 0)).is_ok());
    assert_eq!(decode(&typed_with(&empty, 2)), Err(Error::BadSignature));
    let list_of = |inner: &[u8]| {
        let mut out = Vec::new();
        encode_list(inner, &mut out);
        out
    };
    // Not a list; an entry that is not a list; an entry of one item; a short address; a bad key list.
    assert_eq!(decode(&typed_with(&[0x80], 0)), Err(Error::Malformed));
    assert_eq!(
        decode(&typed_with(&list_of(&[0x80]), 0)),
        Err(Error::Malformed)
    );
    assert_eq!(
        decode(&typed_with(&list_of(&list_of(&[0x80])), 0)),
        Err(Error::Malformed)
    );
    let mut entry = Vec::new();
    encode_bytes(&[1; 19], &mut entry);
    encode_list(&[], &mut entry);
    assert_eq!(
        decode(&typed_with(&list_of(&list_of(&entry)), 0)),
        Err(Error::Malformed)
    );
    let mut entry = Vec::new();
    encode_bytes(&[1; 20], &mut entry);
    encode_bytes(&[], &mut entry);
    assert_eq!(
        decode(&typed_with(&list_of(&list_of(&entry)), 0)),
        Err(Error::Malformed)
    );
    let mut entry = Vec::new();
    encode_bytes(&[1; 20], &mut entry);
    let mut keys = Vec::new();
    encode_bytes(&[1; 31], &mut keys);
    encode_list(&keys, &mut entry);
    assert_eq!(
        decode(&typed_with(&list_of(&list_of(&entry)), 0)),
        Err(Error::Malformed)
    );
    assert!(format!("{:?}", Error::Malformed).contains("Malformed"));
}

#[test]
fn gas_rules() {
    let base = Tx {
        tx_type: 2,
        chain_id: Some(1),
        nonce: 0,
        gas_price: 10,
        priority_fee: Some(1),
        gas_limit: 21_000,
        to: Some([1; 20]),
        value: 5,
        input: vec![],
        access_list: vec![],
        v: 0,
        r: [1; 32],
        s: [1; 32],
        signing_payload: vec![],
    };
    assert_eq!(base.intrinsic_gas(), 21_000);
    assert_eq!(base.min_gas_limit(), 21_000);
    let call = Tx {
        input: vec![0, 0, 1, 2],
        access_list: vec![AccessItem {
            address: [2; 20],
            keys: vec![[0; 32]; 2],
        }],
        ..base.clone()
    };
    // 21000 + 2*4 + 2*16 + 2400 + 2*1900.
    assert_eq!(call.intrinsic_gas(), 21_000 + 8 + 32 + 2_400 + 3_800);
    assert_eq!(call.tokens(), 2 + 8);
    assert_eq!(call.floor_gas(), 21_000 + 100);
    // A creation pays 32000 plus two gas per initcode word.
    let create = Tx {
        to: None,
        input: vec![1; 33],
        ..base.clone()
    };
    assert_eq!(create.intrinsic_gas(), 21_000 + 33 * 16 + 32_000 + 2 * 2);
    assert!(create.initcode_ok());
    assert!(
        !Tx {
            to: None,
            input: vec![1; solo_eth::MAX_INITCODE_SIZE + 1],
            ..base.clone()
        }
        .initcode_ok()
    );
    // Calldata-heavy transactions are bounded below by the EIP-7623 floor.
    let heavy = Tx {
        input: vec![1; 1_000],
        ..base.clone()
    };
    assert_eq!(heavy.intrinsic_gas(), 21_000 + 16_000);
    assert_eq!(heavy.floor_gas(), 21_000 + 40_000);
    assert_eq!(heavy.min_gas_limit(), 61_000);
    assert_eq!(solo_eth::MAX_TX_GAS, 16_777_216);
    let legacy = Tx {
        tx_type: 0,
        priority_fee: None,
        ..base.clone()
    };
    assert_eq!(legacy.effective_gas_price(3), Some(10));
    assert_eq!(
        Tx {
            gas_price: u128::MAX,
            ..base
        }
        .max_cost(),
        None
    );
}

#[test]
fn bloom() {
    assert_eq!(logs_bloom(&[], keccak), [0; 256]);
    let address = [0x11; 20];
    let topics = [[0x22; 32]];
    let bloom = logs_bloom(&[(&address, &topics[..])], keccak);
    let bits: u32 = bloom.iter().map(|b| b.count_ones()).sum();
    assert!((1..=6).contains(&bits));
    // Setting the same entries twice changes nothing.
    assert_eq!(
        logs_bloom(&[(&address, &topics[..]), (&address, &topics[..])], keccak),
        bloom
    );
    // Known value: the bloom of a single address is three bits from its keccak.
    let h = keccak(&address);
    let mut expected = [0u8; 256];
    for i in [0, 2, 4] {
        let bit = (usize::from(h[i]) << 8 | usize::from(h[i + 1])) & 2047;
        expected[255 - bit / 8] |= 1 << (bit % 8);
    }
    assert_eq!(logs_bloom(&[(&address, &[][..])], keccak), expected);
}
