//! Transactions that allocate and drop memory for their whole gas limit must
//! run to completion inside the guest, as they do on Ethereum: the EVM's
//! scratch memory (call inputs and return data, call frames) is garbage once
//! a call returns, and the guest's heap must take it back rather than run out.

use k256::ecdsa::SigningKey;
use solo_abi::chain::{Allocation, call_status};
use solo_abi::codec::Seq;
use solo_abi::conformance::{Case, Env};
use solo_conformance::{GUEST, Runner};
use solo_host::Backend;
use solo_host::hash::keccak256;
use solo_rlp::{encode_bytes, encode_list, encode_uint};

/// Osaka's per-transaction gas cap (EIP-7825).
const TX_GAS: u64 = 1 << 24;
const CONTRACT: [u8; 20] = [0xC0; 20];
const CALLEE: [u8; 20] = [0xCA; 20];

fn strip(bytes: &[u8]) -> &[u8] {
    &bytes[bytes.iter().take_while(|b| **b == 0).count()..]
}

/// A pre-EIP-155 legacy call from the key `[1; 32]` and that key's address.
fn signed_call(to: [u8; 20], gas: u64) -> (Vec<u8>, [u8; 20]) {
    let key = SigningKey::from_slice(&[1; 32]).unwrap();
    let point = key.verifying_key().to_encoded_point(false);
    let from: [u8; 20] = keccak256(&point.as_bytes()[1..])[12..].try_into().unwrap();
    let mut fields = Vec::new();
    encode_uint(0, &mut fields);
    encode_uint(10, &mut fields);
    encode_uint(u128::from(gas), &mut fields);
    encode_bytes(&to, &mut fields);
    encode_uint(0, &mut fields);
    encode_bytes(&[], &mut fields);
    let mut payload = Vec::new();
    encode_list(&fields, &mut payload);
    let (sig, rid) = key.sign_prehash_recoverable(&keccak256(&payload)).unwrap();
    encode_uint(27 + u128::from(rid.to_byte()), &mut fields);
    encode_bytes(strip(&sig.r().to_bytes()), &mut fields);
    encode_bytes(strip(&sig.s().to_bytes()), &mut fields);
    let mut tx = Vec::new();
    encode_list(&fields, &mut tx);
    (tx, from)
}

fn case(code: Vec<u8>) -> Case {
    let (tx, from) = signed_call(CONTRACT, TX_GAS);
    let account = |address, balance, code: Vec<u8>| Allocation {
        address,
        balance,
        nonce: u64::from(!code.is_empty()),
        code,
        storage: Seq(Vec::new()),
    };
    Case {
        env: Env {
            chain_id: 1,
            gas_limit: 30_000_000,
            base_fee: 7,
            timestamp: 1_000,
            number: 1,
            ..Env::default()
        },
        allocations: Seq(vec![
            account(from, 1_000_000_000_000_000_000, Vec::new()),
            account(CONTRACT, 0, code),
            account(CALLEE, 0, vec![0x00]),
        ]),
        tx,
    }
}

/// `loop: CALL(gas, target, 0, 0, args, 0, 0); POP; JUMP loop`, until out of gas.
fn call_loop(target: [u8; 20], args: u16) -> Vec<u8> {
    let mut code = vec![0x5B, 0x60, 0x00, 0x60, 0x00, 0x61];
    code.extend_from_slice(&args.to_be_bytes());
    code.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0x73]);
    code.extend_from_slice(&target);
    code.extend_from_slice(&[0x5A, 0xF1, 0x50, 0x60, 0x00, 0x56]);
    code
}

fn runs_out_of_gas(code: &[u8]) {
    for backend in [Backend::Interpreter, Backend::Native] {
        let mut runner = Runner::new(GUEST, backend).unwrap();
        let executed = runner
            .run(&case(code.to_vec()))
            .unwrap_or_else(|status| panic!("the guest ended with {status:?} on {backend:?}"));
        assert_eq!(executed.outcome.status, call_status::HALT, "{backend:?}");
        assert_eq!(executed.outcome.gas_used, TX_GAS, "{backend:?}");
    }
}

/// Every iteration copies 32 KiB into the identity precompile and gets 32 KiB
/// back: about 10 bytes of garbage per unit of gas.
#[test]
fn identity_churn_runs_out_of_gas() {
    runs_out_of_gas(&call_loop(
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4],
        0x8000,
    ));
}

/// Every iteration enters and leaves a call frame of a contract that stops.
#[test]
fn call_frame_churn_runs_out_of_gas() {
    runs_out_of_gas(&call_loop(CALLEE, 0));
}
