//! Modules invoked from chain state (spec 05 §4.4.1).

use super::*;
use crate::code::{CODE_PREFIX, code_key, load_cost};

/// A module that reports 7 and 9.
fn reporter() -> Vec<u8> {
    let mut body = vec![li(Reg::A0, 7), li(Reg::A1, 9)];
    body.extend(report());
    module(&imports(), &body, &[])
}

fn call(exec: &mut Executor<MemStorage>, hash: &[u8; 32], gas: i64, cap: Capability) -> CallResult {
    exec.call(hash, NS, b"", gas, cap, Flags::default())
}

fn not_found() -> Termination {
    Termination::HostError(HostStatus::NotFound.code())
}

#[test]
fn keys_and_costs() {
    assert_eq!(CODE_PREFIX, b"code/");
    assert_eq!(code_key(&[1; 32]).len(), 37);
    assert!(code_key(&[1; 32]).starts_with(CODE_PREFIX));
    assert_eq!(load_cost(0), 0);
    assert_eq!(load_cost(1), 1);
    assert_eq!(load_cost(64), 2);
    assert_eq!(load_cost(65), 3);
}

#[test]
fn modules_run_from_state_while_their_bytes_are_there() {
    let bytes = reporter();
    let hash = keccak256(&bytes);
    let mut exec = executor();
    let missing = call(&mut exec, &hash, 10_000, Capability::Sandboxed);
    assert_eq!(missing.status, not_found());
    assert!(!missing.started);

    exec.state_mut().set(&code_key(&hash), &bytes);
    let from_state = call(&mut exec, &hash, 10_000, Capability::Sandboxed);
    assert_eq!(regs(&from_state), (7, 9));
    // Again, now from the cache: the same gas, the load cost included.
    let cached = call(&mut exec, &hash, 10_000, Capability::Sandboxed);
    assert_eq!(cached, from_state);

    // Gone from state: the cached copy does not run.
    exec.state_mut().delete(&code_key(&hash));
    assert_eq!(
        call(&mut exec, &hash, 10_000, Capability::Sandboxed).status,
        not_found()
    );

    // Different bytes under the key never run, cached or not.
    exec.state_mut().set(&code_key(&hash), b"not the module");
    assert_eq!(
        call(&mut exec, &hash, 10_000, Capability::Sandboxed).status,
        not_found()
    );

    // An explicit load takes over: no state check, no load cost.
    exec.state_mut().delete(&code_key(&hash));
    assert_eq!(exec.load(&bytes, Capability::Sandboxed).unwrap(), hash);
    let explicit = call(&mut exec, &hash, 10_000, Capability::Sandboxed);
    assert_eq!(regs(&explicit), (7, 9));
    assert_eq!(
        from_state.gas_used,
        explicit.gas_used + load_cost(bytes.len()).unsigned_abs()
    );
}

#[test]
fn loading_is_paid_by_the_callee() {
    let bytes = reporter();
    let hash = keccak256(&bytes);
    let cost = load_cost(bytes.len());
    let mut exec = executor();
    exec.state_mut().set(&code_key(&hash), &bytes);
    let short = call(&mut exec, &hash, cost - 1, Capability::Sandboxed);
    assert_eq!(short.status, Termination::OutOfGas);
    assert_eq!(short.gas_used, (cost - 1).unsigned_abs());
    assert!(short.started);
    assert_eq!(short.invoke_status(), HostStatus::CalleeTrapped);
    // Exactly the load cost leaves nothing for the first block.
    let exact = call(&mut exec, &hash, cost, Capability::Sandboxed);
    assert_eq!(exact.status, Termination::OutOfGas);
    // A limit the VM rejects is rejected as before.
    let negative = call(&mut exec, &hash, -1, Capability::Sandboxed);
    assert_eq!(
        negative.status,
        Termination::HostError(HostStatus::InvalidArgument.code())
    );
}

#[test]
fn modules_from_state_validate_for_the_callers_set() {
    let mut exec = executor();
    exec.set_extension(Box::new(Doubler));
    let mut body = vec![li(Reg::A0, 21), ecall(1)];
    body.extend(report());
    let bytes = module(&["output_write", "ext_double"], &body, &[]);
    let hash = keccak256(&bytes);
    exec.state_mut().set(&code_key(&hash), &bytes);
    assert_eq!(
        call(&mut exec, &hash, 10_000, Capability::Sandboxed).status,
        not_found()
    );
    let privileged = call(&mut exec, &hash, 10_000, Capability::Privileged);
    assert_eq!(regs(&privileged).0, 42);
    // Cached now, but a sandboxed instance still cannot import it.
    assert_eq!(
        call(&mut exec, &hash, 10_000, Capability::Sandboxed).status,
        not_found()
    );

    // Bytes that hash right but are no module.
    let junk = b"SOLO but not a module".to_vec();
    let junk_hash = keccak256(&junk);
    exec.state_mut().set(&code_key(&junk_hash), &junk);
    assert_eq!(
        call(&mut exec, &junk_hash, 10_000, Capability::Privileged).status,
        not_found()
    );
}

#[test]
fn invoke_reaches_modules_in_state() {
    let callee = reporter();
    let hash = keccak256(&callee);
    let mut exec = executor();
    exec.state_mut().set(&code_key(&hash), &callee);
    // The caller passes the callee's hash from rodata and reports invoke's status.
    let mut body = vec![
        li(Reg::A0, 0x10000),
        li(Reg::A1, 0x10000),
        li(Reg::A2, 0),
        li(Reg::A3, 0),
        li(Reg::A4, 5_000),
        li(Reg::A5, 0),
        ecall(INVOKE),
    ];
    body.extend(report());
    let invoker = module(&imports(), &body, &hash);
    let r = run(&mut exec, &invoker, b"", 100_000);
    assert_eq!(regs(&r).0, 0, "invoke status Ok");
}

#[test]
fn caches_never_change_a_result() {
    // A module that imports a privileged function, in the state of two
    // executors; only one of them has run it, privileged, and cached it.
    let mut body = vec![li(Reg::A0, 21), ecall(1)];
    body.extend(report());
    let bytes = module(&["output_write", "ext_double"], &body, &[]);
    let hash = keccak256(&bytes);
    let cost = load_cost(bytes.len());
    let [mut warm, mut fresh] = [executor(), executor()];
    for exec in [&mut warm, &mut fresh] {
        exec.set_extension(Box::new(Doubler));
        exec.state_mut().set(&code_key(&hash), &bytes);
    }
    assert_eq!(
        regs(&call(&mut warm, &hash, 10_000, Capability::Privileged)).0,
        42
    );
    for gas in [-1, 0, cost - 1, cost, 10_000] {
        assert_eq!(
            call(&mut warm, &hash, gas, Capability::Sandboxed),
            call(&mut fresh, &hash, gas, Capability::Sandboxed),
            "limit {gas}"
        );
    }
    // A load that fails validation is paid for like one that succeeds.
    let refused = call(&mut fresh, &hash, 10_000, Capability::Sandboxed);
    assert_eq!(refused.status, not_found());
    assert_eq!(refused.gas_used, cost.unsigned_abs());
    assert_eq!(refused.invoke_status(), HostStatus::NotFound);
    // So is one whose bytes do not hash to the key, and a limit below the
    // cost stops it before they are hashed.
    for exec in [&mut warm, &mut fresh] {
        exec.state_mut().set(&code_key(&hash), &[0; 640]);
    }
    for gas in [19, 20, 10_000] {
        let r = call(&mut warm, &hash, gas, Capability::Privileged);
        assert_eq!(r, call(&mut fresh, &hash, gas, Capability::Privileged));
        assert_eq!(r.gas_used, gas.min(20).unsigned_abs());
    }
}
