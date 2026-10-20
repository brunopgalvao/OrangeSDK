//! Real guests on both backends: the recompiled `hello` guest against its
//! three host functions, and the reference kernel fixture running several
//! of its entrypoints through `solo-host`'s executor with the node's
//! privileged extension.

use std::cell::RefCell;
use std::rc::Rc;

use k256::ecdsa::SigningKey;
use solo_abi::Encode;
use solo_abi::chain::{Allocation, GenesisParams, query};
use solo_abi::codec::Seq;
use solo_abi::types::{ExecContext, Genesis, QueryArgs, ValidateArgs, exports};
use solo_host::hash::keccak256;
use solo_host::{Backend, CallResult, Executor, Flags, MemStorage, ModuleCache};
use solo_jit::Compiled;
use solo_node::{NodeExtension, NodeServices, Sim};
use solo_recompile::{Input, Options, recompile};
use solo_rlp::{encode_bytes, encode_list, encode_uint};
use solo_vm::gas::CostTable;
use solo_vm::host::{Capability, Host, HostContext};
use solo_vm::isa::Reg;
use solo_vm::module::{Module, Program};
use solo_vm::status::Termination;

const HELLO: &[u8] = include_bytes!("../../solo-recompile/tests/fixtures/hello.elf");
const KERNEL: &[u8] = include_bytes!("../../solo-node/tests/fixtures/kernel.elf");

/// The host functions `hello` imports, recording what it was given.
#[derive(Debug, Default, PartialEq, Eq)]
struct HelloHost {
    output: Vec<u8>,
    hashed: Vec<Vec<u8>>,
}

impl Host for HelloHost {
    fn resolve(&self, name: &str, _capability: Capability) -> Option<u32> {
        ["hash_keccak256", "output_write", "log_emit"]
            .iter()
            .position(|n| *n == name)
            .and_then(|i| u32::try_from(i).ok())
    }

    fn call(&mut self, handle: u32, ctx: &mut HostContext<'_>) -> Result<(), Termination> {
        let (a0, a1, a2) = (ctx.arg32(Reg::A0), ctx.arg32(Reg::A1), ctx.arg32(Reg::A2));
        let fault = |_| Termination::MemoryFault;
        match handle {
            0 => {
                ctx.charge(30 + 6 * u64::from(a1.div_ceil(32)))?;
                let data = ctx.memory.read(a0, a1).map_err(fault)?.to_vec();
                ctx.memory.write(a2, &keccak256(&data)).map_err(fault)?;
                self.hashed.push(data);
            }
            1 => {
                ctx.charge(10 + u64::from(a1.div_ceil(32)))?;
                self.output = ctx.memory.read(a0, a1).map_err(fault)?.to_vec();
            }
            _ => {}
        }
        ctx.set(Reg::A0, 0);
        Ok(())
    }
}

#[test]
fn hello_agrees_on_both_backends() {
    let bytes = recompile(&Input::load(HELLO).unwrap(), &Options::default()).unwrap();
    let host = HelloHost::default();
    let module = Module::parse(&bytes, &|n| {
        host.resolve(n, Capability::Sandboxed).is_some()
    })
    .unwrap();
    let program = Program::new(module, CostTable::V1);
    let compiled = Compiled::new(&program).unwrap();
    for gas in [50, 500, 2_000, 1_000_000] {
        let mut ih = HelloHost::default();
        let mut i = solo_vm::interp::Instance::new(
            &program,
            &ih,
            Capability::Sandboxed,
            "main",
            &[40, 2],
            gas,
        )
        .unwrap();
        let mut nh = HelloHost::default();
        let mut n =
            solo_jit::Instance::new(&compiled, &nh, Capability::Sandboxed, "main", &[40, 2], gas)
                .unwrap();
        let (is, ns) = (i.run(&mut ih), n.run(&mut nh));
        assert_eq!(ns, is, "gas {gas}");
        assert_eq!(n.regs(), i.regs());
        assert_eq!(n.gas(), i.gas());
        assert_eq!(n.position(), i.position());
        assert_eq!(nh, ih);
        let l = *i.memory().layout();
        let stack = l.stack_top - l.stack_base;
        assert_eq!(
            n.memory().read(l.stack_base, stack),
            i.memory().read(l.stack_base, stack)
        );
        if gas == 1_000_000 {
            assert_eq!(is, Termination::Halt);
            assert_eq!(n.reg(Reg::A0), 42);
            assert_eq!(nh.output, keccak256(b"hello, solo"));
        }
    }
}

/// An EIP-155 legacy transfer signed with a key of 32 `seed` bytes.
fn transfer(seed: u8, nonce: u64, to: [u8; 20], value: u128) -> Vec<u8> {
    let key = SigningKey::from_slice(&[seed; 32]).unwrap();
    let fields = |out: &mut Vec<u8>| {
        encode_uint(u128::from(nonce), out);
        encode_uint(1_000_000_000, out);
        encode_uint(21_000, out);
        encode_bytes(&to, out);
        encode_uint(value, out);
        encode_bytes(&[], out);
    };
    let mut unsigned = Vec::new();
    fields(&mut unsigned);
    for v in [1337, 0, 0] {
        encode_uint(v, &mut unsigned);
    }
    let mut list = Vec::new();
    encode_list(&unsigned, &mut list);
    let (sig, rid) = key.sign_prehash_recoverable(&keccak256(&list)).unwrap();
    let mut signed = Vec::new();
    fields(&mut signed);
    encode_uint(1337 * 2 + 35 + u128::from(rid.to_byte()), &mut signed);
    for part in [sig.r().to_bytes(), sig.s().to_bytes()] {
        let skip = part.iter().take_while(|b| **b == 0).count();
        encode_bytes(&part[skip..], &mut signed);
    }
    let mut out = Vec::new();
    encode_list(&signed, &mut out);
    out
}

fn address(seed: u8) -> [u8; 20] {
    let key = SigningKey::from_slice(&[seed; 32]).unwrap();
    let point = key.verifying_key().to_encoded_point(false);
    let mut a = [0u8; 20];
    a.copy_from_slice(&keccak256(&point.as_bytes()[1..])[12..]);
    a
}

fn genesis() -> Genesis {
    let params = GenesisParams {
        slot_ms: 400,
        max_txs: 8,
        allocations: Seq(vec![Allocation {
            address: address(1),
            balance: 1_000_000_000_000_000_000_000,
            ..Allocation::default()
        }]),
    };
    let validator = SigningKey::from_slice(&[0x42; 32]).unwrap();
    Genesis {
        chain_id: 1337,
        fee_schedule: vec![],
        modules: Seq(vec![]),
        params: params.to_bytes(),
        validators: Sim::validator_set(&[validator]).to_bytes(),
    }
}

/// What one kernel call leaves behind: its result, where it ended, the
/// executor's logs and metrics so far, and the state commitment.
type Step = (
    CallResult,
    Option<([u8; 32], u32, usize)>,
    Vec<(u32, Vec<u8>)>,
    Vec<(String, i64, u32)>,
    [u8; 32],
);

/// Everything a kernel call sequence leaves behind, call by call, and
/// whether the kernel ran as native code.
type Trace = (Vec<Step>, Option<bool>);

/// Runs a fixed sequence of kernel entrypoints on `backend`.
fn kernel_trace(module: &[u8], backend: Backend) -> Trace {
    let services = Rc::new(RefCell::new(NodeServices {
        now_ms: 1_000,
        ..NodeServices::default()
    }));
    let mut exec = Executor::new(ModuleCache::new(CostTable::V1), MemStorage::default());
    exec.set_extension(Box::new(NodeExtension::new(services)));
    exec.set_backend(backend);
    let kernel = exec.load(module, Capability::Privileged).unwrap();
    let query = |method: &str, params: Vec<u8>| QueryArgs {
        method: method.as_bytes().to_vec(),
        params,
        at: None,
    };
    let validate = |tx: Vec<u8>| ValidateArgs {
        tx,
        context: ExecContext {
            height: 1,
            slot: 1,
            ..ExecContext::default()
        },
    };
    let calls: Vec<(&str, Vec<u8>, i64)> = vec![
        (exports::INIT, genesis().to_bytes(), 1 << 40),
        (
            exports::QUERY,
            query(query::CHAIN_ID, vec![]).to_bytes(),
            1 << 40,
        ),
        (
            exports::QUERY,
            query(query::ACCOUNT, address(1).to_vec()).to_bytes(),
            1 << 40,
        ),
        (exports::DRIVER_STATE, vec![], 1 << 40),
        (
            exports::VALIDATE_TX,
            validate(transfer(1, 0, address(2), 5)).to_bytes(),
            1 << 40,
        ),
        (
            exports::VALIDATE_TX,
            validate(vec![0xC0, 0x01]).to_bytes(),
            1 << 40,
        ),
        (
            exports::QUERY,
            query(query::BLOCK_NUMBER, vec![]).to_bytes(),
            5_000,
        ),
    ];
    let mut steps = Vec::new();
    for (export, input, gas) in calls {
        let result = exec.call_export(
            &kernel,
            export,
            [0; 32],
            &input,
            gas,
            Capability::Privileged,
            Flags::default(),
        );
        steps.push((
            result,
            exec.last_position(),
            exec.logs().to_vec(),
            exec.metrics().to_vec(),
            solo_node::extension::commitment(exec.state_mut()),
        ));
    }
    (steps, exec.runs_natively(&kernel))
}

#[test]
fn kernel_entrypoints_agree_on_both_backends() {
    let module = recompile(&Input::load(KERNEL).unwrap(), &Options::default()).unwrap();
    let (interpreted, ran_natively) = kernel_trace(&module, Backend::Interpreter);
    assert_eq!(ran_natively, None);
    let statuses: Vec<Termination> = interpreted.iter().map(|s| s.0.status).collect();
    assert_eq!(&statuses[..6], &[Termination::Halt; 6]);
    assert_eq!(statuses[6], Termination::OutOfGas);
    assert!(interpreted[0].0.gas_used > 1_000, "{:?}", interpreted[0].0);
    let (native, ran_natively) = kernel_trace(&module, Backend::Native);
    // The kernel must really have run as native code; a silent fallback
    // would compare the interpreter with itself.
    assert_eq!(ran_natively, Some(true));
    assert_eq!(native, interpreted);
}

/// Wall-clock time of the kernel sequence on each backend; ignored by
/// default, run with `cargo test --release -p solo-jit --test guests --
/// --ignored --nocapture`.
#[test]
#[ignore = "timing; run explicitly in release mode"]
fn kernel_timing() {
    let module = recompile(&Input::load(KERNEL).unwrap(), &Options::default()).unwrap();
    let parsed = Module::parse(&module, &|_| true).unwrap();
    let program = Program::new(parsed, CostTable::V1);
    let start = std::time::Instant::now();
    let compiled = Compiled::new(&program).unwrap();
    let compile = start.elapsed();
    let mut times = Vec::new();
    for backend in [Backend::Interpreter, Backend::Native] {
        let start = std::time::Instant::now();
        let trace = kernel_trace(&module, backend);
        times.push((start.elapsed(), trace));
    }
    assert_eq!(times[0].1, times[1].1);
    println!(
        "kernel sequence (init, 3 queries, driver state, 2 validations, 1 query out of gas)\n  interpreter {:>9.1} ms\n  native      {:>9.1} ms (including one compile of {:.1} ms, {} bytes of code)\n  speedup {:.1}x",
        times[0].0.as_secs_f64() * 1e3,
        times[1].0.as_secs_f64() * 1e3,
        compile.as_secs_f64() * 1e3,
        compiled.code_size(),
        times[0].0.as_secs_f64() / times[1].0.as_secs_f64(),
    );
}
