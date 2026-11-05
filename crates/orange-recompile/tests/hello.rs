//! End to end: the hello guest, built by `tools/build-guest.sh`, is
//! recompiled and executed on the reference interpreter against a host that
//! implements the three host functions it uses.

use orange_recompile::{Input, Options, recompile};
use orange_vm::gas::CostTable;
use orange_vm::host::{Capability, Host, HostContext};
use orange_vm::interp::Instance;
use orange_vm::isa::Reg;
use orange_vm::module::{Module, Program};
use orange_vm::status::Termination;
use tiny_keccak::{Hasher, Keccak};

const HELLO: &[u8] = include_bytes!("fixtures/hello.elf");

#[derive(Default)]
struct HelloHost {
    output: Vec<u8>,
    hashed: Vec<Vec<u8>>,
    logs: Vec<String>,
}

impl Host for HelloHost {
    fn resolve(&self, name: &str, _capability: Capability) -> Option<u32> {
        match name {
            "hash_keccak256" => Some(1),
            "output_write" => Some(2),
            "log_emit" => Some(3),
            _ => None,
        }
    }

    fn call(&mut self, handle: u32, ctx: &mut HostContext<'_>) -> Result<(), Termination> {
        match handle {
            1 => {
                let src = ctx.arg32(Reg::A0);
                let len = ctx.arg32(Reg::A1);
                let dst = ctx.arg32(Reg::A2);
                ctx.charge(30 + 6 * u64::from(len.div_ceil(32)))?;
                let data = ctx
                    .memory
                    .read(src, len)
                    .map_err(|_| Termination::MemoryFault)?
                    .to_vec();
                let mut digest = [0u8; 32];
                let mut k = Keccak::v256();
                k.update(&data);
                k.finalize(&mut digest);
                ctx.memory
                    .write(dst, &digest)
                    .map_err(|_| Termination::MemoryFault)?;
                self.hashed.push(data);
                ctx.set(Reg::A0, 0);
            }
            2 => {
                let src = ctx.arg32(Reg::A0);
                let len = ctx.arg32(Reg::A1);
                ctx.charge(10 + u64::from(len.div_ceil(32)))?;
                self.output = ctx
                    .memory
                    .read(src, len)
                    .map_err(|_| Termination::MemoryFault)?
                    .to_vec();
                ctx.set(Reg::A0, 0);
            }
            3 => {
                let src = ctx.arg32(Reg::A1);
                let len = ctx.arg32(Reg::A2);
                let msg = ctx
                    .memory
                    .read(src, len)
                    .map_err(|_| Termination::MemoryFault)?;
                self.logs.push(String::from_utf8_lossy(msg).into_owned());
                ctx.set(Reg::A0, 0);
            }
            _ => return Err(Termination::HostError(99)),
        }
        Ok(())
    }
}

fn hello_program() -> Program {
    let input = Input::load(HELLO).expect("fixture loads");
    let bytes = recompile(&input, &Options::default()).expect("hello recompiles");
    let host = HelloHost::default();
    let module = Module::parse(&bytes, &|n| {
        host.resolve(n, Capability::Sandboxed).is_some()
    })
    .expect("valid module");
    Program::new(module, CostTable::V1)
}

#[test]
fn hello_runs_on_the_interpreter() {
    let program = hello_program();
    let mut host = HelloHost::default();
    let mut inst = Instance::new(
        &program,
        &host,
        Capability::Sandboxed,
        "main",
        &[40, 2],
        1_000_000,
    )
    .unwrap();
    assert_eq!(inst.run(&mut host), Termination::Halt);
    assert_eq!(inst.reg(Reg::A0), 42, "a0 + a1");
    assert_eq!(inst.reg(Reg::A1), 1, "COUNTER after one increment");
    assert_eq!(host.hashed, vec![b"hello, orange".to_vec()]);
    let mut expected = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(b"hello, orange");
    k.finalize(&mut expected);
    assert_eq!(host.output, expected);
    assert!(
        inst.gas() < 1_000_000 && inst.gas() > 900_000,
        "gas used: {}",
        1_000_000 - inst.gas()
    );
    assert!(inst.steps() > 10);
}

#[test]
fn hello_module_is_deterministic_and_small() {
    let input = Input::load(HELLO).unwrap();
    let a = recompile(&input, &Options::default()).unwrap();
    let b = recompile(&input, &Options::default()).unwrap();
    assert_eq!(a, b, "recompilation is deterministic");
    assert!(a.len() < 16_384, "hello module is {} bytes", a.len());
    let module = Module::parse(&a, &|_| true).unwrap();
    assert!(module.export("main").is_some());
    assert_eq!(module.layout.ro_base, 0x1_0000);
    assert_eq!(module.rodata, b"hello, orange");
    assert_eq!(module.layout.rw_base, 0x1_2000);
    assert_eq!(module.layout.data_size, 0);
    assert_eq!(module.layout.bss_size, 248);
    assert_eq!(module.layout.heap_base, 0x1_4000);
    assert_eq!(module.layout.stack_top, 0xFFFF_0000);
    assert!(module.imports.iter().any(|i| i == "hash_keccak256"));
    assert!(module.imports.iter().any(|i| i == "output_write"));
}

#[test]
fn hello_runs_out_of_gas_cleanly() {
    let program = hello_program();
    let mut host = HelloHost::default();
    let mut inst =
        Instance::new(&program, &host, Capability::Sandboxed, "main", &[1, 2], 50).unwrap();
    assert_eq!(inst.run(&mut host), Termination::OutOfGas);
    assert!(inst.gas() < 0);
}
