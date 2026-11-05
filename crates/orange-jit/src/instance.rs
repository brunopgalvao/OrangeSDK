//! Running compiled programs: the same interface and the same results as
//! [`orange_vm::interp::Instance`].

use orange_vm::gas::{MAX_GAS_LIMIT, bulk_cost, sbrk_cost};
use orange_vm::host::{Capability, Host, HostContext};
use orange_vm::interp::InstanceError;
use orange_vm::isa::Reg;
use orange_vm::memory::Memory;
use orange_vm::status::Termination;

use crate::Compiled;
use crate::code::Site;
use crate::ctx::{Ctx, EXIT_FAULT, EXIT_HALT, EXIT_INVALID_JUMP, EXIT_OUT_OF_GAS, EXIT_TRAP};

/// Where native code starts on the next entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Resume {
    /// The start of a block, by index.
    Block(u32),
    /// Just after a resumable site, by index into the site table.
    Site(usize),
}

/// One running (or finished) instance of a compiled program.
///
/// Unlike the interpreter it counts no steps and has no step limit: those
/// exist for debugging hosts (spec 01 §6), which use the interpreter.
#[derive(Debug)]
pub struct Instance<'c> {
    compiled: &'c Compiled,
    ctx: Ctx,
    memory: Memory,
    imports: Vec<u32>,
    resume: Resume,
    position: (u32, usize),
    done: Option<Termination>,
}

fn low32(v: u64) -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    let w = v as u32;
    w
}

impl<'c> Instance<'c> {
    /// Creates an instance positioned at the export `entry`, with `args` in
    /// `a0`–`a5` (missing arguments are 0), `sp` at `stack_top`, and the gas
    /// counter at `gas_limit`, exactly as [`orange_vm::interp::Instance::new`].
    ///
    /// # Errors
    /// See [`InstanceError`]; the checks run in the interpreter's order.
    pub fn new(
        compiled: &'c Compiled,
        host: &dyn Host,
        capability: Capability,
        entry: &str,
        args: &[u64],
        gas_limit: i64,
    ) -> Result<Instance<'c>, InstanceError> {
        if !(0..=MAX_GAS_LIMIT).contains(&gas_limit) {
            return Err(InstanceError::GasLimit);
        }
        let block = compiled
            .exports
            .iter()
            .find(|(n, _)| n == entry)
            .map(|(_, b)| *b)
            .ok_or(InstanceError::NoSuchExport)?;
        let mut imports = Vec::with_capacity(compiled.imports.len());
        for (i, name) in compiled.imports.iter().enumerate() {
            let missing = InstanceError::UnresolvedImport(u32::try_from(i).unwrap_or(u32::MAX));
            imports.push(host.resolve(name, capability).ok_or(missing)?);
        }
        let mut ctx = Ctx::default();
        for (i, a) in args.iter().take(6).enumerate() {
            ctx.regs[Reg::A0.index() + i] = *a;
        }
        ctx.regs[Reg::SP.index()] = u64::from(compiled.layout.stack_top);
        ctx.gas = gas_limit;
        Ok(Instance {
            compiled,
            ctx,
            memory: Memory::new(compiled.layout, &compiled.rodata, &compiled.data),
            imports,
            resume: Resume::Block(block),
            position: (block, 0),
            done: None,
        })
    }

    /// The registers.
    #[must_use]
    pub const fn regs(&self) -> &[u64; Reg::COUNT] {
        &self.ctx.regs
    }

    /// One register.
    #[must_use]
    pub const fn reg(&self, r: Reg) -> u64 {
        self.ctx.regs[r.index()]
    }

    /// Remaining gas; negative after `OutOfGas`.
    #[must_use]
    pub const fn gas(&self) -> i64 {
        self.ctx.gas
    }

    /// The memory.
    #[must_use]
    pub const fn memory(&self) -> &Memory {
        &self.memory
    }

    /// Mutable access to memory, for hosts preparing input or reading output.
    pub const fn memory_mut(&mut self) -> &mut Memory {
        &mut self.memory
    }

    /// The program position: the current block and the index of the next
    /// instruction in it; after termination, the instruction (or block
    /// entry) that ended the run, as the interpreter reports it.
    #[must_use]
    pub const fn position(&self) -> (u32, usize) {
        self.position
    }

    /// Runs to termination. A finished instance cannot be resumed; running
    /// it again returns the same status.
    pub fn run(&mut self, host: &mut dyn Host) -> Termination {
        if let Some(t) = self.done {
            return t;
        }
        let t = loop {
            let ret = crate::exec::run(self.compiled, &mut self.ctx, &mut self.memory, self.resume);
            let exit = self.compiled.exit(ret);
            self.position = (exit.block, exit.index as usize);
            match self.ctx.exit_kind {
                EXIT_HALT => break Termination::Halt,
                EXIT_TRAP => break Termination::Trap,
                EXIT_FAULT => break Termination::MemoryFault,
                EXIT_INVALID_JUMP => break Termination::InvalidJump,
                EXIT_OUT_OF_GAS => {
                    // Native code subtracts without saturating. The counter can
                    // only wrap if a host drove it near i64::MIN and returned
                    // success; the interpreter saturates there (spec 01 §5).
                    if self.ctx.gas >= 0 {
                        self.ctx.gas = i64::MIN;
                    }
                    break Termination::OutOfGas;
                }
                _ => {
                    let site = self.compiled.site(ret);
                    if let Err(t) = self.perform(self.compiled.sites[site].1, host) {
                        break t;
                    }
                    self.resume = Resume::Site(site);
                }
            }
        };
        self.done = Some(t);
        t
    }

    fn set(&mut self, r: Reg, v: u64) {
        if r != Reg::ZERO {
            self.ctx.regs[r.index()] = v;
        }
    }

    fn charge(&mut self, cost: u64) -> Result<(), Termination> {
        let cost = i64::try_from(cost).unwrap_or(i64::MAX);
        self.ctx.gas = self.ctx.gas.saturating_sub(cost);
        if self.ctx.gas < 0 {
            Err(Termination::OutOfGas)
        } else {
            Ok(())
        }
    }

    /// Performs a resumable site exactly as the interpreter performs the
    /// instruction (spec 02 §4, 04 §3).
    fn perform(&mut self, site: Site, host: &mut dyn Host) -> Result<(), Termination> {
        match site {
            Site::Ecall(import) => {
                let handle = self.imports[import as usize];
                let mut ctx = HostContext {
                    regs: &mut self.ctx.regs,
                    memory: &mut self.memory,
                    gas: &mut self.ctx.gas,
                };
                host.call(handle, &mut ctx)?;
                self.ctx.regs[Reg::ZERO.index()] = 0;
            }
            Site::Sbrk { rd, rs1 } => {
                let bytes = low32(self.ctx.regs[rs1.index()]);
                let old_end = match self.memory.sbrk_pages(bytes) {
                    Some(pages) => {
                        self.charge(sbrk_cost(pages))?;
                        self.memory.sbrk(bytes).map_or(0, |(end, _)| end)
                    }
                    None => 0,
                };
                self.set(rd, u64::from(old_end));
            }
            Site::Memcopy { dst, src, len } => {
                let n = low32(self.ctx.regs[len.index()]);
                self.charge(bulk_cost(n))?;
                let (d, s) = (self.ctx.regs[dst.index()], self.ctx.regs[src.index()]);
                self.memory
                    .copy(low32(d), low32(s), n)
                    .ok()
                    .ok_or(Termination::MemoryFault)?;
            }
            Site::Memfill { dst, val, len } => {
                let n = low32(self.ctx.regs[len.index()]);
                self.charge(bulk_cost(n))?;
                let (d, v) = (self.ctx.regs[dst.index()], self.ctx.regs[val.index()]);
                #[allow(clippy::cast_possible_truncation)]
                let byte = v as u8;
                self.memory
                    .fill(low32(d), byte, n)
                    .ok()
                    .ok_or(Termination::MemoryFault)?;
            }
        }
        Ok(())
    }
}
