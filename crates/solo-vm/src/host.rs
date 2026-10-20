//! The host side of the boundary as the interpreter sees it (spec 05).
//!
//! The interpreter knows nothing about storage, networking, or nested calls.
//! It resolves import names to handles once at instantiation and hands the
//! machine state to the host on every `ecall`. Everything in spec 05 is
//! implemented by a [`Host`]; this crate ships only the interface and a
//! host that provides nothing, for programs that need no imports.

use crate::isa::Reg;
use crate::memory::Memory;
use crate::status::Termination;

/// Capability set an instance runs under (spec 01 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Contracts and kernel modules: the restricted host-function set.
    Sandboxed,
    /// The kernel: every host function.
    Privileged,
}

/// Machine state handed to a host function for the duration of one call.
pub struct HostContext<'a> {
    /// All thirty-two registers. Arguments are `a0`–`a5`; results go in `a0`, `a1`.
    pub regs: &'a mut [u64; Reg::COUNT],
    /// The instance's memory.
    pub memory: &'a mut Memory,
    /// The instance's gas counter. The host debits per-unit costs here and
    /// returns `Err(Termination::OutOfGas)` if it would go negative (spec 04 §3.3).
    pub gas: &'a mut i64,
}

impl HostContext<'_> {
    /// Reads an argument register.
    #[must_use]
    pub fn arg(&self, reg: Reg) -> u64 {
        self.regs[reg.index()]
    }

    /// Reads the low 32 bits of an argument register as a pointer or length.
    #[must_use]
    pub fn arg32(&self, reg: Reg) -> u32 {
        #[allow(clippy::cast_possible_truncation)]
        let v = self.regs[reg.index()] as u32;
        v
    }

    /// Writes a result register. Writes to `zero` are discarded.
    pub fn set(&mut self, reg: Reg, value: u64) {
        if reg != Reg::ZERO {
            self.regs[reg.index()] = value;
        }
    }

    /// Debits `cost` from the gas counter.
    ///
    /// # Errors
    /// `Termination::OutOfGas` if the counter would go negative; the counter is
    /// left negative so the host can read it (spec 01 §5).
    pub fn charge(&mut self, cost: u64) -> Result<(), Termination> {
        let cost = i64::try_from(cost).unwrap_or(i64::MAX);
        *self.gas = self.gas.saturating_sub(cost);
        if *self.gas < 0 {
            Err(Termination::OutOfGas)
        } else {
            Ok(())
        }
    }
}

/// A provider of host functions.
pub trait Host {
    /// Resolves an import name under `capability` to a handle the interpreter
    /// passes back on every call (spec 03 §5.1 rule 9). `None` rejects the
    /// module at load.
    fn resolve(&self, name: &str, capability: Capability) -> Option<u32>;

    /// Performs the host function `handle`. Returning `Err` terminates the
    /// instance with that status (spec 05 §6).
    ///
    /// # Errors
    /// A terminating status as spec 05 defines for the function.
    fn call(&mut self, handle: u32, ctx: &mut HostContext<'_>) -> Result<(), Termination>;
}

/// A host that provides no functions. Modules with imports fail to load.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoHost;

impl Host for NoHost {
    fn resolve(&self, _name: &str, _capability: Capability) -> Option<u32> {
        None
    }

    fn call(&mut self, _handle: u32, _ctx: &mut HostContext<'_>) -> Result<(), Termination> {
        Err(Termination::HostError(u32::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::tests::small_layout;

    #[test]
    fn context_helpers() {
        let mut regs = [0u64; Reg::COUNT];
        regs[Reg::A0.index()] = 0x1_0000_002A;
        let rodata = [0u8; 16];
        let mut mem = Memory::new(small_layout(), &rodata, &[0; 8]);
        let mut gas: i64 = 100;
        let mut ctx = HostContext {
            regs: &mut regs,
            memory: &mut mem,
            gas: &mut gas,
        };
        assert_eq!(ctx.arg(Reg::A0), 0x1_0000_002A);
        assert_eq!(ctx.arg32(Reg::A0), 42);
        ctx.set(Reg::A1, 7);
        ctx.set(Reg::ZERO, 9);
        assert_eq!(ctx.arg(Reg::A1), 7);
        assert_eq!(ctx.arg(Reg::ZERO), 0);
        assert_eq!(ctx.charge(60), Ok(()));
        assert_eq!(*ctx.gas, 40);
        assert_eq!(ctx.charge(41), Err(Termination::OutOfGas));
        assert_eq!(*ctx.gas, -1);
        assert_eq!(ctx.charge(u64::MAX), Err(Termination::OutOfGas));
        assert_eq!(*ctx.gas, i64::MIN);
        assert!(ctx.memory.read(0x1_0000, 1).is_ok());
    }

    #[test]
    fn no_host() {
        let mut h = NoHost;
        assert_eq!(h.resolve("anything", Capability::Privileged), None);
        assert_eq!(h.resolve("anything", Capability::Sandboxed), None);
        let mut regs = [0u64; Reg::COUNT];
        let mut mem = Memory::new(small_layout(), &[0; 16], &[0; 8]);
        let mut gas = 0;
        let mut ctx = HostContext {
            regs: &mut regs,
            memory: &mut mem,
            gas: &mut gas,
        };
        assert_eq!(h.call(0, &mut ctx), Err(Termination::HostError(u32::MAX)));
        assert_eq!(alloc::format!("{NoHost:?}"), "NoHost");
        assert_eq!(Capability::Sandboxed, Capability::Sandboxed);
    }
}
