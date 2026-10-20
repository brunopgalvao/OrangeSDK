//! Termination statuses (spec 01 §6) and host status codes (spec 05 §6).

/// How an instance ended (spec 01 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Termination {
    /// The program executed `halt`; `a0` and `a1` hold return values.
    Halt,
    /// The gas counter went negative at a charge point (spec 01 §5).
    OutOfGas,
    /// The program executed `trap`.
    Trap,
    /// An access outside the mapped regions or a write to read-only memory.
    MemoryFault,
    /// An indirect jump named an invalid or empty jump-table slot.
    InvalidJump,
    /// A host call returned a terminating error with this code.
    HostError(u32),
    /// A debugging host's instruction budget ran out. Never in consensus.
    StepLimit,
}

/// Status codes returned by host functions (spec 05 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum HostStatus {
    /// Success.
    Ok = 0,
    /// Malformed argument.
    InvalidArgument = 1,
    /// Key or item does not exist.
    NotFound = 2,
    /// A write inside a static call. Terminates the callee.
    StaticViolation = 3,
    /// Invoke nesting deeper than the host allows.
    DepthExceeded = 4,
    /// Insufficient gas for the call. Terminates the instance as `OutOfGas`.
    OutOfGas = 5,
    /// A pointer range outside instance memory. Terminates the instance.
    MemoryFault = 6,
    /// The callee of `invoke` ended with anything but `Halt`.
    CalleeTrapped = 7,
    /// A privileged function used outside its allowed entrypoint group.
    Unavailable = 8,
}

impl HostStatus {
    /// Whether this status terminates the instance that received it (spec 05 §6).
    #[must_use]
    pub const fn terminates(self) -> bool {
        matches!(
            self,
            HostStatus::StaticViolation | HostStatus::OutOfGas | HostStatus::MemoryFault
        )
    }

    /// The code as it appears in `a0`.
    #[must_use]
    pub const fn code(self) -> u32 {
        self as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_spec_table() {
        let all = [
            (HostStatus::Ok, 0),
            (HostStatus::InvalidArgument, 1),
            (HostStatus::NotFound, 2),
            (HostStatus::StaticViolation, 3),
            (HostStatus::DepthExceeded, 4),
            (HostStatus::OutOfGas, 5),
            (HostStatus::MemoryFault, 6),
            (HostStatus::CalleeTrapped, 7),
            (HostStatus::Unavailable, 8),
        ];
        for (status, code) in all {
            assert_eq!(status.code(), code);
        }
    }

    #[test]
    fn terminating_statuses_match_spec_table() {
        assert!(HostStatus::StaticViolation.terminates());
        assert!(HostStatus::OutOfGas.terminates());
        assert!(HostStatus::MemoryFault.terminates());
        for s in [
            HostStatus::Ok,
            HostStatus::InvalidArgument,
            HostStatus::NotFound,
            HostStatus::DepthExceeded,
            HostStatus::CalleeTrapped,
            HostStatus::Unavailable,
        ] {
            assert!(!s.terminates(), "{s:?} must not terminate");
        }
    }

    #[test]
    fn termination_is_comparable_and_debuggable() {
        assert_eq!(Termination::HostError(3), Termination::HostError(3));
        assert_ne!(Termination::Halt, Termination::Trap);
        assert_eq!(alloc::format!("{:?}", Termination::StepLimit), "StepLimit");
    }
}
