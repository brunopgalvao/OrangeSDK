//! Native contracts from the EVM (spec 16 §5): an account whose code is
//! `0xEF02 ‖ code hash` runs that OrangeSDK module instead of EVM bytecode.
//!
//! revm consults its precompile provider for every message call, after the
//! value transfer and inside the call's journal checkpoint, and hands it the
//! code of the account being called. [`NativeProvider`] serves the Ethereum
//! precompiles first, then any call whose code is a designator, by invoking
//! the module through the host. revm commits the checkpoint when the result
//! is a success and reverts it otherwise, value transfer included.
//!
//! A module runs static and returns its storage writes. They are kept here as
//! a *batch*, and the batch's number is written to slot 0 of the native
//! contract's EVM storage, which is otherwise unused, through revm's journal.
//! Each batch names the batch the slot held before it. A revert of any
//! enclosing frame rolls the slot back, so the chain from the slot's final
//! value is exactly the batches that stand; `evm::commit` has them applied.
//! Each batch also names its contract, and a walk stops at a batch of
//! another, so a slot 0 that held anything before the transaction (genesis
//! refuses that, spec 16 §4.1) can never reach another contract's writes.

use alloc::string::String;
use alloc::vec::Vec;

use orange_abi::codec::Seq;
use orange_abi::modules::{self, CallContext, ModuleCall, Write, status};
use orange_abi::types::Address;
use revm::context_interface::{ContextTr, JournalTr};
use revm::handler::{EthPrecompiles, PrecompileProvider};
use revm::interpreter::{CallInputs, CallScheme, Gas, InstructionResult, InterpreterResult};
use revm::primitives::hardfork::SpecId;
use revm::primitives::{Address as RAddress, AddressSet, Bytes, U256};
use revm::state::Account as RAccount;

use crate::evm::{self, BlockFields, Env, Message, Outcome, Precompiles};
use crate::modules::{Invoked, invoke};

/// Executes `message` at `block` with Ethereum's precompiles and native
/// contracts; commits the state changes only if `commit_state`. Every
/// message the kernel runs goes through here.
pub fn run(message: Message, block: BlockFields, commit_state: bool) -> Outcome {
    run_in(message, &Env::kernel(block), commit_state)
}

/// [`run`] in `env` rather than a kernel block: the conformance guest runs
/// Ethereum's state tests through this, so that they take the kernel's own
/// path, native contracts included (spec 07 §4.2).
pub fn run_in(message: Message, env: &Env, commit_state: bool) -> Outcome {
    evm::run_in::<NativeProvider>(message, env, commit_state)
}

/// One native call's write set, and the batch before it in the chain of
/// its contract.
#[derive(Debug, Clone)]
pub struct Batch {
    /// The native contract that made the writes.
    pub address: Address,
    /// The batch number slot 0 held before this one; 0 for none.
    pub previous: u64,
    /// The writes, in order.
    pub writes: Vec<Write>,
}

/// The precompile provider of the reference kernel: Ethereum's precompiles,
/// the outbox (spec 17 §2) and native contracts.
#[derive(Debug)]
pub struct NativeProvider {
    eth: EthPrecompiles,
    block: BlockFields,
    /// Whether this is a query: then a module's VM gas is capped by what the
    /// kernel instance has left (spec 16 §6).
    query: bool,
    /// Batches of this transaction, numbered from 1.
    pub batches: Vec<Batch>,
}

/// The slot of a native contract's EVM storage that holds its latest batch number.
pub const HEAD_SLOT: U256 = U256::ZERO;

impl NativeProvider {
    /// A provider for one transaction in `block`.
    pub fn new(spec: SpecId, block: BlockFields, query: bool) -> NativeProvider {
        NativeProvider {
            eth: EthPrecompiles::new(spec),
            block,
            query,
            batches: Vec::new(),
        }
    }

    /// The writes that stand for `address` when its slot 0 holds `head`, oldest first.
    pub fn standing(&self, address: &Address, head: u64) -> Vec<&Write> {
        let mut chain = Vec::new();
        let mut id = head;
        while let Some(batch) = id
            .checked_sub(1)
            .and_then(|i| self.batches.get(i as usize))
            .filter(|b| b.address == *address)
        {
            chain.push(batch);
            id = batch.previous;
        }
        chain.iter().rev().flat_map(|b| b.writes.iter()).collect()
    }

    fn call<CTX: ContextTr>(
        &mut self,
        ctx: &mut CTX,
        inputs: &CallInputs,
        code_hash: &[u8; 32],
    ) -> Result<InterpreterResult, String> {
        let limit = inputs.gas_limit;
        let halt = |result: InstructionResult| {
            let mut gas = Gas::new_with_regular_gas_and_reservoir(limit, inputs.reservoir);
            gas.spend_all();
            InterpreterResult::new(result, Bytes::new(), gas)
        };
        let finish = |result: InstructionResult, used: u64, output: Vec<u8>| {
            let mut gas = Gas::new_with_regular_gas_and_reservoir(limit, inputs.reservoir);
            let _ = gas.record_regular_cost(used);
            InterpreterResult::new(result, Bytes::from(output), gas)
        };
        let target = inputs.target_address;
        // A module runs only as the account that holds its designator:
        // no DELEGATECALL, no CALLCODE, no EIP-7702 delegation to it.
        let own_code = ctx
            .journal_mut()
            .code_hash(target)
            .map_err(|_| String::from("database"))?
            .data;
        if !matches!(inputs.scheme, CallScheme::Call | CallScheme::StaticCall)
            || target != inputs.bytecode_address
            || own_code != inputs.known_bytecode.0
        {
            return Ok(halt(InstructionResult::PrecompileError));
        }
        if limit < modules::CALL_GAS {
            return Ok(halt(InstructionResult::PrecompileOOG));
        }
        let mut vm_limit = (limit - modules::CALL_GAS) * modules::VM_GAS_PER_EVM_GAS;
        if self.query {
            vm_limit = vm_limit.min(crate::modules::gas_remaining() / 2);
        }
        let head_word = ctx
            .journal_mut()
            .sload(target, HEAD_SLOT)
            .map_err(|_| String::from("database"))?
            .data;
        let head = u64::try_from(head_word).unwrap_or(0);
        let address: Address = target.0.0;
        let pending = self.standing(&address, head).into_iter().cloned().collect();
        let call = ModuleCall::Call {
            context: CallContext {
                address,
                caller: inputs.caller.0.0,
                value: u128::try_from(inputs.call_value()).unwrap_or(u128::MAX),
                height: self.block.number,
                timestamp: self.block.timestamp,
                is_static: inputs.is_static,
            },
            data: inputs.input.bytes(ctx).to_vec(),
            pending: Seq(pending),
        };
        let Invoked { output, gas_used } = invoke(
            code_hash,
            &modules::namespace(&address),
            &orange_abi::Encode::to_bytes(&call),
            vm_limit,
            false,
        );
        let Some(output) = output else {
            return Ok(halt(InstructionResult::PrecompileError));
        };
        let mut used = modules::CALL_GAS + modules::evm_gas(gas_used);
        if output.status == status::REVERT {
            return Ok(finish(InstructionResult::Revert, used, output.data));
        }
        let writes = output.writes.0;
        if inputs.is_static && !writes.is_empty() {
            return Ok(halt(InstructionResult::StateChangeDuringStaticCall));
        }
        used = used.saturating_add(modules::write_gas(&writes));
        if used > limit {
            return Ok(halt(InstructionResult::PrecompileOOG));
        }
        if !writes.is_empty() {
            self.batches.push(Batch {
                address,
                previous: head,
                writes,
            });
            ctx.journal_mut()
                .sstore(target, HEAD_SLOT, U256::from(self.batches.len()))
                .map_err(|_| String::from("database"))?;
        }
        Ok(finish(InstructionResult::Return, used, output.data))
    }
}

impl Precompiles for NativeProvider {
    fn for_message(block: BlockFields, query: bool) -> Self {
        NativeProvider::new(SpecId::OSAKA, block, query)
    }

    /// A native contract keeps no EVM storage: its slot 0 holds the number
    /// of its latest standing batch, whose chain is applied to its namespace.
    fn commit_storage(&self, address: &Address, account: &RAccount) -> bool {
        if crate::outbox::commit(address, account) {
            return true;
        }
        if !account
            .info
            .code
            .as_ref()
            .is_some_and(|c| modules::designated(c.original_byte_slice()).is_some())
        {
            return false;
        }
        let head = account
            .storage
            .get(&HEAD_SLOT)
            .map_or(0, |s| u64::try_from(s.present_value).unwrap_or(0));
        let writes: Vec<_> = self.standing(address, head).into_iter().cloned().collect();
        crate::modules::apply(Some(&modules::namespace(address)), &writes);
        true
    }
}

impl<CTX: ContextTr> PrecompileProvider<CTX> for NativeProvider {
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: <CTX::Cfg as revm::context_interface::Cfg>::Spec) -> bool {
        <EthPrecompiles as PrecompileProvider<CTX>>::set_spec(&mut self.eth, spec)
    }

    fn run(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
    ) -> Result<Option<InterpreterResult>, String> {
        if let Some(result) =
            <EthPrecompiles as PrecompileProvider<CTX>>::run(&mut self.eth, context, inputs)?
        {
            return Ok(Some(result));
        }
        if crate::outbox::is_outbox(inputs) {
            return crate::outbox::call(context, inputs).map(Some);
        }
        match modules::designated(inputs.known_bytecode.1.original_byte_slice()) {
            Some(code_hash) => self.call(context, inputs, &code_hash).map(Some),
            None => Ok(None),
        }
    }

    fn warm_addresses(&self) -> &AddressSet {
        self.eth.warm_addresses()
    }

    fn contains(&self, address: &RAddress) -> bool {
        self.eth.contains(address)
    }
}
