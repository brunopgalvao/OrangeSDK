//! `counter`: the example kernel module and native contract (spec 16).
//!
//! Installed with the `HOOKS` capability it counts the blocks it has seen
//! and remembers the last height; from the EVM it is a contract with this
//! Solidity interface:
//!
//! ```solidity
//! interface ICounter {
//!     function count() external view returns (uint256);          // 0x06661abd
//!     function initial() external view returns (uint256);        // 0xbb806dc9
//!     function add(uint256 n) external returns (uint256);        // 0x1003e2d2
//!     function blocks() external view returns (uint256);         // 0x967ff23e
//!     function lastHeight() external view returns (uint256);     // 0x25159aa9
//!     function fail(uint256 code) external;                      // 0x132e4f3c, reverts Failed(code)
//!     function paid() external payable returns (uint256);        // 0x295b4e17, msg.value
//!     function spin() external;                                  // 0xf0acd7d5, never returns
//!     function hashOf(bytes calldata data) external view returns (bytes32); // 0xa0490fa0
//!     function whoami() external view returns (address);         // 0xb3b36bb3, msg.sender
//!     error Failed(uint256 code);                                // 0xc77ea641
//! }
//! ```
//!
//! `init` takes the starting count as eight little-endian bytes (or nothing
//! for zero). The `module_query` method answers the view functions.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use solo_module::Store;
use solo_module::abi::{address, arg, as_u64, bytes_arg, encode, selector, word};
use solo_module::solo_abi::modules::{CallContext, ModuleCall};

const COUNT: &[u8] = b"count";
const INITIAL: &[u8] = b"initial";
const BLOCKS: &[u8] = b"blocks";
const LAST: &[u8] = b"last";

const FAILED: [u8; 4] = [0xc7, 0x7e, 0xa6, 0x41];

fn handle(call: &ModuleCall, store: &mut Store) -> Result<Vec<u8>, Vec<u8>> {
    match call {
        ModuleCall::Init { arg } => {
            let start = <[u8; 8]>::try_from(arg.as_slice()).map_or(0, u64::from_le_bytes);
            store.set_u64(COUNT, start);
            store.set_u64(INITIAL, start);
            Ok(Vec::new())
        }
        ModuleCall::BeginBlock { .. } => {
            let blocks = store.get_u64(BLOCKS);
            store.set_u64(BLOCKS, blocks + 1);
            Ok(Vec::new())
        }
        ModuleCall::EndBlock { height, .. } => {
            store.set_u64(LAST, *height);
            Ok(Vec::new())
        }
        ModuleCall::Call { context, data, .. } => dispatch(data, Some(context), store),
        ModuleCall::Query { data } => dispatch(data, None, store),
    }
}

fn dispatch(data: &[u8], context: Option<&CallContext>, store: &mut Store) -> Result<Vec<u8>, Vec<u8>> {
    let words = |w: [u8; 32]| Ok(w.to_vec());
    match selector(data).ok_or_else(Vec::new)? {
        [0x06, 0x66, 0x1a, 0xbd] => words(word(u128::from(store.get_u64(COUNT)))),
        [0xbb, 0x80, 0x6d, 0xc9] => words(word(u128::from(store.get_u64(INITIAL)))),
        [0x96, 0x7f, 0xf2, 0x3e] => words(word(u128::from(store.get_u64(BLOCKS)))),
        [0x25, 0x15, 0x9a, 0xa9] => words(word(u128::from(store.get_u64(LAST)))),
        [0x10, 0x03, 0xe2, 0xd2] => {
            let n = arg(data, 0).as_ref().and_then(as_u64).ok_or_else(Vec::new)?;
            let count = store.get_u64(COUNT).checked_add(n).ok_or_else(Vec::new)?;
            store.set_u64(COUNT, count);
            words(word(u128::from(count)))
        }
        [0x13, 0x2e, 0x4f, 0x3c] => Err(encode(FAILED, &[arg(data, 0).unwrap_or_default()])),
        [0x29, 0x5b, 0x4e, 0x17] => words(word(context.map_or(0, |c| c.value))),
        [0xf0, 0xac, 0xd7, 0xd5] => spin(),
        [0xa0, 0x49, 0x0f, 0xa0] => words(solo_module::keccak256(&bytes_arg(data, 0).ok_or_else(Vec::new)?)),
        [0xb3, 0xb3, 0x6b, 0xb3] => words(address(&context.map_or([0; 20], |c| c.caller))),
        _ => Err(Vec::new()),
    }
}

/// Runs until the gas runs out.
fn spin() -> ! {
    let mut n = 0u64;
    loop {
        n = core::hint::black_box(n.wrapping_add(1));
    }
}

solo_module::module!(handle);
