//! The Solo canonical encoding (spec 06 §2) and the types that cross the
//! host–kernel boundary (spec 06 §3–§5). `no_std` with `alloc`, so the same
//! code runs inside the kernel and in the host.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod bridge;
pub mod bridge_in;
pub mod chain;
pub mod codec;
pub mod conformance;
pub mod governance;
pub mod modules;
pub mod rotation;
pub mod staking;
pub mod types;

pub use codec::{Decode, DecodeError, Decoder, Encode, Encoder};
