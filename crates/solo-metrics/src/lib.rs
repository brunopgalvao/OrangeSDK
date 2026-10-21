//! Node telemetry (spec 11).
//!
//! [`Registry`] holds counters, gauges and fixed-bucket histograms and
//! renders them in the Prometheus text exposition format 0.0.4; [`parse`]
//! reads that format back. [`NodeMetrics`] is the node's schema on top of
//! it: chain progress, kernel calls, emitted metrics, the mempool and the
//! peer-to-peer transport. [`health`] turns a node's `/status` and
//! `/metrics` into the verdict `solo doctor` prints.
//!
//! Everything here is consensus-ignored: nothing a kernel can observe
//! depends on it, and a node that records nothing behaves identically.

#![forbid(unsafe_code)]

pub mod health;
pub mod node;
pub mod parse;
pub mod registry;

pub use health::{DEFAULT_LIMITS, Limits, assess, summary};
pub use node::{
    Direction, NodeMetrics, Origin, PendingUpgrade, Status, Traffic, VERSION, exported_names,
};
pub use parse::{ParseError, Sample, parse};
pub use registry::{CONTENT_TYPE, Desc, Kind, Registry};
