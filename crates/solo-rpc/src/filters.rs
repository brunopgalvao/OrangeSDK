//! Polled filters (spec 20 §8.1): `eth_newFilter`, `eth_newBlockFilter`,
//! `eth_newPendingTransactionFilter`, `eth_getFilterChanges`,
//! `eth_getFilterLogs` and `eth_uninstallFilter`, as geth serves them over
//! HTTP. A filter remembers the first block it has not reported; each poll
//! reports what happened since and moves it. One not polled for
//! [`FILTER_TIMEOUT`] is dropped.

use std::collections::{BTreeSet, HashMap};
use std::hash::{BuildHasher, RandomState};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use solo_host::hash::keccak256;

use crate::Rpc;
use crate::filter::{Blocks, Filter};
use crate::hex::{data, parse_quantity};
use crate::methods::{RpcError, param_str};

/// How long a filter lives without being polled: geth's deadline.
pub const FILTER_TIMEOUT: Duration = Duration::from_mins(5);

/// Default most filters a node keeps installed at once ([`Rpc::max_filters`]).
pub const MAX_FILTERS: usize = 1024;

/// What a filter reports.
#[derive(Debug)]
enum Kind {
    /// Logs that match, within the filter's numeric block bounds.
    Logs {
        filter: Filter,
        from: Option<u64>,
        to: Option<u64>,
    },
    /// The hashes of new blocks.
    Blocks,
    /// The hashes of transactions new to the pool or to a block, and the
    /// ones the last poll saw, so that none is reported twice.
    Pending { seen: BTreeSet<[u8; 32]> },
}

#[derive(Debug)]
struct Installed {
    kind: Kind,
    /// The first height not yet reported.
    next: u64,
    polled: Instant,
}

/// The filters installed on a node, by id.
#[derive(Debug)]
pub(crate) struct Filters {
    installed: HashMap<String, Installed>,
    /// Random per server, so that ids cannot be guessed: anyone who knows
    /// an id can drain or remove its filter.
    seed: u64,
    count: u64,
}

impl Default for Filters {
    fn default() -> Filters {
        Filters {
            installed: HashMap::new(),
            seed: RandomState::new().hash_one(0u8),
            count: 0,
        }
    }
}

/// A numeric block bound of a filter range: a tag that moves with the head
/// bounds nothing.
fn bound(tag: Option<&str>) -> Result<Option<u64>, RpcError> {
    match tag {
        None | Some("latest" | "pending" | "safe" | "finalized") => Ok(None),
        Some("earliest") => Ok(Some(0)),
        Some(hex) => parse_quantity(hex).map(Some),
    }
}

fn not_found() -> RpcError {
    RpcError::server("filter not found")
}

impl Rpc {
    /// Drops the filters not polled within [`Rpc::filter_timeout`].
    fn sweep(&mut self, now: Instant) {
        let timeout = self.filter_timeout;
        self.filters
            .installed
            .retain(|_, f| now.duration_since(f.polled) < timeout);
    }

    fn install(&mut self, kind: Kind) -> Result<Value, RpcError> {
        let now = Instant::now();
        self.sweep(now);
        if self.filters.installed.len() >= self.max_filters {
            return Err(RpcError::server(format!(
                "too many filters installed, the limit is {}",
                self.max_filters
            )));
        }
        let next = self.block_number()? + 1;
        let filters = &mut self.filters;
        filters.count += 1;
        let mut preimage = filters.seed.to_be_bytes().to_vec();
        preimage.extend_from_slice(&filters.count.to_be_bytes());
        let id = data(&keccak256(&preimage)[..16]);
        let installed = Installed {
            kind,
            next,
            polled: now,
        };
        filters.installed.insert(id.clone(), installed);
        Ok(json!(id))
    }

    /// `eth_newFilter(filter)`.
    pub(crate) fn new_log_filter(&mut self, params: &[Value]) -> Result<Value, RpcError> {
        let filter = Filter::parse(params.first())?;
        let (from, to) = match &filter.blocks {
            Blocks::Range(from, to) => (bound(from.as_deref())?, bound(to.as_deref())?),
            Blocks::Hash(_) => (None, None),
        };
        if let (Some(from), Some(to)) = (from, to)
            && from > to
        {
            return Err(RpcError::invalid_params("invalid block range"));
        }
        self.install(Kind::Logs { filter, from, to })
    }

    /// `eth_newBlockFilter()`.
    pub(crate) fn new_block_filter(&mut self) -> Result<Value, RpcError> {
        self.install(Kind::Blocks)
    }

    /// `eth_newPendingTransactionFilter()`.
    pub(crate) fn new_pending_filter(&mut self) -> Result<Value, RpcError> {
        self.install(Kind::Pending {
            seen: BTreeSet::new(),
        })
    }

    /// `eth_uninstallFilter(id)`: whether there was such a filter.
    pub(crate) fn uninstall_filter(&mut self, params: &[Value]) -> Result<Value, RpcError> {
        let id = param_str(params, 0)?;
        self.sweep(Instant::now());
        Ok(json!(self.filters.installed.remove(id).is_some()))
    }

    /// `eth_getFilterLogs(id)`: every log a log filter matches over its
    /// whole range, as `eth_getLogs` answers it.
    pub(crate) fn filter_logs(&mut self, params: &[Value]) -> Result<Value, RpcError> {
        let id = param_str(params, 0)?;
        let now = Instant::now();
        self.sweep(now);
        let installed = self.filters.installed.get_mut(id).ok_or_else(not_found)?;
        let Kind::Logs { filter, .. } = &installed.kind else {
            return Err(not_found());
        };
        installed.polled = now;
        let filter = filter.clone();
        self.logs(&filter)
    }

    /// `eth_getFilterChanges(id)`: what the filter matches since its last
    /// poll, at most [`Rpc::max_log_range`] blocks of it; a later poll
    /// reports the rest.
    pub(crate) fn filter_changes(&mut self, params: &[Value]) -> Result<Value, RpcError> {
        let id = param_str(params, 0)?.to_owned();
        let now = Instant::now();
        self.sweep(now);
        let mut installed = self.filters.installed.remove(&id).ok_or_else(not_found)?;
        installed.polled = now;
        let result = self.changes(&mut installed);
        self.filters.installed.insert(id, installed);
        result.map(Value::Array)
    }

    fn changes(&mut self, installed: &mut Installed) -> Result<Vec<Value>, RpcError> {
        let start = installed.next;
        let head = self.block_number()?;
        let end = head.min(start.saturating_add(self.max_log_range.saturating_sub(1)));
        installed.next = installed.next.max(end + 1);
        match &mut installed.kind {
            Kind::Logs { filter, from, to } => {
                let lo = start.max(from.unwrap_or(0));
                let hi = end.min(to.unwrap_or(u64::MAX));
                if matches!(filter.blocks, Blocks::Hash(_)) || lo > hi {
                    return Ok(Vec::new());
                }
                self.scan_logs(filter, lo, hi)
            }
            Kind::Blocks => {
                let mut out = Vec::new();
                for height in start..=end {
                    self.run_background();
                    let (_, hash) = self.header_at(height)?.unwrap_or_default();
                    out.push(json!(data(&hash)));
                }
                Ok(out)
            }
            Kind::Pending { seen } => {
                let mut candidates = Vec::new();
                for height in start..=end {
                    self.run_background();
                    let (header, _) = self.header_at(height)?.unwrap_or_default();
                    candidates.extend(header.tx_hashes.0);
                }
                candidates.extend(self.node().mempool().iter().map(|tx| tx.hash));
                let mut out = Vec::new();
                let mut now_seen = BTreeSet::new();
                for hash in candidates {
                    if now_seen.insert(hash) && !seen.contains(&hash) {
                        out.push(json!(data(&hash)));
                    }
                }
                *seen = now_seen;
                Ok(out)
            }
        }
    }
}
