//! Log filters (`eth_getLogs`): which blocks, which contracts, which topics.

use serde_json::{Map, Value};
use solo_abi::chain::Log;

use crate::RpcError;
use crate::hex::{parse_address, parse_hash};

/// Most topic positions a filter may constrain, as in geth.
pub const MAX_TOPICS: usize = 4;

/// Which blocks a filter covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocks {
    /// One block, by hash.
    Hash([u8; 32]),
    /// A range of block tags or numbers; `None` is `latest`.
    Range(Option<String>, Option<String>),
}

/// A parsed log filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    /// The blocks to search.
    pub blocks: Blocks,
    /// Contracts whose logs match; empty matches every contract.
    pub addresses: Vec<[u8; 20]>,
    /// Per topic position, the values that match; `None` matches anything.
    pub topics: Vec<Option<Vec<[u8; 32]>>>,
}

fn string(value: &Value, what: &str) -> Result<String, RpcError> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| RpcError::invalid_params(format!("{what} must be a string")))
}

/// A block tag or number field: `None` when absent or null.
fn tag(object: &Map<String, Value>, name: &str) -> Result<Option<String>, RpcError> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => string(value, name).map(Some),
    }
}

fn addresses(value: Option<&Value>) -> Result<Vec<[u8; 20]>, RpcError> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(list)) => list
            .iter()
            .map(|a| parse_address(&string(a, "address")?))
            .collect(),
        Some(single) => Ok(vec![parse_address(&string(single, "address")?)?]),
    }
}

/// One topic position: null or a null member matches anything.
fn position(value: &Value) -> Result<Option<Vec<[u8; 32]>>, RpcError> {
    match value {
        Value::Null => Ok(None),
        Value::Array(alternatives) if alternatives.iter().any(Value::is_null) => Ok(None),
        Value::Array(alternatives) => alternatives
            .iter()
            .map(|t| parse_hash(&string(t, "topic")?))
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        single => Ok(Some(vec![parse_hash(&string(single, "topic")?)?])),
    }
}

impl Filter {
    /// Parses a filter object.
    ///
    /// # Errors
    /// Invalid params if the object is missing, a field does not parse, it
    /// names both a block hash and a range, or it has too many topics.
    pub fn parse(value: Option<&Value>) -> Result<Filter, RpcError> {
        let Some(Value::Object(object)) = value else {
            return Err(RpcError::invalid_params("expected a filter object"));
        };
        let from = tag(object, "fromBlock")?;
        let to = tag(object, "toBlock")?;
        let blocks = match tag(object, "blockHash")? {
            Some(_) if from.is_some() || to.is_some() => {
                return Err(RpcError::invalid_params(
                    "cannot specify both BlockHash and FromBlock/ToBlock, choose one or the other",
                ));
            }
            Some(hash) => Blocks::Hash(parse_hash(&hash)?),
            None => Blocks::Range(from, to),
        };
        let topics = match object.get("topics") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(positions)) => positions
                .iter()
                .map(position)
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => return Err(RpcError::invalid_params("topics must be an array")),
        };
        if topics.len() > MAX_TOPICS {
            return Err(RpcError::invalid_params("exceed max topics"));
        }
        Ok(Filter {
            blocks,
            addresses: addresses(object.get("address"))?,
            topics,
        })
    }

    /// Whether `log` passes the address and topic constraints.
    #[must_use]
    pub fn matches(&self, log: &Log) -> bool {
        let topics = &log.topics.0;
        (self.addresses.is_empty() || self.addresses.contains(&log.address))
            && self.topics.len() <= topics.len()
            && self
                .topics
                .iter()
                .zip(topics)
                .all(|(want, have)| want.as_ref().is_none_or(|w| w.contains(have)))
    }
}
