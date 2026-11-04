//! The block-position methods of the execution API (spec 20 §8.2):
//! transaction counts and transactions by block and index, and the uncle
//! methods, which answer as for a post-merge block, with no uncles.

use serde_json::{Value, json};
use solo_abi::chain::BlockHeader;

use crate::Rpc;
use crate::hex::{parse_hash, parse_quantity, quantity};
use crate::methods::{RpcError, param_str};

/// How a method names its block.
#[derive(Clone, Copy)]
pub(crate) enum By {
    /// A tag or a number.
    Number,
    /// A hash.
    Hash,
}

impl Rpc {
    /// The block the first parameter names, if it exists.
    fn named_block(&mut self, by: By, params: &[Value]) -> Result<Option<BlockHeader>, RpcError> {
        let param = param_str(params, 0)?;
        match by {
            By::Number => {
                let height = self.resolve_block(param)?;
                Ok(self.header_at(height)?.map(|(header, _)| header))
            }
            By::Hash => self.header_by_hash(&parse_hash(param)?),
        }
    }

    /// `eth_getBlockTransactionCountByNumber` and `…ByHash`: null for a
    /// block that does not exist.
    pub(crate) fn transaction_count(
        &mut self,
        by: By,
        params: &[Value],
    ) -> Result<Value, RpcError> {
        Ok(self.named_block(by, params)?.map_or(Value::Null, |h| {
            json!(quantity(h.tx_hashes.0.len() as u128))
        }))
    }

    /// `eth_getTransactionByBlockNumberAndIndex` and `…HashAndIndex`: null
    /// for a block or an index that does not exist.
    pub(crate) fn transaction_at(&mut self, by: By, params: &[Value]) -> Result<Value, RpcError> {
        let index = parse_quantity(param_str(params, 1)?)?;
        let header = self.named_block(by, params)?;
        let hash = header.and_then(|h| {
            let index = usize::try_from(index).ok()?;
            h.tx_hashes.0.get(index).copied()
        });
        match hash {
            Some(hash) => self.transaction_by_hash(&hash),
            None => Ok(Value::Null),
        }
    }

    /// `eth_getUncleCountByBlockNumber` and `…ByHash`: zero, or null for a
    /// block that does not exist.
    pub(crate) fn uncle_count(&mut self, by: By, params: &[Value]) -> Result<Value, RpcError> {
        Ok(self
            .named_block(by, params)?
            .map_or(Value::Null, |_| json!(quantity(0))))
    }
}
