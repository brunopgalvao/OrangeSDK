//! The message-verifier module (spec 18 §5.2, §6) over a key-value store:
//! it proves an `EthereumOutbox` message against a state root the inbox
//! passes, records the message delivered, and paces and pauses deliveries.
//!
//! The module in `guest/modules/eth-message-verifier` is this code with the
//! store of `orange-module` and host crypto.

use alloc::vec::Vec;

use orange_abi::bridge_in::{BridgeInParams, INBOX_ADDRESS};
use orange_abi::chain::reason;
use orange_abi::types::Address;

use crate::abi::{self, Delivery, encode, word};
use crate::client::{Context, Storage, arg, get, put, words};
use crate::{Crypto, inbox};

/// Keys of the verifier's namespace (spec 18 §4.2).
pub mod keys {
    use alloc::vec::Vec;

    /// `config` → [`super::Config`].
    pub const CONFIG: &[u8] = b"config";
    /// `paused` → `[1]` while deliveries are stopped.
    pub const PAUSED: &[u8] = b"paused";
    /// `window` → [`super::Window`].
    pub const WINDOW: &[u8] = b"window";

    /// `delivered/` ‖ nonce (big-endian u64) → `[1]` once the message is delivered.
    #[must_use]
    pub fn delivered(nonce: u64) -> Vec<u8> {
        crate::client::keys::keyed(b"delivered/", nonce)
    }
}

record! {
    /// What genesis fixes: the outbox, this chain's id, the governance
    /// account and the rate limit.
    Config {
        /// The `EthereumOutbox` on Ethereum.
        outbox: Address,
        /// This chain's id, which every message hash names.
        chain_id: u64,
        /// The account that may pause and set the rate limit; zero for none.
        governance: Address,
        /// Length of a rate-limit window in seconds.
        window: u64,
        /// Deliveries allowed per window.
        max_messages: u64,
    }
}

record! {
    /// The rate limit's current window.
    Window {
        /// When it opened, in seconds.
        start: u64,
        /// Deliveries in it so far.
        count: u64,
    }
}

/// Genesis in the verifier's namespace (spec 18 §4.1): its configuration.
pub fn genesis(
    store: &mut dyn Storage,
    params: &BridgeInParams,
    chain_id: u64,
    governance: Address,
) {
    let limits = &params.limits;
    put(
        store,
        keys::CONFIG,
        &Config {
            outbox: params.outbox,
            chain_id,
            governance,
            window: limits.window,
            max_messages: limits.max_messages,
        },
    );
}

fn consume(
    c: &dyn Crypto,
    store: &mut dyn Storage,
    cfg: &Config,
    ctx: &Context,
    data: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    if ctx.caller != INBOX_ADDRESS {
        return Err(encode(abi::NOT_INBOX, &[]));
    }
    let d = Delivery::decode(data).ok_or_else(Vec::new)?;
    if store.get(keys::PAUSED).is_some() {
        return Err(encode(abi::PAUSED_ERROR, &[]));
    }
    let nonce = d.message.nonce;
    if store.get(&keys::delivered(nonce)).is_some() {
        return Err(encode(abi::ALREADY_DELIVERED, &[word(nonce)]));
    }
    let mut window: Window = get(store, keys::WINDOW).unwrap_or_default();
    if ctx.timestamp >= window.start.saturating_add(cfg.window) {
        window = Window {
            start: ctx.timestamp,
            count: 0,
        };
    }
    if window.count >= cfg.max_messages {
        return Err(encode(abi::RATE_LIMITED, &[]));
    }
    if inbox::verify(
        c,
        &d.anchor,
        &cfg.outbox,
        cfg.chain_id,
        &d.message,
        &d.account_proof,
        &d.storage_proof,
    )
    .is_err()
    {
        return Err(encode(abi::BAD_PROOF, &[]));
    }
    window.count += 1;
    put(store, keys::WINDOW, &window);
    store.set(&keys::delivered(nonce), Some(&[1]));
    Ok(Vec::new())
}

/// Serves a native call to the verifier (spec 18 §5.2): `Ok` with the
/// return data and the writes made in `store`, or `Err` with revert data,
/// in which case the caller discards the writes.
///
/// # Errors
/// Revert data: the interface's errors, or empty for calldata it does not
/// know or a namespace without the verifier's state.
pub fn call(
    c: &dyn Crypto,
    store: &mut dyn Storage,
    ctx: &Context,
    data: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    let cfg: Config = get(store, keys::CONFIG).ok_or_else(Vec::new)?;
    let selector = data.get(..4).ok_or_else(Vec::new)?;
    if selector == abi::CONSUME {
        return consume(c, store, &cfg, ctx, data);
    }
    let governed =
        selector == abi::PAUSE || selector == abi::UNPAUSE || selector == abi::SET_RATE_LIMIT;
    if !governed {
        return query(store, data);
    }
    if cfg.governance == [0; 20] || ctx.caller != cfg.governance {
        return Err(encode(abi::NOT_GOVERNANCE, &[]));
    }
    if selector == abi::SET_RATE_LIMIT {
        let (Some(window), Some(max_messages), 68) = (arg(data, 0), arg(data, 1), data.len())
        else {
            return Err(Vec::new());
        };
        put(
            store,
            keys::CONFIG,
            &Config {
                window,
                max_messages,
                ..cfg
            },
        );
    } else if data.len() != 4 {
        return Err(Vec::new());
    } else {
        store.set(keys::PAUSED, (selector == abi::PAUSE).then_some(&[1]));
    }
    Ok(Vec::new())
}

/// Answers a view (`delivered`, `paused`, `rateLimit`), as `module_query` does.
///
/// # Errors
/// Empty revert data for calldata that is no view or a namespace without
/// the verifier's state.
pub fn query(store: &dyn Storage, data: &[u8]) -> Result<Vec<u8>, Vec<u8>> {
    let cfg: Config = get(store, keys::CONFIG).ok_or_else(Vec::new)?;
    let selector = data.get(..4).ok_or_else(Vec::new)?;
    let flag = |b: bool| Ok(words(&[word(u64::from(b))]));
    if selector == abi::DELIVERED && data.len() == 36 {
        flag(
            store
                .get(&keys::delivered(arg(data, 0).ok_or_else(Vec::new)?))
                .is_some(),
        )
    } else if selector == abi::PAUSED && data.len() == 4 {
        flag(store.get(keys::PAUSED).is_some())
    } else if selector == abi::RATE_LIMIT && data.len() == 4 {
        Ok(words(&[word(cfg.window), word(cfg.max_messages)]))
    } else {
        Err(Vec::new())
    }
}

/// The verifier's part of admitting a delivery of message `nonce` to the inbox.
///
/// # Errors
/// [`reason::INBOX_PAUSED`] or [`reason::MESSAGE_DELIVERED`].
pub(crate) fn admit(store: &dyn Storage, nonce: u64) -> Result<(), u32> {
    if store.get(keys::PAUSED).is_some() {
        return Err(reason::INBOX_PAUSED);
    }
    if store.get(&keys::delivered(nonce)).is_some() {
        return Err(reason::MESSAGE_DELIVERED);
    }
    Ok(())
}

/// The calldata of `setRateLimit(window, maxMessages)`.
#[must_use]
pub fn set_rate_limit_call(window: u64, max_messages: u64) -> Vec<u8> {
    encode(abi::SET_RATE_LIMIT, &[word(window), word(max_messages)])
}
