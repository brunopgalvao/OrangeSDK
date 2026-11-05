//! The light-client module (spec 18 §4–§5) over a key-value store: the
//! state genesis writes, the calls the native contract at the light-client
//! address serves, its views, and the admission checks the kernel runs for
//! the bridge's addresses.
//!
//! The module in `guest/modules/eth-light-client` is this code with the
//! store of `orange-module` and host crypto; the kernel uses [`genesis`] and
//! [`admit`] with its own state.

use alloc::vec::Vec;

use orange_abi::bridge_in::{
    BridgeInParams, INBOX_ADDRESS, LIGHT_CLIENT_ADDRESS, LightClientConfig, VERIFIER_ADDRESS,
};
use orange_abi::chain::reason;
use orange_abi::codec::{Decode, Encode};
use orange_abi::types::Address;

use crate::abi::{self, Delivery, encode, word};
use crate::beacon::{Bootstrap, LightClientHeader, Update};
use crate::sync::{self, Rejection, State};
use crate::{Crypto, Hash, verifier};

/// Keys of the light client's namespace (spec 18 §4.2).
pub mod keys {
    use alloc::vec::Vec;

    /// `config` → [`super::Config`].
    pub const CONFIG: &[u8] = b"config";
    /// `finalized` → [`super::Finalized`].
    pub const FINALIZED: &[u8] = b"finalized";

    pub(crate) fn keyed(prefix: &[u8], n: u64) -> Vec<u8> {
        [prefix, &n.to_be_bytes()].concat()
    }

    /// `committee/` ‖ period (big-endian u64) → the committee's keys, 48 bytes each.
    #[must_use]
    pub fn committee(period: u64) -> Vec<u8> {
        keyed(b"committee/", period)
    }

    /// `root/` ‖ execution block number → [`super::ExecutionRoot`].
    #[must_use]
    pub fn root(block_number: u64) -> Vec<u8> {
        keyed(b"root/", block_number)
    }
}

record! {
    /// What genesis fixes: the Ethereum chain, the governance account and
    /// the delay before a state root may prove messages.
    Config {
        /// The Ethereum chain followed.
        light: LightClientConfig,
        /// The account that may set checkpoints and the delay; zero for none.
        governance: Address,
        /// Seconds between storing a state root and its first use.
        delay: u64,
    }
}

record! {
    /// The latest finalized header.
    Finalized {
        /// Its slot.
        slot: u64,
        /// `hash_tree_root` of its beacon header.
        beacon_root: Hash,
        /// Its execution block number.
        block_number: u64,
        /// Its execution block hash.
        block_hash: Hash,
        /// Its execution state root.
        state_root: Hash,
        /// The checkpoint epoch: how many checkpoints governance installed
        /// after genesis's. Only roots of this epoch are served.
        epoch: u64,
    }
}

record! {
    /// A finalized execution block's state root.
    ExecutionRoot {
        /// The state root.
        state_root: Hash,
        /// The block hash.
        block_hash: Hash,
        /// The beacon slot that finalized it.
        slot: u64,
        /// The Orange timestamp, in seconds, from which it may prove messages.
        usable_at: u64,
        /// The checkpoint epoch it was stored in; a root of an older epoch
        /// is treated as absent (spec 18 §5.1).
        epoch: u64,
    }
}

/// A module's storage: its namespace.
pub trait Storage {
    /// The value under `key`.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
    /// Sets `key` to `value`, or deletes it for `None`.
    fn set(&mut self, key: &[u8], value: Option<&[u8]>);
}

/// The call a native call carries (spec 16 §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    /// `msg.sender`.
    pub caller: Address,
    /// The block's timestamp in seconds.
    pub timestamp: u64,
}

pub(crate) fn get<T: Decode>(store: &dyn Storage, key: &[u8]) -> Option<T> {
    T::from_bytes(&store.get(key)?).ok()
}

pub(crate) fn put(store: &mut dyn Storage, key: &[u8], value: &dyn Encode) {
    store.set(key, Some(&value.to_bytes()));
}

/// The `uint64` argument word at `index` after the selector.
pub(crate) fn arg(data: &[u8], index: usize) -> Option<u64> {
    let w = data.get(4 + 32 * index..36 + 32 * index)?;
    w[..24]
        .iter()
        .all(|b| *b == 0)
        .then(|| u64::from_be_bytes(w[24..].try_into().expect("8 bytes")))
}

/// Return data of the words `w`.
pub(crate) fn words(w: &[Hash]) -> Vec<u8> {
    encode([0; 4], w)[4..].to_vec()
}

fn rejected(r: Rejection) -> Vec<u8> {
    encode(abi::UPDATE_REJECTED, &[word(r as u64)])
}

/// Stores `header` as the finalized header and its execution state root,
/// usable from `usable_at`, in checkpoint epoch `epoch`.
fn finalize(
    c: &dyn Crypto,
    store: &mut dyn Storage,
    header: &LightClientHeader,
    usable_at: u64,
    epoch: u64,
) {
    let e = &header.execution;
    let root = ExecutionRoot {
        state_root: e.state_root,
        block_hash: e.block_hash,
        slot: header.beacon.slot,
        usable_at,
        epoch,
    };
    put(store, &keys::root(e.block_number), &root);
    let f = Finalized {
        slot: header.beacon.slot,
        beacon_root: header.beacon.root(c),
        block_number: e.block_number,
        block_hash: e.block_hash,
        state_root: e.state_root,
        epoch,
    };
    put(store, keys::FINALIZED, &f);
}

/// Installs a checked checkpoint: its header becomes the finalized one and
/// its committee the current one; any committee held before is dropped,
/// and the checkpoint epoch moves on, which revokes every root stored
/// before (genesis installs epoch 0).
fn install(
    c: &dyn Crypto,
    store: &mut dyn Storage,
    cfg: &LightClientConfig,
    b: &Bootstrap,
    usable_at: u64,
) {
    let mut epoch = 0;
    if let Some(old) = get::<Finalized>(store, keys::FINALIZED) {
        let p = sync::period(cfg, old.slot);
        store.set(&keys::committee(p), None);
        store.set(&keys::committee(p + 1), None);
        epoch = old.epoch + 1;
    }
    let p = sync::period(cfg, b.header.beacon.slot);
    store.set(&keys::committee(p), Some(&b.current_sync_committee.pubkeys));
    finalize(c, store, &b.header, usable_at, epoch);
}

/// Genesis in the light client's namespace (spec 18 §4.1): the
/// configuration and the checked checkpoint, whose state root is usable
/// after the delay from time zero.
///
/// # Errors
/// The [`Rejection`] for a configuration or checkpoint that cannot work.
pub fn genesis(
    c: &dyn Crypto,
    store: &mut dyn Storage,
    params: &BridgeInParams,
    governance: Address,
) -> Result<(), Rejection> {
    let cfg = &params.config;
    sync::check_config(cfg)?;
    let b = Bootstrap::decode(&params.bootstrap, cfg.sync_committee_size as usize)
        .ok()
        .ok_or(Rejection::Malformed)?;
    sync::bootstrap(c, cfg, &b)?;
    put(
        store,
        keys::CONFIG,
        &Config {
            light: cfg.clone(),
            governance,
            delay: params.limits.delay,
        },
    );
    install(c, store, cfg, &b, params.limits.delay);
    Ok(())
}

/// The light client's state as the sync protocol reads it, and the
/// checkpoint epoch.
fn state(store: &dyn Storage, cfg: &LightClientConfig) -> Option<(State, u64)> {
    let finalized: Finalized = get(store, keys::FINALIZED)?;
    let p = sync::period(cfg, finalized.slot);
    let state = State {
        finalized_slot: finalized.slot,
        current: store.get(&keys::committee(p))?,
        next: store.get(&keys::committee(p + 1)),
    };
    Some((state, finalized.epoch))
}

fn decode_update(cfg: &LightClientConfig, data: &[u8]) -> Result<Update, Rejection> {
    let bytes = abi::decode_bytes_call(data).ok_or(Rejection::Malformed)?;
    let size = cfg.sync_committee_size as usize;
    let update = if data[..4] == abi::SUBMIT_UPDATE {
        Update::decode_update(&bytes, size)
    } else {
        Update::decode_finality_update(&bytes, size)
    };
    update.ok().ok_or(Rejection::Malformed)
}

fn submit(
    c: &dyn Crypto,
    store: &mut dyn Storage,
    cfg: &Config,
    ctx: &Context,
    data: &[u8],
) -> Result<Vec<u8>, Rejection> {
    let light = &cfg.light;
    let update = decode_update(light, data)?;
    let (state, epoch) = state(store, light).ok_or(Rejection::Malformed)?;
    let applied = sync::process(c, light, &state, &update)?;
    if applied.rotate {
        store.set(
            &keys::committee(sync::period(light, state.finalized_slot)),
            None,
        );
    }
    if let (Some(period), Some((committee, _))) = (applied.committee, &update.next_sync_committee) {
        store.set(&keys::committee(period), Some(&committee.pubkeys));
    }
    if applied.finalized {
        finalize(
            c,
            store,
            &update.finalized,
            ctx.timestamp.saturating_add(cfg.delay),
            epoch,
        );
    }
    Ok(Vec::new())
}

fn set_checkpoint(
    c: &dyn Crypto,
    store: &mut dyn Storage,
    cfg: &Config,
    ctx: &Context,
    data: &[u8],
) -> Result<Vec<u8>, Rejection> {
    let light = &cfg.light;
    let bytes = abi::decode_bytes_call(data).ok_or(Rejection::Malformed)?;
    let b = Bootstrap::decode(&bytes, light.sync_committee_size as usize)
        .ok()
        .ok_or(Rejection::Malformed)?;
    sync::bootstrap(c, light, &b)?;
    install(c, store, light, &b, ctx.timestamp.saturating_add(cfg.delay));
    Ok(Vec::new())
}

/// Serves a native call to the light client (spec 18 §5.1): `Ok` with the
/// return data and the writes made in `store`, or `Err` with revert data,
/// in which case the caller discards the writes.
///
/// # Errors
/// Revert data: the interface's errors, or empty for calldata it does not
/// know or a namespace without the light client's state.
pub fn call(
    c: &dyn Crypto,
    store: &mut dyn Storage,
    ctx: &Context,
    data: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    let cfg: Config = get(store, keys::CONFIG).ok_or_else(Vec::new)?;
    let selector = data.get(..4).ok_or_else(Vec::new)?;
    let governed = selector == abi::SET_CHECKPOINT || selector == abi::SET_DELAY;
    if governed && (cfg.governance == [0; 20] || ctx.caller != cfg.governance) {
        return Err(encode(abi::NOT_GOVERNANCE, &[]));
    }
    if selector == abi::SUBMIT_UPDATE || selector == abi::SUBMIT_FINALITY_UPDATE {
        submit(c, store, &cfg, ctx, data).map_err(rejected)
    } else if selector == abi::SET_CHECKPOINT {
        set_checkpoint(c, store, &cfg, ctx, data).map_err(rejected)
    } else if selector == abi::SET_DELAY {
        let delay = arg(data, 0)
            .filter(|_| data.len() == 36)
            .ok_or_else(Vec::new)?;
        put(store, keys::CONFIG, &Config { delay, ..cfg });
        Ok(Vec::new())
    } else {
        query(store, data)
    }
}

/// Answers a view (`finalized`, `executionRoot`, `delay`), as
/// `module_query` does.
///
/// # Errors
/// Empty revert data for calldata that is no view or a namespace without
/// the light client's state.
pub fn query(store: &dyn Storage, data: &[u8]) -> Result<Vec<u8>, Vec<u8>> {
    let cfg: Config = get(store, keys::CONFIG).ok_or_else(Vec::new)?;
    let selector = data.get(..4).ok_or_else(Vec::new)?;
    if selector == abi::FINALIZED && data.len() == 4 {
        let f: Finalized = get(store, keys::FINALIZED).unwrap_or_default();
        Ok(words(&[
            word(f.slot),
            f.beacon_root,
            word(f.block_number),
            f.block_hash,
            f.state_root,
        ]))
    } else if selector == abi::EXECUTION_ROOT && data.len() == 36 {
        let epoch = get::<Finalized>(store, keys::FINALIZED)
            .unwrap_or_default()
            .epoch;
        let r = get::<ExecutionRoot>(store, &keys::root(arg(data, 0).ok_or_else(Vec::new)?))
            .filter(|r| r.epoch == epoch)
            .unwrap_or_default();
        Ok(words(&[
            r.state_root,
            r.block_hash,
            word(r.slot),
            word(r.usable_at),
        ]))
    } else if selector == abi::DELAY && data.len() == 4 {
        Ok(words(&[word(cfg.delay)]))
    } else {
        Err(Vec::new())
    }
}

/// The admission check of a transaction to `to` carrying `value` and
/// `data` (spec 18 §7), against the light client's namespace `light` and
/// the message verifier's `messages`: `Ok` for a transaction to any other
/// address.
///
/// # Errors
/// The reason code: [`reason::BRIDGE_CALL`], [`reason::BRIDGE_UPDATE`],
/// [`reason::MESSAGE_DELIVERED`] or [`reason::INBOX_PAUSED`].
pub fn admit(
    light: &dyn Storage,
    messages: &dyn Storage,
    to: &Address,
    value: u128,
    data: &[u8],
) -> Result<(), u32> {
    if *to != LIGHT_CLIENT_ADDRESS && *to != INBOX_ADDRESS && *to != VERIFIER_ADDRESS {
        return Ok(());
    }
    let cfg: Config = get(light, keys::CONFIG).ok_or(reason::BRIDGE_CALL)?;
    if value != 0 {
        return Err(reason::BRIDGE_CALL);
    }
    let selector = data.get(..4);
    if *to == LIGHT_CLIENT_ADDRESS
        && matches!(selector, Some(s) if s == abi::SUBMIT_UPDATE || s == abi::SUBMIT_FINALITY_UPDATE)
    {
        let light_cfg = &cfg.light;
        let update = decode_update(light_cfg, data)
            .ok()
            .ok_or(reason::BRIDGE_UPDATE)?;
        let (state, _) = state(light, light_cfg).ok_or(reason::BRIDGE_UPDATE)?;
        return sync::precheck(light_cfg, &state, &update)
            .ok()
            .ok_or(reason::BRIDGE_UPDATE);
    }
    if *to != INBOX_ADDRESS {
        return Ok(());
    }
    let delivery = Delivery::decode(data)
        .filter(|_| data[..4] == abi::DELIVER)
        .ok_or(reason::BRIDGE_CALL)?;
    verifier::admit(messages, delivery.message.nonce)
}

/// The calldata of `submitUpdate(update)` or `submitFinalityUpdate(update)`.
#[must_use]
pub fn submit_call(update: &[u8], finality: bool) -> Vec<u8> {
    abi::encode_bytes_call(
        if finality {
            abi::SUBMIT_FINALITY_UPDATE
        } else {
            abi::SUBMIT_UPDATE
        },
        update,
    )
}

/// The calldata of a function taking one `uint64`.
#[must_use]
pub fn u64_call(selector: [u8; 4], n: u64) -> Vec<u8> {
    encode(selector, &[word(n)])
}
