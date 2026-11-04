//! `solo node --sync-from-peers` stops with the reason when no peer can
//! serve it (spec 09 §6), instead of waiting for ever.

use solo_cli::snapshot::{stopped, sync_from_peers};
use solo_node::net::SYNC_PEER_WAIT_MS;
use solo_node::statesync::SyncConfig;
use std::cell::Cell;

#[test]
fn a_sync_without_peers_stops() {
    let dir = solo_scratch::Scratch::new("solo-cli", "lonely-sync");
    let config = SyncConfig {
        chain_id: 1337,
        trust: solo_store::Trust::Key([0; 96]),
        genesis_hash: None,
        dir: dir.to_path_buf(),
    };
    let key = solo_node::net::fresh_key().unwrap();
    let mut transport =
        solo_node::Transport::bind("127.0.0.1:0", key, 1337, [7; 32], vec![]).unwrap();
    // Every reading of the clock is a quarter of the wait later.
    let clock = Cell::new(0);
    let now = || {
        clock.set(clock.get() + SYNC_PEER_WAIT_MS / 4);
        clock.get()
    };
    assert_eq!(
        sync_from_peers(config, &mut transport, &now).unwrap_err(),
        "state sync: no peer to sync from in time"
    );
    // A sync's own failure comes first; a trust too old for what the peers
    // offered says so when they ran out (spec 22 §7.5).
    let old = || Some("too old".to_owned());
    assert_eq!(stopped(None, || None, old), None);
    assert_eq!(
        stopped(None, || Some("no peer to sync from in time"), old).as_deref(),
        Some("state sync: no peer to sync from in time: too old")
    );
    assert_eq!(
        stopped(Some("another genesis"), || None, old).as_deref(),
        Some("state sync: another genesis")
    );
}

/// A node too far behind to catch up from its peers' blocks says so once
/// when that starts, and once when it ends (spec 09 §6a, step 6).
#[test]
fn a_sync_alert_is_logged_when_it_changes() {
    use solo_cli::sync_alert_change as change;
    assert_eq!(change(None, None), None);
    assert_eq!(
        change(None, Some("block 1 is no longer kept")).as_deref(),
        Some("catch-up: block 1 is no longer kept")
    );
    assert_eq!(change(Some("a"), Some("b")), None);
    assert_eq!(
        change(Some("a"), None).as_deref(),
        Some("catch-up: peers serve the blocks this node needs again")
    );
}
