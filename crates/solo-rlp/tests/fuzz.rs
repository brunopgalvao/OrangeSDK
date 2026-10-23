//! Seeded fuzzing of RLP decoding: random and mutated bytes never panic
//! the decoder, everything it accepts re-encodes to exactly the input, and
//! the typed readers never panic on what it accepts. See `solo-fuzz` for
//! the long mode.

use solo_fuzz::{evolve, zero_seeds};
use solo_rlp::{Item, decode, decode_prefix, encode_item, encode_uint};

/// Every typed reader on every item; an integer it reads is canonical, so
/// it re-encodes to the item.
fn walk(item: &Item<'_>) {
    let _ = (item.u64(), item.u256(), item.array::<20>(), item.bytes());
    if let Ok(v) = item.u128() {
        let (mut ours, mut theirs) = (Vec::new(), Vec::new());
        encode_uint(v, &mut ours);
        encode_item(item, &mut theirs);
        assert_eq!(ours, theirs);
        assert_eq!(item.u64().ok(), u64::try_from(v).ok());
    }
    if let Ok(items) = item.list() {
        items.iter().for_each(walk);
    }
}

#[test]
fn accepted_items_reencode_exactly() {
    let mut seeds = zero_seeds(0xFF, 3);
    seeds.push(vec![0xC4, 0x83, b'd', b'o', b'g']);
    seeds.push(vec![0xC7, 0xC0, 0xC1, 0xC0, 0xC3, 0xC0, 0xC1, 0xC0]);
    seeds.push([&[0xB8, 0x38][..], &[0xAB; 56]].concat());
    let accepted = evolve("rlp-items", 20_000, seeds, |bytes| {
        let _ = decode_prefix(bytes);
        let Ok(item) = decode(bytes) else {
            return false;
        };
        let mut out = Vec::new();
        encode_item(&item, &mut out);
        assert_eq!(out, bytes);
        walk(&item);
        true
    });
    assert!(accepted > 2_000, "{accepted}");
}
