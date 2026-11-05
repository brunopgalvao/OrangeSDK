//! Seeded fuzzing of what a node decodes from its peers: transport frames
//! (spec 09), including the stream splitter fed in arbitrary chunks, the
//! state sync's requests and responses (spec 22 §7.4), and the snapshot
//! header a manifest carries. Random and mutated bytes never panic a
//! decoder, and whatever one accepts re-encodes to exactly its input. See
//! `orange-fuzz` for the long mode.

use std::fmt::Debug;

use orange_abi::{Decode, Encode};
use orange_fuzz::{Rng, evolve, zero_seeds};
use orange_node::net::{Frame, MAX_FRAME, frame_bytes, take_frames};
use orange_node::statesync::{Entry, Manifest, Offer, Summary, SyncRequest, SyncResponse};
use orange_store::snapshot::SnapshotHeader;

fn codec<T: Encode + Decode + PartialEq + Debug>(name: &str, cases: u64) {
    evolve(name, cases, zero_seeds(8, 120), |bytes| {
        let Ok(value) = T::from_bytes(bytes) else {
            return false;
        };
        assert_eq!(
            value.to_bytes(),
            bytes,
            "{name}: {value:?} is not canonical"
        );
        true
    });
}

#[test]
fn peer_messages_decode_only_canonical_bytes() {
    codec::<Frame>("node-frame", 3_000);
    codec::<SyncRequest>("node-sync-request", 1_000);
    codec::<SyncResponse>("node-sync-response", 3_000);
    codec::<Manifest>("node-manifest", 1_000);
    codec::<Offer>("node-offer", 300);
    codec::<Summary>("node-summary", 300);
    codec::<Entry>("node-entry", 300);
    codec::<SnapshotHeader>("node-snapshot-header", 2_000);
}

fn frame(r: &mut Rng) -> Frame {
    let len = r.index(40);
    let payload = r.bytes(len);
    let id = r.u64();
    match r.below(8) {
        0 => Frame::Hello {
            version: u16::try_from(r.below(3)).unwrap(),
            id: r.array32(),
            chain_id: id,
            genesis: r.array32(),
            nonce: r.array32(),
            ephemeral: std::array::from_fn(|_| r.byte()),
        },
        6 => Frame::Auth {
            signature: std::array::from_fn(|_| r.byte()),
        },
        1 => Frame::Message {
            topic: u16::try_from(r.below(5)).unwrap(),
            payload,
        },
        2 => Frame::Tx { raw: payload },
        3 => Frame::Request {
            request_id: id,
            payload,
        },
        4 => Frame::Response {
            request_id: id,
            payload,
        },
        5 => Frame::SyncRequest {
            request_id: id,
            payload,
        },
        _ => Frame::SyncResponse {
            request_id: id,
            payload,
        },
    }
}

#[test]
fn a_stream_splits_into_the_same_frames_however_it_arrives() {
    orange_fuzz::run("node-frame-stream", 500, |r| {
        let frames: Vec<Frame> = (0..r.below(6)).map(|_| frame(r)).collect();
        let mut stream: Vec<u8> = frames.iter().flat_map(frame_bytes).collect();
        let corrupt = r.chance(1, 4);
        if corrupt {
            stream = r.mutate(&stream);
        }
        // Deliver the stream in random chunks, as reads return it.
        let mut buf = Vec::new();
        let mut got = Vec::new();
        let mut failed = false;
        let mut at = 0;
        while at < stream.len() && !failed {
            let n = 1 + r.index(stream.len() - at);
            buf.extend_from_slice(&stream[at..at + n]);
            at += n;
            match take_frames(&mut buf) {
                Ok(f) => got.extend(f),
                Err(_) => failed = true,
            }
        }
        if !corrupt {
            assert!(!failed);
            assert_eq!(got, frames);
            assert!(buf.is_empty());
        }
        // Whatever was taken is a prefix-consistent decoding: each frame
        // re-encodes to bytes of the stream, in order.
        let taken: Vec<u8> = got.iter().flat_map(frame_bytes).collect();
        assert!(stream.starts_with(&taken));
    });
    // A length word over the limit closes the stream before its body comes.
    let mut buf = u32::try_from(MAX_FRAME + 1).unwrap().to_le_bytes().to_vec();
    assert!(take_frames(&mut buf).is_err());
}
