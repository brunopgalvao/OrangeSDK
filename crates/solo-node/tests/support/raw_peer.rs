//! A raw peer for the transport tests: a socket that says the handshake of
//! spec 09 §3 by hand, with any key, so a test can also get it wrong.

#![allow(dead_code)]

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use k256::ecdsa::SigningKey;
use solo_node::net::{Frame, frame_bytes, hello_digest, take_frames};
use solo_node::{sign_recoverable, validator_id};

/// The chain a raw peer says it is on.
#[derive(Debug, Clone, Copy)]
pub struct Chain {
    pub chain_id: u64,
    pub genesis: [u8; 32],
}

impl Chain {
    /// A `Hello` naming `id` with `nonce` on this chain.
    #[must_use]
    pub fn hello(&self, id: [u8; 32], nonce: [u8; 32]) -> Frame {
        Frame::Hello {
            id,
            chain_id: self.chain_id,
            genesis: self.genesis,
            nonce,
        }
    }

    /// The `Auth` of `key` for a connection whose own nonce is `mine` and
    /// whose peer's is `theirs`.
    #[must_use]
    pub fn auth(&self, key: &SigningKey, mine: &[u8; 32], theirs: &[u8; 32]) -> Frame {
        let digest = hello_digest(self.chain_id, &self.genesis, mine, theirs);
        Frame::Auth {
            signature: sign_recoverable(key, &digest).unwrap(),
        }
    }
}

pub fn send(s: &mut TcpStream, frame: &Frame) {
    s.write_all(&frame_bytes(frame)).unwrap();
}

/// Reads `s` while calling `poll`, until `done` holds for the frames read
/// or ten seconds pass: the frames, and whether the other end closed.
pub fn read_until(
    s: &mut TcpStream,
    poll: &mut dyn FnMut(),
    mut done: impl FnMut(&[Frame]) -> bool,
) -> (Vec<Frame>, bool) {
    s.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut buf, mut frames, mut chunk) = (Vec::new(), Vec::new(), [0u8; 4096]);
    let mut closed = false;
    while Instant::now() < deadline && !closed && !done(&frames) {
        poll();
        loop {
            match s.read(&mut chunk) {
                Ok(0) => {
                    closed = true;
                    break;
                }
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => {
                    closed = true;
                    break;
                }
            }
        }
        frames.extend(take_frames(&mut buf).unwrap());
        std::thread::sleep(Duration::from_millis(2));
    }
    s.set_nonblocking(false).unwrap();
    (frames, closed)
}

/// The nonce of the first `Hello` among `frames`.
#[must_use]
pub fn nonce_of(frames: &[Frame]) -> Option<[u8; 32]> {
    frames.iter().find_map(|f| match f {
        Frame::Hello { nonce, .. } => Some(*nonce),
        _ => None,
    })
}

/// Completes the handshake on `s`, a connection either end opened, as the
/// holder of `key`: says `Hello`, waits for the other end's while calling
/// `poll`, and sends `Auth`. The frames read on the way, the other end's
/// `Hello` among them.
pub fn complete(
    s: &mut TcpStream,
    key: &SigningKey,
    chain: Chain,
    poll: &mut dyn FnMut(),
) -> Vec<Frame> {
    let mine = solo_host::hash::keccak256(&validator_id(key));
    send(s, &chain.hello(validator_id(key), mine));
    let (frames, _) = read_until(s, poll, |f| nonce_of(f).is_some());
    let theirs = nonce_of(&frames).expect("the other end said no Hello");
    send(s, &chain.auth(key, &mine, &theirs));
    frames
}

/// Dials `addr` and completes the handshake as the holder of `key`.
pub fn connect(
    addr: SocketAddr,
    key: &SigningKey,
    chain: Chain,
    poll: &mut dyn FnMut(),
) -> (TcpStream, Vec<Frame>) {
    let mut s = TcpStream::connect(addr).unwrap();
    let frames = complete(&mut s, key, chain, poll);
    (s, frames)
}
