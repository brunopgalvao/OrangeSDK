//! A raw peer for the transport tests: a socket that says the handshake of
//! spec 09 §3 by hand, with any key, and seals what follows it (§3a), so a
//! test can also get either wrong.

#![allow(dead_code)]

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use k256::ecdsa::SigningKey;
use orange_host::hash::keccak256;
use orange_node::net::{Frame, MAX_FRAME, frame_bytes, hello_digest, take_frame};
use orange_node::session::{Ephemeral, Session, Side, VERSION};
use orange_node::{sign_recoverable, validator_id};

/// The chain a raw peer says it is on.
#[derive(Debug, Clone, Copy)]
pub struct Chain {
    pub chain_id: u64,
    pub genesis: [u8; 32],
}

/// The fresh key a raw peer draws for a connection whose nonce is `nonce`.
#[must_use]
pub fn ephemeral(nonce: &[u8; 32]) -> Ephemeral {
    Ephemeral::from_seed(&keccak256(&[b"raw".as_slice(), nonce].concat()))
}

impl Chain {
    /// A `Hello` of this version naming `id` with `nonce` on this chain,
    /// and the fresh key [`ephemeral`] draws for that nonce.
    #[must_use]
    pub fn hello(&self, id: [u8; 32], nonce: [u8; 32]) -> Frame {
        Frame::Hello {
            version: VERSION,
            id,
            chain_id: self.chain_id,
            genesis: self.genesis,
            nonce,
            ephemeral: ephemeral(&nonce).public(),
        }
    }

    /// The `Auth` of `key` for a connection whose own `Hello` committed to
    /// `mine` and whose peer's to `theirs`.
    #[must_use]
    pub fn auth(&self, key: &SigningKey, mine: &Side, theirs: &Side) -> Frame {
        let digest = hello_digest(self.chain_id, &self.genesis, mine, theirs);
        Frame::Auth {
            signature: sign_recoverable(key, &digest).unwrap(),
        }
    }
}

/// One end of a connection, spoken by hand: frames go out in the clear
/// until the other end's `Hello` has been read, and sealed after it.
pub struct Wire {
    pub s: TcpStream,
    pub chain: Chain,
    /// What this end's `Hello` commits it to.
    pub side: Side,
    /// What the other end's `Hello` committed it to, once read.
    pub theirs: Option<Side>,
    /// Every byte read, sealed or not.
    pub seen: Vec<u8>,
    ephemeral: Option<Ephemeral>,
    session: Option<Session>,
    buf: Vec<u8>,
}

impl Wire {
    /// A wire over `s` whose `Hello` will carry `nonce`.
    #[must_use]
    pub fn over(s: TcpStream, chain: Chain, nonce: [u8; 32]) -> Wire {
        let ephemeral = ephemeral(&nonce);
        Wire {
            s,
            chain,
            side: Side {
                nonce,
                ephemeral: ephemeral.public(),
            },
            theirs: None,
            seen: Vec::new(),
            ephemeral: Some(ephemeral),
            session: None,
            buf: Vec::new(),
        }
    }

    /// Dials `addr`.
    #[must_use]
    pub fn dial(addr: SocketAddr, chain: Chain, nonce: [u8; 32]) -> Wire {
        Wire::over(TcpStream::connect(addr).unwrap(), chain, nonce)
    }

    /// This end's `Hello`, naming `id`.
    #[must_use]
    pub fn hello(&self, id: [u8; 32]) -> Frame {
        self.chain.hello(id, self.side.nonce)
    }

    /// This connection's `Auth` signed by `key`.
    #[must_use]
    pub fn auth(&self, key: &SigningKey) -> Frame {
        self.chain.auth(key, &self.side, &self.theirs.unwrap())
    }

    /// Writes `bytes` as they are.
    pub fn write(&mut self, bytes: &[u8]) {
        self.s.write_all(bytes).unwrap();
    }

    /// Writes `frame` in the clear.
    pub fn send_clear(&mut self, frame: &Frame) {
        self.write(&frame_bytes(frame));
    }

    /// `frame` sealed under the session, counted as sent.
    pub fn seal(&mut self, frame: &Frame) -> Vec<u8> {
        self.session
            .as_mut()
            .expect("no session yet")
            .seal(frame)
            .unwrap()
    }

    /// Writes `frame`, sealed once the session is agreed.
    pub fn send(&mut self, frame: &Frame) {
        if self.session.is_some() {
            let sealed = self.seal(frame);
            self.write(&sealed);
        } else {
            self.send_clear(frame);
        }
    }

    /// The whole frames read so far: a `Hello` in the clear agrees the
    /// session, and what follows it is opened under it.
    fn frames(&mut self) -> Vec<Frame> {
        let mut out = Vec::new();
        loop {
            let frame = match self.session.as_mut() {
                Some(session) => session.open(&mut self.buf).expect("a frame that opens"),
                None => take_frame(&mut self.buf, MAX_FRAME).unwrap(),
            };
            let Some(frame) = frame else {
                return out;
            };
            if let Frame::Hello {
                nonce, ephemeral, ..
            } = frame
            {
                let theirs = Side { nonce, ephemeral };
                self.theirs = Some(theirs);
                let c = self.chain;
                self.session = Session::new(
                    self.ephemeral.take().unwrap(),
                    c.chain_id,
                    &c.genesis,
                    &self.side,
                    &theirs,
                );
            }
            out.push(frame);
        }
    }

    /// Reads while calling `poll`, until `done` holds for the frames read or
    /// `max` passes: the frames, and whether the other end closed.
    pub fn read_for(
        &mut self,
        max: Duration,
        poll: &mut dyn FnMut(),
        mut done: impl FnMut(&[Frame]) -> bool,
    ) -> (Vec<Frame>, bool) {
        self.s.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + max;
        let (mut frames, mut chunk) = (Vec::new(), [0u8; 4096]);
        let mut closed = false;
        while Instant::now() < deadline && !closed && !done(&frames) {
            poll();
            loop {
                match self.s.read(&mut chunk) {
                    Ok(0) => {
                        closed = true;
                        break;
                    }
                    Ok(n) => {
                        self.buf.extend_from_slice(&chunk[..n]);
                        self.seen.extend_from_slice(&chunk[..n]);
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => {
                        closed = true;
                        break;
                    }
                }
            }
            frames.extend(self.frames());
            std::thread::sleep(Duration::from_millis(2));
        }
        self.s.set_nonblocking(false).unwrap();
        (frames, closed)
    }

    /// [`Wire::read_for`] for up to ten seconds.
    pub fn read_until(
        &mut self,
        poll: &mut dyn FnMut(),
        done: impl FnMut(&[Frame]) -> bool,
    ) -> (Vec<Frame>, bool) {
        self.read_for(Duration::from_secs(10), poll, done)
    }

    /// Whether the other end closes within ten seconds, polled by `poll`.
    pub fn closes(&mut self, poll: &mut dyn FnMut()) -> bool {
        self.read_until(poll, |_| false).1
    }
}

/// The nonce of the first `Hello` among `frames`.
#[must_use]
pub fn nonce_of(frames: &[Frame]) -> Option<[u8; 32]> {
    frames.iter().find_map(|f| match f {
        Frame::Hello { nonce, .. } => Some(*nonce),
        _ => None,
    })
}

/// Completes the handshake on `w`, a connection either end opened, as the
/// holder of `key`: says `Hello`, waits for the other end's while calling
/// `poll`, and sends `Auth`, sealed. The frames read on the way, the other
/// end's `Hello` among them.
pub fn complete(w: &mut Wire, key: &SigningKey, poll: &mut dyn FnMut()) -> Vec<Frame> {
    w.send_clear(&w.hello(validator_id(key)));
    let (frames, _) = w.read_until(poll, |f| nonce_of(f).is_some());
    assert!(nonce_of(&frames).is_some(), "the other end said no Hello");
    w.send(&w.auth(key));
    frames
}

/// Dials `addr` and completes the handshake as the holder of `key`.
pub fn connect(
    addr: SocketAddr,
    key: &SigningKey,
    chain: Chain,
    poll: &mut dyn FnMut(),
) -> (Wire, Vec<Frame>) {
    let mut w = Wire::dial(addr, chain, keccak256(&validator_id(key)));
    let frames = complete(&mut w, key, poll);
    (w, frames)
}
