//! The host's half of block catch-up (spec 09 §6a): the driver asks a peer
//! for finalized blocks (spec 08 §7a) and abandons the request when it
//! enters a view, which a node following a fast chain does every slot; an
//! answer that takes longer than a slot would then always be dropped, and a
//! node far behind would ask, drop and ask again forever. The host keeps
//! the requests on the wire across views instead: it sends the driver's
//! request under an id of its own, parks the answer, and hands it to the
//! driver's request for the same blocks, the one outstanding or the next
//! one. It asks ahead for the batches after a parked one while the peer
//! reports more, as many at a time as answers come back quickly, and asks
//! another peer, waiting twice as long each time, when one does not answer.
//!
//! The answers are the driver's to verify: the host only reads heights to
//! know which request an answer serves, trims the blocks the driver has
//! already finalized off the front of one, and drops one the driver
//! refused.

use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Unbounded};

use solo_abi::chain::{SyncRequest, SyncResponse};
use solo_abi::types::Input;
use solo_abi::{Decode, Encode};

use crate::extension::Outbound;

/// Ids of the host's own requests start here, above any the driver uses.
pub const HOST_IDS: u64 = 1 << 63;

/// How long the host first waits for an answer before it asks another
/// peer; each further try waits twice as long, up to [`MAX_WAIT_MS`].
pub const FIRST_WAIT_MS: u64 = 1_000;

/// The longest wait for one answer.
pub const MAX_WAIT_MS: u64 = 16_000;

/// The most requests on the wire at once: the one the driver wants and
/// the batches asked ahead of it.
pub const MAX_DEPTH: usize = 8;

/// A peer counts as reachable this long after the host last heard from it.
pub const PEER_TTL_MS: u64 = 30_000;

/// A request on the wire.
#[derive(Debug, Clone)]
struct Flight {
    from: u64,
    peer: [u8; 32],
    sent_ms: u64,
    deadline_ms: u64,
    /// How long this try waits; the next one waits twice as long.
    wait_ms: u64,
}

/// An answer the driver has not taken yet.
#[derive(Debug, Clone)]
struct Parked {
    response: SyncResponse,
    top: u64,
}

/// The host's catch-up state.
#[derive(Debug)]
pub struct CatchUp {
    on: bool,
    next_id: u64,
    flights: BTreeMap<u64, Flight>,
    /// Answers by the first height they hold.
    parked: BTreeMap<u64, Parked>,
    /// The driver's latest request not answered yet: its id and first height.
    wanted: Option<(u64, u64)>,
    /// The first height of a parked answer handed to the driver this step.
    handed: Option<u64>,
    /// When each peer was last heard from.
    peers: BTreeMap<[u8; 32], u64>,
    /// How many requests may be on the wire.
    depth: usize,
    /// How many blocks the last answer held: how far apart requests asked
    /// ahead start.
    stride: u64,
    /// The peer last asked.
    tried: [u8; 32],
}

impl Default for CatchUp {
    fn default() -> CatchUp {
        CatchUp {
            on: true,
            next_id: HOST_IDS,
            flights: BTreeMap::new(),
            parked: BTreeMap::new(),
            wanted: None,
            handed: None,
            peers: BTreeMap::new(),
            depth: 1,
            stride: 1,
            tried: [0; 32],
        }
    }
}

/// `response` without the proposals below `from`; `None` when it holds no
/// proposal at `from`.
fn trimmed(response: &SyncResponse, from: u64) -> Option<Vec<u8>> {
    let mut response = response.clone();
    response.proposals.0.retain(|p| p.height >= from);
    (response.proposals.0.first()?.height == from).then(|| response.to_bytes())
}

impl CatchUp {
    /// Turns the host's catch-up on or off; off, requests and answers pass
    /// between the driver and the wire untouched, as before it existed.
    pub fn set(&mut self, on: bool) {
        self.on = on;
    }

    /// How many requests may be on the wire now.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// How many of the host's requests are on the wire.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.flights.len()
    }

    /// How many answers wait for the driver.
    #[must_use]
    pub fn parked(&self) -> usize {
        self.parked.len()
    }

    /// Notes that `peer` was heard from at `now_ms`.
    pub fn heard(&mut self, peer: [u8; 32], now_ms: u64) {
        self.peers.insert(peer, now_ms);
    }

    /// Takes the driver's request: the parked answer that serves it, as
    /// the input to step the driver with, or `None` and the request goes
    /// out (unless one for the same blocks is on the wire already).
    /// Anything that is not a sync request goes out as it is.
    pub fn on_request(
        &mut self,
        peer: [u8; 32],
        request_id: u64,
        payload: Vec<u8>,
        now_ms: u64,
        out: &mut Vec<Outbound>,
    ) -> Option<Input> {
        let from = match SyncRequest::from_bytes(&payload) {
            Ok(request) if self.on => request.from_height,
            _ => {
                out.push(Outbound::Request {
                    peer,
                    request_id,
                    payload,
                });
                return None;
            }
        };
        self.heard(peer, now_ms);
        self.forget_below(from);
        if let Some((&first, parked)) = self.parked.range(..=from).next_back()
            && let Some(payload) = trimmed(&parked.response, from)
        {
            if self.handed != Some(first) {
                self.wanted = None;
                self.handed = Some(first);
                return Some(Input::Response {
                    request_id,
                    payload,
                });
            }
            // Handed in this very step and asked for again: the driver
            // refused it. It is dropped now, not after the step, or a driver
            // that asks again at once would be handed it for ever.
            self.parked.remove(&first);
            self.handed = None;
            self.depth = 1;
        }
        self.wanted = Some((request_id, from));
        if !self.flights.values().any(|f| f.from == from) {
            self.send(peer, from, FIRST_WAIT_MS, now_ms, out);
        }
        None
    }

    /// Takes an answer from the wire: the input to step the driver with,
    /// if any. An answer to the driver's own request (catch-up off) goes to
    /// it as it is; one to the host's is parked, and handed to the driver's
    /// outstanding request if it serves that one.
    pub fn on_response(
        &mut self,
        request_id: u64,
        payload: Vec<u8>,
        now_ms: u64,
        out: &mut Vec<Outbound>,
    ) -> Option<Input> {
        let Some(flight) = self.flights.remove(&request_id) else {
            // A second answer to a request already answered or retried is
            // nobody's.
            return (request_id < HOST_IDS).then_some(Input::Response {
                request_id,
                payload,
            });
        };
        self.heard(flight.peer, now_ms);
        let Some(response) = SyncResponse::from_bytes(&payload)
            .ok()
            .filter(|r| r.certificate.is_some())
        else {
            // Nothing to serve from: the next poll asks someone else.
            return None;
        };
        let (first, top) = response
            .proposals
            .0
            .first()
            .zip(response.proposals.0.last())
            .map(|(a, b)| (a.height, b.height))?;
        // Quick answers widen the window; slow ones narrow it.
        if now_ms.saturating_sub(flight.sent_ms) <= flight.wait_ms / 4 {
            self.depth = (self.depth + 1).min(MAX_DEPTH);
        } else {
            self.depth = (self.depth / 2).max(1);
        }
        self.stride = top - first + 1;
        let limit = response.finalized_height;
        self.parked.insert(first, Parked { response, top });
        self.ask_ahead(flight.peer, limit, now_ms, out);
        let (id, from) = self
            .wanted
            .filter(|(_, from)| (first..=top).contains(from))?;
        self.wanted = None;
        trimmed(&self.parked[&first].response, from).map(|payload| Input::Response {
            request_id: id,
            payload,
        })
    }

    /// After a step: a parked answer the driver was handed is spent and
    /// dropped, so it is not handed again. The driver takes an answer whole
    /// or not at all, so what is left of one it took holds only suffix
    /// proposals (spec 08 §3a), which it never takes. One it did not take
    /// (its finalized height is still below it) was refused, and the peer
    /// that sent it is asked nothing more for now.
    pub fn settle(&mut self, finalized: u64) {
        if let Some(first) = self.handed.take()
            && self.parked.remove(&first).is_some()
            && finalized < first
        {
            self.depth = 1;
        }
    }

    /// Asks again what timed out, of the next reachable peer, waiting twice
    /// as long; and the driver's outstanding request when nothing serves it.
    /// What the driver finalized, `finalized` and below, is not asked again.
    /// The driver's outstanding request, once the driver finalized its first
    /// height by other means, is answered with an empty `Response`, the
    /// input to step the driver with: the driver drops it, and is free to
    /// ask again. Without it the driver would wait for that answer until it
    /// next enters a view, which a node whose peers have moved on to the
    /// next epoch never does.
    pub fn poll(&mut self, now_ms: u64, finalized: u64, out: &mut Vec<Outbound>) -> Option<Input> {
        self.forget_below(finalized + 1);
        let moot = self
            .wanted
            .take_if(|(_, from)| *from <= finalized)
            .map(|(request_id, _)| Input::Response {
                request_id,
                payload: Vec::new(),
            });
        let late: Vec<Flight> = self
            .flights
            .extract_if(.., |_, f| f.deadline_ms <= now_ms)
            .map(|(_, f)| f)
            .collect();
        for flight in late {
            self.depth = 1;
            let peer = self.next_peer(&flight.peer, now_ms);
            let wait = (flight.wait_ms * 2).min(MAX_WAIT_MS);
            self.send(peer, flight.from, wait, now_ms, out);
        }
        if let Some((_, from)) = self.wanted
            && !self.flights.values().any(|f| f.from == from)
        {
            let peer = self.next_peer(&self.tried, now_ms);
            self.send(peer, from, FIRST_WAIT_MS, now_ms, out);
        }
        moot
    }

    /// Forgets what holds nothing from `from` on: answers wholly below it,
    /// and requests whose answers would, by the stride, end below it.
    fn forget_below(&mut self, from: u64) {
        let stride = self.stride;
        self.parked.retain(|_, p| p.top >= from);
        self.flights.retain(|_, f| f.from + stride > from);
    }

    /// Asks `peer` for the batches after the highest parked one, up to
    /// `limit`, the peer's finalized height, as far as the window allows.
    /// The batch after a request on the wire is guessed to start one
    /// stride after it: an answer that starts lower overlaps and is
    /// trimmed, one that starts higher leaves a gap the driver's own
    /// request fills.
    fn ask_ahead(&mut self, peer: [u8; 32], limit: u64, now_ms: u64, out: &mut Vec<Outbound>) {
        while self.flights.len() < self.depth {
            let next = self
                .parked
                .values()
                .map(|p| p.top + 1)
                .chain(self.flights.values().map(|f| f.from + self.stride))
                .max()
                .expect("an answer was just parked");
            if next > limit {
                return;
            }
            self.send(peer, next, FIRST_WAIT_MS, now_ms, out);
        }
    }

    /// The reachable peer after `peer` in id order, wrapping; `peer` itself
    /// when it is the only one.
    fn next_peer(&self, peer: &[u8; 32], now_ms: u64) -> [u8; 32] {
        let reachable = |(p, seen): (&[u8; 32], &u64)| {
            (now_ms.saturating_sub(*seen) <= PEER_TTL_MS).then_some(*p)
        };
        self.peers
            .range((Excluded(*peer), Unbounded))
            .chain(self.peers.range(..*peer))
            .find_map(reachable)
            .unwrap_or(*peer)
    }

    fn send(
        &mut self,
        peer: [u8; 32],
        from: u64,
        wait_ms: u64,
        now_ms: u64,
        out: &mut Vec<Outbound>,
    ) {
        self.tried = peer;
        let id = self.next_id;
        self.next_id += 1;
        self.flights.insert(
            id,
            Flight {
                from,
                peer,
                sent_ms: now_ms,
                deadline_ms: now_ms + wait_ms,
                wait_ms,
            },
        );
        out.push(Outbound::Request {
            peer,
            request_id: id,
            payload: SyncRequest { from_height: from }.to_bytes(),
        });
    }
}
