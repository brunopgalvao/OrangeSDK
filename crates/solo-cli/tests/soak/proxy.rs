//! The soak's network: every peer connection between two nodes runs
//! through a proxy of its own, so that a link can be cut (a partition),
//! slowed (a slow node) and healed while the nodes run. Nodes run without
//! peer exchange and dial only the proxies they are given, so no traffic
//! goes around them.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// The state of the link between two nodes, both directions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Link {
    /// No traffic: open connections close, new ones are closed at once.
    pub blocked: bool,
    /// Every chunk is held this long before it is passed on.
    pub delay_ms: u64,
    /// Bumped when the link is cut, so that connections opened before close.
    pub generation: u64,
}

/// Every link's state, by the unordered pair of node ids.
#[derive(Default)]
pub struct Net {
    links: Mutex<HashMap<(usize, usize), Link>>,
    stop: AtomicBool,
}

fn key(a: usize, b: usize) -> (usize, usize) {
    (a.min(b), a.max(b))
}

impl Net {
    /// The link between `a` and `b`.
    pub fn link(&self, a: usize, b: usize) -> Link {
        self.links
            .lock()
            .unwrap()
            .get(&key(a, b))
            .copied()
            .unwrap_or_default()
    }

    /// Cuts or heals the link between `a` and `b`.
    pub fn set_blocked(&self, a: usize, b: usize, blocked: bool) {
        let mut links = self.links.lock().unwrap();
        let link = links.entry(key(a, b)).or_default();
        if blocked && !link.blocked {
            link.generation += 1;
        }
        link.blocked = blocked;
    }

    /// Delays the link between `a` and `b`.
    pub fn set_delay(&self, a: usize, b: usize, delay_ms: u64) {
        self.links
            .lock()
            .unwrap()
            .entry(key(a, b))
            .or_default()
            .delay_ms = delay_ms;
    }

    /// Heals every link.
    pub fn heal_all(&self) {
        for link in self.links.lock().unwrap().values_mut() {
            link.blocked = false;
            link.delay_ms = 0;
        }
    }

    /// Stops every proxy thread.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}

/// Starts the proxy node `from` dials to reach node `to` at `target`; its
/// address.
pub fn spawn(net: &Arc<Net>, from: usize, to: usize, target: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("proxy listener");
    listener
        .set_nonblocking(true)
        .expect("non-blocking listener");
    let addr = listener.local_addr().expect("proxy address");
    let net = Arc::clone(net);
    thread::spawn(move || {
        while !net.stopped() {
            match listener.accept() {
                Ok((inbound, _)) => {
                    let link = net.link(from, to);
                    if link.blocked {
                        let _ = inbound.shutdown(Shutdown::Both);
                        continue;
                    }
                    let Ok(outbound) =
                        TcpStream::connect_timeout(&target, Duration::from_millis(500))
                    else {
                        let _ = inbound.shutdown(Shutdown::Both);
                        continue;
                    };
                    let _ = inbound.set_nonblocking(false);
                    pump_both(&net, from, to, link.generation, inbound, outbound);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => thread::sleep(Duration::from_millis(100)),
            }
        }
    });
    addr
}

fn pump_both(net: &Arc<Net>, from: usize, to: usize, generation: u64, a: TcpStream, b: TcpStream) {
    let (Ok(a2), Ok(b2)) = (a.try_clone(), b.try_clone()) else {
        return;
    };
    for (src, dst) in [(a, b2), (b, a2)] {
        let net = Arc::clone(net);
        thread::spawn(move || pump(&net, from, to, generation, src, dst));
    }
}

/// Copies `src` to `dst` until either closes or the link is cut.
fn pump(
    net: &Net,
    from: usize,
    to: usize,
    generation: u64,
    mut src: TcpStream,
    mut dst: TcpStream,
) {
    let _ = src.set_read_timeout(Some(Duration::from_millis(100)));
    let _ = dst.set_write_timeout(Some(Duration::from_secs(10)));
    let _ = dst.set_nodelay(true);
    let mut buf = vec![0u8; 64 * 1024];
    let close = |src: &TcpStream, dst: &TcpStream| {
        let _ = src.shutdown(Shutdown::Both);
        let _ = dst.shutdown(Shutdown::Both);
    };
    loop {
        let link = net.link(from, to);
        if net.stopped() || link.blocked || link.generation != generation {
            close(&src, &dst);
            return;
        }
        match src.read(&mut buf) {
            Ok(0) => {
                // The sender closed: pass the close on once what it sent is.
                let _ = dst.shutdown(Shutdown::Write);
                return;
            }
            Ok(n) => {
                let read_at = Instant::now();
                if link.delay_ms > 0 {
                    let due = read_at + Duration::from_millis(link.delay_ms);
                    while Instant::now() < due {
                        thread::sleep(Duration::from_millis(10).min(due - Instant::now()));
                        let now = net.link(from, to);
                        if now.blocked || now.generation != generation {
                            close(&src, &dst);
                            return;
                        }
                    }
                }
                if dst.write_all(&buf[..n]).is_err() {
                    close(&src, &dst);
                    return;
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => {
                close(&src, &dst);
                return;
            }
        }
    }
}
