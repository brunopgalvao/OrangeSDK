//! Addresses an operator names: an `ip:port`, or a `host:port` whose DNS
//! name is resolved at every dial (spec 09 §5, §5a.5), off the thread that
//! drives the node and within a bounded time, so that a record that changed
//! is picked up at the next dial and a slow resolver never holds the node.
//!
//! Only configured peers and bootstrap addresses take names; the signed
//! records of peer exchange carry an `ip:port` (spec 09 §5a.1).

use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// How long a dial of a name may take in all, its resolution and its
/// connection attempts together (spec 09 §5); past it the dial is
/// abandoned and counts as failed.
pub const RESOLVE_MS: u64 = 5_000;

/// Most dials of names whose threads still run, abandoned ones included
/// (spec 09 §5): no new one starts past them, so a resolver that hangs
/// holds at most this many threads.
pub const MAX_RESOLVING: usize = 8;

/// Longest DNS name taken, in bytes.
pub const MAX_NAME: usize = 253;

/// A configured peer's or a bootstrap address: an IP address and port, or a
/// DNS name and port.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PeerAddr {
    /// An `ip:port`, dialled as it is.
    Ip(SocketAddr),
    /// A `host:port`, resolved at every dial.
    Name {
        /// The DNS name.
        host: String,
        /// The port.
        port: u16,
    },
}

impl From<SocketAddr> for PeerAddr {
    fn from(addr: SocketAddr) -> PeerAddr {
        PeerAddr::Ip(addr)
    }
}

impl fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerAddr::Ip(addr) => addr.fmt(f),
            PeerAddr::Name { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

/// Whether `host` is a DNS name: at most [`MAX_NAME`] bytes, of labels of 1
/// to 63 letters, digits and hyphens, none starting or ending with a
/// hyphen, and not all digits and dots (a malformed IPv4 address). A final
/// dot is allowed.
fn is_name(host: &str) -> bool {
    let bare = host.strip_suffix('.').unwrap_or(host);
    let label = |l: &str| {
        (1..=63).contains(&l.len())
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    host.len() <= MAX_NAME
        && bare.split('.').all(label)
        && !bare.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

impl FromStr for PeerAddr {
    type Err = ();

    /// An `ip:port` (`[v6]:port` for IPv6), or a `host:port` with a DNS
    /// name and a port from 1 to 65535.
    fn from_str(text: &str) -> Result<PeerAddr, ()> {
        if let Ok(addr) = text.parse::<SocketAddr>() {
            return Ok(PeerAddr::Ip(addr));
        }
        let (host, port) = text.rsplit_once(':').ok_or(())?;
        let port: u16 = port.parse().ok().filter(|p| *p != 0).ok_or(())?;
        is_name(host).then_some(()).ok_or(())?;
        Ok(PeerAddr::Name {
            host: host.to_ascii_lowercase(),
            port,
        })
    }
}

impl PeerAddr {
    /// `text` as an address a node can dial: an `ip:port` that is
    /// [`crate::peers::dialable`], or a `host:port`.
    #[must_use]
    pub fn dialable(text: &str) -> Option<PeerAddr> {
        text.parse()
            .ok()
            .filter(|a| !matches!(a, PeerAddr::Ip(ip) if !crate::peers::dialable(ip)))
    }
}

/// Turns a DNS name into addresses. The reference host asks the operating
/// system ([`SystemResolver`]); tests give one of their own.
pub trait Resolve: Send + Sync {
    /// Every address `host` names, A and AAAA records alike, with `port`.
    ///
    /// # Errors
    /// If the name does not resolve.
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

/// The operating system's resolver.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok((host, port).to_socket_addrs()?.collect())
    }
}

/// Counts a running dial of a name for as long as its thread lives.
struct Running(Arc<AtomicUsize>);

impl Drop for Running {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Connects to `addr`: an IP address within `timeout`; a name resolved by
/// `resolver`, then each address it gives tried in order, each within
/// `timeout`, until one connects or `within` has passed since the call
/// ([`RESOLVE_MS`] for the transport's dials).
///
/// # Errors
/// The last attempt's error, `TimedOut` once `within` has passed, or
/// `NotFound` when the name gave no address.
pub fn connect(
    addr: &PeerAddr,
    resolver: &dyn Resolve,
    timeout: Duration,
    within: Duration,
) -> io::Result<TcpStream> {
    let (host, port) = match addr {
        PeerAddr::Ip(ip) => return TcpStream::connect_timeout(ip, timeout),
        PeerAddr::Name { host, port } => (host, *port),
    };
    let by = Instant::now() + within;
    let mut last = io::Error::from(io::ErrorKind::NotFound);
    for ip in resolver.resolve(host, port)? {
        let left = by.saturating_duration_since(Instant::now()).min(timeout);
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match TcpStream::connect_timeout(&ip, left) {
            Ok(stream) => return Ok(stream),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Dials `addr` on a thread of its own and hands `done` the result. A dial
/// of a name counts in `running` while its thread lives; none starts while
/// [`MAX_RESOLVING`] run, and `false` says so.
pub fn spawn_dial(
    addr: PeerAddr,
    resolver: &Arc<dyn Resolve>,
    running: &Arc<AtomicUsize>,
    timeout: Duration,
    done: Box<dyn FnOnce(io::Result<TcpStream>) + Send>,
) -> bool {
    let guard = match addr {
        PeerAddr::Ip(_) => None,
        PeerAddr::Name { .. } => {
            if running.fetch_add(1, Ordering::SeqCst) >= MAX_RESOLVING {
                running.fetch_sub(1, Ordering::SeqCst);
                return false;
            }
            Some(Running(Arc::clone(running)))
        }
    };
    let resolver = Arc::clone(resolver);
    std::thread::spawn(move || {
        let _guard = guard;
        let within = Duration::from_millis(RESOLVE_MS);
        done(connect(&addr, &*resolver, timeout, within));
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_parse_as_ips_or_names_and_print_back() {
        let ip: PeerAddr = "10.0.0.1:30333".parse().unwrap();
        assert_eq!(ip, PeerAddr::Ip("10.0.0.1:30333".parse().unwrap()));
        let v6: PeerAddr = "[::1]:7".parse().unwrap();
        assert_eq!(v6.to_string(), "[::1]:7");
        let name: PeerAddr = "Orange-0.example.org.:30333".parse().unwrap();
        assert_eq!(
            name,
            PeerAddr::Name {
                host: "orange-0.example.org.".into(),
                port: 30333
            }
        );
        assert_eq!(name.to_string(), "orange-0.example.org.:30333");
        assert_eq!(ip.to_string(), "10.0.0.1:30333");
        for bad in [
            "",
            "nope",
            "host:",
            "host:0",
            "host:65536",
            ":80",
            "-a.org:1",
            "a-.org:1",
            "a..org:1",
            "a_b:1",
            "10.0.0:1",
            "1.2.3.4.5:1",
            "::1:80",
        ] {
            assert_eq!(bad.parse::<PeerAddr>(), Err(()), "{bad}");
        }
        let long = format!("{}:1", vec!["a".repeat(63); 4].join("."));
        assert!(long.parse::<PeerAddr>().is_err());
        let longest = format!("{}.{}:1", vec!["a".repeat(63); 3].join("."), "a".repeat(61));
        assert!(longest.parse::<PeerAddr>().is_ok());
        assert!(format!("{}:1", "a".repeat(64)).parse::<PeerAddr>().is_err());
    }

    struct Fixed(Vec<SocketAddr>);

    impl Resolve for Fixed {
        fn resolve(&self, _: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
            Ok(self
                .0
                .iter()
                .map(|a| SocketAddr::new(a.ip(), port))
                .collect())
        }
    }

    /// A name that gives nothing is not found, and the addresses left once
    /// the time is up are not tried.
    #[test]
    fn a_dial_of_a_name_stops_when_it_runs_out_of_addresses_or_time() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr: PeerAddr = format!("seed.test:{}", listener.local_addr().unwrap().port())
            .parse()
            .unwrap();
        let second = Duration::from_secs(1);
        let none = connect(&addr, &Fixed(vec![]), second, second).unwrap_err();
        assert_eq!(none.kind(), io::ErrorKind::NotFound);
        let here = Fixed(vec!["127.0.0.1:1".parse().unwrap()]);
        assert!(connect(&addr, &here, second, second).is_ok());
        let late = connect(&addr, &here, second, Duration::ZERO).unwrap_err();
        assert_eq!(late.kind(), io::ErrorKind::TimedOut);
        // An address that refuses is passed over for the next; an address
        // that is an ip is dialled without the resolver.
        let open = listener.local_addr().unwrap();
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let both = Exact(vec![closed, open]);
        assert!(connect(&addr, &both, second, second).is_ok());
        let refused = connect(&addr, &Exact(vec![closed]), second, second).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
        assert!(connect(&PeerAddr::Ip(open), &Exact(vec![]), second, second).is_ok());
    }

    struct Exact(Vec<SocketAddr>);

    impl Resolve for Exact {
        fn resolve(&self, _: &str, _: u16) -> io::Result<Vec<SocketAddr>> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn a_dialable_address_is_a_name_or_an_ip_a_node_can_dial() {
        assert!(PeerAddr::dialable("0.0.0.0:1").is_none());
        assert!(PeerAddr::dialable("10.0.0.1:0").is_none());
        assert!(PeerAddr::dialable("x").is_none());
        assert!(PeerAddr::dialable("10.0.0.1:1").is_some());
        assert!(PeerAddr::dialable("seed.example:1").is_some());
    }
}
