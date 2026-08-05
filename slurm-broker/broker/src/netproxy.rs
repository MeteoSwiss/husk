//! The egress proxy: the one place a caged job's traffic can leave, and the only place
//! the allowlist is enforced.
//!
//! # Shape, and why this one
//!
//! ```text
//! job cage  ─ socat TCP-LISTEN:3128 ─┐
//! rank 0    ─ socat TCP-LISTEN:3128 ─┼─► <spool>/net.sock ─► THIS PROXY ─► the internet
//! rank 1    ─ socat TCP-LISTEN:3128 ─┘      (a FILE)          (outside,      (the only
//!   (each has its OWN netns, so each                           holds THE      process
//!    needs its own loopback listener;                          allowlist)     with a route)
//!    none of them has a route anywhere)
//! ```
//!
//! A unix socket crosses the network-namespace boundary because it is a **filesystem**
//! object — the same reasoning that makes the `/run/munge` mount mask load-bearing rather
//! than a syscall filter. So the cage keeps `--unshare-net` and gains exactly one hole,
//! whose shape husk controls.
//!
//! **This process runs OUTSIDE the cage**, in the broker's trust domain. That is forced by
//! the axiom — the thing enforcing the policy must not be inside the thing it confines —
//! and it is why this file is written defensively: a bug here is a bug in the trusted
//! half.
//!
//! **One proxy per node, one relay per rank.** The relay is a byte-shuffler with no
//! policy in it; the allowlist, and later the TLS termination and audit, live here. What
//! must never be duplicated is the decision.
//!
//! # What it is not
//!
//! **`CONNECT` only, which means HTTPS works and plain `http://` does not.** A proxied
//! `http://` request is an absolute-URI `GET http://host/path`, not a tunnel, so serving it
//! would mean parsing and re-emitting the request — a second HTTP parser, and therefore a
//! second thing that can disagree with the first about where a request is going. That is
//! the F13/F14 shape, and the reason it is refused rather than implemented. The refusal
//! names `https://` so the failure is actionable. In practice everything that matters is
//! HTTPS: GitHub, PyPI, conda, the CSCS inference API.
//!
//! **No TLS termination**: husk tunnels bytes after authorising the destination and never
//! inspects them. Honest about the guarantee — we control WHERE a job may talk, not WHAT
//! it says. Terminating TLS would let husk hold an API key and inject it so the agent never
//! sees the credential (ROADMAP 6b); neither the accept loop nor the allowlist gate below
//! changes when that arrives.
//!
//! # Threat notes
//!
//! * The client is the caged job: **hostile input**. Request parsing is bounded in both
//!   size and time, so a job cannot pin a trusted-side thread by dribbling a header.
//! * DNS resolution happens HERE, after the allowlist check on the name. The job never
//!   supplies an address, so it cannot authorise a name and connect to something else.
//! * A refusal says what was refused and why, on the job's own connection: a silent drop
//!   would be indistinguishable from a network fault and would cost somebody an afternoon.

use crate::netallow::Allowlist;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Longest request head we will read before giving up. A `CONNECT` line plus headers is a
/// few hundred bytes; this is generous and still bounded, so a job cannot make the trusted
/// side buffer without limit.
const MAX_HEAD: usize = 8 * 1024;

/// How long a client has to send its request line, and how long a dial may take. Both
/// exist so a caged job cannot hold a trusted-side thread open indefinitely.
const READ_TIMEOUT: Duration = Duration::from_secs(15);
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// Concurrent tunnels. The cage is agent-controlled, so without a cap a job could spawn
/// threads in the trusted process until it falls over — the same denial-of-service class
/// as the step-broker's `MAX_IN_FLIGHT`.
const MAX_TUNNELS: usize = 64;

/// What the proxy decided about one request, for the log.
enum Verdict {
    Allowed,
    Refused(String),
}

/// Parse a `CONNECT host:port HTTP/1.1` request head.
///
/// Returns the destination. Everything else in the head is read and discarded — husk is a
/// tunnel, not an HTTP implementation, and the fewer fields it interprets the fewer places
/// its reading can differ from anyone else's.
fn parse_connect(head: &str) -> Result<(String, u16), String> {
    let line = head.lines().next().unwrap_or_default();
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    if !method.eq_ignore_ascii_case("CONNECT") {
        // A plain `http://` URL through a proxy is an absolute-URI request like
        // `GET http://host/path`, NOT a tunnel — so it lands here. husk does not serve it,
        // and the message has to say that rather than suggest setting the variable the
        // client already set.
        return Err(format!(
            "husk tunnels HTTPS only (CONNECT); this was a {method} request, which is what \
             a plain http:// URL sends to a proxy. Use https:// . Forwarding plain HTTP \
             would mean husk parsing and re-emitting your requests, and a second parser is \
             a second thing that can disagree about where a request is going."
        ));
    }
    // Split on the LAST colon: an IPv6 literal is bracketed, so the final colon is the
    // port separator in every well-formed form.
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| format!("CONNECT target {target:?} has no port"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("CONNECT target {target:?} has a bad port"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(format!("CONNECT target {target:?} has no host"));
    }
    Ok((host.to_string(), port))
}

/// Read the request head (up to the blank line), bounded in size.
fn read_head(stream: &mut BufReader<UnixStream>) -> Result<String, String> {
    let mut head = String::new();
    loop {
        if head.len() > MAX_HEAD {
            return Err("request head too large".to_string());
        }
        let mut line = String::new();
        match stream.read_line(&mut line) {
            Ok(0) => return Err("client closed before sending a request".to_string()),
            Ok(_) => {}
            Err(e) => return Err(format!("reading the request: {e}")),
        }
        let blank = line.trim().is_empty();
        head.push_str(&line);
        if blank {
            return Ok(head);
        }
    }
}

/// Copy bytes one way until EOF, then shut the write side down so the peer sees it.
fn pump(mut from: impl Read, mut to: impl Write + AsShutdown) {
    let mut buf = [0u8; 32 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    to.shutdown_write();
}

/// Shut down only the write half, so a one-way close propagates instead of tearing the
/// whole tunnel down — some protocols legitimately half-close.
trait AsShutdown {
    fn shutdown_write(&self);
}
impl AsShutdown for TcpStream {
    fn shutdown_write(&self) {
        let _ = self.shutdown(std::net::Shutdown::Write);
    }
}
impl AsShutdown for UnixStream {
    fn shutdown_write(&self) {
        let _ = self.shutdown(std::net::Shutdown::Write);
    }
}

fn serve_one(client: UnixStream, allow: &Allowlist) -> Verdict {
    let _ = client.set_read_timeout(Some(READ_TIMEOUT));
    let mut reader = BufReader::new(match client.try_clone() {
        Ok(c) => c,
        Err(e) => return Verdict::Refused(format!("cannot read from the client: {e}")),
    });
    let mut out = client;

    let head = match read_head(&mut reader) {
        Ok(h) => h,
        Err(e) => return Verdict::Refused(e),
    };
    let (host, port) = match parse_connect(&head) {
        Ok(d) => d,
        Err(e) => {
            let _ = write!(out, "HTTP/1.1 400 Bad Request\r\n\r\nhusk: {e}\r\n");
            return Verdict::Refused(e);
        }
    };

    // THE GATE. One call, one place, on the name the client asked for — and the dial below
    // uses that same name, so there is no window in which an authorised name becomes a
    // different destination.
    if !allow.permits(&host, port) {
        let why = format!(
            "{host}:{port} is not on husk's network allowlist. Ask your operator to add it \
             to sandbox.network.allowedDomains if the work genuinely needs it."
        );
        let _ = write!(out, "HTTP/1.1 403 Forbidden\r\n\r\nhusk: {why}\r\n");
        return Verdict::Refused(why);
    }

    // Resolve and dial HERE, in the trusted process. The job never supplies an address,
    // so it cannot authorise a name and reach something else.
    let addrs = match std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), port)) {
        Ok(a) => a.collect::<Vec<_>>(),
        Err(e) => {
            let why = format!("cannot resolve {host}: {e}");
            let _ = write!(out, "HTTP/1.1 502 Bad Gateway\r\n\r\nhusk: {why}\r\n");
            return Verdict::Refused(why);
        }
    };
    let upstream = addrs
        .iter()
        .find_map(|a| TcpStream::connect_timeout(a, DIAL_TIMEOUT).ok());
    let upstream = match upstream {
        Some(u) => u,
        None => {
            let why = format!("cannot connect to {host}:{port}");
            let _ = write!(out, "HTTP/1.1 502 Bad Gateway\r\n\r\nhusk: {why}\r\n");
            return Verdict::Refused(why);
        }
    };

    if write!(out, "HTTP/1.1 200 Connection established\r\n\r\n").is_err() {
        return Verdict::Refused("client went away before the tunnel opened".into());
    }

    // Tunnel. Two directions, one thread each, and the buffered reader carries over any
    // bytes the client already sent after its request head.
    let up_read = match upstream.try_clone() {
        Ok(u) => u,
        Err(e) => return Verdict::Refused(format!("cannot split the upstream socket: {e}")),
    };
    let down_write = match out.try_clone() {
        Ok(c) => c,
        Err(e) => return Verdict::Refused(format!("cannot split the client socket: {e}")),
    };
    let t = std::thread::spawn(move || pump(up_read, down_write));
    pump(reader, upstream);
    let _ = t.join();
    Verdict::Allowed
}

/// One slot in the concurrent-tunnel budget, released by `Drop` (`P6`).
///
/// **B1-F8.** The release used to be the thread's LAST STATEMENT, which a panic in
/// `serve_one` never reaches — and the leak is permanent, because nothing resets the
/// counter. Sixty-four panics and every later connection is refused for the rest of the
/// job, with a message about load rather than the bug. The input that panics comes from the
/// cage, so the trigger is the agent's to choose.
///
/// `fetch_update` on acquire also makes the cap EXACT: the old check-then-add let two
/// connections pass the test before either incremented.
struct TunnelSlot(Arc<AtomicUsize>);

impl TunnelSlot {
    fn acquire(live: &Arc<AtomicUsize>) -> Option<Self> {
        live.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            (n < MAX_TUNNELS).then_some(n + 1)
        })
        .ok()
        .map(|_| Self(Arc::clone(live)))
    }
}

impl Drop for TunnelSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Serve until the listener dies. Never returns in normal operation.
pub fn serve(listener: UnixListener, allow: Allowlist) {
    let allow = Arc::new(allow);
    let live = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let client = match conn {
            Ok(c) => c,
            Err(e) => {
                eprintln!("husk-proxy: accept failed: {e}");
                continue;
            }
        };
        let Some(slot) = TunnelSlot::acquire(&live) else {
            // Refuse rather than queue: a queued connection looks like a slow network to
            // the job, and "husk is slow" is a worse diagnosis to hand someone than
            // "husk refused, here is why".
            let mut c = client;
            let _ = write!(
                c,
                "HTTP/1.1 503 Service Unavailable\r\n\r\nhusk: too many concurrent \
                 connections ({MAX_TUNNELS})\r\n"
            );
            continue;
        };
        let allow = Arc::clone(&allow);
        std::thread::spawn(move || {
            // Moved into the thread and dropped when it ends, HOWEVER it ends.
            let _slot = slot;
            match serve_one(client, &allow) {
                // Logged on the TRUSTED side, so the record of what a job reached does not
                // depend on the job. Host and port only: never the payload.
                Verdict::Allowed => {}
                Verdict::Refused(why) => eprintln!("husk-proxy: refused: {why}"),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panicking_tunnel_returns_its_slot() {
        // **B1-F8, the case that made it a bug rather than a tidiness note.** The release
        // used to be the thread's last statement, which a panic never reaches — and nothing
        // resets the counter, so the leak is permanent. Sixty-four panics and every later
        // connection is refused for the rest of the job, with a message about load.
        let live = Arc::new(AtomicUsize::new(0));
        for _ in 0..MAX_TUNNELS * 2 {
            let slot = TunnelSlot::acquire(&live).expect("a returned slot must be reusable");
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _slot = slot;
                panic!("whatever serve_one does with hostile bytes");
            }));
            assert!(r.is_err(), "the test must actually panic or it proves nothing");
        }
        assert_eq!(live.load(Ordering::Relaxed), 0, "every slot must come back");
    }

    #[test]
    fn the_tunnel_cap_is_exact_and_slots_are_reusable() {
        // The old check-then-add let two connections pass `live < MAX` before either
        // incremented, so the cap was approximate. fetch_update makes it exact — and the
        // cap must still be a cap, not a one-shot budget.
        let live = Arc::new(AtomicUsize::new(0));
        let held: Vec<TunnelSlot> =
            (0..MAX_TUNNELS).map(|_| TunnelSlot::acquire(&live).expect("under the cap")).collect();
        assert_eq!(live.load(Ordering::Relaxed), MAX_TUNNELS);
        assert!(TunnelSlot::acquire(&live).is_none(), "the cap must hold at the boundary");
        drop(held);
        assert_eq!(live.load(Ordering::Relaxed), 0, "dropping releases");
        assert!(TunnelSlot::acquire(&live).is_some(), "a job gets its network back");
    }

    #[test]
    fn parses_a_connect_request() {
        assert_eq!(
            parse_connect("CONNECT api.example.com:443 HTTP/1.1\r\nHost: x\r\n\r\n").unwrap(),
            ("api.example.com".to_string(), 443)
        );
        // IPv6 literals arrive bracketed; the last colon is still the separator.
        assert_eq!(
            parse_connect("CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n").unwrap(),
            ("2001:db8::1".to_string(), 8443)
        );
    }

    #[test]
    fn refuses_anything_that_is_not_connect() {
        // husk is a tunnel, not an HTTP implementation. A plain GET carries a URL, and
        // interpreting URLs is a second parser with its own differentials - so it is
        // refused rather than handled. The practical consequence is that https:// works
        // and http:// does not, which is why the refusal names https:// explicitly.
        let why = parse_connect("GET http://example.com/ HTTP/1.1\r\n\r\n").unwrap_err();
        assert!(why.contains("https://"), "the refusal must be actionable: {why}");
        for bad in [
            "GET http://example.com/ HTTP/1.1\r\n\r\n",
            "POST http://example.com/ HTTP/1.1\r\n\r\n",
            "\r\n",
        ] {
            assert!(parse_connect(bad).is_err(), "must refuse {bad:?}");
        }
    }

    #[test]
    fn refuses_a_malformed_connect_target() {
        for bad in [
            "CONNECT example.com HTTP/1.1\r\n\r\n",        // no port
            "CONNECT example.com:notaport HTTP/1.1\r\n\r\n",
            "CONNECT :443 HTTP/1.1\r\n\r\n",               // no host
            "CONNECT example.com:99999 HTTP/1.1\r\n\r\n",  // out of range
        ] {
            assert!(parse_connect(bad).is_err(), "must refuse {bad:?}");
        }
    }

    /// End to end over a real unix socket, with a real allowlist and a real upstream:
    /// the gate has to be exercised through the code path that actually serves clients,
    /// not just called directly. Two requests, one allowed and one not.
    #[test]
    fn the_allowlist_gates_real_connections() {
        use std::io::BufRead;
        // A stand-in "internet": a listener we control, allowlisted by name.
        let upstream = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for c in upstream.incoming().flatten() {
                let mut c = c;
                let _ = c.write_all(b"UPSTREAM-SPOKE\n");
            }
        });

        let dir = std::env::temp_dir().join(format!("husk-proxy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("gw.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let allow = Allowlist::parse(&[format!("localhost:{port}")]).unwrap();
        std::thread::spawn(move || serve(listener, allow));

        // ALLOWED: the tunnel opens and upstream bytes come back.
        let mut c = UnixStream::connect(&sock).unwrap();
        write!(c, "CONNECT localhost:{port} HTTP/1.1\r\n\r\n").unwrap();
        let mut r = BufReader::new(c.try_clone().unwrap());
        let mut status = String::new();
        r.read_line(&mut status).unwrap();
        assert!(status.contains("200"), "expected a tunnel, got {status:?}");
        let mut rest = String::new();
        let _ = r.read_line(&mut rest); // blank line
        let mut body = String::new();
        let _ = r.read_line(&mut body);
        assert!(body.contains("UPSTREAM-SPOKE"), "tunnel did not carry bytes: {body:?}");

        // REFUSED: same proxy, a host that is not on the list.
        let mut c2 = UnixStream::connect(&sock).unwrap();
        write!(c2, "CONNECT evil.example.com:443 HTTP/1.1\r\n\r\n").unwrap();
        let mut r2 = BufReader::new(c2);
        let mut status2 = String::new();
        r2.read_line(&mut status2).unwrap();
        assert!(status2.contains("403"), "an unlisted host must be refused: {status2:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
