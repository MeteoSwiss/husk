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
//! * The client is the caged job: **hostile input**. The request head is bounded in size
//!   (`MAX_HEAD`) and in TOTAL wall-clock time (`HEAD_TIMEOUT`), both by construction: at
//!   most `MAX_HEAD + 1` bytes are ever pulled off the socket, and the deadline is a budget
//!   for the whole head rather than for each read. So a job can neither make the trusted
//!   side buffer without limit nor pin a thread by dribbling a header. This sentence used
//!   to be true of the intent only (`B5-6`, `P12`), which is why it now names the mechanism
//!   that carries it.
//! * **The TUNNEL is deliberately not bounded in time, and that is a decision, not an
//!   omission.** The request-phase deadline used to survive into the body phase and cut any
//!   HTTPS response that took more than 15 s to start (`B5-5`). What bounds a tunnel now is
//!   written out at the point the deadline is cleared, in `read_head`.
//! * DNS resolution happens HERE, after the allowlist check on the name. The job never
//!   supplies an address, so it cannot authorise a name and connect to something else.
//! * A refusal says what was refused and why, on the job's own connection: a silent drop
//!   would be indistinguishable from a network fault and would cost somebody an afternoon.

use crate::netallow::Allowlist;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Longest request head we will read before giving up. A `CONNECT` line plus headers is a
/// few hundred bytes; this is generous and still bounded, so a job cannot make the trusted
/// side buffer without limit.
///
/// **This bounds the request HEAD and nothing else.** The tunnel body is not capped at all,
/// so a 2 GiB wheel, a model download and a streaming API response are untouched by it — a
/// distinction the refusal message has to make, because "husk caps my downloads" is exactly
/// the wrong theory a bare 431 invites (`P13`).
const MAX_HEAD: usize = 8 * 1024;

/// How long the client has to deliver its **whole** request head.
///
/// A wall-clock budget for the head phase, re-armed shorter before every read, not a
/// per-read timeout: `MAX_HEAD` one-byte reads that are each just inside a per-read limit
/// is 34 hours on one trusted-side thread, which is the dribbling attack the module header
/// claims is impossible (`B5-6`).
///
/// It is cleared the instant the head is read. **It never governs the tunnel** — see
/// `read_head` and `tunnel`.
const HEAD_TIMEOUT: Duration = Duration::from_secs(15);

/// How long a dial may take, so a caged job cannot hold a trusted-side thread open by
/// naming an allowlisted host that blackholes.
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// Concurrent tunnels, sized from the descriptor budget this process actually has.
///
/// The cage is agent-controlled, so without a cap a job could spawn threads in the trusted
/// process until it falls over — the same denial-of-service class as the step-broker's
/// `MAX_IN_FLIGHT`. What follows is about the SIZE of that cap, which was wrong twice over.
///
/// **`RDF F-4`, both halves.** This was `const MAX_TUNNELS: usize = 64`. Sixty-four was
/// chosen when husk severed any tunnel idle for 15 s, so keep-alive pools never survived and
/// the cap was hard to reach. `2cc3d21` removed that timeout — correctly, because every clock
/// that could go on the body phase is either shorter than a legitimate idle connection or is
/// not a bound — and in doing so made 64 genuinely reachable. Two things were then wrong with
/// it, and neither of them is the number:
///
/// * **The cap is per JOB and every rank shares it.** `rank.rs` gives each rank its own
///   in-cage `socat` onto the ONE proxy socket, so a 64-rank single-node step in which each
///   rank opens one HTTPS connection is at the cap before connection pooling is even
///   involved — and multi-rank steps are the entire reason the step broker exists. A cap a
///   real MPI job hits is a defect, not a virtue.
/// * **Nobody who hit it could change it.** The 503 said "ask your operator to raise the
///   cap"; `MAX_TUNNELS` was a `const` with no override anywhere in the tree, so the
///   operator's only route was rebuilding and reinstalling husk. That is `P11` in its
///   sharpest form: a refusal naming an action that does not exist.
///
/// **What replaces it: the cap is a division, not a number.** A tunnel's cost is descriptors,
/// so the budget is read from the descriptors this process has — `Max open files` in
/// `/proc/self/limits`, minus a reserve, divided by `FDS_PER_TUNNEL`, clamped to
/// `TUNNEL_CEILING`. That answers both halves at once:
///
/// * At the common 1024 soft limit the cap is `(1024 - 64) / 5 = 192`, so a **128-rank step
///   with one connection per rank fits**, which 64 did not.
/// * At a site soft limit of 256 the cap is 38, and that is the point rather than a
///   regression: 64 tunnels need 320 descriptors, so the old constant promised a job more
///   egress than the process could hold and paid for the difference in `EMFILE` — which is
///   `RDF F-5`'s accept-loop spin, reachable exactly when the cap outruns the budget. A cap
///   derived from the budget cannot outrun it.
/// * The remedy in the 503 is now one that exists and that husk honours: raise the descriptor
///   limit (`ulimit -n`, propagated into the job by Slurm on most sites) and the next proxy
///   sizes itself larger. No rebuild, no release.
///
/// **It is deliberately not derived from the rank count**, which was the other candidate.
/// `SLURM_NTASKS` is not set at all unless `--ntasks` was requested (`policy.rs` measured
/// exactly that), and husk's own validated task count lives at SUBMIT time in `policy.rs`,
/// which this process is not; the only route to it here is the environment. An
/// environment-derived cap is a number the confined side would like to influence, and the
/// thing being sized IS the denial-of-service budget of the trusted process (`P2` — the
/// confined side supplies neither its own boundary nor its own record). Descriptors are what
/// a tunnel actually spends, this process can see them without asking anybody, and they track
/// the rank count for free: a node configured to run 128 ranks is a node whose limits were
/// raised to run 128 ranks.
///
/// File descriptors ONE OPEN TUNNEL holds. Counted off `tunnel` below, not estimated: `out`
/// (the accepted client), `client_read` (its clone, which the head reader owns), `down_write`
/// (its second clone), `upstream`, and `up_read` (its clone).
const FDS_PER_TUNNEL: usize = 5;

/// Descriptors that are not tunnels: the listener, stdio, the log, whatever the resolver
/// opens for a lookup, and headroom for the accepted connection that is about to be REFUSED —
/// a refusal needs a descriptor too, and a cap that leaves none is a cap that cannot say why.
const FD_RESERVE: usize = 64;

/// Threads ONE OPEN TUNNEL holds. Counted off the code, not estimated, and re-counted by
/// `the_thread_cost_of_a_tunnel_is_counted_not_recalled` on every run: `serve` spawns one per
/// accepted connection and `tunnel` spawns a second for the reverse pump.
///
/// **`N1-6`.** The comment below said "each tunnel is one spawned thread" and derived the
/// ceiling's cost from that. There are two, so the figure it reasoned from was out by 2x. The
/// ceiling itself is unchanged and still defensible — this is the number, corrected, and given
/// a test so the next reader is not counting by hand either (`P12`).
const THREADS_PER_TUNNEL: usize = 2;

/// An upper bound that is about THREADS, because descriptors stop being the binding
/// constraint on a generous site. A tunnel costs `THREADS_PER_TUNNEL` threads, so 1024 of them
/// is 2048 threads and ~16 GiB of untouched virtual stack plus a few tens of MiB resident,
/// which a compute node carries, whereas the ~200,000 that this laptop's 1,048,576-descriptor
/// limit would otherwise buy is not a proxy, it is a fork bomb with a budget.
///
/// **It is also a cap that `ulimit -n` cannot move**, which is why `too_many_tunnels` branches
/// on which of the two bounds is binding rather than on whether husk could read a limit
/// (`N1-1`).
const TUNNEL_CEILING: usize = 1024;

/// The cap when the descriptor budget cannot be read at all. Deliberately the OLD constant:
/// if `/proc` is unreadable husk has learned nothing, so it does exactly what it did before
/// rather than guessing upward. `/proc` is already a hard dependency of this binary, so this
/// arm is close to unreachable; it exists because "close to" is not "is".
const TUNNEL_CAP_WHEN_UNKNOWN: usize = 64;

/// This process's soft `RLIMIT_NOFILE`, or `None` if it cannot be read.
///
/// **`/proc`, not `getrlimit(2)`, and that is the same lesson as this fix's other half.**
/// `RLIMIT_NOFILE` is 7 on x86_64 and aarch64 but 5 on alpha, mips and sparc — of which mips
/// and sparc are real `rustc` targets, so the argument does not rest on alpha, which is not
/// one (`RHGN`) — and `struct rlimit`'s layout is a second per-architecture question stacked
/// on the first. Item 2 of this
/// same fix exists because one hard-coded asm-generic constant was silently wrong on Santis
/// (`spool::O_NOFOLLOW`); adding another one, in the same commit, to size a denial-of-service
/// cap would be the identical mistake with a worse blast radius — read too small a limit and
/// the job has no egress, too large and it has `EMFILE`. `/proc/self/limits` is text, it is
/// architecture-independent, and this binary already depends on `/proc` (`main.rs` reads
/// `/proc/self/exe`, and the spool reaper resolves `/proc/self/fd/<n>`).
fn fd_soft_limit() -> Option<usize> {
    parse_max_open_files(&std::fs::read_to_string("/proc/self/limits").ok()?)
}

/// The parser, split out so a test can execute it against BOTH a pinned sample and this
/// machine's real `/proc` text — a parser checked only against its own fixture is a test of
/// the fixture (`P9`).
fn parse_max_open_files(limits: &str) -> Option<usize> {
    let row = limits.lines().find(|l| l.starts_with("Max open files"))?;
    let soft = row["Max open files".len()..].split_whitespace().next()?;
    if soft == "unlimited" {
        return Some(usize::MAX);
    }
    soft.parse().ok()
}

/// The cap, as a pure function of the descriptor budget, so the whole sizing decision can be
/// executed in a test at limits this machine does not have.
///
/// Never zero: at least one tunnel is always permitted, because a cap of nought is husk
/// switching a job's egress off over arithmetic, behind a 503 that reads like a bug in husk.
fn cap_for(fd_limit: Option<usize>) -> usize {
    match fd_limit {
        Some(n) => (n.saturating_sub(FD_RESERVE) / FDS_PER_TUNNEL).clamp(1, TUNNEL_CEILING),
        None => TUNNEL_CAP_WHEN_UNKNOWN,
    }
}

/// Would a bigger descriptor limit produce a bigger cap? **The 503's remedy branches on this
/// and on nothing else** (`N1-1`).
///
/// The question a reader of that message is actually asking is "can I do anything about this",
/// and the answer is not "did husk read /proc" — it is "which of `cap_for`'s two bounds is
/// binding". `cap_for` is monotonic and its maximum is `TUNNEL_CEILING`, so a cap at the
/// ceiling is one no descriptor limit can raise, and a cap below it is one every extra
/// `FDS_PER_TUNNEL` descriptors moves.
///
/// **Stated in terms of `cap_for` rather than by repeating its arithmetic**, so there is one
/// division in this file and not two that agree (`P8`) — the same reason `main.rs` now derives
/// its open flags from `spool`'s.
fn a_bigger_limit_would_raise_the_cap(fd_limit: Option<usize>) -> bool {
    fd_limit.is_some() && cap_for(fd_limit) < TUNNEL_CEILING
}

/// How the descriptor budget is written into a message for a human.
fn fd_limit_text(fd_limit: Option<usize>) -> String {
    match fd_limit {
        None => "unknown".to_string(),
        Some(n) if n == usize::MAX => "unlimited".to_string(),
        Some(n) => n.to_string(),
    }
}

/// Errnos that mean `accept` failed for want of a DESCRIPTOR rather than for want of a
/// client. `EMFILE` (24) and `ENFILE` (23) are the asm-generic pair and are identical on
/// x86_64 and aarch64, the two architectures husk ships to; `ENOMEM` (12) and `ENOBUFS` (105)
/// are the kernel's out-of-memory arms for the same call.
///
/// A number this list does NOT contain gets exactly the old behaviour — one log line, retry
/// at once — so a short list costs a missed backoff and never a wrong sleep. That is the same
/// safe direction `main.rs` chose for an architecture missing from its `O_NOFOLLOW` list: an
/// omission degrades to today, it does not invent a new failure.
const ACCEPT_EXHAUSTED: &[i32] = &[12, 23, 24, 105];

/// First and last backoff after an `accept` that failed for want of a descriptor.
const ACCEPT_BACKOFF_START: Duration = Duration::from_millis(50);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// What the accept loop does about one failed `accept`.
struct AcceptRetry {
    sleep: Duration,
    log: bool,
}

/// **`RDF F-5`.** Under `EMFILE` the pending connection stays in the backlog, so the next
/// `accept` fails identically and at once: the bare `continue` this replaces was an unbounded
/// busy loop writing one line per iteration into `$_husk_log`, which lives in the operator's
/// `$HOME`. `RDF` said that was not reachable at a cap of 64 and 1024 descriptors, and said
/// the backoff should land BEFORE the cap is raised, not after. The cap is raised in this same
/// change, so the backoff lands here.
///
/// Pure, and a function of the errno as well as the count, because the two arms are different
/// failures. A descriptor shortage clears when a tunnel closes, so sleeping is progress; an
/// `ECONNABORTED` has already consumed its backlog entry, so sleeping on it would let the
/// caged job buy 50 ms of the trusted side's attention per aborted connection — a new denial
/// of service, installed while closing one. Hence: back off ONLY on exhaustion.
///
/// The log is thinned to powers of two, so a burst of a thousand costs eleven lines instead of
/// a thousand, and the first one is always written — an operator must learn about the first
/// failure immediately, not on a round number.
///
/// **`N1-5`: the thinning applies to BOTH arms, and it did not.** The harm this function exists
/// for is "an unbounded busy loop writing one line per iteration into `$_husk_log`, which lives
/// in the operator's `$HOME`" — and that harm is about the LOG, not about the sleep. The first
/// version backed off on exhaustion and thinned the log on the same branch, leaving the arm that
/// does not sleep as the only unbounded writer in the function: a permanently failing `accept`
/// with a non-listed errno spins at CPU speed and narrates every iteration. Thinning it costs
/// nothing that matters — the first failure is still reported immediately (1 is a power of two),
/// and an errno that repeats 1000 times is not 1000 pieces of information.
///
/// The SLEEP still branches, and that split is the load-bearing one: sleeping on `ECONNABORTED`
/// would sell the caged job 50 ms of the trusted side's attention per aborted connection.
fn accept_retry(errno: Option<i32>, consecutive: u32) -> AcceptRetry {
    let log = consecutive.is_power_of_two();
    if !errno.is_some_and(|e| ACCEPT_EXHAUSTED.contains(&e)) {
        return AcceptRetry { sleep: Duration::ZERO, log };
    }
    let doublings = consecutive.saturating_sub(1).min(5);
    let sleep = (ACCEPT_BACKOFF_START * (1u32 << doublings)).min(ACCEPT_BACKOFF_MAX);
    AcceptRetry { sleep, log }
}

/// What the proxy decided about one request, for the log.
///
/// `Allowed` carries its destination because the log is the only trusted-side account of
/// what a job reached. It used to be a bare variant logged as nothing at all (W0), which
/// left husk recording what it STOPPED and never what it PERMITTED — the P2 record half
/// missing, directly under a comment claiming it was there.
enum Verdict {
    Allowed(String),
    Refused(String),
}

/// A refusal, and the answer the job gets on its own connection.
///
/// **`B5-6`.** Three of the five refusal paths used to `return Verdict::Refused(..)` and
/// write nothing, under a module header promising the opposite — so the case a *caged*
/// client is most likely to hit (an over-long head) arrived as a bare connection close,
/// indistinguishable from a network fault. Round 2's `F12` measured the same silence from
/// the other side (`0 bytes: b''`) and added the operator half: the 15 s expiry reached the
/// log as a bare `Resource temporarily unavailable (os error 11)`.
///
/// So a refusal is now a VALUE with both audiences in it, and there is exactly one place
/// that writes one (`answer`). `speak` is `None` only where husk genuinely has no channel
/// left — after `200 Connection established`, when every further byte is a TLS record to
/// the client — and that arm is named rather than implied (`P11`'s split audience).
struct Refusal {
    /// The operator's line. Names the cause, not the errno alone.
    why: String,
    /// Status and reason phrase for the client, or `None` if the channel is no longer ours.
    speak: Option<(u16, String)>,
}

impl Refusal {
    fn speaking(status: u16, phrase: impl Into<String>, why: impl Into<String>) -> Self {
        Self { why: why.into(), speak: Some((status, phrase.into())) }
    }

    /// A refusal husk cannot deliver, because the connection is already a tunnel or already
    /// gone. The operator still gets the line; the client gets a close, which is honest
    /// here and dishonest anywhere else.
    fn unspeakable(why: impl Into<String>) -> Self {
        Self { why: why.into(), speak: None }
    }

    fn answer(self, out: &mut impl Write) -> Verdict {
        let Refusal { why, speak } = self;
        if let Some((status, phrase)) = speak {
            // The reason phrase is a HEADER LINE and adversary bytes reach it (the 403
            // names the host the job asked for), so it is sanitised HERE, once, instead of
            // at each call site — a later call site that forgot would be response
            // splitting. Call sites that embed adversary input bound its share of the line
            // too, so this cap never eats the informative tail.
            let phrase = header_safe(&phrase, 200);
            let _ = write!(out, "HTTP/1.1 {status} {phrase}\r\n\r\nhusk: {why}\r\n");
        }
        Verdict::Refused(why)
    }
}

/// Everything that could split a response or run away with a status line, removed: only
/// printable ASCII and the space survive, and the result is bounded.
fn header_safe(s: &str, max: usize) -> String {
    s.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(max).collect()
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

/// The two refusals the head phase can produce on its own, built in one place so the
/// message an operator reads and the message the job reads cannot drift apart.
///
/// Both carry the SAME consequence sentence: the cap and the deadline are on the request
/// HEAD, never on the tunnel. Without it the natural reading of a 431 or a 408 from husk is
/// "husk caps my downloads" or "husk cuts my connections at 15 s" — a confident wrong theory
/// about the one layer the agent can see (`P13`), and in the 408's case the exact theory
/// `B5-5` was.
fn head_too_large() -> Refusal {
    Refusal::speaking(
        431,
        format!("husk: CONNECT request head over {MAX_HEAD} bytes"),
        format!(
            "the CONNECT request head did not finish inside the {MAX_HEAD} bytes husk reads. \
             That cap is on the REQUEST HEAD only: once a tunnel is open husk does not limit \
             how much you send or receive, so downloads of any size are unaffected. If this \
             is a real CONNECT, shorten the headers; if it is something else, husk tunnels \
             https:// only."
        ),
    )
}

fn head_timed_out(budget: Duration, got: usize) -> Refusal {
    // `{budget:?}` and not `as_secs()`: a sub-second budget truncates to "0s", and "husk
    // waited 0s" is a message that reads as a bug in husk. `Duration`'s own formatting says
    // `15s` here and `200ms` under a test, both true.
    Refusal::speaking(
        408,
        format!("husk: CONNECT request head not complete after {budget:?}"),
        format!(
            "no complete CONNECT request head arrived within {budget:?}: husk has {got} bytes \
             and not the blank line that ends one. This deadline is on the REQUEST HEAD only \
             and is cleared the moment the head arrives — an open tunnel is never timed out \
             by husk, however long the far end takes to answer."
        ),
    )
}

/// The refusal when a job is at its concurrency cap.
///
/// Built here rather than inline in `serve`, for the reason `head_too_large` and
/// `head_timed_out` are: one place, so the sentence in the operator's log and the sentence on
/// the job's connection cannot drift, and so a test can render it without an accept loop.
///
/// Three things it has to say that the old one did not (`RDF F-4`, `RDF F-6c`):
///
/// * a remedy that **exists** — the descriptor limit husk sized the cap from, rather than a
///   `const` nobody short of a rebuild can reach (`P11`);
/// * that **every rank shares one proxy**, because on a multi-rank step that is the entire
///   explanation and it is invisible from inside the cage (`P13`);
/// * that the counter counts an ACCEPTED CONNECTION and not an open tunnel — a connection
///   still sending its `CONNECT` head is in it — so "this job already holds N tunnels open"
///   was not always true.
fn too_many_tunnels(cap: usize, fd_limit: Option<usize>) -> Refusal {
    // The remedy BRANCHES ON WHETHER RAISING THE LIMIT WOULD MOVE THE CAP, which is the
    // question the reader is asking. Telling someone to raise a limit that would not move it
    // is a second `P11` defect wearing the first one's clothes: the action exists, and it
    // changes nothing.
    //
    // **`N1-1`.** This used to branch on `Some(n) if n != usize::MAX`, so BOTH cases where the
    // cap is the thread ceiling fell into the else arm — the fallback arm — and the job was
    // told husk "could not read this proxy's own open-file limit from /proc/self/limits" and
    // that this "is worth reporting", on a run whose own startup banner printed the limit two
    // functions away. Every clause was false, and husk contradicted itself about one fact in
    // one job's stderr. The second case is the one the review did not reach and this laptop
    // sits in: a FINITE limit of 1,048,576 gives a descriptor budget of 209,702 tunnels, the
    // cap is `TUNNEL_CEILING`, and the old first arm cheerfully said the cap was 1024 "because
    // this proxy's soft open-file limit is 1048576 and one tunnel holds 5 descriptors" — false
    // arithmetic — and then named `ulimit -n` as the remedy. Same defect, opposite arm.
    //
    // The ceiling arm deliberately does not name `ulimit -n` even to dismiss it: a reader
    // skimming a 503 for a command will find one, and the test below reads the message the
    // same way, by asking whether the string appears at all. A remedy mentioned is a remedy
    // offered (`P11`).
    let remedy = if a_bigger_limit_would_raise_the_cap(fd_limit) {
        format!(
            "Or raise it: the cap is {cap} because this proxy's soft open-file limit is {} \
             and one tunnel holds {FDS_PER_TUNNEL} descriptors, so `ulimit -n <bigger>` in the \
             shell husk was launched from (Slurm propagates resource limits into the job on \
             most sites) is the whole change - husk sizes itself from that limit at startup \
             and needs no rebuild.",
            fd_limit_text(fd_limit)
        )
    } else if fd_limit.is_some() {
        format!(
            "Raising the descriptor limit will not move it: this proxy's soft open-file limit \
             is {}, which is already worth more than {cap} tunnels, so the cap in force is \
             husk's own ceiling of {TUNNEL_CEILING} concurrent tunnels - \
             {THREADS_PER_TUNNEL} threads each - and not a descriptor budget. There is no \
             setting on this side that raises it, so the only thing that helps here is closing \
             what you are not using.",
            fd_limit_text(fd_limit)
        )
    } else {
        format!(
            "Raising it is not available here: {cap} is husk's fallback, because it could not \
             read this proxy's own open-file limit from /proc/self/limits and will not size \
             the cap upward on a guess. That is worth reporting - on a Linux compute node it \
             should not happen."
        )
    };
    Refusal::speaking(
        503,
        format!("husk: at this job's cap of {cap} concurrent egress connections"),
        // NO leading "husk" — `Refusal::answer` prefixes every body with `husk: `, and a body
        // that opens with the name again renders as `husk: husk ...`, which is the exact
        // stutter `2cc3d21` removed from two other messages (`RDF F-6`).
        format!(
            "this job is already carrying {cap} connections through husk's egress proxy, \
             which is the cap, so this one was refused rather than queued. The count is of \
             connections husk has ACCEPTED - one still sending its CONNECT head is in it - and \
             it is per JOB: on a multi-rank step every rank relays through this one proxy and \
             they share this budget. husk does not time out an idle tunnel, a connection is \
             yours until one end closes it, so a client that pools keep-alive connections \
             accumulates them. Close what you are not using. {remedy}"
        ),
    )
}

/// Read the request head (up to the blank line), bounded in SIZE and in TOTAL TIME.
///
/// **`B5-6`.** The old loop tested `head.len() > MAX_HEAD` at the TOP, before reading, and
/// then called `BufRead::read_line`, which is unbounded — so the cap applied per COMPLETED
/// LINE and a client that never sent `\n` was not bounded at all. Measured (`B5-6`): 256 MiB on one
/// line, +512 MiB peak RSS in the trusted process, times the concurrency cap. The module header
/// above it said the read was "bounded in both size and time", which was a description of
/// the intent (`P12`).
///
/// Both bounds are now carried by construction rather than by the loop remembering to look:
///
/// * **Size** — the loop copies at most `MAX_HEAD + 1` bytes out of the reader, so that is
///   all that is ever pulled off the socket whatever the client sends or withholds. The
///   `+ 1` is the sentinel that separates a head of exactly `MAX_HEAD` from one that had
///   not finished.
/// * **Time** — `budget` is spent by the WHOLE head, re-armed shorter before **every read
///   syscall**. That is why the loop drives `fill_buf`/`consume` itself rather than calling
///   `read_line`/`read_until`: those loop internally without returning, so a deadline
///   re-armed around them is re-armed once per LINE, and a client that never sends `\n` is
///   back to bounded-by-size-only. A per-read deadline bounds one read, not the phase —
///   `MAX_HEAD` one-byte reads arriving 14 s apart is 34 hours on a trusted-side thread,
///   and 64 of those is the job's entire egress for the price of a trickle.
///
/// **`B5-5` lives here too.** The descriptor this reads from is the one that becomes the
/// tunnel's client side, so the deadline is armed and cleared in the same function, on every
/// path out including the error arms (`P6` — the release is not left to a caller
/// remembering it). Clearing it is what stops a 15 s request deadline from severing a slow
/// HTTPS response.
///
/// **What bounds the body phase afterwards: nothing in time, by design.** Every clock we
/// could put there is either shorter than a legitimate idle connection — a pooled keep-alive
/// socket between two turns of an agent, an SSE stream waiting on an event, an inference API
/// thinking before its first token — in which case it severs working jobs, which is the
/// defect being fixed; or long enough not to be a bound. What does bound a tunnel: either
/// peer closing (both directions propagate a half-close), the concurrency cap (`cap_for`), and
/// the proxy's own lifetime, which is the job's — `die_with_parent()` plus the wall limit
/// husk forces on the submission. The party that can hold a tunnel open is the caged job,
/// and it is paying for the wall time it holds it with.
fn read_head(stream: &mut BufReader<UnixStream>, budget: Duration) -> Result<String, Refusal> {
    let started = Instant::now();
    let head = read_head_within(stream, budget, started);
    let _ = stream.get_ref().set_read_timeout(None);
    head
}

fn read_head_within(
    stream: &mut BufReader<UnixStream>,
    budget: Duration,
    started: Instant,
) -> Result<String, Refusal> {
    let mut head: Vec<u8> = Vec::with_capacity(512);
    // Where the line currently being accumulated starts, so the blank line that ends a head
    // can be recognised without a second pass over the bytes.
    let mut line_start = 0usize;
    loop {
        // Re-arm with what is LEFT. `Duration::ZERO` means "block forever" to `setsockopt`,
        // so an exhausted budget must refuse here rather than arm an unbounded read — the
        // careless version of this line is a hang, on the trusted side, chosen by the job.
        let left = budget.checked_sub(started.elapsed()).unwrap_or(Duration::ZERO);
        if left.is_zero() {
            return Err(head_timed_out(budget, head.len()));
        }
        let _ = stream.get_ref().set_read_timeout(Some(left));

        let chunk = match stream.fill_buf() {
            Ok(c) => c,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                // NAMED, not passed through. This used to fold into the generic arm below,
                // so husk's own 15 s policy reached the operator as a bare
                // `Resource temporarily unavailable (os error 11)` — round 2's `F12`.
                return Err(head_timed_out(budget, head.len()));
            }
            Err(e) => {
                return Err(Refusal::speaking(
                    400,
                    "husk: could not read the CONNECT request head",
                    format!("reading the request head from the client: {e}"),
                ))
            }
        };
        if chunk.is_empty() {
            return Err(Refusal::speaking(
                400,
                "husk: no complete CONNECT request",
                format!(
                    "the client closed the connection after {} bytes, before the blank line \
                     that ends a request head",
                    head.len()
                ),
            ));
        }

        // Never past the cap, and never past the first newline: bytes after the head belong
        // to the TUNNEL and must stay in the reader for `pump` to carry.
        let room = MAX_HEAD + 1 - head.len();
        let want = room.min(chunk.len());
        let newline = chunk[..want].iter().position(|b| *b == b'\n');
        let take = newline.map_or(want, |i| i + 1);
        head.extend_from_slice(&chunk[..take]);
        stream.consume(take);

        if head.len() > MAX_HEAD {
            return Err(head_too_large());
        }
        if newline.is_some() {
            if head[line_start..].iter().all(|b| b.is_ascii_whitespace()) {
                break;
            }
            line_start = head.len();
        }
    }
    String::from_utf8(head).map_err(|_| {
        Refusal::speaking(
            400,
            "husk: CONNECT request head is not text",
            "the request head is not valid UTF-8; a CONNECT head is ASCII".to_string(),
        )
    })
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
    serve_one_with(client, allow, HEAD_TIMEOUT)
}

/// `serve_one` with the head budget supplied, so a test can execute this whole path in a
/// second instead of in fifteen. The only production caller passes `HEAD_TIMEOUT`.
fn serve_one_with(client: UnixStream, allow: &Allowlist, head_budget: Duration) -> Verdict {
    let mut out = client;
    // ONE place answers the client, whatever went wrong. `tunnel` cannot return a refusal
    // that reaches nobody, because the only refusal it can build is an `Err(Refusal)` and
    // this is the only thing that consumes one (`B5-6`).
    match tunnel(&mut out, allow, head_budget) {
        Ok(reached) => Verdict::Allowed(reached),
        Err(refusal) => refusal.answer(&mut out),
    }
}

/// Authorise one request and then shuffle its bytes. Returns what was reached, or the
/// refusal to hand back.
fn tunnel(
    out: &mut UnixStream,
    allow: &Allowlist,
    head_budget: Duration,
) -> Result<String, Refusal> {
    // This clone is BOTH the head reader and the tunnel's client side, so the head deadline
    // is armed and cleared on the very descriptor it must not outlive — no reliance on
    // `dup(2)` sharing `SO_RCVTIMEO` between handles.
    let client_read = out.try_clone().map_err(|e| {
        Refusal::speaking(
            503,
            "husk: the proxy could not take the connection",
            format!(
                "the proxy could not duplicate the client socket ({e}). That is a fault on \
                 husk's side of the boundary, most likely file-descriptor exhaustion in the \
                 proxy process — the request was never read, so it was neither allowed nor \
                 refused, and retrying once other connections finish is reasonable."
            ),
        )
    })?;
    let mut reader = BufReader::new(client_read);

    let head = read_head(&mut reader, head_budget)?;
    let (host, port) = parse_connect(&head)
        .map_err(|e| Refusal::speaking(400, "Bad Request", e))?;

    // THE GATE. One call, one place, on the name the client asked for — and the dial below
    // uses that same name, so there is no window in which an authorised name becomes a
    // different destination.
    if !allow.permits(&host, port) {
        let why = format!(
            "{host}:{port} is not on husk's network allowlist. Ask your operator to add it \
             to sandbox.network.allowedDomains if the work genuinely needs it."
        );
        // THE REASON PHRASE, not just the body.
        //
        // This refusal answers a CONNECT, and almost no client shows a CONNECT response
        // BODY. curl prints `curl: (56) CONNECT tunnel failed, response 403`; Python raises
        // `Tunnel connection failed: 403 Forbidden`. Both discard the careful explanation
        // below and leave the caller with a bare number that names neither husk nor the host
        // — a good message on a channel nobody reads, which is the shape that cost this
        // project three incidents in one week (P13).
        //
        // The status line survives, because both of those quote it. So the short form goes
        // there and the full form stays in the body for clients that do show it.
        //
        // SANITISED, because `host` is adversary-supplied and a reason phrase is a header
        // line: anything with CR or LF in it would be response splitting. Bounded too — a
        // 4 KiB "hostname" must not become a 4 KiB status line. `Refusal::answer` sanitises
        // again for every phrase; this cap is what keeps the tail of THIS one readable.
        let safe_host: String = host
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || ".-_:".contains(*c))
            .take(64)
            .collect();
        return Err(Refusal::speaking(
            403,
            format!("husk blocked {safe_host}:{port} (not on the egress allowlist)"),
            why,
        ));
    }

    // Resolve and dial HERE, in the trusted process. The job never supplies an address,
    // so it cannot authorise a name and reach something else.
    let addrs = std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), port))
        .map(|a| a.collect::<Vec<_>>())
        .map_err(|e| Refusal::speaking(502, "Bad Gateway", format!("cannot resolve {host}: {e}")))?;
    let upstream = addrs
        .iter()
        .find_map(|a| TcpStream::connect_timeout(a, DIAL_TIMEOUT).ok())
        .ok_or_else(|| {
            Refusal::speaking(502, "Bad Gateway", format!("cannot connect to {host}:{port}"))
        })?;

    // The NAME husk authorised and the ADDRESS it actually dialled, captured before the
    // socket is moved into the tunnel. Both, because name-vs-address divergence is the
    // whole question the allowlist can be wrong about — a log with only the name could not
    // show it. Never the payload.
    let reached = match upstream.peer_addr() {
        Ok(a) => format!("{host}:{port} -> {a}"),
        Err(_) => format!("{host}:{port}"),
    };

    // SPLIT BOTH SOCKETS BEFORE THE 200, and that ordering is the fix, not a tidy-up. After
    // `200 Connection established` the channel is a tunnel: every further byte husk writes
    // is a TLS record to the client, so an HTTP refusal written there is not a refusal, it
    // is corruption that surfaces as a handshake error naming nobody. These two arms were
    // two of `B5-6`'s three silent paths; doing the splits first is what makes them
    // answerable at all (`P11`).
    let up_read = upstream.try_clone().map_err(|e| split_failed("upstream", &reached, e))?;
    let down_write = out.try_clone().map_err(|e| split_failed("client", &reached, e))?;

    if write!(out, "HTTP/1.1 200 Connection established\r\n\r\n").is_err() {
        return Err(Refusal::unspeakable("client went away before the tunnel opened"));
    }

    // The record AT THE MOMENT OF THE DECISION, and it is `B5-5`'s change that makes it
    // necessary: `Verdict::Allowed` is only emitted when a tunnel ENDS, and a tunnel is now
    // allowed to last as long as the job does. Without this line the trusted-side account of
    // a long-lived egress does not exist until it closes, which for the connection an
    // operator most wants to see is never (`P2`, `P7`).
    eprintln!("husk-proxy: opened: {reached}");

    // Tunnel. Two directions, one thread each, and the buffered reader carries over any
    // bytes the client already sent after its request head.
    let t = std::thread::spawn(move || pump(up_read, down_write));
    pump(reader, upstream);
    let _ = t.join();
    Ok(reached)
}

/// A `dup(2)` that failed after husk had already authorised and reached the host. Says so:
/// this is husk's own resource exhaustion, and a message that read like an allowlist denial
/// would send someone to edit a list that was never consulted (`P11`).
fn split_failed(which: &str, reached: &str, e: std::io::Error) -> Refusal {
    Refusal::speaking(
        503,
        "husk: the proxy could not start the tunnel",
        format!(
            "{reached} was authorised and reached, and then the proxy could not split the \
             {which} socket ({e}). That is a fault on husk's side of the boundary, most \
             likely file-descriptor exhaustion in the proxy process — the destination was \
             allowed, not refused, so the allowlist is not the thing to change."
        ),
    )
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
    /// `cap` is passed rather than read from a constant: it is computed once per proxy from
    /// the descriptor budget (see `cap_for`), and a slot must be counted against the same
    /// number the refusal quotes.
    fn acquire(live: &Arc<AtomicUsize>, cap: usize) -> Option<Self> {
        live.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| (n < cap).then_some(n + 1))
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
    // ONCE, at startup, and then quoted in every refusal that spends it. Reading it per
    // connection would let the cap move under a job that is already inside it.
    let fd_limit = fd_soft_limit();
    let cap = cap_for(fd_limit);
    // Announced for the same reason the allowlist is announced two screens up in `main.rs`:
    // a boundary nobody can see is a boundary nobody can check (`P2`'s record half), and this
    // one is now DERIVED rather than written down, so the operator cannot read it off the
    // source. It is also the number the 503 quotes, so the log says it before anyone hits it.
    eprintln!(
        "husk-proxy: up to {cap} concurrent tunnels ({FDS_PER_TUNNEL} descriptors each; soft \
         open-file limit {})",
        fd_limit_text(fd_limit)
    );
    // Consecutive FAILED accepts, reset by any success. Only the exhaustion errnos back off;
    // see `accept_retry`.
    let mut failures: u32 = 0;
    for conn in listener.incoming() {
        let client = match conn {
            Ok(c) => {
                failures = 0;
                c
            }
            Err(e) => {
                failures = failures.saturating_add(1);
                let retry = accept_retry(e.raw_os_error(), failures);
                if retry.log {
                    let waiting = if retry.sleep.is_zero() {
                        String::new()
                    } else {
                        format!(
                            " - the proxy is out of descriptors; retrying every {:?} until a \
                             tunnel closes. Nothing is lost: pending connections stay in the \
                             listen backlog",
                            retry.sleep
                        )
                    };
                    eprintln!("husk-proxy: accept failed ({failures} in a row): {e}{waiting}");
                }
                if !retry.sleep.is_zero() {
                    std::thread::sleep(retry.sleep);
                }
                continue;
            }
        };
        let Some(slot) = TunnelSlot::acquire(&live, cap) else {
            // Refuse rather than queue: a queued connection looks like a slow network to
            // the job, and "husk is slow" is a worse diagnosis to hand someone than
            // "husk refused, here is why".
            //
            // The message says husk does not reap idle tunnels because `B5-5`'s fix is what
            // made that worth saying. Before it, husk severed any tunnel whose client went
            // quiet for 15 s, so keep-alive pools never survived and this cap was hard to
            // reach; now a connection lasts until one end closes it, which is correct and
            // also means a pooling client can accumulate them. Announcing the change is
            // husk's job (`P13`) — the alternative, an idle timeout, is the defect again.
            let mut c = client;
            too_many_tunnels(cap, fd_limit).answer(&mut c);
            continue;
        };
        let allow = Arc::clone(&allow);
        std::thread::spawn(move || {
            // Moved into the thread and dropped when it ends, HOWEVER it ends.
            let _slot = slot;
            match serve_one(client, &allow) {
                // Logged on the TRUSTED side, so the record of what a job reached does not
                // depend on the job. Host and port only: never the payload.
                Verdict::Allowed(what) => eprintln!("husk-proxy: allowed: {what}"),
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
        const CAP: usize = 64;
        let live = Arc::new(AtomicUsize::new(0));
        for _ in 0..CAP * 2 {
            let slot =
                TunnelSlot::acquire(&live, CAP).expect("a returned slot must be reusable");
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
        const CAP: usize = 64;
        let live = Arc::new(AtomicUsize::new(0));
        let held: Vec<TunnelSlot> = (0..CAP)
            .map(|_| TunnelSlot::acquire(&live, CAP).expect("under the cap"))
            .collect();
        assert_eq!(live.load(Ordering::Relaxed), CAP);
        assert!(TunnelSlot::acquire(&live, CAP).is_none(), "the cap must hold at the boundary");
        drop(held);
        assert_eq!(live.load(Ordering::Relaxed), 0, "dropping releases");
        assert!(TunnelSlot::acquire(&live, CAP).is_some(), "a job gets its network back");
    }

    /// **`RDF F-4`, the half that is a number.** The cap was `const MAX_TUNNELS = 64`, per JOB,
    /// shared by every rank — so a 64-rank step with one HTTPS connection per rank was at the
    /// cap before pooling entered the picture, and a 128-rank step could not get half its ranks
    /// onto the network at all. Multi-rank steps are the reason the step broker exists.
    ///
    /// Pinned at the level of the bug: the SIZING FUNCTION, at descriptor limits this machine
    /// does not have (it has 1,048,576). The old code has no such function, which is the point
    /// — a constant has nothing to test.
    ///
    /// **The false friend it replaces**: `the_tunnel_cap_is_exact_and_slots_are_reusable` is a
    /// true and useful test that stays green for any cap whatsoever, including 1. Exactness is
    /// not adequacy, and nothing in the suite looked at the number.
    ///
    /// **MUTATION that turns it red:** make `cap_for` return `TUNNEL_CAP_WHEN_UNKNOWN` on every
    /// arm — i.e. put the old constant back. The 1024-limit row fails, naming the rank count.
    #[test]
    fn the_cap_is_sized_from_the_descriptor_budget_not_a_number_typed_in() {
        // What a 128-rank single-node step needs from ONE proxy: every rank relays through it.
        const RANKS_ON_A_BIG_NODE: usize = 128;

        // The common Linux default. This is the row that fails at HEAD.
        let common = cap_for(Some(1024));
        assert_eq!(common, (1024 - FD_RESERVE) / FDS_PER_TUNNEL);
        assert!(
            common >= RANKS_ON_A_BIG_NODE,
            "a {RANKS_ON_A_BIG_NODE}-rank step opening one connection per rank does not fit \
             in a cap of {common}; every rank shares this one proxy, and 64 was the old value"
        );

        // The other direction, and it is not a regression: at 256 descriptors a cap of 64
        // would promise 320 descriptors' worth of tunnels and pay the difference in EMFILE.
        let tight = cap_for(Some(256));
        assert!(tight < 64, "a cap must not outrun the descriptors backing it: {tight}");
        assert_eq!(tight, (256 - FD_RESERVE) / FDS_PER_TUNNEL);

        // Threads, not descriptors, bound the generous end.
        assert_eq!(cap_for(Some(1_048_576)), TUNNEL_CEILING);
        assert_eq!(cap_for(Some(usize::MAX)), TUNNEL_CEILING);

        // Never zero, whatever the arithmetic says: switching a job's egress off entirely
        // over a subtraction is a husk-shaped bug report, not a policy.
        for tiny in [0usize, 1, FD_RESERVE, FD_RESERVE + 1] {
            assert_eq!(cap_for(Some(tiny)), 1, "cap_for({tiny}) must still permit one tunnel");
        }

        // Unknown budget means husk learned nothing, so it does what it did before.
        assert_eq!(cap_for(None), TUNNEL_CAP_WHEN_UNKNOWN);

        // Monotonic: more descriptors must never mean fewer tunnels.
        let mut last = 0;
        for n in (0..4096).step_by(37) {
            let c = cap_for(Some(n));
            assert!(c >= last, "cap_for is not monotonic at {n}: {c} < {last}");
            last = c;
        }
    }

    /// The parser, against a PINNED sample and against this machine's real `/proc` text.
    ///
    /// Both, deliberately. A parser tested only on its own fixture is a test of the fixture
    /// (`P9`); a parser tested only against the live file cannot pin the shapes this machine
    /// does not currently produce — `unlimited` in particular, which is a real value of that
    /// field and would otherwise parse as `None` and silently drop the proxy to 64.
    #[test]
    fn the_descriptor_budget_is_read_from_real_proc_text() {
        let sample = "Limit                     Soft Limit           Hard Limit           Units\n\
                      Max stack size            8388608              unlimited            bytes\n\
                      Max open files            1024                 1048576              files\n\
                      Max locked memory         8388608              8388608              bytes\n";
        assert_eq!(parse_max_open_files(sample), Some(1024));
        assert_eq!(
            parse_max_open_files("Max open files            unlimited            unlimited"),
            Some(usize::MAX),
            "`unlimited` is a real value of this field and must not read as unparseable"
        );
        assert_eq!(parse_max_open_files("Max cpu time              unlimited\n"), None);
        assert_eq!(parse_max_open_files(""), None);

        // And the format assumption itself, against the kernel rather than against me.
        let live = fd_soft_limit().expect("/proc/self/limits must be readable and parseable");
        assert!(live > 0, "a soft descriptor limit of {live} cannot be right");
    }

    /// **`RDF F-5`.** `accept` failing with `EMFILE` leaves the pending connection in the
    /// backlog, so the next call fails identically and at once — the bare `continue` was an
    /// unbounded busy loop writing one log line per iteration into the operator's `$HOME`.
    /// `RDF` asked for the backoff BEFORE the cap is raised; the cap is raised in this change.
    ///
    /// Pinned as a pure decision so both arms can be executed without exhausting the host's
    /// descriptors, which no harness here can arrange (`P10`, said out loud).
    ///
    /// **MUTATION that turns it red:** return `Duration::ZERO` unconditionally (the old
    /// behaviour) — the burst row fails; or drop the errno test and back off on everything —
    /// the `ECONNABORTED` row fails, which is the arm that stops this fix from selling the
    /// caged job 50 ms of the trusted side per aborted connection; or move `log` back inside
    /// the exhaustion branch — the benign-burst row fails.
    ///
    /// **`N1-5`, and THE FALSE FRIEND IS IN THIS TEST'S OWN HISTORY.** The row below used to
    /// read `assert!(r.log, "errno {benign} keeps the old one-line-per-failure behaviour")` —
    /// green, and asserting the defect. The harm this whole function exists for is an unbounded
    /// log in the operator's `$HOME`; pinning "one line per failure" on the arm that does not
    /// sleep pinned the only unbounded writer left in the function. A passing assertion is
    /// evidence about the assertion (`P9`): what it proxied was "the benign arm is unchanged",
    /// and unchanged was the bug.
    ///
    /// **AXIS IT DOES NOT COVER:** that the loop in `serve` calls this at all, or calls it with
    /// a count it actually resets on success. That is `serve`'s, and it is exercised only by
    /// the live-listener test this harness cannot run (`P10`).
    #[test]
    fn an_accept_that_fails_for_want_of_descriptors_backs_off_and_stops_shouting() {
        // EMFILE: sleep, growing, bounded.
        let first = accept_retry(Some(24), 1);
        assert_eq!(first.sleep, ACCEPT_BACKOFF_START);
        assert!(first.log, "the FIRST failure must always be reported, not a round number");
        assert!(accept_retry(Some(24), 2).sleep > first.sleep, "the backoff must grow");
        assert_eq!(accept_retry(Some(24), 99).sleep, ACCEPT_BACKOFF_MAX, "and must be bounded");

        // A connection that aborted before accept is NOT a shortage: its backlog entry is
        // already consumed, so sleeping on it would let the caged side buy trusted-side idle
        // time. ECONNABORTED (103) and EINTR (4) still buy no sleep — that is the split this
        // fix must keep — but they no longer buy a log line each either (`N1-5`).
        for benign in [103, 4] {
            assert_eq!(
                accept_retry(Some(benign), 7).sleep,
                Duration::ZERO,
                "errno {benign} must not buy a sleep"
            );
            assert!(accept_retry(Some(benign), 1).log, "the FIRST is always reported");
            assert!(
                !accept_retry(Some(benign), 7).log,
                "errno {benign} is thinned like every other repeat: the log lives in the \
                 operator's $HOME whichever arm writes it"
            );
            let lines = (1..=1000u32).filter(|n| accept_retry(Some(benign), *n).log).count();
            assert!(lines <= 11, "a benign burst of 1000 still shouts {lines} times");
        }
        assert_eq!(accept_retry(None, 3).sleep, Duration::ZERO);
        assert!(!accept_retry(None, 3).log, "an accept error with no errno is thinned too");

        // A thousand consecutive EMFILEs: the old loop wrote a thousand lines into $HOME as
        // fast as the CPU allowed. Now it is a handful, and the loop yields between them.
        let lines = (1..=1000u32).filter(|n| accept_retry(Some(24), *n).log).count();
        assert!(lines <= 11, "a burst of 1000 still shouts {lines} times");
        let slept: Duration = (1..=1000u32).map(|n| accept_retry(Some(24), n).sleep).sum();
        assert!(slept > Duration::from_secs(900), "the loop must actually yield: {slept:?}");
    }

    /// **`RDF F-4`'s message half, and `P11`.** The old 503 ended "or ask your operator to
    /// raise the cap" while the cap was a `const` with no override in the tree: the operator's
    /// only route was rebuilding and reinstalling husk. An unattributed denial invites
    /// confident wrong remediation; a denial naming an action nobody can take invites a
    /// support round that ends in "you cannot".
    ///
    /// Rendered through `Refusal::answer`, the way the job receives it, so this covers the
    /// status line as well — most clients show only that (`RDF F-6a`).
    ///
    /// **MUTATION that turns it red:** restore the old body text.
    #[test]
    fn the_concurrency_refusal_names_a_remedy_that_exists() {
        let mut wire = Vec::new();
        let verdict = too_many_tunnels(cap_for(Some(1024)), Some(1024)).answer(&mut wire);
        let sent = String::from_utf8(wire).unwrap();

        assert!(sent.starts_with("HTTP/1.1 503 "), "{sent:?}");
        assert!(sent.contains("192"), "the cap in force must be stated: {sent}");
        assert!(
            sent.contains("ulimit -n"),
            "the remedy must be one the reader can perform: {sent}"
        );
        assert!(
            sent.contains("soft open-file limit is 1024"),
            "and it must say what the cap was derived FROM, or the remedy is a guess: {sent}"
        );
        assert!(
            !sent.contains("husk: husk"),
            "`answer` already prefixes the body with husk; this is the stutter `2cc3d21` \
             removed from two other messages (`RDF F-6`): {sent}"
        );

        // And when husk could NOT read the limit, the remedy must not name one anyway: the
        // fallback cap does not move with `ulimit`, so saying it would is `P11` again.
        let mut blind = Vec::new();
        too_many_tunnels(cap_for(None), None).answer(&mut blind);
        let blind = String::from_utf8(blind).unwrap();
        assert!(!blind.contains("ulimit -n"), "a remedy that would not work: {blind}");
        assert!(blind.contains("/proc/self/limits"), "say what husk could not read: {blind}");
        assert!(
            sent.contains("every rank"),
            "on a multi-rank step the shared proxy IS the explanation (`P13`): {sent}"
        );
        assert!(
            !sent.contains("ask your operator to raise the cap"),
            "that action did not exist; it is the `P11` defect this replaces: {sent}"
        );
        // The status line, which is all curl and urllib3 surface, still names husk.
        let status = sent.lines().next().unwrap();
        assert!(status.contains("husk"), "the reason phrase must name husk: {status:?}");
        assert!(matches!(verdict, Verdict::Refused(_)));
    }

    /// **`N1-1` — the remedy must match THE BOUND THAT ACTUALLY PRODUCED THE CAP.**
    ///
    /// The test above pinned two of the three cases and `ef9895a` claimed "both now carry
    /// assertions". They did not. `too_many_tunnels` branched on `Some(n) if n != usize::MAX`,
    /// so every cap produced by the THREAD ceiling fell into the fallback arm and the job was
    /// told husk "could not read this proxy's own open-file limit from /proc/self/limits" and
    /// that this "is worth reporting" — while the startup banner on the same run printed the
    /// limit. Reviewer-measured for `unlimited`; and this laptop is the other instance, with a
    /// finite 1,048,576 that took the OTHER arm and offered `ulimit -n` for a cap `ulimit -n`
    /// cannot move.
    ///
    /// Pinned as a PROPERTY rather than as three strings, because the strings are what drifted:
    /// **the message names `ulimit -n` if and only if some larger limit would produce a larger
    /// cap.** `cap_for` is the oracle for that, and it is executed here rather than reasoned
    /// about. The string rows underneath are the concrete anchor for the property.
    ///
    /// **MUTATION that turns it red:** put `match fd_limit { Some(n) if n != usize::MAX => …,
    /// _ => … }` back — the `usize::MAX` and 1,048,576 rows both fail, in opposite directions.
    ///
    /// **AXES IT DOES NOT COVER:** whether `serve` passes a `cap` that agrees with the
    /// `fd_limit` beside it (it computes both from one `fd_soft_limit()` call, once, at
    /// startup — not re-read per connection), and whether `ulimit -n` is honoured by the site's
    /// Slurm, which no test on this side can answer.
    #[test]
    fn the_remedy_names_ulimit_exactly_when_ulimit_would_help() {
        fn rendered(fd_limit: Option<usize>) -> String {
            let mut wire = Vec::new();
            too_many_tunnels(cap_for(fd_limit), fd_limit).answer(&mut wire);
            String::from_utf8(wire).unwrap()
        }

        // THE PROPERTY, over every shape of budget a node can present.
        for limit in [
            None,
            Some(0),
            Some(64),
            Some(256),
            Some(384),
            Some(1024),
            Some(5_179),
            Some(5_184),   // exactly TUNNEL_CEILING tunnels' worth: raising it moves nothing
            Some(1_048_576),
            Some(usize::MAX),
        ] {
            let sent = rendered(limit);
            let helps = a_bigger_limit_would_raise_the_cap(limit);
            assert_eq!(
                sent.contains("ulimit -n"),
                helps,
                "cap_for({limit:?}) = {} of a ceiling of {TUNNEL_CEILING}; naming `ulimit -n` \
                 here is {}: {sent}",
                cap_for(limit),
                if helps { "required" } else { "a remedy that would not move the cap" }
            );
            // Whatever the arm, husk must never claim it could not read a limit it read.
            if limit.is_some() {
                assert!(
                    !sent.contains("could not read"),
                    "husk read this limit; the banner prints it on the same run: {sent}"
                );
                assert!(
                    sent.contains(&fd_limit_text(limit)),
                    "the message must quote the limit the way the startup banner does, or the \
                     two halves of one job's stderr disagree about one fact: {sent}"
                );
            }
        }

        // The two concrete arms the review measured, as text.
        let unlimited = rendered(Some(usize::MAX));
        assert!(
            unlimited.contains("unlimited") && unlimited.contains("thread"),
            "an unlimited descriptor budget must be named as such, and the cap attributed to \
             the ceiling that really produced it: {unlimited}"
        );
        assert!(
            !unlimited.contains("worth reporting"),
            "`ulimit -n unlimited` on a compute node is not a defect report: {unlimited}"
        );
        // And the fallback arm keeps its own words, which are true only there.
        let blind = rendered(None);
        assert!(blind.contains("/proc/self/limits") && blind.contains("worth reporting"), "{blind}");
    }

    /// **`N1-6`.** `TUNNEL_CEILING`'s rationale is a memory-cost argument, and the number it
    /// reasoned from was "each tunnel is one spawned thread". There are two: `serve` spawns one
    /// per accepted connection, `tunnel` spawns a second for the reverse pump. The ceiling did
    /// not change; the sentence under it was out by 2x, and a hand-count in a comment decays
    /// exactly the way `FDS_PER_TUNNEL`'s would (`P12`).
    ///
    /// So the count is re-taken from the source on every run. Lexical, and deliberately
    /// scoped to the PRODUCTION half of this file — the tests below spawn threads of their own,
    /// and counting those would make the assertion meaningless.
    ///
    /// **MUTATION that turns it red:** set `THREADS_PER_TUNNEL` to 1, or add/remove a spawn in
    /// the production path without touching it.
    ///
    /// **AXIS IT DOES NOT COVER:** `FDS_PER_TUNNEL`, which has no syntactic marker to count and
    /// stays a hand-count checked against `tunnel`'s body by a reader.
    #[test]
    fn the_thread_cost_of_a_tunnel_is_counted_not_recalled() {
        let src = include_str!("netproxy.rs");
        let production = src.split("#[cfg(test)]").next().expect("this file has a test module");
        assert_eq!(
            production.matches("thread::spawn").count(),
            THREADS_PER_TUNNEL,
            "the production path spawns a different number of threads per tunnel than \
             THREADS_PER_TUNNEL says, so TUNNEL_CEILING's memory argument is out by that \
             factor. Count them in `serve` and `tunnel` and correct the constant."
        );
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

    /// **`B5-5`, and the one that matters.** `READ_TIMEOUT` was set on the client socket
    /// before `try_clone` and never cleared, so the REQUEST-phase deadline governed the
    /// TUNNEL: the same descriptor went to `pump`, whose `Err` arm breaks the loop and
    /// half-closes the upstream. Measured against a real `serve()` loop, husk sent FIN
    /// upstream **15.19 s** after the client went quiet — and an HTTPS client is quiet in
    /// exactly that way whenever the server takes time to produce its first byte.
    ///
    /// Pinned at the level of the bug: a real TCP upstream, a real `UnixStream` client, the
    /// real `serve_one` path, and an assertion about what the UPSTREAM sees. The head budget
    /// is injected so the test costs a second rather than sixteen; the production caller
    /// passes `HEAD_TIMEOUT`.
    ///
    /// **The false friends.** `the_allowlist_gates_real_connections` and
    /// `an_allowed_tunnel_records_the_name_and_the_address_it_dialled` both drive a real
    /// tunnel and both pass on the buggy code, because neither one is ever idle: the client
    /// half-closes immediately, which is the single case the stale deadline cannot cut.
    #[test]
    fn a_tunnel_outlives_the_head_deadline_when_the_client_is_merely_idle() {
        use std::net::{Shutdown, TcpListener};
        use std::sync::mpsc;

        const BUDGET: Duration = Duration::from_millis(250);
        // Long enough that a stale BUDGET-sized deadline has fired several times over.
        const WATCH: Duration = Duration::from_millis(1500);

        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel::<&'static str>();
        std::thread::spawn(move || {
            let (mut c, _) = upstream.accept().unwrap();
            c.set_read_timeout(Some(WATCH)).unwrap();
            let mut buf = [0u8; 64];
            // The client sends nothing after its CONNECT, so the only thing that can end
            // this read is husk closing the request direction underneath it.
            let seen = match c.read(&mut buf) {
                Ok(0) => "FIN-FROM-HUSK",
                Ok(_) => "DATA",
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    "STILL-OPEN"
                }
                Err(_) => "ERROR",
            };
            let _ = tx.send(seen);
            std::thread::sleep(Duration::from_millis(100));
        });

        let (mut client, proxy_side) = UnixStream::pair().unwrap();
        let allow = Allowlist::parse(&[format!("localhost:{port}")]).unwrap();
        let proxy = std::thread::spawn(move || serve_one_with(proxy_side, &allow, BUDGET));

        write!(client, "CONNECT localhost:{port} HTTP/1.1\r\n\r\n").unwrap();
        let mut r = BufReader::new(client.try_clone().unwrap());
        let mut status = String::new();
        r.read_line(&mut status).unwrap();
        assert!(status.contains("200"), "expected a tunnel, got {status:?}");

        // ...and now the client is simply idle, the way every HTTPS client is while it waits
        // for a slow server to start answering.
        let seen = rx.recv_timeout(WATCH * 4).expect("the upstream never reported");
        assert_eq!(
            seen, "STILL-OPEN",
            "husk closed the request direction while the client was merely idle: that is \
             B5-5, and it severs any HTTPS response that takes longer than the head deadline \
             to start"
        );

        let _ = client.shutdown(Shutdown::Both);
        let _ = proxy.join();
    }

    /// **`B5-5`, the other half: the deadline must still bound the HEAD.** A fix that simply
    /// deleted the timeout would pass the test above and hand a caged job an unbounded
    /// trusted-side read. Here the client sends one header and then stops, and the head
    /// phase has to end by itself.
    #[test]
    fn a_head_that_stops_half_way_still_hits_the_deadline() {
        const BUDGET: Duration = Duration::from_millis(250);
        let (mut client, proxy_side) = UnixStream::pair().unwrap();
        let allow = Allowlist::parse(&["example.com:443".to_string()]).unwrap();
        let started = Instant::now();
        let proxy = std::thread::spawn(move || serve_one_with(proxy_side, &allow, BUDGET));

        // A CONNECT line and no blank line: a well-formed head that never ends.
        write!(client, "CONNECT example.com:443 HTTP/1.1\r\n").unwrap();
        // The test waits with a bound of its own, so a head phase that never ends fails
        // here rather than hanging the suite (`P9`: a test that can only hang cannot fail).
        client.set_read_timeout(Some(BUDGET * 8)).unwrap();
        let mut r = BufReader::new(client.try_clone().unwrap());
        let mut status = String::new();
        r.read_line(&mut status).expect("husk never answered a head that stopped half way");
        assert!(
            status.starts_with("HTTP/1.1 408"),
            "a stalled head must be refused, out loud: {status:?}"
        );
        assert!(started.elapsed() < BUDGET * 8, "took {:?}", started.elapsed());
        assert_eq!(proxy.join().map(|v| matches!(v, Verdict::Refused(_))).unwrap(), true);
    }

    /// **`B5-6`, the size half.** `read_head` tested `head.len() > MAX_HEAD` at the TOP of
    /// the loop and then called `BufRead::read_line`, which is unbounded — so the cap applied
    /// per COMPLETED LINE, and a client that never sent `\n` was not bounded at all. Measured
    /// against a real `serve()`: 256 MiB on one line, **+512 MiB peak RSS** in the trusted
    /// process, and the job got `""` back.
    ///
    /// Asserted behaviourally rather than by reading a constant, and both halves of the
    /// finding in one place: husk must ANSWER (the refusal was one of the three silent
    /// paths), and it must have stopped READING long before 256 MiB.
    ///
    /// **The false friend:** every existing `parse_connect` test passes a `&str` that is
    /// already in memory, so none of them can see how it got there.
    #[test]
    fn an_endless_request_head_is_bounded_and_answered_rather_than_swallowed() {
        const FLOOD: usize = 256 * 1024 * 1024;
        // Generous: a socket buffer plus one chunk, nowhere near the 8 KiB husk keeps.
        const PLAUSIBLE_BACKPRESSURE: usize = 16 * 1024 * 1024;

        let (client, proxy_side) = UnixStream::pair().unwrap();
        let allow = Allowlist::parse(&["example.com:443".to_string()]).unwrap();
        let proxy =
            std::thread::spawn(move || serve_one_with(proxy_side, &allow, Duration::from_secs(2)));

        client.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let mut w = client.try_clone().unwrap();
        let pushed = std::thread::spawn(move || {
            let chunk = vec![b'A'; 64 * 1024]; // no newline, ever
            let mut sent = 0usize;
            while sent < FLOOD {
                match w.write_all(&chunk) {
                    Ok(()) => sent += chunk.len(),
                    Err(_) => break,
                }
            }
            sent
        });

        let mut r = BufReader::new(client);
        let mut status = String::new();
        r.read_line(&mut status).expect("husk never answered an endless head");
        assert!(
            status.starts_with("HTTP/1.1 431"),
            "an over-long head must come back as a refusal the job can read: {status:?}"
        );
        assert!(status.contains("husk"), "the status line must name the refuser: {status:?}");

        let sent = pushed.join().unwrap();
        assert!(
            sent < PLAUSIBLE_BACKPRESSURE,
            "husk kept reading a head that never ended: the client pushed {sent} bytes \
             (B5-6 measured 256 MiB in, +512 MiB RSS out)"
        );
        let _ = proxy.join();
    }

    /// The boundary the `B5-6` rewrite moves, pinned so it cannot be broken quietly.
    ///
    /// `read_head` stopped using `BufRead::read_line` and now drives `fill_buf`/`consume`
    /// itself, which means it is now responsible for consuming EXACTLY the head: bytes the
    /// client pipelined behind the blank line belong to the TUNNEL and must stay in the
    /// reader for `pump` to carry. A version that consumed the whole buffer would pass every
    /// other test in this file and silently eat the first TLS record of every connection
    /// that arrives in one write — which is what a real client does.
    #[test]
    fn bytes_pipelined_behind_the_head_still_reach_the_upstream() {
        use std::net::{Shutdown, TcpListener};
        use std::sync::mpsc;

        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            let (mut c, _) = upstream.accept().unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 64];
            while let Ok(n) = c.read(&mut buf) {
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
                if got.len() >= 11 {
                    break;
                }
            }
            let _ = tx.send(String::from_utf8_lossy(&got).into_owned());
        });

        let (mut client, proxy_side) = UnixStream::pair().unwrap();
        let allow = Allowlist::parse(&[format!("localhost:{port}")]).unwrap();
        let proxy = std::thread::spawn(move || {
            serve_one_with(proxy_side, &allow, Duration::from_secs(2))
        });

        // ONE write: head and payload in the same buffer, the way a TLS client sends them.
        write!(client, "CONNECT localhost:{port} HTTP/1.1\r\n\r\nEARLY-BYTES").unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).expect("upstream saw nothing"),
            "EARLY-BYTES",
            "the head reader swallowed bytes that belonged to the tunnel"
        );
        let _ = client.shutdown(Shutdown::Both);
        let _ = proxy.join();
    }

    /// **`B5-6`, the time half — the part the finding did not measure.** "Bounded in both
    /// size and time" was false in a second way: the deadline was per-READ, so a client that
    /// stayed under it forever was never refused. With `MAX_HEAD` bytes at 14 s apart that is
    /// 34 hours on one trusted-side thread, and a cap's worth of them is the job's whole
    /// egress for the price of a trickle.
    ///
    /// This client is never silent for as long as the budget, so a per-read deadline never
    /// fires; only a budget for the whole phase ends it.
    #[test]
    fn a_dribbled_head_is_bounded_by_the_whole_budget_not_by_each_read() {
        const BUDGET: Duration = Duration::from_millis(300);
        let (client, proxy_side) = UnixStream::pair().unwrap();
        let allow = Allowlist::parse(&["example.com:443".to_string()]).unwrap();
        let started = Instant::now();
        let proxy = std::thread::spawn(move || serve_one_with(proxy_side, &allow, BUDGET));

        client.set_read_timeout(Some(BUDGET * 6)).unwrap();
        let mut w = client.try_clone().unwrap();
        let drip = std::thread::spawn(move || {
            for _ in 0..64 {
                if w.write_all(b"X").is_err() {
                    break;
                }
                std::thread::sleep(BUDGET / 4);
            }
        });

        let mut r = BufReader::new(client);
        let mut status = String::new();
        r.read_line(&mut status).expect(
            "the head phase is bounded by each read, not by the phase: husk was still \
             reading a trickle after six budgets",
        );
        let took = started.elapsed();
        assert!(status.starts_with("HTTP/1.1 408"), "{status:?}");
        assert!(
            took < BUDGET * 6,
            "the head phase is bounded by each read, not by the phase: {took:?}"
        );
        let _ = proxy.join();
        let _ = drip.join();
    }

    /// **`B5-6`, the second half: three of five refusal paths wrote nothing back**, so a job
    /// could not tell a refusal from a network fault — under a module header saying that is
    /// exactly what must not happen, and confirmed from the client side in round 2 (`F12`:
    /// `received 0 bytes: b''`).
    ///
    /// A table rather than one case, because "husk answered" is the property, not "husk
    /// answered THIS". Each row also asserts the status is the RIGHT one: a 408 and a 431
    /// are different remediations, and folding them into one 400 is an unattributed denial
    /// (`P11`).
    ///
    /// Not covered here, and said plainly: the two `dup(2)` arms need file-descriptor
    /// exhaustion in the proxy process to reach, which this harness cannot arrange. They are
    /// answered by CONSTRUCTION instead — both `try_clone` calls now happen before the
    /// `200`, so their refusal is an `Err(Refusal)` like every other, and `serve_one_with`
    /// has exactly one thing that consumes one.
    #[test]
    fn every_refusal_before_the_tunnel_reaches_the_job_and_names_its_own_cause() {
        // A port nothing listens on, so the dial fails without needing a resolver.
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);

        let cases: Vec<(&str, String, &str)> = vec![
            (
                "an over-long head",
                format!("CONNECT {}:443 HTTP/1.1\r\n", "a".repeat(MAX_HEAD + 64)),
                "431",
            ),
            ("a head that never ends", "CONNECT example.com:443 HTTP/1.1\r\n".into(), "408"),
            ("not a CONNECT", "GET http://example.com/ HTTP/1.1\r\n\r\n".into(), "400"),
            ("an unlisted host", "CONNECT evil.example.com:443 HTTP/1.1\r\n\r\n".into(), "403"),
            (
                "an allowlisted host that will not answer",
                format!("CONNECT 127.0.0.1:{dead_port} HTTP/1.1\r\n\r\n"),
                "502",
            ),
        ];

        for (name, request, want) in cases {
            let (mut client, proxy_side) = UnixStream::pair().unwrap();
            let allow =
                Allowlist::parse(&[format!("127.0.0.1:{dead_port}"), "example.com:443".into()])
                    .unwrap();
            let proxy = std::thread::spawn(move || {
                serve_one_with(proxy_side, &allow, Duration::from_millis(250))
            });
            client.write_all(request.as_bytes()).unwrap();
            client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

            let mut r = BufReader::new(client.try_clone().unwrap());
            let mut status = String::new();
            // `Ok(0)` (a bare close) and a timeout are both the B5-6 bug; neither may pass.
            let status = match r.read_line(&mut status) {
                Ok(0) | Err(_) => String::new(),
                Ok(_) => status,
            };
            assert!(
                status.starts_with(&format!("HTTP/1.1 {want}")),
                "{name}: expected {want}, got {status:?} (an empty string is the B5-6 bug)"
            );
            let _ = proxy.join();
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

    #[test]
    fn an_allowed_tunnel_records_the_name_and_the_address_it_dialled() {
        // W0. The allowed branch used to log NOTHING, directly under a comment promising
        // "the record of what a job reached does not depend on the job" — so husk recorded
        // what it stopped and never what it permitted, and a successful egress had no
        // trusted-side account of its destination at all.
        //
        // Pinned at the VERDICT, which is what the log is built from, and asserting BOTH
        // halves: the NAME husk authorised and the ADDRESS it actually dialled. A record
        // with only the name could not show a name-vs-address divergence, which is the one
        // thing an allowlist can be silently wrong about.
        use std::io::Read;
        use std::net::{Shutdown, TcpListener};

        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = upstream.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for c in upstream.incoming().flatten() {
                let mut c = c;
                let _ = c.write_all(b"UPSTREAM-SPOKE\n");
            }
        });

        let (client, proxy_side) = UnixStream::pair().unwrap();
        let allow = Allowlist::parse(&[format!("localhost:{port}")]).unwrap();

        std::thread::spawn(move || {
            let mut c = client;
            let _ = write!(c, "CONNECT localhost:{port} HTTP/1.1\r\n\r\n");
            // Half-close so the proxy's client->upstream pump sees EOF and serve_one can
            // return; without this the test deadlocks on a tunnel nobody ends.
            let _ = c.shutdown(Shutdown::Write);
            let mut sink = Vec::new();
            let _ = c.read_to_end(&mut sink);
        });

        match serve_one(proxy_side, &allow) {
            Verdict::Allowed(recorded) => {
                assert!(
                    recorded.contains(&format!("localhost:{port}")),
                    "the record must name what was AUTHORISED: {recorded:?}"
                );
                assert!(
                    recorded.contains("127.0.0.1:"),
                    "the record must name the address actually DIALLED: {recorded:?}"
                );
            }
            Verdict::Refused(why) => panic!("expected an allowed tunnel, got refusal: {why}"),
        }
    }
}
