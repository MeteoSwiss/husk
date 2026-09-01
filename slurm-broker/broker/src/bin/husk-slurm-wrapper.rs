//! husk-slurm-wrapper — the fail-closed outer wrapper for the SLURM broker.
//!
//! Sequence (any failure aborts BEFORE the agent ever runs):
//!   1. resolve + validate config (stub, broker, sbatch target all exist+exec)
//!   2. create the spool dir
//!   3. launch the broker in the background — OUTSIDE the namespaces, so it keeps
//!      clean MUNGE credentials + network (the very things the sandbox denies) — and
//!      wait for it to ANNOUNCE ITSELF on a descriptor created before it existed, which
//!      the confined side can neither write nor plant (`spawn_broker`, `P2`)
//!   4. unshare a user+mount namespace (IDENTITY uid map — never map to root, see
//!      `enter_user_mount_ns`: EUID==0 breaks the agent's own Bash sandbox)
//!   5. bind-mount the stub over the real `sbatch`, then READ BACK to prove it
//!   6. exec the agent (husk) — inherits the mount, so its per-command
//!      bwrap sees the stub instead of the real sbatch
//!
//! Fail-closed is enforced structurally, not by discipline:
//!   - every fallible step returns `io::Result` and is `?`-propagated, so a
//!     failure can never "fall through" to the exec;
//!   - the agent exec REQUIRES a `SandboxReady` witness, and the only way to mint one is
//!     the bind+verify succeeding. The COMPILER carries that sentence, not the reader.
//!     Until 2026-08-31 this bullet WAS the enforcement, and it was false. What makes it
//!     true is four things at once, listed in `P6` and checked by
//!     `the_witnesses_stay_unforgeable_and_so_does_the_next_one` — not the one-line
//!     property two rewrites of that paragraph got wrong. See `mod witness`;
//!   - the broker handle's `Drop` kills the broker on any early return, so a
//!     setup failure never leaves an orphan broker. On success, `execve` replaces
//!     this process image, so `Drop` never runs and the broker lives on.
//!
//! Zero external crates on purpose: this is a trusted boundary-setup binary, so
//! its audit surface is std + the two libc symbols every process already links.

use std::convert::Infallible;
use std::ffi::CString;
use std::fs;
use std::io::{self, Read, Write};
use std::os::raw::{c_char, c_int, c_ulong, c_void};
use std::os::unix::ffi::OsStrExt;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use std::ptr;

// The one internal, dependency-free shared const (keeps this binary's zero-crate
// audit surface intact — see the module header).
use husk_slurm_broker::{
    read_settings_layer, session_log_path, session_spool_dir, SettingsLayer, BROKERED_MUTATING,
    BROKER_READY_FD_ENV, MAX_SETTINGS_BYTES, READONLY_SLURM,
};

// ---- the only FFI: two namespace syscalls std doesn't expose ----------------
const CLONE_NEWNS: c_int = 0x0002_0000; // new mount namespace
const CLONE_NEWUSER: c_int = 0x1000_0000; // new user namespace
const MS_BIND: c_ulong = 0x1000;

extern "C" {
    fn unshare(flags: c_int) -> c_int;
    fn getxattr(
        path: *const c_char,
        name: *const c_char,
        value: *mut c_void,
        size: usize,
    ) -> isize;
    fn mount(
        src: *const c_char,
        target: *const c_char,
        fstype: *const c_char,
        flags: c_ulong,
        data: *const c_void,
    ) -> c_int;
    fn getuid() -> u32;
    fn getgid() -> u32;
}

fn sys_unshare(flags: c_int) -> io::Result<()> {
    // SAFETY: pure flag argument; return value checked.
    if unsafe { unshare(flags) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn bind_file(src: &Path, target: &Path) -> io::Result<()> {
    let s = CString::new(src.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "stub path has a NUL byte"))?;
    let t = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sbatch path has a NUL byte"))?;
    // SAFETY: valid C strings; null fstype/data are valid for a bind mount.
    let r = unsafe { mount(s.as_ptr(), t.as_ptr(), ptr::null(), MS_BIND, ptr::null()) };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// ---- config -----------------------------------------------------------------
struct Config {
    spool: PathBuf,
    agent: Vec<String>, // command to exec (default: husk)
    /// `sbatch` to shadow (explicit `--sbatch-path`, else first on PATH).
    /// `None` means NO SLURM on this machine -> no brokering at all (see `run`).
    sbatch: Option<PathBuf>,
    /// Brokering pieces — only needed (and validated) when SLURM is detected.
    stub: Option<PathBuf>,
    broker: Option<PathBuf>,
}

/// Raw, unresolved CLI flags — the pure parse step, separated from env defaults
/// and filesystem validation so it can be unit-tested with synthetic argv.
#[derive(Default)]
struct RawArgs {
    spool: Option<PathBuf>,
    stub: Option<PathBuf>,
    broker: Option<PathBuf>,
    sbatch: Option<PathBuf>,
    agent: Vec<String>,
    help: bool,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> io::Result<RawArgs> {
    let mut raw = RawArgs::default();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--spool" => raw.spool = args.next().map(PathBuf::from),
            "--stub" => raw.stub = args.next().map(PathBuf::from),
            "--broker" => raw.broker = args.next().map(PathBuf::from),
            "--sbatch-path" => raw.sbatch = args.next().map(PathBuf::from),
            "--" => {
                raw.agent = args.by_ref().collect();
                break;
            }
            "-h" | "--help" => {
                raw.help = true;
                return Ok(raw);
            }
            other => return Err(usage(format!("unknown argument '{other}'"))),
        }
    }
    Ok(raw)
}

impl Config {
    fn parse() -> io::Result<Config> {
        let raw = parse_args(std::env::args().skip(1))?;
        if raw.help {
            print_help();
            std::process::exit(0);
        }

        // Per-session by default (`.husk-slurm-spool-<pid>`, this pid, which becomes the
        // agent's after the exec). Two husk sessions in one project directory then get
        // their own rendezvous, and — with the `owner` file the broker writes — a spool
        // left on disk can be told apart from one in use.
        let spool = raw
            .spool
            .or_else(|| std::env::var_os("HUSK_SLURM_SPOOL").map(PathBuf::from))
            .unwrap_or_else(|| {
                session_spool_dir(&std::env::current_dir().unwrap_or_default(), std::process::id())
            });
        let agent = if raw.agent.is_empty() {
            vec!["husk".to_string()]
        } else {
            raw.agent
        };
        // SLURM detection: explicit --sbatch-path, else first `sbatch` on PATH.
        // None => no SLURM here => no brokering (decided in `run`). Validation of
        // the brokering pieces is deferred to the SLURM-present branch so the
        // no-SLURM (laptop) case needs none of them.
        let sbatch = raw.sbatch.or_else(|| which("sbatch"));
        Ok(Config { spool, agent, sbatch, stub: raw.stub, broker: raw.broker })
    }
}

fn require_executable(p: &Path, what: &str) -> io::Result<()> {
    let md = fs::metadata(p).map_err(|e| {
        io::Error::new(e.kind(), format!("{what} '{}' is not accessible: {e}", p.display()))
    })?;
    if !md.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{what} '{}' is not a regular file", p.display()),
        ));
    }
    if md.permissions().mode() & 0o111 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{what} '{}' is not executable", p.display()),
        ));
    }
    Ok(())
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(name);
        if let Ok(md) = fs::metadata(&cand) {
            if md.is_file() && md.permissions().mode() & 0o111 != 0 {
                return Some(cand);
            }
        }
    }
    None
}

// ---- the broker child: killed on any early return, survives a successful exec
//
// TWO resources, ONE owner: the child process, and the readiness channel it reports on.
// They are acquired together in `spawn_broker` and released together in `Drop`, so neither
// can outlive the other on any path, including the unwind (`P6`).
struct BrokerHandle(Child, UnixStream);

/// What one non-blocking look at the readiness channel says.
///
/// Three outcomes, named rather than folded into an `Option<bool>`, because conflating them
/// IS the bug this fix closes: `<spool>/owner.exists()` answered "serving" for a file the
/// confined side had planted, and "not yet" for a broker that had already died.
enum Readiness {
    /// The byte arrived. The broker is back from `claim_spool`: its settings parsed, its
    /// spool is taken (or knowingly shared), and it is about to watch it.
    Serving,
    /// Nothing yet, and the channel is still open — an ordinary still-starting broker.
    NotYet,
    /// EOF: every copy of the write end is closed, so the byte is never coming.
    ChannelClosed,
}

impl BrokerHandle {
    /// One non-blocking look. `WouldBlock` is the normal answer here, not an error.
    fn readiness(&mut self) -> io::Result<Readiness> {
        let mut byte = [0u8; 1];
        match self.1.read(&mut byte) {
            Ok(0) => Ok(Readiness::ChannelClosed),
            Ok(_) => Ok(Readiness::Serving),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(Readiness::NotYet),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(Readiness::NotYet),
            Err(e) => Err(e),
        }
    }

    /// Wait a BOUNDED moment for an already-dying child to become reapable.
    ///
    /// The kernel tears down the fd table before the task is reapable, so EOF on the channel
    /// can arrive microseconds before `try_wait` will say why. Without this the operator gets
    /// a sentence about a descriptor instead of the exit status and the broker's own words —
    /// the wrong half of the fact, at the moment they are most confused (`P13`).
    fn reap_within(&mut self, limit: Duration) -> io::Result<Option<ExitStatus>> {
        let start = Instant::now();
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(Some(status));
            }
            if start.elapsed() > limit {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for BrokerHandle {
    fn drop(&mut self) {
        // Reached only on an error unwind (a successful `execve` replaces this
        // image, so Drop never runs there). Don't leave an orphan broker.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Choose where the broker's session log goes, creating the directory for it.
///
/// `~/.husk/log/husk-<utc>-<pid>.log`, which is deliberately NOT in the spool. The spool
/// has to be writable by the caged agent for the stub to reach it, so a log kept there
/// is one the confined side can truncate or forge — the audited party must not be able
/// to author the audit trail. Reads are unrestricted, so the agent can still open this
/// file to diagnose itself.
///
/// Falls back to the old in-spool location if `$HOME` is unusable, with a warning:
/// logging is diagnostics, not the boundary, so it must not be able to abort a launch.
fn resolve_session_log(spool: &Path) -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Some(home) = home.filter(|h| !h.as_os_str().is_empty()) {
        let path = session_log_path(&home, secs, std::process::id());
        match path.parent().map(fs::create_dir_all) {
            Some(Ok(())) => {
                // B1-F7: give the directory a lifetime owner. This is the moment it is
                // about to grow, so it is the moment to bound it — one file per session is
                // the right shape, "one per session forever" is a home quota that fills and
                // takes the user down with a cause nobody will connect to husk. Best-effort:
                // hygiene must never stop a session from starting.
                if let Some(dir) = path.parent() {
                    let n = husk_slurm_broker::prune_log_dir(dir, secs);
                    if n > 0 {
                        eprintln!(
                            "husk-slurm-wrapper: pruned {n} old log file(s) from {}",
                            dir.display()
                        );
                    }
                }
                return path;
            }
            _ => eprintln!(
                "husk-slurm-wrapper: cannot create '{}' — falling back to a log inside the \
                 spool, which the sandboxed agent can write",
                path.parent().unwrap_or(&path).display()
            ),
        }
    }
    spool.join("broker.log")
}

/// Start the broker, holding one end of the channel it will announce itself on.
///
/// **The readiness signal is a descriptor, not a file.** `<spool>/owner` used to be the only
/// positive evidence `BrokerReady` had, and `lib.rs` states the rule for that directory:
/// *"Everything in here is agent-writable, so nothing in here is evidence."* Three versions of
/// this function tried to make a file in there mean something, and the failure was never in
/// the reading:
///
///   - read it as it stands, and a leftover `owner` mints the witness for a broker that
///     exited(1) — the 2026-08-06 Balfrin incident (`B5-2`);
///   - compare pids, and `echo pid=1 > owner` is a permanent refusal blaming another session
///     — an agent-triggerable denial of service (`RC-4`, and it got the fix reverted);
///   - unlink it first, and `mkdir owner` makes the unlink fail with `EISDIR`, `exists()` is
///     still true, and the witness mints on iteration 1 (`RC2-1`, measured end to end: 0.005 s
///     to launch against a broker that had already exited(2)). Requiring a regular file, or
///     refusing when the unlink fails, is `RC-4` again in different clothes.
///
/// Every disposition of a file the confined side owns is either a false accept or a denial it
/// can trigger; there is no third option at that level. So the evidence leaves the filesystem
/// (`P2`): a socket pair is created HERE, before the child exists, and one end becomes the
/// broker's fd 0. The only two processes that can ever hold an end are this one and the child
/// it is about to fork. A descriptor cannot be pre-planted, `mkdir`ed, symlinked or deleted
/// from inside the cage, and after this change there is nothing in the spool left to aim at.
///
/// **`<spool>/owner` still exists, and is no longer evidence.** `main.rs` still writes and
/// reads it — `spool_owner_pid` for guest detection, `owns_spool` for teardown,
/// `reap_stale_spools` for sessions that were killed rather than signalled. That is
/// BOOKKEEPING among brokers about a directory they share; the wrapper's fail-closed decision
/// no longer consults it, which is why `BrokerReady::establish` no longer takes a spool path
/// at all. The signature carries that distinction, not this paragraph.
///
/// **And nothing in the spool is touched here any more,** which retires the cost the unlink
/// added. Pointed at a shared spool — `HUSK_SLURM_SPOOL` is exported into the agent's
/// environment, so a nested husk lands there by default — it deleted the OUTER session's
/// `owner`; the outer broker then took the whole directory with it at teardown, and every
/// later `sbatch` in that session timed out at 120 s against a spool that no longer existed
/// (`RC2-2`, measured against a live outer broker).
fn spawn_broker(broker: &Path, spool: &Path, log_path: &Path) -> io::Result<BrokerHandle> {
    // Created before the fork, so the child inherits exactly one end and nothing else can
    // obtain one. Non-blocking on OUR side: `establish_within` polls it beside `try_wait`,
    // and a blocking read there would hide a dying broker behind a wait that never returns.
    let (ours, theirs) = UnixStream::pair()
        .and_then(|(ours, theirs)| ours.set_nonblocking(true).map(|()| (ours, theirs)))
        .map_err(|e| {
            io::Error::new(e.kind(), format!("cannot create the broker readiness channel: {e}"))
        })?;
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|e| {
            io::Error::new(e.kind(), format!("cannot open session log '{}': {e}", log_path.display()))
        })?;
    let errlog = log.try_clone()?;
    // Does the broker's own log land somewhere the CONFINED side can read?
    //
    // Normally no: it is `~/.husk/log/...`, and the cage tmpfs-masks the home (a caged
    // agent measures `~/.husk` as ENOENT). The broker relies on that to write refusal
    // DETAIL — the resolved host path, the errno — to its stderr while handing the agent
    // a message with no host fact in it (A7-1). In the `$HOME`-unusable fallback above the
    // log moves INTO THE SPOOL, which the agent can read, and that detail would become
    // exactly the existence oracle the sanitised message removed.
    //
    // So tell the broker which mode it is in, DERIVED from where the log actually went
    // rather than tracked as a second flag that could drift from it. The agent cannot
    // reach this env: the wrapper is outside the cage and starts before the agent exists.
    let reachable = log_path.starts_with(spool);
    let child = Command::new(broker)
        .arg("--spool")
        .arg(spool)
        .env("HUSK_SLURM_SPOOL", spool)
        .env("HUSK_LOG_AGENT_READABLE", if reachable { "1" } else { "0" })
        // fd 0 IS the readiness channel. It is the descriptor this wrapper already owns and
        // already sets (it was `Stdio::null()`), so there is no `pre_exec` and no `dup2`, and
        // the binary's zero-crate / two-libc-symbol audit surface is unchanged. The login
        // broker never reads stdin; `--hold-cage`, the one mode that does, is never spawned
        // from here. The NUMBER is told to the broker rather than assumed, and it is set on
        // this `Command`, so what the agent puts in the environment is never read (`P2`).
        .env(BROKER_READY_FD_ENV, "0")
        .stdin(Stdio::from(OwnedFd::from(theirs)))
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(errlog))
        .spawn()
        .map_err(|e| io::Error::new(e.kind(), format!("failed to launch broker: {e}")))?;
    Ok(BrokerHandle(child, ours))
}

// ---- `mod witness`: the tokens `run` cannot mint ----------------------------
//
// `P6`'s acquisition-side twin is *make the unverified state unrepresentable*. The
// compiler is the only thing that can carry that, and Rust's encapsulation unit is the
// MODULE — so a witness declared beside its consumer is a naming convention.
//
// It was one, and it was measured (`B5-1`, verified by `D1`). `SandboxReady` and
// `SettingsIntact` were field-less unit structs at this file's top level, so
//
//     let intact = SettingsIntact::establish().unwrap_or(SettingsIntact);
//     let ready  = SandboxReady::establish(stub, sbatch).unwrap_or(SandboxReady);
//
// compiled with no new warnings, left 328/328 green, and launched the agent with the
// sbatch bind failed and a `"sandbox": {"enabled": false}` override in force.
//
// THE PROPERTY, stated so the next witness can be checked against it: **no expression
// outside this module may yield one of these types.** A private field behind a module
// boundary is how it is obtained here — but it is the property, not the recipe, that is
// load-bearing, and three ordinary edits undo it just as completely as a public field
// would: a `#[derive(Default)]` (the fields are `()`, for which the derive is free), a
// `Deserialize`, or any `pub`/`pub(crate)` item in here that returns a witness. The first
// two are why `the_witnesses_stay_unforgeable_and_so_does_the_next_one` compiles
// `.unwrap_or(T)`, `.unwrap_or_default()`, a struct literal and `().into()` against EVERY
// `pub(crate) struct` DECLARED IN HERE rather than against a list someone has to extend —
// the module, not the `use` line, because a witness reached by full path or by a second
// `use` line is not on that line and was measured green (`RC2-4`). The third is why that
// test also refuses any `pub` item in here outside two exact `establish` signatures, and
// any trait `impl` at all.
//
// Two residuals, stated rather than implied:
//
//   - `unsafe` still forges anything (`mem::zeroed`, `transmute`). Intended floor: the
//     module makes the mistake impossible to make by ACCIDENT and impossible to review
//     past, not impossible to write on purpose.
//   - INSIDE this module there is no mechanism at all. An `establish` that returns `Ok`
//     without checking is indistinguishable from one that checks, to any tool. Naming it
//     `establish` does not make it check: `RC2-4` renamed one to `establish_not_applicable`
//     and the audit admitted it, so the audit now takes two exact signatures — but the
//     residual is the second half, and it stays. That is why the module holds three
//     functions and nothing else, and why the test refuses to let a fourth `pub` item
//     appear here unnoticed.
mod witness {
    use super::*;

    // ---- the second witness: the broker is actually SERVING ---------------------

    /// Proof that the broker came up and claimed its spool.
    ///
    /// `spawn_broker` returns as soon as `execve` succeeds, which says nothing about whether the
    /// broker survived its own startup. It has a fail-closed path — unreadable settings, an
    /// unusable spool — where it prints a precise reason and exits(2). Nothing checked.
    ///
    /// **2026-08-06, Balfrin.** A zero-byte `.claude/settings.json` sent it down that path. The
    /// wrapper had already `exec`d the agent, so the dead broker became a zombie nobody reaped,
    /// every `sbatch` and `squeue` went into a spool with no reader, and each one returned
    /// `timed out after 120s waiting for the SLURM broker`. Four sessions in a row, for hours.
    /// The actual reason — naming the file, the parse error and the fix — was sitting in
    /// `~/.husk/log/`, which the cage masks from the agent and which no human thinks to open
    /// while a command is merely slow.
    ///
    /// The same shape had already cost a day on the compute side, where the guard started the
    /// step broker and did not check it either. Fixing one half and not the other is how it got
    /// two chances.
    ///
    /// So: no agent runs unless a broker is serving it. `exec_agent` demands this token, and the
    /// only way to mint one is to read the byte the broker writes on a descriptor it inherited
    /// from `spawn_broker` — see that function for why the evidence is not a file. The
    /// wrapper's stderr is the terminal the human is looking at, so the refusal lands where a
    /// decision can be made instead of in a file nobody opens.
    pub(crate) struct BrokerReady(#[allow(dead_code)] BrokerHandle);

    /// How long the broker may take to announce itself. Generous: it parses a little JSON and
    /// writes one file, but the project dir can be on a cold Lustre mount.
    const BROKER_READY_TIMEOUT: Duration = Duration::from_secs(15);

    /// How long to wait for an exit STATUS once the channel has already reported EOF. The
    /// race it covers is microseconds wide (the kernel closes the fds, then the task becomes
    /// reapable); this is only large enough that a loaded login node cannot lose it, and it is
    /// reached on no path where the launch was going to succeed.
    const EXIT_STATUS_GRACE: Duration = Duration::from_millis(500);

    impl BrokerReady {
        /// Wait for the broker to SAY it is serving, or for it to die trying.
        ///
        /// Dropping `handle` on the error paths kills the broker, so a half-started one is not
        /// left behind — that is `BrokerHandle`'s `Drop` doing its job.
        pub(crate) fn establish(handle: BrokerHandle, log_path: &Path) -> io::Result<Self> {
            Self::establish_within(handle, log_path, BROKER_READY_TIMEOUT)
        }

        /// The timeout is a parameter so the "alive but never announces itself" path is
        /// testable without a fifteen-second test. Everything else is identical.
        ///
        /// **NOTE WHAT IS NOT A PARAMETER: the spool.** The readiness question is answered from
        /// a descriptor this process created before the broker existed, so there is no path
        /// here for the confined side to plant, delete, `mkdir` or point elsewhere (`P2`).
        /// Three attempts at this check read a file out of that directory and each one was
        /// either a false accept or a denial the agent could trigger; the argument that is
        /// *gone* is the fix.
        pub(crate) fn establish_within(
            mut handle: BrokerHandle,
            log_path: &Path,
            limit: Duration,
        ) -> io::Result<Self> {
            let start = Instant::now();
            loop {
                // THE CHILD IS ASKED FIRST, and the order is the check (`B5-2`). A broker that
                // announces itself and then dies has said something true about the past and
                // false about the present, and a loop that looks at the channel first returns
                // on the buffered byte without ever asking. Death is the fact that outranks it:
                // once the child is reaped there is nothing left to serve the session, whatever
                // it said earlier. Asking first also gets the operator the real reason instead
                // of a timeout, at the moment they are most confused.
                //
                // What this does NOT close, said plainly: a broker that signals and dies in the
                // window between this call and the next line still mints. No check at this
                // level can close that — liveness at time T is not liveness at T+e — and the
                // residual is the same one every readiness probe has.
                if let Some(status) = handle.0.try_wait()? {
                    return Err(Self::exited(status, log_path));
                }
                match handle.readiness()? {
                    Readiness::Serving => return Ok(BrokerReady(handle)),
                    Readiness::NotYet => {}
                    // The write end is gone and no byte came. Nearly always that means the
                    // process is gone too, so give it a bounded moment to become reapable and
                    // report the exit STATUS; if it really is still running, say that instead.
                    // "It closed the channel" and "it timed out" are different bugs, and one
                    // message for both would send the operator after the wrong one (`P13`).
                    Readiness::ChannelClosed => {
                        return Err(match handle.reap_within(EXIT_STATUS_GRACE)? {
                            Some(status) => Self::exited(status, log_path),
                            None => io::Error::other(format!(
                                "the SLURM broker closed its readiness channel without ever \
                                 saying it was serving, and it is still running.\nhusk: \
                                 refusing to launch the agent — a broker that will not answer \
                                 this will not answer an sbatch either.\nhusk: broker log \
                                 {}\nhusk: the broker said:\n{}",
                                log_path.display(),
                                broker_refusal_reason(log_path)
                            )),
                        });
                    }
                }
                if start.elapsed() > limit {
                    return Err(io::Error::other(format!(
                        "the SLURM broker did not claim its spool within {}s (it is still \
                         running, but not serving).\nhusk: refusing to launch the agent rather \
                         than hand it a broker that may never answer.\nhusk: if husk was just \
                         reinstalled, check that the broker beside this wrapper came from the \
                         same build — one built before 2026-08-31 does not know how to signal \
                         readiness and will always time out here.\nhusk: broker log {}\nhusk: \
                         the broker said:\n{}",
                        limit.as_secs(),
                        log_path.display(),
                        broker_refusal_reason(log_path)
                    )));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        /// The single wording for "the broker is gone", so the two paths that can discover it
        /// cannot drift into two descriptions of one fact (`P8`).
        fn exited(status: ExitStatus, log_path: &Path) -> io::Error {
            io::Error::other(format!(
                "the SLURM broker exited during startup ({status}), so nothing would serve \
                 this session.\nhusk: refusing to launch the agent — otherwise every sbatch \
                 and squeue it runs would hang for 120s with no explanation.\nhusk: the \
                 broker said:\n{}",
                broker_refusal_reason(log_path)
            ))
        }
    }

    pub(crate) struct SandboxReady(());

    impl SandboxReady {
        /// Bind the stub over the real sbatch, then PROVE it by comparing dev+inode.
        /// Returning `Ok` is the only way to obtain the token exec_agent requires.
        pub(crate) fn establish(stub: &Path, sbatch: &Path) -> io::Result<SandboxReady> {
            bind_file(stub, sbatch)?;
            let a = fs::metadata(stub)?;
            let b = fs::metadata(sbatch)?;
            if a.dev() == b.dev() && a.ino() == b.ino() {
                Ok(SandboxReady(()))
            } else {
                Err(io::Error::other(format!(
                    "bind verification FAILED: '{}' is not the stub after mount",
                    sbatch.display()
                )))
            }
        }
    }

    /// Witness: no settings layer overrides husk's sandbox block. See P6 (structural, not
    /// remembered) and P7 (a control that can fail silently has already failed).
    ///
    /// THE FACT THAT IS SPECIFIC TO HUSK, and the reason this is fail-closed rather than a
    /// warning: husk's own compute-side reader of these files is ADDITIVE — a downgraded
    /// block can only tighten a job, so it fails SAFE — while the borrowed login runtime uses
    /// REPLACE semantics on the whole `sandbox` key, so one stray file drops the ~/.claude
    /// credential masks AND the strict egress allowlist together, and fails OPEN. The
    /// `/sandbox` toggle writes exactly such a file; one was found in this repo, written by a
    /// toggle earlier the same day.
    ///
    /// Minted before any resource is acquired — no spool, no broker, no namespace — so a
    /// refusal has nothing to unwind, and both exec paths demand it, so the agent is
    /// unreachable without it. Same guarantee `SandboxReady` gives the sbatch stub.
    pub(crate) struct SettingsIntact(());

    impl SettingsIntact {
        pub(crate) fn establish() -> io::Result<SettingsIntact> {
            let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
            let cwd = std::env::current_dir().unwrap_or_default();
            let hits = sandbox_override_files(&home, &cwd);
            if hits.is_empty() {
                return Ok(SettingsIntact(()));
            }
            eprint!("{}", override_message(&hits));
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "husk's sandbox block is overridden by a higher-precedence settings file",
            ))
        }
    }
}

use witness::{BrokerReady, SandboxReady, SettingsIntact};

/// The broker's own words, for relaying to the terminal.
///
/// Its messages are already good — they name the file, the error and the fix. The failure was
/// never their content, it was that they landed somewhere neither party reads. So quote them
/// rather than paraphrase: a second wording of the same fact is one more thing to drift.
fn broker_refusal_reason(log_path: &Path) -> String {
    let text = match fs::read_to_string(log_path) {
        Ok(t) => t,
        Err(e) => {
            return format!("      (could not read {}: {e})", log_path.display());
        }
    };
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("husk:") || l.starts_with("broker:"))
        .collect();
    if lines.is_empty() {
        return format!("      (nothing in {} — it died before saying why)", log_path.display());
    }
    lines
        .iter()
        .rev()
        .take(6)
        .rev()
        .map(|l| format!("      {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Unshare a user+mount namespace so we can bind-mount the stub over `sbatch`.
///
/// The mapping is IDENTITY (`uid -> uid`), deliberately NOT `0 -> uid`. We do not need
/// to be root inside: CAP_SYS_ADMIN in a new user namespace comes from *creating* it,
/// not from being uid 0, so the bind-mount works either way (bwrap does the same).
///
/// Mapping ourselves to root broke the agent's OWN Bash sandbox: with EUID==0 the
/// sandbox-runtime treats us as a "root parent" and adds `bwrap --cap-drop ALL`, which
/// empties the capability BOUNDING set. `apply-seccomp` then creates its nested userns
/// but can no longer gain the CAP_SYS_ADMIN that writing `uid_map` requires — so every
/// Bash command died with `apply-seccomp: write /proc/self/uid_map: Operation not
/// permitted` on SLURM machines (never on a laptop, where no SLURM means no namespace
/// at all). Identity mapping keeps EUID != 0, so the inner sandbox takes its normal,
/// working path. Identity is also the least surprising view: files keep their real
/// owner inside the namespace instead of appearing to belong to root.
/// Warn if the project's files carry a POSIX ACL naming a group this namespace cannot map.
///
/// **The worst cost-to-diagnose defect reported against husk so far** (KENDA session,
/// 2026-08-07: two full from-scratch builds). The chain, which nothing along the way names:
///
///   1. an unprivileged user namespace can map exactly ONE gid — its own — so every other
///      group on a file's ACL is unmapped, and the kernel renders it as `(gid_t)-1`,
///      i.e. `group:4294967295:` in `getfacl`;
///   2. `shutil.copystat` copies `system.posix_acl_access`, and setting a blob containing an
///      unmapped group returns **EINVAL**;
///   3. Python's `shutil._copyxattr` tolerates ENOTSUP/EACCES/ENODATA but not EINVAL, so it
///      raises;
///   4. `spack install` dies copying its package repo;
///   5. the site's `spack_install` runs under `set -e` and never reaches `create_sh_env`;
///   6. `create_sh_env` writes `<build>/setting`, which the ICON runscript sources;
///   7. `ECCODES_DEFINITION_PATH` is therefore unset, and the model dies at RUNTIME with
///      `get_cdi_varID: Variable RAD_PRECIP not found!`
///
/// Incremental builds hid it entirely, because `setting` survived from an earlier build.
///
/// **husk cannot fix the cause.** Mapping the group is what an unprivileged userns is not
/// allowed to do, and the ACL frequently names a group the user is not even in, so mapping
/// every supplementary group would not help either. What husk can do is refuse to let this
/// be silent: say it at session start, seven steps before the symptom (`P13`).
///
/// Cheap by construction — one `getxattr` on the project directory. ACLs are inherited from
/// the directory, so the directory is the right place to look, and Lustre is never walked.
fn warn_on_unmappable_acl_groups(project_dir: &Path) {
    // POSIX ACL xattr layout: u32 version, then 8-byte entries of
    // { u16 tag, u16 perm, u32 id }. ACL_GROUP == 0x0008; an unmapped id reads as u32::MAX.
    const ACL_GROUP: u16 = 0x0008;
    let Ok(cpath) = CString::new(project_dir.as_os_str().as_bytes()) else { return };
    let Ok(name) = CString::new("system.posix_acl_access") else { return };
    let mut buf = [0u8; 1024];
    // SAFETY: both pointers are valid NUL-terminated C strings, and the length matches buf.
    let n = unsafe {
        getxattr(
            cpath.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
        )
    };
    // No ACL, or one bigger than any real ACL: nothing to say. Absence is the normal case.
    if n < 4 || n as usize > buf.len() {
        return;
    }
    let mut unmapped = 0usize;
    let mut i = 4usize; // skip the version word
    while i + 8 <= n as usize {
        let tag = u16::from_ne_bytes([buf[i], buf[i + 1]]);
        let id = u32::from_ne_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]);
        if tag == ACL_GROUP && id == u32::MAX {
            unmapped += 1;
        }
        i += 8;
    }
    if unmapped == 0 {
        return;
    }
    eprintln!(
        "husk-slurm-wrapper: WARNING: {} carries a POSIX ACL naming a group this sandbox \
         cannot map (it shows as group 4294967295).",
        project_dir.display()
    );
    eprintln!(
        "husk: an unprivileged sandbox maps exactly one group, so husk cannot fix this and \
         neither can you from inside."
    );
    eprintln!(
        "husk: what it breaks: anything that COPIES a file's ACL fails with EINVAL — \
         Python's shutil.copystat and copytree, `setfacl`, and therefore `spack install`, \
         which dies copying its package repo."
    );
    eprintln!(
        "husk: the symptom appears far away. A spack build under `set -e` stops before its \
         final step, an environment file is never written, and the model fails at RUNTIME \
         with a missing variable. Suspect this FIRST if a from-scratch build behaves \
         differently from an incremental one."
    );
    eprintln!(
        "husk: workarounds: run the build's final env-generation step by hand, or copy with \
         `cp` / `shutil.copy` (contents only) rather than `copy2` / `copystat`."
    );
}

fn enter_user_mount_ns() -> io::Result<()> {
    // SAFETY: pure getters.
    let (uid, gid) = unsafe { (getuid(), getgid()) };
    sys_unshare(CLONE_NEWUSER | CLONE_NEWNS)?;
    // setgroups must be denied before writing gid_map in an unprivileged userns.
    fs::write("/proc/self/setgroups", "deny")?;
    fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n"))?;
    fs::write("/proc/self/gid_map", format!("{gid} {gid} 1\n"))?;
    Ok(())
}

/// Replace this process with the agent. Requires proof the sandbox is ready, and
/// takes ownership of the broker so the failure path tears it down.
///
/// `_broker` is never named in the body on purpose — it is held only for its
/// `Drop`: on a failed `exec` it is dropped here (killing the orphan broker); on
/// a successful `exec` the image is replaced, so `Drop` never runs and the broker
/// keeps serving. (A bare `_` would drop it immediately — wrong; the name binding
/// keeps it alive to end of scope.)
fn exec_agent(
    _ready: SandboxReady,
    _broker: BrokerReady,
    _intact: SettingsIntact,
    agent: &[String],
    spool: &Path,
) -> io::Result<Infallible> {
    let mut cmd = Command::new(&agent[0]);
    cmd.args(&agent[1..]);
    cmd.env("HUSK_SLURM_SPOOL", spool);
    if let Some(log) = std::env::var_os("HUSK_SESSION_LOG") {
        cmd.env("HUSK_SESSION_LOG", log);
    }
    // `exec` only returns on failure; on success the image is replaced and
    // `_broker` is "leaked" into the new image (it keeps running). On failure we
    // return Err and `_broker` drops here -> killed. Fail-closed either way.
    let err = cmd.exec();
    Err(io::Error::new(err.kind(), format!("failed to exec agent '{}': {err}", agent[0])))
}

/// No-SLURM path: just become the agent. NO broker, NO spool, NO bind, no
/// `HUSK_SLURM_SPOOL` — zero trace of any SLURM interaction. The agent runs in
/// the normal sandbox, and with no broker there is no sanctioned bridge to a
/// scheduler, so it cannot submit jobs even if an `sbatch` is hidden here.
fn exec_plain(_intact: SettingsIntact, agent: &[String]) -> io::Result<Infallible> {
    let mut cmd = Command::new(&agent[0]);
    cmd.args(&agent[1..]);
    let err = cmd.exec();
    Err(io::Error::new(err.kind(), format!("failed to exec agent '{}': {err}", agent[0])))
}

/// What `run` should do, decided PURELY from config — no I/O, no side effects — so
/// the fail-closed decision is unit-testable. Brokering is a capability added only
/// on positive SLURM detection.
enum Plan<'a> {
    /// No SLURM here — just become the agent (no broker, no spool, no trace).
    Plain,
    /// SLURM present and all pieces resolved — broker.
    Broker { stub: &'a Path, broker: &'a Path, sbatch: &'a Path },
}

fn plan(cfg: &Config) -> io::Result<Plan<'_>> {
    let sbatch = match &cfg.sbatch {
        None => return Ok(Plan::Plain), // no SLURM -> the safe default
        Some(p) => p.as_path(),
    };
    // SLURM present: the pieces are required. Missing one is a FAIL-CLOSED error —
    // we do not run an unbrokered (if still sandboxed) session on a real cluster
    // just because a path was forgotten.
    let stub = cfg
        .stub
        .as_deref()
        .ok_or_else(|| usage("SLURM detected (sbatch present) but no --stub was provided"))?;
    let broker = cfg
        .broker
        .as_deref()
        .ok_or_else(|| usage("SLURM detected (sbatch present) but no --broker was provided"))?;
    Ok(Plan::Broker { stub, broker, sbatch })
}

/// Bind the stub over each read-only SLURM command present on PATH. Best-effort:
/// an absent command is skipped; a failed bind is logged, not fatal. Unlike the
/// sbatch shadow, a missed read-shadow can't become an escape — the real command
/// fails inside the sandbox and is read-only regardless.
fn shadow_readonly_commands(stub: &Path) {
    for cmd in READONLY_SLURM.iter().chain(BROKERED_MUTATING) {
        if let Some(target) = which(cmd) {
            match bind_file(stub, &target) {
                Ok(()) => eprintln!("husk-slurm-wrapper: {cmd} <- stub (read-only query)"),
                Err(e) => eprintln!(
                    "husk-slurm-wrapper: could not shadow '{cmd}' ({e}) — the agent's \
                     '{cmd}' will not work (not an escape)"
                ),
            }
        }
    }
}

/// Does this settings text carry a `"sandbox"` KEY?
///
/// Two scans, OR-ed, and both halves earn their place:
///
///   1. `raw_sandbox_key` — the original scan for the literal bytes `"sandbox"` followed by a
///      colon. Coarse on purpose, and kept as a FLOOR: it is nine lines, so however wrong (2)
///      gets, this control can never refuse LESS than the version that shipped.
///   2. `decoded_sandbox_key` — the same question asked of the DECODED string tokens.
///
/// (2) exists because (1)'s coarseness was NOT one-sided, which is what its comment claimed
/// (`B5-3`). JSON string escapes are not a style a writer picks, they are part of the format
/// the consumer parses: `{"sandbox": {"enabled": false}}` is the key `sandbox` to
/// `JSON.parse` — measured, and `json.loads` agrees — while the byte scan saw an unrelated key
/// and let the launch through with the cage fully disabled.
///
/// Still not a JSON parse — this binary links no external crates (see the module header) — but
/// it is not a list of evasions either (`P5`): it decodes the string production of the grammar,
/// which is the whole class rather than the one member that was demonstrated.
fn mentions_sandbox_key(text: &str) -> bool {
    raw_sandbox_key(text) || decoded_sandbox_key(text)
}

/// The literal bytes `"sandbox"` used as a key. Superset of the truth by design: a file that
/// merely mentions the word inside a string value trips it, and refusing a launch is the safe
/// direction, with a remedy the message states correctly either way.
fn raw_sandbox_key(text: &str) -> bool {
    let bytes = text.as_bytes();
    let needle = b"\"sandbox\"";
    let mut from = 0usize;
    while from + needle.len() <= bytes.len() {
        let rel = match bytes[from..].windows(needle.len()).position(|w| w == needle) {
            Some(r) => r,
            None => return false,
        };
        if colon_follows(bytes, from + rel + needle.len()) {
            return true;
        }
        from = from + rel + needle.len();
    }
    false
}

/// A `"sandbox"` key that survives DECODING — the same string `JSON.parse` would hand the
/// runtime, whatever escapes it was spelled with.
///
/// Walks string tokens, decodes each into a buffer one byte longer than the needle (so the scan
/// stays allocation-free and anything longer is rejected without being stored), and treats it as
/// a key when the next non-space character after the closing quote is a colon — which in
/// well-formed JSON only a key can be.
///
/// **ONE LEFT-TO-RIGHT PASS, and that is a correctness property, not a style note.** Every byte
/// is walked at most once: a token walk starts at `i`, runs to `j`, and the scan resumes at `j`
/// (or at `j + 1` past a closing quote), never inside the span just walked. `j > i` on every
/// exit — `j` starts at `i + 1` and only increases — so the scan strictly advances and the cost
/// is O(bytes).
///
/// The first version of this function resumed a failed token at `i + 1` instead, after the inner
/// loop had already walked to the failure. That is quadratic, and the input that shows it is not
/// exotic: `{"a": "` then `\"` repeated. Measured, same 640 KB file, 0.30 ms before the decoder
/// existed and **40.4 s** with it — and `SettingsIntact::establish()` is the first statement in
/// `run()`, so a few MB in a cloned repository's `.claude/settings.local.json` was a hang before
/// husk's first line of output. `no_settings_file_can_make_the_preflight_hang` pins it.
///
/// Deliberately NOT a validator, and the resume point is where that costs something. A token
/// this cannot decode is abandoned, and the token boundaries after it may be misaligned with the
/// ones a parser would find. Every abandon condition — an unterminated string, an undefined
/// escape, a truncated `\uXXXX` — is a JSON syntax error, so `JSON.parse` rejects the whole file
/// and the runtime loads no override from it either; and `raw_sandbox_key` still runs over the
/// same bytes. That is the argument for scanning less after a malformed token rather than more.
fn decoded_sandbox_key(text: &str) -> bool {
    const NEEDLE: &[u8] = b"sandbox";
    let b = text.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] != b'"' {
            i += 1;
            continue;
        }
        let mut buf = [0u8; NEEDLE.len() + 1];
        let mut n = 0usize;
        let mut j = i + 1;
        // `Ok(after)` = the index just past the closing quote; `Err(at)` = a token that cannot
        // be decoded, and the index the scan must resume at so no byte is walked twice.
        let end: Result<usize, usize> = loop {
            let Some(&c) = b.get(j) else { break Err(j) }; // unterminated string; j == b.len()
            let (byte, next) = match c {
                b'"' => break Ok(j + 1),
                b'\\' => match b.get(j + 1) {
                    Some(b'"') => (b'"', j + 2),
                    Some(b'\\') => (b'\\', j + 2),
                    Some(b'/') => (b'/', j + 2),
                    Some(b'b') => (0x08, j + 2),
                    Some(b'f') => (0x0c, j + 2),
                    Some(b'n') => (b'\n', j + 2),
                    Some(b'r') => (b'\r', j + 2),
                    Some(b't') => (b'\t', j + 2),
                    // Only the ASCII range can be part of an ASCII needle; everything else
                    // (including either half of a surrogate pair) folds to one non-ASCII byte,
                    // which simply cannot match.
                    Some(b'u') => match hex4(b, j + 2) {
                        Some(cp) => (if cp < 0x80 { cp as u8 } else { 0xff }, j + 6),
                        None => break Err(j),
                    },
                    _ => break Err(j), // not an escape JSON defines
                },
                other => (other, j + 1),
            };
            if n < buf.len() {
                buf[n] = byte;
            }
            n += 1;
            j = next;
        };
        match end {
            Ok(after) if n == NEEDLE.len() && buf[..n] == *NEEDLE && colon_follows(b, after) => {
                return true
            }
            Ok(after) => i = after,
            Err(resume) => i = resume,
        }
    }
    false
}

/// The value of a `\uXXXX` escape whose four hex digits start at `at`.
fn hex4(b: &[u8], at: usize) -> Option<u32> {
    let mut v = 0u32;
    for k in 0..4 {
        let d = *b.get(at + k)?;
        let digit = match d {
            b'0'..=b'9' => d - b'0',
            b'a'..=b'f' => d - b'a' + 10,
            b'A'..=b'F' => d - b'A' + 10,
            _ => return None,
        };
        v = v * 16 + u32::from(digit);
    }
    Some(v)
}

/// Is the next non-space byte at or after `at` a `:`? (i.e. was the string just closed a KEY)
fn colon_follows(b: &[u8], mut at: usize) -> bool {
    while at < b.len() && b[at].is_ascii_whitespace() {
        at += 1;
    }
    at < b.len() && b[at] == b':'
}

/// The settings files that can OVERRIDE husk's sandbox block, in the order reported.
///
/// NOT `~/.claude/settings.json` — that is husk's own layer and is supposed to carry a
/// sandbox block. The project-level files are included because the same slot is where a
/// cloned repository would ship a hostile value.
/// The CANONICAL git root at or above `from` — the directory the runtime anchors
/// `localSettings` on.
///
/// Two stages, because the runtime does two stages: walk up to the first `.git`, then
/// FOLLOW it. In a linked worktree `.git` is a FILE containing `gitdir: <main>/.git/
/// worktrees/<name>`, and the runtime resolves that back to the MAIN repository — so the
/// settings file it loads is `<main>/.claude/settings.local.json`, not the worktree's.
///
/// The first version of this stopped at the `.git` file and returned the WORKTREE, with a
/// comment claiming that was the point of accepting a file. Backwards: catching the file
/// and stopping is exactly what yields the wrong directory. A reviewer demonstrated the
/// bypass on husk's own repo — strace showed the shipped binary reading the main repo's
/// settings while husk's walk reported nothing to check, so the cage launched disabled.
/// P15: the control named a target, and the name resolved to the wrong object.
///
/// A submodule's `.git` file points INTO the superproject but the runtime anchors on the
/// submodule directory itself, which is where the plain walk already lands — so following
/// the link must not change that answer. Hence: follow only when the link resolves to a
/// `worktrees/` entry, which is the case that diverges.
fn git_root(from: &Path) -> Option<PathBuf> {
    let mut d = std::fs::canonicalize(from).ok()?;
    loop {
        let dot = d.join(".git");
        if dot.is_dir() {
            return Some(d); // ordinary checkout: this is the root
        }
        if dot.is_file() {
            return Some(main_worktree_root(&dot).unwrap_or(d));
        }
        if !d.pop() {
            return None;
        }
    }
}

/// Resolve a `.git` FILE to the main worktree's root, if it is a linked worktree.
///
/// `gitdir: /main/.git/worktrees/name` -> `/main`. Returns `None` for anything else (a
/// submodule, an unparseable file), so the caller keeps the directory the walk found.
fn main_worktree_root(dot_git_file: &Path) -> Option<PathBuf> {
    // THE SIBLING OF `RE-1`, in the same function chain and swept in the same pass rather
    // than named as future work. This was a bare `read_to_string`, and its caller's
    // Two things are reachable, and neither is the one it is tempting to write down: a
    // planted FIFO is filtered out by the caller's `dot.is_file()`, so it never gets here.
    // What does: an oversized REGULAR `.git` file, which `is_file()` waves through into an
    // unbounded read; and a `rename(2)` of a FIFO over `<workdir>/.git` between that check
    // and this read, because `is_file()` is a check on a NAME and the agent owns the workdir
    // (`P15`). This runs from `sandbox_override_files`, i.e. the first statement of `run()`,
    // before husk has printed anything.
    //
    // Every non-`Bytes` disposition maps to `None`, which is this function's existing
    // fail-safe answer ("keep the directory the walk found"), so bounding it adds NO refusal
    // and cannot deny a launch. A `.git` link file is one line; a megabyte is absurd for it
    // and is merely the bound that was already to hand.
    let SettingsLayer::Bytes(raw) = read_settings_layer(dot_git_file) else {
        return None;
    };
    let text = String::from_utf8(raw).ok()?;
    let target = text.lines().find_map(|l| l.strip_prefix("gitdir:"))?.trim();
    let mut p = PathBuf::from(target);
    if p.is_relative() {
        p = dot_git_file.parent()?.join(p);
    }
    // .../<main>/.git/worktrees/<name>  ->  climb to the `.git` component, take its parent.
    let mut cur = p.as_path();
    while let Some(parent) = cur.parent() {
        if cur.file_name().is_some_and(|n| n == ".git") {
            return std::fs::canonicalize(parent).ok();
        }
        cur = parent;
    }
    None
}

/// One settings layer husk refuses, and WHY it refuses that one.
///
/// The reason is CARRIED rather than re-derived when the message is built. There are now two
/// ways for a layer to be refused, and a message that re-opened the file to work out which
/// would read adversary-controlled input a second time and could answer differently than the
/// decision did. One input, one disposition, decided once.
#[derive(Debug)]
struct Override {
    path: PathBuf,
    why: Why,
}

#[derive(Debug)]
enum Why {
    /// The layer carries a `"sandbox"` key — raw, or spelled with `\uXXXX` escapes.
    SandboxKey,
    /// husk could not scan it. NOT the same sentence as "it holds no override" (`P7`), so it
    /// is not the same disposition either.
    TooLargeToScan,
    /// A FIFO, a directory or a device where a settings layer should be. Same conclusion as
    /// `TooLargeToScan` — husk did not scan it and cannot rule the key out — but a different
    /// remedy, so a different line (`P11`). Before `RE-1` this was not a disposition at all:
    /// `File::open` on a FIFO blocks until a writer appears, and this function is reached
    /// from the FIRST statement of `run()`, so `mkfifo .claude/settings.local.json` inside
    /// one session made every later `husk` in that directory produce NOTHING, forever.
    /// Measured on the release wrapper at `608618e`: 15 s, no output, killed.
    NotAFile,
}

// `MAX_SETTINGS_BYTES` now lives in the lib, beside `read_settings_layer`, because the broker
// reads the same three files and had no bound at all (`RE-1`). The reasoning that produced the
// number — `RC-1`, `RC-2` and the 802 MB measurement this binary was the first to pay — moved
// with it. One number, one reader, two binaries (`P8`).
//
// `RC-1` offered two remedies for this preflight's cost and only the first (a linear decoder)
// was taken. This is the second, and it also covers a cost the OTHER `RC` fix added:
// `from_utf8_lossy` emits three bytes per invalid byte, so a file that is not valid UTF-8
// costs `len + 3*invalid`. It IS a refusal and not a skip: a layer husk could not read is a
// layer that may hold `"enabled": false`, and skipping it is the exact fail-open arm `RC-2`
// closed.

fn sandbox_override_files(home: &Path, cwd: &Path) -> Vec<Override> {
    let mut v = vec![
        home.join(".claude/settings.local.json"),
        cwd.join(".claude/settings.local.json"),
        cwd.join(".claude/settings.json"),
    ];
    // THE ONE THIS CONTROL EXISTED TO CATCH, AND MISSED BY ONE DIRECTORY. The runtime anchors
    // `localSettings` on the CANONICAL GIT ROOT, not on the cwd — so launching husk anywhere
    // below a repository root loads `<gitroot>/.claude/settings.local.json`, which this
    // function never looked at. A repo could carry the exact file the check refuses, and husk
    // would start. Found by a synergizer pass reading the shipped 2.1.246 binary; the first
    // version of this list was three paths guessed from the docs, which is a denylist (P5).
    if let Some(root) = git_root(cwd) {
        let at_root = root.join(".claude/settings.local.json");
        if !v.contains(&at_root) {
            v.push(at_root);
        }
    }
    v.into_iter()
        // READ THE BYTES THE RUNTIME READS, not a stricter subset of them (`RC-2`). This was
        // `read_to_string`, which fails on any file that is not valid UTF-8 — and the `Err`
        // arm below resolves to "no override", so **two non-UTF-8 bytes anywhere in the file
        // launched husk** while `node` read `sandbox.enabled = false` out of the same bytes.
        // Measured: `readFileSync(f, "utf8")` decodes leniently, replacing each malformed
        // sequence with U+FFFD, and `JSON.parse` then reports the keys as normal. So does
        // `from_utf8_lossy`, byte for byte — husk's reader and the runtime's reader now
        // disagree about nothing, which is the class `B5-3` is an instance of.
        //
        // The `Err` arm stays "no override", and after this change that is a statement about
        // the runtime rather than a hope: every error `fs::read` can still return here —
        // absent, EACCES, EISDIR, EIO — is one `readFileSync` returns too, and a settings
        // layer the runtime cannot read is a layer that overrides nothing. It is said out
        // loud rather than assumed (`P7`), because "husk saw no override" and "husk could not
        // look" are not the same sentence to an operator.
        .filter_map(|f| {
            // AT MOST one byte past the cap, and the file TYPE decided on the descriptor
            // rather than on the name — both in `read_settings_layer`, which the broker's
            // policy reader and its network allowlist now share. The size half was already
            // here; the type half was not, and its absence was a hang before husk's first
            // line of output (`RE-1`, and see `Why::NotAFile`).
            match read_settings_layer(&f) {
                SettingsLayer::TooLarge(_) => Some(Override { path: f, why: Why::TooLargeToScan }),
                SettingsLayer::NotARegularFile => Some(Override { path: f, why: Why::NotAFile }),
                SettingsLayer::Bytes(buf) => mentions_sandbox_key(&String::from_utf8_lossy(&buf))
                    .then_some(Override { path: f, why: Why::SandboxKey }),
                SettingsLayer::Absent => None,
                SettingsLayer::Unreadable(e) => {
                    eprintln!(
                        "husk-slurm-wrapper: {} exists but could not be read ({e}) — the agent \
                         runtime cannot read it either, so it overrides nothing; not treating it \
                         as a sandbox override.",
                        f.display()
                    );
                    None
                }
            }
        })
        .collect()
}

/// The refusal text, built separately from the I/O so the properties that make a denial
/// USABLE (P11) are unit-testable: name husk, name the file, say what would be lost, and
/// read as standing policy rather than an outage.
///
/// Kept SHORT on purpose. The first version ran ~18 lines and was cut in half after it
/// fired in real use: a refusal nobody finishes reading teaches nothing, and the operator
/// only needs what was found, what it costs, and what to do.
fn override_message(hits: &[Override]) -> String {
    let mut m = String::from(
        "husk: refusing to launch — a settings file overrides husk's sandbox block.\n\n",
    );
    for f in hits {
        // One line per layer, and the line says which of the two dispositions this is. Kept to
        // one line each so the message cannot grow past the dozen `the_refusal_stays_short`
        // pins, and so the remedy below covers both.
        m.push_str(&match f.why {
            Why::SandboxKey => format!("  {}  contains a \"sandbox\" block\n", f.path.display()),
            Why::TooLargeToScan => format!(
                "  {}  is over {MAX_SETTINGS_BYTES} bytes — too large to be a settings file, so \
                 husk did not scan it and cannot rule the key out\n",
                f.path.display()
            ),
            Why::NotAFile => format!(
                "  {}  is not a regular file (a FIFO, a directory or a device), so husk did \
                 not read it and cannot rule the key out — delete it\n",
                f.path.display()
            ),
        });
    }
    m.push_str(
        "
That layer outranks husk's, so the keys it sets win — and `\"enabled\": false` there switches
the cage off entirely: no ~/.claude credential masks (the OAuth token), no strict egress
allowlist, while the session still looks sandboxed. Nothing is wrong with the cluster or
your account — husk refuses until the override is gone.

Fix: remove the \"sandbox\" key from the file(s) above, or delete the file if that is all it
holds. A /sandbox toggle in an earlier session writes exactly this.
",
    );
    m
}

fn run() -> io::Result<Infallible> {
    let cfg = Config::parse()?;
    // Before the spool, the broker and the namespaces: a refusal has nothing to unwind.
    let intact = SettingsIntact::establish()?;
    match plan(&cfg)? {
        Plan::Plain => {
            eprintln!(
                "husk-slurm-wrapper: no SLURM (sbatch) on PATH — launching \
                 husk without job brokering."
            );
            exec_plain(intact, &cfg.agent)
        }
        Plan::Broker { stub, broker, sbatch } => {
            // Validate the pieces exist + are executable before touching namespaces.
            require_executable(stub, "stub")?;
            require_executable(broker, "broker")?;
            require_executable(sbatch, "sbatch target")?;

            fs::create_dir_all(&cfg.spool).map_err(|e| {
                io::Error::new(e.kind(), format!("cannot create spool '{}': {e}", cfg.spool.display()))
            })?;
            std::env::set_var("HUSK_SLURM_SPOOL", &cfg.spool);

            // Published into the agent's environment so a session that hits a husk denial
            // has somewhere to look. The agent can READ this file and not write it, which
            // is the whole reason it is not in the spool.
            let session_log = resolve_session_log(&cfg.spool);
            std::env::set_var("HUSK_SESSION_LOG", &session_log);

            // Broker first, in the clean outer namespaces (keeps MUNGE + network).
            // Seven steps before the symptom. See the function.
            warn_on_unmappable_acl_groups(&std::env::current_dir().unwrap_or_default());

            // N6-F1's pre-seeding of the login auto-exec masks USED TO BE HERE. It was removed
            // on 2026-08-27 because it protected nothing and cost something.
            //
            // Its premise was "an absent deny path cannot be bound, so make it present and the
            // vendor will bind it read-only". MEASURED on Balfrin in a directory that started
            // empty: the three files are created, `/proc/self/mountinfo` carries ZERO binds for
            // them, and all three are WRITABLE. The premise is false in both branches.
            //
            // Why it cannot work, from the shipped 2.1.246 binary: a relative filesystem path is
            // resolved against the DECLARING SOURCE's base dir. husk's `denyWrite` lives in
            // `~/.claude/settings.json`, so `.Rprofile` means `$HOME/.Rprofile` — making the
            // PROJECT's file present can never satisfy a deny aimed at the home. The runtime's
            // own DANGEROUS_FILES list is what actually masks `.bashrc`, `.gitconfig` and the
            // rest beside them, which is why those ARE protected and husk's three are not.
            //
            // The cost was real: an empty `.Rprofile`/`.Renviron` in every project directory
            // (shadowing `~/.Renviron`, where `R_LIBS_USER` lives), plus an `.hg/` directory that
            // makes any directory a Mercurial repo root by hg's own test. husk fabricated the
            // auto-exec surfaces it was trying to mask.
            //
            // W1-1 is therefore OPEN and shipped as a named residual (decision A2): the real fix
            // is 6a, where husk owns the login mount plan and never binds these writable at all.
            // `husk-verify.sh` reports it every run so it stays visible rather than assumed-handled.

            let broker_handle = spawn_broker(broker, &cfg.spool, &session_log)?;
            // Spawning proves only that execve worked. Wait for the broker to CLAIM its
            // spool before anything depends on it — see BrokerReady.
            let serving = BrokerReady::establish(broker_handle, &session_log)?;

            // Now shrink OUR world and swap sbatch for the stub.
            enter_user_mount_ns()?;
            let ready = SandboxReady::establish(stub, sbatch)?;
            // Best-effort: also shadow the Tier-1 read-only query commands. NOT
            // fail-closed — see shadow_readonly_commands.
            shadow_readonly_commands(stub);

            eprintln!(
                "husk-slurm-wrapper: SLURM detected; spool={} log={} sbatch<-stub OK; \
                 agent skill: ~/.claude/skills/husk/; launching {}",
                cfg.spool.display(),
                session_log.display(),
                cfg.agent.join(" ")
            );
            exec_agent(ready, serving, intact, &cfg.agent, &cfg.spool)
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(_never) => ExitCode::SUCCESS, // unreachable: exec replaces us on success
        Err(e) => {
            // A control that already printed its own full refusal marks the error
            // `PermissionDenied` (today only `SettingsIntact`). Re-summarising it here
            // just repeats the header the operator has already read — that duplication
            // is exactly the verbosity that got the first version cut in half.
            if e.kind() != io::ErrorKind::PermissionDenied {
                eprintln!("husk-slurm-wrapper: {e}");
            }
            eprintln!("husk-slurm-wrapper: refusing to launch the agent (fail-closed).");
            ExitCode::FAILURE
        }
    }
}

fn usage(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

fn print_help() {
    let _ = writeln!(
        io::stdout(),
        "husk-slurm-wrapper — fail-closed outer wrapper for the SLURM broker\n\
\n\
USAGE: husk-slurm-wrapper --stub PATH --broker PATH [--spool DIR]\n\
                            [--sbatch-path PATH] [-- AGENT_CMD...]\n\
\n\
  --stub PATH       in-sandbox sbatch stub to bind over the real sbatch (required)\n\
  --broker PATH     trusted broker binary to launch outside the sandbox (required)\n\
  --spool DIR       spool dir (default: $HUSK_SLURM_SPOOL or\n\
                    ./.husk-slurm-spool-<pid>, removed when the session ends)\n\
  --sbatch-path P   sbatch to shadow (default: first `sbatch` on PATH)\n\
  -- AGENT_CMD...   command to exec after setup (default: husk)\n"
    );
}

#[cfg(test)]
mod tests {

    use super::{mentions_sandbox_key, override_message, raw_sandbox_key, sandbox_override_files};

    /// A refusal for the ordinary reason, for the message tests. (`Override` and `Why` reach
    /// here through the `use super::*;` further down.)
    fn keyed(p: &str) -> Override {
        Override { path: std::path::PathBuf::from(p), why: Why::SandboxKey }
    }

    // ---- the refusal MESSAGE is part of the control (P11) ---------------------------
    //
    // These assertions existed for the shell version and were lost when the check moved
    // to Rust; restored here. A denial that does not say who refused, what it costs, or
    // what to do sends the operator to a sysadmin — or, worse, to disabling husk.

    #[test]
    fn the_refusal_says_who_what_and_how_to_fix_it() {
        let m = override_message(&[keyed("/tmp/proj/.claude/settings.local.json")]);
        assert!(m.contains("husk"), "must name husk, not fail anonymously");
        assert!(m.contains("/tmp/proj/.claude/settings.local.json"), "must name the file to fix");
        assert!(m.contains("token") || m.contains("credential"),
            "must teach the CONSEQUENCE, or the operator 'fixes' it by disabling husk");
        assert!(m.contains("Nothing is wrong with the cluster"),
            "must read as authorization, not an outage (P11)");
        assert!(m.contains("remove the \"sandbox\" key"), "must state the remedy");
    }

    #[test]
    fn the_refusal_is_identical_on_retry() {
        // A denial that varies reads as flakiness; an identical one reads as policy.
        let hits = vec![keyed("/x/.claude/settings.local.json")];
        assert_eq!(override_message(&hits), override_message(&hits));
    }

    #[test]
    fn the_refusal_stays_short() {
        // It ran ~18 lines and was cut after firing in real use ("too verbose, should be
        // half as long"). This pins it: a message nobody finishes reading teaches nothing.
        let m = override_message(&[keyed("/x/.claude/settings.local.json")]);
        let lines = m.lines().count();
        assert!(lines <= 12, "refusal grew back to {lines} lines; keep it under a dozen:\n{m}");

        // ...and the second disposition must not be the thing that grows it back.
        let big = override_message(&[Override {
            path: std::path::PathBuf::from("/x/.claude/settings.local.json"),
            why: Why::TooLargeToScan,
        }]);
        assert!(
            big.lines().count() <= 12,
            "the too-large refusal is {} lines:\n{big}",
            big.lines().count()
        );
    }

    #[test]
    fn the_refusal_lists_every_offending_file() {
        let m = override_message(&[
            keyed("/a/.claude/settings.local.json"),
            Override {
                path: std::path::PathBuf::from("/b/.claude/settings.json"),
                why: Why::TooLargeToScan,
            },
        ]);
        assert!(m.contains("/a/.claude/settings.local.json"));
        assert!(m.contains("/b/.claude/settings.json"));
        // The two dispositions must not print the same sentence: "it has a sandbox block" and
        // "husk could not look" send the operator to different remedies (`P7`, `P11`).
        assert!(m.contains("contains a \"sandbox\" block"), "{m}");
        assert!(m.contains("too large to be a settings file"), "{m}");
    }


    // ---- the sandbox-override preflight (P6 witness: SettingsIntact) ----------------
    //
    // The failure mode guarded here is a check that is too EAGER (blocking husk's own
    // user-level settings, which are SUPPOSED to carry a sandbox block) or too LAX
    // (missing the project-level file, where a cloned repo can ship the same key).

    #[test]
    fn a_sandbox_key_is_recognised_but_a_sandbox_value_is_not() {
        assert!(mentions_sandbox_key(r#"{"sandbox": {"enabled": false}}"#));
        assert!(mentions_sandbox_key("{\"sandbox\"  :  {}}"), "whitespace before the colon is still a key");
        assert!(mentions_sandbox_key("{\n  \"sandbox\"\n  : {}\n}"), "a newline before the colon is still a key");
        // A string VALUE that happens to be the word must not trip it: the next
        // non-space character is not a colon.
        assert!(!mentions_sandbox_key(r#"{"note": "sandbox"}"#));
        assert!(!mentions_sandbox_key(r#"{"sandboxed": true}"#), "a different key must not match");
        assert!(!mentions_sandbox_key(r#"{"not_sandbox": true}"#), "a suffix match must not count");
        assert!(!mentions_sandbox_key("{}"));
        assert!(!mentions_sandbox_key(""));
    }

    // ---- B5-3: the needle must see what the PARSER sees, not what the bytes look like --
    //
    // The old scan's defence was that its coarseness was one-sided — "a file that merely
    // mentions the word in a string value would trip it, and refusing a launch is the safe
    // direction". It was not one-sided. JSON string escapes are part of the format the runtime
    // parses, not a style a writer chooses, so a settings file carrying a fully effective
    // sandbox-off block sailed past a fail-closed witness.
    //
    // Every POSITIVE below is the key `sandbox` to a conforming parser (checked against
    // `json.loads`). Every NEGATIVE is a file a real user has, and refusing those would be its
    // own failure — an operator whose husk will not start "fixes" it by uninstalling husk.
    #[test]
    fn an_escaped_sandbox_key_is_still_the_sandbox_key() {
        // --- the bypass, exactly as measured ----------------------------------------
        assert!(
            mentions_sandbox_key(r#"{"\u0073andbox": {"enabled": false}}"#),
            "one escaped byte turned the whole cage off and husk reported nothing"
        );
        assert!(mentions_sandbox_key(
            r#"{"\u0073\u0061\u006e\u0064\u0062\u006f\u0078": {"enabled": false}}"#
        ));
        assert!(mentions_sandbox_key(r#"{"sandbo\u0078": {}}"#), "the LAST byte escapes too");
        assert!(mentions_sandbox_key(r#"{"sa\u006Edbox": {}}"#), "uppercase hex digits count");
        assert!(
            mentions_sandbox_key("{\"\\u0073andbox\"\n  :  {}}"),
            "escaping and whitespace before the colon compose"
        );
        assert!(
            mentions_sandbox_key(r#"{"permissions": {"allow": []}, "\u0073andbox": {}}"#),
            "it need not be the first key"
        );

        // --- files that must still launch -------------------------------------------
        assert!(!mentions_sandbox_key(
            r#"{"model": "opus[1m]", "permissions": {"allow": ["Bash(ls:*)"], "deny": []}}"#
        ));
        assert!(
            !mentions_sandbox_key(r#"{"\u0073andboxed": true}"#),
            "decodes to `sandboxed`, a different key"
        );
        assert!(
            !mentions_sandbox_key(r#"{"\u0053andbox": {}}"#),
            "decodes to `Sandbox`; JSON keys are case-sensitive and the schema's key is lowercase"
        );
        assert!(
            !mentions_sandbox_key(r#"{"note": "\u0073andbox"}"#),
            "a string VALUE is not a key, however it is spelled"
        );
        assert!(!mentions_sandbox_key(r#"{"env": {"PATH": "/opt/sandbox/bin:/usr/bin"}}"#));
        assert!(!mentions_sandbox_key(r#"{"hooks": {"Stop": [{"command": "echo done"}]}}"#));

        // --- malformed input: never panic, and never err toward LAUNCHING ------------
        // These are not valid JSON, so the runtime would not load them either; the contract
        // here is only that the scan terminates and does not go quiet.
        for junk in [
            r#"{"\u0073andbox"#,            // unterminated
            r#"{"a\q": 1, "sandbox": {}}"#, // undefined escape, then the real key
            r#"{"\u007": 1}"#,              // truncated \u
            r#"{"\ud83d\ude00": 1}"#,       // surrogate pair
            "\"\"\"\"\"\"\"\"\"\"",         // nothing but quotes
            "",
            "{}",
        ] {
            let _ = mentions_sandbox_key(junk);
        }
        assert!(
            mentions_sandbox_key(r#"{"a\q": 1, "sandbox": {}}"#),
            "an undefined escape earlier in the file must not hide a later plain key"
        );

        // --- the raw byte scan is a FLOOR, not a fallback ----------------------------
        // The invariant, asserted over every string this test uses rather than over three
        // hand-picked ones: `raw_sandbox_key(s)` IMPLIES `mentions_sandbox_key(s)`. However
        // wrong the decoder gets — including in the resume rule that made it linear — this
        // control can never refuse LESS than the version that shipped.
        let corpus = [
            r#"{"sandbox": {"enabled": false}}"#,
            r#"{"\u0073andbox": {"enabled": false}}"#,
            r#"{"permissions": {"sandbox": true}}"#, // nested: over-refusal, deliberately kept
            r#"{"model": "opus[1m]", "permissions": {"allow": ["Bash(ls:*)"]}}"#,
            r#"{"note": "\u0073andbox"}"#,
            r#"{"env": {"PATH": "/opt/sandbox/bin:/usr/bin"}}"#,
            r#"{"x": "he said \"sandbox\": no"}"#,
            r#"{"a\q": 1, "sandbox": {}}"#,
            r#"{"\u0073andbox"#,
            "{\"sandbox\"  :  {}}",
            "{}",
            "",
        ];
        for s in corpus {
            assert!(
                !raw_sandbox_key(s) || mentions_sandbox_key(s),
                "the union went NARROWER than the byte scan alone, which is the one thing it \
                 may not do: {s}"
            );
        }
        // ...and the floor is load-bearing, not vacuous: something in the corpus reaches it.
        assert!(corpus.iter().any(|s| raw_sandbox_key(s)), "the floor assertion tested nothing");
    }

    // ---- RC-1: the preflight's COST is part of the control ---------------------------
    //
    // `SettingsIntact::establish()` is the first statement in `run()`, so any input that makes
    // this scan slow is a hang before husk's first line of output — the failure shape
    // `BrokerReady`'s own doc comment calls the worst thing husk does to a human ("a command is
    // merely slow", nobody opens the log, hours go by). The first decoder written for `B5-3`
    // had exactly that: it abandoned a malformed token and resumed one byte later, after the
    // inner loop had already walked to the failure, which is O(n^2). Same 640 KB file: 0.30 ms
    // before, 40.4 s after.
    //
    // The bound is deliberately loose. This asserts LINEARITY, not a wall-clock budget, and it
    // has to stay green on a loaded machine and under a debug build. Measured on the real
    // function bodies, `-O`, same machine, the two resume rules on identical input:
    //
    //       input     resume at the END (this)    resume at i+1 (reverted)
    //       160 KB                     149 us                      2.71 s
    //       320 KB                     297 us                     10.67 s
    //       640 KB                     605 us                     43.40 s      <- 71,700x
    //      1280 KB                    1.20 ms                    171.46 s
    //
    // 4x the size is 4x the time on the left and 16x on the right. At the 256 KB used here the
    // gap is about three orders of magnitude, so five seconds cannot be reached by a slow
    // machine and cannot be missed by a quadratic one. A tight bound would be a flaky test,
    // which on this project is a test that gets deleted.
    #[test]
    fn no_settings_file_can_make_the_preflight_hang() {
        let mut adversarial = String::from(r#"{"a": ""#);
        adversarial.push_str(&r#"\""#.repeat(128 * 1024)); // 256 KB of escaped quotes
        adversarial.push_str(r#"\z"#); // ...then one byte that is not a JSON escape
        let started = std::time::Instant::now();
        let hit = mentions_sandbox_key(&adversarial);
        let elapsed = started.elapsed();
        assert!(!hit, "the adversarial input carries no sandbox key; it is a COST test");
        assert!(
            elapsed < Duration::from_secs(5),
            "the settings preflight took {elapsed:?} on {} bytes. It is the first statement in \
             run(), so this is not slowness, it is husk hanging with no output — check that the \
             decoder still resumes at the END of an abandoned token and not at i+1.",
            adversarial.len()
        );
    }

    fn write(p: &std::path::Path, body: &str) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    /// A scratch HOME + cwd pair; both are real directories so the reads are real.
    fn scratch(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let base = std::env::temp_dir().join(format!("husk-preflight-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        let cwd = base.join("work");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&cwd).unwrap();
        (home, cwd)
    }

    #[test]
    fn a_clean_home_and_project_do_not_block() {
        let (home, cwd) = scratch("clean");
        assert!(sandbox_override_files(&home, &cwd).is_empty());
    }

    #[test]
    fn husks_own_user_settings_must_not_block_itself() {
        // ~/.claude/settings.json is husk's OWN layer and carries the shipped sandbox
        // block. A preflight that flagged it would make husk unlaunchable.
        let (home, cwd) = scratch("own");
        write(&home.join(".claude/settings.json"),
              r#"{"sandbox": {"enabled": true, "filesystem": {"denyRead": ["/users"]}}}"#);
        assert!(sandbox_override_files(&home, &cwd).is_empty(),
            "husk's own settings.json must never be treated as an override");
    }

    #[test]
    fn a_local_file_without_a_sandbox_key_is_fine() {
        let (home, cwd) = scratch("perms");
        write(&cwd.join(".claude/settings.local.json"),
              r#"{"permissions": {"allow": ["Bash(ls *)"]}}"#);
        write(&home.join(".claude/settings.local.json"), r#"{"model": "opus"}"#);
        assert!(sandbox_override_files(&home, &cwd).is_empty());
    }

    #[test]
    fn the_sandbox_toggles_project_local_file_blocks() {
        // THE OBSERVED ARTIFACT: this exact JSON was found in the husk repo on
        // 2026-08-25, written by toggling /sandbox off earlier the same day.
        let (home, cwd) = scratch("toggle");
        write(&cwd.join(".claude/settings.local.json"),
              r#"{"sandbox": {"enabled": false, "autoAllowBashIfSandboxed": false}}"#);
        let hits = sandbox_override_files(&home, &cwd);
        assert_eq!(hits.len(), 1, "the toggle's artifact must block: {hits:?}");
    }

    #[test]
    fn a_user_level_local_override_blocks_even_when_it_enables_the_sandbox() {
        // `enabled: true` is not reassuring: the layer REPLACES husk's whole block, so a
        // cheerful-looking local file still drops the credential masks and the allowlist.
        let (home, cwd) = scratch("enabled");
        write(&home.join(".claude/settings.local.json"), r#"{"sandbox": {"enabled": true}}"#);
        assert_eq!(sandbox_override_files(&home, &cwd).len(), 1);
    }

    #[test]
    fn a_settings_local_at_the_GIT_ROOT_is_found_from_a_subdirectory() {
        // THE BYPASS OF THIS VERY CONTROL, found by a synergizer pass reading the shipped
        // 2.1.246 binary. The runtime anchors `localSettings` on the CANONICAL GIT ROOT, not
        // on the cwd. husk checked home + cwd, so launching anywhere BELOW a repository root
        // loaded a file husk never looked at — the control refusing exactly this file at one
        // path while starting happily on it at another, one directory up.
        //
        // The first version of that path list was guessed from the docs. P5: a denylist is a
        // bug list, and this is the bug.
        let (home, cwd) = scratch("gitroot");
        std::fs::create_dir_all(cwd.join(".git")).unwrap();          // cwd IS the repo root
        let sub = cwd.join("analysis/deep");
        std::fs::create_dir_all(&sub).unwrap();
        write(&cwd.join(".claude/settings.local.json"), r#"{"sandbox": {"enabled": false}}"#);

        let hits = sandbox_override_files(&home, &sub);
        assert_eq!(
            hits.len(),
            1,
            "a sandbox override at the GIT ROOT must be found when husk is launched in a \
             subdirectory — the runtime loads it, so husk must see it: {hits:?}"
        );
        assert!(hits[0].path.ends_with(".claude/settings.local.json"), "{hits:?}");
    }

    #[test]
    fn a_linked_worktree_resolves_to_the_MAIN_repo_settings() {
        // THE BYPASS THAT SURVIVED THE FIRST FIX, demonstrated by a reviewer on husk's own
        // repo with strace: the runtime follows a worktree's `.git` FILE back to the main
        // repository and loads ITS settings, while husk stopped at the file and reported
        // the worktree — so the cage launched with `enabled:false` in force and husk said
        // nothing. Mutation (b) — exists() vs is_dir() — was NOT caught before, because the
        // only test built a `.git` DIRECTORY and never a file.
        let (home, base) = scratch("worktree");
        let main = base.join("mainrepo");
        std::fs::create_dir_all(main.join(".git/worktrees/wt")).unwrap();
        write(&main.join(".claude/settings.local.json"), r#"{"sandbox": {"enabled": false}}"#);

        let wt = base.join("linked");
        std::fs::create_dir_all(wt.join("sub")).unwrap();
        std::fs::write(
            wt.join(".git"),
            format!("gitdir: {}/.git/worktrees/wt\n", main.display()),
        )
        .unwrap();

        let hits = sandbox_override_files(&home, &wt.join("sub"));
        assert_eq!(
            hits.len(),
            1,
            "a worktree's .git FILE must resolve to the MAIN repo, whose settings the runtime \
             actually loads — stopping at the file checks a directory that has none: {hits:?}"
        );
        assert!(hits[0].path.starts_with(&main), "must be the MAIN repo's file: {hits:?}");
    }

    #[test]
    fn a_submodule_anchors_on_itself_not_the_superproject() {
        // A submodule's `.git` is also a FILE, but the runtime anchors on the submodule
        // DIRECTORY — so following the link must NOT change that answer. Pinning it because
        // the worktree fix is exactly the kind of change that would over-correct here.
        let (home, base) = scratch("submodule");
        let sup = base.join("super");
        std::fs::create_dir_all(sup.join(".git/modules/sub")).unwrap();
        write(&sup.join(".claude/settings.local.json"), r#"{"sandbox": {"enabled": false}}"#);
        let sub = sup.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join(".git"), format!("gitdir: {}/.git/modules/sub\n", sup.display()))
            .unwrap();
        write(&sub.join(".claude/settings.local.json"), r#"{"sandbox": {"enabled": true}}"#);

        let hits = sandbox_override_files(&home, &sub);
        assert!(
            hits.iter().any(|h| h.path.starts_with(&sub)),
            "a submodule anchors on itself; its own settings must be the one seen: {hits:?}"
        );
    }

    #[test]
    fn the_walk_stops_at_the_INNER_repo_of_a_nest() {
        // Mutation (c) — climbing past the first `.git` — was NOT caught before: the old
        // test only exercised the no-repo branch and never built nested repos, while the
        // commit claimed it pinned this. It does now.
        let (home, base) = scratch("nested");
        let outer = base.join("outer");
        std::fs::create_dir_all(outer.join(".git")).unwrap();
        write(&outer.join(".claude/settings.local.json"), r#"{"sandbox": {"enabled": false}}"#);
        let inner = outer.join("inner");
        std::fs::create_dir_all(inner.join(".git")).unwrap();

        let hits = sandbox_override_files(&home, &inner);
        assert!(
            hits.is_empty(),
            "the walk must stop at the INNER repo — climbing on would attribute an unrelated \
             parent project's settings to this one: {hits:?}"
        );
    }

    #[test]
    fn a_git_root_search_does_not_escape_into_an_unrelated_parent() {
        // The walk must stop at the first `.git`, not keep climbing: a repo nested inside
        // another must not have its parent's local settings attributed to it, and a cwd with
        // no repository above it must yield nothing rather than walking to `/`.
        let (home, cwd) = scratch("nogit");
        let sub = cwd.join("plain/dir");
        std::fs::create_dir_all(&sub).unwrap();
        assert!(
            sandbox_override_files(&home, &sub).is_empty(),
            "no repository above the cwd means no git-root layer to check"
        );
    }

    #[test]
    fn a_cloned_repo_shipping_a_project_sandbox_block_is_refused() {
        let (home, cwd) = scratch("cloned");
        write(&cwd.join(".claude/settings.json"),
              r#"{"sandbox": {"network": {"allowedDomains": ["evil.example"]}}}"#);
        assert_eq!(sandbox_override_files(&home, &cwd).len(), 1,
            "a settings file arriving inside a repo is the untrusted-input vector");
    }

    #[test]
    fn every_offending_file_is_reported_not_just_the_first() {
        // The message tells the operator what to fix; stopping at the first hit would
        // send them round the loop twice (P11: a denial must be actionable).
        let (home, cwd) = scratch("both");
        write(&home.join(".claude/settings.local.json"), r#"{"sandbox": {"enabled": false}}"#);
        write(&cwd.join(".claude/settings.local.json"), r#"{"sandbox": {"enabled": false}}"#);
        assert_eq!(sandbox_override_files(&home, &cwd).len(), 2);
    }

    #[test]
    fn an_unmappable_acl_group_is_detected_from_the_xattr_blob() {
        // The parse, against real POSIX ACL layout: u32 version, then 8-byte entries of
        // { u16 tag, u16 perm, u32 id }. Only ACL_GROUP (0x0008) with id == u32::MAX is the
        // unmapped case; a normal group entry and the non-group tags must not trip it.
        //
        // Tested at the blob level because the alternative — setting a real ACL naming an
        // unmapped group — is not something a test can arrange, and this is the part that
        // could get the offsets wrong.
        fn scan(blob: &[u8]) -> usize {
            const ACL_GROUP: u16 = 0x0008;
            let mut n = 0;
            let mut i = 4;
            while i + 8 <= blob.len() {
                let tag = u16::from_ne_bytes([blob[i], blob[i + 1]]);
                let id = u32::from_ne_bytes([blob[i + 4], blob[i + 5], blob[i + 6], blob[i + 7]]);
                if tag == ACL_GROUP && id == u32::MAX {
                    n += 1;
                }
                i += 8;
            }
            n
        }
        let entry = |tag: u16, id: u32| {
            let mut e = Vec::new();
            e.extend_from_slice(&tag.to_ne_bytes());
            e.extend_from_slice(&5u16.to_ne_bytes()); // r-x
            e.extend_from_slice(&id.to_ne_bytes());
            e
        };
        let mut blob = vec![2, 0, 0, 0]; // ACL_EBADF version word
        blob.extend(entry(0x0001, u32::MAX)); // ACL_USER_OBJ — id is unused, must NOT count
        blob.extend(entry(0x0004, 30382)); //    ACL_GROUP_OBJ
        blob.extend(entry(0x0008, 30382)); //    ACL_GROUP, mapped — fine
        assert_eq!(scan(&blob), 0, "a fully mapped ACL must be silent");

        blob.extend(entry(0x0008, u32::MAX)); // ACL_GROUP, UNMAPPED — this is the one
        assert_eq!(scan(&blob), 1, "the unmapped group entry must be found");

        blob.extend(entry(0x0008, u32::MAX));
        assert_eq!(scan(&blob), 2, "and counted, not just detected once");

        // A truncated trailing entry must not panic or be miscounted.
        blob.truncate(blob.len() - 3);
        assert_eq!(scan(&blob), 1, "a partial entry is ignored, not read past");
    }

    #[test]
    fn no_agent_launches_without_a_broker_that_actually_claimed_its_spool() {
        // **2026-08-06, Balfrin.** A zero-byte settings.json sent the broker down its
        // fail-closed path. It exited(2) having said exactly why; the wrapper had already
        // exec'd the agent, so the corpse became a zombie and every sbatch and squeue the
        // agent ran timed out at 120s against a spool with no reader. Four sessions, hours.
        //
        // spawn() succeeding says only that execve worked. This pins the difference.
        use std::process::Command;
        let dir = std::env::temp_dir().join(format!("husk-brokerready-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let log = dir.join("session.log");
        fs::write(
            &log,
            "broker: no uenv session detected\n\
             husk: refusing to start - /p/.claude/settings.json: not valid JSON: EOF while \
             parsing a value at line 1 column 0\n\
             husk: Fix the JSON and start husk again.\n",
        )
        .unwrap();

        // A broker that dies during startup, exactly like the real one did.
        let (dead, _keep) = handle_and_channel(Command::new("false").spawn().unwrap());
        let err = match BrokerReady::establish(dead, &log) {
            Err(e) => e,
            Ok(_) => panic!("a broker that exited must NOT yield a serving witness"),
        };
        let msg = err.to_string();
        assert!(msg.contains("exited during startup"), "must name what happened: {msg}");
        assert!(
            msg.contains("refusing to launch the agent"),
            "must say husk chose not to proceed: {msg}"
        );
        assert!(
            msg.contains("120s"),
            "must name the symptom it is replacing, or nobody connects the two: {msg}"
        );
        // ...and it must RELAY the broker's own words rather than paraphrase them.
        assert!(
            msg.contains("not valid JSON") && msg.contains("settings.json"),
            "the reason was in the log all along; the fix is surfacing it: {msg}"
        );

        // A broker that is alive but never announces itself: also not serving.
        let (stalled, _keep) = handle_and_channel(Command::new("sleep").arg("30").spawn().unwrap());
        let err = match BrokerReady::establish_within(stalled, &log, Duration::from_millis(300)) {
            Err(e) => e,
            Ok(_) => panic!("alive is not the same as serving"),
        };
        assert!(err.to_string().contains("did not claim its spool"), "{err}");

        // And the success path: ONE BYTE on a descriptor the wrapper created before the broker
        // existed. What used to stand here was `fs::write(dir.join("owner"), "pid=1")` — a
        // simulation the caged agent could also perform, which is what made it the wrong
        // evidence rather than a badly-read one (`P2`).
        let (live, mut chan) = handle_and_channel(Command::new("sleep").arg("30").spawn().unwrap());
        chan.write_all(b"R").unwrap();
        match BrokerReady::establish_within(live, &log, Duration::from_secs(2)) {
            Ok(w) => drop(w), // BrokerHandle::drop reaps the sleep
            Err(e) => panic!("a broker that announced itself must mint the witness: {e}"),
        }

        let _ = fs::remove_dir_all(&dir);
    }
    use super::*;

    fn args(a: &[&str]) -> std::vec::IntoIter<String> {
        a.iter().map(|s| s.to_string()).collect::<Vec<_>>().into_iter()
    }

    #[test]
    fn parse_args_reads_flags_and_trailing_agent() {
        let r = parse_args(args(&[
            "--stub", "/s", "--broker", "/b", "--spool", "/sp", "--", "husk", "--foo",
        ]))
        .unwrap();
        assert_eq!(r.stub.as_deref(), Some(Path::new("/s")));
        assert_eq!(r.broker.as_deref(), Some(Path::new("/b")));
        assert_eq!(r.spool.as_deref(), Some(Path::new("/sp")));
        assert_eq!(r.agent, vec!["husk".to_string(), "--foo".to_string()]);
        assert!(!r.help);
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        assert!(parse_args(args(&["--bogus"])).is_err());
    }

    #[test]
    fn parse_args_help_sets_flag_without_consuming_rest() {
        assert!(parse_args(args(&["--help"])).unwrap().help);
    }

    #[test]
    fn which_finds_sh_misses_nonsense() {
        assert!(which("sh").is_some());
        assert!(which("definitely-not-on-path-xyzzy-9999").is_none());
    }

    fn cfg(sbatch: Option<&str>, stub: Option<&str>, broker: Option<&str>) -> Config {
        Config {
            spool: PathBuf::from("/tmp/x"),
            agent: vec!["husk".to_string()],
            sbatch: sbatch.map(PathBuf::from),
            stub: stub.map(PathBuf::from),
            broker: broker.map(PathBuf::from),
        }
    }

    #[test]
    fn plan_is_plain_when_no_slurm() {
        assert!(matches!(plan(&cfg(None, None, None)).unwrap(), Plan::Plain));
        // brokering pieces being present is irrelevant without sbatch
        assert!(matches!(plan(&cfg(None, Some("/s"), Some("/b"))).unwrap(), Plan::Plain));
    }

    #[test]
    fn plan_brokers_when_slurm_and_pieces_present() {
        assert!(matches!(
            plan(&cfg(Some("/sbatch"), Some("/stub"), Some("/broker"))).unwrap(),
            Plan::Broker { .. }
        ));
    }

    #[test]
    fn plan_fails_closed_when_slurm_present_but_a_piece_is_missing() {
        // The guarantee: detected SLURM + a missing piece must NOT silently run
        // unbrokered — it must error.
        assert!(plan(&cfg(Some("/sbatch"), None, Some("/broker"))).is_err(), "missing stub");
        assert!(plan(&cfg(Some("/sbatch"), Some("/stub"), None)).is_err(), "missing broker");
        assert!(plan(&cfg(Some("/sbatch"), None, None)).is_err(), "missing both");
    }

    #[test]
    fn require_executable_accepts_exec_rejects_nonexec_and_missing() {
        assert!(require_executable(Path::new("/bin/sh"), "sh").is_ok());
        assert!(require_executable(Path::new("/no/such/file/xyzzy"), "x").is_err());

        let p = std::env::temp_dir().join(format!("cs-wrap-test-{}", std::process::id()));
        fs::write(&p, b"x").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(require_executable(&p, "nonexec").is_err(), "0644 file must be rejected");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(require_executable(&p, "exec").is_ok(), "0755 file must be accepted");
        let _ = fs::remove_file(&p);
    }

    // ---- RC-2: husk's reader and the runtime's reader must agree about the same bytes ----
    //
    // One level above `B5-3`, and a smaller bypass than the one `B5-3` closed. The file was
    // read with `read_to_string`, which REFUSES any byte sequence that is not valid UTF-8, and
    // the error arm resolved to "no override" — so two stray bytes anywhere in the file, in a
    // string husk never even looks at, launched husk with the cage off. Measured against the
    // real runtime on this exact content:
    //
    //     node  -> JSON.parse keys: [ 'sandbox', 'junk' ]   sandbox.enabled = false
    //     husk  -> read=ERR(stream did not contain valid UTF-8) -> LAUNCH
    //
    // `readFileSync(f, "utf8")` decodes leniently rather than failing, which is what
    // `from_utf8_lossy` does. The lossy replacement cannot manufacture a key either: U+FFFD is
    // not ASCII, so it can be no part of `sandbox`, and the runtime sees the same replacement.
    #[test]
    fn a_settings_file_with_non_utf8_bytes_is_still_read_the_way_the_runtime_reads_it() {
        let (home, cwd) = scratch("nonutf8");
        let f = cwd.join(".claude/settings.local.json");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        let mut bytes = br#"{"sandbox": {"enabled": false}, "junk": ""#.to_vec();
        bytes.extend_from_slice(&[0xff, 0xfe]); // valid JSON to the runtime, not valid UTF-8
        bytes.extend_from_slice(br#""}"#);
        std::fs::write(&f, &bytes).unwrap();

        let hits = sandbox_override_files(&home, &cwd);
        assert_eq!(
            hits.len(),
            1,
            "two non-UTF-8 bytes must not make a sandbox override invisible — the runtime reads \
             this file and applies it: {hits:?}"
        );

        // ...and the same file with the key spelled the way `B5-3` found: both levels at once.
        let mut escaped = br#"{"\u0073andbox": {"enabled": false}, "junk": ""#.to_vec();
        escaped.extend_from_slice(&[0xff, 0xfe]);
        escaped.extend_from_slice(br#""}"#);
        std::fs::write(&f, &escaped).unwrap();
        assert_eq!(
            sandbox_override_files(&home, &cwd).len(),
            1,
            "an escaped key inside a non-UTF-8 file is both bypasses composed"
        );

        // The over-refusal direction: lossy decoding must not invent an override.
        let mut clean = br#"{"permissions": {"allow": []}, "junk": ""#.to_vec();
        clean.extend_from_slice(&[0xff, 0xfe]);
        clean.extend_from_slice(br#""}"#);
        std::fs::write(&f, &clean).unwrap();
        assert!(
            sandbox_override_files(&home, &cwd).is_empty(),
            "U+FFFD is not part of any key; an unreadable byte must not block a clean file"
        );
    }

    // ---- RC2-6: a layer husk cannot afford to scan is REFUSED, not skipped ----------------
    //
    // The cost being capped was ADDED by the fix that made the read lenient: `from_utf8_lossy`
    // emits three bytes per invalid byte, so 200 MB of `0xff` at a settings path cost 802 MB of
    // peak RSS and 1.76 s in the FIRST STATEMENT of `run()` (pristine: 202 MB, 0.16 s).
    //
    // FALSE FRIEND: a test whose over-size file also CARRIES a sandbox key is green for a cap
    // that skips the file entirely — the fail-open arm — because the refusal would then be
    // arriving from the scan that never ran. The file below carries no key at all, so the
    // refusal can only come from the size. Deleting the cap turns this test red.
    #[test]
    fn a_settings_layer_too_large_to_scan_is_refused_rather_than_skipped() {
        let (home, cwd) = scratch("toobig");
        let f = cwd.join(".claude/settings.local.json");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, vec![b'x'; MAX_SETTINGS_BYTES as usize + 1]).unwrap();

        let hits = sandbox_override_files(&home, &cwd);
        assert_eq!(hits.len(), 1, "an unscannable layer must be refused, not ignored: {hits:?}");
        assert!(
            matches!(hits[0].why, Why::TooLargeToScan),
            "...and for the size, not by accidentally matching a key: {hits:?}"
        );
        assert!(
            override_message(&hits).contains("too large to be a settings file"),
            "the operator must be told which of the two refusals this is (`P7`)"
        );

        // JUST UNDER the cap husk still scans, in both directions — the cap must not become a
        // way to hide a key by padding, and it must not start refusing ordinary big files.
        let pad = MAX_SETTINGS_BYTES as usize - 64;
        let mut with_key = br#"{"sandbox": {"enabled": false}, "pad": ""#.to_vec();
        with_key.resize(pad, b'x');
        with_key.extend_from_slice(br#""}"#);
        std::fs::write(&f, &with_key).unwrap();
        let hits = sandbox_override_files(&home, &cwd);
        assert!(
            matches!(hits.as_slice(), [Override { why: Why::SandboxKey, .. }]),
            "a key one byte under the cap is still a key: {hits:?}"
        );

        let mut clean = br#"{"permissions": {"allow": []}, "pad": ""#.to_vec();
        clean.resize(pad, b'x');
        clean.extend_from_slice(br#""}"#);
        std::fs::write(&f, &clean).unwrap();
        assert!(
            sandbox_override_files(&home, &cwd).is_empty(),
            "a large but scannable clean file must not block a launch"
        );
    }

    /// `RE-1`. The preflight had the size half and not the type half, and the missing half is
    /// the worse one: `File::open` on a FIFO waits for a writer, `SettingsIntact::establish()`
    /// is the FIRST statement in `run()`, and nothing above it has printed a line yet.
    ///
    /// Measured on the release wrapper at `608618e`, with `mkfifo .claude/settings.local.json`
    /// in the launch directory: 15 seconds, **zero bytes of output**, killed by `timeout`. Not
    /// a refusal an operator could act on — the failure shape `BrokerReady`'s own comment calls
    /// the worst thing husk does to a human.
    ///
    /// **FALSE FRIEND, and it is the loudest one in this finding:**
    /// `no_settings_file_can_make_the_preflight_hang` — the name is exactly this property, and
    /// it was green through that measured hang, because it hands a `&str` to the decoder and
    /// never opens a file. It bounds the SCAN; the hang was in the READ.
    /// `a_settings_layer_too_large_to_scan_is_refused_rather_than_skipped` is green too: the
    /// size bound was already here.
    ///
    /// **MUTATION that turns this red:** drop `.custom_flags(O_NONBLOCK)` from
    /// `read_settings_layer` (this FAILS at five seconds rather than hanging the suite), or
    /// drop its `is_file()` check (the FIFO reads as an empty file, `hits` is empty, and the
    /// first assertion fails).
    /// The sibling `RE-1` found next door: `<workdir>/.git`, read by `main_worktree_root`
    /// on the way to the git-root settings layer, from the first statement of `run()`.
    ///
    /// **This test is deliberately a DIRECT call, and the first version of it was a false
    /// friend for the classic reason (`P9`): it planted a FIFO and went through
    /// `sandbox_override_files`, but `git_root` only descends here when `dot.is_file()` is
    /// true — a FIFO is not, so the walk stepped straight past it and the mutation stayed
    /// GREEN.** Testing one layer above the defect proved the layer.
    ///
    /// So what is actually reachable, stated precisely rather than dramatically:
    ///   - an oversized REGULAR `.git` file — `is_file()` is true, and the read was unbounded;
    ///   - a `rename(2)` of a FIFO over `<workdir>/.git` between that check and this read.
    ///     The agent owns the workdir, and the check is on a NAME (`P15`).
    ///
    /// Both are answered by reading through the bounded reader, and this asserts that it IS
    /// the reader in use: nothing else makes a FIFO return instead of blocking.
    ///
    /// Bounding adds no refusal — every non-`Bytes` disposition maps to `None`, which is the
    /// answer this function already gives for an unparseable `.git`.
    ///
    /// **MUTATION that turns this red:** put `fs::read_to_string(dot_git_file).ok()?` back.
    /// This FAILS at five seconds instead of hanging the suite.
    #[test]
    fn a_git_link_file_that_cannot_be_read_in_bounded_time_yields_no_root() {
        let (_home, cwd) = scratch("gitfifo");
        let dot_git = cwd.join(".git");
        if !std::process::Command::new("mkfifo")
            .arg(&dot_git)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let probe = dot_git.clone();
        std::thread::spawn(move || {
            let _ = tx.send(main_worktree_root(&probe).is_none());
        });
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(true) => {}
            Ok(false) => panic!("a FIFO must not resolve to a worktree root"),
            Err(_) => panic!(
                "main_worktree_root blocked for 5s on a FIFO. Its caller's `is_file()` is a \
                 check on a name, in a directory the agent owns, and the read that followed it \
                 was unbounded — same class as the settings layers, same function chain, \
                 reached from the first statement of run() (`RE-1`, `P15`)."
            ),
        }
        // ...and an oversized REGULAR `.git` — the arm that needs no race — yields no root
        // rather than being read into memory. Same reader, so the same bound.
        let big = cwd.join(".git-big");
        std::fs::write(&big, vec![b'x'; (MAX_SETTINGS_BYTES + 1) as usize]).unwrap();
        assert!(main_worktree_root(&big).is_none(), "an oversized .git link must not be read");
        let _ = std::fs::remove_dir_all(cwd.parent().unwrap());
    }

    #[test]
    fn a_settings_layer_that_is_not_a_file_is_refused_rather_than_opened() {
        let (home, cwd) = scratch("fifo");
        let f = cwd.join(".claude/settings.local.json");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        if !std::process::Command::new("mkfifo")
            .arg(&f)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let (h, c) = (home.clone(), cwd.clone());
        std::thread::spawn(move || {
            let _ = tx.send(sandbox_override_files(&h, &c));
        });
        let hits = match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(h) => h,
            Err(_) => panic!(
                "the preflight blocked for 5s on a FIFO. It is the first statement in run(), so \
                 this is not slowness — it is `husk` producing no output at all and never \
                 returning, for every launch in that directory, until someone deletes a file \
                 nothing has named (`RE-1`)."
            ),
        };
        assert_eq!(hits.len(), 1, "a layer husk could not read must be refused, not ignored: {hits:?}");
        assert!(
            matches!(hits[0].why, Why::NotAFile),
            "...and for what it is, so the remedy is `delete it` and not `edit it`: {hits:?}"
        );
        let m = override_message(&hits);
        assert!(m.contains("not a regular file"), "say why (`P11`): {m}");
        assert!(m.contains(".claude/settings.local.json"), "and which file: {m}");
        assert!(m.lines().count() <= 12, "the third disposition must not grow the refusal:\n{m}");
        assert_eq!(m, override_message(&hits), "identical on retry");
        let _ = std::fs::remove_dir_all(cwd.parent().unwrap());
    }

    /// A `BrokerHandle` plus the end a real BROKER would hold.
    ///
    /// Tests drive readiness the only two ways a broker can: write the byte (it announced
    /// itself) or close the descriptor (it is gone). Neither is reachable from inside the cage,
    /// which is the whole point of the change — so unlike the file this replaced, there is no
    /// third "the agent planted it" case for a test to have to cover.
    fn handle_and_channel(child: std::process::Child) -> (BrokerHandle, UnixStream) {
        let (ours, theirs) = UnixStream::pair().expect("socketpair");
        ours.set_nonblocking(true).expect("O_NONBLOCK on our end");
        (BrokerHandle(child, ours), theirs)
    }

    // ---- B5-2 / RC2-1 / RC2-2: the spool decides NOTHING about whether the agent launches ---
    //
    // Three attempts read `<spool>/owner`, a file in a directory `lib.rs` describes as
    // "agent-writable, so nothing in here is evidence", and each disposition failed differently:
    //
    //   - read it as it stands  -> a leftover file minted the witness for a broker that had
    //                              exited(1) (`B5-2`, the 2026-08-06 Balfrin incident);
    //   - compare pids          -> `echo pid=1 > owner` is a permanent refusal (`RC-4`, and it
    //                              is why the first attempt at this fix was reverted);
    //   - unlink it first       -> `mkdir owner` makes the unlink fail with EISDIR, `exists()`
    //                              is still true, and the witness mints on iteration 1
    //                              (`RC2-1`: 0.005 s to launch against a broker that exited(2)).
    //
    // TWO FALSE FRIENDS, both of which passed for a broken fix:
    //   * a test that plants a REGULAR FILE and asserts a refusal is green for the pid
    //     comparison, i.e. for `RC-4`;
    //   * a test that plants a regular file and asserts it was DELETED is green for the unlink,
    //     i.e. for `RC2-1` — `mkdir` walks straight through it, and the deletion itself was the
    //     `RC2-2` availability bug.
    //
    // So this test asserts neither. For every shape an adversary can put in that directory it
    // asserts all three of the properties that actually matter, which no disposition of a file
    // in an agent-writable directory can hold at once (`P2`):
    //
    //   (1) NO FALSE ACCEPT  — a broker that never announces itself is refused anyway;
    //   (2) NO NEW DENIAL    — a broker that does announce itself launches anyway;
    //   (3) NOTHING TOUCHED  — the wrapper deletes nothing in the spool, so a nested session
    //                          pointed at a live outer spool cannot destroy it (`RC2-2`).
    #[test]
    fn a_planted_owner_file_can_neither_mint_the_witness_nor_refuse_the_launch() {
        use std::process::Command;
        let dir = std::env::temp_dir().join(format!("husk-planted-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let log = dir.join("session.log");
        let victim = dir.join("victim.txt");
        let owner = dir.join("owner");

        // Every shape that has been seen in this file, plus the two the last review measured.
        let plants: Vec<(&str, Box<dyn Fn()>)> = vec![
            ("nothing planted at all", {
                let owner = owner.clone();
                Box::new(move || {
                    let _ = fs::remove_file(&owner);
                    let _ = fs::remove_dir_all(&owner);
                })
            }),
            ("a SIGKILLed session's leftover claim", {
                let owner = owner.clone();
                Box::new(move || fs::write(&owner, "pid=999999\nproject=/earlier\n").unwrap())
            }),
            ("a claim naming init, which is always alive", {
                let owner = owner.clone();
                Box::new(move || fs::write(&owner, "pid=1\n").unwrap())
            }),
            ("something that is not a claim at all", {
                let owner = owner.clone();
                Box::new(move || fs::write(&owner, "garbage\n").unwrap())
            }),
            // `RC2-1`: `remove_file` fails EISDIR, the error was discarded, `exists()` stayed
            // true, and the witness minted on iteration 1 against a dead broker.
            ("a DIRECTORY named owner", {
                let owner = owner.clone();
                Box::new(move || fs::create_dir(&owner).unwrap())
            }),
            // `RC2-3`: `fs::write` follows this, and the broker runs OUTSIDE the cage.
            ("a symlink aimed at a file outside the spool", {
                let (owner, victim) = (owner.clone(), victim.clone());
                Box::new(move || std::os::unix::fs::symlink(&victim, &owner).unwrap())
            }),
        ];

        for (why, plant) in plants {
            let _ = fs::remove_file(&owner);
            let _ = fs::remove_dir_all(&owner);
            fs::write(&victim, "IMPORTANT USER DATA").unwrap();
            plant();
            let planted_before = fs::symlink_metadata(&owner).is_ok();

            // (1) A broker that does not announce itself is refused, however the spool is
            //     decorated. This is the assertion `RC2-1` falsified for the unlink.
            let (silent, _keep) =
                handle_and_channel(Command::new("sleep").arg("30").spawn().unwrap());
            match BrokerReady::establish_within(silent, &log, Duration::from_millis(300)) {
                Err(e) => assert!(
                    e.to_string().contains("did not claim its spool"),
                    "{why}: refused for the wrong reason: {e}"
                ),
                Ok(_) => panic!(
                    "{why}: the agent launched against a broker that never announced itself. \
                     Something in the spool is being read as evidence again, and the confined \
                     side writes that directory (`P2`)."
                ),
            }

            // (2) A broker that DOES announce itself launches, however the spool is decorated.
            //     This is the assertion `RC-4` falsified for the pid comparison.
            let (live, mut chan) =
                handle_and_channel(Command::new("sleep").arg("30").spawn().unwrap());
            chan.write_all(b"R").unwrap();
            match BrokerReady::establish_within(live, &log, Duration::from_secs(2)) {
                Ok(w) => drop(w), // BrokerHandle::drop reaps the sleep
                Err(e) => panic!(
                    "{why}: a serving broker was refused because of something in the spool. That \
                     is `RC-4`, the agent-triggerable denial of service the first attempt at \
                     this fix shipped and was reverted for: {e}"
                ),
            }

            // (3) And the wrapper touched nothing. The unlink that used to be here removed the
            //     OUTER session's claim when two husks shared a spool, after which the outer
            //     broker's teardown took the directory and every later sbatch timed out at
            //     120 s against a path that no longer existed (`RC2-2`).
            let handle = spawn_broker(Path::new("true"), &dir, &log)
                .unwrap_or_else(|e| panic!("{why}: could not spawn the stand-in broker: {e}"));
            drop(handle);
            assert_eq!(
                fs::symlink_metadata(&owner).is_ok(),
                planted_before,
                "{why}: spawn_broker changed what is in the spool. It has no business there: a \
                 nested husk inherits HUSK_SLURM_SPOOL and would be deleting a LIVE outer \
                 session's claim (`RC2-2`)."
            );
            assert_eq!(
                fs::read_to_string(&victim).unwrap(),
                "IMPORTANT USER DATA",
                "{why}: a file outside the spool was written through the plant"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    // ---- the three outcomes the old check conflated, each on its own ----------------------
    //
    // `owner.exists()` had two answers for three states. A descriptor has three, and they have
    // to stay three: "it died", "it will never speak" and "it has not spoken yet" send the
    // operator after different problems, and the second one is what a broker older than this
    // wrapper looks like.
    #[test]
    fn readiness_death_and_silence_are_three_different_answers() {
        use std::process::Command;
        let dir = std::env::temp_dir().join(format!("husk-outcomes-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let log = dir.join("session.log");
        fs::write(&log, "broker: husk: refusing to start - settings.json: not valid JSON\n").unwrap();

        // (a) DEAD, found by try_wait while the channel is still open.
        let (dead, _keep) = handle_and_channel(Command::new("false").spawn().unwrap());
        let err = BrokerReady::establish_within(dead, &log, Duration::from_secs(5))
            .err()
            .expect("a broker that exited must not yield a serving witness");
        assert!(err.to_string().contains("exited during startup"), "{err}");

        // (b) DEAD, found by EOF first — the ordinary case, because a dying process closes its
        //     descriptors. The message must still be the exit STATUS and the broker's own
        //     words, not a sentence about a file descriptor (`P13`).
        let (dead, chan) = handle_and_channel(Command::new("false").spawn().unwrap());
        drop(chan);
        let err = BrokerReady::establish_within(dead, &log, Duration::from_secs(5))
            .err()
            .expect("EOF from a dead broker is still a dead broker");
        let msg = err.to_string();
        assert!(msg.contains("exited during startup"), "EOF must resolve to the exit status: {msg}");
        assert!(msg.contains("not valid JSON"), "and still relay the broker's own words: {msg}");

        // (c) ALIVE but silent: the timeout, and it must name the version-skew cause, because a
        //     broker too old to know this protocol is exactly what it looks like.
        let (stalled, _keep) =
            handle_and_channel(Command::new("sleep").arg("30").spawn().unwrap());
        let err = BrokerReady::establish_within(stalled, &log, Duration::from_millis(300))
            .err()
            .expect("alive is not the same as serving");
        let msg = err.to_string();
        assert!(msg.contains("did not claim its spool"), "{msg}");
        assert!(
            msg.contains("same build"),
            "the one thing that makes a modern broker sit here silent is a mixed install, and \
             the operator will not guess it from a timeout (`P11`): {msg}"
        );

        // (d) ALIVE with the channel closed: not a timeout, and it must not be reported as one.
        let (mute, chan) = handle_and_channel(Command::new("sleep").arg("30").spawn().unwrap());
        drop(chan);
        let err = BrokerReady::establish_within(mute, &log, Duration::from_secs(5))
            .err()
            .expect("a broker that will not answer must not mint the witness");
        assert!(
            err.to_string().contains("closed its readiness channel"),
            "a closed channel is its own fault and needs its own sentence: {err}"
        );

        // (e) SERVING. The only path to the witness, and one byte is all it takes.
        let (live, mut chan) =
            handle_and_channel(Command::new("sleep").arg("30").spawn().unwrap());
        chan.write_all(b"R").unwrap();
        match BrokerReady::establish_within(live, &log, Duration::from_secs(2)) {
            Ok(w) => drop(w),
            Err(e) => panic!("a broker that announced itself must mint the witness: {e}"),
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_dead_broker_outranks_the_readiness_it_already_announced() {
        // The order of two statements IS the check. A byte in the socket buffer is a fact about
        // the past; a reaped child is a fact about the present, and it is the one that decides
        // whether anything will serve this session. Reading the channel first returns before the
        // child is ever asked — which is how a STALE `owner` minted `BrokerReady` for a broker
        // that had exited(1), the 2026-08-06 Balfrin incident. Moving the evidence onto a
        // descriptor did not retire this ordering; it is the same mutation on a new mechanism.
        use std::process::Command;
        let dir = std::env::temp_dir().join(format!("husk-deadfirst-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let log = dir.join("session.log");
        fs::write(&log, "broker: husk: refusing to start - settings.json: not valid JSON\n").unwrap();

        // Reap the child BEFORE the call, so `try_wait` is decided and this cannot race.
        let mut child = Command::new("false").spawn().unwrap();
        let waited = Instant::now();
        while child.try_wait().unwrap().is_none() {
            assert!(
                waited.elapsed() < Duration::from_secs(10),
                "`false` did not exit; this test cannot say anything about a REAPED child"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        // It DID announce itself, and then it died. The byte is sitting in the buffer.
        let (handle, mut chan) = handle_and_channel(child);
        chan.write_all(b"R").unwrap();

        let err = match BrokerReady::establish_within(handle, &log, Duration::from_secs(2)) {
            Err(e) => e,
            Ok(_) => panic!(
                "a byte from a broker that has already exited minted the witness — the agent \
                 would launch, and every sbatch and squeue it ran would hang for 120s against a \
                 spool with no reader"
            ),
        };
        assert!(
            err.to_string().contains("exited during startup"),
            "the dead child, not what it said before dying, is the fact that matters: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // ---- `P2`: the readiness evidence must not be a path, and the compiler cannot say so --
    //
    // `BrokerReady::establish` no longer takes a spool, so putting a file check back needs a
    // path from somewhere — and the cheapest somewhere is `spool.join("owner")` written into
    // the loop. That is precisely the diff three reviews in a row have had to argue against in
    // prose, and prose is what `P12` says drifts. Assert it where the rule lives instead:
    // nothing in that impl may reach the filesystem at all.
    //
    // Lexical, and its limit is lexical — one of these strings inside a COMMENT in that block
    // is a false RED. That is the safe direction, and the same trade the module audit makes.
    #[test]
    fn the_readiness_check_never_touches_the_filesystem() {
        let src_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/husk-slurm-wrapper.rs");
        let src = fs::read_to_string(&src_path)
            .unwrap_or_else(|e| panic!("cannot read my own source at {}: {e}", src_path.display()));
        // BOTH impl blocks, and the second one is why this test was widened. `RC3-3`
        // measured that guarding `impl BrokerReady` alone leaves the function that actually
        // reads the channel and mints `Serving` — `BrokerHandle::readiness` — outside the
        // region: a filesystem read injected there kept this test GREEN. `P15`, the shape
        // this round has now hit five times: the control named a target, and the name
        // resolved to the wrong object. Neither block has any legitimate path use, so the
        // rule is "no filesystem in either", not "no filesystem in the one I thought of".
        let regions = [
            ("impl BrokerReady", "    impl BrokerReady {", "\n    pub(crate) struct SandboxReady"),
            ("impl BrokerHandle", "impl BrokerHandle {", "\n}\n"),
        ];

        for (label, open_anchor, close_anchor) in regions {
            let start = src.find(open_anchor).unwrap_or_else(|| {
                panic!(
                    "`{label}` is gone — re-anchor this test on the real one rather than \
                     deleting it; it is the only thing holding the evidence off the filesystem."
                )
            });
            let len = src[start..].find(close_anchor).unwrap_or_else(|| {
                panic!("the end anchor for `{label}` no longer follows it; re-anchor the end")
            });
            let region = &src[start..start + len];

            for forbidden in ["fs::", ".exists()", ".join(", "Path::new", "metadata(", "read_dir"] {
                assert!(
                    !region.contains(forbidden),
                    "`{forbidden}` appears inside `{label}`. Readiness is answered from a \
                     descriptor this process created BEFORE the broker existed; a path here is a \
                     path into a directory the confined side owns, where every disposition of a \
                     file is either a false accept (`B5-2`, `RC2-1`) or a denial the agent can \
                     trigger (`RC-4`). `P2` — and there is no third option at that level."
                );
            }
        }
    }

    // ---- B5-1: the witness types must be UNFORGEABLE, and only rustc can say so -------
    //
    // Every other test in this file asserts behaviour. This one asserts a TYPE-SYSTEM property,
    // and the only instrument that can observe it is the compiler — so the test runs one.
    //
    // Why it has to exist: the previous version of these types was a control whose entire
    // enforcement was a sentence in the module header and a sentence in `PRINCIPLES.md` `P6`.
    // Both were false. A two-word diff that reads as defensive coding
    // (`SandboxReady::establish(..).unwrap_or(SandboxReady)`) compiled with no new warnings and
    // left 328 tests green while launching the agent with the bind failed.
    //
    // WHAT IS DIFFERENT FROM THE ATTEMPT THAT WAS REVERTED, because it is the whole point: the
    // forgeries are generated from the `use witness::{…}` line rather than hard-coded, so the
    // FOURTH witness — `W2-4` asks for an argv one — is covered on the day it is added to that
    // line, not on the day someone remembers to extend a list. The previous version enumerated
    // five named forgeries against two named call sites and was green against
    // `#[derive(Default)]` + `.unwrap_or_default()`, which is the same bug in the same file.
    //
    // COST AND LIMITATION, stated rather than implied. No `trybuild`, no CI, and a dependency
    // in this binary is not free (its zero-external-crate audit surface is a stated property of
    // the trusted boundary). So this shells out to `rustc` over THIS VERY FILE with each
    // forgery injected: ~0.1 s per invocation, no new dependency, type-checking the real source
    // rather than a miniature that could drift from it. It does NOT cover forgeries written in
    // `unsafe` (`mem::zeroed`, `transmute`), which remain possible by design.
    #[test]
    fn the_witnesses_stay_unforgeable_and_so_does_the_next_one() {
        let src_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/husk-slurm-wrapper.rs");
        let pristine = fs::read_to_string(&src_path)
            .unwrap_or_else(|e| panic!("cannot read my own source at {}: {e}", src_path.display()));

        // (0) THE LIST IS DERIVED FROM THE MODULE ITSELF, not from how it is imported.
        //
        // It used to come off the `use witness::{…}` re-export line, and `RC2-4` measured two
        // ways past that in ordinary Rust with a green suite: a fourth witness reached by FULL
        // PATH (`witness::NetnsReady::establish()`), and one re-exported on a SECOND, non-brace
        // `use witness::X;` line. Neither name is on the line the list came from, so
        // `#[derive(Default)]` + `.unwrap_or_default()` — the exact `MU1` forgery this test
        // exists for — compiled. The module is the boundary the control is about, so it is also
        // where the list belongs.
        let module = {
            let start = pristine.find("\nmod witness {").expect("`mod witness` is gone");
            let end = pristine.find("\nuse witness::{").expect("the re-export line is gone");
            assert!(start < end, "the re-export must follow the module it re-exports");
            &pristine[start..end]
        };
        let witnesses: Vec<String> = module
            .lines()
            .filter_map(|l| l.trim_start().strip_prefix("pub(crate) struct "))
            .map(|rest| {
                rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect::<String>()
            })
            .filter(|n| !n.is_empty())
            .collect();
        for known in ["SandboxReady", "SettingsIntact", "BrokerReady"] {
            assert!(
                witnesses.iter().any(|w| w == known),
                "`{known}` is no longer declared in `mod witness`. If it was renamed, fine; if it \
                 moved OUT of the module, the control is gone — a type declared beside its \
                 consumer has no boundary, which is the state `B5-1` measured. Found: {witnesses:?}"
            );
        }

        // (0b) ...and the re-export line may not name anything the module does not declare. Two
        // lists of the same thing drift, so one asserts the other (`P8`). A name here that the
        // module does not define means `use witness::{…}` is pulling a witness in from somewhere
        // with no module boundary at all, and every probe below would then be testing the wrong
        // type while passing.
        let exported = pristine
            .split_once("\nuse witness::{")
            .and_then(|(_, rest)| rest.split_once("};"))
            .map(|(names, _)| names.to_string())
            .expect("the `use witness::{…};` line is gone");
        for name in exported.split(',').map(str::trim).filter(|n| !n.is_empty()) {
            assert!(
                witnesses.iter().any(|w| w == name),
                "`{name}` is re-exported from `mod witness` but is not declared there. Declared: \
                 {witnesses:?}"
            );
        }

        // (1) WHAT MAY APPEAR INSIDE THE MODULE, as an allowlist of shapes.
        //
        // Two rules, and `RC2-4` bought both of them:
        //
        //   (1a) NO TRAIT IMPLS. `N1`: three lines of `impl From<()> for SandboxReady` inside
        //        the module plus `().into()` outside re-opened the bug that got the first
        //        attempt reverted, 33/33 green — the audit only inspected lines starting with
        //        `pub`, and a trait impl starts with `impl`. Every introduction form a trait can
        //        add (`From`, `Default`, `Deserialize`, `FromStr`, …) has this one shape, so
        //        refuse the shape rather than keep a list of trait names (`P5`).
        //
        //   (1b) THE PUBLIC SURFACE IS THREE EXACT SPELLINGS. `N2`: the rule used to admit any
        //        line beginning `pub(crate) fn establish`, so `establish_not_applicable()`
        //        returning `SandboxReady(())` was admitted — `RC-5` surviving a four-character
        //        rename. An allowlist of exact signatures closes that; a fourth witness needing
        //        a differently-shaped constructor makes this go RED and says so, which is the
        //        correct outcome for a change that widens the way in.
        //
        // THE RESIDUAL, and it is not closable by any tool: an `establish` that returns `Ok`
        // without checking anything is indistinguishable from one that checks. `P6` says this in
        // those words rather than implying that a naming rule covers it.
        for line in module.lines() {
            let t = line.trim_start();
            assert!(
                !(t.starts_with("impl ") && t.contains(" for ")),
                "a trait impl inside `mod witness` is an introduction form for a witness, and no \
                 compiler probe can enumerate the traits. Inherent impls only in here:\n    {t}"
            );
            if !t.starts_with("pub") {
                continue;
            }
            assert!(
                t.starts_with("pub(crate) struct ")
                    || t.starts_with("pub(crate) fn establish(")
                    || t.starts_with("pub(crate) fn establish_within("),
                "a new public item in `mod witness` is a new way to mint a witness, and the \
                 module boundary buys nothing once one exists. Make it private, or give it one \
                 of the two admitted `establish` signatures AND make it do the check — the \
                 second half is on you, because nothing here can see it:\n    {t}"
            );
        }

        // The test binary lives in `<target>/<profile>/deps/`, so its own directory IS the
        // dependency directory — derived, never assumed, so a custom CARGO_TARGET_DIR works.
        let exe = std::env::current_exe().expect("test binary has a path");
        let deps = exe.parent().expect("…/deps/<test-binary>").to_path_buf();
        let rlib = fs::read_dir(&deps)
            .unwrap_or_else(|e| panic!("cannot list {}: {e}", deps.display()))
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.extension().is_some_and(|x| x == "rlib")
                    && p.file_name()
                        .is_some_and(|n| n.to_string_lossy().starts_with("libhusk_slurm_broker-"))
            })
            .max_by_key(|p| p.metadata().and_then(|m| m.modified()).ok())
            .unwrap_or_else(|| {
                panic!(
                    "no libhusk_slurm_broker-*.rlib in {} — the wrapper links the lib, so cargo \
                     must have built one; refusing to pass without checking",
                    deps.display()
                )
            });

        let scratch = std::env::temp_dir().join(format!("husk-forge-{}", std::process::id()));
        let _ = fs::remove_dir_all(&scratch);
        fs::create_dir_all(&scratch).unwrap();

        // Returns rustc's stderr, or None if it compiled clean.
        let compile = |tag: &str, text: &str| -> Option<String> {
            let f = scratch.join(format!("{tag}.rs"));
            fs::write(&f, text).unwrap();
            let out = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
                .args(["--edition", "2021", "--crate-type", "bin", "--emit=metadata"])
                .arg("--extern")
                .arg(format!("husk_slurm_broker={}", rlib.display()))
                .arg("-L")
                .arg(format!("dependency={}", deps.display()))
                .arg("-o")
                .arg(scratch.join(format!("{tag}.meta")))
                .arg(&f)
                .output()
                .unwrap_or_else(|e| panic!("could not run rustc: {e}"));
            if out.status.success() {
                None
            } else {
                Some(String::from_utf8_lossy(&out.stderr).into_owned())
            }
        };

        // (2) THE HARNESS SELF-CHECK, and it is the important one. If the unmutated file did
        // not compile here — wrong flags, missing rlib, anything — every "must not compile"
        // assertion below would pass for the wrong reason, and this test would be a green light
        // bolted to a disconnected wire (`P9`). Verified unfoolable: `RUSTC=/bin/true`,
        // `RUSTC=/bin/false` and a missing binary each turn this test RED rather than silent.
        if let Some(err) = compile("pristine", &pristine) {
            panic!(
                "the UNMUTATED wrapper must compile, or the assertions below prove nothing.\n\
                 This is a broken harness, not a broken control:\n{err}"
            );
        }

        // (3) Three forgeries per witness, ONE PER COMPILATION. The one-per-compilation rule is
        // not tidiness: with two forgeries in one translation unit, a witness that is still
        // private makes the compile fail and the assertion pass while the other is wide open. A
        // conjunction is not a test of its conjuncts.
        for ty in &witnesses {
            // EVERY probe names the witness by its MODULE PATH. The list now comes from the
            // module rather than from the `use` line, so a witness that is used by full path and
            // never re-exported is on it — and for such a name the bare form fails with "cannot
            // find value" (E0425) or "cannot find type" (E0412), which is a red for a reason
            // that has nothing to do with privacy. That would still fail safe, and it would
            // teach the maintainer the wrong thing (`P11`). `witness::X` resolves either way, so
            // every probe below tests the same property for every witness.
            let path = format!("witness::{ty}");

            // (a) and (b) are injected at the REAL call site, so they are the diff a maintainer
            // would actually write, and the anchor fires if that call site moves.
            let call_site = pristine
                .lines()
                .find(|l| l.contains(&format!("{ty}::establish")) && l.trim_end().ends_with("?;"))
                .unwrap_or_else(|| {
                    panic!(
                        "no `?`-propagated `{ty}::establish(…)?;` call site found. Either the \
                         witness is unused — in which case the control it carries is gone — or \
                         the call was reshaped and this test can no longer inject at it."
                    )
                })
                .to_string();

            // (a) the measured `B5-1` forgery: the bare name as a value.
            let err = compile(
                &format!("unwrap_or_{ty}"),
                &pristine.replace(&call_site, &call_site.replace("?;", &format!(".unwrap_or({path});"))),
            )
            .unwrap_or_else(|| {
                panic!(
                    "REGRESSION: `{ty}` can be minted from its own call site again with a \
                     two-word diff that reads as defensive coding. The witness is back to being \
                     a naming convention and the agent can be launched with the control failed."
                )
            });
            assert!(
                err.contains("E0603") || err.contains("E0423"),
                "{ty}: it did not compile, but not for the reason this control relies on. Both \
                 codes say the TUPLE CONSTRUCTOR is not usable as a value here — E0603 for the \
                 `witness::X` path form, E0423 for a bare in-scope name. A different error \
                 usually means the type is back in its caller's module, where a private field \
                 buys nothing. rustc said:\n{err}"
            );

            // (b) `RC-5`'s mutation: three characters, and it left the previous fix 29/29 green.
            // `.unwrap_or_default()` reads as hardening; the fields are `()`, for which
            // `#[derive(Default)]` is free. This is the probe that makes the derive a red test
            // rather than a silent re-opening.
            let err = compile(
                &format!("unwrap_or_default_{ty}"),
                &pristine.replace(&call_site, &call_site.replace("?;", ".unwrap_or_default();")),
            )
            .unwrap_or_else(|| {
                panic!(
                    "REGRESSION: `{ty}` has a `Default`, so `.unwrap_or_default()` mints one \
                     from a FAILED establish(). A private field behind a module boundary does \
                     not survive a derive — remove it."
                )
            });
            assert!(
                err.contains("E0277"),
                "{ty}: it did not compile, but not because the witness lacks a `Default`. E0277 \
                 is the missing trait bound; anything else means the mutation did not even \
                 reach the check and proved nothing. rustc said:\n{err}"
            );

            // (c) the struct-literal form, which routes around the tuple constructor. Same
            // refusal `netallow::Entry` has always given. The field value is `loop {}` — type
            // `!`, which coerces to anything — because a real value would make rustc report a
            // TRAIT BOUND before it reports the privacy, and this probe would then be green
            // for a reason that has nothing to do with privacy. (Measured: with
            // `Default::default()` there, `BrokerReady` failed on `BrokerHandle: Default`.)
            // (d) `RC2-4`'s `N1`, at the compiler rather than at the grep. A `From` impl
            // anywhere — inside the module, in a helper module, in a future refactor — makes
            // `().into()` an expression outside `mod witness` that yields the witness. (1a)
            // refuses the shape; this refuses the RESULT, and the two fail independently, so
            // neither one being wrong makes the control silently green.
            let err = compile(
                &format!("into_{ty}"),
                &format!("{pristine}\nfn _forge_into_{ty}() -> {path} {{ ().into() }}\n"),
            )
            .unwrap_or_else(|| {
                panic!(
                    "REGRESSION: `{ty}` can be minted by `().into()` outside `mod witness`. Some \
                     `From` impl reaches it, and a private field behind a module boundary does \
                     not survive one — exactly as it does not survive a `Default`."
                )
            });
            assert!(
                err.contains("E0277"),
                "{ty}: it did not compile, but not because the witness lacks a `From<()>`. E0277 \
                 is the missing trait bound; anything else means the probe never reached the \
                 check. rustc said:\n{err}"
            );

            let err = compile(
                &format!("literal_{ty}"),
                &format!(
                    "{pristine}\n#[allow(unreachable_code)]\nfn _forge_{ty}() -> {path} {{ {path} {{ 0: loop {{}} }} }}\n"
                ),
            )
            .unwrap_or_else(|| panic!("`{ty}` can be built by struct literal outside `mod witness`"));
            assert!(
                err.contains("E0451") || err.contains("E0616"),
                "{ty}: expected a PRIVATE FIELD error (E0451/E0616). Anything else means the \
                 field shape changed and this probe stopped testing privacy:\n{err}"
            );
        }

        let _ = fs::remove_dir_all(&scratch);
    }
}
