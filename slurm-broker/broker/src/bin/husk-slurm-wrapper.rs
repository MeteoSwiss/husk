//! husk-slurm-wrapper — the fail-closed outer wrapper for the SLURM broker.
//!
//! Sequence (any failure aborts BEFORE the agent ever runs):
//!   1. resolve + validate config (stub, broker, sbatch target all exist+exec)
//!   2. create the spool dir
//!   3. launch the broker in the background — OUTSIDE the namespaces, so it keeps
//!      clean MUNGE credentials + network (the very things the sandbox denies)
//!   4. unshare a user+mount namespace (IDENTITY uid map — never map to root, see
//!      `enter_user_mount_ns`: EUID==0 breaks the agent's own Bash sandbox)
//!   5. bind-mount the stub over the real `sbatch`, then READ BACK to prove it
//!   6. exec the agent (husk) — inherits the mount, so its per-command
//!      bwrap sees the stub instead of the real sbatch
//!
//! Fail-closed is enforced structurally, not by discipline:
//!   - every fallible step returns `io::Result` and is `?`-propagated, so a
//!     failure can never "fall through" to the exec;
//!   - the agent exec REQUIRES a `SandboxReady` witness, and the only way to mint
//!     one is the bind+verify succeeding;
//!   - the broker handle's `Drop` kills the broker on any early return, so a
//!     setup failure never leaves an orphan broker. On success, `execve` replaces
//!     this process image, so `Drop` never runs and the broker lives on.
//!
//! Zero external crates on purpose: this is a trusted boundary-setup binary, so
//! its audit surface is std + the two libc symbols every process already links.

use std::convert::Infallible;
use std::ffi::CString;
use std::fs;
use std::io::{self, Write};
use std::os::raw::{c_char, c_int, c_ulong, c_void};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::ptr;

// The one internal, dependency-free shared const (keeps this binary's zero-crate
// audit surface intact — see the module header).
use husk_slurm_broker::{session_log_path, session_spool_dir, READONLY_SLURM};

// ---- the only FFI: two namespace syscalls std doesn't expose ----------------
const CLONE_NEWNS: c_int = 0x0002_0000; // new mount namespace
const CLONE_NEWUSER: c_int = 0x1000_0000; // new user namespace
const MS_BIND: c_ulong = 0x1000;

extern "C" {
    fn unshare(flags: c_int) -> c_int;
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
struct BrokerHandle(Child);

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
            Some(Ok(())) => return path,
            _ => eprintln!(
                "husk-slurm-wrapper: cannot create '{}' — falling back to a log inside the \
                 spool, which the sandboxed agent can write",
                path.parent().unwrap_or(&path).display()
            ),
        }
    }
    spool.join("broker.log")
}

fn spawn_broker(broker: &Path, spool: &Path, log_path: &Path) -> io::Result<BrokerHandle> {
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|e| {
            io::Error::new(e.kind(), format!("cannot open session log '{}': {e}", log_path.display()))
        })?;
    let errlog = log.try_clone()?;
    let child = Command::new(broker)
        .arg("--spool")
        .arg(spool)
        .env("HUSK_SLURM_SPOOL", spool)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(errlog))
        .spawn()
        .map_err(|e| io::Error::new(e.kind(), format!("failed to launch broker: {e}")))?;
    Ok(BrokerHandle(child))
}

// ---- the witness: only mintable by a verified bind --------------------------
struct SandboxReady;

impl SandboxReady {
    /// Bind the stub over the real sbatch, then PROVE it by comparing dev+inode.
    /// Returning `Ok` is the only way to obtain the token exec_agent requires.
    fn establish(stub: &Path, sbatch: &Path) -> io::Result<SandboxReady> {
        bind_file(stub, sbatch)?;
        let a = fs::metadata(stub)?;
        let b = fs::metadata(sbatch)?;
        if a.dev() == b.dev() && a.ino() == b.ino() {
            Ok(SandboxReady)
        } else {
            Err(io::Error::other(format!(
                "bind verification FAILED: '{}' is not the stub after mount",
                sbatch.display()
            )))
        }
    }
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
    _broker: BrokerHandle,
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
fn exec_plain(agent: &[String]) -> io::Result<Infallible> {
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
    for cmd in READONLY_SLURM {
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

fn run() -> io::Result<Infallible> {
    let cfg = Config::parse()?;
    match plan(&cfg)? {
        Plan::Plain => {
            eprintln!(
                "husk-slurm-wrapper: no SLURM (sbatch) on PATH — launching \
                 husk without job brokering."
            );
            exec_plain(&cfg.agent)
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
            let broker_handle = spawn_broker(broker, &cfg.spool, &session_log)?;

            // Now shrink OUR world and swap sbatch for the stub.
            enter_user_mount_ns()?;
            let ready = SandboxReady::establish(stub, sbatch)?;
            // Best-effort: also shadow the Tier-1 read-only query commands. NOT
            // fail-closed — see shadow_readonly_commands.
            shadow_readonly_commands(stub);

            eprintln!(
                "husk-slurm-wrapper: SLURM detected; spool={} log={} sbatch<-stub OK; launching {}",
                cfg.spool.display(),
                session_log.display(),
                cfg.agent.join(" ")
            );
            exec_agent(ready, broker_handle, &cfg.agent, &cfg.spool)
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(_never) => ExitCode::SUCCESS, // unreachable: exec replaces us on success
        Err(e) => {
            eprintln!("husk-slurm-wrapper: {e}");
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
}
