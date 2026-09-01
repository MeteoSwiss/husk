//! The **step-broker**: the trusted half of the srun pair, on the compute node.
//!
//! It runs OUTSIDE the job's bwrap cage but INSIDE the allocation, so it holds what the
//! caged job deliberately does not: MUNGE, a route to slurmctld/slurmd, and the job
//! credential. It reads step requests from the step-spool, validates them as hostile
//! input (`srun::interpret`), forces the per-task cage (`rank::wrap_command`), and runs
//! the real `srun`.
//!
//! ## Concurrency: spawn-and-poll, not thread-per-step
//!
//! Steps must be able to overlap. Packing many small `srun`s into one allocation
//! (`for i in …; do srun -n1 --exclusive … & done; wait`) is standard HPC practice for
//! sweeps and ensembles, coupled models run concurrent steps, and gate C7 measured that
//! Balfrin runs them concurrently with and without `--overlap`. A serial broker would
//! not merely be slower — the second stub would **hang** with no message, which is the
//! most expensive failure mode to diagnose.
//!
//! But this is a trusted process, so it does not spawn a thread per step. It `spawn()`s
//! the `srun`, keeps the child in a list, and `try_wait()`s each pass of the loop,
//! writing the response when one exits. Concurrency with no threads, no shared mutable
//! state and no locks. The stub tails the output files itself, so nothing has to pump
//! bytes here either.
//!
//! In-flight steps are **capped**. The spool is agent-writable, so without a bound a
//! flood of requests becomes a fork bomb in the one process that must not fall over —
//! the same class of denial-of-service as the read-only query flood fixed in v0.4. Past
//! the cap a request is rejected with a message that says so, rather than queued
//! invisibly.

use crate::profile::Profile;
use crate::protocol::{Request, Response};
use crate::rank;
use crate::settings::{self, FsPolicy};
use crate::spool::{is_valid_id, read_nofollow, write_atomic};
use crate::srun;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// Maximum steps running at once. Generous for real workloads (an ensemble of 32 small
/// tasks fits), small enough that a runaway request loop cannot exhaust the node.
const MAX_IN_FLIGHT: usize = 32;

/// Where Slurm's `mpi/cray_shasta` plugin writes the per-step `apinfo` file, when
/// `scontrol` cannot be reached. The rank cage binds `<dir>/mpi_cray_shasta/<job>.<step>`
/// read-write; getting it wrong costs the MPI bootstrap (EROFS), not containment.
const DEFAULT_SLURMD_SPOOL: &str = "/var/spool/slurmd";

/// Where the guard puts a job's egress socket directory, and how it names it.
///
/// These four values are one half of a pair: the other half is the `mktemp -d` template
/// and the socket leaf in the guard `policy.rs` emits. `P8` says two statements of one
/// fact drift, and this is deliberately a second statement — so it is TIED, not trusted:
/// `the_egress_socket_layout_matches_the_guard_that_creates_it` rebuilds the guard's own
/// line from these constants and asserts it appears in the emitted golden. If someone
/// moves the socket, that test goes red before any job loses its network.
const EGRESS_SOCKET_ROOT: &str = "/tmp";
/// The socket file inside that per-job directory.
const EGRESS_SOCKET_LEAF: &str = "net.sock";
/// The guard's `${SLURM_JOB_ID:-nojob}` fallback, for a guard run outside a job.
const EGRESS_NO_JOB_ID: &str = "nojob";
/// The guard's `$(id -u 2>/dev/null || echo u)` fallback, for the same reason.
const EGRESS_UNKNOWN_UID: &str = "u";

/// This process's uid, from procfs.
///
/// Not `libc::getuid`: the broker has no `libc` dependency, and one integer is not a
/// reason to acquire one. `/proc/self` is owned by the process's own uid, so `stat` on it
/// answers the same question with the standard library. `None` if procfs is not there —
/// the caller must then NOT refuse on the uid alone, because a refusal that fires when
/// husk cannot measure is a denial of service husk inflicted on itself.
fn own_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata("/proc/self").ok().map(|m| m.uid())
}

/// Decide whether an inherited `HUSK_NET_SOCK` / `HUSK_SOCAT` pair is THIS job's egress,
/// and refuse it otherwise. Pure except for two `stat`s, so it is testable without
/// mutating the process environment — same reason `spool::filter_submit_env` is pure.
///
/// `Ok(None)` is the ordinary no-network job and must stay SILENT: it is husk's default
/// and by far the common case. `Err` is a pair that arrived but is not this job's, which
/// is worth a message on husk's own stderr.
///
/// **What is actually checked, and why that and not more.** The socket path is not
/// rebuilt (`P8` — the guard remains the single origin of the random component nobody can
/// guess). What is checked is the one thing an inherited value cannot fake: that it is
/// bound to THIS job. The guard's directory carries `${SLURM_JOB_ID}`, and the job id
/// cannot be authored by the shell that launched husk — `spool::never_forwarded` refuses
/// to forward it because it is an `OUTPUT_SPECIFIERS` variable (`P15`). The guard's own
/// comment already reached this conclusion for the cross-session case: *"permission does
/// not distinguish two sessions of one user; only NAMING does."*
///
/// **This check is not the boundary, and `FIX-K.md` was wrong to call it "the authority"**
/// (`K-1`). Every input to it — `HUSK_NET_SOCK`, `HUSK_SOCAT`, `SLURM_JOB_ID` — lives in
/// the same environment as the value being checked, so it is a CORRELATION between two
/// inherited strings, not an authority over either. It defeats the measured `B4-3` exploit
/// (a login session's socket is spelled `…-nojob-…` and a sibling job's carries the wrong
/// id) and it is what an in-cage or nested husk cannot forge for the real job, so it earns
/// its place — but it is defence in depth.
///
/// **The boundary is one line up, in the guard**: `policy::wrap_script` now `unset`s every
/// `HUSK_` name it exports before it exports any of them, so the only writer of this pair
/// for a real job is husk itself. `P2` — the confined side supplies neither its own
/// boundary nor its own record, and after that line neither does the submitting shell.
/// `every_husk_name_the_guard_exports_is_cleared_first` pins it.
///
/// **The strongest construction is still available and is one file away.** The guard
/// already hands the step broker `--spool` and `--workdir` on ARGV; passing the pair there
/// too would remove the environment channel outright rather than clearing it. It was not
/// taken here because it needs an argument in `main.rs`'s step-broker parse loop, which
/// this pass does not own — `FIX-JK2 §2.3` carries the four-line shape of it.
///
/// The uid is checked when it can be read and ignored when it cannot, and the random
/// component is only required to be non-empty and to contain no `/`. Neither is
/// load-bearing; tightening them would add refusals husk cannot measure on hardware
/// without buying a decision the job-id binding does not already make.
fn inherited_egress(
    sock: Option<&str>,
    socat: Option<&str>,
    uid: Option<u32>,
    job_id: &str,
    root: &str,
) -> Result<Option<InheritedEgress>, String> {
    let (sock, socat) = match (sock, socat) {
        (None, None) => return Ok(None),
        (Some(sock), Some(socat)) => (sock, socat),
        // Half a pair. Previously `_ => None` at the call site: correct, and silent. The
        // guard reaches this state on an ordinary node with no socat, and it says so
        // there — but it also reaches it when only one of the two leaked in, and those
        // two look identical from here, so this says which half arrived.
        (Some(_), None) => {
            return Err("HUSK_NET_SOCK is set but HUSK_SOCAT is not, so there is no relay \
                        to put in the rank's namespace"
                .to_string())
        }
        (None, Some(_)) => {
            return Err("HUSK_SOCAT is set but HUSK_NET_SOCK is not, so there is no proxy \
                        socket for a relay to connect to"
                .to_string())
        }
    };
    egress_socket_is_this_jobs(sock, uid, job_id, root)?;
    egress_socket_is_live(sock, uid)?;
    egress_relay_is_runnable(socat)?;
    Ok(Some(InheritedEgress { sock: sock.to_string(), socat: socat.to_string() }))
}

/// The name check: is this socket the one this job's guard created?
fn egress_socket_is_this_jobs(
    sock: &str,
    uid: Option<u32>,
    job_id: &str,
    root: &str,
) -> Result<(), String> {
    let shape = format!(
        "{root}/husk-<uid>-{job_id}-<random>/{EGRESS_SOCKET_LEAF}"
    );
    let rest = sock
        .strip_prefix(root)
        .and_then(|r| r.strip_prefix("/husk-"))
        .ok_or_else(|| format!("HUSK_NET_SOCK is {sock:?}, not a path of the form {shape}"))?;
    let (dir, leaf) = rest
        .split_once('/')
        .ok_or_else(|| format!("HUSK_NET_SOCK is {sock:?}, not a path of the form {shape}"))?;
    if leaf != EGRESS_SOCKET_LEAF {
        return Err(format!("HUSK_NET_SOCK is {sock:?}, not a path of the form {shape}"));
    }
    let (uid_field, rest) = dir
        .split_once('-')
        .ok_or_else(|| format!("HUSK_NET_SOCK is {sock:?}, not a path of the form {shape}"))?;
    let (job_field, random) = rest
        .split_once('-')
        .ok_or_else(|| format!("HUSK_NET_SOCK is {sock:?}, not a path of the form {shape}"))?;
    // THE CHECK. Everything else on this path is shape; this is authority.
    if job_field != job_id {
        return Err(format!(
            "HUSK_NET_SOCK is {sock:?}, which is job {job_field}'s egress socket and this \
             is job {job_id}"
        ));
    }
    if random.is_empty() {
        return Err(format!("HUSK_NET_SOCK is {sock:?}, not a path of the form {shape}"));
    }
    if let Some(u) = uid {
        if uid_field != u.to_string() && uid_field != EGRESS_UNKNOWN_UID {
            return Err(format!(
                "HUSK_NET_SOCK is {sock:?}, which is uid {uid_field}'s directory and this \
                 job runs as uid {u}"
            ));
        }
    }
    Ok(())
}

/// The second half: is there a socket of ours at that name RIGHT NOW?
///
/// Split from the name check because the two are testable to different depths, and saying
/// so is cheaper than pretending otherwise. `symlink_metadata`, so a symlink at the final
/// component is refused rather than followed — the same rule the step's capture files
/// apply (`A4-S1`), for the same reason: the name came from outside.
///
/// The guard only exports `HUSK_NET_SOCK` after `[ -S ]` succeeds and starts the step
/// broker afterwards, so on the accepting path this has already been true once.
fn egress_socket_is_live(sock: &str, uid: Option<u32>) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let md = fs::symlink_metadata(sock)
        .map_err(|e| format!("HUSK_NET_SOCK is {sock:?}, which husk cannot stat ({e})"))?;
    if !md.file_type().is_socket() {
        return Err(format!("HUSK_NET_SOCK is {sock:?}, which is not a socket"));
    }
    if let Some(u) = uid {
        if md.uid() != u {
            return Err(format!(
                "HUSK_NET_SOCK is {sock:?}, a socket owned by uid {} and not by this \
                 job's uid {u}",
                md.uid()
            ));
        }
    }
    Ok(())
}

/// The relay check: is `HUSK_SOCAT` something a rank could actually execute?
///
/// The rank binds this path into every rank cage and runs it. The guard tests `-x` on the
/// node before exporting it, so this is the same question asked in the trusted process:
/// an inherited value that is not executable HERE produces a rank that exports proxy
/// variables for a relay that never starts, which is the "machine with a broken proxy"
/// state `rank.rs` says the design avoids (`B3-8`).
fn egress_relay_is_runnable(socat: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if !socat.starts_with('/') {
        return Err(format!("HUSK_SOCAT is {socat:?}, which is not an absolute path"));
    }
    let md = fs::metadata(socat)
        .map_err(|e| format!("HUSK_SOCAT is {socat:?}, which husk cannot stat ({e})"))?;
    if !md.is_file() || md.permissions().mode() & 0o111 == 0 {
        return Err(format!("HUSK_SOCAT is {socat:?}, which is not an executable file"));
    }
    Ok(())
}

struct Running {
    id: String,
    child: Child,
}

pub struct StepBroker {
    pub spool: PathBuf,
    pub fs_policy: FsPolicy,
    pub profile: Profile,
    pub dry_run: bool,
    /// The workdir the ranks run in — the job's, captured at guard time, never taken
    /// from a request.
    pub workdir: String,
    slurmd_spool: String,
    /// Our own environment, captured at startup. The ranks inherit it via srun, so it is
    /// the baseline against which a job script's changes are measured.
    base_env: std::collections::BTreeMap<String, String>,
    in_flight: Vec<Running>,
    /// The job's shared user namespace, owned by a child process. See `cage`.
    holder: Option<CageHolder>,
    /// The egress pair this job's guard built, or `None` for a job with no network.
    ///
    /// **ONE field, not two.** "Egress needs BOTH" used to be a `match` arm at the call
    /// site, which is a rule someone can forget; here it is a property of the type, so
    /// there is no half-decided state to represent (`P6`).
    egress: Option<InheritedEgress>,
}

/// The egress socket and relay binary for THIS job, after checking they are this job's.
///
/// The values are still INHERITED rather than reconstructed — the guard builds the path
/// once and exports it, and rebuilding it from `SLURM_JOB_ID` would be a second
/// construction of one fact (`P8`). What `B4-3` measured is that "inherited" was doing
/// two jobs at once: carrying the guard's decision, and being the decision. The submit
/// allowlist forwards `HUSK_*` from the operator's login shell (`spool.rs`
/// `SUBMIT_ENV_ALLOW_PREFIX`), and the net-OFF guard neither sets nor unsets these names
/// — so a job husk built with `--unshare-net` and no allowlist inherited a pair from the
/// shell that launched husk, and this struct existing at all was `egress_decided = true`.
/// A fail-OPEN on the one decision husk documents as fail-closed.
///
/// So the value is inherited and the AUTHORITY is checked. See [`inherited_egress`].
#[derive(Debug)]
struct InheritedEgress {
    sock: String,
    socat: String,
}

/// The child that owns the job's shared user namespace.
///
/// Holding the `Child` is what keeps the namespace alive, and dropping it closes the
/// holder's stdin, which is one of its two shutdown paths (`PDEATHSIG` is the other).
/// Nothing else about the child is used — it is a handle to a namespace, not a worker.
struct CageHolder {
    pid: u32,
    _child: std::process::Child,
}

impl StepBroker {
    pub fn new(
        spool: PathBuf,
        fs_policy: FsPolicy,
        profile: Profile,
        workdir: String,
        dry_run: bool,
    ) -> Self {
        let slurmd_spool = resolve_slurmd_spool();
        eprintln!("step-broker: apinfo spool dir {slurmd_spool:?}");
        StepBroker {
            spool,
            fs_policy,
            profile,
            dry_run,
            workdir,
            slurmd_spool,
            base_env: std::env::vars().collect(),
            in_flight: Vec::new(),
            holder: None,
            egress: {
                let var = |n: &str| std::env::var(n).ok().filter(|s| !s.is_empty());
                // `SLURM_JOB_ID` is slurmd's here and cannot be anything else: it is an
                // `OUTPUT_SPECIFIERS` variable, so `spool::never_forwarded` refuses to
                // carry it from the login shell whatever the allowlist says (`bde2049`,
                // `P15`). That is what makes it usable as the thing an egress socket has
                // to be bound to.
                match inherited_egress(
                    var("HUSK_NET_SOCK").as_deref(),
                    var("HUSK_SOCAT").as_deref(),
                    own_uid(),
                    var("SLURM_JOB_ID").as_deref().unwrap_or(EGRESS_NO_JOB_ID),
                    EGRESS_SOCKET_ROOT,
                ) {
                    Ok(e) => e,
                    Err(why) => {
                        // LOUD. A control that declines and tells no one has failed
                        // (`P7`), and this one declines a capability the job may be
                        // relying on. Two lines: what was refused, and why it is not
                        // something the job can fix.
                        eprintln!("step-broker: this job gets no network - {why}.");
                        eprintln!(
                            "step-broker:   husk only routes a step's egress through the \
                             socket THIS job's guard created. An egress setting that \
                             arrived any other way is not husk's decision, so it is not \
                             honoured. If this job was meant to have a network, check \
                             that an allowlist is configured and unset HUSK_NET_SOCK / \
                             HUSK_SOCAT in the shell you launch husk from."
                        );
                        None
                    }
                }
            },
        }
    }

    /// One pass: reap finished steps, then admit new requests. Never blocks on a step.
    pub fn tick(&mut self) -> std::io::Result<()> {
        self.heartbeat();
        self.reap();
        self.scan()
    }

    /// The file name the stub watches to tell a dead broker from a running step.
    pub const HEARTBEAT: &'static str = "broker.alive";

    /// The heartbeat's write-and-rename temp. A LITERAL, not `format!("{}.tmp", HEARTBEAT)`:
    /// the completeness test reads the names this file builds, and a format string that starts
    /// with a placeholder yields no name at all — which is how a leak walks past it (`B4-2`,
    /// mutation `M2`). Tied to `HEARTBEAT` by the completeness test's glob match.
    pub const HEARTBEAT_TMP: &'static str = "broker.alive.tmp";

    /// Say "still here", once per pass.
    ///
    /// The stub has exactly one wait, and it is unbounded — correctly, because a step
    /// legitimately runs for hours and killing a simulation on a wall clock would be worse
    /// than waiting. But that single wait conflates two questions: *has anyone picked this
    /// up* (seconds) and *has the step finished* (hours). With no way to separate them, a
    /// broker that is not running is indistinguishable from a job that is still working, and
    /// srun hangs to the walltime saying nothing. That is what happened on Balfrin
    /// 2026-08-06 when unparseable settings stopped the broker from starting at all.
    ///
    /// A heartbeat rather than a per-request ack, because an ack only answers the first
    /// question. A broker that dies *mid-step* — reaped, killed, panicking — has already
    /// acked, and the stub would wait forever again. One file answers both, and keeps no
    /// per-request state to leak.
    ///
    /// Best-effort by design: a spool we cannot write is a real problem, but it is the
    /// step launch's problem to report, not this function's to abort on.
    fn heartbeat(&self) {
        // Sub-second, because the staleness bound the stub applies must not be pinned to
        // this file's resolution — with whole seconds, any limit near 1s is a coin flip.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let path = self.spool.join(Self::HEARTBEAT);
        // Named as a SUFFIX of the heartbeat, not a dotfile, so the guard's cleanup can
        // reclaim both with one `broker.alive*` glob instead of listing them.
        let tmp = self.spool.join(Self::HEARTBEAT_TMP);
        // Write-and-rename: the stub reads this concurrently, and a torn read would look
        // like a stale broker — i.e. it would manufacture exactly the failure it detects.
        if fs::write(&tmp, format!("{now:.3}\n")).is_ok() && fs::rename(&tmp, &path).is_err() {
            let _ = fs::remove_file(&tmp);
        }
    }

    /// Start the job's cage holder if it is not running yet, and return its pid.
    ///
    /// Lazy on purpose: a step-broker that never launches a step should not create a
    /// namespace. Created once per JOB rather than per step — nothing in it is
    /// step-specific, and a namespace per step would be a process per step to leak.
    fn ensure_holder(&mut self) -> Result<u32, String> {
        // A cached pid is a claim about a process, and processes end. If the holder died,
        // every later step in the job was handed its pid anyway and failed at its own
        // fail-closed gate on `/proc/<pid>/ns/user` — for the whole wall time, with no
        // attempt to recover. Worse in principle than a wedge: pids are recycled, so a
        // stale one can eventually name a DIFFERENT live process of this user's, and the
        // check would pass on a namespace that has nothing to do with this job.
        //
        // Verify it is still the holder we started before handing it out. The namespace
        // link is the evidence, not the pid: it is what the ranks will actually open, and
        // it disappears with the process.
        if let Some(h) = &self.holder {
            if std::path::Path::new(&crate::cage::userns_path(h.pid)).exists() {
                return Ok(h.pid);
            }
            eprintln!(
                "husk: the cage holder for this job (pid {}) is gone; starting a new one. \
                 Steps already running keep the namespace they joined.",
                h.pid
            );
            self.holder = None;
        }
        let exe = std::env::current_exe()
            .map_err(|e| format!("cannot locate the husk broker binary: {e}"))?;
        let mut child = std::process::Command::new(&exe)
            .arg("--hold-cage")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot start the cage holder ({}): {e}", exe.display()))?;

        // The holder reports the pid that is actually INSIDE the namespace. Taking
        // `child.id()` instead would be a guess about process arrangement.
        let mut line = String::new();
        let stdout = child.stdout.take().ok_or("cage holder has no stdout")?;
        std::io::BufRead::read_line(&mut std::io::BufReader::new(stdout), &mut line)
            .map_err(|e| format!("cage holder did not report readiness: {e}"))?;
        let pid: u32 = line
            .trim()
            .parse()
            .map_err(|_| format!("cage holder reported {line:?} instead of a pid"))?;

        // stdin stays OPEN inside `child` for the broker's lifetime: closing it is how
        // the holder learns to exit.
        self.holder = Some(CageHolder { pid, _child: child });
        Ok(pid)
    }

    /// Write the response for every step that has exited. `try_wait` does not block, so
    /// a four-hour step costs nothing here.
    fn reap(&mut self) {
        let spool = self.spool.clone();
        self.in_flight.retain_mut(|r| match r.child.try_wait() {
            Ok(None) => true, // still running
            Ok(Some(status)) => {
                let code = status.code().unwrap_or_else(|| {
                    // Killed by a signal: report it the way a shell would, so the number
                    // in the job log matches what a user would see uncaged.
                    use std::os::unix::process::ExitStatusExt;
                    128 + status.signal().unwrap_or(0)
                });
                let resp = if code == 0 {
                    Response::query(&r.id, String::new(), String::new(), 0)
                } else {
                    let mut resp = Response::query(&r.id, String::new(), String::new(), code);
                    resp.message = format!("step exited with status {code}");
                    resp
                };
                write_response(&spool, &r.id, &resp);
                false
            }
            Err(e) => {
                eprintln!("step-broker: wait failed for {}: {e}", r.id);
                let resp = Response::error(&r.id, format!("could not wait for the step: {e}"));
                write_response(&spool, &r.id, &resp);
                false
            }
        });
    }

    fn scan(&mut self) -> std::io::Result<()> {
        let mut requests: Vec<PathBuf> = Vec::new();
        for entry in fs::read_dir(&self.spool)? {
            let entry = entry?;
            // Regular files only: the spool is agent-writable, so a symlinked request
            // could turn the broker into a read oracle or point it at a FIFO. (F5)
            if !matches!(entry.file_type(), Ok(ft) if ft.is_file()) {
                continue;
            }
            let path = entry.path();
            if path
                .file_name()
                .and_then(|s| s.to_str())
                .map(|s| s.starts_with("req-") && s.ends_with(".json"))
                .unwrap_or(false)
            {
                requests.push(path);
            }
        }
        for path in requests {
            self.admit(&path);
        }
        Ok(())
    }

    fn admit(&mut self, req_path: &Path) {
        let data = match read_nofollow(req_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("step-broker: read {req_path:?}: {e}");
                let _ = fs::remove_file(req_path);
                return;
            }
        };
        let _ = fs::remove_file(req_path);
        let req: Request = match serde_json::from_slice(&data) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("step-broker: malformed request {req_path:?}: {e}");
                return;
            }
        };
        if !is_valid_id(&req.id) {
            eprintln!("step-broker: dropping request with unsafe id {:?}", req.id);
            return;
        }
        let id = req.id.clone();
        eprintln!("step-broker: request id={id} tool={} argv={:?}", req.tool, req.argv);

        // Only steps are brokered here. The sbatch broker on the login node handles
        // submissions; a job may not submit new jobs from inside its own cage (AV8).
        if req.tool != "srun" {
            let msg = format!(
                "'{}' is not brokered inside a job. Only srun is, and only for steps of \
                 this allocation.",
                req.tool
            );
            write_response(&self.spool, &id, &Response::rejected(&id, msg));
            return;
        }
        if self.in_flight.len() >= MAX_IN_FLIGHT {
            let msg = format!(
                "too many steps already running ({MAX_IN_FLIGHT}). husk caps concurrent \
                 steps so a runaway loop cannot exhaust the node; wait for one to finish."
            );
            write_response(&self.spool, &id, &Response::rejected(&id, msg));
            return;
        }

        let step = match srun::interpret(&req.argv) {
            Ok(s) => s,
            Err(reason) => {
                write_response(&self.spool, &id, &Response::rejected(&id, reason));
                return;
            }
        };

        // Build the real invocation: forced options, then the validated ones, then the
        // per-task wrapper that cages whatever the command turns out to be.
        // Run the ranks where the CALLER was, not where the job started. A run script
        // almost always `cd`s into its case directory before launching:
        //     cd $RUNDIR && srun ./icon
        // and ICON then opens `icon_master.namelist` relative to that. Forcing the
        // job's start directory instead sent the ranks somewhere else entirely
        // (Balfrin 2026-07-31: `open_nml: Could not open icon_master.namelist`).
        //
        // `req.cwd` is agent-controlled, so it gets the same check the sbatch path
        // applies to its workdir: absolute, no traversal, not `/`, not under a hidden
        // home. The cage's WRITABLE root is unchanged — this only decides where the
        // ranks start, so honouring it cannot widen what they may write.
        let cwd = if settings::is_workdir_allowed(&req.cwd) {
            req.cwd.clone()
        } else {
            let msg = format!(
                "the step's working directory {:?} is not allowed (it must be an absolute \
                 path, not '/', and not under a hidden home like /users)",
                req.cwd
            );
            write_response(&self.spool, &id, &Response::rejected(&id, msg));
            return;
        };

        let mut argv = vec!["srun".to_string()];
        argv.push("--chdir".to_string());
        argv.push(cwd);
        argv.extend(step.options);
        argv.push("--".to_string());
        // The rank cage, plus the job script's own environment as `--setenv` pairs.
        // A brokered srun otherwise breaks the chain by which a run script's `export`
        // reaches its ranks — the script runs inside the cage, the real srun outside it —
        // and `export OMP_NUM_THREADS=4; srun ./icon` would silently run with different
        // settings than it asked for. See rank::setenv_args for why these go through
        // bwrap rather than into srun's own environment.
        // The job's shared user namespace must exist before any rank starts. Fail the
        // step rather than fall back to per-rank namespaces: that fallback would run the
        // workload in cages that cannot CMA each other, which surfaces as an obscure MPI
        // error rather than as the containment change it actually is.
        let holder_pid = match self.ensure_holder() {
            Ok(pid) => pid,
            Err(e) => {
                let msg = format!("husk: cannot create the job's shared user namespace: {e}");
                eprintln!("step-broker: {msg}");
                write_response(&self.spool, &id, &Response::rejected(&id, msg));
                return;
            }
        };

        let mut cage = self.fs_policy.rank_bwrap_args(&self.workdir);
        // Only the DELTA against our own environment: srun propagates that to the tasks
        // already, so forwarding everything would re-set hundreds of identical values and
        // bury the handful the run script actually changed.
        cage.extend(rank::env_args(&req.env, &self.base_env, self.fs_policy.unset_env()));
        argv.extend(rank::wrap_command(
            self.profile,
            &cage,
            &self.slurmd_spool,
            holder_pid,
            // No arms left to get wrong: "egress needs both, and both must be this
            // job's" was decided once, at startup, by `inherited_egress`.
            self.egress.as_ref().map(|e| rank::Egress {
                sock: &e.sock,
                socat: &e.socat,
            }),
            &step.command,
        ));

        if self.dry_run {
            println!("---- DRY RUN step (request {id}) ----");
            println!("argv: {argv:?}");
            write_response(&self.spool, &id, &Response::query(&id, String::new(), String::new(), 0));
            return;
        }

        // The stub streams these while the step runs, which is why they are files and
        // not pipes: nothing here has to pump bytes, and a step that outlives a dead
        // stub still writes somewhere harmless.
        // **A4-S1, the round's CRITICAL (elevated by the synergizer).** `id` is the rank's,
        // so it can pre-plant `out-<id>`/`err-<id>` as a SYMLINK before sending the request;
        // `File::create` would FOLLOW it and write the step's (attacker-forged) stdout through
        // it — an uncaged, truncating write to any path the submitting user can reach. Chained
        // with the auto-exec masks that means overwriting `~/.bashrc`/`.Rprofile` and running
        // as the operator outside every cage. The spool is agent-writable; the broker is not
        // in the cage; so this open must assume the name is hostile.
        //
        // `create_new` (O_CREAT|O_EXCL) refuses if the name exists AT ALL — a pre-planted
        // symlink OR regular file — and O_NOFOLLOW refuses to traverse a final-component
        // symlink even in a race. A fresh uuid never collides, so a collision IS the attack;
        // we refuse the step rather than write through it. Same pattern as `write_atomic`'s
        // tmp open in spool.rs, for the same reason.
        let out_path = self.spool.join(format!("out-{id}"));
        let err_path = self.spool.join(format!("err-{id}"));
        let (out, err) = match (create_capture_file(&out_path), create_capture_file(&err_path)) {
            (Ok(o), Ok(e)) => (o, e),
            _ => {
                // Clean up a half-created pair so a refusal cannot itself leave a squatting
                // file that fails the NEXT id's create_new. Only our own fresh regular file
                // can be here; O_EXCL guaranteed we did not open anything pre-existing.
                let _ = fs::remove_file(&out_path);
                let _ = fs::remove_file(&err_path);
                let msg = "husk refuses this step: its output-capture name already exists in                     the spool. husk creates out-<id>/err-<id> fresh from a unique id, so a name                     that is already present — a symlink or a planted file — is not husk's and is                     not written through."
                    .to_string();
                write_response(&self.spool, &id, &Response::error(&id, msg));
                return;
            }
        };

        match Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
        {
            Ok(child) => {
                eprintln!("step-broker: launched step for {id} (pid {})", child.id());
                self.in_flight.push(Running { id, child });
            }
            Err(e) => {
                let msg = format!("could not launch srun: {e}");
                write_response(&self.spool, &id, &Response::error(&id, msg));
            }
        }
    }
}

/// Create a step's stdout/stderr capture file, refusing a name that already exists.
///
/// **A4-S1.** The spool is agent-writable and the id is the rank's, so `out-<id>` may be a
/// symlink the rank planted before sending the request. `create_new` (O_CREAT|O_EXCL) fails
/// if the name exists at all — symlink or regular file — and O_NOFOLLOW refuses to traverse a
/// final-component symlink even in a race, so this can never write THROUGH a planted name. A
/// unique id never collides, so a collision is the attack, and the caller refuses the step.
fn create_capture_file(path: &Path) -> std::io::Result<fs::File> {
    create_capture_file_with(path, crate::spool::O_NOFOLLOW)
}

/// The same open with the flags supplied, so a test can pass `0`.
///
/// **`N1-2`.** `crate::spool::O_NOFOLLOW` was the bare asm-generic number with no `cfg`, which
/// makes it `O_LARGEFILE` — a no-op — on aarch64, so on Santis this open ran with the symlink
/// flag switched off for as long as it has existed. It was still not a hole, and the reason is
/// worth pinning rather than asserting: `create_new` is `O_CREAT|O_EXCL`, which refuses a
/// symlink at the final component **regardless of where it points**, so the defence held on
/// its own. `a_planted_symlink_capture_name_is_refused_not_written_through` already implies it
/// — it asserts `ErrorKind::AlreadyExists`, which is `O_EXCL`'s `EEXIST` and not
/// `O_NOFOLLOW`'s `ELOOP` — but it implies it on the architecture where both flags work.
/// `a_planted_capture_name_is_refused_even_when_the_open_flag_does_nothing` says it where
/// husk could not otherwise measure it.
fn create_capture_file_with(path: &Path, flags: i32) -> std::io::Result<fs::File> {
    crate::spool::create_exclusive(path, flags)
}

/// One name shape that can appear in a step spool: a fixed `prefix`, one `*`, a fixed
/// `suffix`. The `*` is supplied by `glob()` and is never carried in the data.
///
/// **`RDF-D-2`: this table is a code-generation INPUT, so its shape check has to be a type.**
/// `policy.rs` splices every entry into the guard as bare, UNQUOTED shell — quoting would
/// defeat the globbing that is the whole point — inside `rm -f "$_husk_spool"/<entry>`. Until
/// this type existed nothing in the tree constrained what an entry could contain, and the
/// executing test that was added to cover this list is a GLOB-SEMANTICS oracle, not an
/// injection one: it plants `glob.replace('*', "9f3c1a")` and checks the spool empties, so an
/// entry that also runs a command passes. A reviewer put ``audit`>RCEMARK`*`` in the old
/// `Vec<String>`, ran an arbitrary command from inside the guard during `cargo test`, and left
/// **310 passed** behind — only the byte-goldens noticed. `P6`: the control is the type, not
/// the assert beside it, and this is the same shape `settings::OUTPUT_SPECIFIERS` took for
/// `RA-3`.
///
/// `new` is a `const fn` and the table below is a `const`, so a bad entry is `error[E0080]`
/// while the crate COMPILES — there is no path for it to be reached on and nobody to trigger
/// it. The fields are private to this module and every consumer is outside it, so
/// `SpoolGlob { .. }` is not a constructor anyone can reach. There is deliberately no
/// `Default`.
mod spool_glob {
    /// A cleanup glob, as the two literal halves either side of its single `*`.
    pub struct SpoolGlob {
        prefix: &'static str,
        suffix: &'static str,
    }

    /// The only bytes a glob half may contain: `[A-Za-z0-9._-]`. Everything a shell would
    /// read as syntax is therefore out — no `/` (which would leave the spool), no `..`
    /// (which would climb out of it), no space (which would split the word into a second
    /// path), no `$`, backtick, `;`, `&`, `|`, `<`, `>`, quote or backslash (which would
    /// EXECUTE), and no second `*`.
    ///
    /// Written out rather than calling `u8::is_ascii_alphanumeric` so this stays a `const fn`
    /// on every toolchain that builds husk.
    const fn is_glob_byte(c: u8) -> bool {
        (c >= b'a' && c <= b'z')
            || (c >= b'A' && c <= b'Z')
            || (c >= b'0' && c <= b'9')
            || c == b'.'
            || c == b'_'
            || c == b'-'
    }

    const fn all_glob_bytes(s: &'static str) -> bool {
        let b = s.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if !is_glob_byte(b[i]) {
                return false;
            }
            i += 1;
        }
        true
    }

    impl SpoolGlob {
        pub const fn new(prefix: &'static str, suffix: &'static str) -> SpoolGlob {
            assert!(all_glob_bytes(prefix), "a glob prefix may only contain [A-Za-z0-9._-]");
            assert!(all_glob_bytes(suffix), "a glob suffix may only contain [A-Za-z0-9._-]");
            // A glob that begins with `*` matches every non-dot name in the directory, which
            // would turn `rm -f "$_husk_spool"/<entry>` into a wholesale delete and destroy
            // the "it still holds" diagnostic that is the reason this cleanup enumerates at
            // all (`P5`, `P7`).
            assert!(!prefix.is_empty(), "a cleanup glob must not begin with its `*`");
            // …and it must be at least three characters WIDE, because a glob `p*s` cannot
            // match a name shorter than `p` + `s`. Three is one more than `..`, so no
            // expansion of any entry can ever hand `rm -f` the spool itself or its parent.
            // That property was a sentence in a test comment; it is an invariant now
            // (`P15` — the confined side owns this directory's parent).
            assert!(
                prefix.len() + suffix.len() >= 3,
                "a cleanup glob must be at least 3 characters wide, so no expansion of it \
                 can ever be `.` or `..`"
            );
            SpoolGlob { prefix, suffix }
        }

        /// The shell `policy.rs` emits. Validated by `new`, so splicing it unquoted is safe.
        pub fn glob(&self) -> String {
            format!("{}*{}", self.prefix, self.suffix)
        }
    }
}

use spool_glob::SpoolGlob;

/// Every name that can appear in a step spool, as a shell glob.
///
/// ONE definition with three readers, because the last three leaks in this directory were all
/// a second list disagreeing with the writers (`P8`): the guard's cleanup in `policy.rs` is
/// GENERATED from this, the completeness scanner checks every path this file builds against
/// it, and the executing test writes one file per entry and then asserts the guard removed
/// the directory. A glob that does not work is red, not litter on a compute node.
///
/// The halves are constants, not spelled-out globs, so the two entries that belong to another
/// module still come FROM that module (`P8`) while staying inside a `const` the compiler
/// validates.
pub const STEP_SPOOL_GLOBS: &[SpoolGlob] = &[
    // Written by the STUB, inside the cage. It is in the spool and the guard has to
    // reclaim it, so "husk writes it" is the wrong membership test for this list.
    SpoolGlob::new("req-", ".json"),
    // `write_response`, via `write_atomic`.
    SpoolGlob::new("resp-", ".json"),
    // `launch_step`'s capture files; the stub removes them, the guard is the backstop.
    SpoolGlob::new("out-", ""),
    SpoolGlob::new("err-", ""),
    // The heartbeat AND its temp, which is deliberately named as a suffix of it.
    SpoolGlob::new(StepBroker::HEARTBEAT, ""),
    // `write_atomic`'s in-flight temp — a DOTFILE, which none of the globs above can
    // match. Its absence here leaked the whole spool on any interrupted step response
    // (`C2-2`), and the login-side reaper had carried the same shape all along. Built from
    // the writer's own two constants; `the_tmp_glob_is_still_the_one_write_atomic_produces`
    // ties the result back to `TMP_GLOB`.
    SpoolGlob::new(husk_slurm_broker::TMP_PREFIX, husk_slurm_broker::TMP_SUFFIX),
];

/// `STEP_SPOOL_GLOBS` as the shell the guard emits.
pub fn step_spool_globs() -> Vec<String> {
    STEP_SPOOL_GLOBS.iter().map(|g| g.glob()).collect()
}

fn write_response(spool: &Path, id: &str, resp: &Response) {
    let path = spool.join(format!("resp-{id}.json"));
    match serde_json::to_vec(resp) {
        Ok(bytes) => {
            if let Err(e) = write_atomic(&path, &bytes) {
                eprintln!("step-broker: failed to write response for {id}: {e}");
            }
        }
        Err(e) => eprintln!("step-broker: failed to serialize response for {id}: {e}"),
    }
}

/// Ask Slurm where slurmd's spool lives, since that is where the per-step `apinfo` file
/// the MPI bootstrap needs is written. Resolved once at startup, in the broker's trusted
/// context; a failure falls back to the documented default rather than aborting, because
/// the cost of being wrong is a failed MPI wire-up, not a containment hole.
fn resolve_slurmd_spool() -> String {
    let out = Command::new("scontrol").arg("show").arg("config").output();
    if let Ok(o) = out {
        let text = String::from_utf8_lossy(&o.stdout);
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("SlurmdSpoolDir") {
                if let Some((_, v)) = rest.split_once('=') {
                    let v = v.trim();
                    if v.starts_with('/') {
                        return v.to_string();
                    }
                }
            }
        }
    }
    eprintln!(
        "step-broker: could not read SlurmdSpoolDir from scontrol; \
         assuming {DEFAULT_SLURMD_SPOOL}"
    );
    DEFAULT_SLURMD_SPOOL.to_string()
}

#[cfg(test)]
mod tests {
    use crate::settings;

    /// `RDF-D-2`: THE ONE TEST THAT IS NOT THE TABLE READING ITSELF.
    ///
    /// Everything else that touches `STEP_SPOOL_GLOBS` derives its expectation from it — the
    /// completeness scanner in `policy.rs` matches `step.rs`'s writers AGAINST the globs, and
    /// the executing test plants `glob.replace('*', …)` and checks the spool empties. Both
    /// pass for any table. `SpoolGlob::new` makes a DANGEROUS entry impossible at compile
    /// time; this makes a WRONG one visible, which is a different question.
    #[test]
    fn the_cleanup_globs_are_the_ones_the_writers_produce() {
        // Written out by hand, in emission order, with the writer that justifies each.
        const REFERENCE: &[(&str, &str)] = &[
            ("req-*.json", "the srun stub, inside the cage"),
            ("resp-*.json", "`write_response` -> `write_atomic`"),
            ("out-*", "`launch_step`'s stdout capture"),
            ("err-*", "`launch_step`'s stderr capture"),
            ("broker.alive*", "the heartbeat AND its `.tmp`, which is a suffix of it"),
            (".*.tmp", "`write_atomic`'s in-flight temp — a DOTFILE (`C2-2`)"),
        ];
        let globs = super::step_spool_globs();
        assert_eq!(
            globs.len(),
            REFERENCE.len(),
            "the cleanup table changed size. Every entry is spliced UNQUOTED into `rm -f` in \
             a directory the confined side can write, so an addition needs a row here."
        );
        for (i, (want, who)) in REFERENCE.iter().enumerate() {
            assert_eq!(&globs[i], want, "glob {i}: {who}");
        }
        // The two entries that belong to other modules must still come FROM them (`P8`), or
        // this reference is just a second spelling that can drift with the writer.
        assert_eq!(globs[4], format!("{}*", super::StepBroker::HEARTBEAT));
        assert_eq!(globs[5], husk_slurm_broker::TMP_GLOB);
    }


    #[test]
    fn a_planted_symlink_capture_name_is_refused_not_written_through() {
        // A4-S1, the round's CRITICAL, at the exact level the bug lived. The rank knows the id,
        // so it plants `out-<id>` as a symlink to a file OUTSIDE the spool before the broker
        // opens it. With the old `File::create` the broker followed the link and wrote the
        // step's (forged) stdout through it — an uncaged write to any path the user can reach.
        use std::io::Write as _;
        use std::os::unix::fs::symlink;

        let dir = std::env::temp_dir().join(format!("husk-a4s1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // The victim lives OUTSIDE the spool and must never be touched.
        let victim = dir.join("victim-bashrc");
        std::fs::write(&victim, b"ORIGINAL
").unwrap();

        // The rank pre-plants the capture name as a symlink to the victim.
        let spool = dir.join("spool");
        std::fs::create_dir_all(&spool).unwrap();
        let planted = spool.join("out-11111111-2222-3333-4444-555555555555");
        symlink(&victim, &planted).unwrap();

        // The broker's own open must REFUSE it, and leave the victim byte-for-byte intact.
        let err = super::create_capture_file(&planted)
            .expect_err("a pre-existing capture name must be refused, never opened");
        assert!(
            matches!(err.kind(), std::io::ErrorKind::AlreadyExists),
            "the refusal must be O_EXCL's AlreadyExists, not some incidental error: {err:?}"
        );
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"ORIGINAL
",
            "the file the symlink pointed at must be UNTOUCHED — no write went through"
        );

        // And the honest path — a fresh unique name — still works and is a real regular file.
        let fresh = spool.join("out-99999999-8888-7777-6666-555555555555");
        {
            let mut f = super::create_capture_file(&fresh).expect("a fresh name must open");
            f.write_all(b"step stdout
").unwrap();
        }
        let meta = std::fs::symlink_metadata(&fresh).unwrap();
        assert!(meta.file_type().is_file(), "the fresh capture must be a real file, not a link");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_planted_capture_name_is_refused_even_when_the_open_flag_does_nothing() {
        // `N1-2`. On Santis `crate::spool::O_NOFOLLOW` was `O_LARGEFILE`, so this open ran
        // with the symlink flag switched off. A4-S1's own test cannot see that: it runs on
        // x86_64, where the flag works, so it would stay green either way — the false friend
        // is not the assertion (it correctly demands `AlreadyExists`, which is O_EXCL's error)
        // but the ARCHITECTURE it runs on.
        //
        // So: the same attack with `flags = 0`, which is exactly what an inert constant
        // produces. `create_new` must carry it alone, and the victim must be untouched.
        //
        // MUTATION that turns it red: drop `.create_new(true)` from `create_exclusive` and
        // rely on the flag. Green on x86_64 with the flag, red here — which is the point.
        use std::os::unix::fs::symlink;

        let dir = std::env::temp_dir().join(format!("husk-n1-cap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim-bashrc");
        std::fs::write(&victim, b"ORIGINAL\n").unwrap();
        let planted = dir.join("out-11111111-2222-3333-4444-555555555555");
        symlink(&victim, &planted).unwrap();

        let err = super::create_capture_file_with(&planted, 0)
            .expect_err("O_EXCL must refuse a planted symlink with the other flag switched off");
        assert!(
            matches!(err.kind(), std::io::ErrorKind::AlreadyExists),
            "the refusal must come from O_EXCL, which is the half that is architecture-\
             independent: {err:?}"
        );
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"ORIGINAL\n",
            "a write went through the planted symlink with the flag inert"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_steps_working_directory_gets_the_same_check_as_a_jobs() {
        // The step runs where the CALLER was — a run script cds into its case directory
        // before launching — so req.cwd is honoured rather than overridden. It is
        // agent-controlled, so it passes the same gate the sbatch path uses.
        assert!(settings::is_workdir_allowed("/scratch/proj/run"));
        for bad in ["/", "relative/path", "/users/victim", "/scratch/../users/x", ""] {
            assert!(
                !settings::is_workdir_allowed(bad),
                "{bad:?} must not be accepted as a step working directory"
            );
        }
    }

    // ---- B4-3: the egress decision has ONE origin now, and it is checked --------------

    /// The path the guard would build for `job`, under a root this test owns.
    fn egress_socket_name(root: &std::path::Path, uid: Option<u32>, job: &str) -> String {
        let u = uid.map(|u| u.to_string()).unwrap_or_else(|| super::EGRESS_UNKNOWN_UID.into());
        root.join(format!("husk-{u}-{job}-aBc123"))
            .join(super::EGRESS_SOCKET_LEAF)
            .to_string_lossy()
            .into_owned()
    }

    /// A real executable, for the relay half.
    fn a_runnable_relay(root: &std::path::Path) -> String {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(root).unwrap();
        let socat = root.join("socat");
        std::fs::write(&socat, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&socat, std::fs::Permissions::from_mode(0o755)).unwrap();
        socat.to_string_lossy().into_owned()
    }

    fn a_test_root(tag: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir()
            .join(format!("husk-egress-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    /// **`B4-3`, the finding.** `StepBroker` read `HUSK_NET_SOCK`/`HUSK_SOCAT` straight out
    /// of its own environment and treated any non-empty pair as "this job has egress".
    /// Measured: the submit allowlist forwards `HUSK_*` from the operator's login shell
    /// (`spool.rs` `SUBMIT_ENV_ALLOW_PREFIX`), and the net-OFF guard neither sets nor
    /// unsets those names — so a job husk built with `--unshare-net` and no allowlist
    /// reached `rank::Egress`, bound a socket into every rank's cage and exported
    /// `HTTP_PROXY`. A fail-OPEN on the one decision husk describes as fail-closed.
    ///
    /// The same name is accepted for the job it was built for and refused for every other
    /// one, which is the whole of the fix: the value stays INHERITED (the guard remains the
    /// single origin of a random component nobody can guess) and the AUTHORITY is checked.
    /// `SLURM_JOB_ID` is the part an inherited value cannot fake, because
    /// `spool::never_forwarded` refuses to carry it from the login shell (`P15`).
    ///
    /// **Mutations that turn this red:** delete the `job_field != job_id` arm in
    /// `egress_socket_is_this_jobs` (the sibling-session case is admitted again);
    /// or restore the old two-field `std::env::var` read, which fails at the type level.
    ///
    /// **What it does not cover.** This is the NAME half only — it makes no syscall, so it
    /// says nothing about whether a socket is really there (`egress_socket_is_live`, below).
    /// It also does not prove the guard's net-OFF path never exports the pair; that is
    /// `policy.rs`'s golden, and `the_egress_socket_layout_matches_the_guard_that_creates_it`
    /// ties this module's idea of the layout to it.
    #[test]
    fn an_egress_socket_built_for_another_job_is_not_this_jobs_egress() {
        let uid = super::own_uid();
        let root = a_test_root("names");
        let r = root.to_string_lossy().into_owned();
        let mine = egress_socket_name(&root, uid, "990001");
        let theirs = egress_socket_name(&root, uid, "424242");

        // The job it was built for: accepted, exactly as before the fix.
        super::egress_socket_is_this_jobs(&mine, uid, "990001", &r)
            .expect("this job's own egress socket must still be accepted");

        // ANY other job — a stale value, or a live sibling session's relay on the same
        // shared /tmp — is refused, and the message says whose it is.
        let why = super::egress_socket_is_this_jobs(&theirs, uid, "990001", &r)
            .expect_err("another job's socket is not this job's egress");
        assert!(why.contains("424242"), "say whose socket it is: {why}");
        assert!(why.contains("990001"), "and which job is asking: {why}");

        // A uid that is not ours, when we can read our own.
        if let Some(u) = uid {
            let other = root
                .join(format!("husk-{}-990001-aBc123", u.wrapping_add(1)))
                .join("net.sock")
                .to_string_lossy()
                .into_owned();
            let why = super::egress_socket_is_this_jobs(&other, uid, "990001", &r)
                .expect_err("another uid's directory is not this job's egress");
            assert!(why.contains("uid"), "{why}");
        }

        // And anything that is not of the guard's shape at all — the hand-set case.
        for bogus in [
            "/tmp/husk-socat",
            "/tmp/proxy.sock",
            "relative/net.sock",
            "/tmp/husk-1-2-3/other.sock",
            "/tmp/husk-1-2-/net.sock",
            "/tmp/husk-1-2-3/sub/net.sock",
        ] {
            assert!(
                super::egress_socket_is_this_jobs(bogus, uid, "2", "/tmp").is_err(),
                "an arbitrary path must not decide a job's egress: {bogus}"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The other half of the socket check: the name is right, but is a socket of ours
    /// actually there? This is the state `B3-8` describes — a rank left exporting
    /// `HTTP_PROXY=http://127.0.0.1:3128` at a relay that never starts — decided here, in
    /// the trusted process, instead of silently inside the cage.
    ///
    /// **What it does not cover, and the reason is measured.** Only the REFUSING direction
    /// is exercised. This suite cannot create a unix socket: the environment it runs in
    /// refuses `socket(AF_UNIX, …)` outright with `EPERM` (the same call is why
    /// `netproxy::tests::the_allowlist_gates_real_connections` is a standing failure here),
    /// so no test in this file can produce the object the accepting arm needs. That arm is
    /// covered on hardware, by `selftest.sh`'s `guard.sock_short` and `net.live` — a job
    /// whose egress works at all has passed it. If this ever runs somewhere `socket(2)` is
    /// permitted, bind one here and delete this paragraph.
    #[test]
    fn a_socket_that_is_not_there_is_not_an_egress_socket() {
        let uid = super::own_uid();
        let root = a_test_root("live");
        let sock = egress_socket_name(&root, uid, "990001");
        // Nothing at the name at all.
        let why = super::egress_socket_is_live(&sock, uid).unwrap_err();
        assert!(why.contains("cannot stat"), "{why}");
        // Something at the name that is not a socket.
        std::fs::create_dir_all(std::path::Path::new(&sock).parent().unwrap()).unwrap();
        std::fs::write(&sock, b"not a socket\n").unwrap();
        let why = super::egress_socket_is_live(&sock, uid).unwrap_err();
        assert!(why.contains("not a socket"), "{why}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The denial-of-service half, and the reason it is its own test: the ORDINARY job is
    /// the one with no network at all, and the fix must leave it exactly where it was —
    /// no refusal, no message, no egress. A control that fires on the common case is a
    /// defect however sound its reasoning.
    #[test]
    fn a_job_with_no_egress_is_still_the_quiet_default() {
        assert!(
            super::inherited_egress(None, None, super::own_uid(), "990001", "/tmp")
                .expect("no pair is not an error")
                .is_none(),
            "a job with no egress must reach the same place it always did"
        );
    }

    /// Half a pair. Both halves have to be present for a rank to get a relay that works,
    /// and that used to be a `match` arm at the call site with a silent `_ => None`. It is
    /// the type's job now, and the refusal says WHICH half arrived — the two causes (a node
    /// with no socat; one leaked variable) are indistinguishable otherwise.
    #[test]
    fn half_an_egress_pair_is_refused_and_names_the_half_that_is_missing() {
        let uid = super::own_uid();
        let root = a_test_root("half");
        let sock = egress_socket_name(&root, uid, "990001");
        let socat = a_runnable_relay(&root);
        let r = root.to_string_lossy().into_owned();
        let a = super::inherited_egress(Some(&sock), None, uid, "990001", &r).unwrap_err();
        assert!(a.contains("HUSK_SOCAT is not"), "{a}");
        let b = super::inherited_egress(None, Some(&socat), uid, "990001", &r).unwrap_err();
        assert!(b.contains("HUSK_NET_SOCK is not"), "{b}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The relay half. The rank binds this path into every rank cage and RUNS it, so a
    /// value that is not executable in the trusted process is a rank that advertises a
    /// proxy which never comes up.
    #[test]
    fn a_relay_that_could_not_run_is_refused_before_a_rank_advertises_it() {
        use std::os::unix::fs::PermissionsExt;
        let root = a_test_root("relay");
        let socat = a_runnable_relay(&root);
        super::egress_relay_is_runnable(&socat).expect("a real executable must be accepted");
        std::fs::set_permissions(&socat, std::fs::Permissions::from_mode(0o644)).unwrap();
        let why = super::egress_relay_is_runnable(&socat).unwrap_err();
        assert!(why.contains("not an executable file"), "{why}");
        assert!(super::egress_relay_is_runnable("socat").is_err(), "must be absolute");
        assert!(
            super::egress_relay_is_runnable(&root.join("nope").to_string_lossy()).is_err(),
            "a relay that is not there is not a relay"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `P8`: the layout constants in this module are a SECOND statement of a fact
    /// `policy.rs` owns, so this ties them to the first. It rebuilds the guard's own
    /// `mktemp -d` template and socket assignment out of husk's constants and asserts they
    /// appear in the EMITTED artifact — the committed golden, not a reading of the
    /// generator.
    ///
    /// This is the test that keeps the `B4-3` fix from becoming its own outage. If someone
    /// moves the egress socket and edits only `policy.rs`, every brokered job would
    /// silently lose its network; instead this goes red.
    ///
    /// **Mutations that turn it red:** `EGRESS_SOCKET_ROOT` -> `"/var/tmp"`;
    /// `EGRESS_SOCKET_LEAF` -> `"egress.sock"`; `EGRESS_NO_JOB_ID` -> `"none"`.
    ///
    /// **What it does not cover:** the golden is regenerable, so this ties two husk
    /// artifacts to each other and not to a running job. Only `selftest.sh`'s
    /// `guard.sock_short` on hardware shows the real path (measured Balfrin and Santis:
    /// `/tmp/husk-27069-990001-AeRcwa/net.sock`, which is exactly this shape).
    #[test]
    fn the_egress_socket_layout_matches_the_guard_that_creates_it() {
        let golden = include_str!("../tests/golden/guard-net-on.sh");
        let template = format!(
            "mktemp -d \"{}/husk-$(id -u 2>/dev/null || echo {})-${{SLURM_JOB_ID:-{}}}-XXXXXX\"",
            super::EGRESS_SOCKET_ROOT,
            super::EGRESS_UNKNOWN_UID,
            super::EGRESS_NO_JOB_ID,
        );
        assert!(
            golden.contains(&template),
            "the step broker expects the guard to create {template}, and the guard does not"
        );
        let assign = format!("_husk_net_sock=\"$_husk_net_dir/{}\"", super::EGRESS_SOCKET_LEAF);
        assert!(
            golden.contains(&assign),
            "the step broker expects the guard to bind {assign}, and the guard does not"
        );
    }

    #[test]
    fn every_pass_leaves_a_fresh_heartbeat_the_stub_can_read() {
        // The stub's only wait is unbounded, and correctly so — a step runs for hours. That
        // makes "nobody is listening" and "still computing" the same observation, which is
        // why srun hung to the walltime on Balfrin 2026-08-06 with the broker not running.
        // This file is what tells them apart, so its FORMAT is load-bearing: the stub parses
        // the contents as unix seconds, not the mtime.
        let dir = std::env::temp_dir().join(format!("husk-hb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut sb = super::StepBroker::new(
            dir.clone(),
            settings::FsPolicy::unchecked_for_test(),
            crate::profile::Profile::SingleNode,
            dir.to_string_lossy().to_string(),
            true,
        );
        sb.tick().expect("a pass over an empty spool still beats");

        let beat = std::fs::read_to_string(dir.join(super::StepBroker::HEARTBEAT))
            .expect("every pass must leave a heartbeat, or a live broker reads as dead");
        let secs: f64 = beat.trim().parse().expect("unix seconds, parseable by the stub");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        assert!(now - secs < 60.0, "the beat must be current: {secs} vs {now}");
        assert!(
            beat.contains('.'),
            "sub-second precision is load-bearing for the stub's bound: {beat:?}"
        );

        // No temp file left beside it: the stub globs this directory looking for its own
        // response, and litter in an agent-writable spool is its own small problem.
        assert!(
            !dir.join(format!("{}.tmp", super::StepBroker::HEARTBEAT)).exists(),
            "the write-and-rename temp must not survive"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
