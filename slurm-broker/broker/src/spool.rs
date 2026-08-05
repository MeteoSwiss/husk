//! Spool watch + request lifecycle. The broker reads `req-*.json`, decides,
//! stages the job script, submits (or dry-runs), and writes `resp-*.json`.
//! It deletes each request after responding so it is processed once; the stub
//! deletes the response after reading it (both tolerate the other being gone).

use crate::policy::{self, Decision, Submission};
use crate::protocol::{Request, Response};
use crate::session::Session;
use crate::settings::FsPolicy;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

// Linux O_NOFOLLOW: opening refuses to traverse a symlink at the final path
// component. The spool is agent-writable, so every spool open uses it (F1/F5).
const O_NOFOLLOW: i32 = 0o400000;

// Kill a read-only query that exceeds its wall-clock budget (F2/F16). One libc symbol,
// keeping the broker's zero-external-crate posture.
const SIGKILL: i32 = 9;
extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

pub struct Broker {
    pub spool: PathBuf,
    pub session: Session,
    pub dry_run: bool,
    /// Compute-cage filesystem policy, resolved once at startup from the TRUSTED project
    /// dir (never from the agent-controlled req.cwd). See main.rs. (F17)
    pub fs_policy: FsPolicy,
    /// Job ids this broker submitted, and the ONLY ones it will cancel.
    ///
    /// Trusted state: it is built from what `sbatch --parsable` returned, never from
    /// anything the agent sent. In memory rather than on disk deliberately — the spool is
    /// agent-writable, so a persisted list would be a list the confined side could edit,
    /// which is precisely the authority this is meant to hold. The cost is that a restarted
    /// broker disowns earlier jobs; they are then cancellable by the human, which is the
    /// right way for that to fail.
    pub submitted: std::cell::RefCell<std::collections::BTreeSet<u64>>,
    /// The TRUSTED project dir — where husk was launched, captured before the agent ran.
    ///
    /// This is the cage's writable root, and it is deliberately NOT `req.cwd`: that comes
    /// from the agent over the spool, so deriving the write boundary from it lets the
    /// confined side choose its own confinement. F17 already established this for the
    /// POLICY; the workdir bind was still using the agent's value.
    pub project_dir: PathBuf,
}

impl Broker {
    /// Process every pending request once. Returns how many were handled.
    pub fn process_once(&self) -> std::io::Result<usize> {
        // Reclaim orphaned spool files (dead stub / crash mid-write) before scanning. (F4)
        self.gc(std::time::Duration::from_secs(GC_MAX_AGE_SECS));
        let mut n = 0;
        for entry in fs::read_dir(&self.spool)? {
            let entry = entry?;
            // Only regular files are requests. Skip symlinks: an agent (who can write
            // the spool) could point a req-*.json at an out-of-spool file to use the
            // broker as a read oracle or to DoS it (/dev/zero, a FIFO). (F5)
            if !matches!(entry.file_type(), Ok(ft) if ft.is_file()) {
                continue;
            }
            let path = entry.path();
            let is_req = path
                .file_name()
                .and_then(|s| s.to_str())
                .map(|s| s.starts_with("req-") && s.ends_with(".json"))
                .unwrap_or(false);
            if is_req {
                self.handle(&path);
                n += 1;
            }
        }
        Ok(n)
    }

    fn handle(&self, req_path: &Path) {
        let result = self.decide_response(req_path);
        // Consume the request so it is not reprocessed, regardless of outcome.
        let _ = fs::remove_file(req_path);
        if let Some((id, resp)) = result {
            let resp_path = self.spool.join(format!("resp-{id}.json"));
            match serde_json::to_vec(&resp) {
                Ok(bytes) => {
                    if let Err(e) = write_atomic(&resp_path, &bytes) {
                        eprintln!("broker: failed to write response for {id}: {e}");
                    }
                }
                Err(e) => eprintln!("broker: failed to serialize response for {id}: {e}"),
            }
        }
    }

    fn decide_response(&self, req_path: &Path) -> Option<(String, Response)> {
        // O_NOFOLLOW read: even after the process_once regular-file check, refuse to
        // follow a symlink swapped in under us (TOCTOU). (F5)
        let data = match read_nofollow(req_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("broker: read {req_path:?}: {e}");
                return None;
            }
        };
        let req: Request = match serde_json::from_slice(&data) {
            Ok(r) => r,
            Err(e) => {
                // No trustworthy id to answer; log and drop.
                eprintln!("broker: malformed request {req_path:?}: {e}");
                return None;
            }
        };
        // `req.id` becomes part of spool file paths (resp-<id>.json, job-<id>.sh) and is
        // agent-controlled, so reject anything that isn't a safe path component before it
        // is used to build a path. Drop (no response) — a valid stub always sends a UUID. (F1)
        if !is_valid_id(&req.id) {
            eprintln!("broker: dropping request with unsafe id {:?}", req.id);
            return None;
        }
        let id = req.id.clone();
        // Audit line: every brokered request is logged before any decision.
        eprintln!(
            "broker: request id={id} submitted_at={} tool={} script.source={} script.name={}",
            req.submitted_at,
            req.tool,
            req.script.source,
            req.script.name.as_deref().unwrap_or("-"),
        );
        // Use the cage policy captured at startup from the TRUSTED project dir — NOT
        // re-resolved from the agent-controlled req.cwd (that let the agent author its
        // own cage by planting a nested .claude/settings.local.json). (F17)
        let resp = match policy::decide(&req, &self.session, &self.fs_policy, &self.project_dir) {
            Decision::Reject(msg) => Response::rejected(&id, msg),
            Decision::Query(argv) => self.run_query(&id, argv),
            Decision::Cancel(targets) => self.cancel(&id, targets),
            Decision::Submit(sub) => self.submit(&id, &req, sub),
        };
        Some((id, resp))
    }

    /// Run a validated read-only query in the broker's context (it has MUNGE +
    /// network) and return its captured output. `argv[0]` is the command, already
    /// checked against the read-only allowlist in `policy`. Output is capped so a
    /// chatty query can't bloat the spool.
    fn run_query(&self, id: &str, argv: Vec<String>) -> Response {
        if argv.is_empty() {
            return Response::error(id, "empty query");
        }
        if self.dry_run {
            println!("---- DRY RUN query (request {id}) ----");
            println!("argv: {argv:?}");
            return Response::query(id, String::new(), String::new(), 0);
        }
        match run_query_cmd(&argv, std::time::Duration::from_secs(QUERY_TIMEOUT_SECS)) {
            Ok((out, false)) => Response::query(
                id,
                cap_output(&out.stdout),
                cap_output(&out.stderr),
                out.status.code().unwrap_or(1),
            ),
            Ok((_, true)) => Response::error(
                id,
                format!("query '{}' exceeded {QUERY_TIMEOUT_SECS}s and was killed", argv[0]),
            ),
            Err(e) => Response::error(id, format!("could not run {}: {e}", argv[0])),
        }
    }

    fn submit(&self, id: &str, req: &Request, sub: Submission) -> Response {
        // The AGENT'S script is staged as data, where the guard will read it inside the cage.
        if let Err(e) = write_atomic(std::path::Path::new(&sub.body_path), sub.body.as_bytes()) {
            return Response::error(id, format!("could not stage job body: {e}"));
        }

        // HUSK'S script goes to sbatch on STDIN, and that is the point.
        //
        // It used to be written into the spool and named on the argv. The spool has to be
        // agent-writable — the agent's stub puts its requests there — so between our write
        // and sbatch's open there was a window in which the agent could `rename()` its own
        // file over ours, and sbatch would submit that instead. The v0.5 review won that
        // race 33 times in 100 against a 2 ms window, with a clean control, and the agent
        // picks the request id so it knows the path.
        //
        // Passing the script on stdin deletes the window rather than narrowing it: there is
        // no path, so there is nothing to substitute. sbatch reads its script from stdin
        // whenever no script operand is given.
        //
        // The agent's own argv for its script moves into the guard as a quoted `set --`,
        // since with no script operand there is nowhere on the sbatch command line for it
        // to go. It is also strictly better there: husk quotes it instead of forwarding it.
        let mut argv: Vec<String> = vec!["sbatch".to_string(), "--parsable".to_string()];
        argv.extend(sub.options);

        if self.dry_run {
            println!("---- DRY RUN (request {id}) ----");
            println!("cwd : {}", req.cwd);
            println!("argv: {argv:?}");
            println!("---- staged body ({}) ----", sub.body_path);
            println!("---- script (stdin) ----");
            println!("{}", sub.wrapped_script);
            // A dry run exists to show what a real submission WOULD do, and the script is
            // the most important half of that. On the live path it never touches the disk
            // (that is the point — see below), so dry-run writes an inspectable copy here.
            let _ = write_atomic(&self.spool.join(format!("dry-{id}.sh")), sub.wrapped_script.as_bytes());
            // The note too. A dry run exists to show what a real submission WOULD return,
            // so anything the live path attaches must be attached here — otherwise the one
            // mode the tests can observe is the one mode that behaves differently.
            return Response::submitted(id, 0).with_note(sub.note);
        }

        let resp = match run_sbatch(&argv, &sub.wrapped_script) {
            Ok(job_id) => {
                // Remember it, so the agent can later stop what it started. This is the
                // only place the set grows, and it grows from slurmctld's answer.
                self.submitted.borrow_mut().insert(job_id);
                Response::submitted(id, job_id).with_note(sub.note)
            }
            Err(e) => Response::error(id, e),
        };
        // Nothing to unstage here any more: husk's script went to sbatch on stdin and was
        // never a file. The AGENT'S body must survive until the job runs it, so its owner
        // is the guard, which removes it on every exit path (see `wrap_script`) — except
        // when the submission failed, in which case no job will ever read it and it is ours.
        if matches!(resp.status.as_str(), "error" | "rejected") {
            let _ = fs::remove_file(&sub.body_path);
        }
        resp
    }

    /// Cancel jobs this broker submitted — and refuse anything else.
    ///
    /// husk brokers `sbatch` but not `scancel`, which left an agent able to START work and
    /// unable to STOP it, not even its own job. That is a containment gap: a runaway needed
    /// a human. It also bit a review session, which left 14 held probe jobs it could not
    /// clean up.
    ///
    /// The gate is OWNERSHIP, checked here rather than in `policy`, because only the broker
    /// knows what it submitted. An id husk did not submit is refused by name — this account
    /// has jobs husk never touched (a human's production runs), and "cancel my own jobs"
    /// must not become "cancel this user's jobs".
    ///
    /// All-or-nothing: one unowned id refuses the whole request. A partial cancel would
    /// leave the agent believing it had stopped something it had not.
    fn cancel(&self, id: &str, targets: Vec<String>) -> Response {
        let owned = self.submitted.borrow();
        let unowned: Vec<&String> = targets
            .iter()
            .filter(|t| !policy::cancel_base_id(t).is_some_and(|b| owned.contains(&b)))
            .collect();
        if !unowned.is_empty() {
            let known: Vec<String> = owned.iter().map(|j| j.to_string()).collect();
            return Response::rejected(
                id,
                format!(
                    "husk will not cancel {} — this session did not submit {}. It cancels \
                     only jobs it submitted itself, because this account also has jobs husk \
                     never touched. Submitted this session: {}",
                    unowned.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                    if unowned.len() == 1 { "it" } else { "them" },
                    if known.is_empty() { "(none yet)".to_string() } else { known.join(", ") },
                ),
            );
        }
        drop(owned);

        let mut argv = vec!["scancel".to_string()];
        argv.extend(targets.iter().cloned());
        if self.dry_run {
            println!("---- DRY RUN cancel (request {id}) ----");
            println!("argv: {argv:?}");
            return Response::query(id, String::new(), String::new(), 0);
        }
        match run_query_cmd(&argv, std::time::Duration::from_secs(QUERY_TIMEOUT_SECS)) {
            Ok((out, false)) => Response::query(
                id,
                cap_output(&out.stdout),
                cap_output(&out.stderr),
                out.status.code().unwrap_or(1),
            ),
            Ok((_, true)) => {
                Response::error(id, format!("scancel exceeded {QUERY_TIMEOUT_SECS}s and was killed"))
            }
            Err(e) => Response::error(id, format!("could not run scancel: {e}")),
        }
    }

    /// Reclaim stale orphaned spool files — a stub that died before deleting its response,
    /// or a broker crash mid-write: `resp-*.json`, `job-*.sh`, and `.*.tmp` older than
    /// `max_age`. Never touches `req-*.json` (live requests, consumed by process_once). (F4)
    fn gc(&self, max_age: std::time::Duration) {
        let entries = match fs::read_dir(&self.spool) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let is_orphan = (name.starts_with("resp-") && name.ends_with(".json"))
                || (name.starts_with("job-") && name.ends_with(".sh"))
                || (name.starts_with('.') && name.ends_with(".tmp"));
            if !is_orphan {
                continue;
            }
            let stale = entry
                .metadata()
                .and_then(|m| m.modified())
                .map(|t| t.elapsed().map(|e| e > max_age).unwrap_or(false))
                .unwrap_or(false);
            if stale {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

const MAX_QUERY_OUTPUT: usize = 1 << 20; // 1 MiB cap on captured query output
const QUERY_TIMEOUT_SECS: u64 = 60; // wall-clock budget for a read-only query

/// Wall-clock budget for a submission. Generous, because slurmctld under load can take a
/// while and killing a submission that would have succeeded is its own failure — but not
/// unbounded, because this broker is single-threaded and a submission that never returns
/// takes `scancel` down with it.
const SUBMIT_TIMEOUT_SECS: u64 = 120;
const GC_MAX_AGE_SECS: u64 = 3600; // orphaned spool files older than this are reclaimed

/// Run a validated read-only query with a wall-clock timeout, killing the child if it
/// exceeds it. The broker's request loop is single-threaded and synchronous, so a query
/// that never exits (e.g. `squeue/sinfo --iterate`) would otherwise wedge the broker for
/// the whole session (F2/F16). std-only: a watchdog thread SIGKILLs the child past the
/// deadline; the reader's `wait_with_output` returns once the pipes close. Returns
/// (output, timed_out). The watchdog exits early on normal completion, so a fast query is
/// not delayed.
fn run_query_cmd(
    argv: &[String],
    timeout: std::time::Duration,
) -> std::io::Result<(std::process::Output, bool)> {
    use std::os::unix::process::CommandExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    // process_group(0): run the query in its OWN process group so we can kill the whole
    // subtree. Killing just the direct child would leave a grandchild (e.g. the `sleep`
    // a shell spawned) alive holding the stdout pipe, so wait_with_output would still
    // block for the full runtime — defeating the timeout.
    // The same allowlist as a submission (B6-F6). These are read-only queries and `scancel`,
    // so nothing here reaches a compute node — but they run with the broker's credentials
    // against the same daemons, and `SCANCEL_*`/`SQUEUE_*` are an unlisted channel into the
    // same decision. One env policy for everything the broker execs, so there is no second
    // path to keep in sync.
    let child = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .envs(submit_env("running a query"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .spawn()?;
    let pid = child.id() as i32;
    let finished = Arc::new(AtomicBool::new(false));
    let killed = Arc::new(AtomicBool::new(false));
    let (f2, k2) = (finished.clone(), killed.clone());
    let watchdog = std::thread::spawn(move || {
        let step = std::time::Duration::from_millis(100);
        let mut waited = std::time::Duration::ZERO;
        while waited < timeout {
            if f2.load(Ordering::Relaxed) {
                return; // child finished; don't linger (fast queries aren't delayed)
            }
            std::thread::sleep(step);
            waited += step;
        }
        if !f2.load(Ordering::Relaxed) {
            k2.store(true, Ordering::Relaxed);
            // SAFETY: kill(2) with a NEGATIVE pid = the child's process group (it leads
            // its own group via process_group(0)), killing the whole subtree. The child
            // is still unreaped here (wait_with_output has not returned), so the pgid is
            // valid and not reused.
            unsafe { libc_kill(-pid, SIGKILL) };
        }
    });
    let out = child.wait_with_output();
    finished.store(true, Ordering::Relaxed);
    let _ = watchdog.join();
    out.map(|o| (o, killed.load(Ordering::Relaxed)))
}

/// Capture bytes as (lossy) UTF-8, truncated to MAX_QUERY_OUTPUT so a chatty
/// read-only query can't bloat the spool response.
fn cap_output(bytes: &[u8]) -> String {
    if bytes.len() <= MAX_QUERY_OUTPUT {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let mut s = String::from_utf8_lossy(&bytes[..MAX_QUERY_OUTPUT]).into_owned();
    s.push_str("\n... [husk: output truncated at 1 MiB]\n");
    s
}

/// Environment variables stripped from the submission, so no brokered job can run with a
/// WEAKENED enforcement layer.
///
/// `SECCOMP_WRAPPER_DEBUG=1` makes seccomp-wrapper return `ENOSYS` instead of killing —
/// i.e. blocked syscalls proceed to return, and the program carries on. That is an
/// off-switch, and `--export=ALL` would otherwise carry it from the launching shell into
/// every job. A diagnostic mode may change what we OBSERVE, never what we ENFORCE (the
/// same reason the broker has `--dry-run` and not a debug mode): to identify a blocked
/// syscall, re-run the job under `strace` INSIDE the unchanged cage — the filter still
/// kills, strace merely shows which call it died attempting.
/// The second category is CREDENTIALS THE JOB HAS NO USE FOR. The broker inherits the
/// launching session's environment and forces `--export=ALL`, so an agent's model
/// credentials would otherwise ride into every compute job — where nothing needs them,
/// since a brokered job has no network at all today. Stripping them here is stronger than
/// masking them in the cage (F4): the value never leaves the login node, so it is absent
/// from slurmd's copy of the environment and from anything that inspects a running job.
///
/// These are bearer tokens that buy paid inference (`CSCS_INFERENCE_API_KEY` is the CSCS
/// one, `ANTHROPIC_AUTH_TOKEN` the form Claude Code uses against an
/// Anthropic-compatible endpoint). `ANTHROPIC_BASE_URL`/`ANTHROPIC_MODEL` are deliberately
/// NOT here: they are not secrets, and a job that somehow carried them can do nothing with
/// them without a token or a route.
///
/// This is the submission surface only. Preventing the AGENT from redirecting its own
/// model traffic — `ANTHROPIC_BASE_URL` pointed at a host husk did not intend — needs husk
/// to own the login environment, which is ROADMAP step 6a.
/// **Superseded by the allowlist below — kept only as the list of names that must never
/// come back**, so a future widening of `SUBMIT_ENV_ALLOW_*` cannot silently re-admit them.
const STRIPPED_SUBMIT_ENV: &[&str] = &[
    "SECCOMP_WRAPPER_DEBUG",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CSCS_INFERENCE_API_KEY",
];

/// What may cross from the broker's login environment into a job. **An allowlist.**
///
/// The four names above were a denylist, and a denylist is a bug list: it protected exactly
/// the four credentials someone had thought of. `--export=ALL` hands slurmd the broker's
/// whole environment, and the broker inherits the human's login shell — so every OTHER
/// secret in it rode into the job unremarked. The reviewer's case was `GH_TOKEN`, but the
/// shape is general: `*_TOKEN`, a cloud key, a database URL with a password in it, anything
/// a scientist exported once. And the job that receives it is the AGENT's job: it reads its
/// own environment, and egress now exists.
///
/// So the direction of failure is inverted. An unrecognised variable is DROPPED, which
/// costs at worst a setting, instead of FORWARDED, which costs a credential. This is the
/// same move as the sbatch option registry (F13/F14/F24/F26/F27): construct what is allowed
/// rather than subtract what is feared.
///
/// The list is generous on purpose — it has to keep a real ICON run working, and the thing
/// husk must not do is quietly break the science. `--export=ALL` is load-bearing for the
/// live uenv view's PATH, so PATH and the toolchain/fabric families stay. If something is
/// missing, it is missing LOUDLY: every dropped name is reported to the broker's own log
/// (names, never values), and `HUSK_SUBMIT_ENV_ALLOW` extends the list without a rebuild.
/// That variable is read from the broker's environment, which is the human's login shell —
/// the same trust level as `HUSK_SLURM_PARTITION`, and not something the caged agent can
/// reach.
const SUBMIT_ENV_ALLOW_EXACT: &[&str] = &[
    // Identity and locale. HOME is needed for the guard's own log; USER/LOGNAME for
    // accounting; TZ/LANG so timestamps and number formats match the login node.
    "HOME", "USER", "LOGNAME", "SHELL", "TERM", "TZ", "LANG", "HOSTNAME", "TMPDIR", "PWD",
    // Toolchain search paths. PATH carries the active uenv view, which is the whole reason
    // --export=ALL exists.
    "PATH", "LD_LIBRARY_PATH", "LIBRARY_PATH", "CPATH", "MANPATH", "PKG_CONFIG_PATH",
    "PYTHONPATH", "PERL5LIB", "JULIA_DEPOT_PATH", "R_LIBS", "R_LIBS_USER",
    // Environment-module state. `module` is exported as a shell FUNCTION, and without these
    // a job script's `module load` fails with nothing that explains why.
    "MODULEPATH", "MODULESHOME", "LOADEDMODULES", "_LMFILES_", "MODULEPATH_ROOT",
    // Threading. Dropping these silently changes how a run PERFORMS, which is the hardest
    // kind of difference to trace back to a sandbox.
    "OMP_NUM_THREADS", "OMP_PLACES", "OMP_PROC_BIND", "OMP_STACKSIZE", "MKL_NUM_THREADS",
    // Build toolchain. Measured on Balfrin: all of these are set in a real login shell and
    // all were dropped by the first version of this list.
    "ACLOCAL_PATH", "CMAKE_PREFIX_PATH", "BOOST_ROOT", "PROJ_LIB", "NVHPC_CUDA_HOME",
    "MPICC", "MPICXX", "MPIF77", "MPIF90",
    "JAVA_HOME", "JAVA_BINDIR", "JDK_HOME", "JRE_HOME", "SDK_HOME",
    "CARGO_HOME", "RUSTUP_HOME", "LM_SETUP_DIR",
    // The module system's version pair — `MODULEPATH` and friends were here from the start,
    // these two were not, and `module` is not obliged to work with half its state.
    "MODULE_VERSION", "MODULE_VERSION_STACK",
    // uenv's squashfs mount forwards its library path in this one variable. A uenv job that
    // loses it loses the stack it was launched with, which is the entire point of the uenv.
    "SQFSMNT_FWD_LD_LIBRARY_PATH",
    // Node/site identity. Cheap, non-secret, and run scripts branch on them.
    "CLUSTER_NAME", "INFRANAME", "HOST", "HOSTTYPE", "MACHTYPE", "OSTYPE", "CPU",
    "LUSTRE_JOB_ID",
];

/// Site paths and site-specific families. **Split out from the list above on purpose**: that
/// one is "what any HPC job needs", this one is "what THIS site's job scripts reference", and
/// the two rot at different rates. An operator on another cluster extends this — or, without
/// a rebuild, `HUSK_SUBMIT_ENV_ALLOW`.
///
/// Derived from a measured Balfrin login shell (2026-08-05), not from imagination: the first
/// version of the allowlist dropped 82 variables and this is the subset a real run needs.
/// `$SCRATCH` alone appears in nearly every run script CSCS ships.
const SUBMIT_ENV_ALLOW_SITE: &[&str] = &["SCRATCH", "PROJECT", "STORE", "APPS"];

/// Families that may cross, matched by prefix. Every one of these is a SETTING namespace —
/// scheduler, fabric, MPI, GPU runtime, module system, I/O library, or husk's own.
///
/// `BASH_FUNC_` is here because `module` is a shell function and HPC job scripts call it.
/// It would be a serious hole if the confined side could set it; it cannot — this is the
/// broker's environment, inherited from the human's login shell before the agent exists.
const SUBMIT_ENV_ALLOW_PREFIX: &[&str] = &[
    "LC_",                                   // locale
    "SLURM_", "SBATCH_", "SRUN_", "SALLOC_", // scheduler (husk's CLI outranks all of it)
    "UENV_", "USER_ENV_",                    // uenv view
    "HUSK_",                                 // husk's own; the rank path reserves it
    "LMOD_", "BASH_FUNC_",                   // module system (and its shell function)
    "CRAY_", "PE_", "PMI_", "PMIX_", "FI_", "UCX_", // fabric / process management
    "MPICH_", "OMPI_", "MV2_", "NCCL_",      // MPI + collectives
    "CUDA_", "NVIDIA_", "ROCR_", "HIP_", "HSA_", // GPU runtimes
    "HDF5_", "NETCDF", "ECCODES_", "GRIB_",  // I/O libraries a weather model needs
    "OMP_", "GOMP_", "KMP_",                 // threading
    "SPACK_", "EBROOT", "EBVERSION",         // package managers
    "GT4PY_",                                // GridTools4Py — ICON's Python dycore path
    "OPR_",                                  // MeteoSwiss operational environment
    "XDG_",                                  // config/data search paths some tools require
];

/// Split `HUSK_SUBMIT_ENV_ALLOW` (colon-separated, `NAME` or `PREFIX*`) into extra rules.
fn extra_submit_env_rules() -> (Vec<String>, Vec<String>) {
    let (mut exact, mut prefix) = (Vec::new(), Vec::new());
    if let Ok(v) = std::env::var("HUSK_SUBMIT_ENV_ALLOW") {
        for item in v.split(':').map(str::trim).filter(|s| !s.is_empty()) {
            match item.strip_suffix('*') {
                Some(p) if !p.is_empty() => prefix.push(p.to_string()),
                _ => exact.push(item.to_string()),
            }
        }
    }
    (exact, prefix)
}

/// May `name` cross into a job? The credential denylist wins over every allow rule,
/// including an operator's — those four names are the ones husk knows buy inference.
fn submit_env_allows(name: &str, extra_exact: &[String], extra_prefix: &[String]) -> bool {
    if STRIPPED_SUBMIT_ENV.contains(&name) {
        return false;
    }
    SUBMIT_ENV_ALLOW_EXACT.contains(&name)
        || SUBMIT_ENV_ALLOW_SITE.contains(&name)
        || SUBMIT_ENV_ALLOW_PREFIX.iter().any(|p| name.starts_with(p))
        || extra_exact.iter().any(|e| e == name)
        || extra_prefix.iter().any(|p| name.starts_with(p.as_str()))
}

/// Partition an environment into (forwarded, dropped-names). Pure, so the policy can be
/// tested without mutating the test process's own environment.
fn filter_submit_env(
    vars: impl Iterator<Item = (String, String)>,
    extra_exact: &[String],
    extra_prefix: &[String],
) -> (Vec<(String, String)>, Vec<String>) {
    let (mut kept, mut dropped) = (Vec::new(), Vec::new());
    for (k, v) in vars {
        if submit_env_allows(&k, extra_exact, extra_prefix) {
            kept.push((k, v));
        } else {
            dropped.push(k);
        }
    }
    (kept, dropped)
}

/// Build the environment a brokered SLURM command runs with, and SAY what was dropped.
///
/// The report is names-only and goes to the broker's stderr — outside the cage, in husk's
/// own log. A dropped variable that breaks a run must be diagnosable in one look; that is
/// the difference between an allowlist someone can live with and one they turn off. It also
/// carries the remedy, because "husk removed something" without "here is how to keep it" is
/// the unattributed denial this project keeps having to fix.
fn submit_env(reason: &str) -> Vec<(String, String)> {
    let (extra_exact, extra_prefix) = extra_submit_env_rules();
    let (kept, mut dropped) = filter_submit_env(std::env::vars(), &extra_exact, &extra_prefix);
    if !dropped.is_empty() {
        dropped.sort();
        eprintln!(
            "husk-broker: {reason}: {} login variable(s) not forwarded to SLURM: {}",
            dropped.len(),
            dropped.join(" ")
        );
        eprintln!(
            "husk-broker:   husk forwards an ALLOWLIST, because --export=ALL would otherwise \
             hand every secret in your login shell to a job the agent controls. If a job \
             needs one of these, export HUSK_SUBMIT_ENV_ALLOW='NAME:PREFIX*' before \
             launching husk."
        );
    }
    kept
}

fn run_sbatch(argv: &[String], script: &str) -> Result<u64, String> {
    run_sbatch_with(argv, script, std::time::Duration::from_secs(SUBMIT_TIMEOUT_SECS))
}

fn run_sbatch_with(
    argv: &[String],
    script: &str,
    timeout: std::time::Duration,
) -> Result<u64, String> {
    use std::io::Write;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    // Default-deny the environment, not default-forward. `env_clear` first, so a variable
    // reaches the job because it is on the allowlist and for no other reason — the same
    // reason the option registry rejects what it does not recognise.
    cmd.env_clear();
    cmd.envs(submit_env("submitting a job"));
    // The script arrives on stdin, so no file exists for anyone to substitute. See `submit`.
    //
    // And it runs under a watchdog, in its own process group, exactly like `run_query_cmd`.
    // This is a single-threaded broker: whatever blocks here blocks every later request,
    // and the request that matters most is the one that stops a job. A submission that
    // hangs used to take `scancel` down with it, so the agent could no longer cancel the
    // very job whose submission was wedged.
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| format!("failed to run sbatch: {e}"))?;
    let pid = child.id() as i32;
    let finished = Arc::new(AtomicBool::new(false));
    let killed = Arc::new(AtomicBool::new(false));
    let (f2, k2) = (finished.clone(), killed.clone());
    let watchdog = std::thread::spawn(move || {
        let step = std::time::Duration::from_millis(100);
        let mut waited = std::time::Duration::ZERO;
        while waited < timeout {
            if f2.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(step);
            waited += step;
        }
        if !f2.load(Ordering::Relaxed) {
            k2.store(true, Ordering::Relaxed);
            // SAFETY: negative pid = the child's own process group, so a shell that spawned
            // helpers goes too. Still unreaped here, so the pgid is valid and not reused.
            unsafe { libc_kill(-pid, SIGKILL) };
        }
    });
    // Small enough to fit the pipe buffer, so this cannot itself block for long; and if
    // sbatch has already died the write fails rather than hanging.
    let write_result = child
        .stdin
        .take()
        .ok_or_else(|| "sbatch stdin unavailable".to_string())
        .and_then(|mut si| {
            si.write_all(script.as_bytes())
                .map_err(|e| format!("failed to send the job script to sbatch: {e}"))
        });
    let out = child.wait_with_output();
    finished.store(true, Ordering::Relaxed);
    let _ = watchdog.join();
    if killed.load(Ordering::Relaxed) {
        return Err(format!(
            "sbatch did not return within {}s and was killed. The job may or may not have \
             been submitted — check with squeue before resubmitting, so you do not start it \
             twice. This is usually the scheduler being unreachable or overloaded, not \
             anything about this job.",
            timeout.as_secs()
        ));
    }
    write_result?;
    let output = out.map_err(|e| format!("failed to run sbatch: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "sbatch failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    // With --parsable, sbatch prints "<jobid>" or "<jobid>;<cluster>".
    let stdout = String::from_utf8_lossy(&output.stdout);
    let first = stdout.split([';', '\n']).next().unwrap_or("").trim();
    first
        .parse::<u64>()
        .map_err(|_| format!("could not parse job id from sbatch output: {stdout:?}"))
}

/// A request `id` is used to build spool file names (`resp-<id>.json`, `job-<id>.sh`),
/// i.e. a path component chosen by the untrusted agent. Restrict it to characters that
/// cannot traverse or escape the spool directory: ASCII alphanumerics, '-', '_'. The
/// stub sends a UUID, which satisfies this; anything with '/', '.', NUL, etc. is rejected.
pub(crate) fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Read a spool file without following a symlink at the final component (F5).
pub(crate) fn read_nofollow(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "out".to_string());
    let tmp = path.with_file_name(format!(".{name}.tmp"));
    {
        // create_new + O_NOFOLLOW: the spool is agent-writable and this tmp name is
        // predictable, so refuse to open it if it already exists or is a symlink —
        // never write THROUGH a pre-planted symlink to an out-of-spool file (F1).
        // (`id` is validated in decide_response, so the tmp stays inside the spool.)
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {

    #[test]
    fn model_credentials_are_stripped_from_the_submission() {
        // The broker inherits the launching session's environment and forces
        // --export=ALL, so without this an agent's inference token rides into every
        // compute job - which has no network and no use for it. Stripping at submission
        // is stronger than masking in the cage: the value never leaves the login node.
        for k in ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CSCS_INFERENCE_API_KEY"] {
            assert!(STRIPPED_SUBMIT_ENV.contains(&k), "{k} must not reach a job");
        }
        // The enforcement off-switch stays stripped for a different reason: a job must
        // never run with a weakened filter.
        assert!(STRIPPED_SUBMIT_ENV.contains(&"SECCOMP_WRAPPER_DEBUG"));
        // Not secrets, and useless without a token or a route - stripping them would be
        // noise rather than defence.
        for k in ["ANTHROPIC_BASE_URL", "ANTHROPIC_MODEL"] {
            assert!(!STRIPPED_SUBMIT_ENV.contains(&k), "{k} is not a credential");
        }
    }
    use super::*;
    use std::os::unix::fs::symlink;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("husk-spool-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    // F1: the agent-writable spool means an attacker can pre-plant the (predictable)
    // `.resp-<id>.json.tmp` path as a symlink to an out-of-spool file. write_atomic
    // must NOT follow it and clobber that file as the real user; it must fail closed.
    #[test]
    fn write_atomic_refuses_a_planted_symlink_at_the_tmp_path() {
        let dir = scratch("wa-symlink");
        let victim = dir.join("victim"); // stands in for ~/.ssh/authorized_keys, etc.
        fs::write(&victim, b"ORIGINAL").unwrap();
        let target = dir.join("resp-pwn.json");
        let tmp = dir.join(".resp-pwn.json.tmp");
        symlink(&victim, &tmp).unwrap();

        let r = write_atomic(&target, b"ATTACKER-CONTENT");

        assert_eq!(
            fs::read(&victim).unwrap(),
            b"ORIGINAL",
            "write_atomic followed a planted symlink and overwrote an out-of-spool file"
        );
        assert!(r.is_err(), "write_atomic must fail closed when its tmp path is pre-planted");
        let _ = fs::remove_dir_all(&dir);
    }

    // F1: an agent-controlled id must not be allowed to traverse/escape the spool.
    #[test]
    fn is_valid_id_accepts_uuid_rejects_path_tricks() {
        assert!(is_valid_id("f1e2d3c4-5678-90ab-cdef-1234567890ab")); // a UUID
        assert!(is_valid_id("abc_123-XYZ"));
        assert!(!is_valid_id("")); // empty
        assert!(!is_valid_id("../../etc/cron.d/x")); // traversal
        assert!(!is_valid_id("a/b")); // slash
        assert!(!is_valid_id("..")); // dot-dot
        assert!(!is_valid_id("a.b")); // dot (could compose ..)
        assert!(!is_valid_id("a b")); // space
        assert!(!is_valid_id(&"x".repeat(200))); // overlong
    }

    // F5: process_once must skip a req-*.json that is a symlink (don't read through it),
    // while still processing a normal regular-file request.
    #[test]
    fn process_once_skips_symlinked_request() {
        let dir = scratch("po-symlink");
        // A symlinked "request" pointing out of the spool — must be ignored, not consumed.
        let elsewhere = dir.join("elsewhere.json");
        fs::write(&elsewhere, b"{}").unwrap();
        let sym_req = dir.join("req-sym.json");
        symlink(&elsewhere, &sym_req).unwrap();
        // A genuine regular-file request (a read-only query; dry-run) — must be processed.
        let real_req = dir.join("req-aaaa-bbbb.json");
        fs::write(
            &real_req,
            br#"{"version":1,"id":"aaaa-bbbb","tool":"squeue","submitted_at":"t","cwd":"/tmp","argv":[],"script":{"source":"none","body":""},"job_args":[],"env":{}}"#,
        )
        .unwrap();

        let broker = Broker {
            spool: dir.clone(),
            session: Session { uenv: None, view: None, allowed_partitions: vec!["preemptible".into()], account: None, limits: Default::default() },
            dry_run: true,
            fs_policy: FsPolicy::default(),
            submitted: Default::default(),
            project_dir: PathBuf::from("/work"),
        };
        broker.process_once().unwrap();

        assert!(
            fs::symlink_metadata(&sym_req).is_ok(),
            "symlinked req was consumed/followed — it must be skipped"
        );
        assert!(!real_req.exists(), "the genuine regular-file request should have been processed");
        let _ = fs::remove_dir_all(&dir);
    }

    // F17: the compute cage must be built from the broker's startup fs_policy (resolved
    // from the TRUSTED project dir), NOT from a settings file the agent plants under an
    // agent-chosen req.cwd. Here the broker's policy is empty; a settings.local.json under
    // the request's cwd tries to grant allowRead:/EVILMARKER — it must be ignored.
    #[test]
    fn cage_ignores_settings_under_agent_cwd() {
        let dir = scratch("f17-cwd");
        // The agent's cwd is a SUBDIRECTORY of the trusted project dir — the realistic
        // shape, and the only one that still submits now that --chdir is confined to the
        // writable set. F17's point is unchanged: the policy comes from the project dir,
        // never from settings the agent planted under the directory it submitted from.
        let proj = dir.join("proj");
        fs::create_dir_all(proj.join(".claude")).unwrap();
        fs::write(
            proj.join(".claude/settings.local.json"),
            br#"{"sandbox":{"filesystem":{"allowRead":["/EVILMARKER"]}}}"#,
        )
        .unwrap();
        let spool = dir.join("spool");
        fs::create_dir_all(&spool).unwrap();

        let broker = Broker {
            spool: spool.clone(),
            session: Session { uenv: None, view: None, allowed_partitions: vec!["preemptible".into()], account: None, limits: Default::default() },
            dry_run: true,
            fs_policy: FsPolicy::default(),
            submitted: Default::default(),
            project_dir: dir.clone(), // the trusted root; `proj` is a subdirectory of it
        };
        let req_json = format!(
            r##"{{"version":1,"id":"f17id","tool":"sbatch","submitted_at":"t","cwd":"{}","argv":["--partition=preemptible"],"script":{{"source":"file","body":"#!/bin/bash\necho hi\n"}},"job_args":[],"env":{{}}}}"##,
            proj.display()
        );
        fs::write(spool.join("req-f17id.json"), req_json).unwrap();

        broker.process_once().unwrap();

        // The staged job script carries the compute-cage bwrap args; it must not re-expose
        // /EVILMARKER (which only the agent-planted settings under req.cwd would add).
        // On the live path husk's script is never a file — it goes to sbatch on stdin, so
        // there is no path for the agent to substitute. Dry-run keeps an inspectable copy.
        let staged = fs::read_to_string(spool.join("dry-f17id.sh")).expect("guard staged");
        assert!(
            !staged.contains("/EVILMARKER"),
            "cage was built from agent-controlled req.cwd settings: {staged}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // THE OWNERSHIP GATE. "Cancel my own jobs" must never become "cancel this user's
    // jobs": the account also runs production work husk never submitted. The set is built
    // from what sbatch returned, so an id the agent invents is refused by name.
    #[test]
    fn scancel_refuses_a_job_this_session_did_not_submit() {
        let dir = scratch("cancel-own");
        let broker = Broker {
            spool: dir.clone(),
            session: Session { uenv: None, view: None, allowed_partitions: vec!["preemptible".into()], account: None, limits: Default::default() },
            dry_run: true,
            fs_policy: FsPolicy::default(),
            submitted: Default::default(),
            project_dir: PathBuf::from("/work"),
        };
        broker.submitted.borrow_mut().insert(4991406);

        // Ours, including the array-task and step spellings of the same base id.
        for t in ["4991406", "4991406_3", "4991406.0"] {
            let r = broker.cancel("x", vec![t.to_string()]);
            assert_eq!(r.status, "ok", "husk must cancel its own job {t}: {}", r.message);
        }

        // Someone else's — a neighbouring job id is the realistic mistake, and a plausible
        // attack: an agent that guesses ids could otherwise cancel a human's production run.
        let r = broker.cancel("x", vec!["4991407".to_string()]);
        assert_eq!(r.status, "rejected");
        assert!(r.message.contains("4991407"), "name the job refused: {}", r.message);
        assert!(r.message.contains("did not submit"), "{}", r.message);

        // All-or-nothing: one unowned id refuses the batch, so the agent is never told it
        // stopped something it did not.
        let r = broker.cancel("x", vec!["4991406".into(), "4991407".into()]);
        assert_eq!(r.status, "rejected", "a mixed list must not partially cancel");
        let _ = fs::remove_dir_all(&dir);
    }

    // F2/F16: a query that never exits must be killed at the timeout, not wedge the broker.
    #[test]
    fn gc_removes_stale_orphans_but_not_live_requests() {
        let dir = scratch("gc");
        fs::write(dir.join("resp-old.json"), b"{}").unwrap();
        fs::write(dir.join("job-old.sh"), b"x").unwrap();
        fs::write(dir.join(".old.tmp"), b"x").unwrap();
        fs::write(dir.join("req-live.json"), b"{}").unwrap();
        let broker = Broker {
            spool: dir.clone(),
            session: Session { uenv: None, view: None, allowed_partitions: vec!["preemptible".into()], account: None, limits: Default::default() },
            dry_run: true,
            fs_policy: FsPolicy::default(),
            submitted: Default::default(),
            project_dir: PathBuf::from("/work"),
        };
        // cutoff 0 => every orphan (any positive age) is stale and reclaimed.
        broker.gc(std::time::Duration::ZERO);
        assert!(!dir.join("resp-old.json").exists());
        assert!(!dir.join("job-old.sh").exists());
        assert!(!dir.join(".old.tmp").exists());
        assert!(dir.join("req-live.json").exists(), "gc must never remove a live request");
        // A generous cutoff keeps fresh orphans (in-flight responses).
        fs::write(dir.join("resp-fresh.json"), b"{}").unwrap();
        broker.gc(std::time::Duration::from_secs(3600));
        assert!(dir.join("resp-fresh.json").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_query_cmd_kills_a_hanging_command() {
        let argv = vec!["sh".into(), "-c".into(), "sleep 30".into()];
        let (_, timed_out) =
            run_query_cmd(&argv, std::time::Duration::from_millis(300)).unwrap();
        assert!(timed_out, "a query past the timeout must be killed");
    }

    /// The broker is single-threaded and serves one request at a time, so anything that
    /// blocks in it blocks EVERYTHING. `run_query_cmd` has had a watchdog since F2/F16;
    /// its sibling `run_sbatch` was a bare `output()` with no timeout and no process
    /// group. A slurmctld that stops answering — or `#SBATCH --wait`, which the body gate
    /// accepted — wedged the broker for as long as it lasted, and the thing that stops
    /// working with it is `scancel`: the agent could no longer stop the job that did it.
    #[test]
    fn run_sbatch_kills_a_hanging_submission() {
        let argv = vec!["sh".into(), "-c".into(), "sleep 30".into()];
        let e = run_sbatch_with(&argv, "", std::time::Duration::from_millis(300))
            .expect_err("a hanging sbatch must not block the broker forever");
        assert!(e.contains("timed out") || e.contains("did not"), "{e}");
    }

    #[test]
    fn run_sbatch_reads_the_script_from_stdin() {
        // Also pins the Fix 1 property from the other side: the script reaches sbatch as
        // bytes on a pipe, not as a path anyone could have swapped.
        let argv = vec!["sh".into(), "-c".into(), "cat >/dev/null; printf 4242".into()];
        let id = run_sbatch_with(&argv, "#!/bin/bash\necho hi\n", std::time::Duration::from_secs(5))
            .expect("a fast submission must succeed");
        assert_eq!(id, 4242);
    }

    /// The env MEDIUM. `STRIPPED_SUBMIT_ENV` was a four-name denylist, and `--export=ALL`
    /// hands slurmd the broker's whole environment — which is the human's login shell. So
    /// every secret nobody had thought of rode into a job the AGENT controls and can read.
    /// The reviewer's case was `GH_TOKEN`; the point is that there is no end to that list.
    #[test]
    fn the_submission_environment_is_an_allowlist_so_an_unlisted_secret_cannot_ride_along() {
        let env: Vec<(String, String)> = [
            // Secrets that were NOT among the four, i.e. exactly what the denylist missed.
            ("GH_TOKEN", "ghp_secret"),
            ("GITHUB_TOKEN", "ghp_secret"),
            ("AWS_SECRET_ACCESS_KEY", "aws"),
            ("OPENAI_API_KEY", "sk-x"),
            ("DATABASE_URL", "postgres://u:pw@h/db"),
            ("MY_COMPANY_VPN_PASSWORD", "hunter2"),
            // …and the four that were.
            ("ANTHROPIC_API_KEY", "sk-ant"),
            ("CSCS_INFERENCE_API_KEY", "cscs"),
            // What a real run genuinely needs, which is why this cannot just be "drop all".
            ("PATH", "/user-environment/env/icon/bin:/usr/bin"),
            ("LD_LIBRARY_PATH", "/user-environment/env/icon/lib"),
            ("UENV_VIEW", "/user-environment:icon:default"),
            ("SLURM_CONF", "/etc/slurm/slurm.conf"),
            ("MODULEPATH", "/opt/cray/modulefiles"),
            ("BASH_FUNC_module%%", "() { eval `modulecmd bash $*`; }"),
            ("MPICH_GPU_SUPPORT_ENABLED", "1"),
            ("OMP_NUM_THREADS", "12"),
            ("HOME", "/users/me"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        let (kept, dropped) = filter_submit_env(env.into_iter(), &[], &[]);
        let kept_names: Vec<&str> = kept.iter().map(|(k, _)| k.as_str()).collect();

        for secret in [
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "OPENAI_API_KEY",
            "DATABASE_URL",
            "MY_COMPANY_VPN_PASSWORD",
            "ANTHROPIC_API_KEY",
            "CSCS_INFERENCE_API_KEY",
        ] {
            assert!(
                !kept_names.contains(&secret),
                "{secret} reached the job — with a denylist it would have, which was the bug"
            );
            assert!(dropped.iter().any(|d| d == secret), "{secret} must be reported as dropped");
        }
        // A denial that breaks the science is a denial nobody keeps. The families a real
        // ICON run needs must survive, or husk has traded a leak for an outage.
        for needed in [
            "PATH",
            "LD_LIBRARY_PATH",
            "UENV_VIEW",
            "SLURM_CONF",
            "MODULEPATH",
            "BASH_FUNC_module%%",
            "MPICH_GPU_SUPPORT_ENABLED",
            "OMP_NUM_THREADS",
            "HOME",
        ] {
            assert!(kept_names.contains(&needed), "{needed} must still reach the job");
        }
    }

    #[test]
    fn the_allowlist_carries_what_a_measured_balfrin_login_shell_actually_provides() {
        // Written from the FIRST HARDWARE RUN, not from imagination: the first version of
        // this allowlist dropped 82 variables from a real Balfrin login shell, and this is
        // the subset a real run needs. `$SCRATCH` alone appears in nearly every run script
        // CSCS ships, and losing `SQFSMNT_FWD_LD_LIBRARY_PATH` costs a uenv job the stack it
        // was launched with — the entire point of the uenv.
        let env: Vec<(String, String)> = [
            "SCRATCH", "PROJECT", "STORE", "APPS",
            "SQFSMNT_FWD_LD_LIBRARY_PATH", "MODULE_VERSION", "MODULE_VERSION_STACK",
            "CMAKE_PREFIX_PATH", "BOOST_ROOT", "MPICC", "MPIF90", "NVHPC_CUDA_HOME",
            "OPR_HOME", "OPR_MODULEFILES", "GT4PY_BUILD_JOBS", "CLUSTER_NAME", "LUSTRE_JOB_ID",
        ]
        .iter()
        .map(|k| (k.to_string(), "v".to_string()))
        .collect();
        let (kept, dropped) = filter_submit_env(env.into_iter(), &[], &[]);
        assert!(dropped.is_empty(), "a real run still needs these: {dropped:?}");
        assert_eq!(kept.len(), 17);

        // …and the same run confirms what the allowlist is FOR. `SSH_AUTH_SOCK` is a live
        // agent-forwarding socket — a credential by any measure — and the old denylist
        // handed it to every job. It stays dropped, along with the desktop noise.
        let noise: Vec<(String, String)> = ["SSH_AUTH_SOCK", "SSH_CLIENT", "DBUS_SESSION_BUS_ADDRESS",
                                            "DISPLAY", "LS_COLORS", "XAUTHLOCALHOSTNAME"]
            .iter()
            .map(|k| (k.to_string(), "v".to_string()))
            .collect();
        let (kept, _) = filter_submit_env(noise.into_iter(), &[], &[]);
        assert!(kept.is_empty(), "a batch job needs none of these: {kept:?}");
    }

    #[test]
    fn the_credential_denylist_outranks_every_allow_rule_including_the_operators() {
        // The operator escape hatch exists so a missing setting is fixable without a
        // rebuild. It must not be a way — accidental or otherwise — to put the inference
        // credentials back on the wire: those are the ones husk KNOWS buy paid compute.
        let extra_exact = vec!["ANTHROPIC_API_KEY".to_string()];
        let extra_prefix = vec!["ANTHROPIC".to_string(), "CSCS_".to_string()];
        let env: Vec<(String, String)> = [("ANTHROPIC_API_KEY", "sk"), ("CSCS_INFERENCE_API_KEY", "k")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let (kept, _) = filter_submit_env(env.into_iter(), &extra_exact, &extra_prefix);
        assert!(kept.is_empty(), "the credential denylist must win: {kept:?}");
    }

    #[test]
    fn a_brokered_command_actually_runs_with_the_filtered_environment() {
        // The rules above are policy; this is the wiring. `cargo test` sets CARGO_PKG_NAME
        // in this process and it is on no allowlist, so if the child can see it then
        // `env_clear` is not in the path that matters and the policy is decoration.
        assert!(std::env::var("CARGO_PKG_NAME").is_ok(), "precondition: cargo sets this");
        let argv = vec!["sh".into(), "-c".into(), "env".into()];
        let (out, _) = run_query_cmd(&argv, std::time::Duration::from_secs(5)).unwrap();
        let seen = String::from_utf8_lossy(&out.stdout);
        assert!(
            !seen.lines().any(|l| l.starts_with("CARGO_PKG_NAME=")),
            "an unlisted variable reached the child: {seen}"
        );
        assert!(seen.lines().any(|l| l.starts_with("PATH=")), "PATH must survive: {seen}");
    }

    #[test]
    fn run_query_cmd_returns_fast_command_output() {
        let argv = vec!["sh".into(), "-c".into(), "printf hello".into()];
        let (out, timed_out) =
            run_query_cmd(&argv, std::time::Duration::from_secs(5)).unwrap();
        assert!(!timed_out, "a fast query must not be flagged timed out");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "hello");
    }
}
