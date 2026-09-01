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

/// Linux `O_NOFOLLOW` and `O_DIRECTORY`, and **the one place in this binary that says which
/// architecture spells them which way** (`N1-3`).
///
/// `O_NOFOLLOW` makes an open refuse to traverse a symlink at the final path component;
/// `O_DIRECTORY` makes it refuse anything that is not a directory. The spool is
/// agent-writable, so every spool open uses one or both (F1/F5, and `main.rs`'s
/// `O_NOFOLLOW_DIRECTORY`, which is now derived from these two rather than restating them).
///
/// **PER ARCHITECTURE, because the kernel defines them per architecture.** This was the bare
/// asm-generic `0o400000` with no `cfg`, and arm64 overrides that block. The evidence, quoted
/// rather than recalled — `/usr/src/linux-hwe-6.8-headers-6.8.0-136/arch/arm64/include/uapi/
/// asm/fcntl.h`, lines 20-28, byte-identical in the `-139` package:
///
/// ```text
/// /*
///  * Using our own definitions for AArch32 (compat) support.
///  */
/// #define O_DIRECTORY   040000  /* must be a directory */
/// #define O_NOFOLLOW   0100000  /* don't follow links */
/// #define O_DIRECT     0200000  /* direct disk access hint - currently ignored */
/// #define O_LARGEFILE  0400000
///
/// #include <asm-generic/fcntl.h>
/// ```
///
/// The `#include` on the last line is the mechanism: `asm-generic/fcntl.h` guards all three
/// with `#ifndef`, so an architecture that defines them FIRST wins. **So `0o400000` is
/// `O_NOFOLLOW` on Balfrin and `O_LARGEFILE` on Santis**, and `O_LARGEFILE` is a no-op in a
/// 64-bit build: the open succeeded, followed the symlink, and said nothing. `P7` — a control
/// that can fail silently has already failed — and `P15`, because the flag is what makes the
/// name resolve to the object husk meant.
///
/// **Beware of checking this the obvious way.** `grep` over `/usr/include` on an x86_64 box
/// finds only the asm-generic pair and no override, which reads as proof that none exists — it
/// is `linux-libc-dev:amd64`, there is no `/usr/include/aarch64-linux-gnu`, and it could not
/// report anything else. That is evidence about the machine, not about aarch64, and it is how
/// this constant was first challenged.
///
/// **ONE LIST, not two that agree (`P8`, and it is the second half of `N1-3`).** Until this
/// change the same five architecture names were written out four times — twice here and twice
/// at `main.rs`'s `O_NOFOLLOW_DIRECTORY` — and the test documented as keeping them identical
/// compared two *values on the compiled target*, which on an x86_64 build host both take the
/// `not(any(...))` arm whatever the lists contain. A reviewer deleted `aarch64` from one of the
/// two lists — silently restoring the exact Santis bug — and the suite stayed byte-identical
/// green. `cfg!` yields the answer as a `bool`, so the list is written once, both flags derive
/// from it, `main.rs` derives from these, and the mutation can no longer be expressed. What the
/// list itself contains is pinned lexically, on the build host, by
/// `the_architecture_list_behind_these_flags_is_stated_exactly_once`.
///
/// The overriding architectures, from the whole kernel tree, are alpha, arm, arm64, m68k, parisc
/// and powerpc; mips and sparc take the generic values — both checked. Of those, the names below
/// are the ones `rustc` can actually target: there is no alpha and no hppa/parisc triple in
/// `rustc --print target-list`, so their absence is correct rather than a gap (`RHGN`, which
/// refuted the earlier note that called it one). An architecture missing from the list gets the
/// asm-generic pair rather than a `compile_error!`, deliberately: refusing to build on an
/// unlisted login node is an outage, a red test is a message.
///
/// **And the number is not what the two READ sites trust.** `read_verified` compares the
/// identity of the opened descriptor with the identity of the name it checked, so the refusal
/// holds even where these constants are wrong — see
/// `a_swapped_spool_entry_is_refused_even_when_the_open_flag_does_nothing`, which passes
/// `flags = 0`, the exact state an inert constant produces, and fails on x86_64 today. What the
/// flag buys on top is a refusal IN THE KERNEL, one syscall earlier, which is what stops a
/// symlink-to-FIFO from blocking `open` forever — a check after the open cannot help with a
/// hang inside it. Measured, against the real `read_nofollow`: with the flag,
/// `symlink -> FIFO` returns `ELOOP` in 11 us; without it, still inside `open(2)` after
/// 1500 ms (`RHGN`).
pub(crate) const FCNTL_OVERRIDDEN_BY_THIS_ARCH: bool = cfg!(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "m68k",
    target_arch = "powerpc",
    target_arch = "powerpc64",
));

/// Refuse a symlink at the final path component. See `FCNTL_OVERRIDDEN_BY_THIS_ARCH`.
pub(crate) const O_NOFOLLOW: i32 = if FCNTL_OVERRIDDEN_BY_THIS_ARCH { 0o100_000 } else { 0o400_000 };

/// Refuse anything that is not a directory. See `FCNTL_OVERRIDDEN_BY_THIS_ARCH`.
pub(crate) const O_DIRECTORY: i32 = if FCNTL_OVERRIDDEN_BY_THIS_ARCH { 0o40_000 } else { 0o200_000 };

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
    /// Where the user-level settings live. Held so submit time can re-check that the
    /// settings the COMPUTE side will re-read still parse — checked, never adopted; the
    /// authoritative policy stays the one captured at startup. (F17)
    pub home: PathBuf,
    /// Job ids this broker submitted, and the ONLY ones it will cancel.
    ///
    /// Trusted state: it is built from what `sbatch --parsable` returned, never from
    /// anything the agent sent. In memory rather than on disk deliberately — the spool is
    /// agent-writable, so a persisted list would be a list the confined side could edit,
    /// which is precisely the authority this is meant to hold. The cost is that a restarted
    /// broker disowns earlier jobs; they are then cancellable by the human, which is the
    /// right way for that to fail.
    pub submitted: std::cell::RefCell<std::collections::BTreeMap<u64, String>>,
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
        // The settings the COMPUTE side will re-read must still parse, or this job is
        // already doomed and does not know it.
        //
        // The step broker resolves the policy again on the compute node, per job, and fails
        // closed if it cannot. That is right. But this broker resolved it once at startup
        // and cached it, so an edit made after the session began is invisible here and fatal
        // there — submissions keep succeeding while every job's step broker dies re-reading
        // the same file. On Balfrin 2026-08-06 that cost five or six jobs, each hanging to
        // its walltime, from one empty `.claude/settings.json`.
        //
        // CHECKED, NOT ADOPTED. The cached policy stays authoritative: it was captured from
        // the trusted project dir before the agent ran, and re-resolving here would hand the
        // confined side a way to author its own cage — exactly F17, and exactly the rule
        // that the confined side must not supply its own boundary. So this reads the files
        // only to answer "would the compute side choke on these?" and throws the result away.
        //
        // PARSE-ONLY, and that distinction is load-bearing. This first shipped calling
        // `resolve`, which is a CONSTRUCTION, not a read: it ends in a 20 000-entry, depth-4
        // walk of the workdir whose own comment says "scan-once at construction". Running it
        // per request put that walk on the submission path, and on a Lustre tree the size of
        // a LETKF benchmark every `sbatch` hit the stub's 120s wall — the agent saw only
        // "timed out after 120s waiting for the SLURM broker", with the broker healthy and
        // simply busy stat-ing. Same shape as the original husk freezes.
        if let Err(e) = FsPolicy::settings_parse_ok(&self.home, &self.project_dir) {
            let msg = format!(
                "husk cannot submit this job: {e}\n\
                 That file decides what a job may read and write, and husk's compute-node \
                 half re-reads it when the job starts — so the job would be refused there, \
                 after queueing, with no output. Fix the JSON and resubmit.\n\
                 Note this session is still running on the settings it read at startup; \
                 restart husk once the file is valid if you meant the change to apply."
            );
            eprintln!("broker: refusing id={id} - settings no longer parse: {e}");
            return Some((id.clone(), Response::rejected(&id, msg)));
        }
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
            //
            // OWNED by `SPOOL_OWNED_PATTERNS`'s `dry-` entry (`B4-1`). It was owned by
            // nothing: `gc` skipped it at an hour, the session teardown skipped it, and the
            // stale-spool reaper skipped it forever after, so the directory was permanent and
            // every session that had ever dry-run ended by telling the operator that the
            // spool held "files husk did not create". `--once` still keeps it — that path
            // deliberately leaves the contents of the scan it was asked to make.
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
                self.submitted.borrow_mut().insert(job_id, sub.body_path.clone());
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
            .filter(|t| !policy::cancel_base_id(t).is_some_and(|b| owned.contains_key(&b)))
            .collect();
        if !unowned.is_empty() {
            let known: Vec<String> = owned.keys().map(|j| j.to_string()).collect();
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
            Ok((out, false)) => {
                let rc = out.status.code().unwrap_or(1);
                // Only on success: a scancel that failed ended nothing, and the body must
                // outlive anything that might still read it.
                if rc == 0 {
                    self.reclaim_cancelled_bodies(&targets);
                }
                Response::query(id, cap_output(&out.stdout), cap_output(&out.stderr), rc)
            }
            Ok((_, true)) => {
                Response::error(id, format!("scancel exceeded {QUERY_TIMEOUT_SECS}s and was killed"))
            }
            Err(e) => Response::error(id, format!("could not run scancel: {e}")),
        }
    }

    /// Remove the staged bodies of jobs this cancel ENDED — the third member of the class
    /// "nobody will read this again", which nothing owned before. See
    /// `cancels_that_end_a_job` for why an array TASK is deliberately not one of them.
    ///
    /// The ownership entry is deliberately KEPT: it records what this session submitted, and
    /// dropping it would turn a second `scancel` of the same id into "husk did not submit
    /// that", which is both untrue and a worse message than SLURM's own.
    fn reclaim_cancelled_bodies(&self, targets: &[String]) {
        let owned = self.submitted.borrow();
        let ids: Vec<u64> = owned.keys().copied().collect();
        for job in husk_slurm_broker::cancels_that_end_a_job(targets, &ids) {
            if let Some(path) = owned.get(&job) {
                let _ = fs::remove_file(path);
            }
        }
    }

    /// Reclaim stale orphaned spool files older than `max_age` — a stub that died before
    /// deleting its response, a dry run nobody came back for, a broker crash mid-write.
    ///
    /// WHAT counts as one is not decided here. This used to be a second literal list beside
    /// `SPOOL_OWNED_PATTERNS`, and the two had drifted in both directions: neither knew about
    /// `dry-<id>.sh`, which husk writes (`B4-1`), and both carried `job-*.sh`, which husk
    /// stopped writing after v0.4. One list now, with the mid-session exception carried on
    /// the entry — `req-*.json` is a live request somebody is blocked on, and reclaiming it
    /// here would hang the stub (F4).
    fn gc(&self, max_age: std::time::Duration) {
        let entries = match fs::read_dir(&self.spool) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !husk_slurm_broker::is_reclaimable_orphan(&name) {
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
/// credentials would otherwise ride into every compute job, where nothing needs them.
///
/// This argument used to end "…and a brokered job has no network anyway". That is no
/// longer true — a job with a configured allowlist reaches the internet through the proxy
/// — which makes the strip MORE load-bearing than when it was written, not less. Keeping
/// credentials out is stronger than masking them in the cage (F4): the value never leaves
/// the login node, so it is absent from slurmd's copy of the environment and from anything
/// that inspects a running job.
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
/// The four names above were a denylist, and a denylist is a bug list (`P5`): they were the
/// four credentials someone had thought of. `--export=ALL` hands slurmd the broker's whole
/// environment and the broker inherits the human's login shell, so every other secret in it
/// rode into a job the AGENT controls — measured: `GH_TOKEN`, and a live `SSH_AUTH_SOCK`.
///
/// Inverted here: an unrecognised variable is DROPPED, costing at worst a setting, instead
/// of FORWARDED, costing a credential.
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
    // Shell startup state. SUSE's /etc/profile resets PATH to the distro default
    // (`/usr/local/bin:/usr/bin:/bin`) unless PROFILEREAD is already set, and then marks
    // PROFILEREAD itself readonly, so the latch cannot be cleared once set. (Not PATH —
    // PATH stays writable, which is how a uenv view or `module load` rewrites it in a
    // login shell that already ran /etc/profile.) So an interactive login shell has the
    // latch and `bash -l` is a no-op there, while a brokered job did not — so every
    // `bash -l` inside one silently threw away the PATH husk had just forwarded, taking the
    // uenv view and any venv bin with it. Reported from
    // a real ICON run on a CSCS login node, 2026-08-29, after `bash -l` and `bash` were
    // measured to give byte-identical PATH once the variable is set.
    //
    // Forwarding PATH is therefore not sufficient to deliver PATH, which is the point worth
    // remembering: this list is measured against what a job's shells DO with the environment,
    // not only against what the environment contains.
    //
    // Safe to forward, and the strongest argument is PARITY, not reasoning: an UNBROKERED
    // job on this cluster already carries it — measured, `PROFILEREAD=true` in the task
    // environment of a plain srun probe (`fabric-probe-5021103.out:171` — a local run
    // artifact, not committed; the same dump carries SSH_AUTH_SOCK and DISPLAY, which is
    // how we know that probe was unbrokered). Forwarding it restores what a job outside
    // husk has, rather than granting something new. Beyond that:
    // the value is the string "true", not a secret; and the confined side cannot set it,
    // because this is the broker's own environment, frozen from the human's login shell
    // before the agent exists (same trust level as HUSK_SLURM_PARTITION).
    //
    // PATH ordering is not a containment control here. The INVENTORY is measured: the
    // compute cage HOLDS a real, configured `sbatch`/`salloc`/`squeue`/`scancel`/`scontrol`
    // today, with only `srun` stubbed (job 5169678, recorded in the round-2 findings — a
    // local artifact, not in the repo). Configured not because husk forwards anything: the
    // `SLURM_CONF` husk forwards is REPLACED, measured twice, because slurmd runs configless
    // and points at its own conf-cache.
    //
    // What CONTAINS such a job is believed to be the MUNGE mask plus no route — and that
    // half is asserted in prose in five places and probed only partially; nothing in this
    // repo detonates a real `sbatch` from inside a job (backlog item in ROADMAP.md). The
    // claim being made here is only the negative one, and it does not depend on the open
    // half: whatever stops a re-submission, it is demonstrably not PATH ordering, since a
    // real sbatch sits on PATH inside the cage already. So restoring PATH takes nothing
    // away.
    //
    // On that axis it may tighten the cage slightly, on a site we do not currently run on.
    // The guard resolves `_husk_real_srun=$(command -v srun)` OUTSIDE the cage using the
    // forwarded login PATH and binds the stub over exactly that path (`policy.rs`), so a
    // `bash -l` that reset PATH could resolve `srun` to a DIFFERENT, unstubbed binary than
    // the one the guard masked — but only where `srun` comes from a uenv view. On both
    // Balfrin and Santis `srun` is /usr/bin/srun, inside the distro default, so the effect
    // there is nil. Unmeasured; stated as a direction, not a gain.
    //
    // It does NOT close the residual underneath it: the guard binds ONE resolved path, so a
    // second `srun` anywhere on the system stays real and reachable by absolute path
    // whatever PATH says. That is the `which()`-first-match backlog item in ROADMAP.md, and
    // no PATH-preservation fixes it.
    //
    // The honest cost, so nobody reads this as a pure win: the latch does not suppress only
    // the PATH reset — it suppresses everything else `/etc/profile` guards with the same
    // test, which on SUSE plausibly includes the `/etc/profile.d/*.sh` sourcing loop. If so,
    // a `bash -l` job stops re-sourcing profile.d, and profile.d had been accidentally
    // compensating for gaps in THIS list (candidates already visible in the measured drop
    // lists: `UDUNITS2_XML_PATH`, `SQUASHFS_MOUNT_LIST` — a weather model dies on the first).
    // So the direction of the silent change moved and improved; the silence did not go away.
    // The env-diff oracle on the test below is what would catch the remainder.
    "PROFILEREAD",
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
    // Lmod's serialised module table, measured on SANTIS (Balfrin's module system does not
    // set these, which is why Balfrin's clean run did not reveal them). Lmod encodes what is
    // currently loaded into `_ModuleTable001_`, `_ModuleTable_Sz_` and `__LMOD_REF_COUNT_*`;
    // a job that inherits `MODULEPATH` but not these has a module system that disagrees with
    // itself about what is loaded. Neither matches the `LMOD_` prefix above — one starts with
    // a double underscore, the other is capitalised differently — which is exactly the kind
    // of near-miss an allowlist has to be measured against rather than guessed at.
    "__LMOD_", "_ModuleTable",
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

/// Variables husk's own compute-node guard reads, in SLURM's namespace — so slurmd is
/// their only legitimate author and an inherited value is a lie about THIS job.
///
/// **`RA2-2`/`RA2-3`, and this is the class, not the two instances.** The guard re-derives
/// the file slurmd will open by substituting `settings::OUTPUT_SPECIFIERS`' expansions,
/// every one of which reads an environment variable. Those variables reached the job by two
/// routes: slurmd sets them for the job it is running, and `--export=ALL` copied whatever
/// the broker's own login shell happened to hold. The second route is pollution — the value
/// describes some OTHER job — and the unset guard added for `RA-2` does not see it, because
/// a stale value is present, not empty.
///
/// It is reachable whenever husk is launched from inside a SLURM step: the login shell then
/// carries a full `SLURM_*` set, `SUBMIT_ENV_ALLOW_PREFIX` forwards it, and nothing unsets
/// it. Executed by `RA2`: with `SLURM_ARRAY_JOB_ID=7002` inherited, the guard checked
/// `x7002.log` while slurmd opened `x9999.log`, and a symlink planted at the real leaf was
/// not seen — `A1-F1` and `N1` both disarmed, by an environment variable, on a job that is
/// not an array at all. `%s` is the same shape with no bypass needed.
///
/// So husk removes the competing author instead of modelling it (`P8`: two sources of one
/// fact will drift, so keep the authoritative one; `P15`: the guard NAMES a variable, and
/// the name has to resolve to this job's value). After this, every `SLURM*` value the guard
/// substitutes came from slurmd on the node running the job, which is the only value that
/// can be right.
///
/// **`USER` is deliberately NOT here, and the GROUND has been corrected (`RAB3-A2`).** The
/// rule this function states is "slurmd is the only legitimate author", not "the guard reads
/// it". `USER` fails that test on its own terms: it is the POSIX login identity, it exists
/// before any job does, and the submitting shell IS one of its legitimate authors. That
/// places it outside this class by the class's own definition, and no fact about slurmd is
/// needed to say so.
///
/// This paragraph used to add "and slurmd does not set it for a batch job". That was an
/// UNMEASURED CLAIM ABOUT SLURMD stated as fact, in the very commit that cited `RA-10`'s
/// standing rule against them and appended a correction for breaking it once already
/// (`P12`: a doc drifts toward the intent, and the over-claim always favours the author). It
/// was load-bearing in BOTH directions, which is why it could not be left standing: if
/// slurmd does set `USER` for a batch step, the cost claimed for stripping it is imaginary;
/// if it does not, then the login shell authors a value husk's guard reads on a compute
/// node, which is precisely the class closed above.
///
/// **So this is a named RESIDUAL, not a settled exclusion**, and it belongs beside `SBATCH_*`
/// rather than in a list that reads decided. What husk actually knows: stripping `USER`
/// makes `${USER:-}` empty *unless* slurmd refills it; whether slurmd refills it has never
/// been measured here; so stripping it blind risks the `RA-2` unset guard refusing every job
/// whose `--output` uses `%u` — the operator DoS this round has already produced twice.
/// Meanwhile the damage is bounded but not zero: the guard's `*/*)` and `*%*)` arms turn a
/// wrong `USER` into a wrong LEAF rather than an escaping path, and a wrong leaf is exactly
/// what disarms the `A1-F1` symlink check and `N1`'s hard-link check.
///
/// **One job settles it**, and `RA`'s probe `P2` already asks for it: from a login shell with
/// `USER=notme` exported,
/// `sbatch --export=ALL --wrap='echo "USER=[$USER] SLURM_JOB_USER=[$SLURM_JOB_USER]"'`.
/// If `USER` comes back empty or `notme`, the repair that is NOT a DoS is for the broker to
/// AUTHOR `USER` from the passwd database instead of forwarding the login shell's — closing
/// the class without emptying the variable. Not shipped: the broker has no `libc` dependency,
/// so it is more than a one-liner, and the measurement comes first.
///
/// `no_variable_slurmd_owns_can_be_authored_by_the_login_shell` pins the partition and makes
/// a new table entry state which side it is on.
///
/// What this does NOT close: whether slurmd's own value AGREES with slurmd's own `%`
/// rendering. `%s` renders `batch` (measured, Santis) while `SLURM_STEP_ID` may be set to
/// something else in a batch step (unmeasured — `RA`'s probe `P2`). That is husk's model of
/// slurmd, a different class, and only a job settles it.
fn slurmd_owned_guard_variable(name: &str) -> bool {
    // `SLURM`, not `SLURM_`: `SLURMD_NODENAME` is in the same namespace and misses the
    // underscore. Today the allowlist's `SLURM_` prefix happens not to forward it, which
    // made `%N` safe BY ACCIDENT OF SPELLING rather than by decision (`P15`).
    name.starts_with("SLURM")
        && crate::settings::OUTPUT_SPECIFIERS.iter().any(|s| s.variable() == name)
}

/// Names no allow rule may re-admit, paired with the reason husk prints when it drops one.
/// `None` means `SUBMIT_ENV_ALLOW_*` decides.
///
/// Separate from the allowlist because `submit_env`'s report must not offer
/// `HUSK_SUBMIT_ENV_ALLOW` as the remedy for a name that variable cannot re-admit (`P11`:
/// a denial whose stated remedy does not work is worse than an unattributed one — it is
/// confident wrong remediation, and the operator will conclude husk is broken).
fn never_forwarded(name: &str) -> Option<&'static str> {
    if STRIPPED_SUBMIT_ENV.contains(&name) {
        return Some("a credential that buys inference");
    }
    if slurmd_owned_guard_variable(name) {
        return Some("read by husk's compute-node guard, so only slurmd may set it for a job");
    }
    None
}

/// May `name` cross into a job? `never_forwarded` wins over every allow rule, including an
/// operator's.
fn submit_env_allows(name: &str, extra_exact: &[String], extra_prefix: &[String]) -> bool {
    if never_forwarded(name).is_some() {
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
    let (kept, dropped) = filter_submit_env(std::env::vars(), &extra_exact, &extra_prefix);
    // Two reports, because the two drops have DIFFERENT remedies and one message cannot
    // carry both (`P11`). The allowlist's drops are re-admittable; `never_forwarded`'s are
    // not, and telling an operator to export `HUSK_SUBMIT_ENV_ALLOW` for a name that rule
    // will refuse again sends them to retry a fix that cannot work.
    let (mut refused, mut missing): (Vec<String>, Vec<String>) =
        dropped.into_iter().partition(|n| never_forwarded(n).is_some());
    if !missing.is_empty() {
        missing.sort();
        eprintln!(
            "husk-broker: {reason}: {} login variable(s) not forwarded to SLURM: {}",
            missing.len(),
            missing.join(" ")
        );
        eprintln!(
            "husk-broker:   husk forwards an ALLOWLIST, because --export=ALL would otherwise \
             hand every secret in your login shell to a job the agent controls. If a job \
             needs one of these, export HUSK_SUBMIT_ENV_ALLOW='NAME:PREFIX*' before \
             launching husk."
        );
    }
    if !refused.is_empty() {
        refused.sort();
        // Grouped BY REASON, not one line per name: `submit_env` also runs on every query,
        // and a credential in the launching shell is the normal case rather than the
        // exception. `never_forwarded` holds two reasons today, so this is at most two extra
        // lines per invocation — and the reasons are READ OFF it rather than re-typed here,
        // so a third one reports itself (`P8`).
        let mut reasons: Vec<&'static str> = Vec::new();
        for name in &refused {
            if let Some(why) = never_forwarded(name) {
                if !reasons.contains(&why) {
                    reasons.push(why);
                }
            }
        }
        for why in reasons {
            let names: Vec<&str> = refused
                .iter()
                .filter(|n| never_forwarded(n) == Some(why))
                .map(|n| n.as_str())
                .collect();
            eprintln!(
                "husk-broker: {reason}: never forwarded, and HUSK_SUBMIT_ENV_ALLOW cannot \
                 re-admit them ({why}): {}",
                names.join(" ")
            );
        }
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
///
/// Two callers, both of them a trusted process reading a directory the confined side writes:
/// the login broker's `decide_response` and the step broker's `admit`. Each has already
/// skipped non-regular entries while listing, which is a check on the NAME at the time of the
/// `readdir`; this is the use, and the window between them is as long as whatever the broker
/// did with the previous request — an `sbatch` that may take a minute. `P3`: validation is
/// not enforcement, so the enforcement is here.
pub(crate) fn read_nofollow(path: &Path) -> std::io::Result<Vec<u8>> {
    let named = named_regular_file(path)?;
    read_verified(path, &named, O_NOFOLLOW)
}

/// Step one: is this NAME a regular file right now, and what is its identity?
///
/// `lstat`, so a symlink is refused HERE and never opened — and so is a FIFO, a device or a
/// directory. That last part is not tidiness: `open(2)` on a FIFO with no writer **blocks
/// inside the open**, which no check placed after the open can rescue, and the brokers are
/// single-threaded loops, so one blocked read is the end of brokering for that session.
/// `O_NOFOLLOW` never covered it either — it refuses a symlink, not a FIFO.
///
/// The `Metadata` it returns is not a permission slip; it is the identity `read_verified`
/// will require the descriptor to have. Same two-step, same reason, as `main.rs`'s
/// `named_directory` + `open_verified`.
///
/// **Residual, measured and not fixed here (`P12`).** This closes the DETERMINISTIC FIFO,
/// not the raced one: a name that is a regular file at this `lstat` and a FIFO by the time
/// `read_verified` opens it still blocks forever. Closing that needs `O_NONBLOCK` in the
/// open, which is a THIRD per-architecture flag number (alpha, mips, parisc and sparc
/// override it, and that is a different list again from `O_NOFOLLOW`'s) that nobody on this
/// machine can verify for the machines husk ships to. The exposure is a caged job hanging its
/// own broker — self-harm, one session, no data crosses the boundary — so the trade is to
/// report it rather than to guess at a third constant in the fix whose whole subject is a
/// constant that was guessed at. Written down so the next person finds it named.
fn named_regular_file(path: &Path) -> std::io::Result<fs::Metadata> {
    let md = fs::symlink_metadata(path)?;
    if md.is_file() {
        Ok(md)
    } else {
        Err(not_a_spool_file("it is a symlink, a FIFO, a device or a directory, not a file"))
    }
}

/// Step two: open it, and then **verify what was opened**, on the descriptor.
///
/// **Why an identity check and not just the flag** (`N1-2`, following `20ca07d`'s
/// `open_verified`): `O_NOFOLLOW` is a per-architecture number that nobody on an x86_64
/// machine can execute for aarch64, and it was already wrong once — silently, on Santis, for
/// as long as this constant has existed. A constant nobody here can execute is one review
/// away from being changed back. So the flag stays, because it refuses in the kernel one
/// syscall earlier, and the CORRECTNESS rests on something this machine can run: `lstat`
/// recorded `(dev, ino)`, `fstat` on the descriptor requires the same pair, and therefore the
/// object husk authorised is the object husk reads. If the name was swapped in between, the
/// descriptor is a different inode and husk refuses.
///
/// `named` is a PARAMETER and not something this function re-derives — that is the whole of
/// the fix. A function that `lstat`s and then `open`s cannot be shown to survive a swap
/// between the two, because a test cannot get in between them; a function that is HANDED the
/// earlier identity can be handed one taken before the swap, which is what
/// `a_spool_entry_swapped_after_the_check_is_refused_even_with_an_inert_open_flag` does.
/// `flags` is a parameter for the same kind of reason: so a test can pass `0`, the state an
/// inert constant produces, and prove the refusal does not depend on the number. Production
/// has one caller and it passes `O_NOFOLLOW`.
///
/// **What it does not do, stated rather than implied (`P12`).** A HARD LINK inside the spool
/// to a file outside it is a regular file with one identity, so it passes both this check and
/// `O_NOFOLLOW`; that is unchanged, and it is bounded by a hard link not crossing a
/// filesystem. The read is not size-capped either: a large regular file the confined side
/// wrote in its own spool is read whole, exactly as before.
fn read_verified(path: &Path, named: &fs::Metadata, flags: i32) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    let mut f = fs::OpenOptions::new().read(true).custom_flags(flags).open(path)?;
    let opened = f.metadata()?;
    if !(opened.is_file() && opened.dev() == named.dev() && opened.ino() == named.ino()) {
        return Err(not_a_spool_file(
            "the name was a regular file when husk listed it and a different object when \
             husk opened it",
        ));
    }
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

/// The refusal, in one place so every arm says who refused and why.
///
/// It reaches an operator as `broker: read <path>: <this>`, and an operator who reads only an
/// errno would conclude the filesystem is broken. `P11`: the denial is attributed, and it
/// names the property that failed rather than the syscall that reported it.
fn not_a_spool_file(what: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "husk did not read this spool entry: {what}. The spool is writable by the confined \
             side, so husk reads only the regular file it listed - never a symlink, a FIFO, a \
             device, or a file substituted behind it - and drops the request instead."
        ),
    )
}

/// Create a file that must not exist yet, refusing a name that does.
///
/// **`create_new` is the load-bearing half here, and `O_NOFOLLOW` is the belt** — the reverse
/// of `read_verified`, which is why these two sites needed no identity check when the
/// constant turned out to be inert on aarch64 (`N1-2`). `O_CREAT|O_EXCL` refuses a symlink
/// **regardless of where it points**, by POSIX and by measurement: `EEXIST`, not `ELOOP`, and
/// the existing tests already assert `ErrorKind::AlreadyExists` rather than the flag's error.
/// So `write_atomic`'s temp and `step::create_capture_file` were never open on Santis, only
/// less defended.
///
/// `flags` is a parameter so a test can pass `0` and demonstrate that claim rather than
/// assert it (`P12` — the honest form of "this is carried by something else" is a test with
/// the something-else's partner switched off).
pub(crate) fn create_exclusive(path: &Path, flags: i32) -> std::io::Result<fs::File> {
    fs::OpenOptions::new().write(true).create_new(true).custom_flags(flags).open(path)
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "out".to_string());
    // The name comes from the constants every cleanup matches on, not from a format string
    // here. This function is the ONLY writer of the shape, and three readers that never
    // write it have to recognise it (`P8`, and see `TMP_PREFIX`).
    let tmp = path.with_file_name(husk_slurm_broker::tmp_name(&name));
    // create_new + O_NOFOLLOW: the spool is agent-writable and this tmp name is
    // predictable, so refuse to open it if it already exists or is a symlink —
    // never write THROUGH a pre-planted symlink to an out-of-spool file (F1).
    // (`id` is validated in decide_response, so the tmp stays inside the spool.)
    //
    // The `?` is deliberate and must stay ABOVE the cleanup below: a name we did not create
    // is not ours to unlink, so this failure returns with the planted file intact.
    let mut f = create_exclusive(&tmp, O_NOFOLLOW)?;
    // Past this point the temp is OURS — O_EXCL says nothing else had that name — so every
    // exit path releases it (`P6`). It used to leak on three: `write_all`, `sync_all` and the
    // `rename` all propagated with the file still on disk. That cost twice over: the step
    // spool then held a `.resp-<id>.json.tmp` that no glob in the guard's cleanup could
    // match, and because the open above is `create_new`, the surviving temp made EVERY later
    // response for that id fail too — one ENOSPC and that request id is poisoned for the
    // rest of the session.
    let written = f.write_all(bytes).and_then(|()| f.sync_all());
    drop(f);
    let done = written.and_then(|()| fs::rename(&tmp, path));
    if done.is_err() {
        // `remove_file`, never anything recursive: this runs as the real user in a directory
        // the confined side can write, so the only name it may ever unlink is the one it
        // just created. If the agent swapped a directory in, the unlink fails and we leave
        // it — a cleanup must not become a second failure mode.
        let _ = fs::remove_file(&tmp);
    }
    done
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

    /// **`N1-2`, at the level of the bug and on the architecture husk can run.**
    ///
    /// `read_nofollow`'s only defence was `O_NOFOLLOW`, and `O_NOFOLLOW` was the bare
    /// asm-generic `0o400000`, which is `O_LARGEFILE` — a no-op — on aarch64. On Santis this
    /// read followed symlinks, for as long as the constant has existed, in a directory the
    /// confined side writes. Nothing said so: the open simply succeeded (`P7`).
    ///
    /// The flag is fixed, but a per-architecture number is not something this machine can
    /// check, and a constant nobody here can execute is one review away from being changed
    /// back — it was, in this very round. So the refusal is made to rest on something x86_64
    /// CAN execute, exactly as `20ca07d` did for the spool reaper. `flags = 0` is the state an
    /// inert constant produces.
    ///
    /// **This is the RACE, and it is why `read_verified` takes `named` rather than deriving
    /// it.** A function that `lstat`s and then `open`s cannot be tested against a swap between
    /// the two — no test can get in between. Handed the identity taken BEFORE the swap, it
    /// can. The window is real and it is not tight: `step::scan` collects every request path
    /// and only then admits them one at a time, so a rank has however long the previous
    /// `srun` took to replace a name the broker has already listed.
    ///
    /// **MUTATION that turns it red:** delete the `(dev, ino)` comparison in `read_verified`.
    /// (Deleting `named_regular_file`'s `is_file` arm does NOT turn this red — the identity
    /// check catches a symlink on its own. That arm is load-bearing for exactly one input,
    /// and it has its own test below.)
    #[test]
    fn a_spool_entry_swapped_after_the_check_is_refused_even_with_an_inert_open_flag() {
        use std::os::unix::fs::MetadataExt;
        let dir = scratch("read-verified-race");
        // Stands in for anything the SUBMITTING USER can read and the caged job cannot:
        // ~/.ssh/id_ed25519, a token file, another project's data.
        let victim = dir.join("victim-secret");
        fs::write(&victim, b"SSH-PRIVATE-KEY").unwrap();

        // A real regular file, exactly as the broker's `read_dir` saw it...
        let raced = dir.join("req-raced.json");
        fs::write(&raced, b"{}").unwrap();
        let named = super::named_regular_file(&raced).expect("a real request must be accepted");

        // ...and the rank wins the race before the open.
        fs::remove_file(&raced).unwrap();
        symlink(&victim, &raced).unwrap();
        assert_ne!(
            (named.dev(), named.ino()),
            (fs::metadata(&raced).unwrap().dev(), fs::metadata(&raced).unwrap().ino()),
            "the test must actually swap the object or it proves nothing"
        );

        let err = super::read_verified(&raced, &named, 0).expect_err(
            "a name swapped after husk checked it was read with the open flag inert: on \
             Santis that is an uncaged read of any file the submitting user can read",
        );
        assert!(
            !format!("{err}").contains("SSH-PRIVATE-KEY"),
            "the refusal must not carry the content it refused to read"
        );
        assert!(
            format!("{err}").contains("husk"),
            "an unattributed denial invites a confident wrong theory (`P11`): {err}"
        );

        // And an honest request still reads, with the flag inert and with it real.
        let good = dir.join("req-good.json");
        fs::write(&good, b"{\"id\":\"x\"}").unwrap();
        let named = super::named_regular_file(&good).unwrap();
        assert_eq!(super::read_verified(&good, &named, 0).unwrap(), b"{\"id\":\"x\"}");
        assert_eq!(read_nofollow(&good).unwrap(), b"{\"id\":\"x\"}");

        let _ = fs::remove_dir_all(&dir);
    }

    /// **The one input `named_regular_file`'s `is_file` arm is load-bearing for**, and the
    /// reason it is a `lstat` BEFORE the open rather than a check after it: `open(2)` on a
    /// FIFO with no writer blocks INSIDE the open. Both brokers are single-threaded loops, so
    /// one blocked read ends brokering for that session — and `O_NOFOLLOW` never covered this
    /// at all, on any architecture: it refuses a symlink, not a FIFO.
    ///
    /// Measured before writing the fix: `open(symlink -> FIFO, flags = 0)` was still blocked
    /// after 1.5 s, while the same open with a working `O_NOFOLLOW` returned `ELOOP` at once.
    ///
    /// The call runs on its own thread so that a REGRESSION FAILS rather than hanging the
    /// suite (`P9` — a test that can only hang cannot fail).
    ///
    /// **MUTATION that turns it red:** delete the `is_file` arm from `named_regular_file`.
    /// **Residual, named here as well as at the function:** the RACED FIFO (regular at the
    /// `lstat`, FIFO at the open) still blocks. Closing it needs `O_NONBLOCK`, a third
    /// per-architecture flag with a third override list; not guessed at here.
    #[test]
    fn a_fifo_in_the_spool_is_refused_before_the_open_that_would_block_on_it() {
        let dir = scratch("read-fifo");
        let fifo = dir.join("req-fifo.json");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("this test needs mkfifo(1); a missing one must be loud, not skipped");
        assert!(made.success(), "mkfifo failed");

        let (tx, rx) = std::sync::mpsc::channel();
        let probe = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(read_nofollow(&probe).is_err());
        });
        let refused = rx.recv_timeout(std::time::Duration::from_secs(3)).unwrap_or_else(|_| {
            panic!(
                "read_nofollow is still inside open() on a FIFO after 3s: that is the trusted \
                 broker's loop stopped for the rest of the session, chosen by the caged side"
            )
        });
        assert!(refused, "a FIFO at a request name must be refused");
        let _ = fs::remove_dir_all(&dir);
    }

    /// The same attack through the production entry point, named as the **false friend** it
    /// is: green at HEAD on x86_64, and it would have stayed green for every one of the
    /// months `O_NOFOLLOW` was `O_LARGEFILE` on Santis. Kept because it is the shape a reader
    /// looks for, and because it pins that `read_nofollow` still passes the real flag.
    #[test]
    fn read_nofollow_refuses_a_symlinked_request() {
        let dir = scratch("read-nofollow-symlink");
        let victim = dir.join("victim-secret");
        fs::write(&victim, b"SECRET").unwrap();
        let planted = dir.join("req-planted.json");
        symlink(&victim, &planted).unwrap();
        assert!(read_nofollow(&planted).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    /// **The two flag VALUES, against the only two fcntl ABIs Linux has.**
    ///
    /// This test used to carry a second job — asserting that the two `cfg` lists behind these
    /// constants "stay the same list" — and `N1-3` showed that half was vacuous for exactly the
    /// mutation it named. It compares VALUES ON THE COMPILED TARGET, and on an x86_64 build host
    /// both lists took their `not(any(...))` arm whatever they contained: a reviewer deleted
    /// `aarch64` from one of the two, restoring the precise Santis defect, and `cargo test` came
    /// back byte-identical green. There is now ONE list (`FCNTL_OVERRIDDEN_BY_THIS_ARCH`), and
    /// what it contains is pinned lexically, on the build host, by
    /// `the_architecture_list_behind_these_flags_is_stated_exactly_once`.
    ///
    /// What is left here is worth keeping for a different reason: it pins the numbers against
    /// the two ABIs, so a wrong digit is caught on whichever architecture is building, and it
    /// pins that `main.rs` still DERIVES its constant from these two rather than restating them.
    ///
    /// **MUTATION that turns it red:** change either octal digit, set either constant to `0`,
    /// or give `main.rs` its own `O_NOFOLLOW_DIRECTORY` literal again.
    ///
    /// **AXIS IT DOES NOT COVER:** whether the arm64 numbers are right for a real arm64 kernel.
    /// Only the quoted header answers that, and only a Santis run confirms it.
    #[test]
    fn the_two_nofollow_constants_in_this_binary_agree() {
        assert!(
            matches!((O_NOFOLLOW, O_DIRECTORY), (0o100_000, 0o40_000) | (0o400_000, 0o200_000)),
            "O_NOFOLLOW={O_NOFOLLOW:#o} O_DIRECTORY={O_DIRECTORY:#o} is neither the asm-generic \
             pair (0o400000/0o200000) nor the arm64 override (0o100000/0o40000)"
        );
        // Each is a single bit, on every architecture that defines it, and they are not the
        // same bit — the Santis defect was O_NOFOLLOW landing on O_LARGEFILE.
        assert_eq!(O_NOFOLLOW.count_ones(), 1, "{O_NOFOLLOW:#o} is not one flag");
        assert_eq!(O_DIRECTORY.count_ones(), 1, "{O_DIRECTORY:#o} is not one flag");
        assert_eq!(O_NOFOLLOW & O_DIRECTORY, 0, "the two flags must be different bits");
        assert_eq!(
            crate::O_NOFOLLOW_DIRECTORY,
            O_NOFOLLOW | O_DIRECTORY,
            "main.rs's O_NOFOLLOW_DIRECTORY is no longer derived from this module's two flags, \
             so the binary is back to two independent statements of one kernel fact (`P8`)"
        );
    }

    /// **`N1-3` — the mutation the value comparison above could not see, caught on x86_64.**
    ///
    /// Which architectures override the asm-generic fcntl block is a fact about the KERNEL, and
    /// until this change it was written out four times: twice in this file and twice in
    /// `main.rs`. Its only guard was the runtime comparison above, which on the build host
    /// compares two identical fallback arms. Measured by a reviewer at `ef9895a`: remove
    /// `aarch64` from ONE of the two lists — silently restoring the exact defect the fix exists
    /// for — and the suite is byte-identical green at 349/2.
    ///
    /// So this check is LEXICAL and reads the source, because the thing that must not drift is
    /// source text and no value on this target reflects it. `include_str!` embeds both files at
    /// compile time, so it does not depend on the working directory, on the tree still being
    /// present, or on where the test binary runs.
    ///
    /// **MUTATION that turns it red, here, on x86_64:**
    ///   * delete `"aarch64"` from the list — the reviewer's mutation D: the golden fails;
    ///   * restore a second `cfg` list in `main.rs` — the "stated once" assertion fails;
    ///   * replace `cfg!(...)` with a hard-coded `true` — the faithful model of the Santis state,
    ///     which the old guard passed green: the occurrence count drops to zero and fails.
    ///
    /// **AXES IT DOES NOT COVER.** It cannot tell whether a name is spelled the way `rustc`
    /// spells it — a typo yields a `cfg` predicate that is simply never true, and only that
    /// architecture would notice. It says nothing about the octal values (the test above). And
    /// it is a check on TEXT: reformat the list and it goes red without a defect, which is the
    /// price of seeing a change the build host is otherwise blind to.
    #[test]
    fn the_architecture_list_behind_these_flags_is_stated_exactly_once() {
        // Assembled rather than written, or this test's own source would be a hit below.
        let key = concat!("target_", "arch");

        // The kernel's overriding architectures are alpha, arm, arm64, m68k, parisc and
        // powerpc. `rustc --print target-list` has no alpha and no hppa/parisc triple at all,
        // so those two can never be a value of this predicate, and their absence is correct
        // rather than a gap — `RHGN` refuted the earlier note that called it one.
        let golden = ["aarch64", "arm", "m68k", "powerpc", "powerpc64"];

        // Every occurrence, and every occurrence that parses as `<key> = "<name>"`. They must
        // be the same number: a scanner that can silently match nothing is a green test that
        // checked nothing (`P7`, `P10`).
        fn scan(src: &str, key: &str) -> (usize, Vec<String>) {
            let (mut seen, mut names, mut rest) = (0usize, Vec::new(), src);
            while let Some(i) = rest.find(key) {
                seen += 1;
                rest = &rest[i + key.len()..];
                if let Some(t) = rest.trim_start().strip_prefix('=') {
                    if let Some(t) = t.trim_start().strip_prefix('"') {
                        if let Some(end) = t.find('"') {
                            names.push(t[..end].to_string());
                        }
                    }
                }
            }
            (seen, names)
        }

        let (here_seen, here) = scan(include_str!("spool.rs"), key);
        let (there_seen, there) = scan(include_str!("main.rs"), key);

        assert_eq!(
            here_seen,
            here.len(),
            "an architecture predicate in spool.rs is not in the `<key> = \"name\"` shape this \
             test can read, so the scan is partly blind. If you meant it as prose, say \"the \
             per-architecture cfg list\" instead of naming the predicate: {here:?}"
        );
        assert_eq!(there_seen, there.len(), "same, in main.rs: {there:?}");

        assert_eq!(
            there_seen, 0,
            "main.rs states the architecture list again ({there:?}). That is the two-lists shape \
             `N1-3` found: the lists can then diverge, and no value on this build host changes \
             when they do. main.rs must derive its flags from spool's (`P8`)."
        );
        assert_eq!(
            here, golden,
            "the architecture list behind O_NOFOLLOW/O_DIRECTORY changed. Removing a name here \
             makes both flags silently take the asm-generic values on that architecture — which \
             is O_LARGEFILE, a 64-bit no-op, and is exactly how the flag was inert on Santis for \
             months. Adding one makes them take the arm64 values where the kernel does not."
        );
    }

    /// **`N1-2`, the argued no-change.** Three of the four inert-flag sites carry
    /// `create_new`, and `O_CREAT|O_EXCL` refuses a symlink at the final component regardless
    /// of where it points — so those sites were weakened on Santis, not open. That claim is
    /// the reason `write_atomic` and `create_capture_file` did NOT grow an identity check,
    /// and a reason to skip work has to be executed rather than asserted (`P12`).
    ///
    /// **MUTATION that turns it red:** drop `.create_new(true)` from `create_exclusive`.
    #[test]
    fn an_exclusive_create_refuses_a_planted_symlink_with_no_help_from_the_flag() {
        let dir = scratch("create-exclusive");
        let victim = dir.join("victim");
        fs::write(&victim, b"ORIGINAL").unwrap();
        let planted = dir.join(".resp-pwn.json.tmp");
        symlink(&victim, &planted).unwrap();

        let err = super::create_exclusive(&planted, 0)
            .expect_err("O_EXCL alone must refuse a symlinked name");
        assert!(
            matches!(err.kind(), std::io::ErrorKind::AlreadyExists),
            "the refusal must be O_EXCL's EEXIST, not the flag's ELOOP: {err:?}"
        );
        assert_eq!(fs::read(&victim).unwrap(), b"ORIGINAL", "a write went through the symlink");
        // And the same thing through the real caller, still with the flag inert.
        let target = dir.join("resp-pwn.json");
        assert!(write_atomic(&target, b"ATTACKER-CONTENT").is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"ORIGINAL");
        let _ = fs::remove_dir_all(&dir);
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

    // `C2-2`/`D1 §6`, the failure half. `write_atomic` propagated the error from `write_all`,
    // `sync_all` AND `rename` with its temp still on disk, and that temp is a DOTFILE, which
    // neither the compute guard's globs nor a `rm resp-*` could match. The agent does not even
    // need the write→rename race to reach it: pre-planting a DIRECTORY at the response name
    // makes the rename fail every time, deterministically, from inside the cage. Release on
    // every path (`P6`).
    #[test]
    fn write_atomic_leaves_no_temp_behind_when_it_fails() {
        let dir = scratch("wa-failpath");
        // What a rank plants before sending its request: `mkdir resp-<id>.json`.
        let target = dir.join("resp-planted.json");
        fs::create_dir(&target).unwrap();
        let tmp = dir.join(husk_slurm_broker::tmp_name("resp-planted.json"));

        let r = write_atomic(&target, b"{}");

        assert!(r.is_err(), "renaming onto a directory must fail");
        assert!(
            !tmp.exists(),
            "the in-flight temp survived the failure: {} is a dotfile that no shell glob in \
             the guard's cleanup matched, so the whole step spool leaks",
            tmp.display()
        );
        // And the id is not poisoned for the rest of the session: the open is `create_new`,
        // so a surviving temp would have failed every later response for this id too.
        let ok_target = dir.join("resp-planted2.json");
        assert!(write_atomic(&ok_target, b"{}").is_ok());
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
            session: Session { uenv: None, view: None, allowed_partitions: vec!["preemptible".into()], allowed_accounts: vec![], allowed_uenvs: vec![], limits: Default::default() },
            dry_run: true,
            fs_policy: FsPolicy::unchecked_for_test(),
            submitted: Default::default(),
            project_dir: PathBuf::from("/work"),
            home: PathBuf::from("/nonexistent-home"),
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
    fn settings_that_stopped_parsing_are_refused_at_submit_not_discovered_in_a_hung_job() {
        // **Balfrin 2026-08-06.** A human closed vim on an empty buffer, leaving a zero-byte
        // `.claude/settings.json`. This broker had already resolved its policy at startup, so
        // it kept accepting submissions — while every job's step broker re-read that file on
        // the compute node, failed closed, and left srun hanging to the walltime with no
        // output. Five or six jobs, four nodes, four rank counts, one afternoon.
        //
        // The submitting side can see this coming, so it should say so while someone is still
        // watching a terminal.
        let dir = std::env::temp_dir().join(format!("husk-submitcheck-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(".claude")).unwrap();
        fs::create_dir_all(dir.join("spool")).unwrap();
        // CONTENT that does not parse. An EMPTY file is deliberately NOT this case any
        // more: as of 2026-08-06 empty means absent, because Anthropic's runtime creates
        // zero-byte settings files on its own and `:wq` on an empty buffer leaves one — and
        // a zero-byte file has no denies in it to lose. A file with content that will not
        // parse is a typo in real policy, and that still refuses. See
        // `an_empty_settings_file_is_absent_but_a_broken_one_still_refuses`.
        fs::write(dir.join(".claude/settings.json"), b"{\"permissions\": }").unwrap();

        let broker = Broker {
            spool: dir.join("spool"),
            session: Session { uenv: None, view: None, allowed_partitions: vec!["preemptible".into()], allowed_accounts: vec![], allowed_uenvs: vec![], limits: Default::default() },
            dry_run: true,
            // The cached policy is FINE — that is the whole point. It was captured before
            // the file was broken, and it stays authoritative.
            fs_policy: FsPolicy::unchecked_for_test(),
            submitted: Default::default(),
            project_dir: dir.clone(),
            home: PathBuf::from("/nonexistent-home"),
        };
        let req = r##"{"version":1,"id":"submitcheck","tool":"sbatch","submitted_at":"t","cwd":"/tmp","argv":["--partition=preemptible"],"script":{"source":"file","body":"#!/bin/bash\necho hi\n"},"job_args":[],"env":{}}"##;
        fs::write(broker.spool.join("req-submitcheck.json"), req).unwrap();
        broker.process_once().unwrap();

        let resp: serde_json::Value = serde_json::from_slice(
            &fs::read(broker.spool.join("resp-submitcheck.json")).expect("a response"),
        )
        .unwrap();
        let text = resp.to_string();
        assert_eq!(
            resp["status"], "rejected",
            "the submission must be REFUSED, not queued to die later: {text}"
        );
        assert!(
            text.contains("settings.json"),
            "and must name the file, or the agent cannot fix it: {text}"
        );
        assert!(
            text.contains("compute"),
            "and must explain WHERE it would have failed, since nothing is wrong here: {text}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

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
            session: Session { uenv: None, view: None, allowed_partitions: vec!["preemptible".into()], allowed_accounts: vec![], allowed_uenvs: vec![], limits: Default::default() },
            dry_run: true,
            fs_policy: FsPolicy::unchecked_for_test(),
            submitted: Default::default(),
            project_dir: dir.clone(), // the trusted root; `proj` is a subdirectory of it
            home: PathBuf::from("/nonexistent-home"),
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
            session: Session { uenv: None, view: None, allowed_partitions: vec!["preemptible".into()], allowed_accounts: vec![], allowed_uenvs: vec![], limits: Default::default() },
            dry_run: true,
            fs_policy: FsPolicy::unchecked_for_test(),
            submitted: Default::default(),
            project_dir: PathBuf::from("/work"),
            home: PathBuf::from("/nonexistent-home"),
        };
        broker.submitted.borrow_mut().insert(4991406, "/work/.husk-body-cancel-own.sh".to_string());

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
        // DERIVED from the owned list, so a new artifact is exercised the day it is added and
        // cannot sit in the list untested (`B4-1`/`B4-5`, and `P9`: the old version of this
        // test planted the two names it already knew about).
        let planted: Vec<String> = husk_slurm_broker::SPOOL_OWNED_PATTERNS
            .iter()
            .map(|a| format!("{}old{}", a.prefix, a.suffix))
            .collect();
        for name in &planted {
            fs::write(dir.join(name), b"x").unwrap();
        }
        // …and the two entries with no OTHER hand-written witness, spelled out (`RDF-D-4`).
        // The `planted` loop above derives its names from the list it is testing, so removing
        // an entry removes the fixture that would have caught it: measured at `608618e`,
        // deleting `dry-` — `B4-1`'s own entry — or `resp-` left the whole suite green. `job-`
        // and `.tmp` survived that mutation only because they happen to have a second,
        // hand-written assertion elsewhere; these two now have one too.
        for name in ["dry-old.sh", "resp-old.json"] {
            fs::write(dir.join(name), b"x").unwrap();
        }
        fs::write(dir.join("req-live.json"), b"{}").unwrap();
        let broker = Broker {
            spool: dir.clone(),
            session: Session { uenv: None, view: None, allowed_partitions: vec!["preemptible".into()], allowed_accounts: vec![], allowed_uenvs: vec![], limits: Default::default() },
            dry_run: true,
            fs_policy: FsPolicy::unchecked_for_test(),
            submitted: Default::default(),
            project_dir: PathBuf::from("/work"),
            home: PathBuf::from("/nonexistent-home"),
        };
        // cutoff 0 => every orphan (any positive age) is stale and reclaimed.
        broker.gc(std::time::Duration::ZERO);
        for name in &planted {
            let gone = !dir.join(name).exists();
            let live = name.starts_with("req-");
            assert_eq!(
                gone, !live,
                "{name}: gc must reclaim every stale artifact husk writes, and must never take \
                 a live request out from under a waiting stub"
            );
        }
        // Named explicitly as well, because this is the file the session-teardown message was
        // firing on: a dry run left `dry-<id>.sh` and NOTHING owned it (`B4-1`). It is only
        // an oracle because the plant above is hand-written; while the plant was derived from
        // the list, deleting `dry-` made this line pass vacuously (`RDF-D-4`, `P9`).
        assert!(!dir.join("dry-old.sh").exists(), "the dry-run copy has an owner now");
        assert!(
            !dir.join("resp-old.json").exists(),
            "a stale response nobody will ever read must be reclaimable mid-session"
        );
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
    fn a_second_cluster_found_module_state_the_first_one_never_set() {
        // **Santis, 2026-08-05.** Balfrin came back clean at 32 drops; Santis dropped 42, and
        // the difference was Lmod's serialised module table. Lmod encodes what is loaded into
        // `_ModuleTable001_`, `_ModuleTable_Sz_` and `__LMOD_REF_COUNT_MODULEPATH`; a job that
        // inherits `MODULEPATH` but not these has a module system that disagrees with itself.
        // Neither name matches the `LMOD_` prefix that was already there — one has a double
        // underscore, the other is capitalised differently.
        //
        // The lesson is about METHOD, not about Lmod: an allowlist is only as good as the
        // environments it has been measured against, and one clean cluster is not evidence
        // about the next. Re-read the "not forwarded" line on every NEW site.
        let env: Vec<(String, String)> = [
            "_ModuleTable001_", "_ModuleTable_Sz_", "__LMOD_REF_COUNT_MODULEPATH", "LMOD_CMD",
        ]
        .iter()
        .map(|k| (k.to_string(), "v".to_string()))
        .collect();
        let (_, dropped) = filter_submit_env(env.into_iter(), &[], &[]);
        assert!(dropped.is_empty(), "Lmod's own state must reach the job: {dropped:?}");

        // Santis also surfaced a channel worth keeping SHUT, and it is not noise: bash sources
        // `$BASH_ENV` on non-interactive startup, so it is a code-execution channel into every
        // shell a job runs. The old four-name denylist forwarded it to every job.
        let (kept, _) = filter_submit_env(
            [("BASH_ENV".to_string(), "/tmp/payload.sh".to_string())].into_iter(),
            &[],
            &[],
        );
        assert!(kept.is_empty(), "BASH_ENV is arbitrary code on shell startup: {kept:?}");
    }

    /// Renamed from `the_guard_reads_no_variable_the_login_shell_can_author`, which asserted
    /// a property husk does NOT have: `USER` is read by the guard and IS authorable by the
    /// login shell, and the body of this test asserts that exception rather than closing it
    /// (`RAB3-A2`). A test name is read far more often than a test body, so a name that
    /// over-claims is a claim about a control (`P12`). This one states what is actually
    /// proved: within slurmd's namespace, no guard variable survives from the login shell.
    #[test]
    fn no_variable_slurmd_owns_can_be_authored_by_the_login_shell() {
        // `RA2-2`/`RA2-3`, at the level of the CLASS. husk's compute-node guard re-derives
        // the file slurmd will open by substituting `OUTPUT_SPECIFIERS`' expansions, and
        // every expansion reads an environment variable. `--export=ALL` plus this file's
        // `SLURM_` prefix rule gave those variables a SECOND author: whatever the broker's
        // own login shell happened to hold. The `RA-2` unset guard cannot see it, because a
        // stale value is present, not empty.
        //
        // Executed by `RA2` before this fix: `SLURM_ARRAY_JOB_ID=7002` inherited from the
        // launching shell, the guard checked `x7002.log`, slurmd opened `x9999.log`, and a
        // symlink planted at the real leaf was NOT REFUSED — A1-F1 and N1 both disarmed
        // through an environment variable, on a job that is not an array at all.
        let polluted: Vec<(String, String)> = [
            ("SLURM_JOB_ID", "7001"),           // %j
            ("SLURM_ARRAY_JOB_ID", "7002"),     // %A — the one RA2 executed
            ("SLURM_ARRAY_TASK_ID", "3"),       // %a
            ("SLURMD_NODENAME", "nid001"),      // %N
            ("SLURM_NODEID", "9"),              // %n
            ("SLURM_LOCALID", "9"),             // %t
            ("SLURM_STEP_ID", "0"),             // %s — RA2-3, no bypass needed
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let (kept, dropped) = filter_submit_env(polluted.into_iter(), &[], &[]);
        assert!(
            kept.is_empty(),
            "a value describing ANOTHER job reached this one, and the guard reads it: {kept:?}"
        );
        assert_eq!(dropped.len(), 7);

        // THE PARTITION, stated per variable rather than per instance, so a new table entry
        // has to say which side it is on instead of inheriting an accident. This is what
        // makes the fix cover the class: `%n`/`%t` have no unset guard at all (`:-0` is
        // non-empty), so for them a stale value diverges SILENTLY — neither is named in
        // `RA2`, and both are closed here.
        for spec in crate::settings::OUTPUT_SPECIFIERS {
            let var = spec.variable();
            match never_forwarded(var) {
                Some(_) => assert!(
                    var.starts_with("SLURM"),
                    "{var} is refused as slurmd-owned but is not in slurmd's namespace"
                ),
                // `USER` is the ONE exception, and it is a RESIDUAL rather than a settled
                // exclusion (`RAB3-A2`). It is outside the class because the class is
                // "slurmd is the only legitimate author" and the submitting shell IS one of
                // `USER`'s legitimate authors — a ground that needs no claim about slurmd.
                // The old comment here said "slurmd does not set it for a batch job", which
                // was unmeasured. What is true without measuring: stripping it empties
                // `${USER:-}` unless slurmd refills it, and the `RA-2` unset guard would
                // then REFUSE EVERY JOB whose --output uses `%u` — the operator DoS this
                // round has already produced twice. See `slurmd_owned_guard_variable`'s
                // docstring for the probe that settles it and the non-DoS repair. A new
                // entry reading some other login-shell variable lands here and turns this
                // red, which is the point.
                None => assert_eq!(
                    var, "USER",
                    "{var} is read by the guard and forwarded from the login shell; say why, \
                     or add it to the slurmd-owned set"
                ),
            }
        }
        // `SLURMD_NODENAME` is the reason the namespace test is `SLURM` and not `SLURM_`.
        // The allowlist's prefix is `SLURM_`, which this name misses by one character, so
        // `%N` was safe BY ACCIDENT OF SPELLING. Asserted on the RULE, not through
        // `filter_submit_env`, because the allowlist would keep that assertion green while
        // the decision rotted (`P15`: test the boundary, do not infer it).
        assert!(never_forwarded("SLURMD_NODENAME").is_some(), "must be a decision, not a typo");

        // An operator's own widening must not re-admit them either — including the exact
        // prefix that carried them in.
        let extra_exact = vec!["SLURM_ARRAY_JOB_ID".to_string()];
        let extra_prefix = vec!["SLURM".to_string()];
        let (kept, _) = filter_submit_env(
            [
                ("SLURM_ARRAY_JOB_ID".to_string(), "7002".to_string()),
                ("SLURM_STEP_ID".to_string(), "0".to_string()),
            ]
            .into_iter(),
            &extra_exact,
            &extra_prefix,
        );
        assert!(kept.is_empty(), "HUSK_SUBMIT_ENV_ALLOW re-admitted a guard variable: {kept:?}");

        // ---- AND THE COST, which is the half the previous fix left out ----
        //
        // What this must NOT do is take the SLURM namespace with it. `SLURM_CONF` is how a
        // configless site's `sbatch` finds its controller: dropping it would fail every
        // submission on a site that sets it, which is a total outage authored by a security
        // fix. The rule is "a variable husk's own guard substitutes", derived from the
        // table, not "starts with SLURM".
        let neighbours: Vec<(String, String)> = [
            "SLURM_CONF", "SLURM_ACCOUNT", "SLURM_PARTITION", "SLURM_TIME_FORMAT",
            "SLURM_JOB_NAME", "SBATCH_ACCOUNT", "SRUN_CPUS_PER_TASK", "SALLOC_ACCOUNT",
        ]
        .iter()
        .map(|k| (k.to_string(), "v".to_string()))
        .collect();
        let (kept, dropped) = filter_submit_env(neighbours.into_iter(), &[], &[]);
        assert!(dropped.is_empty(), "the strip took a neighbour with it: {dropped:?}");
        assert_eq!(kept.len(), 8);
        // …and `USER`, whose absence is the DoS.
        let (kept, _) = filter_submit_env(
            [("USER".to_string(), "hpcuser".to_string())].into_iter(),
            &[],
            &[],
        );
        assert_eq!(kept.len(), 1, "%u would refuse every job that uses it");
    }

    #[test]
    fn a_drop_no_setting_can_undo_says_so_instead_of_offering_the_setting() {
        // `P11`. `submit_env`'s report tells the operator to export `HUSK_SUBMIT_ENV_ALLOW`
        // to get a dropped variable back. For the two sets `never_forwarded` holds, that
        // remedy DOES NOT WORK — and a denial whose stated remedy fails is worse than an
        // unattributed one, because the operator spends the afternoon proving husk broken.
        // So each of those names carries its own reason and its own "cannot re-admit".
        for name in ["ANTHROPIC_API_KEY", "CSCS_INFERENCE_API_KEY", "SECCOMP_WRAPPER_DEBUG"] {
            assert!(never_forwarded(name).is_some(), "{name} is a credential husk strips");
        }
        for name in ["SLURM_ARRAY_JOB_ID", "SLURM_STEP_ID", "SLURM_JOB_ID"] {
            let why = never_forwarded(name).expect("slurmd-owned");
            assert!(why.contains("slurmd"), "the reason must name the author: {why}");
        }
        // A name the ALLOWLIST merely does not list keeps the re-admittable remedy, or the
        // report has traded one wrong message for another.
        assert!(never_forwarded("MY_COMPANY_VPN_PASSWORD").is_none());
        assert!(never_forwarded("UDUNITS2_XML_PATH").is_none());
    }

    /// The contract: a login shell inside a brokered job must see the PATH the broker sent
    /// it, not the distro default. Forwarding `PATH` does not achieve that on its own —
    /// SUSE's `/etc/profile` overwrites PATH with `/usr/local/bin:/usr/bin:/bin` unless
    /// `PROFILEREAD` is already set, then marks `PROFILEREAD` readonly so the latch sticks. An interactive login shell has
    /// it; a brokered job did not; so every `bash -l` in a job discarded the uenv view and
    /// any venv bin, and the run failed looking for its own toolchain (ICON, 2026-08-29).
    ///
    /// This pins the INPUT to that contract, which is all a unit test can reach. The oracle
    /// is on hardware, and it must be WIDER than the bug: not `bash -lc 'echo $PATH'`, which
    /// only confirms the fix, but
    ///
    /// ```text
    /// diff <(bash -lc env | sort) <(bash -c env | sort)
    /// ```
    ///
    /// in a brokered job, with the delta expected to be empty or explained. The narrow check
    /// would miss the real residual risk: `PROFILEREAD` latches OFF everything `/etc/profile`
    /// guards, not just the PATH reset, so what a login shell in a job no longer sets is the
    /// part nothing else measures. See the allowlist comment.
    ///
    /// Note this is not a variable anyone would have guessed at — it was found by reading the
    /// broker's own "not forwarded" line, which is the method the Lmod test above argues for.
    #[test]
    fn the_submit_env_forwards_path_and_the_profile_latch_that_preserves_it() {
        let env: Vec<(String, String)> = [
            ("PROFILEREAD", "true"),
            ("PATH", "/user-environment/env/icon/bin:/usr/bin"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        let (kept, dropped) = filter_submit_env(env.into_iter(), &[], &[]);
        assert!(dropped.is_empty(), "a job's login shell needs both of these: {dropped:?}");
        assert!(
            kept.iter().any(|(k, v)| k == "PROFILEREAD" && v == "true"),
            "without PROFILEREAD, /etc/profile discards the PATH husk forwarded: {kept:?}"
        );
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
