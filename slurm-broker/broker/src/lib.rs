//! husk-slurm-broker shared library — DELIBERATELY dependency-free.
//!
//! Its only job is to hold constants shared by BOTH binaries in this crate: the
//! broker (`src/main.rs`, which pulls in serde etc.) and the fail-closed outer
//! wrapper (`src/bin/husk-slurm-wrapper.rs`, which is zero-dependency by design).
//! Because this lib has no dependencies, the wrapper can reuse the allowlist below
//! without inheriting the broker's dependency graph — single source of truth,
//! without widening the wrapper's audit surface.
//!
//! Keep this file free of external crates.

/// Build identity — the stamp `build.rs` compiles in, and the tests that keep it fresh.
///
/// In the lib, not in `main.rs`, for the reason stated in this file's header: both binaries
/// may need it. The broker prints it in the session banner today; the wrapper does not yet,
/// and giving it the same line is a one-liner whenever its owner wants one.
pub mod build_identity;

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Tier-1 read-only SLURM commands the broker runs on the agent's behalf. Shared
/// by the broker's `policy` (the authoritative gate) and the wrapper's shadow
/// list so the two cannot drift. Tier-2 (verb-gated scontrol/sacctmgr/sdiag) is
/// deferred — see the slurm-readonly-tier2 note.
pub const READONLY_SLURM: &[&str] = &[
    "squeue", "sinfo", "sacct", "sstat", "sprio", "sreport", "sshare",
];

/// Brokered commands that CHANGE state, and so are gated on more than their name.
///
/// Only `scancel`, and only for jobs this broker submitted (see `policy::cancel_targets`
/// and the ownership check in `spool`). It is listed separately from `READONLY_SLURM`
/// because the two are shadowed the same way but decided very differently: a read-only
/// query is safe by virtue of what the command IS, a cancel is safe only by virtue of
/// WHICH JOB it names.
///
/// husk made it easier for an agent to start work than to stop it: `sbatch` was brokered
/// and `scancel` was not, so an agent could launch a job and then had no way to kill it —
/// not even one of its own. A runaway then needed a human. That is a containment gap, not
/// an inconvenience, and it is why this exists.
pub const BROKERED_MUTATING: &[&str] = &["scancel"];

/// Auto-exec files the LOGIN cage must keep an agent from planting in the project dir.
///
/// **In the lib, not settings.rs, because two binaries need it:** `main`/`settings` assert it
/// against the shipped `denyWrite`, and the WRAPPER pre-creates each one (below) before the
/// vendor cage is built. One source, or the two drift (`P8`).
///
/// Each fires as the USER, outside every cage, the next time a human runs the tool in that
/// directory: R sources `.Rprofile`/`.Renviron` from cwd at startup, Mercurial trusts
/// `.hg/hgrc` because the invoking user owns it. `.Renviron` is here because it DEFEATS the
/// `.Rprofile` mask beside it — it can set `R_PROFILE_USER` at an agent path R then sources as
/// code (A4-L2), so masking `.Rprofile` while leaving `.Renviron` writable protects nothing.
pub const LOGIN_AUTO_EXEC_DENY: &[&str] = &[".Rprofile", ".Renviron", ".hg/hgrc"];


// ---- spool naming + lifecycle ----------------------------------------------
//
// The spool holds the request/response files the caged stub and the trusted broker
// exchange, so it MUST live somewhere the agent can write — in practice the project
// directory, which the sandbox already makes writable. That is a constraint, not a
// preference, and it has two consequences worth stating:
//
//   1. Everything in here is agent-writable, so nothing in here is evidence. The
//      broker's session log deliberately lives OUTSIDE it (see `session_log_path`).
//   2. It is litter in someone's source tree, so it is per-session and it cleans up
//      after itself — the same rule the per-job step spool already follows.
//
// Two independent teardown paths, because a directory leaked per session accumulates
// forever in a tree the user did not choose: the broker removes its own spool when it
// is signalled (it dies with the session via PDEATHSIG), and any broker starting up
// reaps the dead spools it finds beside its own.

/// How the wrapper tells the broker which inherited descriptor to announce readiness on.
///
/// ONE name, defined once and read by both halves: two spellings of the same rendezvous drift,
/// and the failure mode here is a fifteen-second refusal on every launch (`P8`). The value is a
/// file-descriptor NUMBER.
///
/// The wrapper sets it on the `Command` it spawns and never in its own environment, so it is
/// not inherited by the agent, and nothing the confined side puts in an environment is ever
/// read as this. The signal it names replaced `<spool>/owner`, which lives in a directory the
/// agent must be able to write and therefore could not be evidence about anything (`P2`).
pub const BROKER_READY_FD_ENV: &str = "HUSK_BROKER_READY_FD";

/// Directory-name prefix for a login-side spool. The bare prefix with no `-<pid>`
/// suffix is the LEGACY fixed name used before spools became per-session; the reaper
/// still recognises it so old directories get cleaned up rather than lingering.
pub const SPOOL_PREFIX: &str = ".husk-slurm-spool";

/// Per-job STEP spool, created by the guard before the run-time output check. Distinct from
/// SPOOL_PREFIX (the session spool of a LIVE broker, which must never be reaped by age).
pub const STEP_SPOOL_PREFIX: &str = ".husk-step-spool-";

/// The spool directory for one husk session. Per-pid so two husk sessions launched in
/// the same project directory get their own rendezvous instead of racing in a shared
/// one, and so "is this directory live?" has an answer.
pub fn session_spool_dir(parent: &Path, pid: u32) -> PathBuf {
    parent.join(format!("{SPOOL_PREFIX}-{pid}"))
}

/// Files husk itself creates in a login-side spool. The reaper removes ONLY these and
/// then `rmdir`s, so it can never delete something husk did not put there — if anyone
/// dropped a file in the spool, the `rmdir` fails and the directory survives.
pub const SPOOL_OWNED_FILES: &[&str] = &["owner", "broker.log"];

/// The name `write_atomic` gives the file it is still writing: a LEADING DOT, the target
/// name, and `.tmp`. Defined here rather than at the writer because four places depend on
/// the shape and only one of them writes it — the login reaper below, the login `gc`
/// (`spool.rs`), and the compute guard's cleanup glob (`policy.rs`) all have to recognise
/// a name they never produce (`P8`).
///
/// The leading dot is why this constant exists at all. A shell glob does not match it
/// unless the pattern begins with one, so `resp-*.json` misses `.resp-<id>.json.tmp`
/// entirely; the guard's cleanup did, and one interrupted step response leaked a whole
/// step spool (`C2-2`/`D1 §6`).
pub const TMP_PREFIX: &str = ".";
pub const TMP_SUFFIX: &str = ".tmp";

/// The shell glob matching exactly what `tmp_name` produces. Tied to the two constants by
/// `the_tmp_glob_matches_what_write_atomic_writes`, because a glob is a second spelling of
/// a name and two spellings drift (`P8`).
pub const TMP_GLOB: &str = ".*.tmp";

/// The in-flight name `write_atomic` uses for `name`.
pub fn tmp_name(name: &str) -> String {
    format!("{TMP_PREFIX}{name}{TMP_SUFFIX}")
}

/// One name shape husk itself writes into a login-side spool.
///
/// ONE list, with the exception carried ON the entry, rather than two lists that happen to
/// differ (`P8`). There were two: this one, and `gc`'s literal in `spool.rs`. They had
/// drifted in both directions at once — `job-*.sh` was in both and written by neither since
/// v0.4, and `dry-<id>.sh` was written by `submit` and in neither, so a dry run ended the
/// session with *"kept spool … it holds files husk did not create"* about a file husk had
/// created (`B4-1`). That message is a security-shaped statement, and it was false.
pub struct SpoolArtifact {
    pub prefix: &'static str,
    pub suffix: &'static str,
    /// May the age-based `gc` reclaim this while the session is still RUNNING?
    ///
    /// `remove_spool_dir` takes every entry, because it runs at teardown when there is no
    /// longer anyone to serve. `gc` runs mid-session and takes only the entries marked
    /// here. The one `false` is not an oversight and must not be normalised away.
    pub gc_while_live: bool,
    /// Why this entry exists and why its `gc_while_live` is what it is, in one clause, so
    /// the next reader does not have to re-derive it from the writer.
    pub why: &'static str,
}

pub const SPOOL_OWNED_PATTERNS: &[SpoolArtifact] = &[
    SpoolArtifact {
        prefix: "req-",
        suffix: ".json",
        // F4. A request is LIVE: the stub wrote it and is now blocked on the answer. Aging
        // one out mid-session would delete the question and leave the stub waiting for a
        // response that can no longer be written — a silent hang, which is the failure mode
        // husk spends the most effort not producing (`P13`).
        gc_while_live: false,
        why: "a live request the stub is blocked on; reclaiming it mid-session hangs the stub",
    },
    SpoolArtifact {
        prefix: "resp-",
        suffix: ".json",
        gc_while_live: true,
        why: "an answer whose stub died before reading it; nobody will read it now",
    },
    SpoolArtifact {
        prefix: "dry-",
        suffix: ".sh",
        gc_while_live: true,
        // B4-1. Written by `Broker::submit` on the --dry-run path and owned by nothing at
        // all until this entry. The same content goes to stdout in the same breath, so
        // reclaiming the copy costs the operator nothing; and `--once` does not run this
        // reaper (main.rs keeps the CONTENTS of a scan it was asked to make), so the file
        // still outlives the dry run that produced it.
        why: "the inspectable copy --dry-run leaves behind; its content also went to stdout",
    },
    SpoolArtifact {
        prefix: "job-",
        suffix: ".sh",
        gc_while_live: true,
        // B4-5 asked for this arm to be DELETED as dead. It is dead as a WRITER — nothing in
        // this tree has written `job-<id>.sh` since husk started passing its script to sbatch
        // on stdin — but it is not dead as a READER: v0.4 shipped and is installed, and a v0.4
        // broker that was killed left exactly this file in a spool that a v0.5 broker beside
        // it now has to reap. Delete the arm and that directory becomes permanent AND reports
        // "files husk did not create" about a file husk created — the very symptom `B4-1` is
        // about. Kept for the same reason the legacy `SPOOL_PREFIX` directory name is kept
        // three constants up, and labelled the same way so nobody reads it as live.
        why: "LEGACY (v0.4 and earlier staged husk's script here); no current writer",
    },
    SpoolArtifact {
        prefix: TMP_PREFIX,
        suffix: TMP_SUFFIX,
        gc_while_live: true,
        why: "write_atomic's in-flight temp, left by a crash between create and rename",
    },
];

fn matches_artifact(a: &SpoolArtifact, name: &str) -> bool {
    name.len() > a.prefix.len() + a.suffix.len()
        && name.starts_with(a.prefix)
        && name.ends_with(a.suffix)
}

fn is_husk_spool_file(name: &str) -> bool {
    SPOOL_OWNED_FILES.contains(&name)
        || SPOOL_OWNED_PATTERNS.iter().any(|a| matches_artifact(a, name))
}

/// True if `name` is a husk-written spool file that the age-based `gc` may reclaim while the
/// session is still running. `spool.rs::gc`'s only rule, so the two lists cannot drift.
pub fn is_reclaimable_orphan(name: &str) -> bool {
    SPOOL_OWNED_PATTERNS
        .iter()
        .any(|a| a.gc_while_live && matches_artifact(a, name))
}

/// True if `name` is a husk login-side spool directory (per-session or legacy).
pub fn is_spool_dir_name(name: &str) -> bool {
    name == SPOOL_PREFIX || name.strip_prefix(SPOOL_PREFIX).is_some_and(|r| r.starts_with('-'))
}

/// The pid recorded in a spool's `owner` file, if it has one.
///
/// Plain `key=value` text rather than JSON: this module stays dependency-free, and a
/// human or an agent looking at a stale directory can read it with `cat`.
pub fn spool_owner_pid(spool: &Path) -> Option<u32> {
    let text = std::fs::read_to_string(spool.join("owner")).ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("pid="))
        .and_then(|v| v.trim().parse().ok())
}

extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
    #[link_name = "getuid"]
    fn libc_getuid() -> u32;
}

/// Does a process with this pid exist? `kill(pid, 0)` performs the permission check
/// and delivers nothing.
///
/// A recycled pid reads as alive, so this errs toward NOT reaping — the safe direction
/// for a function whose other branch deletes a directory.
pub fn pid_is_alive(pid: u32) -> bool {
    // SAFETY: signal 0 delivers nothing; it only probes for the process's existence.
    unsafe { libc_kill(pid as i32, 0) == 0 }
}

/// Does this path belong to the user running us?
///
/// The reaper deletes things, so it must never even consider a directory belonging to
/// someone else — husk can be launched in a world-writable directory (`/tmp` on a shared
/// login node), where a spool-shaped name proves nothing about who made it. "The
/// permissions would have stopped me anyway" is not a reason to try. A pid read from
/// another user's `owner` file is also not a pid this session can reason about, so the
/// liveness check would be meaningless there too.
pub fn owned_by_me(path: &Path) -> bool {
    // SAFETY: getuid cannot fail and takes no arguments.
    let me = unsafe { libc_getuid() };
    std::fs::symlink_metadata(path).map(|m| m.uid()).unwrap_or(u32::MAX) == me
}

/// Remove a spool directory, but only the files husk created in it. Returns true if the
/// directory is gone afterwards.
pub fn remove_spool_dir(spool: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(spool) else {
        return !spool.exists();
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Regular files only: never follow a directory or a symlink out of the spool.
        if matches!(entry.file_type(), Ok(ft) if ft.is_file()) && is_husk_spool_file(&name) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    // Fails (harmlessly) if anything unrecognised is left — that directory is not ours
    // to delete.
    std::fs::remove_dir(spool).is_ok()
}

/// Reap dead husk spools sitting beside `keep`, and report what happened.
///
/// Scoped DELIBERATELY to one directory — the one husk was launched in. Walking up the
/// tree would clean more (the field report found two spools at different depths) at the
/// cost of husk deleting directories outside where it was invoked, which is not a trade
/// a sandbox should make.
///
/// A spool is dead when its `owner` names a pid that no longer exists. A LEGACY spool
/// has no `owner` at all, so age stands in for liveness: it is reaped only once
/// everything in it is older than `legacy_min_age`, which keeps a concurrently running
/// older husk from having its spool pulled out from under it.
pub fn reap_stale_spools(
    parent: &Path,
    keep: &Path,
    legacy_min_age: std::time::Duration,
) -> Vec<String> {
    let mut notes = Vec::new();
    let Ok(entries) = std::fs::read_dir(parent) else {
        return notes;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path == keep || !matches!(entry.file_type(), Ok(ft) if ft.is_dir()) {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !is_spool_dir_name(&name) {
            continue;
        }
        if !owned_by_me(&path) {
            continue;
        }
        match spool_owner_pid(&path) {
            Some(pid) if pid_is_alive(pid) => {
                notes.push(format!("spool {name} belongs to live pid {pid} — left alone"));
                continue;
            }
            Some(pid) => {
                if remove_spool_dir(&path) {
                    notes.push(format!("reaped stale spool {name} (owner pid {pid} is gone)"));
                } else {
                    notes.push(format!("stale spool {name} has files husk did not create — left alone"));
                }
            }
            None => {
                if !all_contents_older_than(&path, legacy_min_age) {
                    notes.push(format!("spool {name} has no owner file but was touched recently — left alone"));
                    continue;
                }
                if remove_spool_dir(&path) {
                    notes.push(format!("reaped stale spool {name} (pre-v0.5 layout, idle)"));
                } else {
                    notes.push(format!("stale spool {name} has files husk did not create — left alone"));
                }
            }
        }
    }
    notes
}

fn all_contents_older_than(dir: &Path, age: std::time::Duration) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().all(|e| {
        e.metadata()
            .and_then(|m| m.modified())
            .map(|t| t.elapsed().map(|e| e > age).unwrap_or(false))
            .unwrap_or(false)
    })
}

// ---- the egress socket ------------------------------------------------------

/// `sizeof(sockaddr_un.sun_path)`. A kernel constant, not a tunable: a unix socket
/// address that does not fit is refused by `bind()`, and there is no way to ask for more.
pub const SUN_PATH_MAX: usize = 108;

/// Vet the egress socket's path before binding it.
///
/// Two failures this turns from obscure into obvious:
///
/// 1. **Too long.** The socket used to live in the job's step spool, so its address was
///    `<workdir>/.husk-step-spool-<jobid>/net.sock` — ~34 bytes of suffix on top of a
///    project path. A real Balfrin project measured ~57 bytes total, i.e. it worked with
///    under 20 to spare, and a project one or two directories deeper would have lost its
///    network to a bare `AF_UNIX path too long`.
///
/// 2. **A directory we do not control.** The socket now lives in node-local `/tmp`, which
///    is world-writable, and job ids are public in `squeue`. A directory an attacker
///    pre-created is one they can put their own socket in — which would route this job's
///    egress through their proxy. Owner-only and owned by us, or refuse to start: no
///    egress is a safe outcome, egress through someone else's process is not.
pub fn check_socket_path(path: &Path) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    let len = path.as_os_str().as_bytes().len();
    if len >= SUN_PATH_MAX {
        return Err(format!(
            "socket path is {len} bytes but a unix socket address holds at most {} \
             (sun_path is fixed by the kernel): {}",
            SUN_PATH_MAX - 1,
            path.display()
        ));
    }
    let parent = path.parent().ok_or_else(|| format!("{} has no parent", path.display()))?;
    let md = std::fs::symlink_metadata(parent)
        .map_err(|e| format!("cannot inspect {}: {e}", parent.display()))?;
    if !md.is_dir() {
        return Err(format!("{} is not a directory", parent.display()));
    }
    // SAFETY: getuid cannot fail and takes no arguments.
    let me = unsafe { libc_getuid() };
    if md.uid() != me {
        return Err(format!(
            "{} is owned by uid {}, not by uid {me} — refusing to put this job's egress \
             through a directory it does not control",
            parent.display(),
            md.uid()
        ));
    }
    if md.mode() & 0o077 != 0 {
        return Err(format!(
            "{} is mode {:o}; it must not be group- or world-accessible, or another user \
             on this node could replace the socket",
            parent.display(),
            md.mode() & 0o7777
        ));
    }
    Ok(())
}

// ---- the session log --------------------------------------------------------

/// Where the broker's session log goes: `~/.husk/log/husk-<utc>-<pid>.log`.
///
/// OUTSIDE the spool, and outside every path the sandbox makes writable, on purpose.
/// The spool has to be agent-writable for the stub to reach it, so a log kept there is
/// a log the confined side can truncate, rewrite, or plant lines in — an audit trail
/// that the audited party edits is not an audit trail. Reads are unrestricted, so the
/// agent can still read this file to diagnose itself; it just cannot author it.
///
/// One file per session also settles the question the field report ran into: with an
/// append-only shared log there is no way to tell a dead session's lines from a live
/// one's.
pub fn session_log_path(home: &Path, unix_secs: u64, pid: u32) -> PathBuf {
    home.join(".husk/log").join(format!("husk-{}-{pid}.log", utc_stamp(unix_secs)))
}

/// A staged job body is prunable once nothing can still be waiting to run it.
///
/// **The guard used to delete this itself, and that was wrong** (2026-08-09). Its comment
/// said the body is "owned by the guard because it must outlive submission but must not
/// outlive the job" — and *the job is not the task*. One submission is N array tasks, so N
/// guards each delete the shared body: an `--array=1-27 %6` run had tasks 1–6 succeed and
/// 7–27 fail identically with `.husk-body-<uuid>.sh: No such file or directory`, because the
/// first wave finished and reclaimed the script the rest were still going to read.
///
/// The same shape bites a REQUEUED job — and husk forces the preemptible partition, so a
/// preempted job re-running its script is the normal case, not an edge one.
///
/// So the guard is the wrong owner: it is a per-task actor holding a per-submission resource.
/// Ownership moves to the session, age-based, because nothing on the compute side knows
/// whether some other task is still queued. Generous on purpose — a job may sit pending for
/// days, and reclaiming a body early is exactly the bug being fixed. These are a few KiB of
/// shell each and they are hidden, so the cost of keeping them is far below the cost of
/// deleting one too soon.
pub const BODY_RETAIN_MAX_AGE_SECS: u64 = 7 * 86_400;

/// The bound must exceed how long a job can sit PENDING, or reclaiming a body would
/// reintroduce the defect on a busy queue rather than on a fast one. A compile error rather
/// than a test, because lowering it is the only way this breaks and that is a code change.
const _: () = assert!(BODY_RETAIN_MAX_AGE_SECS >= 7 * 86_400);

/// Which `.husk-body-*.sh` files in a project dir are old enough to reclaim.
///
/// Pure so the rule is testable without a filesystem. Names are husk's own artifacts — the
/// prefix is what makes deleting in a USER's project directory defensible at all.
/// Which `.husk-step-spool-<jobid>` directories in a project dir are safe to reclaim.
///
/// **A1, 2026-08-19: the guard leaks its step spool on the abnormal exit path.** The spool is
/// created before the run-time output guard, and a guard REFUSAL does `exit 1` — which jumps
/// past the cleanup that lives after the re-exec. So a refused job (a swapped `--output`, a
/// preemption) leaves its `.husk-step-spool-<jobid>` behind. The guard's own trap is the
/// immediate fix (Track F); this is the reaper that does not depend on any exit path running
/// at all — the layer that survives even `SIGKILL`, which no in-guard cleanup can.
///
/// Age-based, and the age bar is the same 7 days as the bodies: husk forces the preemptible
/// partition, so nothing husk submits runs for a day, let alone a week. A directory older than
/// that has no live owner by construction, so this never races a running job — the reason it
/// can be a flat age check rather than a liveness probe.
pub fn spools_to_prune(entries: &[(String, u64)], max_age_secs: u64) -> Vec<String> {
    entries
        .iter()
        .filter(|(name, age)| name.starts_with(STEP_SPOOL_PREFIX) && *age > max_age_secs)
        .map(|(name, _)| name.clone())
        .collect()
}

/// Which of this session's jobs a cancel request ENDS, so their staged bodies can be reclaimed.
///
/// **C5: the owner of a resource is its LAST user, not its first.** The guard removes the body
/// on every path where the job RUNS, and `submit` removes it when the submission failed. Both
/// are members of the class "nobody will read this again" — and the class has a third member
/// neither covers: a job that is cancelled before it ever runs. A3 and A10 hit it independently,
/// both by the ordinary route of `--hold`ing a probe job and cancelling it, and A3 measured the
/// residue at ~78 KB spread across real work directories. The age reaper eventually claims those,
/// but only in a directory some LATER broker session happens to start in, which is not a
/// guarantee at all.
///
/// **An array TASK is not a job, and this is the trap.** `scancel 12345_3` ends one task; its
/// siblings still have to read the same body. Deleting it there is exactly the defect `e18144e`
/// fixed — tasks 2..N dying with `.husk-body-<uuid>.sh: No such file or directory`, which reads
/// like an escape and is not. So only a BARE id reclaims: the whole job, every task with it.
pub fn cancels_that_end_a_job(targets: &[String], owned: &[u64]) -> Vec<u64> {
    let mut out: Vec<u64> = targets
        .iter()
        .filter(|t| !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()))
        .filter_map(|t| t.parse::<u64>().ok())
        .filter(|id| owned.contains(id))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

pub fn bodies_to_prune(entries: &[(String, u64)], max_age_secs: u64) -> Vec<String> {
    entries
        .iter()
        .filter(|(name, age)| {
            name.starts_with(".husk-body-") && name.ends_with(".sh") && *age > max_age_secs
        })
        .map(|(name, _)| name.clone())
        .collect()
}

/// Retention for `~/.husk/log`. **B1-F7: the directory had an owner for its CONTENT and
/// none for its LIFETIME.** One file per session is the right shape — it is what makes a
/// dead session's lines distinguishable from a live one's — but "one per session, forever"
/// is unbounded growth in a user's home, which on a cluster is a quota, and a quota that
/// fills is an outage with a confusing cause. Every other husk resource names an owner and
/// a release; this one named neither.
///
/// The owner is the NEXT session start: the wrapper prunes just before it opens its own
/// log. Cheap (one readdir), needs no daemon, and the moment it runs is the moment the
/// directory is about to grow.
///
/// Three independent bounds, because each catches what the others miss: age (old logs are
/// worthless), count (many short sessions in a day), and total bytes (one pathological run
/// that logged a great deal). Whichever binds first wins.
pub const LOG_RETAIN_MAX_AGE_SECS: u64 = 14 * 86_400;
pub const LOG_RETAIN_MAX_FILES: usize = 50;
pub const LOG_RETAIN_MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
/// Never touch anything written in the last hour: a concurrent session's log is not ours to
/// remove, and mtime is the only liveness signal available here. Deleting a live session's
/// log would break the one guarantee that made this file worth keeping outside the spool.
pub const LOG_RETAIN_MIN_AGE_SECS: u64 = 3600;

/// One log file as the retention policy sees it.
pub struct LogEntry {
    pub name: String,
    pub age_secs: u64,
    pub bytes: u64,
}

/// Which log files to delete. **Pure**, so the policy is testable without mtimes on disk —
/// the IO half below is then small enough to read.
///
/// Only files husk itself writes are candidates (`husk-*.log` session logs, `job-*.log` from
/// the compute guard). Anything else in that directory belongs to someone else, and a
/// cleanup that deletes what it did not create is a deletion primitive, not hygiene — the
/// same rule the spool reaper and the job guard already follow.
pub fn logs_to_prune(mut entries: Vec<LogEntry>) -> Vec<String> {
    entries.retain(|e| {
        (e.name.starts_with("husk-") || e.name.starts_with("job-")) && e.name.ends_with(".log")
    });
    // Oldest first: age is the order every bound prunes in.
    entries.sort_by(|a, b| b.age_secs.cmp(&a.age_secs).then_with(|| a.name.cmp(&b.name)));
    let prunable = |e: &LogEntry| e.age_secs >= LOG_RETAIN_MIN_AGE_SECS;

    let mut doomed: Vec<String> = Vec::new();
    let mut kept: Vec<&LogEntry> = Vec::new();
    for e in &entries {
        if e.age_secs > LOG_RETAIN_MAX_AGE_SECS && prunable(e) {
            doomed.push(e.name.clone());
        } else {
            kept.push(e);
        }
    }
    // Count and bytes, still oldest-first, and still never a file that may be live.
    let mut total: u64 = kept.iter().map(|e| e.bytes).sum();
    let mut n = kept.len();
    for e in kept {
        if n <= LOG_RETAIN_MAX_FILES && total <= LOG_RETAIN_MAX_TOTAL_BYTES {
            break;
        }
        if !prunable(e) {
            continue;
        }
        doomed.push(e.name.clone());
        total = total.saturating_sub(e.bytes);
        n -= 1;
    }
    doomed
}

/// Apply `logs_to_prune` to a real directory. Returns how many files were removed.
///
/// Best-effort by design: this is hygiene, not the boundary, so it must never be able to
/// stop a session from starting. Every error is swallowed deliberately.
pub fn prune_log_dir(dir: &Path, now_secs: u64) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
    let mut entries = Vec::new();
    for e in rd.flatten() {
        let Ok(md) = e.metadata() else { continue };
        if !md.is_file() {
            continue;
        }
        let age = md
            .modified()
            .ok()
            .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| now_secs.saturating_sub(d.as_secs()))
            .unwrap_or(0);
        entries.push(LogEntry {
            name: e.file_name().to_string_lossy().to_string(),
            age_secs: age,
            bytes: md.len(),
        });
    }
    let mut removed = 0;
    for name in logs_to_prune(entries) {
        if std::fs::remove_file(dir.join(&name)).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// `YYYYmmdd-HHMMSSZ` from a Unix timestamp. UTC, so a filename means the same thing
/// from any login node; sortable, so `ls` is chronological.
pub fn utc_stamp(unix_secs: u64) -> String {
    let (days, rem) = ((unix_secs / 86400) as i64, unix_secs % 86400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}{m:02}{d:02}-{hh:02}{mm:02}{ss:02}Z")
}

/// Days-since-epoch to (year, month, day). Howard Hinnant's `civil_from_days`, which
/// is exact for the proleptic Gregorian calendar and needs no table and no crate.
fn civil_from_days(z: i64) -> (i64, u64, u64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ---- the settings layers, read under a bound ---------------------------------------
//
// `<project>/.claude/settings.json` and `<project>/.claude/settings.local.json` are POLICY
// INPUTS that the confined agent can create: the compute cage binds them read-only over
// themselves with `--ro-bind-try`, and `-try` skips a path that does not exist yet, so a job
// in a directory that has no `.claude/` can make one. Everything in this section exists
// because five separate readers used to open them with no bound at all (`RE-1`).
//
// It lives in the lib, not beside any one reader, because BOTH binaries read these paths and
// this file's header says why that means one definition and not two (`P8`).

/// The largest settings layer husk will read, in bytes.
///
/// **A read with no bound is a denial of service the confined side can trigger.** Measured on
/// the release binaries, a 200 MB layer at `<project>/.claude/settings.local.json`:
///
///   - the login broker announced readiness at 0.249 s carrying **207 MB of RSS**, on a login
///     node's shared per-user memory cgroup;
///   - `husk-proxy` paid the same 207 MB again on the compute node, and reads the file TWICE
///     (`Allowlist::resolve`, then `login_and_compute_disagree`);
///   - `FsPolicy::settings_parse_ok` re-reads all three layers on **every `sbatch`**, so the
///     cost is not paid once at startup, it is paid per request for the life of the session;
///   - the wrapper's own preflight, whose earlier `read_to_string` cost 802 MB peak RSS on
///     200 MB of `0xff` (`RC2-6`) — that is the measurement this constant was first written
///     for, and it now bounds every other reader too.
///
/// A megabyte cannot fire on anything a human wrote: the settings file husk itself ships,
/// `user-config/settings.json`, is 3,376 bytes, and `project-config/settings.json` is 171 —
/// roughly 310x and 6,000x under this bound. `the_bound_cannot_fire_on_the_config_husk_ships`
/// pins that against the real file rather than against a number in a comment.
pub const MAX_SETTINGS_BYTES: u64 = 1024 * 1024;

// PINNED FROM BOTH SIDES, at COMPILE time, because nothing else pins the value. Every test
// here is written in terms of the constant — `MAX + 1` is oversized whatever `MAX` is — so
// editing this one token to 64 MiB left the entire suite green while re-opening the memory
// half of `RE-1` sixty-four-fold. That is a bound checked by its own definition, which is no
// bound at all (`P9`). An assertion the compiler runs cannot be forgotten (`P6`).
//
// The LOWER bound is the operator: `user-config/settings.json` is 3,376 bytes, and a limit a
// real config can reach is a defect. `the_bound_cannot_fire_on_the_config_husk_ships` checks
// the shipped files against this at run time; this checks the constant itself.
//
// The UPPER bound is the adversary, and it is the half that was missing. The bound decides
// how much agent-authored input every later stage must survive: a megabyte of `denyRead` is
// tens of thousands of entries, each of which is dedup work and a `std::fs::metadata` call in
// `split_file_denies`. Raising this raises all of that with it, which is precisely the
// coupling the first version of this fix failed to notice.
const _: () = assert!(MAX_SETTINGS_BYTES >= 256 * 1024);
const _: () = assert!(MAX_SETTINGS_BYTES <= 4 * 1024 * 1024);

/// Linux `O_NONBLOCK`. Spelled out rather than imported because this crate links no `libc`
/// crate on purpose (see this file's header); `spool::O_NOFOLLOW` is spelled the same way.
///
/// x86_64 and aarch64 — the two architectures husk builds for — both take the asm-generic
/// definition, so one number serves both. It is not TRUSTED to be right, though: a wrong
/// value here would silently restore the blocking `open`, which is the whole bug. `a_fifo_at_a_settings_path_never_blocks_the_reader`
/// opens a real FIFO and fails if the flag did not take effect, so the constant is checked
/// by its EFFECT on the machine the tests run on and not by inspection.
const O_NONBLOCK: i32 = 0o4000;

/// What husk found at a settings path. One input, one disposition, decided once.
///
/// The variants are what the FILE is, not what any particular control should do about it —
/// the broker's policy reader refuses a layer it cannot read (a lost `denyRead` is a wider
/// cage) while the wrapper's preflight refuses a layer it cannot SCAN (an unscanned layer may
/// hold `"enabled": false`). Same facts, two sentences, and each caller writes its own.
pub enum SettingsLayer {
    /// Nothing at that path. Contributes nothing, which is correct: the human made no claims
    /// in a file they did not write.
    Absent,
    /// Something is there and husk could not read it. The same DISPOSITION as absent for
    /// every caller today, but deliberately not the same variant: "husk saw no policy" and
    /// "husk could not look" are not the same sentence to an operator (`P7`).
    Unreadable(std::io::Error),
    /// The bytes, at most `MAX_SETTINGS_BYTES` of them. Not decoded here — the broker wants
    /// strict UTF-8 and the wrapper wants the lossy decode `readFileSync(f, "utf8")` performs
    /// (`RC-2`), and picking one for both would make husk's two halves disagree about the
    /// same file.
    Bytes(Vec<u8>),
    /// A FIFO, a directory, a device or a socket, where a settings file should be.
    NotARegularFile,
    /// Larger than `MAX_SETTINGS_BYTES`; carries the size husk saw, so a refusal can say it.
    TooLarge(u64),
}

/// Read one settings layer without ever blocking and without ever reading more than
/// `MAX_SETTINGS_BYTES`.
///
/// **The order is the control, not tidiness, and the ORDER IS NOT `config.rs`'s.** That one
/// stats the path and then opens it, which is right for `~/.husk/config.json` because only
/// the operator can write that directory. Here the agent can, so a `stat` that says "regular
/// file" is a statement about a NAME, and the name can be pointed at something else before
/// the `open` — `rename(2)` over a path is atomic and needs no privilege. The confined side
/// then wins a race and gets the blocking `open` back.
///
/// So this opens FIRST, with `O_NONBLOCK` — which is what makes `open` on a FIFO return
/// instead of waiting for a writer — and then asks the DESCRIPTOR what it is. `fstat` on a
/// held fd cannot be raced: it answers about the object husk actually has, which is `P15`
/// exactly ("check the name resolves to the object you meant").
///
/// **`O_NOFOLLOW` is deliberately NOT set.** `~/.claude/settings.json -> team/shared.json` is
/// an ordinary thing for an operator to do and `config.rs` supports the same shape; a symlink
/// is followed, and whatever it lands on is then judged on its own merits.
///
/// The size bound is applied TWICE — to the `fstat` and to the read — because a file may grow
/// between them. The second one is what actually holds; the first only saves reading a
/// megabyte husk is going to throw away.
pub fn read_settings_layer(path: &Path) -> SettingsLayer {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let f = match std::fs::OpenOptions::new().read(true).custom_flags(O_NONBLOCK).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return SettingsLayer::Absent,
        Err(e) => return SettingsLayer::Unreadable(e),
    };
    // `fstat`, not `stat`: see the note above about the race this closes.
    let meta = match f.metadata() {
        Ok(m) => m,
        Err(e) => return SettingsLayer::Unreadable(e),
    };
    if !meta.is_file() {
        return SettingsLayer::NotARegularFile;
    }
    if meta.len() > MAX_SETTINGS_BYTES {
        return SettingsLayer::TooLarge(meta.len());
    }
    let mut buf = Vec::new();
    if let Err(e) = f.take(MAX_SETTINGS_BYTES + 1).read_to_end(&mut buf) {
        return SettingsLayer::Unreadable(e);
    }
    if buf.len() as u64 > MAX_SETTINGS_BYTES {
        return SettingsLayer::TooLarge(buf.len() as u64);
    }
    SettingsLayer::Bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::LOGIN_AUTO_EXEC_DENY;

    // ---- RE-1: the settings layers are read under a bound ----------------------------
    //
    // `<project>/.claude/settings.json` and `settings.local.json` are policy inputs the
    // CONFINED AGENT can create, and five readers used to open them with `read_to_string`.
    // Two shapes made that unbounded, and neither needs any privilege:
    //
    //   - a FIFO. `open(2)` on one waits for a writer and `read_to_string` never returns, so
    //     one `mkfifo` refused every later launch, permanently. Measured on the release
    //     binaries at `608618e`: the wrapper produced NOTHING for 15 s and was killed; the
    //     login broker's last line named a Lustre walk; `husk-proxy` printed nothing at all.
    //   - a very large file. Measured: a 200 MB layer cost 207 MB of RSS in the broker and
    //     207 MB again in `husk-proxy`, and `settings_parse_ok` re-reads all three layers on
    //     every `sbatch`.
    //
    // These pin the READER, which is the level the bug is at — the level at which one fix
    // covers all five call sites. `FsPolicy`'s own tests are the false friends: every one of
    // them is about CONTENT, and neither of these shapes is about content.

    fn layer_scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("husk-layer-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// **MUTATION that turns this red:** drop `.custom_flags(O_NONBLOCK)` from
    /// `read_settings_layer`. The open then blocks, the worker thread never sends, and this
    /// FAILS at five seconds rather than hanging the suite forever — which is the point of
    /// running it on a thread at all.
    ///
    /// Removing the `is_file()` check alone leaves this test GREEN, because with `O_NONBLOCK`
    /// the FIFO reads as empty rather than blocking. That is not a hole in the test, it is the
    /// second assertion: an empty read would make husk treat a planted FIFO as a settings file
    /// that sets no policy, so the disposition has to be `NotARegularFile` and not `Bytes`.
    #[test]
    fn a_fifo_at_a_settings_path_never_blocks_the_reader() {
        let d = layer_scratch("fifo");
        let p = d.join("settings.local.json");
        let made = std::process::Command::new("mkfifo")
            .arg(&p)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !made {
            return; // no mkfifo on this box; nothing to assert
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let probe = p.clone();
        std::thread::spawn(move || {
            let _ = tx.send(matches!(
                super::read_settings_layer(&probe),
                super::SettingsLayer::NotARegularFile
            ));
        });
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(true) => {}
            Ok(false) => panic!(
                "a FIFO read as something husk would take policy from. `O_NONBLOCK` makes the \
                 open return, but a FIFO with no writer then reads as ZERO BYTES — i.e. as an \
                 empty settings file — so the descriptor still has to be rejected by TYPE."
            ),
            Err(_) => panic!(
                "reading a FIFO settings layer blocked for 5s. `open` on a FIFO waits for a \
                 writer unless O_NONBLOCK is set, and this read runs in the wrapper's preflight \
                 (its FIRST statement), in the broker's 15s launch budget, and on every sbatch \
                 — so this is not a slow start, it is husk never starting, with the operator \
                 pointed at a Lustre walk or at nothing at all (`RE-1`, `P11`)."
            ),
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A directory and a device node take the same path as the FIFO, and a device is the one
    /// that would otherwise be read to exhaustion: `/dev/zero` is a settings layer of infinite
    /// length. The `take()` bound already caps it; the type check is what NAMES it.
    #[test]
    fn a_directory_or_a_device_is_not_a_settings_layer_either() {
        let d = layer_scratch("notafile");
        std::fs::create_dir_all(d.join("settings.json")).unwrap();
        assert!(matches!(
            super::read_settings_layer(&d.join("settings.json")),
            super::SettingsLayer::NotARegularFile
        ));
        // A symlink is FOLLOWED — `~/.claude/settings.json -> team/shared.json` is ordinary —
        // and then judged on what it lands on. Pointing one at a device must not launder it.
        if std::os::unix::fs::symlink("/dev/zero", d.join("settings.local.json")).is_ok() {
            assert!(
                matches!(
                    super::read_settings_layer(&d.join("settings.local.json")),
                    super::SettingsLayer::NotARegularFile
                ),
                "a symlink to a device is not a settings file"
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **MUTATION that turns this red:** delete either size check in `read_settings_layer`.
    /// Deleting only the `meta.len()` one leaves it green (the read bound still holds), which
    /// is correct and is why the message quotes the size from whichever check fired.
    #[test]
    fn a_settings_layer_over_the_bound_is_refused_rather_than_read() {
        let d = layer_scratch("toobig");
        let p = d.join("settings.local.json");
        std::fs::write(&p, vec![b'x'; (super::MAX_SETTINGS_BYTES + 1) as usize]).unwrap();
        match super::read_settings_layer(&p) {
            super::SettingsLayer::TooLarge(n) => {
                assert_eq!(n, super::MAX_SETTINGS_BYTES + 1, "carry the size, so a refusal can say it")
            }
            _ => panic!("a layer over the bound must not be read into memory"),
        }
        // ...and one byte UNDER the bound is still read. A bound that refuses the last legal
        // file is an off-by-one that only shows up in production.
        std::fs::write(&p, vec![b'x'; super::MAX_SETTINGS_BYTES as usize]).unwrap();
        assert!(matches!(super::read_settings_layer(&p), super::SettingsLayer::Bytes(_)));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The bound is only defensible if no real config can reach it, so this asks the REAL
    /// FILES rather than a number in a comment — the shipped user layer and the shipped
    /// project layer, read from the repository. If husk's own config ever grows past a
    /// megabyte, this fails before an operator finds out by being refused a launch.
    #[test]
    fn the_bound_cannot_fire_on_the_config_husk_ships() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut checked = 0;
        for rel in ["user-config/settings.json", "project-config/settings.json"] {
            let f = root.join(rel);
            let Ok(meta) = std::fs::metadata(&f) else { continue };
            checked += 1;
            assert!(
                meta.len() * 8 < super::MAX_SETTINGS_BYTES,
                "{rel} is {} bytes against a {}-byte bound — under 8x of headroom is not a \
                 bound on an adversary any more, it is a bound on the operator",
                meta.len(),
                super::MAX_SETTINGS_BYTES
            );
        }
        assert!(checked > 0, "neither shipped settings file was found; this test asserted nothing");
    }

    /// The race the fd check exists for, run rather than argued.
    ///
    /// A `stat`-then-`open` reader decides on a NAME. The agent owns that directory, so it can
    /// `rename(2)` a FIFO over the path between the two calls and get the blocking `open` back
    /// — atomically, unprivileged, and as many times as it likes. This spins exactly that
    /// swap under the reader.
    ///
    /// **MUTATION that turns this red:** put a `std::fs::metadata(path)` type check BEFORE the
    /// open and drop the flag, i.e. transcribe `config.rs`'s order. It hangs within a few
    /// hundred iterations on this machine.
    #[test]
    fn swapping_a_fifo_over_the_path_mid_read_still_cannot_block() {
        let d = layer_scratch("race");
        let p = d.join("settings.local.json");
        let fifo = d.join("f");
        if !std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return;
        }
        std::fs::write(d.join("r"), b"{}").unwrap();
        std::fs::rename(d.join("r"), &p).unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flip = {
            let (d, p, fifo, stop) = (d.clone(), p.clone(), fifo.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = std::fs::hard_link(&fifo, d.join("tmp"));
                    let _ = std::fs::rename(d.join("tmp"), &p);
                    std::fs::write(d.join("tmp2"), b"{}").unwrap();
                    let _ = std::fs::rename(d.join("tmp2"), &p);
                }
            })
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let probe = p.clone();
        std::thread::spawn(move || {
            for _ in 0..2000 {
                // Any disposition is fine; NONE of them may be "still running".
                let _ = super::read_settings_layer(&probe);
            }
            let _ = tx.send(());
        });
        let outcome = rx.recv_timeout(std::time::Duration::from_secs(10));
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = flip.join();
        let _ = std::fs::remove_dir_all(&d);
        assert!(
            outcome.is_ok(),
            "the reader blocked while a FIFO was being renamed over the path. A type check on \
             the NAME is a statement about a name; the agent owns that directory and can point \
             it somewhere else before the open (`P15`). Decide on the DESCRIPTOR."
        );
    }

    #[test]
    fn renviron_is_on_the_deny_list_so_it_cannot_defeat_the_rprofile_mask() {
        // A4-L2: .Renviron can set R_PROFILE_USER to an agent path R sources as code, so
        // masking .Rprofile while leaving .Renviron writable protects nothing. It is the
        // sibling that must be swept in the same pass.
        assert!(
            LOGIN_AUTO_EXEC_DENY.contains(&".Renviron"),
            ".Renviron must be denied alongside .Rprofile or the mask is bypassable"
        );
    }

    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("husk-lib-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_staged_body_outlives_the_task_that_reads_it() {
        // **2026-08-09, Balfrin.** `--array=1-27 %6`: tasks 1-6 succeeded, 7-27 all failed
        // with `.husk-body-<uuid>.sh: No such file or directory`. The guard deleted the body
        // at the end of each task, so the first wave reclaimed the script the rest were still
        // going to read. 21 of 27 results lost, and the array as a whole looked like it ran.
        //
        // The guard is a per-TASK actor and the body is a per-SUBMISSION resource, so it can
        // never be the owner: nothing on the compute node knows whether another task is still
        // queued. Ownership is age-based and the session's.
        let fresh = 60u64;
        let old = super::BODY_RETAIN_MAX_AGE_SECS + 1;

        let e = |n: &str, a: u64| (n.to_string(), a);
        let entries = vec![
            e(".husk-body-abc.sh", fresh),          // a job could still be queued on this
            e(".husk-body-def.sh", old),            // nothing can still be waiting
            e("run.sh", old),                       // not husk's
            e(".husk-body-ghi.txt", old),           // husk-ish name, not a body
            e("husk-body-jkl.sh", old),             // no leading dot: not ours either
            e(".husk-step-spool-123", old),         // a different husk artifact, different owner
        ];
        let doomed = super::bodies_to_prune(&entries, super::BODY_RETAIN_MAX_AGE_SECS);

        assert_eq!(doomed, vec![".husk-body-def.sh"], "only an aged husk BODY may be reclaimed");
        assert!(
            !doomed.iter().any(|n| n == ".husk-body-abc.sh"),
            "a recent body must survive — reclaiming one early IS the bug being fixed"
        );
    }

    #[test]
    fn cancelling_a_job_reclaims_its_body_and_cancelling_a_task_does_not() {
        let owned = [5144759u64, 5146044];

        // The ordinary case A3 and A10 both hit: --hold a probe, cancel it, walk away. Before
        // this rule nothing owned that body -- the guard never ran, and `submit` only reclaims
        // when the SUBMISSION failed.
        assert_eq!(cancels_that_end_a_job(&["5144759".into()], &owned), vec![5144759]);

        // THE ONE THAT MATTERS. `e18144e` cost a round when task 1 deleted the body its
        // siblings had not read yet; tasks 2..N died with "No such file or directory" and it
        // read like an escape. Cancelling one TASK must reclaim nothing.
        assert!(
            cancels_that_end_a_job(&["5144759_3".into()], &owned).is_empty(),
            "an array TASK is not the job: its siblings still have to read that body"
        );
        // ... but cancelling the array as a whole ends every task with it.
        assert_eq!(cancels_that_end_a_job(&["5144759".into()], &owned), vec![5144759]);
    }

    #[test]
    fn a_cancel_reclaims_nothing_this_session_did_not_submit() {
        let owned = [5144759u64];
        // The ownership gate refuses these before we get here; this is the second lock, so a
        // future caller cannot turn "husk deletes its own staged bodies" into "husk deletes a
        // file named by a job id it was handed".
        assert!(cancels_that_end_a_job(&["999".into()], &owned).is_empty());
        assert!(cancels_that_end_a_job(&["".into()], &owned).is_empty());
        assert!(cancels_that_end_a_job(&["../x".into()], &owned).is_empty());
        assert!(cancels_that_end_a_job(&["5144759x".into()], &owned).is_empty());
    }

    #[test]
    fn only_old_step_spools_are_reaped_and_only_husk_dirs() {
        let old = super::BODY_RETAIN_MAX_AGE_SECS + 1;
        let young = 10u64;
        let entries = vec![
            (".husk-step-spool-5138292".to_string(), old),   // leaked, old -> reap
            (".husk-step-spool-9999999".to_string(), young),  // maybe still live -> keep
            (".husk-body-abc.sh".to_string(), old),           // a body, not a spool -> not here
            ("results".to_string(), old),                     // the user's own dir -> never
            (".husk-slurm-spool-1".to_string(), old),         // the SESSION spool, not a step -> keep
        ];
        let doomed = super::spools_to_prune(&entries, super::BODY_RETAIN_MAX_AGE_SECS);
        assert_eq!(doomed, vec![".husk-step-spool-5138292".to_string()],
            "only an OLD step spool is reaped, and nothing else: {doomed:?}");
    }

    #[test]
    fn utc_stamp_is_sortable_and_correct() {
        assert_eq!(utc_stamp(0), "19700101-000000Z");
        assert_eq!(utc_stamp(1_785_542_400), "20260801-000000Z"); // 2026-08-01T00:00:00Z
        assert_eq!(utc_stamp(1_785_542_400 + 3661), "20260801-010101Z");
        // A leap day, the case a hand-rolled calendar gets wrong.
        assert_eq!(utc_stamp(1_709_164_800), "20240229-000000Z");
        // Lexicographic order must equal chronological order — that is the point.
        assert!(utc_stamp(1_785_542_400) < utc_stamp(1_785_542_401));
    }

    // The audit log must not be inside the spool: the spool is agent-writable by
    // construction, so a log kept there is one the confined side can rewrite.
    #[test]
    fn session_log_lives_outside_the_spool_and_the_project() {
        let log = session_log_path(Path::new("/users/me"), 1_785_542_400, 4242);
        assert_eq!(log, PathBuf::from("/users/me/.husk/log/husk-20260801-000000Z-4242.log"));
        assert!(!log.to_string_lossy().contains(SPOOL_PREFIX));
    }

    #[test]
    fn spool_dir_names_cover_per_session_and_legacy() {
        assert!(is_spool_dir_name(".husk-slurm-spool"));       // legacy fixed name
        assert!(is_spool_dir_name(".husk-slurm-spool-12345")); // per-session
        assert!(!is_spool_dir_name(".husk-slurm-spoolX"));     // not ours
        assert!(!is_spool_dir_name(".husk-step-spool-99"));    // the job's, cleaned by the job
        assert!(!is_spool_dir_name("src"));
    }

    // The reaper deletes directories, so its refusal cases matter more than its
    // success case: a live owner, and anything husk did not create.
    #[test]
    fn reaper_spares_live_owners_and_foreign_files() {
        let dir = scratch("reap-spare");
        let mine = session_spool_dir(&dir, 1);
        fs::create_dir_all(&mine).unwrap();

        // Owned by a pid that certainly exists: us.
        let live = session_spool_dir(&dir, std::process::id());
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("owner"), format!("pid={}\n", std::process::id())).unwrap();

        // Dead owner, but the user left a file of their own in it.
        let dead_but_dirty = session_spool_dir(&dir, 999_999);
        fs::create_dir_all(&dead_but_dirty).unwrap();
        fs::write(dead_but_dirty.join("owner"), "pid=999999\n").unwrap();
        fs::write(dead_but_dirty.join("notes.txt"), "mine").unwrap();

        let notes = reap_stale_spools(&dir, &mine, Duration::ZERO);

        assert!(live.exists(), "reaped a spool whose owner is still running: {notes:?}");
        assert!(dead_but_dirty.exists(), "reaped a directory holding a foreign file: {notes:?}");
        assert!(
            dead_but_dirty.join("notes.txt").exists(),
            "deleted a file husk did not create: {notes:?}"
        );
        assert!(mine.exists(), "reaped the caller's own spool: {notes:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A sample file name for every entry of `SPOOL_OWNED_PATTERNS`, derived from the list
    /// rather than typed out.
    ///
    /// `B4-5`: the tests that used to guard this list planted `job-abc.sh` and `resp-abc.json`
    /// by hand, so the list looked maintained while carrying one entry with no writer and
    /// missing one writer with no entry. Deriving the fixtures means a new entry is exercised
    /// the moment it is added, and an entry whose matcher does not work goes red (`P9`).
    fn one_file_per_owned_pattern() -> Vec<String> {
        SPOOL_OWNED_PATTERNS
            .iter()
            .map(|a| format!("{}sample{}", a.prefix, a.suffix))
            .collect()
    }

    /// `RDF-D-4`: THE ONE TEST THAT IS NOT THE TABLE READING ITSELF.
    ///
    /// Every other assertion about `SPOOL_OWNED_PATTERNS` derives its fixtures FROM
    /// `SPOOL_OWNED_PATTERNS` — `one_file_per_owned_pattern` here, and the `planted` loop in
    /// `spool.rs::gc_removes_stale_orphans_but_not_live_requests`. That was a deliberate
    /// improvement (`B4-5`: a hand-typed fixture let the list carry an entry with no writer),
    /// and it bought a self-sealing false friend with the change: DELETE an entry and its
    /// sample is never planted, so the absence assertion passes vacuously. Measured at
    /// `608618e` — deleting `dry-`, which is the entry `B4-1` is ABOUT, left the whole suite
    /// green, and so did deleting `resp-`.
    ///
    /// `FIX-D` names this exact trap and defends against it on the COMPUTE side ("a list
    /// derived only from the globs would delete its own witness"). This is the login side
    /// getting the same defence: the expected table is written out here, independently, with
    /// the writer that justifies each row. Changing the table costs a deliberate edit HERE,
    /// where the edit has to name a writer.
    #[test]
    fn the_owned_pattern_table_is_the_one_we_think_it_is() {
        // (prefix, suffix, gc_while_live, who writes it)
        const REFERENCE: &[(&str, &str, bool, &str)] = &[
            ("req-", ".json", false,
             "the srun stub, inside the cage; LIVE, so `gc` must not take it (F4)"),
            ("resp-", ".json", true, "`step::write_response`, via `write_atomic`"),
            ("dry-", ".sh", true, "`Broker::submit` on the --dry-run path (B4-1)"),
            ("job-", ".sh", true,
             "LEGACY: v0.4 and earlier staged husk's script here; no current writer (B4-5)"),
            (".", ".tmp", true, "`write_atomic`'s in-flight temp, from TMP_PREFIX/TMP_SUFFIX"),
        ];
        assert_eq!(
            SPOOL_OWNED_PATTERNS.len(),
            REFERENCE.len(),
            "the owned-artifact table and its reference disagree on HOW MANY name shapes husk \
             claims in a spool. An entry ADDED without a row here is one nothing independent \
             checks; an entry REMOVED is a file husk writes and no longer reclaims, and the \
             session-teardown message will report it as \"files husk did not create\" (`B4-1`)."
        );
        for (i, (prefix, suffix, gc, who)) in REFERENCE.iter().enumerate() {
            let got = &SPOOL_OWNED_PATTERNS[i];
            assert_eq!(got.prefix, *prefix, "entry {i}: written by {who}");
            assert_eq!(got.suffix, *suffix, "entry {i} ({prefix}): written by {who}");
            assert_eq!(
                got.gc_while_live, *gc,
                "entry {i} ({prefix}) changed whether the MID-SESSION reaper may take it. \
                 The one `false` is the live request a stub is blocked on; normalising it \
                 away is a silent hang (`P13`). {who}"
            );
            assert!(!got.why.is_empty(), "entry {i} ({prefix}) must carry its own reason");
        }
    }

    #[test]
    fn the_tmp_glob_matches_what_write_atomic_writes() {
        // The guard's cleanup cannot call `tmp_name`; it is shell, so it carries the glob.
        // That is a second spelling of the same name, and this is the tie (`P8`).
        assert_eq!(TMP_GLOB, format!("{TMP_PREFIX}*{TMP_SUFFIX}"));
        let produced = tmp_name("resp-abc123.json");
        assert_eq!(produced, ".resp-abc123.json.tmp");
        assert!(
            produced.starts_with(TMP_PREFIX) && produced.ends_with(TMP_SUFFIX),
            "the glob would miss the file the writer actually writes: {produced}"
        );
        // And the login reaper recognises it, which is what the compute guard did not.
        assert!(is_husk_spool_file(&produced));
        assert!(is_reclaimable_orphan(&produced));
    }

    #[test]
    fn gc_and_the_reaper_differ_on_exactly_one_artifact_and_it_is_the_live_request() {
        // Two dispositions for one list. The difference is deliberate and it is ONE entry:
        // `gc` runs mid-session, and a request is the one thing in the spool that somebody is
        // still waiting on. Anything else diverging is drift, and this is where it shows.
        let split: Vec<&str> = SPOOL_OWNED_PATTERNS
            .iter()
            .filter(|a| !a.gc_while_live)
            .map(|a| a.prefix)
            .collect();
        assert_eq!(
            split,
            vec!["req-"],
            "the mid-session reaper and the teardown reaper may differ about a LIVE request \
             and nothing else; a new exception needs its own reason on the entry"
        );
        for name in one_file_per_owned_pattern() {
            assert!(
                is_husk_spool_file(&name),
                "{name} is on the owned list but the teardown reaper does not recognise it"
            );
        }
        assert!(!is_reclaimable_orphan("req-live.json"));
        assert!(!is_husk_spool_file("notes.txt"));
        assert!(!is_reclaimable_orphan("notes.txt"));
    }

    #[test]
    fn a_spool_left_by_a_v0_4_broker_is_still_reapable() {
        // Why `job-*.sh` is KEPT although nothing writes it any more (`B4-5` asked for the
        // arm to be deleted). v0.4 staged husk's wrapped script in the spool as `job-<id>.sh`;
        // v0.4 is tagged and installed on both clusters, so a v0.4 session that was killed
        // leaves one behind, and a later broker is the only thing that will ever clean it up.
        // Delete the arm and that directory becomes permanent AND says "files husk did not
        // create" about a file husk created — `B4-1`'s symptom, produced by the fix for
        // `B4-1`'s sibling.
        //
        // `RDF-D-3`: the fixture is a REAL v0.4 spool now. It used to be
        // `session_spool_dir(&dir, 999_999)` plus an `owner` file — the v0.5 layout — while
        // v0.4 wrote the fixed legacy name `.husk-slurm-spool` with no `owner` at all
        // (`v0.4:main.rs:83`). Both layouts funnel into `remove_spool_dir`, so the `job-`
        // arm was genuinely pinned either way; the test's NAME described a directory it did
        // not build. Building the real one also exercises the age-based legacy branch of
        // `reap_stale_spools`, which is the branch a v0.4 leftover actually takes.
        let dir = scratch("reap-v04");
        let mine = session_spool_dir(&dir, 1);
        fs::create_dir_all(&mine).unwrap();
        let dead = dir.join(SPOOL_PREFIX);
        fs::create_dir_all(&dead).unwrap();
        fs::write(dead.join("job-4f2a1c.sh"), "#!/bin/bash\n#SBATCH --parsable\n").unwrap();

        let notes = reap_stale_spools(&dir, &mine, Duration::ZERO);

        assert!(!dead.exists(), "a v0.4-era spool must still be reapable: {notes:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reaper_removes_a_dead_session_and_an_idle_legacy_spool() {
        let dir = scratch("reap-take");
        let mine = session_spool_dir(&dir, 1);
        fs::create_dir_all(&mine).unwrap();

        // pid 999999 is above the usual pid_max and not running here.
        let dead = session_spool_dir(&dir, 999_999);
        fs::create_dir_all(&dead).unwrap();
        fs::write(dead.join("owner"), "pid=999999\nproject=/somewhere\n").unwrap();
        // One file per entry of the list, DERIVED — including `dry-sample.sh`, the file
        // `B4-1` found leaking, and `.sample.tmp`, the shape the compute side missed.
        for name in one_file_per_owned_pattern() {
            fs::write(dead.join(&name), "x").unwrap();
        }
        // …and two names written out BY HAND, which is not redundancy (`RDF-D-4`). The loop
        // above takes its fixtures from the list under test, so deleting an entry deletes
        // its own witness and the reaper is never asked about that shape: at `608618e`,
        // removing `dry-` or `resp-` from `SPOOL_OWNED_PATTERNS` left the entire suite green.
        // These two are planted whatever the list says, so an entry that goes missing leaves
        // a file the reaper cannot claim, `rmdir` fails, and this test goes red.
        for name in ["dry-4f2a1c.sh", "resp-4f2a1c.json"] {
            fs::write(dead.join(name), "x").unwrap();
        }

        // The pre-v0.5 layout: fixed name, no owner file, just an old log.
        let legacy = dir.join(SPOOL_PREFIX);
        fs::create_dir_all(&legacy).unwrap();
        fs::write(legacy.join("broker.log"), "old lines\n").unwrap();

        let notes = reap_stale_spools(&dir, &mine, Duration::ZERO);

        assert!(!dead.exists(), "a spool whose owner is gone must be reaped: {notes:?}");
        assert!(!legacy.exists(), "an idle pre-v0.5 spool must be reaped: {notes:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    // A legacy spool cannot prove it is dead, so age is the only evidence available.
    // A fresh one may belong to an older husk that is running right now.
    #[test]
    fn reaper_leaves_a_recently_touched_legacy_spool() {
        let dir = scratch("reap-legacy-fresh");
        let mine = session_spool_dir(&dir, 1);
        fs::create_dir_all(&mine).unwrap();
        let legacy = dir.join(SPOOL_PREFIX);
        fs::create_dir_all(&legacy).unwrap();
        fs::write(legacy.join("broker.log"), "a session may still be writing this\n").unwrap();

        let notes = reap_stale_spools(&dir, &mine, Duration::from_secs(3600));

        assert!(legacy.exists(), "reaped a legacy spool that could still be in use: {notes:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reaper_ignores_directories_that_are_not_husk_spools() {
        let dir = scratch("reap-foreign");
        let mine = session_spool_dir(&dir, 1);
        fs::create_dir_all(&mine).unwrap();
        let foreign = dir.join(".config");
        fs::create_dir_all(&foreign).unwrap();

        reap_stale_spools(&dir, &mine, Duration::ZERO);

        assert!(foreign.exists(), "the reaper touched a directory that is not a husk spool");
        let _ = fs::remove_dir_all(&dir);
    }

    // husk can be launched in a shared world-writable directory, where a spool-shaped
    // name proves nothing about who created it. This is the gate that keeps the reaper
    // from ever considering someone else's directory.
    #[test]
    fn owned_by_me_distinguishes_mine_from_another_users() {
        let dir = scratch("owner-uid");
        assert!(owned_by_me(&dir), "a directory this test just created must read as ours");
        // Root-owned on every system husk runs on, and the tests do not run as root.
        assert!(!owned_by_me(Path::new("/etc")), "a root-owned directory must not read as ours");
        assert!(!owned_by_me(Path::new("/nonexistent-husk-path")), "must fail closed");
        let _ = fs::remove_dir_all(&dir);
    }

    // The length limit is the reason the socket left the step spool. This pins the real
    // measurement: the old layout on a realistic project path, versus the new one.
    #[test]
    fn socket_path_length_is_checked_against_the_kernel_limit() {
        let dir = scratch("sockpath");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(check_socket_path(&dir.join("net.sock")).is_ok());

        // The old layout: <workdir>/.husk-step-spool-<jobid>/net.sock. A project path of
        // 80 characters is not exotic on scratch, and it does not fit.
        let deep = PathBuf::from(format!("/scratch/{}", "d".repeat(70)))
            .join(".husk-step-spool-4988019")
            .join("net.sock");
        let err = check_socket_path(&deep).expect_err("an over-long path must be refused");
        assert!(err.contains("108") || err.contains("107"), "the message must name the limit: {err}");
        assert!(err.contains("bytes"), "the message must give the actual length: {err}");

        // Exactly at the boundary: 107 bytes fits, 108 does not.
        let base = "/tmp/";
        let ok = PathBuf::from(format!("{base}{}", "x".repeat(107 - base.len())));
        let over = PathBuf::from(format!("{base}{}", "x".repeat(108 - base.len())));
        assert_eq!(ok.as_os_str().len(), 107);
        assert_eq!(over.as_os_str().len(), 108);
        // Both have /tmp as parent, which is world-writable — so isolate the length check
        // by asserting only on which error comes back.
        assert!(!check_socket_path(&ok).is_err_and(|e| e.contains("sun_path")));
        assert!(check_socket_path(&over).is_err_and(|e| e.contains("sun_path")));
        let _ = fs::remove_dir_all(&dir);
    }

    // /tmp is world-writable and job ids are public, so the directory the socket goes in
    // is the thing an attacker would target. Refusing costs the job its network; not
    // refusing could route the job's egress through someone else's proxy.
    #[test]
    fn socket_path_refuses_a_directory_we_do_not_control() {
        let dir = scratch("sockdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(check_socket_path(&dir.join("net.sock")).is_ok(), "our own 0700 dir is fine");

        for mode in [0o777, 0o770, 0o707, 0o701] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = check_socket_path(&dir.join("net.sock"))
                .expect_err("a group/world-accessible directory must be refused");
            assert!(err.contains("mode"), "{err}");
        }

        // Owned by root, not by us.
        let err = check_socket_path(Path::new("/etc/net.sock"))
            .expect_err("a directory owned by another user must be refused");
        assert!(err.contains("owned by uid"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pid_is_alive_sees_this_process_and_not_a_dead_one() {
        assert!(pid_is_alive(std::process::id()));
        assert!(!pid_is_alive(999_999));
    }

    fn log(name: &str, age_secs: u64, bytes: u64) -> LogEntry {
        LogEntry { name: name.to_string(), age_secs, bytes }
    }

    #[test]
    fn the_log_directory_has_a_lifetime_bound_by_age_count_and_bytes() {
        // **B1-F7.** `~/.husk/log` had an owner for its CONTENT (one file per session, kept
        // outside the agent-writable spool on purpose) and none for its LIFETIME. On a
        // cluster an unbounded directory in $HOME is a quota, and a quota that fills is an
        // outage whose cause nobody connects to husk.
        //
        // Three bounds because each catches what the others miss.
        let old = logs_to_prune(vec![
            log("husk-20260101-000000Z-1.log", 30 * 86_400, 10),
            log("husk-20260804-000000Z-2.log", 86_400, 10),
        ]);
        assert_eq!(old, vec!["husk-20260101-000000Z-1.log"], "age must prune");

        let many: Vec<LogEntry> = (0..LOG_RETAIN_MAX_FILES + 5)
            .map(|i| log(&format!("husk-{i:04}.log"), 7200 + i as u64, 10))
            .collect();
        assert_eq!(logs_to_prune(many).len(), 5, "count must prune the excess, and only it");

        let fat = vec![
            log("husk-a.log", 7200, LOG_RETAIN_MAX_TOTAL_BYTES),
            log("husk-b.log", 3601, LOG_RETAIN_MAX_TOTAL_BYTES),
        ];
        assert_eq!(logs_to_prune(fat), vec!["husk-a.log"], "bytes must prune, oldest first");
    }

    #[test]
    fn log_pruning_spares_live_sessions_and_files_husk_did_not_write() {
        // A concurrent session's log is not ours to delete — mtime is the only liveness
        // signal here, so nothing recent is ever a candidate. Deleting a live session's log
        // would break the exact guarantee that put this file outside the spool.
        let live: Vec<LogEntry> = (0..LOG_RETAIN_MAX_FILES + 10)
            .map(|i| log(&format!("husk-{i:04}.log"), 60, 10))
            .collect();
        assert!(logs_to_prune(live).is_empty(), "a fresh file may belong to a live session");

        // And a cleanup that enumerates what it did NOT create is a deletion primitive, not
        // hygiene — the same rule the spool reaper and the job guard already follow.
        let foreign = vec![
            log("notes.txt", 99 * 86_400, 10),
            log("husk-old.log", 99 * 86_400, 10),
            log("job-4242.log", 99 * 86_400, 10),
            log("important-backup.log.gz", 99 * 86_400, 10),
        ];
        let doomed = logs_to_prune(foreign);
        assert!(doomed.contains(&"husk-old.log".to_string()), "husk's own logs are fair game");
        assert!(doomed.contains(&"job-4242.log".to_string()), "so are the guard's");
        assert_eq!(doomed.len(), 2, "and nothing else, ever: {doomed:?}");
    }
}
