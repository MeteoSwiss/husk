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

/// Directory-name prefix for a login-side spool. The bare prefix with no `-<pid>`
/// suffix is the LEGACY fixed name used before spools became per-session; the reaper
/// still recognises it so old directories get cleaned up rather than lingering.
pub const SPOOL_PREFIX: &str = ".husk-slurm-spool";

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

/// Name patterns for the transient spool files (prefix, suffix).
pub const SPOOL_OWNED_PATTERNS: &[(&str, &str)] =
    &[("req-", ".json"), ("resp-", ".json"), ("job-", ".sh"), (".", ".tmp")];

fn is_husk_spool_file(name: &str) -> bool {
    SPOOL_OWNED_FILES.contains(&name)
        || SPOOL_OWNED_PATTERNS
            .iter()
            .any(|(p, s)| name.len() > p.len() + s.len() && name.starts_with(p) && name.ends_with(s))
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

#[cfg(test)]
mod tests {
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

    #[test]
    fn reaper_removes_a_dead_session_and_an_idle_legacy_spool() {
        let dir = scratch("reap-take");
        let mine = session_spool_dir(&dir, 1);
        fs::create_dir_all(&mine).unwrap();

        // pid 999999 is above the usual pid_max and not running here.
        let dead = session_spool_dir(&dir, 999_999);
        fs::create_dir_all(&dead).unwrap();
        fs::write(dead.join("owner"), "pid=999999\nproject=/somewhere\n").unwrap();
        fs::write(dead.join("resp-abc.json"), "{}").unwrap();
        fs::write(dead.join("job-abc.sh"), "#!/bin/sh\n").unwrap();

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
