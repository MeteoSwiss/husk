//! The broker's TRUSTED view of the human's Mode-1 uenv session, captured from
//! its OWN environment at startup. The agent never influences this (see BROKER.md:
//! "uenv — inherit the Mode-1 session").

use std::env;
use std::os::unix::process::CommandExt;
use std::time::{Duration, Instant};

// NB: the broker submits uenv jobs with `--export=ALL` (inherit the trusted Mode-1
// session), NOT a locked env allowlist. Verified on Balfrin (uenv 8.1) + Santis
// (10.0.1): only --export=ALL activates the view PATH inside the job; an allowlist
// mounts but leaves the view inactive. See policy.rs for the rationale + AV7 caveat.

/// The partition the broker forces (and requires the agent to request) when
/// HUSK_SLURM_PARTITION is unset. Only a default: not every site has a preemptible
/// partition, so an operator overrides it via the env var.
pub const DEFAULT_PARTITION: &str = "preemptible";

/// Split the operator's `HUSK_SLURM_PARTITION` into the set a job may request.
///
/// A comma-separated LIST, because one partition is not enough on a real cluster: GPU
/// nodes and CPU-only postprocessing nodes are different partitions, and a workflow
/// legitimately needs both. Which one a job wants is a HARDWARE choice only the job can
/// make, so husk cannot pick for it — but it can bound the set.
///
/// Entries are trimmed and empties dropped, so `short, pp-short,` is three tokens and two
/// partitions. An entry that is not a plausible partition name is DROPPED rather than
/// carried: this string is operator config, but it becomes an argument to the real sbatch,
/// and a name is never allowed to smuggle an option or a shell character.
///
/// **...and it is REPORTED, which it was not.** This whole block belonged to
/// `parse_partition_list` and was orphaned onto `parse_account_list` by `3c04ddf`, which
/// inserted that function between an existing doc comment and its `pub fn`. The merged block
/// then argued BOTH dispositions — "dropped rather than carried" here, "reported rather than
/// dropped in silence" below — and the function that actually implemented the silent one was
/// the one with no documentation at all (`B2-3`). Worse than cosmetic: dropping every entry
/// leaves an empty list, and `from_env` turns an empty list into `DEFAULT_PARTITION`, so one
/// misplaced space in `HUSK_SLURM_PARTITION="pp short"` silently SUBSTITUTED a different
/// policy — a partition the site may not even have — with no line anywhere saying so.
///
/// Now the two siblings agree, use one grammar (`config::is_valid_partition`), and give an
/// operator the same sentence for the same mistake.
pub fn parse_partition_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter(|s| {
            let ok = crate::config::is_valid_partition(s);
            if !ok {
                eprintln!(
                    "broker: ignoring HUSK_SLURM_PARTITION entry {s:?} — not a SLURM partition \
                     name (letters, digits, `._-`, max 64, no leading dash). The other entries \
                     still apply; if none do, husk falls back to {DEFAULT_PARTITION:?}."
                );
            }
            ok
        })
        .map(str::to_string)
        .collect()
}

/// Split the operator's `HUSK_SLURM_ACCOUNT` into the set a job may bill to.
///
/// Same shape and same reasoning as [`parse_partition_list`], one field over. A rejected
/// entry is REPORTED rather than dropped in silence: this is operator config, the operator
/// is present at install time, and a typo that silently removes an account presents later as
/// "husk will not let me bill project X" — a refusal with no cause attached, which is the
/// failure this project keeps paying for.
pub fn parse_account_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter(|s| {
            let ok = crate::sbatch::is_valid_account(s);
            if !ok {
                eprintln!(
                    "broker: ignoring HUSK_SLURM_ACCOUNT entry {s:?} — not a SLURM account \
                     name (letters, digits, `._+-`, max 64). The other entries still apply."
                );
            }
            ok
        })
        .map(str::to_string)
        .collect()
}

/// What a job that sets no `--time` will get, and the ceiling it cannot exceed.
///
/// husk forces every brokered job onto one partition, so it moves jobs somewhere with
/// limits the submitter did not choose and may not know. A caged agent hit exactly that
/// on 2026-08-01: its job inherited a 30-minute limit, it only found out from `squeue`
/// afterwards, and its own report made the point — "a guardrail that redirects a job
/// somewhere with different limits is well-placed to mention them, especially when the
/// script sets no --time of its own." Harmless at 7 minutes; a longer run dies mid-flight
/// with nothing said at submit time.
///
/// Read from `scontrol`, never assumed: the numbers are site config and would rot in a
/// constant. Absent (query failed, or SLURM reports neither) means husk says nothing
/// rather than guessing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PartitionLimits {
    /// `DefaultTime` — what a job with no `--time` actually gets. The number that bites.
    pub default_time: Option<String>,
    /// `MaxTime` — the ceiling. This is what `sinfo`'s TIMELIMIT column shows, which is
    /// why reading `sinfo` does NOT tell you what an untimed job will get.
    pub max_time: Option<String>,
}

impl PartitionLimits {
    /// Parse `scontrol show partition <name>` output: whitespace-separated `key=value`
    /// tokens spread over indented lines.
    pub fn parse(scontrol_output: &str) -> PartitionLimits {
        let mut limits = PartitionLimits::default();
        for tok in scontrol_output.split_whitespace() {
            let Some((k, v)) = tok.split_once('=') else { continue };
            // SLURM writes these for "no limit set"; they are not useful to repeat back.
            let usable = !matches!(v, "NONE" | "UNLIMITED" | "n/a" | "");
            match k {
                "DefaultTime" if usable => limits.default_time = Some(v.to_string()),
                "MaxTime" if usable => limits.max_time = Some(v.to_string()),
                _ => {}
            }
        }
        limits
    }

    pub fn is_empty(&self) -> bool {
        self.default_time.is_none() && self.max_time.is_none()
    }
}

/// How long the WHOLE partition-limits query may take, every allowed partition together.
///
/// **One budget for the phase, not one per partition, and that is the load-bearing choice.**
/// A per-call timeout still scales with the operator's partition list, which is exactly the
/// shape `B2-2` measured: the two partitions the deployed Balfrin config declares, times an
/// eight-second `scontrol`, is 16.007 s against the wrapper's fifteen-second launch budget. A
/// per-call bound of 8 s would have passed that test and failed at three partitions. A phase
/// budget is a number that does not move when the operator edits their config file.
///
/// **Two seconds, because of what the money buys.** `Session::limits` has exactly one consumer
/// — `policy::time_limit_note`, one advisory sentence appended to an already-accepted
/// submission. `config.rs` states the rule this code broke, thirty lines from the function
/// that consumes its output: a subprocess during broker startup is *"the one path where a hang
/// has already cost two live incidents"*. The rule was written down, one instance was fixed,
/// and the other instance spawned N of them (`C4`).
///
/// **Hitting it is expected on an unhealthy site, not exotic.** SLURM's own `MessageTimeout`
/// defaults to 10 s and a configured backup controller doubles it, so a wedged `slurmctld`
/// blocks far past this. That is why giving up is a normal outcome with a normal message and
/// not a failure: husk names the partitions it could not ask about and serves the session,
/// exactly as it already does where `scontrol` is not installed at all.
pub const PARTITION_LIMITS_BUDGET: Duration = Duration::from_secs(2);

/// How much of a subprocess's stdout husk will read.
///
/// `scontrol show partition` is a few hundred bytes. A process that writes 64 KiB in answer has
/// stopped being the thing husk asked a question of, and reading it unbounded is the second
/// half of the same defect as running it unbounded.
const MAX_ANSWER_BYTES: u64 = 64 * 1024;

/// How long husk will keep draining a subprocess's output AFTER that subprocess has exited —
/// **in total**, across every read, not per read.
///
/// **The distinction is the whole of `RE-2`, and the first version of this got it wrong.**
/// `set_read_timeout` is an IDLE timeout: it fires when one `read` waits too long, so a
/// straggler that produces one byte every 200 ms resets it forever. Measured against that
/// version: a 300 ms deadline and a 250 ms drain limit returned after **8.094 s**, and the true
/// bound was `MAX_ANSWER_BYTES` reads x the idle timeout, about four and a half hours. A total
/// deadline is the only kind that bounds a cooperative dribbler.
///
/// It matters more than it looks, because this runs AFTER `signal_ready` and BEFORE the spool
/// loop: a stall here is not a slow start, it is an agent that has been launched against a
/// broker that never serves, i.e. `timed out after 120s` on every `sbatch` — the 2026-08-06
/// failure arriving through the door this fix opened.
///
/// Reached only when something other than the child still holds the write end. On every
/// ordinary path the answer is already buffered and the drain returns immediately.
const ANSWER_DRAIN_LIMIT: Duration = Duration::from_millis(250);

/// The per-read timeout used while draining. Small, because it is only how often the TOTAL
/// deadline above gets to be checked.
const DRAIN_POLL: Duration = Duration::from_millis(20);

// `kill(2)`. Declared here rather than taken from a crate for the same reason `main.rs`
// declares `prctl`: this binary's dependency surface is a security property.
extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: std::os::raw::c_int, sig: std::os::raw::c_int) -> std::os::raw::c_int;
}
const SIGKILL: std::os::raw::c_int = 9;

/// How often the deadline is checked while a child runs. `std` has no `wait_timeout`, and this
/// binary's dependency surface is a security property, so it polls — the same shape and the
/// same reason as the wrapper's `reap_within`. Five milliseconds is invisible next to a healthy
/// `scontrol` (tens of milliseconds) and 400 checks deep into a two-second budget.
const WAIT_POLL: Duration = Duration::from_millis(5);

/// Run a program, give up at `deadline`, and never leave it behind.
///
/// **Every exit from this function has released the child** — returned, killed-and-reaped, or
/// failed to spawn at all. That is not politeness: the broker lives for the whole session, so a
/// `scontrol` abandoned at startup would sit as a zombie for hours, and one left RUNNING would
/// hold an RPC open against the controller that is already unwell. "Release on every path"
/// (`B1`) is the reason this is a spawn-and-poll rather than a thread with a timeout, which is
/// the tempting shape that bounds the WAIT and leaves the process unbounded.
///
/// The deadline is checked BEFORE the spawn, which is what makes a phase budget a phase budget:
/// once it is spent, the remaining partitions cost nothing at all rather than one fork each.
///
/// **stdout is a socket pair, not `Stdio::piped()`, and that is the second bound.** Reading a
/// pipe blocks until EOF, and EOF is not the child's to give alone: any grandchild that
/// inherited the descriptor holds it open, so `scontrol` could exit, `try_wait` could return,
/// and the read could then block for as long as that grandchild lives — an unbounded wait
/// inside a function whose name says otherwise (`P12`). A `UnixStream` takes
/// `set_read_timeout`, which a `ChildStdout` does not, so the drain has a clock too. Same
/// device, for the same reason, as the wrapper's readiness channel.
///
/// A child that fills the socket buffer and stops making progress never exits, hits the
/// deadline, and is killed — bounded by the same clock, not by a second mechanism.
fn run_bounded(program: &str, args: &[&str], deadline: Instant) -> Result<String, String> {
    if Instant::now() >= deadline {
        return Err("husk's startup budget for this query was already spent".to_string());
    }
    let (mut ours, theirs) = std::os::unix::net::UnixStream::pair()
        .map_err(|e| format!("could not create a channel for {program}: {e}"))?;
    // A PROCESS GROUP of its own, so "release the child" can mean the whole tree it started.
    // `Child::kill` signals one pid. Measured on the first version of this fix: a `scontrol`
    // that is a site wrapper script — `( sleep 30 & wait )`, no `exec` — left its grandchild
    // running, PPID 1, after `run_bounded` had returned and declared the child released
    // (`RE-4`). A site that wraps its SLURM commands is not exotic, and the leak is per session.
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(std::os::fd::OwnedFd::from(theirs)))
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .spawn()
        .map_err(|e| format!("could not run {program}: {e}"))?;
    let group = child.id() as std::os::raw::c_int;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    // The direct child is reaped, but anything it left behind is not. Same
                    // signal as the timeout path: a failing wrapper leaks exactly like a
                    // hanging one.
                    reap_group(&mut child, group);
                    return Err(format!("{program} exited {status}"));
                }
                return Ok(drain(&mut ours, &mut child, group));
            }
            Ok(None) => {}
            // RELEASE ON EVERY PATH INCLUDING THIS ONE. `std`'s `Child` has no reaping `Drop`,
            // so returning here without killing leaves a running process for the life of the
            // session — the one arm the first version of this function forgot (`RE-5`).
            Err(e) => {
                reap_group(&mut child, group);
                return Err(format!("could not wait for {program}: {e}"));
            }
        }
        if Instant::now() >= deadline {
            reap_group(&mut child, group);
            return Err(format!(
                "{program} did not answer within husk's startup budget, so husk stopped waiting \
                 for it and killed it"
            ));
        }
        std::thread::sleep(WAIT_POLL);
    }
}

/// Read what the child said, under a TOTAL deadline — see `ANSWER_DRAIN_LIMIT`.
///
/// Anything still holding the write end after the total is spent is killed with the group and
/// the bytes already received are kept: husk would rather parse a partial answer than throw a
/// good one away over a straggler, and either way this returns.
fn drain(
    ours: &mut std::os::unix::net::UnixStream,
    child: &mut std::process::Child,
    group: std::os::raw::c_int,
) -> String {
    use std::io::Read;
    let until = Instant::now() + ANSWER_DRAIN_LIMIT;
    let _ = ours.set_read_timeout(Some(DRAIN_POLL));
    let mut buf: Vec<u8> = Vec::new();
    loop {
        if buf.len() as u64 >= MAX_ANSWER_BYTES {
            break;
        }
        let mut chunk = [0u8; 8192];
        match ours.read(&mut chunk) {
            Ok(0) => break, // EOF: every write end is closed, so this is the whole answer.
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) => break,
        }
        if Instant::now() >= until {
            // Something outlived the child and is still holding the descriptor. It is part of
            // the tree husk started, so husk ends it rather than leaving it behind.
            reap_group(child, group);
            break;
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// SIGKILL the whole process group husk created, then reap the direct child.
///
/// Both halves are needed and they close different leaks: without the signal the tree keeps
/// running, without the `wait` the direct child is a zombie for the life of the session.
/// Idempotent — every caller may have been beaten to it by an ordinary exit, and `ESRCH` is a
/// perfectly good outcome.
///
/// **WHAT THIS DOES NOT CATCH, stated because the fix for `RE-4` reads as if it caught
/// everything (`RE-C`, `P12`).** `kill(-pgid)` reaches every process still IN the group. A
/// grandchild that calls `setsid(2)` leaves the group for a session of its own and survives.
/// Measured twice, independently, in a standalone harness replicating `setpgid(0,0)` +
/// `kill(-pgid)` against the same no-`exec` wrapper this file's test uses: the in-group
/// grandchild is gone after the kill; the `setsid` one is alive with `ppid=1`, `pgrp` and
/// `session` equal to its own pid, and the group husk signalled was a different number. It is
/// not that the signal was lost — the process was never in the set the signal names (`P15`). A
/// site `scontrol` wrapper whose background job detaches therefore leaks one process per
/// session.
///
/// It is **not fixed here, and the trade is the point.** Closing it needs a PID namespace or a
/// subreaper, and a PID namespace around a login-node broker that has to reach `slurmctld` and
/// MUNGE is a large change aimed at a small leak. The leak is bounded by what this code path IS:
/// a best-effort, read-only `scontrol show partition` that runs AFTER `signal_ready()`, buys one
/// advisory sentence, and cannot refuse a launch (`P1` — the boundary is not drawn here). A
/// leaked grandchild holds no husk resource but the stdout socketpair, and `drain` has its own
/// total deadline, so it cannot stall the broker either. Recorded, with the bound, rather than
/// half-fixed with a scan that would itself be a denylist (`P5`).
fn reap_group(child: &mut std::process::Child, group: std::os::raw::c_int) {
    // SAFETY: `kill` with a negative pid signals the process group; the group id is the pid of a
    // child this function created with `process_group(0)`, so it names nothing else. A failure
    // (already gone) is exactly as acceptable as a success.
    unsafe {
        libc_kill(-group, SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Ask SLURM what one partition's time limits are, giving up at `deadline`.
///
/// Best-effort, as it has always been: `Err` means husk stays quiet about that partition's
/// limits rather than inventing them. What is new is that "best-effort" now includes the case
/// where the answer never comes, which used to be indistinguishable from a hang.
fn query_partition_limits_before(
    program: &str,
    partition: &str,
    deadline: Instant,
) -> Result<PartitionLimits, String> {
    run_bounded(program, &["show", "partition", partition], deadline).map(|o| PartitionLimits::parse(&o))
}

/// What husk says when it could not read some partition's limits.
///
/// **A pure function, because the message IS part of the control** — the same reason the
/// wrapper builds its refusal text separately from the I/O. `P11` asks for four things and this
/// is where they are checkable: who refused, what it cost, what it did NOT cost, and one reason
/// PER PARTITION.
///
/// That last one is not decoration. The first version joined every partition name and printed
/// `unanswered[0].1`, so a partition husk never forked a process for was reported as *"scontrol
/// did not answer about `debug`"* — a false statement about which program was run, inside the
/// fix whose whole subject is attribution (`RE-7`). Two partitions can go unanswered for two
/// different reasons in the same pass, and they routinely do: the first times out, the rest find
/// the phase budget already spent.
fn limits_note(unanswered: &[(String, String)], budget: Duration) -> String {
    let names = unanswered.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>().join(", ");
    let detail = unanswered
        .iter()
        .map(|(p, why)| format!("{p}: {why}"))
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "broker: no time limits for {names} within a {:.1}s budget — {detail}. This costs the \
         session ONE advisory sentence: husk cannot tell a job what --time it gets by default on \
         those partitions. It costs nothing else — submission, policy and the cage are \
         unaffected. A slow or unresponsive slurmctld is the usual cause.",
        budget.as_secs_f32(),
    )
}

/// Ask about every partition under ONE deadline, and report which ones went unanswered.
///
/// `program` is a parameter so the give-up path is testable without putting a stub `scontrol`
/// first on `PATH`: mutating `PATH` from a test is a data race against every other test in the
/// binary, and this crate already has one flaking test for exactly that reason.
fn limits_for_partitions(
    program: &str,
    partitions: &[String],
    budget: Duration,
) -> (std::collections::BTreeMap<String, PartitionLimits>, Vec<(String, String)>) {
    let deadline = Instant::now() + budget;
    let mut limits = std::collections::BTreeMap::new();
    let mut unanswered = Vec::new();
    for p in partitions {
        match query_partition_limits_before(program, p, deadline) {
            Ok(l) => {
                limits.insert(p.clone(), l);
            }
            Err(why) => {
                // The KEY is still inserted, empty, so the map this returns is shape-identical
                // to the one the unbounded version returned on a failed query. `PartitionLimits`
                // documents absent and empty as the same answer; keeping both behaviours
                // identical means this change moves the timing and nothing else.
                limits.insert(p.clone(), PartitionLimits::default());
                unanswered.push((p.clone(), why));
            }
        }
    }
    (limits, unanswered)
}

#[derive(Debug, Clone)]
pub struct Session {
    /// What to pass to `--uenv`. Prefer UENV_LABEL; fall back to UENV_MOUNT_LIST
    /// (its `file:mount-point` pairs are themselves a valid `--uenv` argument).
    pub uenv: Option<String>,
    /// The partitions a brokered job may request — from HUSK_SLURM_PARTITION in the
    /// broker's TRUSTED env (operator-set, agent-inaccessible), defaulting to
    /// DEFAULT_PARTITION. Never empty.
    ///
    /// The job chooses one and husk RE-EMITS the matching entry from this list, so no agent
    /// byte reaches sbatch: same construct-and-re-emit shape as --chdir, which is confined
    /// to the writable set rather than forced to a constant. Prefer low-priority/preemptible
    /// partitions — see THREAT-MODEL.md on why the partition is the resource-envelope
    /// control.
    pub allowed_partitions: Vec<String>,
    /// The accounts a brokered job may be billed to, from `HUSK_SLURM_ACCOUNT` in the
    /// broker's TRUSTED environment (operator-set at install, agent-inaccessible). Empty
    /// where the site does not use accounts. Where a site does require one, its `cli_filter`
    /// typically rejects every submission without it, so it is not optional there.
    ///
    /// A LIST for the same reason `allowed_partitions` is one, and it took a real user to
    /// notice: a person with hours on two projects has to be able to say which one a job
    /// bills, and "re-run install-husk.sh" is not an answer per job. The property that
    /// matters is that the CONFINED SIDE DOES NOT GET FREE CHOICE OF WHO PAYS — not that
    /// there is exactly one answer. Bounding the set keeps the first and drops the second.
    ///
    /// The first entry is the default when a job names none.
    pub allowed_accounts: Vec<String>,
    /// uenv images a job may ask for, by LABEL, from `~/.husk/config.json`. Empty means the
    /// job may not choose one and the launching session's uenv is inherited, as before.
    ///
    /// **husk never emits a mount point.** uenv takes each image's mount from its own
    /// metadata when none is given (`src/uenv/env.cpp`: *"otherwise use the mount point
    /// provided in the meta data"*), which is both the compatible answer and the one that
    /// keeps the job from choosing where an image lands. Duplicate mounts are uenv's error,
    /// with uenv's message.
    pub allowed_uenvs: Vec<String>,
    /// What to pass to `--view`, normalized to `uenvname:viewname`. UENV_VIEW is
    /// mount-qualified on this uenv (e.g. `/user-environment:icon:default`), which is
    /// NOT a valid `--view` argument, so a leading `/mount-point:` field is stripped.
    /// The exported UENV_VIEW does not survive into the job, so this CLI flag is what
    /// restores the job's view to match the session (verified on Balfrin).
    pub view: Option<String>,
    /// Time limits PER allowed partition, read from `scontrol` at startup. A partition
    /// absent from the map, or present with empty limits, means husk says nothing about
    /// limits for it rather than guessing. See `PartitionLimits`.
    pub limits: std::collections::BTreeMap<String, PartitionLimits>,
}

impl Session {
    /// Environment only — no I/O, so it stays cheap and testable. The partition limits
    /// need SLURM, so they are filled in separately (`with_partition_limits`).
    /// Build from the operator's config file, falling back to the environment.
    ///
    /// **Precedence: `~/.husk/config.json` wins where it speaks; the env vars are the
    /// fallback.** Not the other way round, and the reason is mechanical rather than
    /// aesthetic: the launcher EXPORTS `HUSK_SLURM_*` from the install-time files, so if the
    /// environment won, a config file could never take effect for anyone who used the install
    /// flags — which is every existing install. This way an existing site keeps working
    /// untouched, and the moment an operator writes the file it takes over.
    ///
    /// A malformed config refuses here rather than degrading to the env fallback. Falling
    /// back would mean a typo silently reverts policy to whatever the installer set months
    /// ago, which is the worst of both: no error, and a boundary nobody chose.
    pub fn from_env_and_config(home: &std::path::Path) -> Result<Self, String> {
        let (cfg, path) = crate::config::HuskConfig::load_reporting(home)?;
        // SAY WHICH FILE. Balfrin and Tasna share a home, so "the config" is ambiguous there
        // and a wrong-file diagnosis is expensive. One line, at startup, next to the build
        // stamp that exists for the same reason.
        eprintln!(
            "broker: operator config {} (system {:?})",
            if cfg.is_some() { path.display().to_string() } else { format!("{} — absent, using defaults", path.display()) },
            crate::config::system_key()
        );
        let cfg = cfg.unwrap_or_default();
        let mut s = Self::from_env();
        if !cfg.accounts.is_empty() {
            s.allowed_accounts = cfg.accounts;
        }
        if !cfg.partitions.is_empty() {
            s.allowed_partitions = cfg.partitions;
        }
        s.allowed_uenvs = cfg.uenvs;
        Ok(s)
    }

    pub fn from_env() -> Self {
        let nonempty = |k: &str| env::var(k).ok().filter(|v| !v.is_empty());
        Session {
            uenv: nonempty("UENV_LABEL").or_else(|| nonempty("UENV_MOUNT_LIST")),
            view: nonempty("UENV_VIEW").map(|v| normalize_view(&v)),
            allowed_partitions: nonempty("HUSK_SLURM_PARTITION")
                .map(|v| parse_partition_list(&v))
                .filter(|v: &Vec<String>| !v.is_empty())
                .unwrap_or_else(|| vec![DEFAULT_PARTITION.to_string()]),
            // Grammar-checked like every other value that reaches sbatch's command line.
            // `HUSK_SLURM_PARTITION` has had one since it shipped; this one did not, purely
            // because it arrived later — an asymmetry with no reason behind it (B6-F9). The
            // source is trusted (operator-set, agent-inaccessible), so this is not a
            // boundary; it is the difference between a typo that SLURM explains and a typo
            // that becomes an argument nobody validated.
            allowed_accounts: nonempty("HUSK_SLURM_ACCOUNT")
                .map(|v| parse_account_list(&v))
                .unwrap_or_default(),
            allowed_uenvs: Vec::new(),
            limits: Default::default(),
        }
    }

    /// Ask SLURM about every allowed partition, once, under one deadline.
    ///
    /// **Called AFTER the broker has announced itself** (`main.rs`), so nothing here can cost a
    /// launch even if the deadline is hit. The deadline is here anyway, and the two are not
    /// redundant: moving the call only decides who waits, while the budget decides whether the
    /// wait ever ends. A `scontrol` that never returns would, on its own, mean a broker that
    /// announced readiness and then never reached its spool loop — which is the 2026-08-06
    /// failure that `BrokerReady` exists to prevent, arriving through a different door.
    pub fn with_partition_limits(self) -> Self {
        self.with_partition_limits_within(PARTITION_LIMITS_BUDGET)
    }

    /// The budget is a parameter so the give-up path is testable in milliseconds. Everything
    /// else is identical — the same shape as the wrapper's `establish_within`.
    pub fn with_partition_limits_within(mut self, budget: Duration) -> Self {
        let (limits, unanswered) =
            limits_for_partitions("scontrol", &self.allowed_partitions, budget);
        self.limits = limits;
        if !unanswered.is_empty() {
            // SAY WHAT WAS LOST AND WHAT WAS NOT (`P11`). A silent degrade here would present
            // later as "husk stopped telling me about time limits", with no cause attached; a
            // refusal would trade a courtesy sentence for the whole session.
            eprintln!("{}", limits_note(&unanswered, budget));
        }
        self
    }
}

/// Strip a leading absolute-path (mount-point) field from a UENV_VIEW value so it is
/// a valid `sbatch --view` argument:
/// `/user-environment:icon:default` -> `icon:default`. Values that are already
/// unqualified (`icon:default`, or a bare `default`) pass through unchanged.
fn normalize_view(raw: &str) -> String {
    if raw.starts_with('/') {
        if let Some((_mount, rest)) = raw.split_once(':') {
            return rest.to_string();
        }
    }
    raw.to_string()
}



#[cfg(test)]
mod tests {
    use super::{limits_for_partitions, limits_note, normalize_view, run_bounded, PartitionLimits};
    use std::time::{Duration, Instant};

    /// A stub program, so the bound can be tested without putting anything on `PATH`.
    /// Mutating `PATH` from a test races every other test in this binary — this crate already
    /// has one test flaking for exactly that reason (`RAB3`) — and `run_bounded` takes the
    /// program name as a parameter so that it does not have to.
    ///
    /// **The executable is copied into place by `cp`, and never written by THIS process.** That
    /// is not fastidiousness; it is the fix for a flake I introduced and then measured.
    /// `execve` returns `ETXTBSY` while any process holds a WRITABLE descriptor to the file, and
    /// in a multi-threaded test binary that is a live race with nothing to do with the code
    /// under test: this thread's `fs::write` of the stub is inherited across another thread's
    /// `fork`, and stays open in that child until it `exec`s. Measured before this change:
    /// 3 failures in 8 runs of `session::`, spread over three different tests, each reading
    /// `could not run …/scontrol: Text file busy (os error 26)`.
    ///
    /// Letting `cp` open it means the writable descriptor only ever exists in a process this
    /// one cannot fork a copy of, and it is gone before `stub` returns. A retry loop would have
    /// hidden the flake; this removes it. The BODY is written by us — it is never executed.
    fn stub(tag: &str, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("husk-stub-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let src = d.join("body");
        let p = d.join("scontrol");
        std::fs::write(&src, body).unwrap();
        let ok = std::process::Command::new("cp")
            .arg(&src)
            .arg(&p)
            .status()
            .expect("cp must be available to build a test stub");
        assert!(ok.success(), "cp failed while staging the test stub");
        // `chmod(2)` on a path, not through a descriptor, so this opens nothing either.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// `B2-2`. `query_partition_limits` ran `scontrol` with `.output()` — no timeout, no
    /// deadline, serial, once per allowed partition — during broker startup, before the spool
    /// was claimed. Two partitions (what the deployed Balfrin config declares) times an 8 s
    /// controller measured 16.007 s against the wrapper's 15 s launch budget, and husk refused
    /// to launch with a message naming the spool.
    ///
    /// **The bound is asserted at 60x the expected cost, so a loaded laptop cannot turn it
    /// red:** the call should return in ~0.3 s (the budget plus a fork) and the stub sleeps 30,
    /// so any assertion between about 1 s and 25 s distinguishes them. 5 s is used.
    ///
    /// **And the child is KILLED AND REAPED, not abandoned** — the second assertion, and the
    /// reason this is a spawn-and-poll rather than a thread with a timeout. That shape bounds
    /// the WAIT and leaves the process running: a broker lives for the whole session, so an
    /// abandoned `scontrol` would hold an RPC open against a controller that is already unwell
    /// and sit in the process table for hours (`B1` — release on every path).
    ///
    /// **MUTATION that turns it red:** delete the `Instant::now() >= deadline` block in
    /// `run_bounded` (the first assertion fails — after 30 s), or replace `child.kill()` with
    /// nothing (the second fails: `/proc/<pid>` is still there).
    #[test]
    fn a_subprocess_that_never_answers_is_killed_and_reaped_not_merely_abandoned() {
        let pidfile = std::env::temp_dir().join(format!("husk-stub-pid-{}", std::process::id()));
        let _ = std::fs::remove_file(&pidfile);
        // `exec` so the pid in the file IS the long-running process, not a shell wrapping it.
        let slow = stub("slow", &format!("#!/bin/sh\necho $$ > {}\nexec sleep 30\n", pidfile.display()));

        let began = Instant::now();
        let answer = run_bounded(
            &slow.to_string_lossy(),
            &["show", "partition", "short"],
            Instant::now() + Duration::from_millis(300),
        );
        let waited = began.elapsed();

        assert!(answer.is_err(), "a program that never answers must not produce limits");
        assert!(
            waited < Duration::from_secs(5),
            "waited {waited:?} for a program that sleeps 30s under a 0.3s budget. Unbounded, \
             this is `B2-2`: 16.007s of a 15s launch budget, and husk refuses to start."
        );
        assert!(
            answer.as_ref().unwrap_err().contains("did not answer"),
            "the failure must say WHAT did not answer, or the operator debugs the wrong layer \
             (`P11`): {answer:?}"
        );
        let pid = std::fs::read_to_string(&pidfile).unwrap_or_default().trim().to_string();
        assert!(!pid.is_empty(), "the stub did not get far enough to report its pid");
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "the subprocess (pid {pid}) is still in the process table after husk gave up on \
             it. Killed-but-not-reaped leaves a zombie for the life of the session; \
             not-killed-at-all leaves a live RPC against slurmctld."
        );
        let _ = std::fs::remove_file(&pidfile);
        let _ = std::fs::remove_dir_all(slow.parent().unwrap());
    }

    /// The budget belongs to the PHASE, not to each partition — asserted from the PARENT side,
    /// on the reason each partition went unanswered, so there is no clock and no race in it.
    ///
    /// This is the half of `B2-2` a per-call timeout would not have fixed: a per-call bound
    /// still scales with the operator's partition list, so it passes at two partitions and
    /// fails at three, on a threshold nothing documents. Once the phase budget is spent the
    /// remaining partitions cost nothing at all — not even a `fork`, which is what the second
    /// and third reasons below say in husk's own words.
    ///
    /// **FALSE FRIEND, and it was in the first version of this test:** counting how many times
    /// the stub *itself* recorded a run is racy in the direction that hides the bug. Spawned
    /// and killed with an already-expired deadline, `/bin/sh` is often SIGKILLed before it
    /// executes its first line, so the counter stays at 1 even when three children were forked.
    /// The mutation below was GREEN against that assertion. The counter is kept as a secondary
    /// observation — it can only false-PASS, never false-fail — and the load-bearing assertion
    /// is the one the parent makes.
    ///
    /// **MUTATION that turns it red:** move `let deadline = Instant::now() + budget;` from
    /// `limits_for_partitions` into the loop body (each partition gets its own budget), or
    /// delete `run_bounded`'s pre-spawn deadline check (each partition costs a `fork`).
    #[test]
    fn the_startup_budget_belongs_to_the_phase_not_to_each_partition() {
        let runs = std::env::temp_dir().join(format!("husk-stub-runs-{}", std::process::id()));
        let _ = std::fs::remove_file(&runs);
        let slow = stub("phase", &format!("#!/bin/sh\necho x >> {}\nexec sleep 30\n", runs.display()));
        let names: Vec<String> = ["short", "pp-short", "debug"].iter().map(|s| s.to_string()).collect();

        let began = Instant::now();
        let (limits, unanswered) =
            limits_for_partitions(&slow.to_string_lossy(), &names, Duration::from_millis(300));
        let waited = began.elapsed();

        assert_eq!(unanswered.len(), 3, "every unanswered partition must be reported by name");
        // THE LOAD-BEARING ASSERTION, made by the parent: only the FIRST partition was ever
        // asked. The other two found the phase budget already spent and cost nothing.
        assert!(
            unanswered[0].1.contains("did not answer"),
            "the first partition should have been asked and timed out: {:?}",
            unanswered[0].1
        );
        for (name, why) in &unanswered[1..] {
            assert!(
                why.contains("already spent"),
                "partition {name:?} was ASKED after the phase budget was gone ({why:?}). One \
                 budget covers the whole phase; a per-partition bound is `B2-2` again with a \
                 larger partition count, and it costs a `fork` per partition on top."
            );
        }
        // Secondary, and racy in the safe direction only: a stub SIGKILLed before /bin/sh runs
        // its first line records nothing, so this can false-pass but never false-fail.
        let spawns = std::fs::read_to_string(&runs).unwrap_or_default().lines().count();
        assert!(spawns <= 1, "the stub recorded {spawns} runs for three partitions");
        assert!(waited < Duration::from_secs(5), "three partitions took {waited:?}");
        assert_eq!(
            limits.len(),
            3,
            "the map must keep the same SHAPE it had when an unbounded query failed — a key \
             per allowed partition, empty. Dropping keys here would be a behaviour change \
             riding along with a timing fix."
        );
        assert!(limits.values().all(|l| l.is_empty()), "and husk must not invent limits");
        let _ = std::fs::remove_file(&runs);
        let _ = std::fs::remove_dir_all(slow.parent().unwrap());
    }

    /// `RE-7`, and the reason the message is a function. Two partitions go unanswered for two
    /// DIFFERENT reasons in the same pass — the first times out, the rest find the phase budget
    /// already spent — and the first version stamped reason #1 over the whole list, so husk
    /// reported that `scontrol` "did not answer about `debug`" when it had never run `scontrol`
    /// for `debug` at all.
    ///
    /// **FALSE FRIEND:** the phase-budget test asserts the `unanswered` tuples carry the right
    /// reasons, and it was green throughout — the defect was entirely in how they were rendered.
    /// A control's message needs its own test or it is not covered by the test of the control.
    ///
    /// **MUTATION that turns it red:** render `{p}: skipped`, or go back to
    /// `unanswered[0].1` for the whole list.
    #[test]
    fn every_unanswered_partition_gets_its_own_reason() {
        let unanswered = vec![
            ("short".to_string(), "scontrol did not answer within husk's startup budget".to_string()),
            ("pp-short".to_string(), "husk's startup budget for this query was already spent".to_string()),
        ];
        let note = limits_note(&unanswered, Duration::from_secs(2));
        assert!(note.contains("short: scontrol did not answer"), "{note}");
        assert!(note.contains("pp-short: husk's startup budget"), "{note}");
        // `P11`: what it cost, and — the half that stops an operator chasing it — what it did not.
        assert!(note.contains("ONE advisory sentence"), "say what was lost: {note}");
        assert!(note.contains("costs nothing else"), "and what was not: {note}");
        assert!(note.starts_with("broker:"), "or the wrapper's relay drops it: {note}");
        // Identical on retry (`P11`): no timestamps, no counters, nothing that reads as weather.
        assert_eq!(note, limits_note(&unanswered, Duration::from_secs(2)));
    }

    /// `RE-2`. **`set_read_timeout` is an IDLE timeout, and a straggler that dribbles resets it
    /// forever.** The first version of this fix set it to `ANSWER_DRAIN_LIMIT` and called that
    /// the bound. Measured against that version, with a grandchild emitting one byte every
    /// 200 ms and a 300 ms deadline: **returned Ok after 8.094 s**, and the true ceiling was
    /// `MAX_ANSWER_BYTES` reads x the idle timeout — about four and a half hours. After the fix,
    /// on the identical stub: **0.266 s**.
    ///
    /// It is the worst kind of residual for THIS patch, because the drain now runs after
    /// `signal_ready` and before the spool loop: a stall is an agent already launched against a
    /// broker that never serves, i.e. `timed out after 120s` on every `sbatch` — the 2026-08-06
    /// failure coming back through the door the reorder opened.
    ///
    /// **FALSE FRIEND:** a stub that writes once and then holds the descriptor open is bounded
    /// by an idle timeout and passes on the broken code. The dribble is the whole test.
    ///
    /// **MUTATION that turns it red:** replace the `drain` loop's total deadline with a single
    /// `set_read_timeout(ANSWER_DRAIN_LIMIT)` + `read_to_end`.
    #[test]
    fn a_dribbling_straggler_cannot_outlast_the_total_drain_deadline() {
        let leaky = stub(
            "dribble",
            "#!/bin/sh\n( i=0; while [ $i -lt 60 ]; do printf x; sleep 0.2; i=$((i+1)); done ) &\n\
             echo PartitionName=short\nexit 0\n",
        );
        let began = Instant::now();
        let out = run_bounded(
            &leaky.to_string_lossy(),
            &["show", "partition", "short"],
            Instant::now() + Duration::from_millis(300),
        );
        let waited = began.elapsed();
        assert!(out.is_ok(), "a successful exit is still a success: {out:?}");
        assert!(
            waited < Duration::from_secs(4),
            "waited {waited:?} draining a grandchild that emits one byte every 200ms. Every \
             single read finishes inside the idle timeout, so an idle timeout never fires — \
             only a TOTAL deadline bounds a cooperative dribbler (`RE-2`). The stub dribbles \
             for 12s and the real ceiling was 65536 reads x the idle timeout."
        );
        let _ = std::fs::remove_dir_all(leaky.parent().unwrap());
    }

    /// `RE-4`. `Child::kill` signals ONE pid. A `scontrol` that is a site wrapper script — no
    /// `exec` — leaves its grandchild running, reparented to init, after `run_bounded` has
    /// returned and its own documentation has claimed the child released. Measured on the first
    /// version: `pid 443, state S, PPID 1, still in the process table`.
    ///
    /// **FALSE FRIEND, and it was in my own first test:**
    /// `a_subprocess_that_never_answers_is_killed_and_reaped_not_merely_abandoned` uses
    /// `exec sleep 30` in its stub *specifically* so the pid it checks IS the direct child. It
    /// cannot see this case, and it stayed green throughout. The stub here deliberately does
    /// NOT `exec`.
    ///
    /// **MUTATION that turns it red:** drop `.process_group(0)`, or drop the `libc_kill(-group)`
    /// from `reap_group` and leave only `child.kill()`.
    ///
    /// **AND WHAT IT DOES NOT ASSERT (`RE-C`, `P10`).** The grandchild here STAYS in the group.
    /// One that calls `setsid` does not, and it survives the kill — measured. This test says the
    /// group kill works on the shape it drives, and nothing about the shape it does not; the
    /// residual, and why it is accepted rather than closed, is on `reap_group` itself. Reading
    /// this green test as "the tree is always released" is the over-claim `P12` describes.
    #[test]
    fn the_whole_process_group_is_killed_not_just_the_child_husk_forked() {
        let pidfile = std::env::temp_dir().join(format!("husk-gpid-{}", std::process::id()));
        let _ = std::fs::remove_file(&pidfile);
        // No `exec`: the shell stays, forks `sleep`, and waits. Killing the shell alone orphans
        // the sleep — which is precisely what a site wrapper around `scontrol` looks like.
        let wrapper = stub(
            "wrapper",
            &format!("#!/bin/sh\nsleep 30 &\necho $! > {}\nwait\n", pidfile.display()),
        );
        let _ = run_bounded(
            &wrapper.to_string_lossy(),
            &["show", "partition", "short"],
            Instant::now() + Duration::from_millis(400),
        );
        std::thread::sleep(Duration::from_millis(200));
        let pid = std::fs::read_to_string(&pidfile).unwrap_or_default().trim().to_string();
        assert!(!pid.is_empty(), "the wrapper did not get far enough to report its grandchild");
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "grandchild pid {pid} outlived the query husk started and gave up on. `Child::kill` \
             signals one pid; husk starts a process GROUP so that giving up releases the tree, \
             not just the process it happens to hold a handle to (`RE-4`, `B1`)."
        );
        let _ = std::fs::remove_file(&pidfile);
        let _ = std::fs::remove_dir_all(wrapper.parent().unwrap());
    }

    /// The residual I found in my own fix, closed rather than documented: `scontrol` exits, a
    /// grandchild it backgrounded still holds the stdout descriptor, and a `Stdio::piped()` read
    /// then blocks until THAT process dies — an unbounded wait inside a function called
    /// `run_bounded` (`P12`: a description of a control decays into a description of its intent).
    ///
    /// **MUTATION that turns it red:** go back to `.stdout(Stdio::piped())` +
    /// `child.stdout.take()`. The call then takes 30 s instead of 0.25 s.
    #[test]
    fn a_child_that_leaves_its_output_channel_open_does_not_hang_the_broker() {
        let leaky = stub(
            "leaky",
            "#!/bin/sh\n( sleep 30 ) &\necho PartitionName=short\necho '   DefaultTime=00:30:00 \
             MaxTime=01:00:00'\nexit 0\n",
        );
        let began = Instant::now();
        let out = run_bounded(
            &leaky.to_string_lossy(),
            &["show", "partition", "short"],
            Instant::now() + Duration::from_secs(10),
        );
        let waited = began.elapsed();
        assert!(
            waited < Duration::from_secs(5),
            "waited {waited:?} to drain the output of a program that had already exited, because \
             a grandchild still held the descriptor. The stub's straggler sleeps 30s."
        );
        // ...and the answer it DID give is kept, not thrown away over the straggler.
        let limits = PartitionLimits::parse(&out.expect("a successful exit is still a success"));
        assert_eq!(limits.default_time.as_deref(), Some("00:30:00"));
        let _ = std::fs::remove_dir_all(leaky.parent().unwrap());
    }

    /// The direction that matters most, and the one this review round got wrong three times: a
    /// bound must not become a denial of service aimed at the operator. A healthy `scontrol`
    /// still answers, is still parsed, and is reported as answered.
    ///
    /// A missing program is the other ordinary case — every developer laptop, and every test
    /// machine — and it must be a quiet `Err`, never a hang and never a panic.
    #[test]
    fn a_partition_that_answers_in_time_is_still_read_normally() {
        let ok = stub(
            "ok",
            "#!/bin/sh\necho PartitionName=short\necho '   DefaultTime=00:30:00 MaxTime=01:00:00'\n",
        );
        let names = vec!["short".to_string()];
        let (limits, unanswered) =
            limits_for_partitions(&ok.to_string_lossy(), &names, Duration::from_secs(10));
        assert!(unanswered.is_empty(), "a healthy answer must not be reported as a give-up");
        assert_eq!(limits["short"].default_time.as_deref(), Some("00:30:00"));
        assert_eq!(limits["short"].max_time.as_deref(), Some("01:00:00"));

        let began = Instant::now();
        let missing = run_bounded("husk-no-such-program-4242", &["show"], Instant::now() + Duration::from_secs(10));
        assert!(missing.is_err(), "an absent program is an Err");
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "an absent program must fail immediately, not wait out the budget — this is the \
             normal case on any machine without SLURM"
        );
        let _ = std::fs::remove_dir_all(ok.parent().unwrap());
    }

    #[test]
    fn the_account_env_var_is_held_to_the_same_grammar_as_the_option() {
        // B6-F9. `HUSK_SLURM_PARTITION` has had a value grammar since it shipped and
        // `HUSK_SLURM_ACCOUNT` did not — an asymmetry with no reason behind it, just an
        // order of arrival. The source is trusted, so this is not a boundary; it is the
        // difference between a typo SLURM explains and a typo that becomes an argument
        // nobody validated. Asserted against the SAME predicate the registry uses, so the
        // two cannot drift apart (P8).
        for ok in ["s83", "csstaff", "pr-tst-1", "a_b.c+d"] {
            assert!(crate::sbatch::is_valid_account(ok), "must accept {ok}");
        }
        for bad in ["", "has space", "semi;colon", "$(id)", "a/b", &"x".repeat(65)] {
            assert!(!crate::sbatch::is_valid_account(bad), "must refuse {bad:?}");
        }
        // An option-SHAPED value is accepted here, deliberately, and the contrast is worth
        // keeping: `--account` is always emitted as ONE argv element (`--account=VALUE`), so
        // a leading dash is data and cannot become a flag. Compare `rank.rs`, where env
        // NAMES become bare arguments to bwrap and an option-shaped name is therefore
        // refused outright. Same charset question, opposite answer, because the emission
        // differs — which is the argument for canonical re-emission (P4/P5).
        assert!(crate::sbatch::is_valid_account("--flag"));
    }

    // Real `scontrol show partition` output: one PartitionName= line then indented
    // key=value tokens. DefaultTime and MaxTime are DIFFERENT numbers and live on
    // different lines — reading sinfo gives you MaxTime, which is not what an untimed
    // job gets, and that gap is what surprised a caged agent on 2026-08-01.
    const SCONTROL: &str = "PartitionName=short
   AllowGroups=ALL AllowAccounts=ALL AllowQos=ALL
   AllocNodes=ALL Default=NO QoS=N/A
   DefaultTime=00:30:00 DisableRootJobs=NO ExclusiveUser=NO GraceTime=0 Hidden=NO
   MaxNodes=UNLIMITED MaxTime=01:00:00 MinNodes=0 LLN=NO
   Nodes=nid[001000-001030]
   State=UP TotalCPUs=3712 TotalNodes=29
";

    // The operator's list. A real cluster needs more than one: GPU nodes and CPU-only
    // postprocessing nodes are different partitions.
    #[test]
    fn partition_lists_are_split_trimmed_and_sanitised() {
        use super::parse_partition_list as split;
        assert_eq!(split("short"), vec!["short"]);
        assert_eq!(split("short,pp-short"), vec!["short", "pp-short"]);
        // Humans put spaces and trailing commas in lists.
        assert_eq!(split(" short , pp-short , "), vec!["short", "pp-short"]);
        // These become ARGUMENTS to the real sbatch. A name that could be read as an option
        // or carry shell syntax is dropped, not passed through — even from operator config,
        // because "it is trusted" is how the last few bugs got in.
        assert!(split("--partition=evil").is_empty());
        assert!(split("-p").is_empty());
        assert!(split("a b").is_empty());
        assert!(split("$(id)").is_empty());
        assert!(split("a;b").is_empty());
        // A bad entry does not take the good ones with it.
        assert_eq!(split("short,--evil,pp-short"), vec!["short", "pp-short"]);
        assert!(split("").is_empty());
        assert!(split(" , , ").is_empty());
    }

    /// ONE PARTITION GRAMMAR, and the two readers are asserted against it — not against a
    /// transcription of it (`B2-7(a)`, `P8`).
    ///
    /// `config.rs::validate` and this module each spelled the rule out by hand, three lines
    /// from an `--account` check that is a single shared predicate whose own doc says "one
    /// grammar, one definition". They agreed when measured; nothing made them.
    ///
    /// **MUTATION that turns this red:** widen `config::is_valid_partition` to allow `+`
    /// (the account grammar's charset). `parse_partition_list` starts keeping `a+b` and the
    /// loop below fails on the entry it accepted.
    ///
    /// **The axis it does not cover:** it pairs the SPLITTER with the PREDICATE. That
    /// `config::validate` refuses what the predicate refuses is now true by construction —
    /// it calls it — so there is nothing left to assert there, which is the point.
    #[test]
    fn the_partition_grammar_has_one_definition_and_both_readers_use_it() {
        use crate::config::is_valid_partition as ok;
        for s in ["short", "pp-short", "a.b_c-d", "x"] {
            assert!(ok(s), "must accept {s:?}");
        }
        for s in ["", "-p", "--partition=evil", "a b", "a;b", "a+b", &"x".repeat(65)] {
            assert!(!ok(s), "must refuse {s:?}");
        }
        // The splitter keeps an entry IF AND ONLY IF the one predicate accepts it.
        for s in ["short", "pp-short", "a.b_c-d", "-p", "a b", "a+b", "$(id)"] {
            let kept = super::parse_partition_list(s);
            assert_eq!(
                kept.is_empty(),
                !ok(s),
                "the splitter and the grammar must agree about {s:?}, got {kept:?}"
            );
        }
    }

    /// A dropped partition does not merely go missing — it SUBSTITUTES a policy (`B2-3`).
    ///
    /// `from_env` turns an empty list into `DEFAULT_PARTITION`, so one misplaced space made
    /// husk force jobs onto a partition the operator never named and possibly does not have,
    /// with nothing said. The sibling field has reported its drops since it shipped; the doc
    /// block that promised this behaviour was attached to that sibling.
    ///
    /// **MUTATION:** delete the `eprintln!` from `parse_partition_list` — this test cannot
    /// see stderr, so it asserts the mechanism it CAN see: the per-entry drop and the
    /// substitution it feeds. The message itself is pinned by review, not here, and that
    /// limit is why the honest form of this fix is to return `(kept, rejected)` and let the
    /// caller print — a signature change reaching `from_env`.
    #[test]
    fn one_bad_partition_entry_does_not_silently_become_the_default() {
        assert_eq!(super::parse_partition_list("short,--evil,pp-short"), vec!["short", "pp-short"]);
        // The whole list gone, from ONE misplaced space — the input that makes this a policy
        // substitution rather than a missing entry.
        assert!(super::parse_partition_list("pp short").is_empty());
        // ...and `from_env` reads an empty list as "operator said nothing" and installs
        // `DEFAULT_PARTITION`. Asserted as the RULE rather than by driving `from_env`, which
        // reads process-wide environment and cargo runs tests as threads of one process —
        // the flake this crate has already paid for once.
        assert_eq!(
            Some(super::parse_partition_list("pp short"))
                .filter(|v: &Vec<String>| !v.is_empty())
                .unwrap_or_else(|| vec![super::DEFAULT_PARTITION.to_string()]),
            vec![super::DEFAULT_PARTITION.to_string()],
        );
    }

    #[test]
    fn parses_default_and_max_time_from_scontrol() {
        let l = PartitionLimits::parse(SCONTROL);
        assert_eq!(l.default_time.as_deref(), Some("00:30:00"));
        assert_eq!(l.max_time.as_deref(), Some("01:00:00"));
        assert!(!l.is_empty());
    }

    // "No limit" placeholders must not be repeated back at the user as if they were
    // numbers — saying "the default limit is UNLIMITED" is worse than saying nothing.
    #[test]
    fn treats_slurms_no_limit_placeholders_as_unknown() {
        for v in ["UNLIMITED", "NONE", "n/a"] {
            let l = PartitionLimits::parse(&format!("DefaultTime={v} MaxTime={v}"));
            assert!(l.is_empty(), "{v} must read as 'nothing to say', got {l:?}");
        }
    }

    // scontrol missing, permission denied, partition unknown: husk stays quiet rather
    // than inventing a limit.
    #[test]
    fn unparseable_output_yields_no_claim() {
        assert!(PartitionLimits::parse("").is_empty());
        assert!(PartitionLimits::parse("Invalid partition name specified").is_empty());
        // A substring match would wrongly pick this up from an unrelated key.
        assert!(PartitionLimits::parse("OverSubscribe=NO DefaultTimeXX=9").is_empty());
    }

    #[test]
    fn strips_mount_prefix_from_uenv_view() {
        assert_eq!(normalize_view("/user-environment:icon:default"), "icon:default");
    }
    #[test]
    fn leaves_unqualified_view_untouched() {
        assert_eq!(normalize_view("icon:default"), "icon:default");
        assert_eq!(normalize_view("default"), "default");
    }
}
