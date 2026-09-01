//! husk-slurm-broker — trusted out-of-sandbox SLURM broker for husk.
//! Watches the spool, validates agent sbatch requests as hostile input, forces
//! safe options, re-sandboxes the job, and submits. See BROKER.md / PROTOCOL.md.

mod config;
mod cage;
// The network phase is built decision-first: the allowlist and the proxy that enforces it
// are complete and tested before the relay wiring that carries traffic to them exists.
// Nothing reaches these yet, hence the attributes — remove them when the guard starts a
// proxy and binds its socket into the cage.
mod netallow;
mod netproxy;
mod policy;
mod profile;
mod rank;
mod protocol;
mod sbatch;
mod srun;
mod session;
mod settings;
mod spool;
mod step;
/// The offline grader for `slurm-broker/slurmd-differential.sh` artefacts. Test-only: it
/// adds no code to the shipped binary, and it needs `settings`/`policy`, which live in this
/// binary crate rather than in the dependency-free `lib.rs`.
#[cfg(test)]
mod slurmd_differential;

use session::Session;
use spool::Broker;
use std::path::PathBuf;
use std::time::Duration;

// Die with the session: the wrapper spawns us, then execs the agent (same PID).
// PR_SET_PDEATHSIG asks the kernel to SIGTERM us when that parent task exits, so we
// never linger as an orphan watching a dead spool. (Zero-dep: one libc symbol.)
const PR_SET_PDEATHSIG: std::os::raw::c_int = 1;
const SIGTERM: std::os::raw::c_ulong = 15;

/// `prctl(PR_SET_DUMPABLE, 0)` — refuse to be a ptrace/CMA target.
///
/// The broker is the one process in reach of a caged job that deliberately holds what the
/// cage removes: MUNGE, the daemon route, the real sbatch/srun. Everything on a compute
/// node runs as the SAME UID, and the kernel gates `process_vm_readv`/`process_vm_writev`
/// with the ptrace-attach check — so same-uid is normally enough to read another
/// process's memory. Yama's `ptrace_scope` would narrow that to descendants, but Balfrin
/// has no Yama at all (verified 2026-07-31), leaving credentials as the only gate.
///
/// Clearing the dumpable flag makes the kernel demand CAP_SYS_PTRACE instead, which an
/// unprivileged caged rank cannot have. So the broker stops being addressable even if
/// CMA is later allowed for MPI — which is exactly the concession being considered, since
/// Cray MPICH needs `process_vm_readv` for intra-node transfers.
///
/// Consistent rather than new policy: `ptrace` is already in seccomp-wrapper's deny-list.
/// This closes the same door from the other side, for the process that matters most.
///
/// Costs: no core dumps from the broker, and its `/proc/<pid>` entries become root-owned,
/// so `ls /proc/<pid>/fd` on it stops working for the user. Both acceptable for a daemon.
const PR_SET_DUMPABLE: std::os::raw::c_int = 4;
extern "C" {
    fn prctl(
        option: std::os::raw::c_int,
        arg2: std::os::raw::c_ulong,
        arg3: std::os::raw::c_ulong,
        arg4: std::os::raw::c_ulong,
        arg5: std::os::raw::c_ulong,
    ) -> std::os::raw::c_int;
}

/// Make this process unreadable to same-uid processes (see PR_SET_DUMPABLE).
fn refuse_to_be_read() {
    // SAFETY: PR_SET_DUMPABLE with a constant; the remaining args are ignored.
    if unsafe { prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        // Not fatal: it is a hardening measure, not the boundary. Say so rather than
        // failing a submission over it — but say it, so a kernel that refuses is visible.
        eprintln!("broker: warning: could not clear the dumpable flag; this process is \
                   readable by same-uid processes (process_vm_readv/ptrace)");
    }
}

fn die_with_parent() {
    // SAFETY: PR_SET_PDEATHSIG with a signal number; extra args are ignored.
    unsafe {
        prctl(PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0);
    }
    // Guard the race where the parent already died before the prctl call.
    // SAFETY: getppid takes no args and cannot fail.
    if unsafe { libc_getppid() } == 1 {
        std::process::exit(0);
    }
}

extern "C" {
    #[link_name = "getppid"]
    fn libc_getppid() -> std::os::raw::c_int;
    #[link_name = "kill"]
    fn libc_kill(pid: std::os::raw::c_int, sig: std::os::raw::c_int) -> std::os::raw::c_int;
}

// ---- orderly shutdown, so the spool does not outlive the session -------------
//
// The spool is a directory husk creates in the user's own source tree, so leaving one
// behind on every launch is not a cosmetic issue: the field report of 2026-07-31 found
// two of them at different depths and an agent debugging a failed job read the older,
// dead one and drew conclusions from a stale project root.
//
// PDEATHSIG delivers SIGTERM when the session ends, so cleanup hangs off that. The
// handler only sets a flag; the removal happens on the main loop's next tick, where it
// is ordinary code rather than something that must be async-signal-safe.
static SHUTDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// How idle a pre-v0.5 spool (fixed name, no `owner` file) must be before it is reaped.
/// It cannot prove it is dead, so age is the only evidence there is, and an hour is
/// comfortably longer than the gap between two of a live broker's writes.
const LEGACY_SPOOL_MIN_AGE_SECS: u64 = 3600;

type SigHandler = extern "C" fn(std::os::raw::c_int);

extern "C" fn note_shutdown(_sig: std::os::raw::c_int) {
    SHUTDOWN.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Catch the signals that end a session, so the spool is removed instead of orphaned.
/// SIGKILL cannot be caught, which is exactly why the reaper on the next startup exists
/// as a second, independent path.
fn catch_shutdown_signals() {
    const SIGINT: std::os::raw::c_int = 2;
    const SIGTERM_NUM: std::os::raw::c_int = 15;
    // SAFETY: installing a handler that does nothing but store to an AtomicBool.
    unsafe {
        let h = note_shutdown as SigHandler as usize;
        crate::cage::libc_signal(SIGTERM_NUM, h);
        crate::cage::libc_signal(SIGINT, h);
    }
}

fn shutting_down() -> bool {
    SHUTDOWN.load(std::sync::atomic::Ordering::SeqCst)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Claim this spool by recording who is using it, and report whether the claim stuck.
///
/// Only the claimant removes the directory on exit. If an `owner` file already names a
/// LIVE process, this broker is a guest in someone else's spool: it still serves (two
/// brokers on one spool is harmless — each request is consumed once), but it must not
/// delete the directory out from under the other session.
fn claim_spool(spool: &std::path::Path, project_dir: &std::path::Path) -> bool {
    if let Some(other) = husk_slurm_broker::spool_owner_pid(spool) {
        if other != std::process::id() && husk_slurm_broker::pid_is_alive(other) {
            eprintln!(
                "broker: spool {spool:?} is already owned by live pid {other} — sharing it, \
                 and leaving its cleanup to that session"
            );
            return false;
        }
    }
    let owner = format!(
        "pid={}\nstarted={}\nproject={}\nversion={}\n",
        std::process::id(),
        husk_slurm_broker::utc_stamp(now_secs()),
        project_dir.display(),
        env!("CARGO_PKG_VERSION"),
    );
    write_claim(&spool.join("owner"), &owner)
}

/// Write the claim WITHOUT following a symlink to it, and never truncate what is already there.
///
/// `fs::write` follows symlinks. The spool must be writable by the caged agent for the stub to
/// reach it, and this process runs OUTSIDE the cage — so `ln -s ~/thesis.tex <spool>/owner` made
/// the broker truncate that file and stamp `pid=…` over it. Measured on a pristine build:
/// `IMPORTANT USER DATA` became `pid=12`, and it reproduces through `--once`, i.e. on every path
/// that reaches this function (`RC2-3`). An out-of-cage arbitrary-file truncate, from one symlink
/// in a directory the agent is supposed to be able to write.
///
/// `create_new` is `O_CREAT|O_EXCL`, which POSIX requires to FAIL on an existing symlink rather
/// than resolve it — so there is no window to lose: an attacker who re-plants between the unlink
/// and the open gets `EEXIST`, not a truncate. The `remove_file` is `unlink(2)`, which does not
/// follow a symlink either, and it only removes the one claim this function has already decided
/// it may overwrite (the caller checked immediately above that no LIVE process owns it).
///
/// `owned_by_me` guards that removal because husk can be launched in a world-writable directory,
/// where a spool-shaped name proves nothing about who made it — the same reason `reap_stale_spools`
/// has always had it (`RC2-7`).
///
/// **Every failure is a `false`, never a refusal to serve.** A directory named `owner`, a
/// read-only spool, another user's claim: the broker still brokers, as a guest that will not
/// delete the directory on the way out. Refusing here would hand the confined side a launch it
/// can abort with one `mkdir`, which is `RC-4` — the denial of service that got the first attempt
/// at this fix reverted.
fn write_claim(owner_path: &std::path::Path, body: &str) -> bool {
    use std::io::Write;
    if husk_slurm_broker::owned_by_me(owner_path) {
        let _ = std::fs::remove_file(owner_path);
    }
    let created = std::fs::OpenOptions::new().write(true).create_new(true).open(owner_path);
    match created.and_then(|mut f| f.write_all(body.as_bytes())) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("broker: could not record spool ownership ({e}) — this spool will be left behind");
            false
        }
    }
}

/// Tell the wrapper this broker is serving, on the descriptor it handed us before we existed.
///
/// **What this replaces, and why the replacement is not another way of reading a file.**
/// `<spool>/owner` was the wrapper's only positive evidence that a broker had come up. It is a
/// file in a directory the CAGED side must be able to write, so every disposition of it was
/// either a false accept — a planted `owner`, or one `mkdir owner` that makes an unlink fail —
/// or a denial the agent could trigger with `echo pid=1 > owner`. A descriptor created by the
/// wrapper before the fork has neither property: nothing inside the cage can create one, delete
/// one, or point one somewhere else (`P2`).
///
/// **`owner` is still written and still read** — `spool_owner_pid` for guest detection,
/// `owns_spool` for teardown, `reap_stale_spools` for sessions that were killed rather than
/// signalled. That is bookkeeping among brokers about a directory they share. It is no longer
/// evidence for a fail-closed decision, and the wrapper's `BrokerReady::establish` no longer
/// takes a spool path at all.
///
/// **What the byte attests** is exactly what `claim_spool` returning attests: the settings
/// resolved, the project dir resolved, and the spool is ours or knowingly shared. Not that the
/// claim STUCK — a broker sharing a live session's spool serves it, which `claim_spool`'s `bool`
/// exists to say — so a guest announces itself too, and the wrapper launches, as it did when the
/// evidence was the file.
///
/// **Absent variable is a silent no-op:** `--once`, `--dry-run`, a hand-started broker, every
/// test. None of them has a wrapper waiting. And an error is best-effort for the same reason the
/// log is: failing to speak to a wrapper must not stop a broker that has already claimed its
/// spool from serving.
fn signal_ready() {
    use std::io::Write;
    let Some(raw) = std::env::var_os(husk_slurm_broker::BROKER_READY_FD_ENV) else {
        return;
    };
    let Some(fd) = raw.to_str().and_then(|v| v.trim().parse::<std::os::fd::RawFd>().ok()) else {
        eprintln!(
            "broker: {} is set to {raw:?}, which is not a descriptor number — the wrapper will \
             time out waiting for this broker to announce itself",
            husk_slurm_broker::BROKER_READY_FD_ENV
        );
        return;
    };
    // SAFETY: the descriptor was opened by the wrapper and passed across `execve`; it is valid
    // for as long as this process is. `ManuallyDrop` because we must NOT close it: the wrapper
    // reads EOF here as "this broker is gone", so closing it would report a death that has not
    // happened, and freeing fd 0 would hand it to the next `open` in this process.
    let mut chan =
        std::mem::ManuallyDrop::new(unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) });
    if let Err(e) = chan.write_all(b"R") {
        eprintln!(
            "broker: could not signal readiness to the wrapper ({e}) — it will refuse to launch \
             the agent in a few seconds, and this line is the reason"
        );
    }
}

/// `--hold-cage` — own the node cage's namespaces and nothing else.
///
/// Creates one **bare** user namespace, identity-maps this user into it, and does nothing
/// else for as long as the job needs it. No mounts, no network: every rank still builds
/// its own cage with `bwrap --userns <this>`, and sharing only the user namespace is what
/// makes rank-to-rank CMA legal (see the `cage` module).
///
/// Deliberately not `unshare(1) -- sleep`: the namespace is created in-process so the map
/// is ours to guarantee rather than a flag to trust, and so nothing sits between the
/// step-broker and this process to swallow the shutdown signal.
///
/// **The step-broker spawns this; it must never BE this.** The broker is defined by being
/// outside the cage — it holds MUNGE, the daemon route and the real `srun`, all of which
/// the cage removes. Sharing the ranks' user namespace would also make the broker a valid
/// `ptrace_may_access` target, and "the broker is not a target" is half the argument that
/// made the CMA read concession acceptable at all (`PR_SET_DUMPABLE` is the other half).
///
/// Prints its pid, then blocks until stdin reaches EOF. The pid is reported by the holder
/// itself rather than taken from `Child::id()` so that it is the pid actually inside the
/// namespace. Two independent shutdown paths, because a namespace leaked per job would
/// accumulate on a node: EOF on stdin when the step-broker drops the pipe, and `PDEATHSIG`
/// if the step-broker dies without dropping anything.
fn hold_cage_mode() -> ! {
    die_with_parent();

    if let Err(e) = cage::create_shared_userns() {
        eprintln!("husk: {e}");
        std::process::exit(1);
    }

    // NOTE: the holder deliberately does NOT call refuse_to_be_read().
    //
    // NOT because it cannot. Measured 2026-07-31 on kernel 6.8: a holder that clears
    // PR_SET_DUMPABLE can still be opened and joined with `bwrap --userns` by a sibling
    // process, so the flag is available here. An earlier comment claimed otherwise and
    // was never measured.
    //
    // It is left off because the trade is bad. The gain is a third layer on something
    // already protected twice over — a rank cannot read this process (measured), and it
    // holds no credentials, no daemon route and no memory worth reading. The risk is
    // kernel-dependent: that measurement is from 6.8, Balfrin runs 5.14 Cray Shasta, and
    // if joining did break there then EVERY step would die. Measure on the target before
    // trading a working MPI path for defence in depth on an empty process. It also makes
    // `/proc/<pid>` root-owned, which already misled one debugging session.
    //
    // It does not need the flag anyway: a rank is MEASURABLY unable to read this process
    // (2026-07-31, `process_vm_readv` -> EPERM with Yama neutralised, against a control
    // that reads a peer rank successfully). The likely reason — explanation, not
    // measurement — is that this process's mm belongs to the INITIAL user namespace,
    // since it was created at exec and the namespace came later, so the kernel's
    // ptrace-attach check demands CAP_SYS_PTRACE there, which a rank does not have.
    //
    // And the exposure would be nil regardless: no credentials, no daemon route, no
    // memory worth reading. It exists only to keep one namespace alive.

    // The PID namespace, added on top of the user namespace (that order is a kernel rule:
    // creating a pidns needs CAP_SYS_ADMIN, which we only have inside a userns we own).
    // The pid reported below is the holder's PID-1 CHILD, not this process: it names both
    // namespaces at once, and it is the one that must stay alive for the job.
    let held = match cage::create_shared_pidns() {
        Ok(pid) => pid,
        Err(e) => {
            eprintln!("husk: {e}");
            std::process::exit(1);
        }
    };

    use std::io::{Read, Write};
    println!("{held}");
    if std::io::stdout().flush().is_err() {
        eprintln!("husk: cage holder could not report readiness");
        std::process::exit(1);
    }

    let mut buf = [0u8; 64];
    loop {
        match std::io::stdin().read(&mut buf) {
            Ok(0) | Err(_) => break, // broker closed the pipe, or it broke: either way, done
            Ok(_) => continue,       // nothing is expected on this channel; ignore it
        }
    }
    // Take the namespace holder down explicitly. It has PDEATHSIG too, but that only fires
    // when THIS process dies — and on the clean path we exit deliberately, so saying so is
    // what makes the teardown deterministic rather than a race between exit() and the
    // kernel's parent-death delivery.
    //
    // SIGKILL, not SIGTERM: the holder is PID 1 of its namespace, and a namespace init
    // ignores any signal it has no handler for — even from an ancestor namespace, where
    // SIGKILL and SIGSTOP are the only exceptions. SIGTERM here is silently discarded.
    // SAFETY: kill(2) with a signal number; the child is ours and not yet reaped.
    unsafe { libc_kill(held as i32, 9) };
    std::process::exit(0);
}

/// `--net-proxy --socket PATH --workdir DIR` — the egress proxy for one job.
///
/// Runs OUTSIDE the cage, started by the guard before it enters the sandbox, and answers
/// on a unix socket inside the job's spool. The cage keeps `--unshare-net`; the socket is
/// visible inside it only because the workdir is bind-mounted, which is the whole trick —
/// a unix socket crosses a network namespace because it is a filesystem object.
///
/// The allowlist is resolved HERE rather than passed in, from the same three settings
/// files the broker reads. Passing it on the command line would mean the policy in force
/// depends on a string the guard carried, and the guard's command line is visible to
/// anything that can read /proc; resolving it means the policy is read from files the
/// agent cannot write.
fn net_proxy_mode(args: &[String]) -> ! {
    die_with_parent();
    refuse_to_be_read();

    let mut socket = None;
    let mut workdir = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--socket" => socket = it.next().cloned(),
            "--workdir" => workdir = it.next().cloned(),
            other => {
                eprintln!("husk-proxy: unknown argument {other:?}");
                std::process::exit(2);
            }
        }
    }
    let (Some(socket), Some(workdir)) = (socket, workdir) else {
        eprintln!("husk-proxy: --socket PATH --workdir DIR are both required");
        std::process::exit(2);
    };

    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    let (allow, raw) = match netallow::Allowlist::resolve(&home, std::path::Path::new(&workdir)) {
        Ok(a) => a,
        Err(why) => {
            // A policy that does not compile must not become a policy that permits
            // nothing SILENTLY: the operator wrote something and deserves to know it was
            // rejected. Fail loudly, and the job simply has no egress.
            eprintln!("husk-proxy: {why}");
            std::process::exit(1);
        }
    };
    if allow.is_empty() {
        eprintln!("husk-proxy: no sandbox.network.allowedDomains configured; not starting");
        std::process::exit(0);
    }

    // Announce the policy in force, on every job. An egress boundary nobody can see is
    // one nobody can check, and `*` in particular should never be a surprise.
    if allow.is_open() {
        eprintln!(
            "husk-proxy: WARNING - sandbox.network.allowedDomains contains \"*\": this job \
             may reach ANY host. The scheduler ports stay blocked and /run/munge stays \
             masked, so the broker cannot be bypassed, but nothing else is restricted."
        );
    }
    eprintln!("husk-proxy: allowing {}", raw.join(", "));
    // ONE FILE, TWO DIALECTS — say so, because the operator cannot see it from either side.
    // Deleting `strictAllowlist` opens the LOGIN cage (the vendor asks, and auto mode answers
    // yes) and changes NOTHING here (husk's proxy is default-deny and has nothing to ask). A
    // job then gets 403s that look like a husk bug while the same host is reachable from the
    // session shell. Happened on Santis; nothing in either half explained it.
    if netallow::Allowlist::login_and_compute_disagree(&home, std::path::Path::new(&workdir)) {
        eprintln!(
            // The divergence is REPORTED, not repaired, and that is the decision — not a
            // gap waiting for someone to converge the two cages (Christoph, 2026-08-31).
            //
            // The login cage can afford "unlisted host = a question" because it HAS a place
            // to put the question: an interactive session with an approval step and a model
            // in the loop, which is what makes auto-approval a review rather than a
            // rubber stamp. A batch job has no such channel and cannot grow one — no human,
            // no reviewer, nothing to ask. So on the compute side "unlisted = allowed" would
            // not mean auto-approved, it would mean UNEXAMINED, and the allowlist is the
            // only check that exists there.
            //
            // Converging them therefore has only bad directions: make login strict and lose
            // the workflow the vendor provides, or make compute permissive and lose the one
            // control it has. Announcing the difference is the right answer, and the message
            // says which half is which so the reader can act on it.
            "husk-proxy: NOTE - sandbox.network.strictAllowlist is not true, so the LOGIN cage \
             treats an unlisted host as a question and auto-approves it, while this job \
             enforces the list above. The two halves of husk disagree about the same config."
        );
        eprintln!(
            "husk-proxy: to open BOTH, say it explicitly: \"allowedDomains\": [\"*\"]. husk will \
             not read a MISSING key as permission to open a boundary."
        );
    }

    // Vet the address before binding it. Both failure modes this catches produce a job
    // with no network, and the difference between a named cause and `AF_UNIX path too
    // long` is a bring-up round. See check_socket_path.
    if let Err(why) = husk_slurm_broker::check_socket_path(std::path::Path::new(&socket)) {
        eprintln!("husk-proxy: refusing to bind the egress socket: {why}");
        std::process::exit(1);
    }

    // A stale socket from a crashed predecessor would make bind() fail; the directory is
    // per-job and owner-only (checked just above), so anything here is ours.
    let _ = std::fs::remove_file(&socket);
    let listener = match std::os::unix::net::UnixListener::bind(&socket) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("husk-proxy: cannot bind {socket}: {e}");
            std::process::exit(1);
        }
    };
    // Owner-only. The caged job runs as this user, so this costs it nothing, and it keeps
    // other users on a shared node from borrowing the job's egress.
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)) {
        eprintln!("husk-proxy: cannot restrict {socket}: {e}");
        std::process::exit(1);
    }
    eprintln!("husk-proxy: listening on {socket}");
    netproxy::serve(listener, allow);
    std::process::exit(0);
}

/// The name prefixes this reaper is allowed to act on at all.
///
/// **One list, because there are two consumers.** `bodies_to_prune` filters on
/// `.husk-body-`+`.sh` and `spools_to_prune` on `STEP_SPOOL_PREFIX`; this is the union, used to
/// decide which entries are worth a `metadata()` call. `STEP_SPOOL_PREFIX` is taken from the
/// same constant the consumer uses, so half of it cannot drift; the body prefix is a literal
/// inside `bodies_to_prune` and is therefore copied here, which is exactly the drift `P8`
/// warns about — so `the_age_of_an_entry_husk_will_never_touch_is_never_read` asserts this
/// list against those two functions rather than against my reading of them.
///
/// **If you add a third pruner, add its prefix HERE**, or its files become invisible to it.
/// That is the cost of the prefilter and it is stated rather than discovered.
const PRUNABLE_PREFIXES: &[&str] = &[".husk-body-", husk_slurm_broker::STEP_SPOOL_PREFIX];

/// Is this entry's AGE worth a syscall?
///
/// The name comes free with `getdents`; the age is a `statx`, and on Lustre a `statx` is an MDS
/// round trip. Asking the cheap question first is the whole of the walk fix.
fn needs_its_age_read(name: &str) -> bool {
    PRUNABLE_PREFIXES.iter().any(|prefix| name.starts_with(prefix))
}

/// Read an entry's age, and count that read, in ONE place.
///
/// **The counter and the syscall are welded together on purpose** (`RE-11`). They used to be two
/// statements, so `let md = e.metadata();` could be hoisted above the name guard while
/// `report.aged += 1` stayed below it — one `statx` per entry restored, `aged` unchanged, and
/// `the_age_of_an_entry_husk_will_never_touch_is_never_read` **green**. A self-reported counter
/// only measures the thing it is attached to; this is what attaches it.
///
/// `metadata()` on a `DirEntry` is `lstat` — it does NOT follow a symlink, so the age is the
/// link's own. That is deliberate for the age gate and dangerous for anything that then opens
/// the name; see `open_dir_nofollow`, which is where that name is turned into a handle.
fn age_of(e: &std::fs::DirEntry, report: &mut PruneReport) -> u64 {
    report.aged += 1;
    e.metadata()
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.elapsed().ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// How many directory entries one prune pass will look at.
///
/// Deliberately the same number as the credential auto-scan's own cap in `settings.rs`, which
/// sits four lines away in the same startup path and has had a cap, and a warning, since it
/// shipped — the sibling this walk should have matched from the start. It is duplicated rather
/// than shared only because that constant is private to `settings.rs`; the number is a
/// coarse "this is not a project directory any more" bar, not a tuned one, so the copy costs
/// nothing if the two ever differ.
///
/// **Hitting it is not a failure.** The pass stops, says so by name, and the launch continues:
/// this is hygiene, and a reaper that refused to start a session over a large directory would
/// be a denial of service dressed as tidiness.
const PRUNE_SCAN_MAX_ENTRIES: usize = 20_000;

/// What one prune pass actually did — returned so a test can assert the thing that was wrong.
///
/// `aged` is the number of `metadata()` calls, which is the defect stated as a number: it used
/// to equal `scanned`.
#[derive(Debug, Default, PartialEq, Eq)]
struct PruneReport {
    /// Units of directory work spent, and the meter the cap bounds: one per entry listed at
    /// ANY level — the project directory and the inside of each stale step spool — plus one per
    /// artifact removed. Counting only the top level bounded the cheap half and left 90,000
    /// unlinks unbounded behind a `scanned` of 300 (`RE-3`).
    scanned: usize,
    /// Entries whose modification time was read — one `statx` each.
    aged: usize,
    /// Bodies and step spools actually reclaimed.
    removed: usize,
    /// The scan stopped at the cap, so this pass was incomplete.
    truncated: bool,
}

/// `O_NOFOLLOW | O_DIRECTORY` for this architecture, **derived rather than restated** (`N1-3`).
///
/// The kernel spells both flags per architecture, and arm64 overrides the asm-generic block, so
/// `0o400000` is `O_NOFOLLOW` on Balfrin and `O_LARGEFILE` — a 64-bit no-op — on Santis. The
/// header, the derivation, the trap that `grep /usr/include` on an x86_64 box "proves" no
/// override exists, and the list of overriding architectures are all written out ONCE, at
/// `spool::FCNTL_OVERRIDDEN_BY_THIS_ARCH`; this cites them rather than repeating them (`P8`).
///
/// **It used to repeat them, and that is the finding this line closes.** These two constants
/// were declared under two `cfg` lists that "have to stay identical", with a test documented as
/// asserting they do. That test compares two *values on the compiled target*, and on an x86_64
/// build host both lists take their `not(any(...))` arm whatever they contain — so a reviewer
/// removed `aarch64` from one of them, restoring the exact Santis defect, and the suite stayed
/// byte-identical green. There is now one list, so there is nothing to keep identical.
///
/// **And the number is still not what is trusted.** `open_dir_verified` does not rely on these
/// flags for correctness at all — see its `fstat` comparison, and
/// `the_symlink_refusal_survives_open_flags_that_do_nothing_on_this_architecture`, which
/// switches them off entirely and asserts the guard holds anyway. What the flags buy is a
/// refusal in the KERNEL, one syscall earlier: `O_DIRECTORY` in particular is what stops a raced
/// swap to a symlink-to-FIFO from blocking `open` forever, which a post-readiness broker cannot
/// afford.
///
/// The convention this follows is already in the tree: `cage.rs` states of `SIGCHLD` that it is
/// "stable across x86_64 and aarch64, the two architectures husk runs on" — the right question,
/// asked and answered. `O_NOFOLLOW` is the same question with the opposite answer, and it was
/// never asked.
const O_NOFOLLOW_DIRECTORY: i32 = spool::O_NOFOLLOW | spool::O_DIRECTORY;

/// Open a stale step spool as a HANDLE, refusing to traverse a symlink at the final component.
///
/// `RE-B`. `RE-9` was closed with `symlink_metadata(&p)` and then `read_dir(&p)`: a check and a
/// use on the same NAME, with a window between them. This prune runs AFTER `signal_ready()`, so
/// the agent is already launched and writing the project directory while it runs — swap a
/// backdated real `.husk-step-spool-N` for a symlink between those two syscalls and the
/// out-of-cage delete is back, race-gated. `P15` is the class: a control names a target, and a
/// path is free to name a different object by the time it is used.
///
/// One `open` settles both questions against one object. `O_NOFOLLOW` refuses a symlink at the
/// leaf, `O_DIRECTORY` refuses a regular file, and what comes back is a descriptor on the inode
/// that passed rather than a name that has to be resolved again — the same shape, for the same
/// reason, as `write_claim`'s `create_new` and `create_capture_file`.
///
/// `None` is not a failure to report. It means husk does not reclaim this one, and one unit of
/// lost hygiene is the right price: nothing on this path may refuse a launch, because it runs
/// after the readiness byte by construction (see the launch-budget window in `main`).
fn open_dir_nofollow(p: &std::path::Path) -> Option<std::fs::File> {
    let named = named_directory(p)?;
    open_verified(p, &named, O_NOFOLLOW_DIRECTORY)
}

/// Step one: is this NAME a directory right now, and what is its identity?
///
/// `lstat`, so a symlink is refused here and never opened — the deterministic `RE-9` case. The
/// `Metadata` it returns is not a permission slip; it is the identity `open_verified` will require
/// the descriptor to have.
fn named_directory(p: &std::path::Path) -> Option<std::fs::Metadata> {
    let md = std::fs::symlink_metadata(p).ok()?;
    md.is_dir().then_some(md)
}

/// Step two: open it, and then **verify the thing that was opened**, on the descriptor.
///
/// **This is check-then-VERIFY, and the distinction from check-then-use is the whole of `RE-B`.**
/// The shape that was wrong resolved the name twice and compared nothing: `symlink_metadata(&p)`
/// decided, `read_dir(&p)` re-resolved, and a swap in between simply won. Here the second
/// resolution is followed by `File::metadata`, which is `fstat` ON THE DESCRIPTOR — not a third
/// lookup of the name — so it reports the object husk is about to descend into and nothing else.
/// If a swap happened, the descriptor is a different inode than `named_directory` measured, the
/// comparison fails, and husk refuses. There is no window in which a swap goes unnoticed, because
/// the object finally used is the object that was verified.
///
/// `flags` is a parameter for exactly one reason: so a test can pass `0` and prove the refusal
/// does not depend on `O_NOFOLLOW_DIRECTORY` being right for the architecture it was built for —
/// a question nobody on an x86_64 machine can answer about aarch64 any other way. Production has
/// one caller, `open_dir_nofollow`, and a lexical assertion pins the constant it passes (`RE-14`).
///
/// Inode reuse is not a way through: matching `(dev, ino)` means it IS the same file. The only
/// way to mint a collision is to have the original freed and its inode handed to something the
/// agent creates — which lands inside the project directory it already writes, so it is not an
/// escalation.
fn open_verified(
    p: &std::path::Path,
    named: &std::fs::Metadata,
    flags: i32,
) -> Option<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let dir = std::fs::OpenOptions::new().read(true).custom_flags(flags).open(p).ok()?;
    let opened = dir.metadata().ok()?;
    (opened.is_dir() && opened.dev() == named.dev() && opened.ino() == named.ino()).then_some(dir)
}

/// The path that resolves to an OPEN DIRECTORY rather than to a name.
///
/// `std::fs` has no `readdir`/`unlinkat` that take a descriptor, and this binary's dependency
/// surface is a security property — the same reason `main.rs` declares `prctl` itself — so it
/// does not grow a `libc` dependency to get them. `/proc/self/fd/<n>` is the kernel's own answer:
/// it is a magic link, so resolving it lands on the dentry the descriptor holds instead of
/// re-walking the original path. Every lookup under it — the listing, and each `remove_file` —
/// therefore happens inside the directory `open_dir_nofollow` accepted, whatever the name means
/// by then. Measured: after `rename` + `symlink` win the race, the listing and the unlink still
/// hit the moved original and the symlink's target is untouched.
///
/// `/proc` is already a hard dependency of this binary: `current_exe()` reads `/proc/self/exe`
/// for the build-stamp line at startup. If it were missing the listing just fails, the spool is
/// left alone, and hygiene is what is lost — the same safe direction as every other failure here.
fn open_dir_path(dir: &std::fs::File) -> std::path::PathBuf {
    use std::os::fd::AsRawFd;
    std::path::PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()))
}

/// Unlink husk's own named artifacts inside an ALREADY-OPEN stale step spool.
///
/// **It takes the open directory and not its path, and that is the fix** (`RE-B`): a caller
/// cannot hand this function a name it checked a moment ago, because it cannot hand it a name at
/// all. Only husk's own prefixes are ever removed — that is what makes unlinking inside a user's
/// project directory defensible — and every entry costs one unit of the same prune budget
/// (`RE-3`).
fn empty_stale_spool(dir: &std::fs::File, cap: usize, report: &mut PruneReport) {
    let inside = open_dir_path(dir);
    let Ok(rd) = std::fs::read_dir(&inside) else { return };
    for f in rd.flatten() {
        // THE INNER WALK SPENDS THE SAME BUDGET (`RE-3`). Capping the outer scan alone bounded
        // the cheap half: measured, 300 stale spools of 300 files each is `scanned = 300` —
        // nowhere near the cap — and 90,000 unlinks. Post-readiness that is not a slow start, it
        // is a broker that has not begun serving while the agent's every `sbatch` runs down its
        // 120 s.
        if report.scanned >= cap {
            report.truncated = true;
            break;
        }
        report.scanned += 1;
        let fname = f.file_name().to_string_lossy().to_string();
        if fname.starts_with("req-")
            || fname.starts_with("resp-")
            || fname.starts_with("out-")
            || fname.starts_with("err-")
            || fname.starts_with("broker.alive")
            || fname == "owner"
            || fname == "net.sock"
            || fname == "socat"
            || fname == "net-proxy.log"
        {
            // `f.path()` is rooted at the handle, so this unlink is relative to the directory
            // that was opened and accepted — not to `.husk-step-spool-N` as the name reads now.
            let _ = std::fs::remove_file(f.path());
        }
    }
}

/// Delete `.husk-body-*.sh` files older than the retention bound, in the project dir.
///
/// Best-effort and quiet on failure: this is hygiene, not a boundary, and a project dir husk
/// cannot write is already reported by everything else that needs it. Only husk's own
/// prefix is ever touched — that is what makes deleting inside a USER's directory defensible.
///
/// **THE NAME IS ASKED BEFORE THE AGE (`B5-7`, `D1`).** This used to call `metadata()` on every
/// entry and then throw away all but the handful whose name matched — one `statx` per file in
/// the user's project directory, measured at **100,009 for a 100,000-entry directory** and
/// 20,009 for 20,000, exactly one per entry. Both consumers reject on the NAME first, so the
/// stat was bought for entries that could never be selected. On a cold Lustre mount, at a
/// conservative 0.15 ms per `statx`, 100k entries is fifteen seconds — and until this commit
/// this ran BEFORE the broker announced itself, so that fifteen seconds was the wrapper's
/// entire launch budget, spent statting files husk was never going to touch. It now runs after
/// readiness AND costs ~0 stats in an ordinary directory; either change alone would have been
/// a fix, and both are here because they close different halves (`when` and `how much`).
fn prune_stale_bodies(project_dir: &std::path::Path) {
    prune_stale_bodies_capped(project_dir, PRUNE_SCAN_MAX_ENTRIES);
}

/// The cap is a parameter so the truncation path is testable without creating twenty thousand
/// files. Everything else is identical — the same shape as `with_partition_limits_within` and
/// the wrapper's `establish_within`.
fn prune_stale_bodies_capped(project_dir: &std::path::Path, cap: usize) -> PruneReport {
    let mut report = PruneReport::default();
    let Ok(rd) = std::fs::read_dir(project_dir) else { return report };
    let mut entries: Vec<(String, u64)> = Vec::new();
    for e in rd.flatten() {
        if report.scanned >= cap {
            report.truncated = true;
            break;
        }
        report.scanned += 1;
        let name = e.file_name().to_string_lossy().to_string();
        // THE CHEAP QUESTION FIRST. An entry husk could never reclaim never costs a syscall.
        if !needs_its_age_read(&name) {
            continue;
        }
        entries.push((name, age_of(&e, &mut report)));
    }
    if report.truncated {
        // WHO IS TALKING, WHAT WAS SKIPPED, AND WHAT IT COSTS (`P11`) — and explicitly that the
        // session is fine, so nobody goes looking for a launch problem that is not there. The
        // prefix matches the rest of this binary's lines so the wrapper's refusal relay would
        // carry it if it ever mattered.
        eprintln!(
            "broker: stopped reclaiming stale husk artifacts after {cap} entries of {} — this \
             session runs normally, and nothing else is affected. What is lost is hygiene: some \
             old .husk-body-*.sh files and .husk-step-spool-* directories were not reclaimed. \
             They will NOT be picked up later on their own — `readdir` order is stable, so \
             every session stops at the same place (measured). Thin the directory, or remove \
             `.husk-body-*` and `.husk-step-spool-*` by hand, if the litter matters.",
            project_dir.display()
        );
    }
    for name in husk_slurm_broker::bodies_to_prune(
        &entries,
        husk_slurm_broker::BODY_RETAIN_MAX_AGE_SECS,
    ) {
        if report.scanned >= cap {
            report.truncated = true;
            break;
        }
        report.scanned += 1;
        let p = project_dir.join(&name);
        if std::fs::remove_file(&p).is_ok() {
            report.removed += 1;
            eprintln!("broker: reclaimed stale job body {}", p.display());
        }
    }
    // Step spools leaked by a guard refusal (A1). A DIRECTORY, so a separate reaper, and
    // `remove_dir` not `remove_dir_all`: husk removes only an EMPTY stale spool. A non-empty
    // one still holds something — a live job's rendezvous, or evidence — and a recursive
    // delete inside a user's own project dir is a primitive husk does not hand itself.
    for name in husk_slurm_broker::spools_to_prune(
        &entries,
        husk_slurm_broker::BODY_RETAIN_MAX_AGE_SECS,
    ) {
        let p = project_dir.join(&name);
        // A SYMLINK IS NOT A SPOOL, AND THIS IS A SECURITY CHECK, NOT A TIDINESS ONE (`RE-9`,
        // closed against the raced instance too by `RE-B`).
        //
        // `DirEntry::metadata` is `lstat`, so the age gate above reads the LINK's timestamp,
        // which the agent sets with one `touch -h -d`. `read_dir` FOLLOWS. So
        // `ln -s ~/somewhere .husk-step-spool-4242` made this broker — running OUTSIDE the cage,
        // with the user's full authority — walk that directory and unlink every file matching
        // husk's spool names. Measured on the pristine build: `owner`, `net.sock`, `req-1.json`
        // and `err-7.log` deleted from the link target, in a directory the agent cannot write
        // itself, and SILENTLY, because the `remove_dir` then fails so nothing is ever logged.
        //
        // The first fix for that was `symlink_metadata(&p)` and then `read_dir(&p)`, which is a
        // check and a use ON A NAME with a window between them, and this loop runs after the
        // readiness byte — the agent is live and writing this directory while it runs. Opening
        // the candidate ONCE, with `O_NOFOLLOW | O_DIRECTORY`, and descending through the
        // resulting handle removes the window instead of narrowing it: there is one object, and
        // it is the object that was checked.
        let opened = open_dir_nofollow(&p);
        if let Some(dir) = &opened {
            empty_stale_spool(dir, cap, &mut report);
        }
        drop(opened);
        // `remove_dir` stays on the PATH, is attempted even when the open was REFUSED, and both
        // of those are deliberate.
        //
        // Attempted-anyway keeps this change a pure security fix with no behaviour delta. `open`
        // needs read permission on the directory; `lstat` did not. So a backdated EMPTY stale
        // spool at mode 000 — which the agent can mint by the thousand — used to be reclaimed
        // here (`read_dir` failed, `remove_dir` succeeded, parent permissions govern `rmdir`) and
        // would silently stop being reclaimed if the refusal skipped this line. That is a new
        // agent-triggerable litter source created while closing something else, which is the one
        // thing this round has learned to look for.
        //
        // On the PATH is safe for a reason that does NOT hold one line above. `rmdir(2)` does not follow a final symlink (measured: `ENOTDIR`) and
        // refuses a non-empty directory, so the worst a swap can buy here is the removal of an
        // empty directory the agent made itself, inside the directory it already writes. Getting
        // a name here to mean anything OUTSIDE the project directory would need a hard link to a
        // directory (the kernel refuses) or a mount (the caged agent's namespace is not the
        // broker's). Deliberately not `remove_dir_all`.
        if std::fs::remove_dir(&p).is_ok() {
            report.removed += 1;
            eprintln!("broker: reclaimed stale step spool {}", p.display());
        }
    }
    report
}

/// Say what the broker is ABOUT TO DO, before it does it.
///
/// **The convention is inverted on purpose, and the inversion IS the attribution fix.** When
/// the wrapper refuses a launch it relays this log's last six `husk:`/`broker:` lines
/// (`husk-slurm-wrapper.rs::broker_refusal_reason`). Every line the startup window used to
/// write was written AFTER its step had finished, so the relayed tail named the last step that
/// COMPLETED and never the step that was hanging. `D1` measured what an operator actually sees
/// at the fifteen-second deadline, with the broker sitting inside `scontrol`:
///
/// ```text
/// husk: the SLURM broker did not claim its spool within 15s (it is still running, but not
///       serving).
/// husk: refusing to launch the agent rather than hand it a broker that may never answer.
/// husk: spool …/b2/spool
/// husk: the broker said:
///       broker: operator config …/b2/home/.husk/config.json (system "magpie")
/// ```
///
/// A spool and a config file. Nothing names a subprocess, and the remediation that message
/// invites — delete the spool, edit the config — is wrong (`P11`).
///
/// Announcing the step first means whatever the broker is stuck in is the LAST line of the
/// relayed tail, on every path, including the ones nobody has thought of yet. That is what
/// makes this attribution rather than one more message about `scontrol`.
fn starting(step: &str) {
    // `std`'s stderr is unbuffered and `spawn_broker` hands this process the SAME file for
    // stdout and stderr (`try_clone`), so the line is on disk before the step begins — which it
    // has to be, since the entire point is to survive a step that never returns.
    eprintln!("{}", startup_line(step));
}

/// The wording, separated from the I/O so the property that makes it useful is testable: it
/// must survive the wrapper's relay filter, which keeps only lines starting `husk:` or
/// `broker:`. A line the relay drops is attribution nobody ever reads (`P8` — the two halves of
/// this are in different binaries).
fn startup_line(step: &str) -> String {
    format!("broker: startup: {step}")
}

fn main() {
    // Before the daemon preamble: the holder must not run it — see hold_cage_mode.
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) == Some("--hold-cage") {
        hold_cage_mode();
    }
    // Emit the read-only query tables for query-parity-probe.sh. Diagnostic only: it reads
    // no spool, touches no policy, and exits.
    if argv.first().map(String::as_str) == Some("--query-options") {
        policy::print_query_options();
        std::process::exit(0);
    }
    // The option contract as markdown, generated from REGISTRY for husk's user-facing skill.
    // Diagnostic only: reads no spool, touches no policy, exits.
    if argv.first().map(String::as_str) == Some("--print-option-contract") {
        print!("{}", sbatch::option_contract_markdown());
        std::process::exit(0);
    }
    // The resolved operator sets, machine-readable, from the ONE reader.
    //
    // The selftest needs to know which partitions and accounts husk will accept. It used to
    // work that out itself — env, then the legacy install file, then a `preemptible` default —
    // and that second reader drifted the moment the config file became authoritative: the rig
    // submitted `preemptible` while the broker allowed only `debug`, and twelve arms failed on
    // one refusal (Santis, 2026-08-18). Re-deriving it in shell only moved the drift, and that
    // version needed python3, which is not on PATH everywhere — so it failed again the same
    // day, silently, on the same cluster. `P8` says make one list assert the other; here it is
    // cheaper to have one list. Diagnostic only: reads no spool, touches no policy, exits.
    if argv.first().map(String::as_str) == Some("--print-config") {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
        match Session::from_env_and_config(&home) {
            Ok(s) => {
                println!("partitions={}", s.allowed_partitions.join(","));
                println!("accounts={}", s.allowed_accounts.join(","));
                println!("uenvs={}", s.allowed_uenvs.join(","));
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("husk: {e}");
                std::process::exit(2);
            }
        }
    }
    if argv.first().map(String::as_str) == Some("--net-proxy") {
        net_proxy_mode(&argv[1..]);
    }

    die_with_parent();
    refuse_to_be_read();

    let mut dry_run = false;
    let mut once = false;
    let mut spool_arg: Option<String> = None;
    let mut poll_ms: u64 = 200;
    // --step-broker: the compute-node half. Same binary, so one artifact to install and
    // one thing to keep in sync; the modes share the spool protocol and nothing else.
    let mut step_broker = false;
    let mut workdir_arg: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--dry-run" => dry_run = true,
            "--step-broker" => step_broker = true,
            "--workdir" => workdir_arg = args.next(),
            "--once" => once = true,
            "--spool" => spool_arg = args.next(),
            "--poll-ms" => {
                poll_ms = args.next().and_then(|s| s.parse().ok()).unwrap_or(poll_ms)
            }
            "-h" | "--help" => {
                print_help();
                return;
            }
            other => {
                eprintln!("broker: unknown argument '{other}' (try --help)");
                std::process::exit(2);
            }
        }
    }

    let spool = spool_arg
        .or_else(|| std::env::var("HUSK_SLURM_SPOOL").ok())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            husk_slurm_broker::session_spool_dir(
                &std::env::current_dir().unwrap_or_default(),
                std::process::id(),
            )
        });

    // Did the spool exist before we touched it? An owner must be able to tell what it
    // CREATED from what it merely found, or it cannot know what it is entitled to remove.
    // (B1-F6 — the `--once` path acquired both a directory and a claim and released neither.)
    let spool_preexisted = spool.exists();
    if let Err(e) = std::fs::create_dir_all(&spool) {
        eprintln!("broker: cannot create spool {spool:?}: {e}");
        std::process::exit(1);
    }

    // ---- step-broker mode: brokers srun for an ALREADY RUNNING job ----------------
    // It needs no Session (no uenv to inherit, no partition to force — the allocation
    // already exists) and does not submit anything; it launches steps within the job it
    // was started by.
    if step_broker {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
        let workdir = workdir_arg.unwrap_or_else(|| {
            std::env::current_dir().unwrap_or_default().to_string_lossy().to_string()
        });
        // Fail CLOSED, and loudly. A settings file that exists but does not parse used to
        // resolve to an empty policy, so a typo removed the denies rather than reporting
        // them. The step broker is the compute-node half; refusing to start it is refusing
        // to run steps, which is the safe direction.
        let fs_policy = match settings::FsPolicy::resolve(&home, &PathBuf::from(&workdir)) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("husk: refusing to start the step broker - {e}");
                eprintln!("husk: that file configures what this job may read and write, so \
                           husk will not run steps while it cannot be read. Fix the JSON.");
                std::process::exit(2);
            }
        };
        let mut sb = step::StepBroker::new(
            spool.clone(),
            fs_policy,
            profile::Profile::SingleNode,
            workdir,
            dry_run,
        );
        eprintln!("step-broker: watching {spool:?}{}", if dry_run { " (dry-run)" } else { "" });
        loop {
            if let Err(e) = sb.tick() {
                eprintln!("step-broker: scan error: {e}");
            }
            if once {
                break;
            }
            std::thread::sleep(Duration::from_millis(poll_ms));
        }
        return;
    }

    // ---- LAUNCH-BUDGET WINDOW: START ------------------------------------------------
    //
    // Everything between here and `signal_ready()` is spent out of the FIFTEEN SECONDS the
    // wrapper waits before it refuses to launch the agent at all
    // (`husk-slurm-wrapper.rs::BROKER_READY_TIMEOUT`). That makes this window a budget, and
    // `B5-7` is the finding that it was being spent by work with no bound on it:
    //
    //   - the partition-limits query ran N serial `scontrol` subprocesses with no deadline —
    //     two partitions x an 8 s controller measured 16.007 s, past the budget (`B2-2`);
    //   - the stale-body reaper ran one `metadata()` per project-directory entry, uncapped —
    //     100,009 `statx` for a 100k-entry directory.
    //
    // (The lexical test below strips comment lines before it looks, so this paragraph may name
    // them freely and a CALL to either one fails. An earlier version compared against the raw
    // text and was satisfied by its own prose — `RE-12`.)
    //
    // Both are now OUT of this window (they run after readiness, below) and both are bounded
    // in their own right. THE RULE FOR THIS WINDOW, which is what a lexical test pins:
    //
    //   only work whose failure must PREVENT the launch belongs in here.
    //
    // That is why the reorder is not simply "claim the spool first". `FsPolicy::resolve` and
    // the operator-config read are fail-CLOSED — they `exit(2)` — and the readiness byte has to
    // mean they passed. A zero-byte `.claude/settings.json` sending the broker down that path
    // AFTER the wrapper had launched the agent is the 2026-08-06 Balfrin incident: four
    // sessions, hours, every `sbatch` returning `timed out after 120s`. Announcing readiness
    // before those two would re-open it while fixing a slow start, which is a strictly worse
    // trade. Best-effort work has no such claim on the budget and is what moved.
    //
    // What is left in here, and why: the config read (fail-closed, now size- and type-bounded,
    // see `config::MAX_CONFIG_BYTES`), the filesystem-policy resolve (fail-closed), the
    // allowlist check (reads the same files, warm), and `claim_spool`. Each announces itself
    // FIRST — see `starting`.
    //
    // AND ONE OF THEM IS STILL UNBOUNDED. Said plainly, because an earlier version of this
    // comment claimed the opposite and the claim was false. `FsPolicy::resolve`'s twenty-
    // thousand-entry cap is on `scan_credentials`, NOT on the settings READ: `settings_layer_text`
    // is a bare `read_to_string` with no size bound and no file-type check — the two defects
    // this commit just fixed for `~/.husk/config.json`, a hundred lines away. Two of its three
    // sources, `<project>/.claude/settings.json` and `settings.local.json`, are in the directory
    // the CONFINED AGENT writes freely. Measured: a 200 MB layer takes 6.3 s and 200 MB of RSS;
    // a FIFO blocks indefinitely, so one `mkfifo` refuses every later launch, permanently, with
    // the operator pointed at a spool. `B5-7` is therefore half closed — on the operator-writable
    // input — and open on the agent-writable one.
    //
    // It is not fixed here because it lives in `settings.rs`, which another fix owns this round.
    // It is the same two-line fix `config.rs` just took. Recorded rather than implied (`P12`).
    let startup_began = std::time::Instant::now();
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    // Resolve the compute-cage filesystem policy ONCE, now, at startup — from the broker's
    // OWN working directory. The broker is spawned by the human in the project directory
    // (before the agent execs), so `current_dir()` is the TRUSTED project dir. This must
    // NOT come from the agent-controlled `req.cwd`, and capturing it pre-agent means the
    // agent cannot tamper with the settings files the cage is built from. (F17)
    let project_dir = std::env::current_dir().unwrap_or_default();

    // Open the session log by saying what session this is. An append-only log shared by
    // every launch in a directory gave a reader no way to tell a live session's lines
    // from a dead one's; one file per session, headed by this, does.
    //
    // FIRST, not last, and that is a change: these two lines used to be printed after the
    // filesystem policy resolved, so a broker that hung before that point produced a log with
    // no build stamp in it — and "which build is serving this session?" is the first question
    // asked of a launch that went wrong, and the one the stamp exists to answer.
    eprintln!(
        "broker: husk {} session pid {} started {} — project dir {project_dir:?}, spool {spool:?}",
        env!("CARGO_PKG_VERSION"),
        std::process::id(),
        husk_slurm_broker::utc_stamp(now_secs()),
    );
    // WHICH BUILD is serving this session, on its own line so `grep build` finds it.
    //
    // The broker is spawned ONCE per husk session and serves it to the end, so reinstalling
    // husk does not touch a session already running. On Balfrin (2026-08-05) a cage-killing
    // bug was fixed, installed, and verified green by a selftest that spawns its own fresh
    // broker — while the live session kept failing every ICON job with the very error that
    // had been fixed, because its broker predated the install. The crate version above could
    // not distinguish them: `0.4.0` does not move between builds. This line does.
    eprintln!(
        "broker: build {} ({}) from {} — a session keeps the broker it started with, so \
         compare this against your install before believing a fix is in effect",
        husk_slurm_broker::build_identity::rev(),
        husk_slurm_broker::utc_stamp(husk_slurm_broker::build_identity::built_unix()),
        std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown path>".into()),
    );

    starting("reading the operator config ~/.husk/config.json");
    let session = match Session::from_env_and_config(&home) {
        Ok(s) => s,
        // A policy file husk cannot read is a refusal, not a fallback: see
        // `from_env_and_config`. Say it in husk's own words and stop.
        Err(e) => {
            eprintln!("husk: {e}");
            std::process::exit(2);
        }
    };
    if session.uenv.is_none() {
        // No uenv loaded is a NORMAL state on an HPC — not an error. Inform, don't scold.
        eprintln!(
            "broker: no uenv session detected — jobs will run in the base HPC \
             environment (inherited login env / modules). This is fine; if you want \
             a uenv stack, `uenv start` it before launching husk."
        );
    }

    // Same rule on the login side, and this is the one that matters most: this policy
    // carries denyRead and the credential masks, so resolving a broken file to "no denies"
    // is resolving it to "the job reads your secrets".
    //
    // This is the OTHER walk of the project directory in this window, and it is the one that
    // was already bounded — capped at 20,000 entries, with a warning when the cap is hit. It
    // stays inside the budget because it is fail-closed; being bounded is what makes that
    // affordable. (Residual, stated rather than fixed here: its cap warning is prefixed
    // `husk-broker:`, which the wrapper's relay filter — `husk:` / `broker:` — drops. That is
    // in `settings.rs`, which this change does not touch.)
    starting(&format!(
        "resolving the compute-cage filesystem policy from {project_dir:?} (this walks the \
         project directory, capped, and can be slow on a cold Lustre mount)"
    ));
    let fs_policy = match settings::FsPolicy::resolve(&home, &project_dir) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("husk: refusing to start - {e}");
            eprintln!("husk: that file configures what jobs may read and write, including \
                       which credentials are masked. husk will not run with a policy it \
                       cannot read. Fix the JSON and start husk again.");
            std::process::exit(2);
        }
    };

    // The network allowlist lives in the same files and gets the same treatment, at the same
    // moment. It is validated here as well as at submit time, and the difference matters for
    // WHO FINDS OUT. A bad entry is valid JSON — `*.com` parses fine and is refused for being
    // vague — so the filesystem check above sails past it. Without this, husk started
    // cleanly, said nothing, and the agent discovered it by having every single submission
    // rejected, then had to relay a configuration problem back to the human in prose.
    //
    // A configuration error belongs in the terminal of the person who wrote the
    // configuration. The submit-time check stays as a backstop, because these files can be
    // edited while a session is running.
    // ...but a broken allowlist does NOT stop husk, and the asymmetry is the point.
    //
    // The two failures move the boundary in opposite directions. An unreadable filesystem
    // policy loses its DENIES, so continuing would run a weaker cage than the human asked
    // for — refuse. An unreadable allowlist loses its ALLOWS, so continuing runs with no
    // egress at all, which is tighter than asked for and is exactly husk's default. Refusing
    // to start would deny the same network AND all the work that never needed it.
    //
    // So the bug was never that egress got switched off. It was that it got switched off in
    // silence: the generated script for a broken allowlist and for no allowlist were
    // byte-identical, and nothing told anyone. Say it here, and the guard says it in the job.
    starting("checking the network allowlist");
    if let Err(e) = netallow::Allowlist::resolve(&home, &project_dir) {
        eprintln!("husk: WARNING - this session has NO NETWORK for any job.");
        eprintln!("husk: the network allowlist could not be read: {e}");
        eprintln!("husk: everything else works normally. Jobs will run with --unshare-net, \
                   as they do when no allowlist is configured at all. Fix that entry and \
                   restart husk to get egress back. SLURM daemon ports are refused outright \
                   and cannot be allowlisted, so if a refusal suggested adding one, it was \
                   wrong.");
    }

    eprintln!("broker: compute-cage policy resolved from project dir {project_dir:?}");

    catch_shutdown_signals();
    starting(&format!("claiming the spool {spool:?}"));
    let owns_spool = claim_spool(&spool, &project_dir);
    // HERE, and not one line later. This is the instant `<spool>/owner` used to appear, and the
    // wrapper's fifteen-second budget was sized against it — `reap_stale_spools` below walks a
    // directory that can be on a cold Lustre mount, and moving the signal after it would turn a
    // slow filesystem into a refused launch. See `signal_ready`.
    signal_ready();
    // ---- LAUNCH-BUDGET WINDOW: END --------------------------------------------------
    //
    // The wrapper may now launch the agent. Everything below is best-effort: it delays only the
    // first spool scan, against `sbatch`'s 120-second wait, and no failure in it can refuse a
    // session. Print the elapsed time so a startup that is merely slow is visible BEFORE it
    // becomes a refusal — the budget is 15 s and this line says how much of it was used.
    eprintln!(
        "broker: startup: announced readiness after {:.3}s (the wrapper allows 15s)",
        startup_began.elapsed().as_secs_f32()
    );

    // Second teardown path: clean up after sessions that were killed rather than
    // signalled. Scoped to the directory husk was launched in — see reap_stale_spools.
    if let Some(parent) = spool.parent() {
        for note in husk_slurm_broker::reap_stale_spools(
            parent,
            &spool,
            Duration::from_secs(LEGACY_SPOOL_MIN_AGE_SECS),
        ) {
            eprintln!("broker: {note}");
        }
    }
    // Reclaim staged job bodies the guard deliberately no longer deletes — see
    // `bodies_to_prune`. Session start is the right moment: it is outside any job, it is
    // where the log prune already happens, and by definition nothing this session submitted
    // is waiting yet. It sits HERE, beside the other reaper and after readiness, because it
    // is hygiene: a large project directory must not be able to refuse a launch (`B5-7`).
    prune_stale_bodies(&project_dir);
    // The partition time limits, last, because they are the least important thing the broker
    // does: one advisory sentence on an accepted submission (`policy::time_limit_note`). This
    // is the `scontrol` of `B2-2`, now both bounded and out of the launch budget.
    let session = session.with_partition_limits();

    let broker = Broker {
        spool: spool.clone(),
        session,
        dry_run,
        fs_policy,
        submitted: Default::default(),
        project_dir: project_dir.clone(),
        home: home.clone(),
    };
    eprintln!(
        "broker: watching {spool:?}{}",
        if dry_run { " (dry-run)" } else { "" }
    );

    loop {
        if let Err(e) = broker.process_once() {
            eprintln!("broker: scan error: {e}");
        }
        // `--once` is a single scan for tests and dry runs, not a session — it leaves the
        // spool CONTENTS (including any staged script it was asked to inspect) exactly as it
        // found them. What it must NOT leave behind is what it acquired: the ownership claim
        // it wrote, and the directory if there was none before.
        //
        // B1-F6. This path used to `return` straight past the teardown below, so a `--once`
        // run in a fresh directory created a spool, stamped `owner` with its own pid, exited,
        // and left both. Nothing else ever cleaned them up: `reap_stale_spools` is scoped and
        // age-gated, and the next session reads that `owner` file to decide what it may
        // touch. "Release on EVERY path" does not mean the normal one and the signalled one.
        //
        // Deliberately not `remove_spool_dir`: the CONTENTS belong to whoever asked for the
        // scan. `remove_dir` refuses a non-empty directory, which is exactly the right
        // behaviour — a dry run that staged a script keeps its directory and says so.
        if once {
            if owns_spool {
                let _ = std::fs::remove_file(spool.join("owner"));
            }
            if !spool_preexisted && std::fs::remove_dir(&spool).is_err() {
                eprintln!("broker: --once kept spool {spool:?} — it is not empty");
            }
            return;
        }
        if shutting_down() {
            break;
        }
        std::thread::sleep(Duration::from_millis(poll_ms));
    }

    if owns_spool {
        if husk_slurm_broker::remove_spool_dir(&spool) {
            eprintln!("broker: session ended; removed spool {spool:?}");
        } else {
            eprintln!(
                "broker: session ended; kept spool {spool:?} — it holds files husk did not create"
            );
        }
    }
}

fn print_help() {
    // The trailing line prints the delimited build stamp, and it does two jobs. For a human
    // it answers "which build is this file?" without starting a session — the question the
    // session banner exists for, asked of a binary sitting on disk. For the compiler it is a
    // use of the WHOLE literal (a formatting argument is a pointer+len to it), which is what
    // guarantees make-release.sh can still find the marker in a release binary built with
    // lto + opt-level="z" + strip. See src/build_identity.rs.
    println!(
        "husk-slurm-broker — trusted out-of-sandbox SLURM broker for husk\n\
\n\
USAGE: husk-slurm-broker [--spool DIR] [--dry-run] [--once] [--poll-ms N]\n\
\n\
  --spool DIR   spool directory (default: $HUSK_SLURM_SPOOL or ./.husk-slurm-spool)\n\
  --dry-run     print the sbatch argv + staged script instead of submitting\n\
  --once        process the spool once and exit (for testing)\n\
  --poll-ms N   poll interval in milliseconds (default 200)\n\
\n\
Policy: see BROKER.md.  Wire protocol: see PROTOCOL.md.\n\
\n\
{}",
        husk_slurm_broker::build_identity::STAMP
    );
}

#[cfg(test)]
mod tests {
    use super::{
        empty_stale_spool, named_directory, needs_its_age_read, open_dir_nofollow, open_verified,
        prune_stale_bodies_capped, startup_line, write_claim, PruneReport,
    };
    use husk_slurm_broker::{bodies_to_prune, spools_to_prune, BODY_RETAIN_MAX_AGE_SECS};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("husk-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Backdate a path so the age-based reapers will select it, without sleeping.
    fn backdate(path: &std::path::Path, secs: u64) {
        let when = std::time::SystemTime::now() - std::time::Duration::from_secs(secs);
        let f = std::fs::File::options().write(true).read(true).open(path).unwrap_or_else(|_| {
            // A directory cannot be opened for writing; O_RDONLY is enough for futimens.
            std::fs::File::open(path).unwrap()
        });
        f.set_times(std::fs::FileTimes::new().set_modified(when)).unwrap();
    }

    /// `B5-7` / `D1`. `prune_stale_bodies` called `metadata()` on EVERY directory entry and then
    /// discarded all but the few whose NAME its two consumers would even look at — one `statx`
    /// per file in the user's project directory, measured at 100,009 for a 100,000-entry
    /// directory and 20,009 for 20,000. Until this commit it also ran BEFORE the broker
    /// announced itself, so on a cold Lustre mount that walk could spend the wrapper's entire
    /// fifteen-second launch budget on files husk was never going to touch.
    ///
    /// The assertion is on `aged` — the number of `metadata()` calls — because that IS the
    /// defect stated as a number. It used to equal `scanned`.
    ///
    /// **FALSE FRIEND, and it is the obvious test to write:** asserting on which files were
    /// DELETED passes on the unfixed code, because the unfixed code deletes exactly the same
    /// set. The stat count is the only thing that moved. This test asserts both, and only the
    /// first one can fail on the bug.
    ///
    /// **MUTATION that turns it red:** move the `needs_its_age_read` guard below the
    /// `report.aged += 1` / `e.metadata()` block, i.e. restore the original order. `aged`
    /// becomes `scanned` (23) and the first assertion fails.
    #[test]
    fn the_age_of_an_entry_husk_will_never_touch_is_never_read() {
        let dir = scratch("prune-age");
        // An ordinary project directory: source, build output, dotfiles, a lockfile.
        for name in [
            "Cargo.toml", "README.md", "src", "target", ".git", ".gitignore", "build.rs",
            "notes.txt", "run.sh", "data.nc", "a.o", "b.o", "c.o", "d.o", "e.o",
            // Near misses that must NOT be reclaimed and must NOT be stat'd: husk-ish names
            // that neither consumer selects. lib.rs's own prune tests use these exact two.
            ".husk-body-ghi.txt", "husk-body-jkl.sh",
        ] {
            std::fs::write(dir.join(name), "x").unwrap();
        }
        // husk's own artifacts: two bodies (one stale, one fresh) and two step spools.
        std::fs::write(dir.join(".husk-body-old.sh"), "#!/bin/sh\n").unwrap();
        std::fs::write(dir.join(".husk-body-new.sh"), "#!/bin/sh\n").unwrap();
        std::fs::create_dir(dir.join(".husk-step-spool-99")).unwrap();
        std::fs::create_dir(dir.join(".husk-step-spool-100")).unwrap();
        // And the SESSION spool, which shares a prefix family but must never be reaped by age.
        std::fs::create_dir(dir.join(".husk-slurm-spool-4242")).unwrap();
        let stale = BODY_RETAIN_MAX_AGE_SECS + 60;
        backdate(&dir.join(".husk-body-old.sh"), stale);
        backdate(&dir.join(".husk-step-spool-99"), stale);
        backdate(&dir.join(".husk-slurm-spool-4242"), stale);

        let report = prune_stale_bodies_capped(&dir, 10_000);

        // 22 directory entries + 1 unit for the body that gets removed. The stale step spool
        // is empty, so descending it costs nothing; a full one would charge per file (`RE-3`).
        assert_eq!(report.scanned, 23, "the fixture changed; fix the expected counts");
        // 5, not 4: `.husk-body-ghi.txt` carries the prefix and is stat'd even though
        // `bodies_to_prune` will then reject it for the suffix. That is the prefilter being
        // deliberately LOOSE — a prefix-only superset costs one stat here and cannot hide a
        // future `.husk-body-*.json` from a future reaper. What matters is 5 against 22.
        assert_eq!(
            report.aged, 5,
            "prune_stale_bodies read the modification time of {} of {} directory entries. It \
             must read only the ones whose NAME could reach a consumer: the 3 `.husk-body-` \
             entries and the 2 step spools here. One `metadata()` per entry is `B5-7` — \
             100,009 `statx` for a 100k-entry project dir, each one an MDS round trip on \
             Lustre.",
            report.aged, report.scanned
        );
        // ...and the behaviour is unchanged, which is the half that passes either way.
        assert_eq!(report.removed, 2, "the stale body and the stale step spool, and nothing else");
        assert!(!dir.join(".husk-body-old.sh").exists(), "the stale body must still be reclaimed");
        assert!(!dir.join(".husk-step-spool-99").exists(), "the stale step spool too");
        assert!(dir.join(".husk-body-new.sh").exists(), "a fresh body may still be queued on");
        assert!(dir.join(".husk-step-spool-100").exists(), "a fresh step spool is live");
        assert!(
            dir.join(".husk-slurm-spool-4242").is_dir(),
            "a SESSION spool is not a step spool, and age says nothing about whether a broker \
             is watching it"
        );
        assert!(dir.join(".husk-body-ghi.txt").exists() && dir.join("husk-body-jkl.sh").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `RE-9`. **An out-of-cage delete primitive, found by a reviewer, pre-existing, and inside
    /// the function this fix rewrites — so it is fixed in the same pass.**
    ///
    /// `DirEntry::metadata` is `lstat`, so the age gate reads the LINK's timestamp, which the
    /// agent sets with one `touch -h -d`. `std::fs::read_dir` then FOLLOWS. So
    /// `ln -s <anywhere> .husk-step-spool-4242`, in a directory the agent writes freely, made
    /// this broker — running OUTSIDE the cage with the user's full authority — walk the target
    /// and unlink every file matching husk's spool names, including under `$HOME`, which the
    /// agent cannot write itself. Measured on the pristine build: `owner`, `net.sock`,
    /// `req-1.json` and `err-7.log` deleted; only `keep.txt` survived.
    ///
    /// And it was SILENT: `remove_dir` on the symlink then fails, so `removed` stayed 0 and the
    /// "reclaimed stale step spool" line never printed.
    ///
    /// **FALSE FRIEND:** asserting that the symlink itself survives is green for the bug — the
    /// bug does not delete the link, it empties what the link points at. The load-bearing
    /// assertion is about the file OUTSIDE the project directory. (Same shape, and the same
    /// lesson, as `a_symlinked_claim_is_never_followed_out_of_the_spool` twenty lines up.)
    ///
    /// **MUTATION that turns it red:** drop the `O_NOFOLLOW` bit from `O_NOFOLLOW_DIRECTORY`,
    /// or put `std::fs::read_dir(&p)` back in place of `empty_stale_spool(&dir, …)`.
    ///
    /// **This test covers the DETERMINISTIC instance only**, and it was green on the
    /// check-then-use code that `RE-B` then broke: there the name is already a symlink when
    /// `symlink_metadata` looks. The raced instance — a real directory at check time, a symlink
    /// by use time — is
    /// `a_step_spool_swapped_for_a_symlink_after_it_is_opened_is_not_followed`, below.
    #[test]
    fn a_symlinked_step_spool_is_never_descended() {
        let dir = scratch("prune-symlink");
        let victim = scratch("prune-victim");
        for f in ["owner", "net.sock", "req-1.json", "err-7.log", "keep.txt"] {
            std::fs::write(victim.join(f), "IMPORTANT USER DATA").unwrap();
        }
        // What the agent can do: a husk-shaped NAME, aimed anywhere, backdated with `touch -h`.
        let link = dir.join(".husk-step-spool-4242");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let stale = std::time::SystemTime::now()
            - std::time::Duration::from_secs(BODY_RETAIN_MAX_AGE_SECS + 60);
        // `set_times` on a File follows the link, so backdate the LINK with `touch -h`, which is
        // exactly the primitive the agent has.
        let _ = std::process::Command::new("touch")
            .arg("-h")
            .arg("-d")
            .arg("2000-01-01")
            .arg(&link)
            .status();
        let _ = stale;

        let report = prune_stale_bodies_capped(&dir, 10_000);

        let survivors = {
            let mut v: Vec<String> = std::fs::read_dir(&victim)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            v.sort();
            v
        };
        assert_eq!(
            survivors,
            vec!["err-7.log", "keep.txt", "net.sock", "owner", "req-1.json"],
            "the broker followed a symlink out of an agent-writable directory and deleted inside \
             the target. It runs outside the cage, so that is an arbitrary-file delete with the \
             user's full authority (`RE-9`, `P2`)."
        );
        assert_eq!(report.removed, 0, "and nothing was reported as reclaimed either");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&victim);
    }

    /// `RE-B`, the constant. `O_NOFOLLOW`/`O_DIRECTORY` are per-architecture numbers and husk
    /// ships to two architectures, so the risk is not that the wrong value fails — it is that the
    /// wrong value SUCCEEDS, follows the link, and says nothing (`P7`). `0o400000` is
    /// `O_NOFOLLOW` on x86_64 and `O_LARGEFILE` on aarch64.
    ///
    /// A unit test on an x86_64 laptop cannot check the aarch64 number. What it can do is assert
    /// the EFFECT rather than the number, so that the first `cargo test` on Santis is where a
    /// wrong constant is reported — which is `P15` applied to a constant: check that the flag
    /// names the behaviour you meant, on the machine where it has to.
    ///
    /// **FALSE FRIEND:** asserting only that the symlink is refused is GREEN for a constant that
    /// refuses everything — which is what the x86_64 pair degrades to on aarch64, where it spells
    /// `O_LARGEFILE | O_DIRECT`. Both halves are load-bearing; a reaper that opens nothing is a
    /// reaper that silently stopped running.
    ///
    /// **MUTATION that turns it red:** delete the `named_directory` gate from
    /// `open_dir_nofollow`. The symlink is then opened (on an architecture where the flags are
    /// inert) or the refusal comes only from the kernel (where they are not), and
    /// `the_symlink_refusal_survives_open_flags_that_do_nothing_on_this_architecture` below is the
    /// half that stays red either way.
    #[test]
    fn a_symlink_is_refused_when_a_stale_step_spool_is_opened() {
        let dir = scratch("open-nofollow");
        let real = dir.join(".husk-step-spool-1");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(dir.join("plain.txt"), "x").unwrap();
        std::os::unix::fs::symlink(&real, dir.join(".husk-step-spool-2")).unwrap();

        assert!(
            open_dir_nofollow(&real).is_some(),
            "a real stale step spool must still open, or the reaper has quietly stopped \
             reclaiming anything at all — which a symlink-refused-only assertion would not notice"
        );
        assert!(
            open_dir_nofollow(&dir.join(".husk-step-spool-2")).is_none(),
            "a symlink to a directory was opened as a step spool. O_NOFOLLOW is not in effect \
             for this architecture, so every unlink below it lands wherever the agent aimed the \
             link, with the broker's out-of-cage authority (`RE-B`, `P7`)."
        );
        assert!(
            open_dir_nofollow(&dir.join("plain.txt")).is_none(),
            "a regular file was opened as a step spool: O_DIRECTORY is not in effect"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **The answer to "your effect test cannot catch it on an x86_64 laptop", and it was a fair
    /// challenge.** `O_NOFOLLOW`'s value differs on aarch64 (see `O_NOFOLLOW_DIRECTORY`), nobody
    /// building here can execute the aarch64 branch, and a review round was spent on whether the
    /// number is right. So the guard is built not to care: switch the open flags OFF completely —
    /// the state an inert constant leaves them in — and the refusal must still happen, for both
    /// the deterministic case and the raced one.
    ///
    /// The raced half is the load-bearing one and it does not race: it wins, by doing the swap
    /// between `named_directory` and `open_verified`, which is where a winning race lands. With
    /// `flags = 0` the `open` genuinely follows the symlink and lands on the victim; the only
    /// thing left is the `fstat` identity comparison, and that is the assertion.
    ///
    /// **FALSE FRIEND:** running only the deterministic half is green with the comparison deleted,
    /// because `named_directory`'s `lstat` refuses a symlink on its own. Only the raced half
    /// reaches the code this test exists for.
    ///
    /// **MUTATION that turns it red:** drop the `dev`/`ino` comparison from `open_verified` (keep
    /// `is_dir`, which is what a tidy-up would keep). The raced assertion fires; the deterministic
    /// one does not.
    #[test]
    fn the_symlink_refusal_survives_open_flags_that_do_nothing_on_this_architecture() {
        let dir = scratch("open-inert-flags");
        let victim = scratch("open-inert-victim");
        let real = dir.join(".husk-step-spool-1");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&victim, dir.join(".husk-step-spool-2")).unwrap();

        // Deterministic: the name is a symlink when husk looks, so it never reaches the open.
        assert!(named_directory(&real).is_some(), "a real directory must still be accepted");
        assert!(
            named_directory(&dir.join(".husk-step-spool-2")).is_none(),
            "a symlink to a directory was accepted as a step spool by name"
        );

        // Raced, with the flags doing NOTHING — the aarch64-with-the-wrong-constant world.
        let named = named_directory(&real).expect("a real directory must be accepted");
        std::fs::rename(&real, dir.join("moved-away")).unwrap();
        std::os::unix::fs::symlink(&victim, &real).unwrap();
        assert!(
            open_verified(&real, &named, 0).is_none(),
            "with the open flags inert, the swap was not detected: husk holds a descriptor on a \
             directory outside the project dir and is about to unlink husk-named files in it. \
             The flags are a request; the fstat comparison is what OBSERVES what was opened, and \
             it is the only part of this guard an x86_64 build can prove (`RE-B`, `P7`, `P15`)."
        );
        // And the same call is still ACCEPTING in the honest case, or the guard has just been
        // turned into a reaper that reclaims nothing.
        let moved = dir.join("moved-away");
        let named2 = named_directory(&moved).expect("the moved directory is still a directory");
        assert!(
            open_verified(&moved, &named2, 0).is_some(),
            "an unswapped directory must still open with inert flags, or this guard refuses \
             everything and the reaper has silently stopped running"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&victim);
    }

    /// The no-regression half of `RE-B`, and the reason the refusal does not `continue`.
    ///
    /// `open` needs read permission on the directory and `symlink_metadata` did not, so hardening
    /// the check narrows what the reaper can reclaim unless the `remove_dir` is attempted anyway.
    /// An empty, backdated, mode-000 `.husk-step-spool-N` is something the agent can mint by the
    /// thousand; before this fix each one was reclaimed, and a fix that quietly stopped reclaiming
    /// them would have added an agent-triggerable litter source while closing a delete primitive.
    ///
    /// **MUTATION that turns it red:** `let Some(dir) = open_dir_nofollow(&p) else { continue };`
    /// — the shape this test exists to reject. `removed` drops to 0 and the spool survives.
    #[test]
    fn an_empty_stale_spool_husk_cannot_read_is_still_reclaimed() {
        let dir = scratch("prune-unreadable");
        let spool = dir.join(".husk-step-spool-9");
        std::fs::create_dir(&spool).unwrap();
        std::fs::set_permissions(&spool, std::os::unix::fs::PermissionsExt::from_mode(0o000))
            .unwrap();
        let _ = std::process::Command::new("touch")
            .args(["-d", "2000-01-01"])
            .arg(&spool)
            .status();

        let report = prune_stale_bodies_capped(&dir, 10_000);

        assert!(
            !spool.exists(),
            "an empty stale step spool husk could not open was left behind. Hardening the \
             candidate check must not narrow what the reaper reclaims: the agent can mint these \
             by the thousand, and they would accumulate in the user's project directory forever \
             (`RE-B`, and the round's standing lesson about what a fix ADDS)."
        );
        assert_eq!(report.removed, 1, "and it must be reported as reclaimed, as it was before");
        let _ = std::fs::set_permissions(
            &spool,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `RE-B`. `RE-9` was closed with `symlink_metadata(&p)` followed by `read_dir(&p)` — a check
    /// and a use on the same NAME. This prune runs AFTER `signal_ready()`, so the agent is
    /// already launched and writing the project directory while it runs: swap a backdated real
    /// `.husk-step-spool-N` for a symlink between those two syscalls and the out-of-cage delete
    /// primitive is back, race-gated, with the broker's full user authority (`P15`, `P2`).
    ///
    /// **This test does not race — it WINS the race, deterministically**, by doing the swap in
    /// the one place a winning race would have to land: between the open and the descent. A test
    /// can stand in that place only because the descent now takes the HANDLE as an argument;
    /// while it took a path there was nowhere to stand, which is why the shipped suite could not
    /// see this.
    ///
    /// **FALSE FRIEND, and it is the test that already existed:**
    /// `a_symlinked_step_spool_is_never_descended` is green on the check-then-use code, because
    /// its name is a symlink at `lstat` time too. It covers the deterministic instance and is
    /// blind to the raced one — the same "the axis was invisible from inside the mutation set"
    /// shape as `RE-A`, one finding over (`P9`).
    ///
    /// **MUTATION that turns it red:** give the descent the caller's NAME back — add an
    /// `at: &Path` parameter to `empty_stale_spool`, `read_dir(at)`, and pass `&p` from the walk
    /// and `&spool` from here. That is the `608618e` shape refactored into this function, and it
    /// is the only way to express the bug once the signature takes a handle: **run, and the first
    /// assertion fires — the victim is emptied.** The type is doing the work, which is why the
    /// mutation has to change the type.
    ///
    /// **A MUTATION I EXPECTED TO WORK AND THAT DID NOT, recorded because it is the interesting
    /// one.** Replacing `open_dir_path(dir)` with
    /// `std::fs::read_link(format!("/proc/self/fd/{}", dir.as_raw_fd())).unwrap()` — the tidy
    /// refactor, "must this really be a `/proc` path?" — stays **green**. Measured: after the
    /// swap that link reads back as `…/moved-away`, because a procfs fd link names the CURRENT
    /// path of the inode the descriptor holds, not the name the caller opened. So that refactor
    /// is accidentally safe, and reporting it as the mutation would have been a false claim about
    /// a green run (`P12`).
    #[test]
    fn a_step_spool_swapped_for_a_symlink_after_it_is_opened_is_not_followed() {
        let dir = scratch("prune-toctou");
        let victim = scratch("prune-toctou-victim");
        for f in ["owner", "net.sock", "req-1.json", "err-7.log", "keep.txt"] {
            std::fs::write(victim.join(f), "IMPORTANT USER DATA").unwrap();
        }
        // A genuine stale step spool: this passes any check the broker cares to make.
        let spool = dir.join(".husk-step-spool-4242");
        std::fs::create_dir(&spool).unwrap();
        for f in ["owner", "req-1.json", "notes.txt"] {
            std::fs::write(spool.join(f), "husk").unwrap();
        }

        // The broker opens the candidate. THIS is the instant the race window used to open.
        let handle = open_dir_nofollow(&spool).expect("a real stale step spool must open");

        // The agent wins it. Both operations are ones it has: it writes this directory.
        let moved = dir.join("moved-away");
        std::fs::rename(&spool, &moved).unwrap();
        std::os::unix::fs::symlink(&victim, &spool).unwrap();

        // The broker descends. It must descend into what it OPENED, not into what the name says.
        let mut report = PruneReport::default();
        empty_stale_spool(&handle, 10_000, &mut report);

        let survivors = |d: &std::path::Path| {
            let mut v: Vec<String> = std::fs::read_dir(d)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            v.sort();
            v
        };
        assert_eq!(
            survivors(&victim),
            vec!["err-7.log", "keep.txt", "net.sock", "owner", "req-1.json"],
            "the descent followed the NAME instead of the handle, so a swap the agent performs \
             after the check emptied a directory outside the project dir. The broker runs \
             outside the cage, so that is an arbitrary-file delete with the user's full \
             authority (`RE-B`, `RE-9`, `P2`)."
        );
        // And the reaper still did its job on the directory it actually holds — otherwise
        // "nothing was deleted anywhere" would pass this test with the reaper switched off.
        assert_eq!(
            survivors(&moved),
            vec!["notes.txt"],
            "the spool that WAS opened must still be emptied of husk's own artifacts, and of \
             nothing else"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&victim);
    }

    /// `RE-3`. The cap bounded the top-level walk and nothing else, so the expensive half — one
    /// `read_dir` plus one `remove_file` per husk-named file INSIDE every stale step spool — ran
    /// uncapped. Measured on the pristine build: 300 stale spools of 300 files each is
    /// `scanned = 300`, nowhere near the cap, and 90,000 unlinks. Since this now runs after
    /// `signal_ready`, that stall is not a slow start: it is an agent already launched against a
    /// broker that has not begun serving, i.e. `timed out after 120s` on every `sbatch`.
    ///
    /// **Who can trigger it:** the agent. It writes the project directory and can backdate.
    ///
    /// **MUTATION that turns it red:** remove the `report.scanned >= cap` break from the INNER
    /// loop. `scanned` stays at 3 and every one of the inner files is unlinked.
    #[test]
    fn the_inside_of_a_stale_spool_spends_the_same_budget() {
        let dir = scratch("prune-inner");
        for n in 0..3 {
            let sp = dir.join(format!(".husk-step-spool-{n}"));
            std::fs::create_dir(&sp).unwrap();
            for i in 0..20 {
                std::fs::write(sp.join(format!("req-{i}.json")), "{}").unwrap();
            }
            let _ = std::process::Command::new("touch")
                .arg("-d")
                .arg("2000-01-01")
                .arg(&sp)
                .status();
        }
        let report = prune_stale_bodies_capped(&dir, 8);
        assert!(
            report.scanned <= 8,
            "the pass spent {} units against a cap of 8 — the walk inside a stale spool must be \
             charged to the same budget, or 20,000 spools of 300 files each is 6,000,000 \
             unlinks behind a `scanned` that never reaches the cap (`RE-3`)",
            report.scanned
        );
        assert!(report.truncated, "and it must know it stopped early");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `P8`, and the reason the prefilter is safe: it is asserted against the two functions it
    /// is a prefilter FOR, not against my reading of them. Anything they would reclaim must
    /// survive `needs_its_age_read`, or the prefilter has silently switched a reaper off.
    ///
    /// **MUTATION that turns it red:** drop `STEP_SPOOL_PREFIX` from `PRUNABLE_PREFIXES`, or
    /// mistype the body prefix as `.husk_body-`. Either way a name `spools_to_prune` /
    /// `bodies_to_prune` selects stops being stat'd, and the loop below catches it.
    #[test]
    fn the_prefilter_hides_nothing_the_two_reapers_would_reclaim() {
        let old = BODY_RETAIN_MAX_AGE_SECS + 1;
        // Every name lib.rs's own two prune tests use, plus the neighbours that make the
        // prefixes ambiguous.
        for name in [
            ".husk-body-abc.sh", ".husk-body-def.sh", ".husk-body-.sh", ".husk-body-x.sh.sh",
            ".husk-body-ghi.txt", "husk-body-jkl.sh", ".husk-body", ".husk-bodyx.sh",
            ".husk-step-spool-1", ".husk-step-spool-123456", ".husk-step-spool-",
            ".husk-step-spool", "husk-step-spool-1", ".husk-slurm-spool-4242",
            "Cargo.toml", "", ".", "..", ".git", "src", "\u{1f600}.sh", ".husk-BODY-x.sh",
        ] {
            let probe = [(name.to_string(), old)];
            let reclaimed = !bodies_to_prune(&probe, BODY_RETAIN_MAX_AGE_SECS).is_empty()
                || !spools_to_prune(&probe, BODY_RETAIN_MAX_AGE_SECS).is_empty();
            assert!(
                !reclaimed || needs_its_age_read(name),
                "{name:?} is reclaimed by one of the two pruners but the prefilter would skip \
                 reading its age, so it can never reach them. The prefilter must be a SUPERSET \
                 of what they select (`P8`)."
            );
        }
    }

    /// The walk is capped, the cap is not a launch failure, and hitting it says so.
    ///
    /// The cap exists because `read_dir` itself is unbounded even with the stats removed, and
    /// because the credential auto-scan four lines away in the same startup path has had one —
    /// and a warning — since it shipped. `C4`: the hazard was recognised and the bound was
    /// applied to one of the two walks.
    ///
    /// **Who can trigger it:** the agent, on the NEXT session — it writes freely in the project
    /// directory. That is why hitting the cap must not be, and is not, a refusal to start:
    /// it stops the reaper early, prints one line, and the session runs.
    ///
    /// **MUTATION that turns it red:** remove the `report.scanned >= cap` break.
    #[test]
    fn a_project_directory_too_large_to_walk_stops_the_walk_not_the_session() {
        let dir = scratch("prune-cap");
        for i in 0..40 {
            std::fs::write(dir.join(format!("f{i}.txt")), "x").unwrap();
        }
        let report = prune_stale_bodies_capped(&dir, 7);
        assert_eq!(report.scanned, 7, "the walk must stop AT the cap, not after the directory");
        assert!(report.truncated, "and it must know that it stopped early, so it can say so");

        // The exact-fit case must not report a truncation that did not happen.
        let small = scratch("prune-cap-fit");
        for i in 0..7 {
            std::fs::write(small.join(format!("f{i}.txt")), "x").unwrap();
        }
        let exact = prune_stale_bodies_capped(&small, 7);
        assert_eq!(exact.scanned, 7);
        assert!(!exact.truncated, "a directory that exactly fits the cap was not truncated");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&small);
    }

    /// `P11`, and the coupling is across two binaries. `broker_refusal_reason` in the wrapper
    /// relays only lines starting `husk:` or `broker:`; a startup announcement it drops is
    /// attribution nobody ever reads. `settings.rs`'s own cap warning is prefixed
    /// `husk-broker:` and IS dropped today, which is what makes this worth pinning rather than
    /// assuming.
    ///
    /// **MUTATION that turns it red:** change `startup_line` to `format!("startup: {step}")` or
    /// to `husk-broker: …`. Both read as harmless and both delete the attribution.
    #[test]
    fn a_startup_announcement_survives_the_wrappers_refusal_relay() {
        let line = startup_line("claiming the spool /x/.husk-slurm-spool-1");
        assert!(
            line.starts_with("broker:") || line.starts_with("husk:"),
            "the wrapper relays only lines starting `husk:` or `broker:`; {line:?} would be \
             filtered out of the refusal an operator reads at the 15s deadline"
        );
        assert!(line.contains("claiming the spool"), "and it must carry the step");
        assert!(!line.contains('\n'), "one line, or the relay's six-line tail holds fewer steps");
    }

    /// CODE ONLY: comment lines stripped, for both lexical tests and for the same reason
    /// (`RE-12`). A lexical assertion that reads prose is satisfied — or, as happened while this
    /// fix was being written, VIOLATED — by a comment that names the very call it is banning:
    /// the walk's own history note says `symlink_metadata` and `read_dir(&p)`, which is exactly
    /// what must never again be CALLED there. Shared rather than written twice, so the two
    /// cannot drift (`P8`).
    fn code_only(src: &str) -> String {
        src.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The rule for the pre-readiness window, pinned lexically because there is nothing else
    /// that can pin it: `main.rs` has no harness that runs `main`.
    ///
    /// Only work whose failure must PREVENT the launch belongs between `LAUNCH-BUDGET WINDOW:
    /// START` and `signal_ready()`. The two unbounded steps `B2-2` and `B5-7` found were both
    /// in there and both are best-effort, so both moved below. This test is what stops them
    /// drifting back — the drift is one line of movement and it reads as harmless.
    ///
    /// It fails SAFE: delete the markers from `main` and the only remaining occurrences are the
    /// literals below, whose span contains the banned names, so the assertion fires anyway.
    ///
    /// **MUTATIONS that turn it red:** move `prune_stale_bodies(&project_dir);` or
    /// `session.with_partition_limits()` back above `signal_ready()`; or move `signal_ready()`
    /// itself above `settings::FsPolicy::resolve` while leaving both inside the markers.
    /// Only the CODE in the window is examined; comment lines are stripped first.
    ///
    /// **Both halves of this test were false friends, and a reviewer broke both** (`RE-11`,
    /// `RE-12`). The ban list was `"prune_stale_bodies("` and `"with_partition_limits("`, so
    /// moving the calls back in through the aliases this very patch created —
    /// `prune_stale_bodies_capped(` and `with_partition_limits_within(` — was **green**. And the
    /// required list was matched by the window's own header COMMENT, so `FsPolicy::resolve`
    /// could be moved below the readiness byte — the literal 2026-08-06 configuration — and the
    /// test stayed **green**. Stripping comments and banning the base names fixes both: prose
    /// may say anything, and no spelling of a call slips through.
    ///
    /// **And a third time, on the axis the first two fixes did not have (`RE-A`).** Both of those
    /// repairs made the test ask *is this call in the window*. Neither made it ask *is it before
    /// the byte*. So `signal_ready()` could be lifted above `FsPolicy::resolve` — both still
    /// inside the markers, the literal 2026-08-06 configuration this docstring says the test
    /// prevents — and it stayed **green**; the rebuilt binary announced readiness at 0.001 s and
    /// then `exit(2)`ed on a broken `.claude/settings.json`. The author's own mutations could not
    /// find it because every one of them moved a best-effort CALL and none moved the READINESS
    /// BYTE, so the ordering axis was not merely unchecked, it was structurally invisible from
    /// inside the mutation set (`P9`). Membership is now checked with `find`, and the indices are
    /// compared.
    ///
    /// **What this test still cannot see (`P10` — write down what the harness substitutes).**
    ///
    /// 1. **Depth.** It reads calls written literally in `main`'s window and nothing inside them.
    ///    Unbounded best-effort work added to `claim_spool`, `Session::from_env_and_config` or
    ///    `FsPolicy::resolve` is invisible here, and that is not hypothetical: `B2-2` arrived
    ///    exactly that way, as an `scontrol` one level down inside `with_partition_limits`. The
    ///    ban list is a denylist of two names at one level (`P5`).
    /// 2. **Duration.** Order is not a bound. This says the fail-closed steps run before the
    ///    byte, never that they FINISH — `RE-1` is a FIFO at the agent-writable
    ///    `.claude/settings.local.json` that blocks inside `FsPolicy::resolve`, in-window, for
    ///    the wrapper's whole fifteen seconds. Passing this test is consistent with a launch that
    ///    is refused every time.
    /// 3. **Execution.** Lexical order is not run order. An early `return`, a `?`, a branch, a
    ///    thread, or a `signal_ready()` moved behind a helper would satisfy every assertion here.
    ///    It is lexical because `main.rs` has no harness that runs `main` (`P10`); the thing that
    ///    actually observes the ordering is driving the built binary against a broken
    ///    `settings.json` and watching for `exit(2)` before the byte, which is a review step, not
    ///    a test.
    fn window_code() -> String {
        let src = include_str!("main.rs");
        let start = src.find("// ---- LAUNCH-BUDGET WINDOW: START").expect("window start marker");
        // Deliberately BETWEEN the two `find`s, so that deleting the markers from `main` leaves
        // a "window" that is this test's own source — which contains the banned names, so the
        // assertion fires rather than vacuously passing.
        let banned_probe = ["prune_stale_bodies", "with_partition_limits"];
        let end = src.find("// ---- LAUNCH-BUDGET WINDOW: END").expect("window end marker");
        assert!(start < end, "the window markers are out of order");
        let _ = banned_probe;
        code_only(&src[start..end])
    }

    #[test]
    fn nothing_best_effort_runs_inside_the_launch_budget_window() {
        let window = window_code();
        // The BASE names, so every spelling of the call is caught — including the `_capped` and
        // `_within` aliases, which is the hole a reviewer walked through.
        for name in ["prune_stale_bodies", "with_partition_limits"] {
            assert!(
                !window.contains(name),
                "{name} is called inside the launch-budget window again. Everything in there is \
                 spent out of the wrapper's 15s BROKER_READY_TIMEOUT, and both are best-effort: \
                 the partition-limits query buys one advisory sentence and cost 16.007s on two \
                 partitions with an 8s scontrol (`B2-2`); the reaper is hygiene and cost one \
                 `statx` per project-dir entry (`B5-7`). Neither may refuse a launch."
            );
        }
        // MEMBERSHIP IS NOT ORDER, and the gap between them is the whole incident (`RE-A`).
        // Everything below this line asserts an INDEX, not a `contains`.
        let ready = window
            .find("signal_ready();")
            .expect("the window must end at the readiness byte, and it is not called at all");
        assert_eq!(
            window.matches("signal_ready(").count(),
            1,
            "the readiness byte is written from more than one place inside the window. The \
             `ends_with` check below would then be satisfied by the LAST of them while an \
             earlier one has already told the wrapper to launch the agent."
        );
        // The fail-closed steps must stay inside the window AND run BEFORE the byte, matched as
        // CALLS. Announcing readiness before the settings parse is the 2026-08-06 incident,
        // arriving from the other side.
        for required in [
            "Session::from_env_and_config(&home)",
            "settings::FsPolicy::resolve(&home, &project_dir)",
            "claim_spool(&spool, &project_dir)",
        ] {
            let at = window.find(required).unwrap_or_else(|| {
                panic!(
                    "{required} left the launch-budget window. It is fail-closed — it exits(2) \
                     — so the readiness byte must not be written before it has passed, or the \
                     wrapper launches an agent whose every sbatch will time out at 120s \
                     (2026-08-06)."
                )
            });
            assert!(
                at < ready,
                "{required} is inside the launch-budget window but AFTER signal_ready(). That \
                 is the 2026-08-06 configuration exactly: the wrapper is told the broker is \
                 ready, execs the agent, and the broker then exit(2)s on a file it could not \
                 read — measured, readiness at 0.001s and every sbatch timing out at 120s with \
                 the reason in a log nobody reads. Membership in the window is not the contract; \
                 running before the byte is (`RE-A`)."
            );
        }
        // ...and nothing may be appended after it, which is the cheaper statement of the same
        // rule and catches a fourth step arriving that nobody thought to name above.
        assert!(
            window.trim_end().ends_with("signal_ready();"),
            "signal_ready() is no longer the last statement in the launch-budget window. \
             Whatever now follows it runs with the agent already launched but the broker not \
             yet serving, and if it can fail it can fail AFTER the promise was made (`RE-A`)."
        );
    }

    /// The two seams the window test cannot see, because they are outside it (`RE-14`, `RE-15`).
    ///
    /// A cap only bounds the walk if the production entry point passes it, and an announcement
    /// only reaches the operator if the production path goes through the function whose prefix
    /// was tested. Both were unasserted: `prune_stale_bodies` could pass `usize::MAX`, and
    /// `starting` could `eprintln!` its own string, each leaving its test green.
    #[test]
    fn the_production_entry_points_use_the_bound_and_the_wording_that_were_tested() {
        let src = include_str!("main.rs");
        // THE BODY OF THE FUNCTION, not the file. Searching the whole file is satisfied by this
        // test's own source — which is `RE-12` again, committed inside the fix for `RE-14`, and
        // caught only because the mutation was run. A lexical assertion must be scoped to the
        // code it is about or it asserts nothing.
        let reaper = src
            .split("fn prune_stale_bodies(project_dir: &std::path::Path) {")
            .nth(1)
            .and_then(|t| t.split("\n}").next())
            .expect("fn prune_stale_bodies must exist");
        assert!(
            reaper.contains("PRUNE_SCAN_MAX_ENTRIES"),
            "the production reaper must pass the constant the cap test exercises, or the cap is \
             tested and not applied: {reaper:?}"
        );
        // ONE STAT CALL SITE IN THE WALK, and it is the one that counts itself (`RE-13`).
        // `report.aged` is a self-reported counter, so welding it to `age_of` stops the natural
        // refactor from hiding a stat but not a deliberate one: `let _ = e.metadata();` above
        // the name guard restores one `statx` per entry and leaves `aged` unchanged — I ran it,
        // and the test was green. There is no syscall counter available to a unit test, so the
        // property is carried lexically instead: the walk may not stat at all, and `age_of` may
        // stat exactly once. (The candidate check is `open_dir_nofollow`, not a `.metadata(`
        // call, so it does not collide with this — see the handle assertions below.)
        let walk = code_only(
            src.split("fn prune_stale_bodies_capped(")
                .nth(1)
                .and_then(|t| t.split("\n}").next())
                .expect("fn prune_stale_bodies_capped must exist"),
        );
        assert!(
            !walk.contains(".metadata("),
            "the walk stats an entry outside `age_of`, so that stat is not counted and \
             `the_age_of_an_entry_husk_will_never_touch_is_never_read` cannot see it (`RE-13`)"
        );
        // AND THE PRODUCTION WALK MUST DESCEND THROUGH THE HANDLE (`RE-B`, and `RE-14`'s lesson
        // applied to the seam this fix creates). `empty_stale_spool` cannot be handed a path —
        // its type forbids it — but the walk could stop calling it, or grow a second descent
        // beside it, and the TOCTOU test would stay green because it drives the helper directly.
        // That is exactly the gap `RE-14` found: the helper was tested, the call site was not.
        // ...and the production opener passes the CONSTANT, not whatever a test passed. Same
        // shape, same reason, as the `PRUNE_SCAN_MAX_ENTRIES` assertion above (`RE-14`): the
        // `flags` parameter exists for a test, so nothing but a lexical check stops production
        // from inheriting a test's value.
        let opener = code_only(
            src.split("fn open_dir_nofollow(p: &std::path::Path) -> Option<std::fs::File> {")
                .nth(1)
                .and_then(|t| t.split("\n}").next())
                .expect("fn open_dir_nofollow must exist"),
        );
        assert!(
            opener.contains("named_directory(p)") && opener.contains("O_NOFOLLOW_DIRECTORY"),
            "the production opener must gate on `named_directory` AND pass the architecture \
             constant. Dropping either leaves both halves of the guard tested and one of them \
             unused (`RE-14`): {opener:?}"
        );
        assert!(
            walk.contains("open_dir_nofollow(&p)") && walk.contains("empty_stale_spool("),
            "the stale-spool descent no longer goes through the opened handle, so \
             `a_step_spool_swapped_for_a_symlink_after_it_is_opened_is_not_followed` is now \
             testing a helper the broker does not use (`RE-B`, `RE-14`): {walk:?}"
        );
        assert!(
            !walk.contains("read_dir(&p)") && !walk.contains("symlink_metadata"),
            "the walk resolves the candidate spool by NAME again. Check-then-use on a path in a \
             directory the agent writes is the raced out-of-cage delete, whatever check precedes \
             it (`RE-B`, `P15`)."
        );
        let age_of = src
            .split("fn age_of(e: &std::fs::DirEntry, report: &mut PruneReport) -> u64 {")
            .nth(1)
            .and_then(|t| t.split("\n}").next())
            .expect("fn age_of must exist");
        assert_eq!(
            age_of.matches(".metadata(").count(),
            1,
            "`age_of` must make exactly one stat per call, or the counter and the syscall have \
             come apart again"
        );
        let starting = src
            .split("fn starting(step: &str) {")
            .nth(1)
            .and_then(|t| t.split("\n}").next())
            .expect("fn starting must exist");
        assert!(
            starting.contains("startup_line(step)"),
            "`starting` must emit `startup_line`, or the relay-prefix test is testing a string \
             the broker never prints: {starting:?}"
        );
    }

    /// `RC2-3`: the broker runs OUTSIDE the cage and writes into a directory the CAGED agent
    /// must be able to write. `fs::write` follows symlinks, so `ln -s <anything> <spool>/owner`
    /// made this process truncate that file and stamp `pid=…` over it. Measured on a pristine
    /// build — `IMPORTANT USER DATA` became `pid=12` — and it reproduced through `--once`
    /// against the *fixed* wrapper, because the wrapper-side unlink that hid it was a patch at
    /// the call site and this is the sink.
    ///
    /// FALSE FRIEND: a test that checks `owner` holds the right bytes afterwards is GREEN for
    /// `fs::write` — the claim really is written, into the victim. The load-bearing assertion is
    /// about the file OUTSIDE the spool.
    #[test]
    fn a_symlinked_claim_is_never_followed_out_of_the_spool() {
        let dir = std::env::temp_dir().join(format!("husk-claimsink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let owner = dir.join("owner");
        let victim = dir.join("victim.txt");
        let body = "pid=4242\nproject=/p\n";

        // (1) A fresh spool: the ordinary path still works.
        assert!(write_claim(&owner, body), "a claim must be recordable in a clean spool");
        assert_eq!(std::fs::read_to_string(&owner).unwrap(), body);

        // (2) A dead session's leftover claim is still overwritten — this function is only
        //     reached once the caller has established that nothing LIVE owns the spool, and
        //     failing here would leak a spool on every recycled directory.
        std::fs::write(&owner, "pid=999999\n").unwrap();
        assert!(write_claim(&owner, body), "a claim this broker may overwrite must be overwritten");
        assert_eq!(std::fs::read_to_string(&owner).unwrap(), body);

        // (3) THE PRIMITIVE. `owner` aimed at a file outside the spool.
        std::fs::write(&victim, "IMPORTANT USER DATA").unwrap();
        std::fs::remove_file(&owner).unwrap();
        std::os::unix::fs::symlink(&victim, &owner).unwrap();
        write_claim(&owner, body);
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "IMPORTANT USER DATA",
            "the broker followed a symlink out of an agent-writable directory and truncated the \
             target. It runs outside the cage, so that is an arbitrary-file write with the \
             user's full authority (`RC2-3`, `P2`)."
        );

        // (4) A DIRECTORY named `owner` must not make this a refusal. `create_new` fails, the
        //     claim is not recorded, and the broker goes on serving as a guest — the caller
        //     turns this `false` into "do not delete the spool on the way out", never into a
        //     denial. Refusing here would be `RC-4`, from one `mkdir` inside the cage.
        let _ = std::fs::remove_file(&owner);
        std::fs::create_dir(&owner).unwrap();
        assert!(!write_claim(&owner, body), "an unwritable claim is a `false`, not a panic");
        assert!(owner.is_dir(), "and nothing was deleted to make room for it");

        // (5) THE CASE THAT DISTINGUISHES THE SINK FIX FROM A CALL-SITE PATCH, and the reason
        //     an `unlink` first is not the answer. Make the removal impossible — here a spool
        //     the user has made read-only, and in the general case another uid's file or a
        //     re-plant between the unlink and the open — and `fs::write` STILL follows the
        //     symlink out, because the target is not in the read-only directory. `create_new`
        //     is `O_CREAT|O_EXCL`, which POSIX requires to fail on an existing symlink rather
        //     than resolve it, so it refuses without ever looking at the target.
        //
        //     FALSE FRIEND: case (3) above passes for `remove_file` + `fs::write`, because the
        //     unlink usually succeeds. This one does not.
        use std::os::unix::fs::PermissionsExt;
        let ro = dir.join("ro");
        std::fs::create_dir(&ro).unwrap();
        let victim2 = dir.join("victim2.txt");
        std::fs::write(&victim2, "IMPORTANT USER DATA").unwrap();
        std::os::unix::fs::symlink(&victim2, ro.join("owner")).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
        write_claim(&ro.join("owner"), body);
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            std::fs::read_to_string(&victim2).unwrap(),
            "IMPORTANT USER DATA",
            "the claim was written THROUGH the symlink when it could not be unlinked first. \
             Unlinking is housekeeping; not resolving the link is the control (`RC2-3`)."
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
