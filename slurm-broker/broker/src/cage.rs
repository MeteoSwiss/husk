//! The node cage's shared user namespace: creating it, holding it, naming it.
//!
//! **The security border is the job on a node, not the process.** All ranks of one MPI
//! job are a single trust domain — same uid, allocation, files, data — so the wall goes
//! around the job, not around each rank. See THREAT-MODEL.md, "the unit of confinement".
//!
//! # What is shared, and why it is exactly one namespace
//!
//! Only the **user namespace**. Every rank still builds its own mount and network
//! namespace with `bwrap`, exactly as before.
//!
//! That is not a compromise, it is the whole finding. The user namespace is the *only* one
//! that was costing us anything: sibling user namespaces cannot `ptrace_may_access` each
//! other, so Cray MPICH's Cross Memory Attach died with `EPERM` no matter what the seccomp
//! filter permitted. Measured 2026-07-31 — two ranks sharing this namespace read each
//! other's memory, the same two ranks in their own namespaces get `EPERM`, which is ICON's
//! exact failure. Per-rank mount and network namespaces are identical copies built from
//! identical arguments; they never blocked a capability, so duplicating them costs nothing.
//!
//! # Why ranks join with `bwrap --userns` rather than `setns`
//!
//! An earlier draft had each rank `setns` into a cage `bwrap` had built. That cannot work:
//! **`bwrap` constructs its sandbox through an intermediate user namespace and then
//! switches to a second one**, so the mount and network namespaces it creates are owned by
//! a user namespace no rank ever joins, and `setns` into them fails `EPERM` however it is
//! ordered (measured: holder userns `…4687`, initial `…1837`, holder netns owned by
//! `…4599`). `bwrap` is not built to be joined from outside.
//!
//! So the holder owns a **bare** user namespace — no mounts, no network, nothing that can
//! be joined incorrectly — and each rank hands it to its own `bwrap` with `--userns`. That
//! also keeps fail-closed behaviour for free: `bwrap` either joins the namespace or exits
//! loudly, so no rank silently runs uncaged.
//!
//! # Consequence for the network phase
//!
//! Ranks keep separate network namespaces, so the *relay* into a cage is per rank. The
//! filtering proxy — allowlist, TLS termination, the audit point — stays **one per node**,
//! reached through a unix socket bind-mounted into every rank's cage. A unix socket
//! crosses a network namespace because it is a filesystem object: the same reasoning that
//! makes the MUNGE *mount* mask load-bearing rather than a syscall filter. Policy is never
//! duplicated; only a byte-shuffler is.

use std::io::Write;

/// SIGCHLD, and the disposition that makes the kernel reap children for us. Both are
/// stable across x86_64 and aarch64, the two architectures husk runs on.
const SIGCHLD: std::os::raw::c_int = 17;
const SIG_IGN: usize = 1;

const CLONE_NEWUSER: std::os::raw::c_int = 0x1000_0000;
const CLONE_NEWPID: std::os::raw::c_int = 0x2000_0000;

const PR_SET_PDEATHSIG: std::os::raw::c_int = 1;
/// SIGKILL, not SIGTERM, and that is a kernel rule rather than bluntness.
///
/// A PID namespace's init ignores every signal it has not installed a handler for — the
/// protection that stops a rank killing the holder from inside. It applies to ANCESTOR
/// namespaces too, with SIGKILL and SIGSTOP the only exceptions. So a PDEATHSIG of SIGTERM
/// is silently discarded and the holder outlives its parent anyway (measured 2026-08-02:
/// both the clean and the SIGKILL path still leaked with SIGTERM). This process holds no
/// state and has nothing to flush, so SIGKILL costs nothing.
const SIGKILL: std::os::raw::c_ulong = 9;

extern "C" {
    fn unshare(flags: std::os::raw::c_int) -> std::os::raw::c_int;
    fn prctl(
        option: std::os::raw::c_int,
        arg2: std::os::raw::c_ulong,
        arg3: std::os::raw::c_ulong,
        arg4: std::os::raw::c_ulong,
        arg5: std::os::raw::c_ulong,
    ) -> std::os::raw::c_int;
    #[link_name = "getppid"]
    fn libc_getppid() -> std::os::raw::c_int;
    #[link_name = "getuid"]
    fn libc_getuid() -> u32;
    #[link_name = "getgid"]
    fn libc_getgid() -> u32;
    #[link_name = "fork"]
    fn libc_fork() -> i32;
    #[link_name = "pause"]
    fn libc_pause() -> std::os::raw::c_int;
    // Declared with `usize` rather than a function-pointer type because SIG_IGN is not a
    // function: it is the sentinel 1. One declaration for the whole crate — two `extern`
    // blocks naming the same symbol with different signatures is undefined behaviour
    // waiting for a mismatched call, and the compiler says so.
    #[link_name = "signal"]
    pub fn libc_signal(sig: std::os::raw::c_int, handler: usize) -> usize;
}

/// The path a rank passes to `bwrap --pidns`.
///
/// Deliberately the SAME pid as `userns_path`: the holder's PID-1 child inherits the user
/// namespace and is the first member of the PID namespace, so one number names both. A
/// second reported pid would be a second thing to keep in step.
pub fn pidns_path(pid: u32) -> String {
    format!("/proc/{pid}/ns/pid")
}

/// The path a rank passes to `bwrap --userns`, given the holder's pid.
///
/// The holder is left **dumpable**, unlike the broker, which does call `refuse_to_be_read`.
///
/// Reading `/proc/<pid>/ns/*` goes through `ptrace_may_access`, so clearing the flag is a
/// plausible way to lose the join — but that is reasoning, not the measurement. Measured on
/// kernel 6.8, a non-dumpable holder is still openable and joinable via `bwrap --userns`.
/// The flag stays set anyway, because the failure mode is what matters: if a kernel *does*
/// enforce it, every rank of every step fails to build its cage. That is fail-closed on the
/// MPI path, in exchange for a third layer on a process that is already unreadable and holds
/// nothing. Not a cheap win. Measure on the target kernel before trading it.
pub fn userns_path(pid: u32) -> String {
    format!("/proc/{pid}/ns/user")
}

/// The identity uid/gid map for this user, as written into a fresh user namespace.
///
/// Separated from the syscall path so the one rule that must never regress is testable:
/// **it is an identity map, never a root map.** `0 <uid> 1` would give `EUID == 0` inside
/// the namespace, which flips the agent runtime into its `--cap-drop ALL` branch; that
/// empties the bounding set, so applying seccomp can no longer write `uid_map`, and every
/// caged command dies. That bug cost a day once.
pub fn identity_map(id: u32) -> String {
    format!("{id} {id} 1")
}

/// Create a user namespace and map this user into it identity-wise.
///
/// `setgroups` must be denied before `gid_map` can be written by an unprivileged process.
/// That is a kernel rule, not a preference.
pub fn create_shared_userns() -> Result<(), String> {
    // Read the ids BEFORE unsharing. Inside a fresh user namespace, and until a map has
    // been written, the process has no valid mapping and reads back as the overflow uid
    // (65534/nobody) — so capturing them afterwards writes `65534 65534 1`, which the
    // kernel rejects with EPERM because it is not this user's id. Ordering bug, found on
    // the first run; the ids we want are the ones we had outside.
    // SAFETY: neither call takes arguments and neither can fail.
    let (uid, gid) = unsafe { (libc_getuid(), libc_getgid()) };

    // SAFETY: a constant CLONE_NEW* flag; this process is single-threaded here.
    if unsafe { unshare(CLONE_NEWUSER) } != 0 {
        return Err(format!(
            "could not create the job's shared user namespace: {}. Unprivileged user \
             namespaces may be disabled on this node.",
            std::io::Error::last_os_error()
        ));
    }

    write_proc_self("setgroups", "deny")?;
    write_proc_self("uid_map", &identity_map(uid))?;
    write_proc_self("gid_map", &identity_map(gid))?;
    Ok(())
}

/// Add a PID namespace to the job cage and return the pid that names it.
///
/// Call AFTER `create_shared_userns`, and the order is a kernel rule rather than taste:
/// creating a PID namespace needs `CAP_SYS_ADMIN`, which an unprivileged process only has
/// inside a user namespace it owns. Reversed, this fails with `EPERM`.
///
/// `unshare(CLONE_NEWPID)` does NOT move the caller — it takes effect for its *children*.
/// So this forks, and the child is PID 1 of the new namespace. That child must then stay
/// alive for the whole job: **a PID namespace dies with its PID 1, taking every process in
/// it along.** It also reaps orphans, which is PID 1's other job.
///
/// The returned pid is the CHILD's, host-side, and it names BOTH namespaces: the child
/// inherited the user namespace, so `/proc/<pid>/ns/user` and `/proc/<pid>/ns/pid` are the
/// two a rank needs. One number, one thing to keep in step.
///
/// What this buys, measured: two ranks joining it are pid 2 and pid 3, they can see each
/// other — which is what Cross Memory Attach needs — and the un-caged step-broker is not
/// in their `/proc` at all. Isolation and MPI at once, which per-rank `--unshare-pid`
/// cannot give (each rank would land in its own namespace, unable to name its peers — the
/// sibling-user-namespace failure that killed ICON, one layer down).
pub fn create_shared_pidns() -> Result<u32, String> {
    // SAFETY: a constant CLONE_NEW* flag; this process is single-threaded here.
    if unsafe { unshare(CLONE_NEWPID) } != 0 {
        return Err(format!(
            "could not create the job's shared PID namespace: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fork in a single-threaded process. The child touches only async-signal-safe
    // calls (`pause`) before it would exit.
    let pid = unsafe { libc_fork() };
    match pid {
        -1 => Err(format!(
            "could not fork the PID-namespace holder: {}",
            std::io::Error::last_os_error()
        )),
        0 => {
            // PID 1 of the new namespace, and the process that actually HOLDS both
            // namespaces — so it needs its own way to die.
            //
            // The parent has two shutdown paths (stdin EOF, PDEATHSIG) precisely so a
            // namespace is never leaked per job. That intent used to stop at the parent:
            // this child had neither, and the parent exited without killing it, so the
            // process holding the namespaces was orphaned on EVERY job (measured
            // 2026-08-02: ppid reparented to 1 while the child ran on). SLURM's cgroup
            // teardown reaps it in practice, which is why nothing broke — but relying on
            // that silently is not the same as saying so, and a proctrack plugin that is
            // not cgroup-based would leak a namespace per job on a node that reboots
            // rarely.
            //
            // So: PDEATHSIG here as well. Belt to the parent's braces, the same pairing
            // the step-broker already uses.
            // SAFETY: PR_SET_PDEATHSIG with a signal number; extra args are ignored.
            unsafe { prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) };
            // The parent may already have died between fork and prctl, in which case the
            // signal will never arrive.
            // SAFETY: getppid takes no arguments and cannot fail.
            if unsafe { libc_getppid() } == 1 {
                std::process::exit(0);
            }
            // Sleep forever. `pause` rather than a sleep loop so it consumes nothing.
            //
            // Reap by disposition, not by loop.
            //
            // The note that used to sit here said orphaned ranks reparent to this PID 1 and
            // their zombies "accumulate for the job's lifetime. Harmless — the namespace and
            // every zombie in it are destroyed when the job ends". The first half is right
            // and the second is not: a zombie in a PID namespace still holds a pid in the
            // NODE-GLOBAL space it was allocated from, shared with every other user on that
            // node. The review measured 30 orphans producing 30 host-visible zombies. That
            // is the one place a rank reaches past its own job.
            //
            // The rejected fix was a wait loop, and rejecting it was right — a subtly wrong
            // one is worse than none. This is not that: POSIX says a SIGCHLD disposition of
            // SIG_IGN makes children be reaped automatically and never become zombies, so
            // the kernel does it and there is no loop to get wrong. `pause` still returns
            // only on a signal, and PID 1 still ignores everything it has no handler for,
            // so `kill -9 1` from inside the namespace remains ineffective.
            //
            // SIGCHLD is 17 on both architectures husk targets (x86_64, aarch64).
            // SAFETY: signal() with a valid signal number and SIG_IGN.
            unsafe { libc_signal(SIGCHLD, SIG_IGN) };
            loop {
                // SAFETY: pause takes no arguments and only returns on a signal.
                unsafe { libc_pause() };
            }
        }
        child => Ok(child as u32),
    }
}

fn write_proc_self(what: &str, contents: &str) -> Result<(), String> {
    let path = format!("/proc/self/{what}");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .and_then(|mut f| f.write_all(contents.as_bytes()))
        .map_err(|e| format!("could not write {path} ({contents:?}): {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_userns_path_names_the_holder() {
        assert_eq!(userns_path(4242), "/proc/4242/ns/user");
    }

    #[test]
    fn a_rank_can_open_the_namespace_of_a_dumpable_holder() {
        // The contract `bwrap --userns` depends on: another process of the same user must
        // be able to OPEN this path. Uses our own pid, which is dumpable by default —
        // exactly the property the holder preserves by NOT clearing PR_SET_DUMPABLE.
        let p = userns_path(std::process::id());
        assert!(
            std::fs::File::open(&p).is_ok(),
            "a rank must be able to open {p} to hand it to bwrap --userns"
        );
    }

    #[test]
    fn the_map_is_an_identity_map_and_never_a_root_map() {
        // Guards the husk userns root-map bug. Mapping the user to 0 inside the namespace
        // flips the agent runtime into its --cap-drop ALL branch, emptying the bounding
        // set so apply-seccomp cannot write uid_map, and every caged command dies.
        for id in [0_u32, 1, 1000, 65534] {
            let m = identity_map(id);
            let fields: Vec<&str> = m.split_whitespace().collect();
            assert_eq!(fields.len(), 3, "a map line is `inside outside count`: {m:?}");
            assert_eq!(fields[0], fields[1], "inside must equal outside: {m:?}");
            assert_eq!(fields[2], "1", "exactly one uid is mapped: {m:?}");
        }
        assert_ne!(identity_map(1000), "0 1000 1", "a root map is forbidden");
    }
}
