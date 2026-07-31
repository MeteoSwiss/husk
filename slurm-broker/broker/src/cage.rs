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

const CLONE_NEWUSER: std::os::raw::c_int = 0x1000_0000;

extern "C" {
    fn unshare(flags: std::os::raw::c_int) -> std::os::raw::c_int;
    #[link_name = "getuid"]
    fn libc_getuid() -> u32;
    #[link_name = "getgid"]
    fn libc_getgid() -> u32;
}

/// The path a rank passes to `bwrap --userns`, given the holder's pid.
///
/// Requires the holder to be **dumpable**: reading `/proc/<pid>/ns/*` goes through
/// `ptrace_may_access`, so a holder that had cleared `PR_SET_DUMPABLE` would be one whose
/// namespace no rank can open. That is why the holder, unlike the broker, does not call
/// `refuse_to_be_read`.
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
