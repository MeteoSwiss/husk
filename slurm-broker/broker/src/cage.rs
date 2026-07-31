//! Joining the node cage.
//!
//! **The security border is the job on a node, not the process.** All ranks of one MPI
//! job are a single trust domain — same uid, allocation, files, data — so the cage is
//! built ONCE PER NODE and every task joins it. A cage per task adds no boundary, only N
//! redundant copies of the job↔host wall, and the copies cost real capability: sibling
//! user namespaces cannot `ptrace_may_access` each other, which is what blocked Cray
//! MPICH's Cross Memory Attach (see THREAT-MODEL.md, "the unit of confinement").
//!
//! It has to be *joining* rather than "run bwrap once", because `srun` launches the
//! tasks: `slurmstepd` execs each one independently, so they can never be children of a
//! bwrap the step-broker started.
//!
//! # The risk this design introduces, and the whole point of this module
//!
//! A per-task cage fails **closed**: if `bwrap` cannot build it, the task does not run.
//! Joining can fail **open** — a task whose `setns` silently did nothing runs OUTSIDE the
//! cage, with `/users` visible and no seccomp ancestry, and nothing about its output says
//! so. That asymmetry is the reason this module exists and why it verifies rather than
//! assumes. **Every failure path here must abort before `exec`.**
//!
//! Two independent things are checked, because either alone is insufficient:
//!
//! 1. **We are in the expected namespaces.** After `setns`, each of
//!    `/proc/self/ns/{user,mnt,net}` must have the identity we opened. Catches a partial
//!    join, a `setns` that failed without us noticing, and a holder that died mid-flight.
//! 2. **We actually moved.** The joined user namespace must DIFFER from the one we
//!    started in. Without this, a spec pointing at our own namespaces — a dead holder
//!    whose pid got reused, a misbuilt command line — passes check 1 trivially while
//!    leaving the task completely uncaged. This is the fail-open case, and it is the one
//!    a naive implementation misses.
//!
//! # Ordering constraints (measured, not assumed)
//!
//! * The **user namespace must be joined first**: `setns` into a net or mount namespace
//!   needs `CAP_SYS_ADMIN` in *both* the target's user namespace and the caller's own,
//!   and joining the user namespace is what grants the latter. Joining the netns from
//!   outside the userns fails `EPERM` — verified on a laptop, 2026-07-31.
//! * The **mount namespace is joined last**, so that path resolution keeps the host's
//!   meaning for as long as this process still needs it. The namespace file descriptors
//!   are all opened up-front anyway, which also pins them against pid reuse between the
//!   open and the `setns`.

use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const CLONE_NEWNS: std::os::raw::c_int = 0x0002_0000;
const CLONE_NEWUSER: std::os::raw::c_int = 0x1000_0000;
const CLONE_NEWNET: std::os::raw::c_int = 0x4000_0000;

extern "C" {
    fn setns(fd: std::os::raw::c_int, nstype: std::os::raw::c_int) -> std::os::raw::c_int;
}

/// Which namespace. The order of the variants is the order they must be entered in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NsKind {
    User,
    Net,
    Mnt,
}

impl NsKind {
    /// Entry order: user first (it grants the capabilities the others need), mount last.
    pub const ORDER: [NsKind; 3] = [NsKind::User, NsKind::Net, NsKind::Mnt];

    pub fn name(self) -> &'static str {
        match self {
            NsKind::User => "user",
            NsKind::Net => "net",
            NsKind::Mnt => "mnt",
        }
    }

    fn clone_flag(self) -> std::os::raw::c_int {
        match self {
            NsKind::User => CLONE_NEWUSER,
            NsKind::Net => CLONE_NEWNET,
            NsKind::Mnt => CLONE_NEWNS,
        }
    }
}

/// The identity of one namespace: the `(device, inode)` of its nsfs node.
///
/// Both halves, not just the inode — inode numbers are only unique within a filesystem,
/// and comparing a bare inode is the kind of "probably unique" reasoning that has no
/// place on a fail-open path.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NsId {
    dev: u64,
    ino: u64,
}

impl NsId {
    pub fn of_path(p: &Path) -> std::io::Result<NsId> {
        // Deliberately follows the symlink: /proc/<pid>/ns/<kind> resolves to the nsfs
        // node, whose (dev, ino) IS the namespace identity. The link's own text
        // ("user:[4026531837]") is a rendering of the same thing and is not parsed.
        let m = std::fs::metadata(p)?;
        Ok(NsId { dev: m.dev(), ino: m.ino() })
    }

    fn of_file(f: &std::fs::File) -> std::io::Result<NsId> {
        let m = f.metadata()?;
        Ok(NsId { dev: m.dev(), ino: m.ino() })
    }
}

/// The three namespaces of one process, by kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NsSet {
    pub user: NsId,
    pub net: NsId,
    pub mnt: NsId,
}

impl NsSet {
    pub fn get(&self, k: NsKind) -> NsId {
        match k {
            NsKind::User => self.user,
            NsKind::Net => self.net,
            NsKind::Mnt => self.mnt,
        }
    }

    /// Read this process's own namespaces.
    pub fn of_self() -> std::io::Result<NsSet> {
        Ok(NsSet {
            user: NsId::of_path(Path::new("/proc/self/ns/user"))?,
            net: NsId::of_path(Path::new("/proc/self/ns/net"))?,
            mnt: NsId::of_path(Path::new("/proc/self/ns/mnt"))?,
        })
    }
}

/// Why a task refused to run. Every variant means "did not exec".
#[derive(Debug, PartialEq, Eq)]
pub enum JoinError {
    /// A namespace we ended up in is not the one we were told to join.
    Mismatch { kind: NsKind },
    /// The join left us in the user namespace we started in — so we are UNCAGED.
    DidNotMove,
    /// The spec named the namespaces this process is already in.
    SpecIsOurself,
}

impl std::fmt::Display for JoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JoinError::Mismatch { kind } => write!(
                f,
                "after joining, this task's {} namespace is not the cage's — refusing to \
                 run a rank that is not fully inside the node cage",
                kind.name()
            ),
            JoinError::DidNotMove => write!(
                f,
                "joining left this task in its original user namespace, so it is NOT \
                 caged — refusing to run. The cage holder is probably dead."
            ),
            JoinError::SpecIsOurself => write!(
                f,
                "the cage namespaces are the ones this task already has, so joining them \
                 would confine nothing — refusing to run. The cage holder is probably dead \
                 and its pid reused."
            ),
        }
    }
}

/// The fail-closed decision, as a pure function.
///
/// Kept separate from the `setns` calls precisely so it can be tested without privileges
/// or namespaces: this is the rule that decides whether a rank runs, and it is the one
/// piece here that must never be wrong.
/// The checks are ordered **most dangerous first**, and each is independently
/// reachable — deliberately. An earlier draft checked `after == expected` before
/// "did we move", which made the second check provably unreachable: matching the
/// expected set while `expected.user != before.user` already implies movement. A dead
/// check on a fail-open path is worse than no check, because it reads like protection.
/// Here `DidNotMove` fires on `after` vs `before` alone, so it survives any future
/// loosening of the per-namespace comparison below.
pub fn verify_join(before: &NsSet, expected: &NsSet, after: &NsSet) -> Result<(), JoinError> {
    // Loudest case: nothing took effect at all, and the task is completely uncaged.
    if after.user == before.user {
        return Err(JoinError::DidNotMove);
    }
    // The spec must describe a cage we were not already in, or "joining" confines nothing.
    if expected.user == before.user {
        return Err(JoinError::SpecIsOurself);
    }
    // Partial join: caged in some dimensions, not others. The dangerous middle, because
    // the task looks confined and is not.
    for k in NsKind::ORDER {
        if after.get(k) != expected.get(k) {
            return Err(JoinError::Mismatch { kind: k });
        }
    }
    Ok(())
}

/// Where the cage's namespaces live. Built from the holder's pid by the step-broker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CageSpec {
    pub user: PathBuf,
    pub net: PathBuf,
    pub mnt: PathBuf,
}

impl CageSpec {
    /// The namespaces of the holder process, by pid.
    pub fn of_pid(pid: u32) -> CageSpec {
        CageSpec {
            user: PathBuf::from(format!("/proc/{pid}/ns/user")),
            net: PathBuf::from(format!("/proc/{pid}/ns/net")),
            mnt: PathBuf::from(format!("/proc/{pid}/ns/mnt")),
        }
    }

    pub fn path(&self, k: NsKind) -> &Path {
        match k {
            NsKind::User => &self.user,
            NsKind::Net => &self.net,
            NsKind::Mnt => &self.mnt,
        }
    }
}

/// Enter the node cage, or die trying. Returns only on success.
///
/// The caller must `exec` immediately afterwards; there is deliberately no way to ask
/// this function "did it work" other than `Ok`, so a caller cannot accidentally continue
/// uncaged after an error.
pub fn enter(spec: &CageSpec) -> Result<(), String> {
    let before = NsSet::of_self().map_err(|e| format!("cannot read own namespaces: {e}"))?;

    // Open ALL of them before entering ANY of them. Two reasons: an open fd pins the
    // namespace so it cannot be recycled between the check and the use, and once we are
    // inside the cage's mount namespace these /proc/<pid>/ paths may no longer resolve.
    let mut files = Vec::with_capacity(3);
    for k in NsKind::ORDER {
        let p = spec.path(k);
        let f = std::fs::File::open(p)
            .map_err(|e| format!("cannot open the cage's {} namespace at {}: {e}", k.name(), p.display()))?;
        let id = NsId::of_file(&f)
            .map_err(|e| format!("cannot identify the cage's {} namespace: {e}", k.name()))?;
        files.push((k, f, id));
    }
    let expected = NsSet {
        user: files.iter().find(|(k, _, _)| *k == NsKind::User).unwrap().2,
        net: files.iter().find(|(k, _, _)| *k == NsKind::Net).unwrap().2,
        mnt: files.iter().find(|(k, _, _)| *k == NsKind::Mnt).unwrap().2,
    };

    for (k, f, _) in &files {
        // SAFETY: a valid open fd and a constant CLONE_NEW* flag.
        if unsafe { setns(f.as_raw_fd(), k.clone_flag()) } != 0 {
            return Err(format!(
                "could not join the cage's {} namespace: {}",
                k.name(),
                std::io::Error::last_os_error()
            ));
        }
    }

    let after = NsSet::of_self()
        .map_err(|e| format!("cannot read own namespaces after joining: {e}"))?;
    verify_join(&before, &expected, &after).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u64) -> NsId {
        NsId { dev: 4, ino: n }
    }
    /// (user, net, mnt)
    fn set(u: u64, n: u64, m: u64) -> NsSet {
        NsSet { user: id(u), net: id(n), mnt: id(m) }
    }

    #[test]
    fn a_complete_join_is_accepted() {
        let before = set(1, 2, 3);
        let cage = set(10, 20, 30);
        assert_eq!(verify_join(&before, &cage, &cage), Ok(()));
    }

    #[test]
    fn refuses_when_any_single_namespace_did_not_take() {
        // A partial join is the dangerous middle: the task looks caged and is not. Each
        // namespace is checked, so no one of them can be the silent hole.
        let before = set(1, 2, 3);
        let cage = set(10, 20, 30);
        // The user case lands on a THIRD namespace (99), not back on `before`: ending up
        // where we started is DidNotMove, a distinct and louder failure. This asserts the
        // partial-join path specifically.
        for (kind, actual) in [
            (NsKind::User, set(99, 20, 30)),
            (NsKind::Net, set(10, 2, 30)),
            (NsKind::Mnt, set(10, 20, 3)),
        ] {
            assert_eq!(
                verify_join(&before, &cage, &actual),
                Err(JoinError::Mismatch { kind }),
                "a task whose {} namespace stayed behind must not run",
                kind.name()
            );
        }
    }

    #[test]
    fn refuses_a_join_that_did_not_move_us() {
        // THE FAIL-OPEN CASE: every setns silently did nothing, so the rank would run
        // with /users visible and no seccomp ancestry, and nothing in its output would
        // say so. Checked against `before` alone, so it cannot be defeated by a future
        // change to the per-namespace comparison.
        assert_eq!(
            verify_join(&set(1, 2, 3), &set(10, 20, 30), &set(1, 2, 3)),
            Err(JoinError::DidNotMove),
            "a task still in its original user namespace is not caged"
        );
    }

    #[test]
    fn refuses_a_spec_that_points_at_ourself() {
        // A dead holder whose pid was reused, or a misbuilt command line, yields a spec
        // naming our own namespaces. Joining "succeeds", changes nothing, confines
        // nothing. Reported distinctly from DidNotMove because the operator fix differs:
        // this one means the holder is gone, not that setns misbehaved.
        assert_eq!(
            verify_join(&set(1, 2, 3), &set(1, 2, 3), &set(9, 9, 9)),
            Err(JoinError::SpecIsOurself)
        );
    }

    #[test]
    fn every_refusal_is_reachable() {
        // Guards the ordering bug this file already had once: `DidNotMove` was
        // unreachable, because `after == expected` plus a non-degenerate spec implies
        // movement. Dead code on a fail-open path reads as protection and provides none,
        // so each variant must be producible through the real entry point.
        let seen = [
            verify_join(&set(1, 2, 3), &set(10, 20, 30), &set(1, 2, 3)),
            verify_join(&set(1, 2, 3), &set(1, 2, 3), &set(9, 9, 9)),
            verify_join(&set(1, 2, 3), &set(10, 20, 30), &set(10, 20, 3)),
        ];
        assert_eq!(seen[0], Err(JoinError::DidNotMove));
        assert_eq!(seen[1], Err(JoinError::SpecIsOurself));
        assert_eq!(seen[2], Err(JoinError::Mismatch { kind: NsKind::Mnt }));
    }

    #[test]
    fn namespace_identity_compares_the_device_too() {
        // Inode numbers are unique per filesystem, not globally. Comparing bare inodes
        // would make two different namespaces look identical.
        let before = set(1, 2, 3);
        let cage = NsSet { user: NsId { dev: 4, ino: 10 }, net: id(20), mnt: id(30) };
        let after = NsSet { user: NsId { dev: 9, ino: 10 }, net: id(20), mnt: id(30) };
        assert_eq!(
            verify_join(&before, &cage, &after),
            Err(JoinError::Mismatch { kind: NsKind::User })
        );
    }

    #[test]
    fn the_user_namespace_is_entered_first_and_the_mount_namespace_last() {
        // Not cosmetic. setns into a net or mount namespace needs CAP_SYS_ADMIN in BOTH
        // the target's user namespace and the caller's own; joining the user namespace is
        // what grants the latter. Verified on hardware: joining the netns from outside
        // the userns fails EPERM. Mount goes last so path resolution keeps the host's
        // meaning while this process still needs it.
        assert_eq!(NsKind::ORDER[0], NsKind::User);
        assert_eq!(NsKind::ORDER[2], NsKind::Mnt);
    }

    #[test]
    fn a_spec_names_the_holders_namespaces() {
        let s = CageSpec::of_pid(4242);
        assert_eq!(s.path(NsKind::User), Path::new("/proc/4242/ns/user"));
        assert_eq!(s.path(NsKind::Net), Path::new("/proc/4242/ns/net"));
        assert_eq!(s.path(NsKind::Mnt), Path::new("/proc/4242/ns/mnt"));
    }

    #[test]
    fn reading_our_own_namespaces_works_and_they_differ_from_each_other() {
        // Sanity on the real /proc: the three kinds must be distinct objects, otherwise
        // every comparison above is meaningless on this system.
        let me = NsSet::of_self().expect("/proc/self/ns must be readable");
        assert_ne!(me.user, me.net);
        assert_ne!(me.user, me.mnt);
        assert_ne!(me.net, me.mnt);
    }
}
