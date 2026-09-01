//! Cage profiles: the declared, bounded set of shapes a brokered job may run in.
//!
//! Design + rationale: `slurm-broker/CAGE-PROFILES.md`. The short version:
//!
//! The compute cage and the login cage necessarily differ (an MPI job needs GPUs and a
//! fabric; an agent shell does not), so literal configuration parity is not the goal. The
//! invariant is narrower — **no escape-relevant capability on compute that login denies**
//! — and a profile is how each divergence is made declared and reviewable rather than
//! accidental.
//!
//! The axis is **topology**, because topology is the threat axis: it determines what
//! network and credential reach a job requires. CPU vs GPU is deliberately NOT a profile
//! — the only difference is the `/dev/nvidia*` nodes and `--dev-bind-try` already skips
//! absent ones, so the variant is implicit in the mechanism.
//!
//! **The broker picks**, never the agent: the profile is a function of options the broker
//! already forces, so it adds no agent-facing input language — nothing to parse, nothing
//! to attack.

/// The topology a job runs in. `Login` is not represented: it is the agent's own cage,
/// not something a brokered job can be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// One node. Needs no IP at all — measured on Balfrin: a single rank and same-node
    /// multi-rank MPI both work with `--unshare-net` intact, because the PMI bootstrap is
    /// node-local and ranks talk over shared memory. Full IP isolation is kept.
    SingleNode,
}

impl Profile {
    /// Choose the profile for a submission, given whatever node count the agent asked for
    /// (CLI or `#SBATCH`, already extracted by the caller).
    ///
    /// Multi-node is **rejected, not downgraded**. Silently forcing `--nodes=1` onto a job
    /// that asked for four would run it on a quarter of the resources and report success
    /// — the same silent-degradation failure mode as an MPI job that "succeeds" as
    /// independent single-rank jobs. A wrong answer that looks like a right one is the
    /// worst outcome available, so this fails loudly with an explanation instead.
    pub fn select(requested_nodes: Option<&str>) -> Result<Self, String> {
        match requested_nodes {
            // The only accepted spellings of "one node". A range (`1-4`) is refused
            // rather than interpreted: its upper bound is what the scheduler may act on.
            None | Some("1") => Ok(Profile::SingleNode),
            Some(n) => Err(format!(
                "husk brokers single-node jobs only, but this asks for --nodes={n}. \
                 Multi-node needs an IP path for the MPI/PMI bootstrap, which would mean \
                 giving the job a network route to the scheduler — a containment decision \
                 that is not made yet, not an oversight. Resubmit with --nodes=1 (or omit \
                 it). Single-node multi-GPU and multi-rank MPI on one node do work."
            )),
        }
    }

    /// sbatch options the profile FORCES onto the real submission.
    ///
    /// `--nodes=1` is emitted rather than merely checked, because the node count is not
    /// reliably knowable at submit time: `--ntasks N` on its own lets the scheduler spread
    /// tasks across nodes. A profile derived by *reading* the request could therefore
    /// dress a two-node job in the single-node cage. Forcing makes it true by
    /// construction. (Same lesson as the option allowlist: capture values, don't trust
    /// references.)
    pub fn forced_sbatch_options(&self) -> Vec<String> {
        match self {
            Profile::SingleNode => vec!["--nodes=1".to_string()],
        }
    }

    /// The `--profile` value passed to `seccomp-wrapper`, which decides the syscall
    /// rules layered on top of its base deny-list. Kept here so the topology decision has
    /// exactly one home: the broker picks a profile, and every layer of the cage derives
    /// from that name rather than re-deriving it.
    ///
    /// `SingleNode` currently adds NO syscall rules. It briefly blocked AF_UNIX — gate
    /// C12 had measured zero such calls in a caged 2-rank MPI run — but that sample had no
    /// CUDA, and CUDA both needs unix sockets and treats the refusal as fatal
    /// (`cuInit -> 304`, Balfrin 2026-07-30, with the mount cage exonerated one arm at a
    /// time). The MUNGE mount mask is what keeps the escape-relevant destination
    /// unreachable, and it is destination-aware in a way a syscall filter cannot be.
    ///
    /// **Where that mask is actually applied, because this is the sentence that makes it
    /// load-bearing and it used to name no enforcer.** TWO places, and both must hold:
    /// `policy::wrap_script`'s loop for the job cage, and `rank::wrap_command`'s for each
    /// rank — bwrap mount namespaces do not propagate, so a rank does not inherit the
    /// job's mask. Either half could once decline to apply and say nothing (`B3-7`).
    ///
    /// **They now take the same decision, and that is asserted by executing both.** Fix `K`
    /// closed the rank half and left the job-cage half at `[ -d ] || continue`, so one node
    /// configuration produced a refused rank and a silently unmasked job cage — two
    /// enforcers of one control giving opposite answers, with the operator meeting the
    /// confusing half first (`K-2`). `K-2`'s fix gives the job cage the same split: absent
    /// is a silent skip (there is nothing to hide, and `--tmpfs` on an absent DEST kills the
    /// cage), present-but-unmaskable stops the job before the body runs.
    /// `policy::tests::the_two_credential_mask_enforcers_agree_on_a_path_neither_can_mask`
    /// drives both slices against one tree and compares them;
    /// `rank::tests::a_credential_path_that_cannot_be_masked_stops_the_rank_instead_of_being_dropped`
    /// pins the rank half on its own.
    ///
    /// **One arm differs by decision, not by oversight.** A path resolving through
    /// whitespace is maskable in the job cage (a bash array carries one word) and not in a
    /// rank (`$_m` is concatenated and expanded unquoted). The job cage masks it and
    /// ANNOUNCES that every `srun` in the job will refuse, rather than refusing a job whose
    /// cage husk can actually build.
    ///
    /// The name is still passed and still validated: an unknown profile is fatal in the
    /// wrapper, so this is where the next rule lands rather than a knob to remove.
    pub fn seccomp_profile(&self) -> &'static str {
        match self {
            Profile::SingleNode => "single-node",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_or_one_node_selects_single_node() {
        assert_eq!(Profile::select(None), Ok(Profile::SingleNode));
        assert_eq!(Profile::select(Some("1")), Ok(Profile::SingleNode));
    }

    #[test]
    fn multi_node_is_rejected_not_downgraded() {
        // The failure mode this guards against is a job that asked for 4 nodes running on
        // 1 and reporting success.
        for n in ["2", "4", "1-4", "0"] {
            let err = Profile::select(Some(n)).expect_err("must reject");
            assert!(err.contains("single-node"), "must say what is supported: {err}");
            assert!(err.contains("--nodes=1"), "must say how to fix it: {err}");
        }
    }

    #[test]
    fn single_node_names_its_seccomp_profile() {
        // The name must match what seccomp-wrapper accepts; an unknown one is fatal
        // there (fail-closed), so a mismatch shows up as every job failing to launch.
        assert_eq!(Profile::SingleNode.seccomp_profile(), "single-node");
    }

    #[test]
    fn single_node_forces_the_node_count() {
        assert_eq!(
            Profile::SingleNode.forced_sbatch_options(),
            vec!["--nodes=1".to_string()]
        );
    }
}
