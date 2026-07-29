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
    fn single_node_forces_the_node_count() {
        assert_eq!(
            Profile::SingleNode.forced_sbatch_options(),
            vec!["--nodes=1".to_string()]
        );
    }
}
