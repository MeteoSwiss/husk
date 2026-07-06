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

/// Tier-1 read-only SLURM commands the broker runs on the agent's behalf. Shared
/// by the broker's `policy` (the authoritative gate) and the wrapper's shadow
/// list so the two cannot drift. Tier-2 (verb-gated scontrol/sacctmgr/sdiag) is
/// deferred — see the slurm-readonly-tier2 note.
pub const READONLY_SLURM: &[&str] = &[
    "squeue", "sinfo", "sacct", "sstat", "sprio", "sreport", "sshare",
];
