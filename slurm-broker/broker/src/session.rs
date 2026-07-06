//! The broker's TRUSTED view of the human's Mode-1 uenv session, captured from
//! its OWN environment at startup. The agent never influences this (see BROKER.md:
//! "uenv — inherit the Mode-1 session").

use std::env;

// NB: the broker submits uenv jobs with `--export=ALL` (inherit the trusted Mode-1
// session), NOT a locked env allowlist. Verified on Balfrin (uenv 8.1) + Santis
// (10.0.1): only --export=ALL activates the view PATH inside the job; an allowlist
// mounts but leaves the view inactive. See policy.rs for the rationale + AV7 caveat.

/// The partition the broker forces (and requires the agent to request) when
/// HUSK_SLURM_PARTITION is unset. Site-specific: Balfrin has `preemptible`; other
/// sites (e.g. Santis) do not, so an operator overrides it via the env var.
pub const DEFAULT_PARTITION: &str = "preemptible";

#[derive(Debug, Clone)]
pub struct Session {
    /// What to pass to `--uenv`. Prefer UENV_LABEL; fall back to UENV_MOUNT_LIST
    /// (its `file:mount-point` pairs are themselves a valid `--uenv` argument).
    pub uenv: Option<String>,
    /// The single partition the broker forces onto every agent job (and requires the
    /// agent to request). From HUSK_SLURM_PARTITION in the broker's TRUSTED env
    /// (operator-set, agent-inaccessible), defaulting to DEFAULT_PARTITION. Choose a
    /// low-priority/preemptible partition — every brokered job lands here.
    pub required_partition: String,
    /// What to pass to `--view`, normalized to `uenvname:viewname`. UENV_VIEW is
    /// mount-qualified on this uenv (e.g. `/user-environment:icon:default`), which is
    /// NOT a valid `--view` argument, so a leading `/mount-point:` field is stripped.
    /// The exported UENV_VIEW does not survive into the job, so this CLI flag is what
    /// restores the job's view to match the session (verified on Balfrin).
    pub view: Option<String>,
}

impl Session {
    pub fn from_env() -> Self {
        let nonempty = |k: &str| env::var(k).ok().filter(|v| !v.is_empty());
        Session {
            uenv: nonempty("UENV_LABEL").or_else(|| nonempty("UENV_MOUNT_LIST")),
            view: nonempty("UENV_VIEW").map(|v| normalize_view(&v)),
            required_partition: nonempty("HUSK_SLURM_PARTITION")
                .unwrap_or_else(|| DEFAULT_PARTITION.to_string()),
        }
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
    use super::normalize_view;

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
