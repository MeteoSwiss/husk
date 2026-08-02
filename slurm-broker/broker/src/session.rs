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

/// Split the operator's `HUSK_SLURM_PARTITION` into the set a job may request.
///
/// A comma-separated LIST, because one partition is not enough on a real cluster: Balfrin
/// has GPU nodes (`short`) and CPU-only postprocessing nodes (`pp-short`), and a workflow
/// legitimately needs both. Which one a job wants is a HARDWARE choice only the job can
/// make, so husk cannot pick for it — but it can bound the set.
///
/// Entries are trimmed and empties dropped, so `short, pp-short,` is three tokens and two
/// partitions. An entry that is not a plausible partition name is DROPPED rather than
/// carried: this string is operator config, but it becomes an argument to the real sbatch,
/// and a name is never allowed to smuggle an option or a shell character.
pub fn parse_partition_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 64
                && !s.starts_with('-')
                && s.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
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

/// Ask SLURM what the forced partition's time limits are. Best-effort: any failure means
/// husk stays quiet about limits rather than inventing them.
pub fn query_partition_limits(partition: &str) -> PartitionLimits {
    let out = std::process::Command::new("scontrol")
        .args(["show", "partition", partition])
        .stdin(std::process::Stdio::null())
        .output();
    match out {
        Ok(o) if o.status.success() => {
            PartitionLimits::parse(&String::from_utf8_lossy(&o.stdout))
        }
        _ => PartitionLimits::default(),
    }
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
    /// `--account` forced onto every job, from `HUSK_SLURM_ACCOUNT` in the broker's TRUSTED
    /// environment (operator-set at install, agent-inaccessible). `None` where the site does
    /// not use accounts — Balfrin does not, Santis REQUIRES one and its cli_filter rejects
    /// every submission without it.
    pub account: Option<String>,
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
    pub fn from_env() -> Self {
        let nonempty = |k: &str| env::var(k).ok().filter(|v| !v.is_empty());
        Session {
            uenv: nonempty("UENV_LABEL").or_else(|| nonempty("UENV_MOUNT_LIST")),
            view: nonempty("UENV_VIEW").map(|v| normalize_view(&v)),
            allowed_partitions: nonempty("HUSK_SLURM_PARTITION")
                .map(|v| parse_partition_list(&v))
                .filter(|v: &Vec<String>| !v.is_empty())
                .unwrap_or_else(|| vec![DEFAULT_PARTITION.to_string()]),
            account: nonempty("HUSK_SLURM_ACCOUNT"),
            limits: Default::default(),
        }
    }

    /// Ask SLURM about every allowed partition, once, at broker startup.
    pub fn with_partition_limits(mut self) -> Self {
        self.limits = self
            .allowed_partitions
            .iter()
            .map(|p| (p.clone(), query_partition_limits(p)))
            .collect();
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
    use super::{normalize_view, PartitionLimits};

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

    // The operator's list. Balfrin needs two: `short` for GPU nodes, `pp-short` for the
    // CPU-only postprocessing nodes.
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
