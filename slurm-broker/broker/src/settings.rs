//! Resolve the sandbox filesystem policy from the (trusted) Claude settings
//! hierarchy and translate it into the compute-side bwrap profile.
//!
//! The agent cannot write any settings file (the permission layer denies edits to
//! settings.json / settings.local.json), so all three layers are trusted human
//! input. We still parse defensively with serde and FAIL SAFE: any missing or
//! malformed file yields NO carve-outs — never a wider cage. The compute job
//! hides all homes by default (HIDDEN_FLOOR); only the human's `allowRead` entries
//! carve specific subpaths back in. This mirrors the login-side `sandbox.filesystem`
//! boundary (the part that governs bash), read from the SAME settings files so the
//! two cages cannot silently drift. See BROKER.md.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Always hidden on the compute node regardless of config — the fail-safe floor.
/// Config `denyRead` adds to this; `allowRead` carves specific subpaths back.
const HIDDEN_FLOOR: &[&str] = &["/users"];

/// NVIDIA device nodes exposed into the job WHEN PRESENT (`--dev-bind-try` binds
/// if the node exists on the compute host, else skips). This makes the GPUs and
/// their NVLink interconnect usable inside the cage — needed because `--dev /dev`
/// gives a bare devtmpfs that would otherwise hide them. It does NOT widen the
/// filesystem policy (device nodes only), is a no-op on non-GPU nodes, and is
/// evaluated on the compute node so it adapts to the real GPU/MIG/NVSwitch layout.
/// Host CUDA/driver libraries come for free via `--ro-bind / /`.
const GPU_DEVICES: &[&str] = &[
    "/dev/nvidiactl",
    "/dev/nvidia-uvm",
    "/dev/nvidia-uvm-tools",
    "/dev/nvidia-caps",
    "/dev/gdrdrv",
    "/dev/nvidia0", "/dev/nvidia1", "/dev/nvidia2", "/dev/nvidia3",
    "/dev/nvidia4", "/dev/nvidia5", "/dev/nvidia6", "/dev/nvidia7",
    "/dev/nvidia-nvswitchctl",
    "/dev/nvidia-nvswitch0", "/dev/nvidia-nvswitch1",
    "/dev/nvidia-nvswitch2", "/dev/nvidia-nvswitch3",
];

/// Fabric NIC device nodes exposed into a RANK cage (never into a plain job cage).
///
/// `/dev/cxi[0-9]*` on Alps — Balfrin has four. Measured (gate C4/C1): the device is
/// REQUIRED for the CXI provider to enumerate (0 endpoints without it, 8 with) and needs
/// no capability beyond the node itself, and enumeration is unaffected by
/// `--unshare-net` — so the rank cage keeps full IP isolation AND the fabric.
///
/// `/dev/cxi_sbl` is deliberately absent: Balfrin shows it 0600 root:root (Slingshot
/// base-link, an admin device). A user job cannot open it, so binding it would widen the
/// cage's surface by exactly the amount it cannot use.
///
/// Like the GPU nodes these are `--dev-bind-try`, so a node without a fabric simply skips
/// them — the same mechanism that makes CPU-vs-GPU not worth a separate profile.
const FABRIC_DEVICES: &[&str] = &[
    "/dev/cxi0", "/dev/cxi1", "/dev/cxi2", "/dev/cxi3",
    "/dev/cxi4", "/dev/cxi5", "/dev/cxi6", "/dev/cxi7",
];

/// Which cage is being built. They differ in exactly two places, both measured:
/// the fabric devices, and who owns `/dev/shm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CageKind {
    /// The batch job itself: a fresh private `/dev/shm`, no fabric.
    Job,
    /// One MPI rank launched by the step-broker. Gets the fabric, and does NOT get a
    /// private `/dev/shm`: a per-task tmpfs gives every rank its own shared-memory
    /// segment namespace, which HANGS same-node multi-rank MPI (probe runs 8-9 — with
    /// and without the netns, so it is not a network problem). The per-JOB `/dev/shm`
    /// subdirectory is bound by the per-task wrapper instead, where the job id is known.
    Rank,
}

/// Credential-daemon socket directories to mask, so a caged job cannot AUTHENTICATE to
/// the cluster services even where it can reach them.
///
/// **Not emitted as static bwrap args** — the mask is applied by the re-exec guard on the
/// COMPUTE NODE (see `policy::wrap_script`), because `--tmpfs DEST` is neither
/// absent-safe nor symlink-safe and only the compute node knows which of these exist.
/// Both failure modes were real, and both killed the cage outright (verified 2026-07-29):
///   * absent DEST under `--ro-bind / /` -> `bwrap: Can't mkdir /run/munge: Read-only
///     file system`. (`--ro-bind-try` tolerates a missing SOURCE, not a missing DEST, and
///     there is no `--tmpfs-try`.)
///   * `/var/run` is a symlink to `/run` on any modern Linux, so masking both paths makes
///     the second one resolve onto the first one's fresh tmpfs and bwrap dies.
///
/// The guard therefore tests each path, resolves it, and de-duplicates before mounting.
///
/// MUNGE is how a process proves its identity to slurmctld/slurmd. On the LOGIN side
/// it is already unreachable — `apply-seccomp` blocks AF_UNIX outright — but the
/// compute guard does not block AF_UNIX (PMI, nsswitch and shared-memory wire-up need
/// it), so `/run/munge/munge.socket.2` came along with `--ro-bind / /` and was
/// reachable inside the job. Nothing in a brokered job needs it: submissions go
/// through the broker, and PMI authenticates with its own `PMI_SHARED_SECRET`.
///
/// Why it matters beyond defence in depth: it DECOUPLES "the job has a network route"
/// from "the job can submit un-caged jobs" (AV8). `--unshare-net` is one wall; this is
/// a second, independent one that survives if multi-node MPI ever forces the netns to
/// be relaxed. A tmpfs (not `--ro-bind /dev/null`) because the target is a directory —
/// but only ever mounted on a path the guard has confirmed exists, see above.
pub(crate) const CREDENTIAL_SOCKET_DIRS: &[&str] = &["/run/munge", "/var/run/munge"];

/// Auto-executing / auto-loaded files re-bound READ-ONLY within every writable
/// root, so a job can't plant a payload that fires LATER on the login node (AV2)
/// — a git hook, an MCP server config, a project settings file, editor tasks.
/// Relative to each writable root. `.git/config` is added unless allowGitConfig.
/// Auto-exec/config FILES masked with `/dev/null` inside every writable root, and the
/// DIRECTORIES masked with a fresh tmpfs. Every entry is something the agent runtime
/// reads back and ACTS ON — settings/permissions, or code it will execute (hooks,
/// commands, agents, skills, workflows, routines, scheduled tasks). A job that plants
/// one gets code or permission grants in the next login-side session: AV2.
///
/// The set mirrors what the login-side runtime masks (observed in the cage's mount
/// table on Balfrin 2026-07-27); keep it a SUPERSET — it protects the login side, we
/// protect the job side.
///
/// The mask is a **fresh tmpfs over the whole directory**, which is deliberately
/// ABSENT-SAFE and future-proof:
/// - `--ro-bind-try` (what this used to use) *skips* a source that does not exist, which
///   left the plant-a-fresh-file hole wide open: a project with no
///   `.claude/settings.local.json` — the common case — let a job simply CREATE one.
/// - Masking the DIRECTORY rather than each known file means a new agent-config feature
///   (upstream keeps adding them: skills, workflows, routines, scheduled tasks…) is
///   covered the day it ships, with no list to keep in sync.
/// - Per-file `--ro-bind /dev/null` would also be absent-safe, but bwrap has to create
///   the mount point, and since the workdir is a bind of the real directory that leaves
///   an EMPTY `settings.json` behind on the host — i.e. invalid JSON in the user's
///   project. A tmpfs leaves at most an empty directory, which is harmless.
///
/// A compute job has no legitimate need to read or write the agent's config, so hiding
/// the directory outright costs nothing. Writes inside the tmpfs are discarded when the
/// job ends and never reach the real filesystem.
const AUTO_EXEC_DIRS: &[&str] = &[
    ".claude",   // settings*, hooks, commands, agents, skills, workflows, routines, …
    ".git/hooks",
    ".vscode",
    ".idea",
];

/// Auto-exec FILES that must stay READABLE, so they get a read-only bind and are only
/// protected when they already exist. `.mcp.json` would be a plant vector (an MCP server
/// config is a command the runtime executes), but masking it empty breaks a project that
/// legitimately uses one, and creating an empty one breaks JSON parsing — so it is
/// backstopped by `enableAllProjectMcpServers: false` in the shipped config, which means
/// a planted server is never auto-started. `.git/config` must be readable for git to work
/// at all, and always exists wherever `.git` does, so absence is not a hole there.
const AUTO_EXEC_RO_FILES: &[&str] = &[".mcp.json"];

/// SLURM filename specifiers we allow in an `--output`/`--error` pattern.
///
/// `%x` (job name) is deliberately ABSENT. slurmd expands these AFTER husk has validated
/// the string, so an allowed specifier whose expansion the agent controls is a
/// parser-differential of exactly the F13/F14 kind: `<workdir>/%x` with a job name of
/// `..` resolves one level above the workdir. Everything permitted here expands to a
/// number, a node name or a user name — none can contain `/` or be `..`.
const OUTPUT_SPECIFIERS: &[char] = &['%', 'A', 'a', 'J', 'j', 'N', 'n', 's', 't', 'u'];

/// The filename part of an `--output`/`--error` value: charset-bounded, with `%` only in
/// front of an allowed specifier.
///
/// Separate from the directory part because the two are checked differently — the
/// directory must be RESOLVED on disk and confined, which is impossible for a string
/// containing an unexpanded `%j`.
pub fn is_valid_output_filename(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 || name == "." || name == ".." {
        return false;
    }
    let mut chars = name.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            match chars.next() {
                Some(spec) if OUTPUT_SPECIFIERS.contains(&spec) => continue,
                _ => return false,
            }
        } else if !(c.is_ascii_alphanumeric() || "._+-".contains(c)) {
            return false;
        }
    }
    true
}

/// Resolve `path` and require it to be the workdir or a descendant of it.
///
/// **Why containment is the whole rule.** `--chdir` decides where the job starts and
/// `--output`/`--error` decide where *slurmd*, running as the user OUTSIDE the cage,
/// writes a file. An unconfined output path is therefore an uncaged arbitrary-write
/// primitive — job stdout into `~/.bashrc` or a `.git/hooks/` file, which is AV2 with the
/// cage bypassed entirely. Confined to the workdir subtree it grants nothing new: that
/// subtree is bound writable into the cage, so the job could write there anyway.
///
/// Resolves symlinks on both sides, because slurmd follows them and a string comparison
/// would not. `Path::starts_with` is component-wise, so `/work2` is not "under" `/work`.
pub fn confine_under_workdir(path: &str, workdir: &str) -> Result<String, String> {
    let root = std::fs::canonicalize(workdir)
        .map_err(|e| format!("cannot resolve the working directory {workdir:?}: {e}"))?;
    let target = std::fs::canonicalize(path).map_err(|e| {
        format!(
            "{path:?} cannot be resolved ({e}). It must already exist — SLURM does not              create output directories."
        )
    })?;
    if !target.starts_with(&root) {
        return Err(format!(
            "{path:?} resolves to {} which is outside the job's working directory {}.              husk confines --chdir/--output/--error to that directory and below, because              SLURM writes those files as you and OUTSIDE the sandbox.",
            target.display(),
            root.display()
        ));
    }
    Ok(target.to_string_lossy().to_string())
}

/// Validate an `--output`/`--error` value and return it canonicalised.
///
/// Splits directory from filename: the directory is resolved and confined, the filename is
/// checked as a pattern. A `%` anywhere in the DIRECTORY part is refused rather than
/// guessed at — husk cannot resolve a path it cannot expand, and validating an
/// unexpanded string would be validating something other than what slurmd opens.
pub fn confine_output_pattern(value: &str, workdir: &str) -> Result<String, String> {
    let (dir, file) = match value.rsplit_once('/') {
        Some((d, f)) => (if d.is_empty() { "/" } else { d }, f),
        // A bare filename is relative to --chdir, which is itself confined.
        None => (workdir, value),
    };
    if dir.contains('%') {
        return Err(format!(
            "{value:?} puts a SLURM % specifier in a DIRECTORY component. husk cannot              resolve a directory it cannot expand, so only the filename may contain them."
        ));
    }
    if !is_valid_output_filename(file) {
        return Err(format!(
            "{file:?} is not an acceptable output filename. Allowed: letters, digits,              `._+-`, and the SLURM specifiers %% %A %a %J %j %N %n %s %t %u. %x (job              name) is not allowed, because husk validates the path before SLURM expands it."
        ));
    }
    let dir = confine_under_workdir(dir, workdir)?;
    Ok(format!("{dir}/{file}"))
}

/// Every file the broker will read policy from: `(relative_to_home, path)`.
///
/// **This list has a twin**, the `sandbox.filesystem.denyWrite` entries in the shipped
/// `user-config/settings.json`, which is what stops the agent EDITING its own policy. The
/// two are the same list written twice, in different files and different languages, and a
/// list duplicated in two places is the failure this project keeps meeting — the smoke
/// probe list, `.gitignore`, `build_and_test.sh`. Adding a source here without adding the
/// deny there hands the agent a writable policy input, which matters more once policy
/// includes the network allowlist. `settings_sources_are_all_write_denied` asserts the
/// pairing against the shipped file.
pub const SETTINGS_SOURCES: [(bool, &str); 3] = [
    (true, ".claude/settings.json"),   // ~/.claude/settings.json
    (false, ".claude/settings.json"),  // <project>/.claude/settings.json
    (false, ".claude/settings.local.json"),
];

/// Is `cwd` an acceptable working directory to force as `--chdir` and bind WRITABLE into
/// the compute cage? The agent controls `req.cwd`, and the workdir is re-bound writable
/// on top of the read-only root + the `--tmpfs` floor, so an unconfined `cwd` re-mounts
/// root read-write (`cwd="/"`) or re-exposes a home (`cwd="/users/x"`). Reject: relative
/// or empty, `/`, any path with a `..` component, and any path equal to or under a
/// HIDDEN_FLOOR. Jobs must run from a scratch/project path. (F15/F19)
pub fn is_workdir_allowed(cwd: &str) -> bool {
    if cwd.is_empty() || !cwd.starts_with('/') || cwd == "/" {
        return false;
    }
    if cwd.split('/').any(|c| c == "..") {
        return false;
    }
    !path_under_floor(cwd)
}

/// True if `p` equals or is nested under a HIDDEN_FLOOR path. Such a path must never be
/// re-exposed by an allow carve-out (the floor must hold regardless of config) and is not
/// an acceptable writable workdir. (F18/F15)
fn path_under_floor(p: &str) -> bool {
    let norm = p.trim_end_matches('/');
    HIDDEN_FLOOR
        .iter()
        .any(|floor| norm == *floor || norm.starts_with(&format!("{floor}/")))
}

/// Resolve a filesystem-policy entry to an absolute path for the COMPUTE cage:
/// - absolute (`/x`) → itself
/// - home-relative (`~/x`) → `None`: it lives under a home, already hidden by the
///   HIDDEN_FLOOR tmpfs, so there is nothing to bind
/// - workdir-relative (`x`, `./x`) → joined onto the workdir (the writable project
///   dir). A relative `denyRead`/credential entry was previously dropped on compute
///   (only absolute paths were emitted) while the login cage honored it, so the two
///   cages drifted and a relative deny failed OPEN. Resolving it here honors it on
///   compute exactly as on login. (F22)
fn abs_for_cage(entry: &str, workdir: &str) -> Option<String> {
    if entry.starts_with('/') {
        Some(entry.to_string())
    } else if entry.starts_with('~') {
        None
    } else {
        let rel = entry.trim_start_matches("./");
        Some(format!("{}/{}", workdir.trim_end_matches('/'), rel))
    }
}

/// True if the absolute path `abs` equals or is nested under the workdir or any
/// `allowWrite` root. Such a path is made writable by a later `--bind`, so a
/// `denyRead` covering it must be re-applied AFTER that bind or it is re-exposed. (F22)
fn is_under_writable_root(abs: &str, workdir: &str, allow_write: &[String]) -> bool {
    let norm = abs.trim_end_matches('/');
    std::iter::once(workdir)
        .chain(allow_write.iter().map(String::as_str))
        .filter(|r| r.starts_with('/'))
        .any(|r| {
            let r = r.trim_end_matches('/');
            norm == r || norm.starts_with(&format!("{r}/"))
        })
}

/// The slice of settings we act on: `sandbox.filesystem.{allowRead,denyRead,
/// allowWrite,denyWrite}` plus credential files to mask (`sandbox.credentials.files`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FsPolicy {
    pub allow_read: Vec<String>,
    pub deny_read: Vec<String>,
    /// Writable roots (`sandbox.filesystem.allowWrite`). The compute cage is
    /// default-deny for writes (root is `--ro-bind`), so each is bound read-write.
    pub allow_write: Vec<String>,
    /// Paths made read-only within writable roots (`sandbox.filesystem.denyWrite`);
    /// takes precedence over allowWrite, so applied after the write binds.
    pub deny_write: Vec<String>,
    /// `sandbox.filesystem.allowGitConfig` — when true, `.git/config` stays
    /// writable (git remote-url edits); `.git/hooks` is protected regardless.
    pub allow_git_config: bool,
    /// Credential files made unreadable (from `sandbox.credentials.files`): bound
    /// with `/dev/null` so the job reads empty, mirroring the login cage which
    /// masks them. `mask` mode is degraded to deny — husk does not implement
    /// value-masking yet, and deny is the safe degrade (same as the runtime does).
    pub deny_files: Vec<String>,
    /// Credential env-var names to drop (`sandbox.credentials.envVars`): emitted
    /// as bwrap `--unsetenv` so a secret in the broker's session env doesn't ride
    /// into the job. (`mask` mode degrades to unset, same as files.) Not strictly
    /// filesystem, but it's the same credential-protection policy from settings.
    pub unset_env: Vec<String>,
}

// --- partial deserialize: model only what we need; serde ignores everything else ---
#[derive(Deserialize, Default)]
struct Settings {
    #[serde(default)]
    sandbox: SandboxCfg,
}
#[derive(Deserialize, Default)]
struct SandboxCfg {
    #[serde(default)]
    filesystem: FsCfg,
    #[serde(default)]
    credentials: CredentialsCfg,
}
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct FsCfg {
    #[serde(default)]
    allow_read: Vec<String>,
    #[serde(default)]
    deny_read: Vec<String>,
    #[serde(default)]
    allow_write: Vec<String>,
    #[serde(default)]
    deny_write: Vec<String>,
    #[serde(default)]
    allow_git_config: bool,
}
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CredentialsCfg {
    #[serde(default)]
    files: Vec<CredFile>,
    #[serde(default)]
    env_vars: Vec<CredEnvVar>,
}
#[derive(Deserialize, Default)]
struct CredFile {
    #[serde(default)]
    path: String,
    // `mode` (mask|deny) is intentionally ignored: every entry is a secret to
    // protect, and husk's only mechanism is deny, so mask degrades to deny.
}
#[derive(Deserialize, Default)]
struct CredEnvVar {
    #[serde(default)]
    name: String,
    // `mode` ignored: every entry is a secret; husk unsets it (mask degrades to unset).
}

impl FsPolicy {
    /// Parse one settings file. Unknown keys are ignored; malformed JSON or an
    /// absent `sandbox.filesystem` block -> empty policy (fail-safe: no carve-outs).
    pub fn parse(json: &str) -> FsPolicy {
        let s: Settings = serde_json::from_str(json).unwrap_or_default();
        let deny_files = s
            .sandbox
            .credentials
            .files
            .into_iter()
            .map(|f| f.path)
            .filter(|p| !p.is_empty())
            .collect();
        let unset_env = s
            .sandbox
            .credentials
            .env_vars
            .into_iter()
            .map(|e| e.name)
            .filter(|n| !n.is_empty())
            .collect();
        FsPolicy {
            allow_read: s.sandbox.filesystem.allow_read,
            deny_read: s.sandbox.filesystem.deny_read,
            allow_write: s.sandbox.filesystem.allow_write,
            deny_write: s.sandbox.filesystem.deny_write,
            allow_git_config: s.sandbox.filesystem.allow_git_config,
            deny_files,
            unset_env,
        }
    }

    /// Union another layer in (dedup). All layers are trusted and carve-outs are
    /// additive, so a higher layer can only ADD allows/denies — never remove a
    /// deny (which keeps the merge fail-safe regardless of layer precedence).
    fn union(&mut self, other: FsPolicy) {
        for p in other.allow_read {
            if !self.allow_read.contains(&p) {
                self.allow_read.push(p);
            }
        }
        for p in other.deny_read {
            if !self.deny_read.contains(&p) {
                self.deny_read.push(p);
            }
        }
        for p in other.allow_write {
            if !self.allow_write.contains(&p) {
                self.allow_write.push(p);
            }
        }
        for p in other.deny_write {
            if !self.deny_write.contains(&p) {
                self.deny_write.push(p);
            }
        }
        for p in other.deny_files {
            if !self.deny_files.contains(&p) {
                self.deny_files.push(p);
            }
        }
        for n in other.unset_env {
            if !self.unset_env.contains(&n) {
                self.unset_env.push(n);
            }
        }
        // A trusted layer opting into git-config writes wins (OR).
        self.allow_git_config = self.allow_git_config || other.allow_git_config;
    }

    /// Resolve the full hierarchy: global `~/.claude/settings.json`, then the
    /// project's `settings.json`, then `settings.local.json` (where the CLI
    /// `/sandbox` toggle and permission grants land). Missing/unreadable files
    /// are skipped — fail-safe.
    pub fn resolve(home: &Path, project_dir: &Path) -> FsPolicy {
        let mut pol = FsPolicy::default();
        let files = SETTINGS_SOURCES.map(|(from_home, rel)| {
            if from_home { home.join(rel) } else { project_dir.join(rel) }
        });
        for f in files {
            if let Ok(text) = std::fs::read_to_string(&f) {
                pol.union(FsPolicy::parse(&text));
            }
        }
        // Route denyRead entries that are regular FILES to /dev/null binds:
        // `--tmpfs` only works on directories.
        pol.split_file_denies(|p| std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false));
        // Drop allow carve-outs where ANY path component (leaf OR an intermediate
        // directory) is a symlink: bwrap follows symlinks on the bind source, so a
        // symlinked component could expose a target the human didn't configure. A
        // leaf-only lstat would miss an intermediate symlink (`/a/b/c` where `/a/b`
        // is the symlink), so walk every component. (F20)
        pol.drop_symlinked_carveouts(path_has_symlink_component);
        // Never let an allow carve-out re-expose a HIDDEN_FLOOR path: drop any
        // allowRead/allowWrite equal to or under a floor. The floor must hold "regardless
        // of config" — this fixes that over-promise and backstops the F17 chain. (F18)
        pol.drop_floor_overlapping_allows();
        // F6a — bounded credential auto-scan of the WORKDIR only (never
        // /users-wide): deny un-declared secret files the user didn't list in
        // credentials.files, so a brokered job can't read (and, once the net cage
        // relaxes, exfiltrate) them. Scan-once at construction — a compute job is
        // structurally single-construction (bwrap is frozen mid-job). Depth- and
        // count-capped; fail-safe (fewer denies on error, base cage still holds).
        let scan = scan_credentials(project_dir);
        for f in scan.files {
            if !pol.deny_files.contains(&f) {
                pol.deny_files.push(f);
            }
        }
        // F21 — the scan is best-effort; if the entry budget was exhausted before
        // the walk finished (a deeply/widely-populated workdir, or an agent padding
        // the tree to starve the scanner), it is INCOMPLETE and a secret may be left
        // unmasked. Never fail silently: warn to stderr so the operator knows to
        // declare deep secrets explicitly. The base cage (HIDDEN_FLOOR + explicit
        // credentials.files) still holds regardless.
        if scan.truncated {
            eprintln!(
                "husk-broker: warning: credential auto-scan of {} hit the {}-entry cap and is \
                 INCOMPLETE — deep or padded secrets may be unmasked. Declare them explicitly \
                 in sandbox.credentials.files.",
                project_dir.display(),
                SCAN_MAX_ENTRIES
            );
        }
        pol
    }

    /// Drop allow carve-outs (`allowRead`/`allowWrite`) whose leaf is a symlink.
    /// bwrap follows symlinks on the bind SOURCE, so a symlinked carve-out could
    /// expose a target the human didn't configure. `is_symlink` classifies each
    /// path (real `symlink_metadata` in `resolve`; a closure in tests).
    fn drop_symlinked_carveouts(&mut self, is_symlink: impl Fn(&str) -> bool) {
        self.allow_read.retain(|p| !is_symlink(p));
        self.allow_write.retain(|p| !is_symlink(p));
    }

    /// Drop allow carve-outs that equal or nest under a HIDDEN_FLOOR path, so a config
    /// `allowRead:["/users"]` can never re-expose the floor inside the cage. (F18)
    fn drop_floor_overlapping_allows(&mut self) {
        self.allow_read.retain(|p| !path_under_floor(p));
        self.allow_write.retain(|p| !path_under_floor(p));
    }

    /// Move denyRead entries that are regular FILES into `deny_files` (bound with
    /// `/dev/null`). bwrap's `--tmpfs` only works on directories, so a file left
    /// in `deny_read` would fail at mount time. `is_file` classifies each path (a
    /// real stat in `resolve`; a closure in tests). Absent or directory paths stay
    /// in `deny_read` (they become `--tmpfs`).
    fn split_file_denies(&mut self, is_file: impl Fn(&str) -> bool) {
        let (files, dirs): (Vec<String>, Vec<String>) = std::mem::take(&mut self.deny_read)
            .into_iter()
            .partition(|p| is_file(p));
        self.deny_read = dirs;
        for f in files {
            if !self.deny_files.contains(&f) {
                self.deny_files.push(f);
            }
        }
    }

    /// Build the compute-side bwrap argument list (everything before `-- cmd`).
    /// `workdir` (the forced `--chdir` dir) is bound WRITABLE so the job can write
    /// its output; everything else is read-only or hidden.
    ///
    /// bwrap applies binds in order (later wins): `--ro-bind / /` first, then
    /// hides/allows applied shallowest-path-first so the most specific rule wins,
    /// then the writable workdir, then `--unshare-net`.
    pub fn compute_bwrap_args(&self, workdir: &str) -> Vec<String> {
        self.bwrap_args(workdir, CageKind::Job)
    }

    /// The RANK cage: as the job cage, plus the fabric devices, minus the private
    /// `/dev/shm`. See `CageKind`.
    pub fn rank_bwrap_args(&self, workdir: &str) -> Vec<String> {
        self.bwrap_args(workdir, CageKind::Rank)
    }

    fn bwrap_args(&self, workdir: &str, kind: CageKind) -> Vec<String> {
        let mut a: Vec<String> = vec![
            "--ro-bind".into(), "/".into(), "/".into(),
            "--dev".into(), "/dev".into(),
            "--proc".into(), "/proc".into(),
            "--tmpfs".into(), "/tmp".into(),
        ];
        // Shared memory: --dev gives a bare /dev, but CUDA IPC and framework
        // dataloaders need /dev/shm. A RANK gets the job's shared one instead, bound by
        // the per-task wrapper — a private tmpfs per rank hangs same-node MPI.
        if kind == CageKind::Job {
            a.push("--tmpfs".into());
            a.push("/dev/shm".into());
            // PID namespace — the JOB cage only, and the asymmetry is the whole point.
            //
            // What it buys: everything on a compute node runs as the same uid, so without
            // this the job can see, signal and `process_vm_readv` every other process of
            // ours on the node — including the un-caged step-broker and egress proxy, which
            // deliberately hold what the cage removes (MUNGE, the daemon route, the one
            // route out). Those are defended today by clearing PR_SET_DUMPABLE, which is a
            // credentials check. A PID namespace is stronger and structural: the job cannot
            // NAME them, so there is nothing to check. `--proc /proc` then shows only the
            // job's own tree (measured: 5 entries instead of 429).
            //
            // Why NOT for a rank. `bwrap --pidns FD` is parent-only — with `--unshare-pid`
            // it makes the given namespace the PARENT of a fresh one, and without it bwrap
            // fails outright ("Can't send pid: Invalid argument", measured on 0.6.1). So
            // ranks cannot JOIN a shared PID namespace the way they join the shared user
            // namespace, and giving each rank `--unshare-pid` would put every rank in its
            // own namespace where it cannot even name its peers. That is precisely how
            // sibling USER namespaces broke Cray MPICH's Cross Memory Attach, and it is the
            // same mistake one layer down. The job cage holds no ranks, so this costs
            // nothing there; MPI started directly from the batch script stays in ONE
            // namespace and keeps CMA.
            a.push("--unshare-pid".into());
        }
        if kind == CageKind::Rank {
            for dev in FABRIC_DEVICES {
                a.push("--dev-bind-try".into());
                a.push((*dev).to_string());
                a.push((*dev).to_string());
            }
        }

        // Expose GPUs + NVLink into the cage when present (see GPU_DEVICES). Safe
        // unconditionally: --dev-bind-try skips absent nodes, and these are device
        // nodes, not filesystem — they don't widen the home-hiding cage.
        for dev in GPU_DEVICES {
            a.push("--dev-bind-try".into());
            a.push((*dev).to_string());
            a.push((*dev).to_string());
        }

        // De-dup within each set so a path that is both in the floor and the
        // config (e.g. /users) is only mounted once.
        let push_uniq = |v: &mut Vec<String>, p: String| {
            if !v.contains(&p) {
                v.push(p);
            }
        };
        let mut hide: Vec<String> = Vec::new();
        for p in HIDDEN_FLOOR {
            push_uniq(&mut hide, (*p).to_string());
        }
        for p in &self.deny_read {
            if p.starts_with('/') {
                push_uniq(&mut hide, p.clone());
            }
        }
        let mut allow: Vec<String> = Vec::new();
        for p in &self.allow_read {
            // "./" / "." is the project dir == workdir, bound writable below. Only
            // absolute carve-outs are safe to re-expose; skip relative ones.
            if p == "./" || p == "." {
                continue;
            }
            if p.starts_with('/') {
                push_uniq(&mut allow, p.clone());
            }
        }

        enum Op {
            Hide(String),
            Allow(String),
        }
        let mut ops: Vec<Op> = Vec::new();
        ops.extend(hide.into_iter().map(Op::Hide));
        ops.extend(allow.into_iter().map(Op::Allow));
        // Shallowest first so deeper (more specific) rules apply last and win.
        ops.sort_by_key(|op| {
            let p = match op {
                Op::Hide(p) | Op::Allow(p) => p,
            };
            p.trim_end_matches('/').matches('/').count()
        });
        for op in ops {
            match op {
                Op::Hide(p) => {
                    a.push("--tmpfs".into());
                    a.push(p);
                }
                Op::Allow(p) => {
                    a.push("--ro-bind".into());
                    a.push(p.clone());
                    a.push(p);
                }
            }
        }

        if workdir.starts_with('/') {
            a.push("--bind".into());
            a.push(workdir.to_string());
            a.push(workdir.to_string());
        }

        // Writable roots (sandbox.filesystem.allowWrite): the cage is default-deny
        // for writes (root is --ro-bind), so each allowed root is bound read-write.
        // The workdir above is always writable (job output); these add scratch etc.
        for p in &self.allow_write {
            if p.starts_with('/') {
                a.push("--bind".into());
                a.push(p.clone());
                a.push(p.clone());
            }
        }
        // denyWrite takes precedence over allowWrite: re-bind the path read-only
        // (reads still allowed, writes blocked). Emitted after the write binds so
        // it wins over a writable ancestor.
        for p in &self.deny_write {
            if p.starts_with('/') {
                a.push("--ro-bind".into());
                a.push(p.clone());
                a.push(p.clone());
            }
        }

        // denyRead entries that land inside a writable root (the workdir or an
        // allowWrite root) must be re-hidden AFTER the writable binds: the
        // ops-loop tmpfs above runs BEFORE the workdir `--bind`, which would
        // re-expose the path. Relative denyRead is resolved onto the workdir so it
        // is honored on compute exactly as on login rather than silently dropped
        // (previously any non-absolute entry was skipped in the ops loop). (F22)
        for p in &self.deny_read {
            if let Some(abs) = abs_for_cage(p, workdir) {
                if is_under_writable_root(&abs, workdir, &self.allow_write) {
                    a.push("--tmpfs".into());
                    a.push(abs);
                }
            }
        }

        // F6b — mask auto-exec paths within every writable root (workdir + allowWrite)
        // so a job can't plant a payload that fires later on login (AV2). Files get a
        // `/dev/null` bind, directories a fresh tmpfs — both apply whether or not the
        // path already exists (see AUTO_EXEC_FILES).
        let mut writable_roots: Vec<&str> = Vec::new();
        if workdir.starts_with('/') {
            writable_roots.push(workdir);
        }
        for p in &self.allow_write {
            if p.starts_with('/') {
                writable_roots.push(p);
            }
        }
        for root in &writable_roots {
            let root = root.trim_end_matches('/');
            for rel in AUTO_EXEC_DIRS {
                a.push("--tmpfs".into());
                a.push(format!("{root}/{rel}"));
            }
            for rel in AUTO_EXEC_RO_FILES {
                let path = format!("{root}/{rel}");
                a.push("--ro-bind-try".into());
                a.push(path.clone());
                a.push(path);
            }
            // `.git/config` must stay READABLE — git needs it to operate, and masking it
            // empty would break the job. It also always exists wherever `.git` does, so
            // the skip-if-absent form is not a hole here. Read-only is enough: the risk
            // is a rewritten remote/`core.hooksPath`, not the file appearing.
            let mut protect = |rel: &str| {
                let path = format!("{root}/{rel}");
                a.push("--ro-bind-try".into());
                a.push(path.clone());
                a.push(path);
            };
            if !self.allow_git_config {
                protect(".git/config");
            }
        }

        // Credential files: bind /dev/null over each so the job reads EMPTY, not
        // the real secret (mirrors the login cage's masking). Emitted AFTER the
        // workdir bind so a secret sitting inside the writable workdir is
        // re-denied. `--ro-bind /dev/null <dest>` also works when the path is
        // absent (bwrap creates an empty file there), so no stat is needed.
        // A `~`-prefixed entry (e.g. ~/.aws/credentials) lives under home, which the
        // /users tmpfs already hides; a workdir-relative entry is resolved onto the
        // workdir so it is masked instead of silently dropped. (F22)
        for f in &self.deny_files {
            if let Some(abs) = abs_for_cage(f, workdir) {
                a.push("--ro-bind".into());
                a.push("/dev/null".into());
                a.push(abs);
            }
        }

        // Drop credential env vars so a secret in the broker's session env never
        // reaches the job (sandbox.credentials.envVars). Order-independent.
        for name in &self.unset_env {
            if !name.is_empty() {
                a.push("--unsetenv".into());
                a.push(name.clone());
            }
        }

        a.push("--unshare-net".into());
        a
    }
}

/// Bounded credential auto-scan limits — keep it from ever becoming a filesystem-
/// wide walk. `MAX_DEPTH` counts subdirectory levels below the workdir; `MAX_ENTRIES`
/// is a circuit-breaker on total directory entries visited across the whole scan.
const SCAN_MAX_DEPTH: usize = 4;
const SCAN_MAX_ENTRIES: usize = 20_000;

/// True if `name` (a file basename) looks like a credential file. Mirrors the
/// standard `permissions.deny` Read() globs (`.env*`, `*.env`, `*.pem`, `*.key`,
/// `credentials`) plus the obvious SSH/git secrets and the common keystore/token
/// files that the base globs miss (F23). (Sourcing the pattern set from the user's
/// actual Read() globs is a reuse-time refinement.) This is a best-effort
/// defense-in-depth scan of the WORKDIR only — the authoritative masks are the
/// human's explicit `sandbox.credentials.files` and the HIDDEN_FLOOR.
fn matches_credential(name: &str) -> bool {
    name.starts_with(".env")            // .env, .env.local   (Read(//**/.env*))
        || name.ends_with(".env")       // foo.env            (Read(//**/*.env))
        || name.ends_with(".pem")       //                    (Read(//**/*.pem))
        || name.ends_with(".key")       //                    (Read(//**/*.key))
        || name.ends_with(".p12")       // PKCS#12 keystore/cert bundle
        || name.ends_with(".pfx")       // PKCS#12 (Windows naming)
        || name.ends_with(".jks")       // Java keystore
        || name.ends_with(".keystore")  // Java/Android keystore
        || name.ends_with(".ppk")       // PuTTY private key
        || name == "credentials"        //                    (Read(//**/credentials))
        || name == ".git-credentials"
        || name == ".netrc"
        || name == ".pgpass"            // PostgreSQL password file
        || name == ".npmrc"             // npm auth token
        || name == ".pypirc"            // PyPI upload token
        || name == ".dockercfg"         // legacy docker registry auth
        || name == ".htpasswd"          // Apache basic-auth hashes
        || name.starts_with("id_rsa")
        || name.starts_with("id_dsa")
        || name.starts_with("id_ed25519")
        || name.starts_with("id_ecdsa")
}

/// Result of a credential auto-scan: the matched files plus whether the scan ran
/// to completion. `truncated` is set only when the entry BUDGET was exhausted (the
/// agent-gameable, anomalous case) — the depth cap is a designed bound and is not
/// flagged, so a normal deep project doesn't spam the warning. (F21)
struct ScanResult {
    files: Vec<String>,
    truncated: bool,
}

/// Bounded walk of `root` (the workdir) returning absolute paths of files whose
/// basename matches a credential pattern. Depth- and entry-count-capped so it can
/// never turn into a filesystem-wide walk; symlinks are not followed. Any error
/// yields fewer results (fail-safe — the base cage still hides homes).
fn scan_credentials(root: &Path) -> ScanResult {
    scan_credentials_capped(root, SCAN_MAX_DEPTH, SCAN_MAX_ENTRIES)
}

/// Inner scan with explicit caps, so tests can drive the entry budget cheaply
/// without materializing SCAN_MAX_ENTRIES files.
fn scan_credentials_capped(root: &Path, depth: usize, max_entries: usize) -> ScanResult {
    let mut out = Vec::new();
    let mut budget = max_entries;
    let mut truncated = false;
    scan_credentials_rec(root, depth, &mut budget, &mut out, &mut truncated);
    ScanResult { files: out, truncated }
}

fn scan_credentials_rec(
    dir: &Path,
    depth: usize,
    budget: &mut usize,
    out: &mut Vec<String>,
    truncated: &mut bool,
) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        if *budget == 0 {
            *truncated = true; // early exit: the walk is incomplete (F21)
            return;
        }
        *budget -= 1;
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_symlink() {
            continue; // don't follow symlinks out of the workdir
        }
        if ft.is_dir() {
            if depth > 0 {
                scan_credentials_rec(&entry.path(), depth - 1, budget, out, truncated);
            }
        } else if ft.is_file() && matches_credential(&entry.file_name().to_string_lossy()) {
            if let Some(s) = entry.path().to_str() {
                out.push(s.to_string());
            }
        }
    }
}

/// Single-quote a token for safe inclusion in the generated shell `exec` line
/// (paths may contain spaces or shell metacharacters).
pub fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// True if ANY component of `p` (an intermediate directory OR the leaf) is a symlink.
/// bwrap resolves symlinks on the bind source, and an `lstat` of the full path only
/// classifies the LEAF — so an intermediate symlink (`/a/b/c` with `/a/b` a symlink)
/// would slip a leaf-only check. Walk each prefix and lstat it. (F20)
fn path_has_symlink_component(p: &str) -> bool {
    let mut acc = PathBuf::new();
    for comp in Path::new(p).components() {
        acc.push(comp);
        if std::fs::symlink_metadata(&acc)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {

    #[test]
    fn settings_sources_are_all_write_denied_by_the_shipped_config() {
        // THE PAIRING. Everything the broker reads policy FROM must be something the
        // agent cannot WRITE, or the agent edits its own cage - and, once the network
        // allowlist lives there, grants itself egress. The two lists are the same list
        // written twice, in different files and different languages, which is exactly the
        // duplication that has bitten this project three times. So assert them against
        // each other rather than trusting that both get updated.
        //
        // denyWrite is enforced by the bwrap filesystem cage, which THREAT-MODEL.md counts
        // as load-bearing (policy ours, enforcement the runtime's today, ours after 6a) -
        // NOT by the runtime's advisory permission rules.
        let shipped = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../user-config/settings.json");
        let text = match std::fs::read_to_string(&shipped) {
            Ok(t) => t,
            // The shipped config is not present in every checkout layout; skipping is
            // better than a false failure, and the install-time path covers deployment.
            Err(_) => return,
        };
        let cfg: serde_json::Value = serde_json::from_str(&text).expect("shipped settings must be valid JSON");
        let deny: Vec<String> = cfg["sandbox"]["filesystem"]["denyWrite"]
            .as_array()
            .expect("shipped settings must carry sandbox.filesystem.denyWrite")
            .iter()
            .map(|v| v.as_str().unwrap_or_default().to_string())
            .collect();

        for (from_home, rel) in SETTINGS_SOURCES {
            let want = if from_home { format!("~/{rel}") } else { rel.to_string() };
            assert!(
                deny.iter().any(|d| d == &want),
                "the broker reads policy from {want:?} but the shipped denyWrite does not \
                 protect it - the agent could edit its own cage. denyWrite = {deny:?}"
            );
        }
    }

    #[test]
    fn output_filenames_allow_slurm_specifiers_but_not_the_job_name() {
        // %x is the parser differential: slurmd expands it AFTER husk validates, and the
        // job name is agent-supplied, so <workdir>/%x with a job name of `..` resolves
        // above the workdir. Everything allowed expands to a number, node or user.
        for ok in ["LOG.exp.mch_icon-ch1_small.run.%j.o", "slurm-%j.out", "a_%A_%a-%N.log", "x%%y"] {
            assert!(is_valid_output_filename(ok), "must accept {ok}");
        }
        for bad in ["%x.log", "log.%q", "trailing%", "a/b", "..", ".", "", "with space.o"] {
            assert!(!is_valid_output_filename(bad), "must refuse {bad:?}");
        }
    }

    #[test]
    fn confinement_follows_symlinks_and_rejects_traversal() {
        // A string prefix check passes a symlink pointing out of the tree; slurmd would
        // follow it and write outside the cage's blast radius. Canonicalise instead.
        let root = std::env::temp_dir().join(format!("husk-conf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("run")).unwrap();
        let w = root.to_string_lossy().to_string();

        assert!(confine_under_workdir(&format!("{w}/run"), &w).is_ok(), "a descendant is fine");
        assert!(confine_under_workdir(&w, &w).is_ok(), "the workdir itself is fine");
        assert!(confine_under_workdir(&format!("{w}/run/.."), &w).is_ok(), "resolves back inside");
        assert!(confine_under_workdir(&format!("{w}/.."), &w).is_err(), "traversal must fail");

        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink("/tmp", root.join("out"));
            assert!(
                confine_under_workdir(&format!("{w}/out"), &w).is_err(),
                "a symlink out of the workdir must not pass"
            );
        }
        // `/work2` must not count as being under `/work`: the check is component-wise.
        let sib = format!("{w}x");
        std::fs::create_dir_all(&sib).unwrap();
        assert!(confine_under_workdir(&sib, &w).is_err(), "sibling prefix must not pass");

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&sib);
    }
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn path_has_symlink_component_catches_intermediate_symlink() {
        let dir = std::env::temp_dir().join(format!("husk-symcomp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("real/models")).unwrap();
        // A clean, all-real path: not flagged.
        let clean = dir.join("real/models");
        assert!(!path_has_symlink_component(clean.to_str().unwrap()));
        // Symlink an INTERMEDIATE component: link -> real, then link/models must be flagged
        // even though its own leaf ("models") is a real dir.
        symlink(dir.join("real"), dir.join("link")).unwrap();
        let via_link = dir.join("link/models");
        assert!(
            path_has_symlink_component(via_link.to_str().unwrap()),
            "intermediate symlink not detected"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn drop_floor_overlapping_allows_protects_the_floor() {
        let mut p = FsPolicy {
            allow_read: vec!["/users".into(), "/users/victim".into(), "/scratch/x".into()],
            allow_write: vec!["/users/me/out".into(), "/data".into()],
            ..Default::default()
        };
        p.drop_floor_overlapping_allows();
        // Floor-overlapping entries are gone; unrelated ones stay.
        assert_eq!(p.allow_read, vec!["/scratch/x".to_string()]);
        assert_eq!(p.allow_write, vec!["/data".to_string()]);
    }

    #[test]
    fn is_workdir_allowed_confines_to_safe_paths() {
        assert!(is_workdir_allowed("/scratch/proj"));
        assert!(is_workdir_allowed("/capstor/scratch/cscs/me/run"));
        assert!(!is_workdir_allowed("/")); // root
        assert!(!is_workdir_allowed("/users")); // the floor itself
        assert!(!is_workdir_allowed("/users/victim")); // under the floor (a home)
        assert!(!is_workdir_allowed("relative/path")); // not absolute
        assert!(!is_workdir_allowed("")); // empty
        assert!(!is_workdir_allowed("/scratch/../users/victim")); // traversal
    }

    #[test]
    fn parse_extracts_filesystem_and_ignores_other_keys() {
        let json = r#"{
            "enableAllProjectMcpServers": false,
            "permissions": { "deny": ["Bash(curl *)"] },
            "sandbox": { "filesystem": { "denyRead": ["/users"], "allowRead": ["./"] } }
        }"#;
        let p = FsPolicy::parse(json);
        assert_eq!(p.deny_read, vec!["/users"]);
        assert_eq!(p.allow_read, vec!["./"]);
    }

    #[test]
    fn parse_failsafe_on_garbage_or_missing_block() {
        assert_eq!(FsPolicy::parse("not json at all"), FsPolicy::default());
        assert_eq!(FsPolicy::parse("{}"), FsPolicy::default());
        assert_eq!(FsPolicy::parse(r#"{"sandbox":{}}"#), FsPolicy::default());
    }

    #[test]
    fn union_dedups_and_is_additive() {
        let mut a = FsPolicy {
            allow_read: vec!["./".into()],
            deny_read: vec!["/users".into()],
            deny_files: vec!["/proj/.env".into()],
            allow_write: vec!["/scratch".into()],
            ..Default::default()
        };
        a.union(FsPolicy {
            allow_read: vec!["./".into(), "/users/x/miniconda3".into()],
            deny_files: vec!["/proj/.env".into(), "/proj/key.pem".into()],
            allow_write: vec!["/scratch".into(), "/capstor/scr".into()],
            ..Default::default()
        });
        assert_eq!(a.allow_read, vec!["./", "/users/x/miniconda3"]);
        assert_eq!(a.deny_read, vec!["/users"]);
        assert_eq!(a.deny_files, vec!["/proj/.env", "/proj/key.pem"]);
        assert_eq!(a.allow_write, vec!["/scratch", "/capstor/scr"]);
    }

    fn joined(p: &FsPolicy, workdir: &str) -> String {
        p.compute_bwrap_args(workdir).join(" ")
    }

    #[test]
    fn default_policy_still_hides_homes_and_isolates_net() {
        // Fail-safe floor: even with NO config, /users is hidden and net unshared.
        let cmd = joined(&FsPolicy::default(), "/work");
        assert!(cmd.contains("--ro-bind / /"));
        assert!(cmd.contains("--tmpfs /users"));
        assert!(cmd.contains("--unshare-net"));
        assert!(cmd.contains("--bind /work /work"));
    }

    #[test]
    fn allowread_carveout_is_reexposed_after_the_hide() {
        let p = FsPolicy {
            allow_read: vec!["./".into(), "/users/x/miniconda3".into()],
            deny_read: vec!["/users".into()],
            ..Default::default()
        };
        let args = p.compute_bwrap_args("/users/x/proj");
        let cmd = args.join(" ");
        // miniconda carve-out present as a read-only bind...
        assert!(cmd.contains("--ro-bind /users/x/miniconda3 /users/x/miniconda3"));
        // ...and applied AFTER the /users tmpfs so it actually re-exposes it.
        let hide = args.iter().position(|a| a == "/users").unwrap();
        let allow = args.iter().position(|a| a == "/users/x/miniconda3").unwrap();
        assert!(hide < allow, "the /users hide must precede the miniconda carve-out");
        // "./" is not bound as a carve-out; it's the writable workdir instead.
        assert!(cmd.contains("--bind /users/x/proj /users/x/proj"));
    }

    #[test]
    fn extra_denyread_becomes_a_tmpfs() {
        let p = FsPolicy {
            allow_read: vec![],
            deny_read: vec!["/capstor/secret".into()],
            ..Default::default()
        };
        assert!(joined(&p, "/work").contains("--tmpfs /capstor/secret"));
    }

    #[test]
    fn exposes_gpus_and_shm_for_single_node_multigpu() {
        // GPU device carve-outs + /dev/shm are present even with no config, so a
        // single-process multi-GPU NVLink job can see the devices inside the cage.
        let cmd = joined(&FsPolicy::default(), "/work");
        assert!(cmd.contains("--tmpfs /dev/shm"));
        assert!(cmd.contains("--dev-bind-try /dev/nvidiactl /dev/nvidiactl"));
        assert!(cmd.contains("--dev-bind-try /dev/nvidia0 /dev/nvidia0"));
        assert!(cmd.contains("--dev-bind-try /dev/nvidia-uvm /dev/nvidia-uvm"));
    }

    #[test]
    fn rank_cage_gets_the_fabric_and_no_private_shm() {
        // The two measured differences from the job cage, and the only two.
        let job = joined(&FsPolicy::default(), "/work");
        let rank = FsPolicy::default().rank_bwrap_args("/work").join(" ");

        assert!(job.contains("--tmpfs /dev/shm"), "job cage keeps its own /dev/shm");
        assert!(
            !rank.contains("--tmpfs /dev/shm"),
            "a per-rank tmpfs /dev/shm HANGS same-node MPI - the per-job dir is bound by \
             the per-task wrapper instead: {rank}"
        );
        assert!(!job.contains("/dev/cxi"), "a plain job has no business on the fabric");
        assert!(rank.contains("--dev-bind-try /dev/cxi0 /dev/cxi0"), "{rank}");
        assert!(rank.contains("--dev-bind-try /dev/cxi3 /dev/cxi3"), "{rank}");
        assert!(
            !rank.contains("cxi_sbl"),
            "the admin base-link device is 0600 root and must never be bound: {rank}"
        );
    }

    // THE PID NAMESPACE IS THE JOB CAGE'S ALONE, and the asymmetry is load-bearing.
    //
    // A job in its own PID namespace cannot see, signal or process_vm_readv the un-caged
    // step-broker and egress proxy — which is stronger than the PR_SET_DUMPABLE credentials
    // check that defends them otherwise, because there is nothing left to name.
    //
    // A RANK must not have one. `bwrap --pidns FD` is parent-only (with `--unshare-pid` it
    // makes the given namespace the parent of a fresh one; without it bwrap fails outright,
    // "Can't send pid: Invalid argument", measured on 0.6.1), so ranks cannot join a shared
    // PID namespace the way they join the shared user namespace. Giving each rank
    // `--unshare-pid` would put every rank in its own namespace, unable to name its peers —
    // which is exactly how sibling USER namespaces broke Cray MPICH's Cross Memory Attach
    // and killed ICON. Same mistake, one layer down.
    #[test]
    fn only_the_job_cage_unshares_pids_because_a_rank_must_still_name_its_peers() {
        let job = joined(&FsPolicy::default(), "/work");
        let rank = FsPolicy::default().rank_bwrap_args("/work").join(" ");

        assert!(
            job.contains("--unshare-pid"),
            "the job cage must hide the node's other processes: {job}"
        );
        assert!(
            !rank.contains("--unshare-pid"),
            "a rank in its own PID namespace cannot name its peers, so CMA dies exactly as \
             it did with sibling user namespaces - ICON's failure: {rank}"
        );
        // ...and a fresh /proc is what makes the namespace visible as isolation rather than
        // a flag: without it the cage would still show the host's process table.
        assert!(job.contains("--proc /proc"), "{job}");
    }

    #[test]
    fn rank_cage_keeps_every_containment_property_of_the_job_cage() {
        // The fabric is a RESOURCE delta, not a containment one: a rank must still get
        // the read-only root, hidden homes, and no network.
        let p = FsPolicy {
            allow_read: vec![],
            deny_read: vec!["/users".into()],
            ..Default::default()
        };
        let rank = p.rank_bwrap_args("/work").join(" ");
        assert!(rank.contains("--ro-bind / /"), "{rank}");
        assert!(rank.contains("--tmpfs /users"), "{rank}");
        assert!(rank.contains("--unshare-net"), "single node needs no IP - measured: {rank}");
    }

    #[test]
    fn credential_masks_are_not_static_bwrap_args() {
        // The MUNGE mask is applied by the re-exec guard on the COMPUTE NODE, never here:
        // `--tmpfs DEST` kills bwrap when DEST is absent under a read-only root, and again
        // when two list entries resolve to the same directory (/var/run -> /run). Both
        // shipped once and took the whole cage down. Only the compute node knows which
        // paths exist, so the decision cannot be made at submit time.
        // Behaviour is pinned by policy::tests::credential_mask_is_applied_only_for_paths_that_exist.
        let cmd = joined(&FsPolicy::default(), "/work");
        for d in CREDENTIAL_SOCKET_DIRS {
            assert!(
                !cmd.contains(&format!("--tmpfs {d}")),
                "{d} must not be a static arg - see the constant's docs"
            );
        }
    }

    #[test]
    fn floor_and_config_denyread_of_same_path_dedup() {
        // /users is in both the fail-safe floor and the config — mount it once.
        let p = FsPolicy {
            allow_read: vec![],
            deny_read: vec!["/users".into()],
            ..Default::default()
        };
        let n = p
            .compute_bwrap_args("/work")
            .windows(2)
            .filter(|w| w[0] == "--tmpfs" && w[1] == "/users")
            .count();
        assert_eq!(n, 1, "/users must be tmpfs'd exactly once");
    }

    // ── credential file denies (sandbox.credentials.files) ──────────────────

    #[test]
    fn parse_extracts_credential_files_and_ignores_mode() {
        let json = r#"{
            "sandbox": {
                "filesystem": { "denyRead": ["/users"] },
                "credentials": { "files": [
                    { "path": "/proj/.env", "mode": "deny" },
                    { "path": "/proj/key.pem", "mode": "mask" }
                ] }
            }
        }"#;
        let p = FsPolicy::parse(json);
        // mask and deny alike land in deny_files (mask degrades to deny).
        assert_eq!(p.deny_files, vec!["/proj/.env", "/proj/key.pem"]);
    }

    #[test]
    fn parse_no_credentials_block_means_no_deny_files() {
        let json = r#"{ "sandbox": { "filesystem": { "denyRead": ["/users"] } } }"#;
        assert!(FsPolicy::parse(json).deny_files.is_empty());
        // empty-path entries are dropped, not emitted as a bind over "/".
        let empty = r#"{ "sandbox": { "credentials": { "files": [ { "path": "" } ] } } }"#;
        assert!(FsPolicy::parse(empty).deny_files.is_empty());
    }

    #[test]
    fn credential_file_is_devnull_bound_after_the_workdir() {
        // A secret inside the writable workdir must be re-denied, so the
        // /dev/null bind has to come AFTER the workdir --bind.
        let p = FsPolicy {
            deny_files: vec!["/users/x/proj/.env".into()],
            ..Default::default()
        };
        let args = p.compute_bwrap_args("/users/x/proj");
        assert!(args
            .join(" ")
            .contains("--ro-bind /dev/null /users/x/proj/.env"));
        let workdir = args.iter().position(|a| a == "/users/x/proj").unwrap();
        let secret = args.iter().position(|a| a == "/users/x/proj/.env").unwrap();
        assert!(
            workdir < secret,
            "the /dev/null credential bind must follow the workdir bind so it overrides it"
        );
    }

    #[test]
    fn non_credential_files_are_not_denied() {
        // Precision: only declared entries are masked; a sibling file is untouched.
        let p = FsPolicy {
            deny_files: vec!["/proj/.env".into()],
            ..Default::default()
        };
        let cmd = joined(&p, "/proj");
        assert!(cmd.contains("--ro-bind /dev/null /proj/.env"));
        assert!(!cmd.contains("/proj/data.txt"));
    }

    #[test]
    fn relative_credential_path_is_skipped_covered_by_home_tmpfs() {
        // ~/.aws/... lives under home, already hidden by the /users tmpfs; a
        // non-absolute entry must NOT become a bind over a bogus path.
        let p = FsPolicy {
            deny_files: vec!["~/.aws/credentials".into()],
            ..Default::default()
        };
        assert!(!joined(&p, "/work").contains("--ro-bind /dev/null ~"));
    }

    // ── symlink-escape guard on allow carve-outs ────────────────────────────

    #[test]
    fn drop_symlinked_carveouts_removes_symlink_leaf_allows() {
        let mut p = FsPolicy {
            allow_read: vec!["/users/x/miniconda3".into(), "/users/x/evil-link".into()],
            allow_write: vec!["/scr/real".into(), "/scr/link".into()],
            ..Default::default()
        };
        // classifier: the *-link / .../link paths are symlinks; the rest are real.
        p.drop_symlinked_carveouts(|path| path.ends_with("-link") || path.ends_with("/link"));
        assert_eq!(p.allow_read, vec!["/users/x/miniconda3"], "symlink-leaf read carve-out dropped");
        assert_eq!(p.allow_write, vec!["/scr/real"], "symlink-leaf write carve-out dropped");
    }

    // ── env credential masking (sandbox.credentials.envVars) ────────────────

    #[test]
    fn parse_extracts_credential_env_vars() {
        let json = r#"{ "sandbox": { "credentials": { "envVars": [
            { "name": "AWS_SECRET_ACCESS_KEY", "mode": "deny" },
            { "name": "GH_TOKEN", "mode": "mask" }
        ] } } }"#;
        let p = FsPolicy::parse(json);
        assert_eq!(p.unset_env, vec!["AWS_SECRET_ACCESS_KEY", "GH_TOKEN"]);
    }

    #[test]
    fn credential_env_vars_become_unsetenv() {
        let p = FsPolicy {
            unset_env: vec!["AWS_SECRET_ACCESS_KEY".into()],
            ..Default::default()
        };
        assert!(joined(&p, "/work").contains("--unsetenv AWS_SECRET_ACCESS_KEY"));
        // an empty name must not emit a bare --unsetenv
        let empty = FsPolicy { unset_env: vec!["".into()], ..Default::default() };
        assert!(!joined(&empty, "/work").contains("--unsetenv"));
    }

    // ── write model (sandbox.filesystem.allowWrite / denyWrite) ─────────────

    #[test]
    fn parse_extracts_allow_and_deny_write() {
        let json = r#"{ "sandbox": { "filesystem": {
            "allowWrite": ["/capstor/scratch/x"], "denyWrite": ["/capstor/scratch/x/.git"]
        } } }"#;
        let p = FsPolicy::parse(json);
        assert_eq!(p.allow_write, vec!["/capstor/scratch/x"]);
        assert_eq!(p.deny_write, vec!["/capstor/scratch/x/.git"]);
    }

    #[test]
    fn default_write_policy_is_ro_root_plus_writable_workdir_only() {
        // No allowWrite: the cage is default-deny for writes — root is read-only,
        // and the ONLY writable bind is the workdir.
        let args = FsPolicy::default().compute_bwrap_args("/work");
        assert!(args.join(" ").contains("--ro-bind / /"));
        let writable_binds = args
            .windows(3)
            .filter(|w| w[0] == "--bind")
            .map(|w| w[1].clone())
            .collect::<Vec<_>>();
        assert_eq!(writable_binds, vec!["/work"], "only the workdir is writable by default");
    }

    #[test]
    fn allow_write_is_bound_read_write() {
        let p = FsPolicy {
            allow_write: vec!["/capstor/scratch/x".into()],
            ..Default::default()
        };
        assert!(joined(&p, "/work").contains("--bind /capstor/scratch/x /capstor/scratch/x"));
    }

    #[test]
    fn split_file_denies_routes_files_to_devnull_keeps_dirs_as_tmpfs() {
        let mut p = FsPolicy {
            deny_read: vec!["/users".into(), "/etc/secret.conf".into()],
            ..Default::default()
        };
        // classifier: only /etc/secret.conf is a file (the rest are dirs).
        p.split_file_denies(|path| path == "/etc/secret.conf");
        assert_eq!(p.deny_read, vec!["/users"], "dir stays in deny_read (tmpfs)");
        assert_eq!(p.deny_files, vec!["/etc/secret.conf"], "file moves to /dev/null");
        let cmd = p.compute_bwrap_args("/work").join(" ");
        assert!(cmd.contains("--tmpfs /users"));
        assert!(cmd.contains("--ro-bind /dev/null /etc/secret.conf"));
        assert!(!cmd.contains("--tmpfs /etc/secret.conf"), "a file must not be tmpfs'd");
    }

    #[test]
    fn deny_write_rebinds_read_only_after_allow_write() {
        // denyWrite takes precedence: a subpath of a writable root is re-bound
        // read-only, and that ro-bind must come AFTER the allowWrite --bind.
        let p = FsPolicy {
            allow_write: vec!["/scr".into()],
            deny_write: vec!["/scr/protected".into()],
            ..Default::default()
        };
        let args = p.compute_bwrap_args("/work");
        assert!(args
            .join(" ")
            .contains("--ro-bind /scr/protected /scr/protected"));
        let wr = args.iter().position(|a| a == "/scr").unwrap();
        let ro = args.iter().position(|a| a == "/scr/protected").unwrap();
        assert!(wr < ro, "denyWrite ro-bind must follow the allowWrite bind to win");
    }

    // ── F6a: bounded credential auto-scan ───────────────────────────────────

    #[test]
    fn matches_credential_recognizes_secrets_and_ignores_normal_files() {
        for n in [
            ".env", ".env.local", "prod.env", "server.pem", "tls.key", "credentials",
            ".git-credentials", ".netrc", "id_rsa", "id_rsa.pub", "id_ed25519",
            // F23 — keystore/token files the base globs miss
            "keystore.p12", "cert.pfx", "release.jks", "app.keystore", "server.ppk",
            ".pgpass", ".npmrc", ".pypirc", ".dockercfg", ".htpasswd", "id_dsa",
        ] {
            assert!(matches_credential(n), "{n} should match");
        }
        for n in [
            "README.md", "main.rs", "data.txt", "keyboard.json", "env.sample",
            "Cargo.toml", "notes", "model.pt", "config.toml", "npmrc.example",
        ] {
            assert!(!matches_credential(n), "{n} should NOT match");
        }
    }

    #[test]
    fn scan_credentials_finds_shallow_secrets_and_respects_the_depth_cap() {
        use std::fs;
        let root = std::env::temp_dir().join(format!("husk-scan-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("a")).unwrap();
        fs::create_dir_all(root.join("1/2/3/4/5/6")).unwrap(); // deeper than MAX_DEPTH
        fs::write(root.join(".env"), "S=1").unwrap();
        fs::write(root.join("README.md"), "hi").unwrap();
        fs::write(root.join("a/server.pem"), "----").unwrap();
        fs::write(root.join("1/2/3/4/5/6/deep.pem"), "x").unwrap();

        let names: Vec<String> = scan_credentials(&root)
            .files
            .iter()
            .map(|p| p.rsplit('/').next().unwrap().to_string())
            .collect();
        assert!(names.contains(&".env".to_string()), "top-level secret found");
        assert!(names.contains(&"server.pem".to_string()), "shallow secret found");
        assert!(!names.contains(&"README.md".to_string()), "non-secret ignored");
        assert!(!names.contains(&"deep.pem".to_string()), "beyond depth cap skipped");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn scan_reports_truncation_when_the_entry_budget_is_exhausted() {
        use std::fs;
        let root = std::env::temp_dir().join(format!("husk-trunc-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        for i in 0..10 {
            fs::write(root.join(format!("pad{i}.txt")), "x").unwrap();
        }
        // A generous budget finishes the walk: not truncated.
        assert!(!scan_credentials_capped(&root, 4, 1000).truncated);
        // A tiny budget is exhausted before the walk finishes: flagged truncated so
        // the operator is warned the scan is incomplete (F21). An agent could pad the
        // tree like this to starve the scanner past a real secret.
        assert!(
            scan_credentials_capped(&root, 4, 3).truncated,
            "entry-budget exhaustion must be reported, not silently swallowed"
        );
        let _ = fs::remove_dir_all(&root);
    }

    // ── F22: relative denyRead / denyFiles honored on compute ────────────────

    #[test]
    fn relative_denyread_is_honored_and_wins_over_the_writable_workdir_bind() {
        // A relative denyRead ("secrets") was previously dropped on compute (only
        // absolute paths were emitted), so the workdir --bind re-exposed it — the
        // login cage hid it, compute didn't. It must now be tmpfs'd, and AFTER the
        // workdir bind so the writable bind can't re-expose it.
        let p = FsPolicy {
            deny_read: vec!["secrets".into(), "./nested/creds".into()],
            ..Default::default()
        };
        let args = p.compute_bwrap_args("/scratch/proj");
        let cmd = args.join(" ");
        assert!(cmd.contains("--tmpfs /scratch/proj/secrets"), "relative denyRead not honored");
        assert!(cmd.contains("--tmpfs /scratch/proj/nested/creds"), "./-prefixed not honored");
        let workdir = args.iter().position(|a| a == "/scratch/proj").unwrap();
        let hidden = args.iter().position(|a| a == "/scratch/proj/secrets").unwrap();
        assert!(workdir < hidden, "the denyRead tmpfs must follow the workdir bind to win");
    }

    #[test]
    fn absolute_denyread_under_the_workdir_is_rehidden_after_the_bind() {
        // An ABSOLUTE denyRead that happens to sit inside the writable workdir is
        // re-hidden after the workdir bind too, else the --bind re-exposes it.
        let p = FsPolicy {
            deny_read: vec!["/scratch/proj/secret".into()],
            ..Default::default()
        };
        let args = p.compute_bwrap_args("/scratch/proj");
        let workdir = args.iter().position(|a| a == "/scratch/proj").unwrap();
        // the LAST tmpfs of the secret must come after the workdir bind
        let last_hide = args
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == "/scratch/proj/secret")
            .map(|(i, _)| i)
            .next_back()
            .unwrap();
        assert!(workdir < last_hide, "denyRead under the workdir must be re-hidden after the bind");
    }

    #[test]
    fn home_relative_denyread_is_left_to_the_floor_not_bound_under_workdir() {
        // A `~`-prefixed entry lives under home (hidden by the /users floor); it must
        // NOT be mis-resolved into a bogus /workdir/~ path.
        let p = FsPolicy {
            deny_read: vec!["~/.aws".into()],
            deny_files: vec!["~/.aws/credentials".into()],
            ..Default::default()
        };
        let cmd = p.compute_bwrap_args("/scratch/proj").join(" ");
        assert!(!cmd.contains("/scratch/proj/~"), "~ entry must not be joined onto the workdir");
        assert!(!cmd.contains("--ro-bind /dev/null /scratch/proj/~"));
    }

    #[test]
    fn relative_credential_file_under_workdir_is_masked() {
        // A workdir-relative credential file is resolved onto the workdir and masked
        // with /dev/null (previously dropped, since only absolute paths were emitted).
        let p = FsPolicy {
            deny_files: vec!["config/secret.pem".into()],
            ..Default::default()
        };
        let cmd = p.compute_bwrap_args("/scratch/proj").join(" ");
        assert!(cmd.contains("--ro-bind /dev/null /scratch/proj/config/secret.pem"));
    }

    // ── F6b: write-protect auto-exec files in writable roots ─────────────────

    #[test]
    fn auto_exec_paths_are_masked_in_workdir_and_allow_write_roots() {
        let p = FsPolicy {
            allow_write: vec!["/scratch/run".into()],
            ..Default::default()
        };
        let cmd = joined(&p, "/proj");
        // Whole agent-config / auto-exec DIRS -> fresh tmpfs (absent-safe; writes land
        // in the tmpfs and are discarded, so nothing persists into a later session).
        for rel in [".claude", ".git/hooks", ".vscode", ".idea"] {
            assert!(
                cmd.contains(&format!("--tmpfs /proj/{rel}")),
                "auto-exec dir {rel} not masked: {cmd}"
            );
        }
        // .mcp.json and .git/config stay READABLE but read-only.
        assert!(cmd.contains("--ro-bind-try /proj/.mcp.json /proj/.mcp.json"));
        assert!(cmd.contains("--ro-bind-try /proj/.git/config /proj/.git/config"));
        // and the same protections on the allowWrite root:
        assert!(cmd.contains("--tmpfs /scratch/run/.claude"));
        assert!(cmd.contains("--tmpfs /scratch/run/.git/hooks"));
    }

    #[test]
    fn auto_exec_masks_apply_to_absent_paths_too() {
        // The hole this closes: `--ro-bind-try` SKIPS a source that doesn't exist, so in
        // the common case of a project with no `.claude/settings.local.json`, a job could
        // simply CREATE one and have the next login-side session honour its permission
        // grants (AV2). A tmpfs over the whole `.claude` dir applies whether or not
        // anything is there, and covers config files upstream hasn't invented yet.
        let cmd = joined(&FsPolicy::default(), "/proj");
        assert!(cmd.contains("--tmpfs /proj/.claude"));
        assert!(
            !cmd.contains("--ro-bind-try /proj/.claude"),
            "must not use the skip-if-absent form for the plantable config dir: {cmd}"
        );
    }

    #[test]
    fn allow_git_config_frees_config_but_still_protects_hooks() {
        let p = FsPolicy { allow_git_config: true, ..Default::default() };
        let cmd = joined(&p, "/proj");
        assert!(!cmd.contains("/proj/.git/config"), "git/config writable when allowGitConfig");
        assert!(
            cmd.contains("--tmpfs /proj/.git/hooks"),
            "hooks are protected regardless"
        );
    }

    #[test]
    fn auto_exec_protection_follows_the_writable_bind() {
        // the ro-bind-try must come AFTER the workdir --bind so it overrides.
        let args = FsPolicy::default().compute_bwrap_args("/proj");
        let wbind = args.iter().position(|a| a == "/proj").unwrap();
        let hooks = args.iter().position(|a| a == "/proj/.git/hooks").unwrap();
        assert!(wbind < hooks, "auto-exec protection must follow the workdir bind");
    }

    #[test]
    fn parse_reads_allow_git_config_flag() {
        let json = r#"{ "sandbox": { "filesystem": { "allowGitConfig": true } } }"#;
        assert!(FsPolicy::parse(json).allow_git_config);
        assert!(!FsPolicy::parse("{}").allow_git_config); // default false
    }
}
