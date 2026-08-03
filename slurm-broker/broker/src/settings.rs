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
    // `.git/hooks` is NOT here: `.git` is masked by shape below, because masking a path
    // inside it is what fabricated a repository when there was none.
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

/// Auto-exec files that are masked with an EMPTY file when absent, not merely protected
/// when present. The difference matters: "read-only if it exists" leaves the plant open for
/// anything that does not normally exist, which is exactly how `.git/config` was planted.
/// Everything here must be harmless when empty — that is what makes the stronger form safe.
const AUTO_EXEC_RO_OR_EMPTY: &[&str] = &[
    ".Rprofile", // R sources it from cwd at startup unless --vanilla. No trust prompt.
];

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
/// Confine a path to the job's WRITABLE SET — the project dir plus every configured
/// `allowWrite` root — rather than to a single directory.
///
/// The set, not one root, because both halves are real. `allowWrite` genuinely adds
/// writable regions, so a job legitimately started in one must be allowed to run and to
/// put its logs there. And `req.cwd` is ADVERSARY-CONTROLLED — the stub runs in the cage
/// and the spool is agent-writable — so it cannot be used as the confinement base for
/// `--output`/`--error`: slurmd writes those as the user and OUTSIDE the cage, which makes
/// an unconfined base an uncaged arbitrary-write primitive. Confining to an agent-chosen
/// directory is not confinement.
///
/// Reports against the whole set, because "outside the working directory" would be a
/// misleading answer when several directories are writable.
pub fn confine_under_any(path: &str, roots: &[String]) -> Result<String, String> {
    let mut last = None;
    for r in roots {
        match confine_under_workdir(path, r) {
            Ok(p) => return Ok(p),
            Err(e) => last = Some(e),
        }
    }
    Err(match last {
        // Every root refused it: report the SET, so the message names what is allowed.
        Some(_) => format!(
            "{path:?} is not inside any directory this job may write. husk confines \
             --chdir/--output/--error to the writable set, because SLURM writes those files \
             as you and OUTSIDE the sandbox. Writable here: {}",
            roots.join(", ")
        ),
        None => "no writable directory is configured for this job".to_string(),
    })
}

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
    match normalize_abs(cwd) {
        None => false,
        Some(n) => n != "/" && !path_under_floor(&n),
    }
}

/// Collapse an absolute path to one spelling, so a comparison against it means something.
///
/// `//users/me`, `/users//me`, `/users/./me` and `/users/me/` are all the same directory to
/// the kernel and to bwrap, and every one of them used to defeat a `starts_with` against the
/// hidden floor. Returns `None` for anything that is not a usable absolute path — empty,
/// relative, or containing a `..` component, which is refused rather than resolved because
/// resolving it here would disagree with what the filesystem does about symlinks.
///
/// This is textual normalisation only. It is the *floor* check, which must work on paths
/// that need not exist yet; `confine_under_workdir` still canonicalises on disk, and that is
/// what catches a symlink pointing somewhere else.
fn normalize_abs(p: &str) -> Option<String> {
    if p.is_empty() || !p.starts_with('/') {
        return None;
    }
    let mut out = String::new();
    for part in p.split('/') {
        match part {
            "" | "." => continue, // repeated or trailing slash, or a no-op component
            ".." => return None,
            c => {
                out.push('/');
                out.push_str(c);
            }
        }
    }
    Some(if out.is_empty() { "/".to_string() } else { out })
}

/// True if `p` equals or is nested under a HIDDEN_FLOOR path. Such a path must never be
/// re-exposed by an allow carve-out (the floor must hold regardless of config) and is not
/// an acceptable writable workdir. (F18/F15)
/// May this configured path become an allow carve-out at all?
///
/// No if it is under the hidden floor (the floor must hold regardless of config, F18), and
/// no if it is the filesystem ROOT. The root is not "under" the floor but it dissolves the
/// whole cage: `--bind / /` is emitted after every mask and re-covers the floor, `--dev`,
/// `--proc` and both tmpfs mounts, so the job sees the host's real /dev and /proc despite
/// `--unshare-pid`. Measured: 280 device nodes instead of 14.
fn usable_carveout(p: &str) -> bool {
    !path_under_floor(p) && !matches!(normalize_abs(p).as_deref(), None | Some("/"))
}

fn path_under_floor(p: &str) -> bool {
    // A path that will not normalise (relative, or containing `..`) is not a path we can
    // vouch for, so it counts as under the floor: the caller's question is always "may I
    // expose this?", and the safe answer to an unresolvable path is no.
    let Some(norm) = normalize_abs(p) else {
        return true;
    };
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
    pub fn parse(json: &str) -> Result<FsPolicy, String> {
        let s: Settings = serde_json::from_str(json)
            .map_err(|e| format!("not valid JSON: {e}"))?;
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
        Ok(FsPolicy {
            allow_read: s.sandbox.filesystem.allow_read,
            deny_read: s.sandbox.filesystem.deny_read,
            allow_write: s.sandbox.filesystem.allow_write,
            deny_write: s.sandbox.filesystem.deny_write,
            allow_git_config: s.sandbox.filesystem.allow_git_config,
            deny_files,
            unset_env,
        })
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
    pub fn resolve(home: &Path, project_dir: &Path) -> Result<FsPolicy, String> {
        let mut pol = FsPolicy::default();
        let files = SETTINGS_SOURCES.map(|(from_home, rel)| {
            if from_home { home.join(rel) } else { project_dir.join(rel) }
        });
        for f in files {
            // A file that is not THERE contributes nothing, which is correct: the human
            // made no claims in a file they did not write. A file that IS there and does
            // not parse is a different thing entirely, and used to be treated the same —
            // so a stray comma silently dropped that layer's denyRead, denyWrite and
            // credential masks, and husk carried on with a weaker cage and said nothing.
            // Deny that cannot be read must never resolve to deny nothing.
            if let Ok(text) = std::fs::read_to_string(&f) {
                let layer = FsPolicy::parse(&text)
                    .map_err(|e| format!("{}: {e}", f.display()))?;
                pol.union(layer);
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
        Ok(pol)
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
        // ...and the filesystem ROOT, which is not "under" the floor but dissolves the
        // entire cage. `allowWrite: ["/"]` emits `--bind / /` LAST, so it re-covers not
        // just the floor but `--dev`, `--proc`, `--tmpfs /tmp` and `--tmpfs /dev/shm` as
        // well: measured, the job then saw 280 host device nodes instead of 14, and read
        // host PID 1 through the real /proc despite `--unshare-pid`. One config entry
        // undoing every mount that came before it is not a carve-out, it is an off switch.
        self.allow_read.retain(|p| usable_carveout(p));
        self.allow_write.retain(|p| usable_carveout(p));
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
            // The caged process tree dies with the guard that owns it.
            //
            // It did not, and the review found the consequence: on a group SIGTERM the
            // guard ran its cleanup, wrote "step spool removed", printed TERMINATED EARLY
            // and exited — while the workload carried on inside an orphaned bwrap, now with
            // no supervisor, no cleanup to come, and a spool that had already been deleted
            // out from under it. A cage whose owner has gone is a lifecycle bug and a
            // containment statement at once: husk had announced the job was over.
            //
            // This is the kernel-coupled half (PDEATHSIG under the hood). The guard's trap
            // is the cooperative half, and cooperative release does not survive SIGKILL.
            "--die-with-parent".into(),
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
            // `usable_carveout` here as well as in `resolve`, deliberately. `FsPolicy` is
            // public and built directly in several places, and this is the function that
            // decides what bwrap is actually asked for — a boundary check belongs at the
            // point the boundary is emitted, not only where the policy happens to be read.
            if p.starts_with('/') && usable_carveout(p) {
                a.push("--bind".into());
                a.push(p.clone());
                a.push(p.clone());
            }
        }
        // denyWrite takes precedence over allowWrite: re-bind the path read-only
        // (reads still allowed, writes blocked). Emitted after the write binds so
        // it wins over a writable ancestor.
        for p in &self.deny_write {
            // A denyWrite is emitted as `--ro-bind p p`, and a bind EXPOSES ITS SOURCE.
            // For a path already visible in the cage that is exactly the intent: make it
            // read-only. For a path the FLOOR HIDES it is the opposite — `denyWrite:
            // ["/users"]` bound every home back over the `--tmpfs /users` that exists to
            // remove them. A deny that grants, and the most plausible of the four fields to
            // get wrong, because the name promises the safe direction.
            //
            // Under the floor there is nothing to make read-only anyway: it is already
            // invisible and already unwritable. Dropping the entry loses nothing.
            if p.starts_with('/') && !path_under_floor(p) {
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
            // `.git` is masked according to what it actually IS, because bwrap creates the
            // mountpoints it is given and the old rule created a repository that was not
            // there. See `git_masking_handles_every_shape_of_dot_git` for the chain this
            // closes; the short version is that `--tmpfs <root>/.git/hooks` conjured a real
            // `.git/` on the host, into which the job then wrote a `core.hooksPath` that
            // `--ro-bind-try .git/config` had already declined to protect because, at the
            // moment bwrap looked, it did not exist.
            // Version-control metadata directories hold executable configuration: git has
            // `core.hooksPath` in `.git/config`, Mercurial has a `[hooks]` section in
            // `.hg/hgrc` and trusts an hgrc owned by the user running it — which a brokered
            // job is. Both are masked by SHAPE, because masking a path INSIDE one is what
            // fabricated a repository when none was there.
            for (dir, inner) in [(".git", "hooks"), (".hg", "")] {
                match std::fs::symlink_metadata(format!("{root}/{dir}")) {
                    // A real repository. Mask the hooks directory where git keeps them;
                    // Mercurial has no hooks directory, only the hgrc protected below.
                    Ok(m) if m.is_dir() => {
                        if !inner.is_empty() {
                            a.push("--tmpfs".into());
                            a.push(format!("{root}/{dir}/{inner}"));
                        }
                    }
                    // A `git worktree` or submodule checkout: the metadata entry is a FILE
                    // pointing at the real repository. A tmpfs cannot go under a file, so
                    // the old rule made bwrap fail and took the whole cage with it, with a
                    // bare bwrap error that never mentioned husk. Bind it read-only: the
                    // pointer is what must not be rewritten, and what it names is outside.
                    Ok(m) if m.is_file() => {
                        let p = format!("{root}/{dir}");
                        a.push("--ro-bind".into());
                        a.push(p.clone());
                        a.push(p);
                    }
                    // Absent, or something stranger. Mask the whole thing rather than a
                    // path inside it: the job may write there and read back its own writes,
                    // and none of it survives. What it can no longer do is leave a
                    // repository behind for the next `git`/`hg` the human runs.
                    _ => {
                        a.push("--tmpfs".into());
                        a.push(format!("{root}/{dir}"));
                    }
                }
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
            // Only meaningful when `.git` is a real repository — and only then is the
            // "config always exists wherever .git does" premise a true one.
            if !self.allow_git_config
                && matches!(std::fs::symlink_metadata(format!("{root}/.git")), Ok(m) if m.is_dir())
            {
                protect(".git/config");
            }
            // `.hg/hgrc` — only where a real `.hg` exists; otherwise the whole `.hg` is
            // already masked above and binding into it would recreate the fabrication bug.
            // Unlike `.git/config`, an hgrc very often does NOT exist in a real repo, so
            // "read-only if present" would leave the plant open. Bind an EMPTY file over it
            // instead: an empty hgrc is valid, so nothing breaks, and it cannot be created.
            if matches!(std::fs::symlink_metadata(format!("{root}/.hg")), Ok(m) if m.is_dir()) {
                let path = format!("{root}/.hg/hgrc");
                let src = if std::path::Path::new(&path).exists() { path.clone() } else { "/dev/null".to_string() };
                a.push("--ro-bind".into());
                a.push(src);
                a.push(path);
            }
            // Auto-exec files that need no repository at all. `.Rprofile` is the one that
            // matters on a cluster: R sources it from the working directory at startup
            // unless you pass --vanilla, there is no trust prompt, and a one-line plant runs
            // the next time a scientist opens R in their own project. Same rule — the real
            // file read-only if it is there, an empty one if it is not — so a legitimate
            // config still works inside the job and a planted one cannot persist.
            for rel in AUTO_EXEC_RO_OR_EMPTY {
                let path = format!("{root}/{rel}");
                let src = if std::path::Path::new(&path).exists() { path.clone() } else { "/dev/null".to_string() };
                a.push("--ro-bind".into());
                a.push(src);
                a.push(path);
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

    /// The auto-exec mask assumed `.git` is always a directory that already exists. All
    /// three of its shapes were wrong in a different way, and the middle one was executed
    /// end to end by the review: a job planted `.git/config` with `core.hooksPath`, it
    /// persisted to the host, `git init` preserved it, and the next `git commit` ran the
    /// payload as the user.
    ///
    /// The chain needed three defects at once. `--tmpfs <root>/.git/hooks` CREATES the
    /// mountpoint, so with `.git` absent bwrap fabricated a real `.git/` on the host.
    /// `.git/config` was protected with `--ro-bind-try`, which silently skips a file that
    /// does not exist — and it did not exist, because the `.git` it would have lived in had
    /// just been invented. And masking `.git/hooks` is irrelevant once `core.hooksPath`
    /// points somewhere else entirely.
    ///
    /// The premise in the source — "`.git/config` always exists wherever `.git` does" — was
    /// true of repositories and false of the directory husk itself conjured.
    #[test]
    fn git_masking_handles_every_shape_of_dot_git() {
        let base = std::env::temp_dir().join(format!("husk-git-shapes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let p = FsPolicy::default();

        // 1. A real repository: mask the hooks, keep config readable.
        let repo = base.join("repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::write(repo.join(".git/config"), "[core]\n").unwrap();
        let a = p.compute_bwrap_args(&repo.to_string_lossy()).join(" ");
        assert!(a.contains(&format!("--tmpfs {}/.git/hooks", repo.display())), "{a}");
        assert!(a.contains(&format!("{}/.git/config", repo.display())), "{a}");

        // 2. No repository at all. husk must NOT mask a path *inside* `.git`, because
        //    creating that mountpoint is what fabricates the repository the plant needs.
        //    Mask the whole `.git` instead: the job may write there and see its own writes,
        //    and none of it survives the job.
        let bare = base.join("bare");
        std::fs::create_dir_all(&bare).unwrap();
        let a = p.compute_bwrap_args(&bare.to_string_lossy()).join(" ");
        assert!(
            !a.contains(&format!("{}/.git/hooks", bare.display())),
            "must not fabricate a repository by masking inside a .git that is not there: {a}"
        );
        assert!(a.contains(&format!("--tmpfs {}/.git ", bare.display())), "{a}");

        // 3. `.git` is a FILE — an ordinary `git worktree` or a submodule checkout. A tmpfs
        //    under a file is not a thing, so bwrap refused and took the whole cage down with
        //    a diagnostic that never mentioned husk.
        let wt = base.join("worktree");
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::write(wt.join(".git"), "gitdir: /elsewhere/.git/worktrees/x\n").unwrap();
        let a = p.compute_bwrap_args(&wt.to_string_lossy()).join(" ");
        assert!(
            !a.contains(&format!("--tmpfs {}/.git", wt.display())),
            "a .git FILE must not be masked as a directory - that kills the cage: {a}"
        );
        assert!(
            a.contains(&format!("--ro-bind {}/.git {}/.git", wt.display(), wt.display())),
            "a .git file is a pointer to a real repo and must be read-only: {a}"
        );

        // 4. Mercurial gets the identical treatment, and `.Rprofile` — which needs no
        //    repository at all — is masked with an EMPTY file when absent rather than
        //    merely protected when present. "Read-only if it exists" is what left
        //    `.git/config` plantable, and it would leave every not-normally-present
        //    auto-exec file plantable too.
        let a = p.compute_bwrap_args(&bare.to_string_lossy()).join(" ");
        assert!(a.contains(&format!("--tmpfs {}/.hg ", bare.display())), "{a}");
        assert!(
            a.contains(&format!("--ro-bind /dev/null {}/.Rprofile", bare.display())),
            "an absent .Rprofile must be masked empty, not left creatable: {a}"
        );

        let hg = base.join("hg");
        std::fs::create_dir_all(hg.join(".hg")).unwrap();
        let a = p.compute_bwrap_args(&hg.to_string_lossy()).join(" ");
        assert!(
            a.contains(&format!("--ro-bind /dev/null {}/.hg/hgrc", hg.display())),
            "an hgrc that does not exist yet must not be creatable: {a}"
        );

        // A real .Rprofile keeps working inside the job — read-only, not blanked.
        let with_r = base.join("withr");
        std::fs::create_dir_all(&with_r).unwrap();
        std::fs::write(with_r.join(".Rprofile"), "options(digits=7)\n").unwrap();
        let a = p.compute_bwrap_args(&with_r.to_string_lossy()).join(" ");
        assert!(
            a.contains(&format!("--ro-bind {}/.Rprofile {}/.Rprofile", with_r.display(), with_r.display())),
            "a legitimate .Rprofile must stay readable: {a}"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Two config values that became mount arguments without being checked against the
    /// floor, and one of them is a deny that GRANTS.
    ///
    /// `denyWrite` is emitted as `--ro-bind p p`, and a bind EXPOSES ITS SOURCE. For a path
    /// that is already visible that is exactly right — it makes it read-only. For a path the
    /// floor HIDES, it un-hides it: `denyWrite: ["/users"]` bound every home back over the
    /// `--tmpfs /users` that exists to remove them, read-only but readable. The most
    /// plausible misconfiguration of the four fields, and it does the opposite of its name.
    ///
    /// `allowWrite: ["/"]` is worse than "the floor is undone": `--bind / /` is emitted last
    /// and re-covers `--dev`, `--proc`, `--tmpfs /tmp` and `--tmpfs /dev/shm` as well, so
    /// the job sees the host's real /dev and /proc despite --unshare-pid.
    #[test]
    fn config_paths_are_filtered_before_they_become_mounts() {
        let p = FsPolicy { deny_write: vec!["/users".into(), "/scratch/x".into()], ..Default::default() };
        let a = p.compute_bwrap_args("/proj").join(" ");
        assert!(
            !a.contains("--ro-bind /users /users"),
            "a denyWrite under the floor must not bind the floor back into the cage: {a}"
        );
        assert!(a.contains("--ro-bind /scratch/x /scratch/x"), "ordinary denyWrite still works: {a}");

        for bad in ["/", "//", "/."] {
            let p = FsPolicy { allow_write: vec![bad.into()], ..Default::default() };
            let a = p.compute_bwrap_args("/proj").join(" ");
            assert!(
                !a.contains(&format!("--bind {bad} {bad}")) && !a.contains("--bind / /"),
                "allowWrite {bad:?} would rebind the host root over the whole cage: {a}"
            );
            // allowRead of the root is deliberately NOT asserted against: the base cage
            // already opens with `--ro-bind / /`, so re-stating it changes nothing. Only
            // the WRITE case is a hole, which is the asymmetry worth remembering.
        }
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

    /// The floor predicates were raw string comparisons, so any spelling of a floor path
    /// that is not byte-identical walked straight through them. `//users/me` is the same
    /// directory as `/users/me` to the kernel and to bwrap — POSIX collapses the leading
    /// double slash — but `"//users/me".starts_with("/users/")` is false, so husk called it
    /// safe. That one character was the difference between a rejected submission and a
    /// job with the victim's home bound writable.
    ///
    /// The lesson is the same one that produced `confine_under_workdir`: **compare paths
    /// after normalising them, never as strings**, because the thing that will act on the
    /// path does not share your spelling.
    #[test]
    fn floor_predicates_normalise_before_comparing() {
        for spelling in [
            "//users",
            "//users/victim",
            "///users/victim",
            "/./users/victim",
            "/users/./victim",
            "/users//victim",
            "/users/victim/",
            "/users/victim//",
            "/scratch/../users/victim",
            "/users/other/../victim",
        ] {
            assert!(
                !is_workdir_allowed(spelling),
                "{spelling:?} names a home and must be refused as a workdir"
            );
        }
        // ...without becoming superstitious about slashes that mean nothing.
        assert!(is_workdir_allowed("//scratch/proj"));
        assert!(is_workdir_allowed("/scratch//proj"));
        assert!(is_workdir_allowed("/scratch/./proj"));
        assert!(is_workdir_allowed("/scratch/proj/"));
    }

    #[test]
    fn parse_extracts_filesystem_and_ignores_other_keys() {
        let json = r#"{
            "enableAllProjectMcpServers": false,
            "permissions": { "deny": ["Bash(curl *)"] },
            "sandbox": { "filesystem": { "denyRead": ["/users"], "allowRead": ["./"] } }
        }"#;
        let p = FsPolicy::parse(json).unwrap();
        assert_eq!(p.deny_read, vec!["/users"]);
        assert_eq!(p.allow_read, vec!["./"]);
    }

    #[test]
    fn parse_failsafe_on_garbage_or_missing_block() {
        // A settings file that is not JSON is an ERROR, not an empty policy. It used to
        // return the default — so a stray comma in settings.json silently removed every
        // denyRead and every credential mask, and the job read the real secrets. The
        // failure direction matters more than the failure: an unreadable DENY must never
        // resolve to "deny nothing".
        assert!(FsPolicy::parse("not json at all").is_err());
        assert!(FsPolicy::parse(r#"{"sandbox": {"filesystem": {"denyRead": ["/x""#).is_err());
        // Valid JSON that simply says nothing is still an empty policy, which is correct:
        // the file parsed, it just made no claims.
        assert_eq!(FsPolicy::parse("{}").unwrap(), FsPolicy::default());
        assert_eq!(FsPolicy::parse(r#"{"sandbox":{}}"#).unwrap(), FsPolicy::default());
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
        let p = FsPolicy::parse(json).unwrap();
        // mask and deny alike land in deny_files (mask degrades to deny).
        assert_eq!(p.deny_files, vec!["/proj/.env", "/proj/key.pem"]);
    }

    #[test]
    fn parse_no_credentials_block_means_no_deny_files() {
        let json = r#"{ "sandbox": { "filesystem": { "denyRead": ["/users"] } } }"#;
        assert!(FsPolicy::parse(json).unwrap().deny_files.is_empty());
        // empty-path entries are dropped, not emitted as a bind over "/".
        let empty = r#"{ "sandbox": { "credentials": { "files": [ { "path": "" } ] } } }"#;
        assert!(FsPolicy::parse(empty).unwrap().deny_files.is_empty());
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
        let p = FsPolicy::parse(json).unwrap();
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
        let p = FsPolicy::parse(json).unwrap();
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
        for rel in [".claude", ".vscode", ".idea"] {
            assert!(
                cmd.contains(&format!("--tmpfs /proj/{rel}")),
                "auto-exec dir {rel} not masked: {cmd}"
            );
        }
        // `.git` is masked by SHAPE. These roots do not exist, so husk cannot see a
        // repository and masks the whole thing — stronger than masking the hooks, and it
        // does not invent a `.git/` on the host the way masking a path inside one did.
        assert!(cmd.contains("--tmpfs /proj/.git "), "{cmd}");
        assert!(cmd.contains("--tmpfs /scratch/run/.git "), "{cmd}");
        // .mcp.json stays READABLE but read-only.
        assert!(cmd.contains("--ro-bind-try /proj/.mcp.json /proj/.mcp.json"));
        // and the same protections on the allowWrite root:
        assert!(cmd.contains("--tmpfs /scratch/run/.claude"));
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
        // Needs a REAL repository, because `.git/config` is only protected — and only
        // needs to be — where a `.git` directory actually exists.
        let d = std::env::temp_dir().join(format!("husk-agc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".git")).unwrap();
        std::fs::write(d.join(".git/config"), "[core]\n").unwrap();
        let root = d.to_string_lossy().to_string();

        let p = FsPolicy { allow_git_config: true, ..Default::default() };
        let cmd = joined(&p, &root);
        assert!(!cmd.contains(&format!("{root}/.git/config")), "config writable: {cmd}");
        assert!(cmd.contains(&format!("--tmpfs {root}/.git/hooks")), "hooks protected: {cmd}");

        let p = FsPolicy::default();
        let cmd = joined(&p, &root);
        assert!(
            cmd.contains(&format!("--ro-bind-try {root}/.git/config {root}/.git/config")),
            "config read-only by default in a real repo: {cmd}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn auto_exec_protection_follows_the_writable_bind() {
        // the ro-bind-try must come AFTER the workdir --bind so it overrides.
        let args = FsPolicy::default().compute_bwrap_args("/proj");
        let wbind = args.iter().position(|a| a == "/proj").unwrap();
        let hooks = args.iter().position(|a| a == "/proj/.git").unwrap();
        assert!(wbind < hooks, "auto-exec protection must follow the workdir bind");
    }

    /// The whole point of Fix 4, at the layer that actually reads the disk. A settings file
    /// that is ABSENT contributes nothing, which is right — the human made no claims in a
    /// file they never wrote. A settings file that EXISTS and does not parse is a different
    /// thing, and used to be treated identically: the layer was dropped, husk carried on
    /// with a weaker cage, and nothing anywhere said so. Since that layer carries denyRead
    /// and the credential masks, "cannot read the denies" resolved to "there are no denies".
    #[test]
    fn resolve_fails_closed_on_a_settings_file_it_cannot_read() {
        let d = std::env::temp_dir().join(format!("husk-resolve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let home = d.join("home");
        let proj = d.join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::create_dir_all(&home).unwrap();

        // Nothing configured anywhere: an empty policy, and no error.
        assert!(FsPolicy::resolve(&home, &proj).is_ok());

        // A real policy, well formed: resolves.
        let dotdir = proj.join(".claude");
        std::fs::create_dir_all(&dotdir).unwrap();
        let f = dotdir.join("settings.json");
        std::fs::write(&f, r#"{"sandbox":{"filesystem":{"denyRead":["/secret"]}}}"#).unwrap();
        let ok = FsPolicy::resolve(&home, &proj).expect("valid settings must resolve");
        assert!(ok.deny_read.iter().any(|p| p == "/secret"), "{ok:?}");

        // The same file with a typo must ERROR, and the error must name the file — the
        // operator has three candidates and no reason to guess.
        std::fs::write(&f, r#"{"sandbox":{"filesystem":{"denyRead":["/secret"]}}"#).unwrap();
        let e = FsPolicy::resolve(&home, &proj).expect_err("a broken settings file must fail");
        assert!(e.contains("settings.json"), "the error must name the file: {e}");

        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn parse_reads_allow_git_config_flag() {
        let json = r#"{ "sandbox": { "filesystem": { "allowGitConfig": true } } }"#;
        assert!(FsPolicy::parse(json).unwrap().allow_git_config);
        assert!(!FsPolicy::parse("{}").unwrap().allow_git_config); // default false
    }
}
