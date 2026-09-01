//! husk's own operator config: `~/.husk/config.json`.
//!
//! **Why a file rather than install flags.** Accounts, partitions and uenv images were
//! configured at install time, which is the wrong lifetime: a person with hours on two
//! projects, or a workflow that needs a GPU partition and a postprocessing one, cannot
//! re-run the installer per job. The set changes far more often than the installation does.
//!
//! **Why husk's own file and not `~/.claude/settings.json`.** That file is the vendor's, and
//! husk merges three managed keys into it. SLURM policy in there would couple husk's config
//! to a format 6a is meant to stop depending on, and the vendor runtime would carry keys it
//! does not understand. `~/.husk/` already exists — the job logs live there — so this is one
//! place for husk's own state rather than a new one.
//!
//! **Why JSON and not TOML.** Comments would be genuinely nicer for an operator file. They
//! are not worth a second parser in the trusted binary: husk's dependency surface is a
//! security property (`serde` + `serde_json` today), and JSON is already parsed here for
//! `settings.json`. Two config formats in one system is its own drift surface (`P8`).
//!
//! **This is a POLICY INPUT, so it inherits the rules for one.** It must live where the agent
//! cannot write it (`P2`) — it does: the whole home is masked inside the cage, on both sides
//! — and it must join the `denyWrite` pairing so the two lists cannot drift (`P8`).
//!
//! **Failure is LOUD and CLOSED.** A missing file means "no policy configured" and is normal.
//! A file that is present and wrong refuses the session, naming the entry and the rule. The
//! alternative — dropping a bad entry and carrying on — silently narrows or widens policy, and
//! the operator learns about it later as a job refusal with no cause attached. That is the
//! failure this project has paid for repeatedly (`P13`).

use serde::Deserialize;

fn one() -> u32 { 1 }
use std::path::{Path, PathBuf};

/// Where husk keeps it, relative to `$HOME`.
pub const CONFIG_REL: &str = ".husk/config.json";

/// The largest `~/.husk/config.json` husk will read into memory.
///
/// **Sized against a deadline, not against a parser.** `load_reporting` runs before the broker
/// claims its spool, and everything in that window is spent out of the fifteen seconds the
/// wrapper allows before it refuses to launch the agent (`B5-7`). An unbounded `read_to_string`
/// there turns one oversized file into a session that will not start.
///
/// A megabyte is roughly four orders of magnitude above the deployed configs this crate tests
/// against (`the_deployed_balfrin_config_loads` is a few hundred bytes), so it cannot fire on
/// anything a person wrote — the same margin, and the same number, the wrapper uses for a
/// settings layer. Hitting it REFUSES rather than skips, per the module header: a policy file
/// husk cannot read is never resolved to "no policy".
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// Lowering this toward the size of a real config would turn a bound into a denial of service
/// aimed at the operator — the failure mode three fixes in this review round produced while
/// closing something else. A compile error rather than a test, because lowering it is the only
/// way this breaks and that is a code change; the same device, for the same reason, as
/// `lib.rs`'s floor under `BODY_RETAIN_MAX_AGE_SECS`.
const _: () = assert!(MAX_CONFIG_BYTES >= 1024 * 1024);

/// The operator's allowlists. Every field is a SET the job selects from — husk re-emits its
/// own copy of the chosen entry, never the request's bytes, which is what makes the set a
/// boundary rather than a suggestion.
/// The `--partition` grammar. **One grammar, one definition** — the sentence
/// `sbatch::is_valid_account` already carries, applied to the field beside it (`B2-7(a)`).
///
/// It was spelled out by hand twice, here and in `session.rs`, three lines from an
/// `--account` check that is a single shared predicate. The two copies were identical when
/// measured, and their two callers already disagreed about what to DO with a bad entry
/// (`B2-3`), which is what drift looks like before it becomes a bug.
///
/// Narrower than the account grammar and deliberately: no `+`, and no leading `-`, because
/// this string becomes an argument to the real `sbatch` and a leading dash is an option.
///
/// **Its home should be `sbatch.rs`, next to `is_valid_account`** — that is where the value
/// crosses into SLURM's argv and where every other `v_*` grammar lives. It is here because
/// `sbatch.rs` belongs to another pass this round; moving it is a one-line change and no
/// caller needs to know.
pub fn is_valid_partition(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('-')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HuskConfig {
    /// Schema version. **Accepted in v0.5 so it can be USED later**: without it, a file
    /// written by a future husk would fail `deny_unknown_fields` with a raw serde error about
    /// an unknown key, instead of a sentence saying the file is from a newer version. Absent
    /// means 1, which is what every file already in the field says.
    ///
    /// It is deliberately the only forward-compatibility mechanism. husk has no merge
    /// algorithm and should not grow one — that is the road to `.pacnew`. A file husk cannot
    /// understand gets a refusal naming the problem, never a silent migration.
    #[serde(default = "one")]
    pub version: u32,
    /// Accounts a job may bill to. First entry is the default.
    #[serde(default)]
    pub accounts: Vec<String>,
    /// Partitions a job may request. First entry is the default.
    #[serde(default)]
    pub partitions: Vec<String>,
    /// uenv images a job may ask for, **by label only** — see `validate`.
    #[serde(default)]
    pub uenvs: Vec<String>,
}

impl Default for HuskConfig {
    fn default() -> Self {
        Self { version: 1, accounts: Vec::new(), partitions: Vec::new(), uenvs: Vec::new() }
    }
}

/// The system this host belongs to, used to pick a per-system config file.
///
/// **From the hostname, deliberately, and not from SLURM.** `SLURM_CLUSTER_NAME` is unset on
/// login nodes, and `scontrol show config` means a subprocess during broker startup — the one
/// path where a hang has already cost two live incidents. Reading `/proc/sys/kernel/hostname`
/// is a file read, and the rule (`balfrin-ln003` → `balfrin`) is one an operator can verify by
/// typing `hostname`.
///
/// `HUSK_SYSTEM` overrides it. Operator-set and agent-unreachable, like every other
/// `HUSK_*` input.
pub fn system_key() -> String {
    if let Ok(v) = std::env::var("HUSK_SYSTEM") {
        if !v.is_empty() {
            return sanitise_key(&v);
        }
    }
    let raw = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::env::var("HOSTNAME").map_err(|_| std::io::Error::other("no hostname")))
        .unwrap_or_default();
    sanitise_key(&raw)
}

fn sanitise_key(raw: &str) -> String {
    raw.trim()
        .split(['-', '.'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

/// Which config file applies here, and why.
///
/// **Per-system file wins, and there is NO MERGE.** `$HOME` is shared between some systems —
/// Balfrin and Tasna are twins sharing a home — so one file cannot serve both: their
/// partitions differ, and a list naming another system's partitions would have husk teach an
/// agent to request something that does not exist. Merge rules are where config systems go
/// wrong; "which file is in effect" should be answerable with `ls`.
pub fn resolve_path(home: &Path) -> (PathBuf, String) {
    let sys = system_key();
    if !sys.is_empty() {
        let per = home.join(format!(".husk/config.{sys}.json"));
        if per.exists() {
            return (per, sys);
        }
    }
    (home.join(CONFIG_REL), sys)
}

impl HuskConfig {
    /// Read and validate. `Ok(None)` means no file, which is not an error.
    ///
    /// Kept beside `load_reporting` because every test wants the config and not the path;
    /// production takes the reporting form, since on a shared home the operator must be able
    /// to see WHICH file applied.
    #[cfg(test)]
    pub fn load(home: &Path) -> Result<Option<Self>, String> {
        Self::load_reporting(home).map(|(c, _)| c)
    }

    /// As `load`, and also says WHICH file was read — on a shared home that line is the
    /// difference between a five-minute and a two-hour diagnosis, which is the same reason
    /// the build stamp is in the banner.
    pub fn load_reporting(home: &Path) -> Result<(Option<Self>, PathBuf), String> {
        let (path, _sys) = resolve_path(home);
        // WHAT KIND OF FILE, before opening it — and this order is the control, not tidiness.
        //
        // `stat(2)` answers for a FIFO; `open(2)` on one BLOCKS until a writer appears, and
        // `read_to_string` on one never returns at all. This read happens before the broker
        // claims its spool, i.e. inside the fifteen seconds the wrapper waits before it
        // refuses to launch the session (`B5-7`), so a blocking read here is not a slow
        // start — it is husk refusing to run, with the operator pointed at a spool (`P11`).
        //
        // `metadata` FOLLOWS symlinks, deliberately: `~/.husk/config.json -> shared/husk.json`
        // is an ordinary thing for an operator to do and stays supported. What is refused is a
        // path that is not, in the end, a regular file.
        let meta = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((None, path)),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        if !meta.is_file() {
            return Err(format!(
                "{} is not a regular file. husk reads its policy from a file, and will not \
                 open a directory, a device or a FIFO to find one — a FIFO in particular would \
                 block this read forever, and this read runs during broker startup, so the \
                 session would fail to launch with nothing naming the cause. Point that name \
                 at a JSON file, or remove it to fall back to the defaults.",
                path.display()
            ));
        }
        if meta.len() > MAX_CONFIG_BYTES {
            return Err(format!(
                "{} is {} bytes and husk reads at most {MAX_CONFIG_BYTES}. That is far larger \
                 than any policy file — the deployed configs in this repository are a few \
                 hundred bytes — so if this is the right path, something other than an \
                 operator wrote it. husk will not read it into memory to find out.",
                path.display(),
                meta.len()
            ));
        }
        // The bound is enforced on the READ as well as on the stat, so a file that grows
        // between the two is still bounded. Same shape the wrapper already uses for settings
        // layers, where a 200 MB one cost 821 MB of RSS before anything looked at it.
        let raw = {
            use std::io::Read;
            let f = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((None, path)),
                Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
            };
            let mut raw = String::new();
            f.take(MAX_CONFIG_BYTES + 1)
                .read_to_string(&mut raw)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            if raw.len() as u64 > MAX_CONFIG_BYTES {
                return Err(format!(
                    "{} grew past {MAX_CONFIG_BYTES} bytes while husk was reading it. Something \
                     is writing that file right now; husk will not start on a policy it read \
                     half of.",
                    path.display()
                ));
            }
            raw
        };
        // An empty or whitespace-only file is ABSENT, not broken. The same rule husk already
        // applies to settings.json, and for the same reason: `: > file` is how a person
        // clears a config, and refusing the session for it cost two live incidents.
        if raw.trim().is_empty() {
            return Ok((None, path));
        }
        let cfg: Self = serde_json::from_str(&raw).map_err(|e| {
            format!(
                "{} is not valid JSON: {e}. husk will not start with a policy file it cannot \
                 read — fix the file, or remove it to fall back to the defaults.",
                path.display()
            )
        })?;
        cfg.validate(&path.display().to_string())?;
        Ok((Some(cfg), path))
    }

    fn validate(&self, where_: &str) -> Result<(), String> {
        if self.version != 1 {
            return Err(format!(
                "{where_}: this config declares version {}, and this husk understands version \
                 1. It was written for a newer husk — upgrade husk, or remove the file to fall \
                 back to the defaults. husk will not guess what a field it does not know means, \
                 because a field it does not know might be a restriction.",
                self.version
            ));
        }
        let bad = |field: &str, entry: &str, why: &str| {
            Err(format!(
                "{where_}: {field} entry {entry:?} {why}. husk refuses rather than dropping it: \
                 a silently ignored entry becomes a job refusal with no cause attached."
            ))
        };
        for a in &self.accounts {
            if !crate::sbatch::is_valid_account(a) {
                return bad("accounts", a, "is not a SLURM account name (letters, digits, `._+-`, max 64)");
            }
        }
        for p in &self.partitions {
            if !is_valid_partition(p) {
                return bad("partitions", p, "is not a partition name (letters, digits, `._-`, max 64, no leading dash)");
            }
        }
        for u in &self.uenvs {
            // LABELS ONLY, and this is the load-bearing line in the file.
            //
            // `--uenv` accepts a FILE PATH as well as a repository label — husk's own
            // session code records that `UENV_MOUNT_LIST`'s `file:mount-point` pairs are a
            // valid `--uenv` argument. The image is mounted BEFORE the cage is built, and
            // husk's guard executes from inside it, so an image the job can name is not a
            // carve-out in the cage: it is the floor the cage stands on. Permitting a path
            // here would let an operator write a policy that reads as an allowlist and is an
            // off switch.
            // THE GRAMMAR IS THEIRS, NOT OURS — read from uenv's lexer (`src/uenv/parse.cpp`),
            // and getting it from the source rather than from the prose changed it twice.
            //
            // A LABEL is `name[/version][:tag][@system][%uarch]`, so it legitimately contains
            // `/`, `:`, `@` and `%`. A first draft here refused any entry containing `/` and
            // would have rejected `prgenv-gnu/24.11:v1` — the standard spelling of every
            // versioned image, and a functional break rather than a safe one.
            //
            // A PATH is anything starting with `/` or `.` (`is_path_start_tok`), which is the
            // real thing to refuse: an image named by path is a filesystem the job hands to
            // itself, mounted before husk's cage exists.
            //
            // A MOUNT POINT is a colon followed by a path — their own comment: *"the ':'
            // character is also used to set the mount point. do not continue parsing if a
            // path follows the ':'"*. husk emits no mount point, so one in the allowlist is
            // an operator writing something husk will not honour; say so rather than carry it.
            if u.starts_with('/') || u.starts_with('.') {
                return bad("uenvs", u, "is a PATH, not a label — uenv reads anything beginning with '/' or '.' as a file. Only repository labels belong here: an image is mounted before husk's cage is built, so one named by path is a filesystem the job hands to itself");
            }
            if u.contains(":/") || u.contains(":.") {
                return bad("uenvs", u, "carries a MOUNT POINT (a ':' followed by a path). husk sets mount points itself — each image lands where its own metadata says — so name the image alone");
            }
            if u.is_empty()
                || u.len() > 128
                || u.starts_with('-')
                || !u.chars().all(|c| c.is_ascii_alphanumeric() || "._:-/@%*".contains(c))
            {
                return bad("uenvs", u, "is not a uenv label. Expected `name[/version][:tag][@system][%uarch]`, max 128, no leading dash");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    trait ErrMsg { fn unwrap_err_or_else_msg(self, ctx: &str) -> String; }
    impl<T> ErrMsg for Result<T, String> {
        fn unwrap_err_or_else_msg(self, ctx: &str) -> String {
            match self { Err(e) => e, Ok(_) => panic!("{ctx}") }
        }
    }

    fn write(dir: &std::path::Path, body: &str) {
        std::fs::create_dir_all(dir.join(".husk")).unwrap();
        std::fs::write(dir.join(CONFIG_REL), body).unwrap();
    }
    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("husk-cfg-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }


    /// `B5-7`. This file is read BEFORE the broker claims its spool, so every millisecond it
    /// takes comes out of the fifteen seconds the wrapper allows before it refuses to launch
    /// the agent at all. Two shapes make that read unbounded, and neither is exotic:
    ///
    ///   - a FIFO. `open(2)` on one BLOCKS until a writer appears and `read_to_string` never
    ///     returns; the session then fails to launch with a message naming the spool.
    ///   - a very large file. `read_to_string` materialises all of it — the same shape the
    ///     wrapper already closed for settings layers, where 200 MB cost 821 MB of RSS.
    ///
    /// **FALSE FRIEND:** `absent_and_empty_are_not_errors_but_a_broken_file_is` covers the
    /// content dispositions and is green for both of these, because neither is about content.
    ///
    /// **MUTATION that turns this red:** delete the `meta.is_file()` guard (the FIFO half
    /// FAILS rather than hangs, on purpose — see the thread below) or the `meta.len()` guard.
    ///
    /// **Who can trigger it:** whoever can write `~/.husk/` — the operator, or another local
    /// process running as them. NOT the agent: the home is masked inside the cage on both
    /// sides, which is the property that makes this file a policy input at all (`P2`).
    #[test]
    fn a_config_husk_cannot_read_in_bounded_time_is_refused_rather_than_read() {
        // (1) A DIRECTORY where a file should be. Fails fast either way, so it is the
        //     assertion that carries the message check.
        let d = tmp("notafile");
        std::fs::create_dir_all(d.join(CONFIG_REL)).unwrap();
        let msg = HuskConfig::load(&d).unwrap_err_or_else_msg("a directory is not a config");
        assert!(msg.contains("not a regular file"), "{msg}");
        assert!(msg.contains(".husk/config.json"), "the refusal must name the path: {msg}");

        // (2) TOO LARGE. Named with the size and the bound, so the operator can see it is a
        //     bound and not a parse error.
        let big = tmp("toobig");
        write(&big, "{}");
        std::fs::write(big.join(CONFIG_REL), "x".repeat((MAX_CONFIG_BYTES + 1) as usize)).unwrap();
        let msg = HuskConfig::load(&big).unwrap_err_or_else_msg("an oversized config is refused");
        assert!(msg.contains("husk reads at most"), "{msg}");
        assert!(msg.contains(&format!("{}", MAX_CONFIG_BYTES + 1)), "say how big it is: {msg}");

        // (3) A FIFO. Run on a thread, because the POINT of the check is that the alternative
        //     never returns — and a test that hangs teaches nobody anything. Removing the
        //     guard makes this FAIL at five seconds instead of blocking the suite forever.
        let fifo = tmp("fifo");
        std::fs::create_dir_all(fifo.join(".husk")).unwrap();
        let made = std::process::Command::new("mkfifo")
            .arg(fifo.join(CONFIG_REL))
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if made {
            let (tx, rx) = std::sync::mpsc::channel();
            let home = fifo.clone();
            std::thread::spawn(move || {
                let _ = tx.send(HuskConfig::load(&home).is_err());
            });
            match rx.recv_timeout(std::time::Duration::from_secs(5)) {
                Ok(true) => {}
                Ok(false) => panic!("a FIFO must not read as a valid operator config"),
                Err(_) => panic!(
                    "reading a FIFO config blocked for 5s. `open` on a FIFO waits for a writer, \
                     and this read happens inside the wrapper's 15s launch budget — so this is \
                     not a slow start, it is husk refusing to run with the operator pointed at \
                     a spool (`B5-7`, `P11`)."
                ),
            }
            let _ = std::fs::remove_dir_all(&fifo);
        }
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&big);
    }

    /// The bound must not fire on anything a person wrote. This is the direction that matters
    /// most: three fixes in this review round created a denial of service aimed at the
    /// operator while closing something else, and a config size check is exactly that shape.
    #[test]
    fn the_size_bound_cannot_fire_on_a_config_an_operator_wrote() {
        let d = tmp("realistic");
        // Far larger than any real one: 200 accounts, partitions and uenvs.
        let list = |p: &str| (0..200).map(|i| format!("\"{p}{i}\"")).collect::<Vec<_>>().join(",");
        write(&d, &format!(
            "{{\"accounts\": [{}], \"partitions\": [{}], \"uenvs\": [{}]}}",
            list("acct"), list("part"), list("uenv")
        ));
        let c = HuskConfig::load(&d).expect("a large but sane config must still load").unwrap();
        assert_eq!(c.accounts.len(), 200);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The config is a POLICY INPUT, so the agent must not be able to write it (`P2`), and
    /// the two statements of that must not drift (`P8`).
    ///
    /// The floor already covers it — `denyRead: /users` masks the whole home on both sides —
    /// but the floor is CSCS-shaped, and a site whose homes are elsewhere would lose the
    /// protection with nothing to notice. The explicit entry is what survives that.
    #[test]
    fn the_config_file_is_denied_to_the_agent_by_the_shipped_settings() {
        let shipped = match std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../user-config/settings.json"
        )) {
            Ok(s) => s,
            Err(_) => return, // release tarballs ship the broker alone
        };
        // THE CONTRACT: the agent cannot CHANGE this file, because it decides which
        // accounts, partitions and images a job may have. Not "~/.husk appears in
        // denyWrite" — that is one mechanism of three, and pinning a mechanism is how a
        // shape test becomes a false friend (P9). ~/.husk lives in the HOME, which is
        // outside the writable set entirely, so the contract holds via `allowWrite: []`
        // whether or not denyWrite names it. MEASURED 2026-08-25: a home path absent from
        // denyWrite still fails `touch` with EROFS; and on the cluster the home mask
        // removes ~/.husk from the cage altogether (verified on Balfrin — it exists on the
        // host and is absent inside).
        //
        // What a unit test CAN see is the writable set. The contract itself is measured by
        // `husk-verify.sh`, which attempts a real zero-byte open-for-append against
        // ~/.husk/config.json in a LIVE cage and accepts absent-or-unwritable.
        let cfg: serde_json::Value =
            serde_json::from_str(&shipped).expect("shipped settings must be valid JSON");
        let allow_write: Vec<String> = cfg["sandbox"]["filesystem"]["allowWrite"]
            .as_array().unwrap_or(&vec![])
            .iter().map(|v| v.as_str().unwrap_or_default().to_string()).collect();
        assert!(
            !allow_write.iter().any(|w| w == "~" || w == "~/" || w.starts_with("~/")),
            "allowWrite must not reach into the home, or ~/{CONFIG_REL} — which decides \
             which accounts, partitions and images a job may have — becomes agent-writable: \
             {allow_write:?}"
        );
    }


    /// `$HOME` is shared between some systems (Balfrin and Tasna are twins), so one file
    /// cannot serve both — their partitions differ, and a shared list would have husk teach an
    /// agent to request a partition that does not exist on the host it is running on.
    #[test]
    fn a_per_system_file_wins_and_there_is_no_merge() {
        let d = tmp("persystem");
        std::fs::create_dir_all(d.join(".husk")).unwrap();
        std::fs::write(d.join(".husk/config.json"), r#"{"partitions": ["shared-one"]}"#).unwrap();
        std::env::set_var("HUSK_SYSTEM", "balfrin");
        // No per-system file yet: the shared one applies.
        assert_eq!(HuskConfig::load(&d).unwrap().unwrap().partitions, vec!["shared-one".to_string()]);
        // With one, it wins OUTRIGHT — the shared file's entries do not leak in.
        std::fs::write(d.join(".husk/config.balfrin.json"), r#"{"partitions": ["pp-short"]}"#).unwrap();
        let c = HuskConfig::load(&d).unwrap().unwrap();
        assert_eq!(c.partitions, vec!["pp-short".to_string()], "per-system file must not merge");
        // A different system on the same home falls back to the shared file.
        std::env::set_var("HUSK_SYSTEM", "tasna");
        assert_eq!(HuskConfig::load(&d).unwrap().unwrap().partitions, vec!["shared-one".to_string()]);
        std::env::remove_var("HUSK_SYSTEM");
    }

    #[test]
    fn hostnames_reduce_to_a_system_key() {
        for (host, want) in [
            ("balfrin-ln003", "balfrin"),
            ("tasna-ln001", "tasna"),
            ("santis-ln002.cscs.ch", "santis"),
            ("BALFRIN-LN1", "balfrin"),
        ] {
            assert_eq!(sanitise_key(host), want, "{host}");
        }
    }

    /// A file from a newer husk must refuse with a SENTENCE, not a serde error about an
    /// unknown key. That is the whole reason `version` is accepted in v0.5 rather than added
    /// in the release that first needs it.
    #[test]
    fn a_newer_schema_version_is_refused_by_name() {
        let d = tmp("version");
        write(&d, r#"{"version": 2, "partitions": ["debug"]}"#);
        let e = HuskConfig::load(&d).unwrap_err_or_else_msg("a newer version must refuse");
        assert!(e.contains("written for a newer husk"), "{e}");
        assert!(e.contains("might be a restriction"), "say why guessing is not an option: {e}");
        // ...and an explicit version 1 is fine, as is none at all.
        write(&d, r#"{"version": 1, "partitions": ["debug"]}"#);
        assert!(HuskConfig::load(&d).is_ok());
    }

    #[test]
    fn the_deployed_santis_config_loads() {
        let d = tmp("santis");
        write(&d, r#"{
  "accounts": ["proj01"],
  "partitions": ["debug"],
  "uenvs": ["icon/25.2:v3"]
}"#);
        let c = HuskConfig::load(&d).expect("the deployed config must load").expect("present");
        assert_eq!(c.accounts, vec!["proj01".to_string()]);
        assert_eq!(c.partitions, vec!["debug".to_string()]);
    }

    /// Christoph's real Balfrin config, 2026-08-18. Kept as a test because a config that the
    /// operator actually deployed is worth more than one invented here — it is the spelling
    /// the validator has to accept, including a versioned-and-tagged uenv label.
    #[test]
    fn the_deployed_balfrin_config_loads() {
        let d = tmp("balfrin");
        write(&d, r#"{
  "accounts": [],
  "partitions": ["short", "pp-short"],
  "uenvs": ["icon/25.2:v3"]
}"#);
        let c = HuskConfig::load(&d).expect("the deployed config must load").expect("present");
        assert_eq!(c.partitions, vec!["short".to_string(), "pp-short".to_string()]);
        assert_eq!(c.uenvs, vec!["icon/25.2:v3".to_string()]);
        assert!(c.accounts.is_empty());
    }

    #[test]
    fn absent_and_empty_are_not_errors_but_a_broken_file_is() {
        let d = tmp("absent");
        assert_eq!(HuskConfig::load(&d), Ok(None), "no file is normal");
        write(&d, "   \n");
        assert_eq!(HuskConfig::load(&d), Ok(None), "an emptied file is absent, not broken");
        write(&d, "{\"accounts\": }");
        let e = HuskConfig::load(&d).expect_err("a broken policy file must refuse the session");
        assert!(e.contains("not valid JSON"), "{e}");
    }

    /// A uenv named by PATH must be refused, and this is the sharp one.
    ///
    /// `--uenv` takes a file path as well as a label, the image is mounted before husk's
    /// cage exists, and the guard runs from inside it. An operator who writes a path here
    /// believes they wrote an allowlist; what they wrote is a way for the job to supply its
    /// own root filesystem. Refusing at CONFIG time is the only place this can be caught
    /// once and for all — by submit time the value looks like any other allowed entry.
    #[test]
    fn a_uenv_named_by_path_is_refused_at_config_time() {
        let d = tmp("uenvpath");
        // Every spelling uenv's own lexer calls a path. The dotted ones are the reason this
        // test exists: they contain no slash, so a `/`-only check accepted them.
        for spelling in [
            "/scratch/me/mine.squashfs:/user-environment",
            "./mine.squashfs",
            "../mine.squashfs",
            ".mine.squashfs",
        ] {
            write(&d, &format!(r#"{{"uenvs": ["{spelling}"]}}"#));
            let e = HuskConfig::load(&d)
                .unwrap_err_or_else_msg(&format!("{spelling} must be refused as a path"));
            assert!(e.contains("is a PATH"), "{spelling}: {e}");
            assert!(e.contains("before husk"), "the message must say WHY: {e}");
        }

        // A mount point is a colon followed by a PATH — uenv's own rule. Refused with its
        // own message, because "not in the allowlist" would send the operator hunting.
        write(&d, r#"{"uenvs": ["icon/25.2:/user-environment"]}"#);
        let e = HuskConfig::load(&d).unwrap_err_or_else_msg("a mount point must be refused");
        assert!(e.contains("MOUNT POINT"), "{e}");

        // ...and every REAL label spelling must load. A first draft refused any entry with a
        // slash, which would have rejected the standard spelling of every versioned image.
        for good in [
            "prgenv-gnu",
            "prgenv-gnu/24.11",
            "prgenv-gnu/24.11:v1",
            "icon/25.2:v3@santis",
            "icon/25.2:v3@santis%gh200",
            "netcdf-tools/2024:latest@*",
        ] {
            write(&d, &format!(r#"{{"uenvs": ["{good}"]}}"#));
            assert!(
                HuskConfig::load(&d).is_ok(),
                "{good} is a legal uenv label and must load"
            );
        }

        // ...and an ordinary label still loads.
        write(&d, r#"{"uenvs": ["prgenv-gnu:v1"]}"#);
        let c = HuskConfig::load(&d).unwrap().unwrap();
        assert_eq!(c.uenvs, vec!["prgenv-gnu:v1".to_string()]);
    }

    #[test]
    fn a_bad_entry_refuses_rather_than_being_dropped() {
        let d = tmp("bad");
        for (body, needle) in [
            (r#"{"accounts": ["ok", "not a name!"]}"#, "accounts"),
            (r#"{"partitions": ["--oops"]}"#, "partitions"),
        ] {
            write(&d, body);
            let e = HuskConfig::load(&d).expect_err("a bad entry must refuse");
            assert!(e.contains(needle), "{e}");
            assert!(e.contains("no cause attached"), "say why refusing beats dropping: {e}");
        }
    }

    /// An unknown key is an error, not a shrug.
    ///
    /// `deny_unknown_fields`, because the failure mode of tolerance here is silent: an
    /// operator writes `"partition"` for `"partitions"`, husk reads an empty set, and every
    /// job is refused for a reason that names nothing. The typo IS the message.
    #[test]
    fn an_unknown_key_is_refused_so_a_typo_cannot_read_as_empty_policy() {
        let d = tmp("unknown");
        write(&d, r#"{"partition": ["normal"]}"#);
        let e = HuskConfig::load(&d).expect_err("a misspelled key must not read as empty policy");
        assert!(e.contains("not valid JSON") || e.contains("unknown field"), "{e}");
    }
}
