//! Resolve the sandbox filesystem policy from the (trusted) Claude settings
//! hierarchy and translate it into the compute-side bwrap profile.
//!
//! **Who establishes that the three layers are trusted human input, and for which
//! caller.** `FsPolicy::resolve` has TWO callers with two different preconditions, and
//! only one of them has a witness (`B2-6`):
//!
//! * the LOGIN broker (`main.rs`, one call at startup) runs behind
//!   `SettingsIntact::establish()` in `bin/husk-slurm-wrapper.rs`, which refuses the whole
//!   launch if any of `~/.claude/settings.local.json`, `<cwd>/.claude/settings.{json,local
//!   .json}` or `<gitroot>/.claude/settings.local.json` carries a `"sandbox":` key. So for
//!   that caller the premise holds by CONSTRUCTION, and more strongly than "the agent
//!   cannot write it" — husk does not start if it was written.
//! * the STEP broker (`main.rs --step-broker`) calls the same function on a COMPUTE node,
//!   where no wrapper runs, no `SettingsIntact` exists, and `project_dir` is inside the
//!   agent-writable project tree. Same function, same three sources, **no witness**.
//!
//! That asymmetry is the reason this file parses defensively rather than trustingly, and
//! anyone adding, reordering or relaxing a layer in `SETTINGS_SOURCES` has two threat
//! contexts to satisfy, not one. It is recorded here because `settings.rs` is where the
//! reader is, and the enforcement is in a binary this file never mentions.
//!
//! We parse defensively with serde and FAIL SAFE: any missing or malformed file yields NO
//! carve-outs — never a wider cage. The compute job hides the submitting user's home root
//! by default (see `Floor`); only the human's `allowRead` entries carve specific subpaths
//! back in. This mirrors the login-side `sandbox.filesystem` boundary (the part that
//! governs bash), read from the SAME settings files so the two cages cannot silently
//! drift. See BROKER.md.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// How CSCS spells its home root — a SITE DEFAULT, not the policy.
///
/// `Floor::for_home` decides what is actually hidden and what is actually masked, from
/// `$HOME`. This constant contributes one thing: on a machine whose homes really are under
/// `/users`, husk keeps masking the whole of it rather than just this user's directory,
/// which is what it has always done and what both guard goldens record. On a machine where
/// `$HOME` is somewhere else the constant is **not confirmed**, and husk does not ask bwrap
/// to mask it. See `Floor` for why those are two different questions. (`B2-1`)
const SITE_FLOOR_DEFAULTS: &[&str] = &["/users"];

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
    // AMD ROCm compute, for LUMI. Free to list because `--dev-bind-try` skips a node that
    // does not have it, so this is a no-op on every NVIDIA machine — which is also why NOT
    // listing it was never a "portability blocker" needing a runtime glob, only an omission.
    //
    // `/dev/kfd` is the unambiguous COMPUTE device. `/dev/dri` is deliberately NOT here:
    // it exists on anything with integrated graphics, so binding it unconditionally would
    // widen the device surface on machines that have no use for it. Making that conditional
    // is genuine run-time work (`ROADMAP` F2) — unlike this line.
    "/dev/kfd",
];

/// Fabric NIC device nodes exposed into a RANK cage (never into a plain job cage).
///
/// `/dev/cxi[0-9]*` on Alps, one per NIC. Measured (gate C4/C1): the device is
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
    // InfiniBand, for Euler. Same reasoning as `/dev/kfd`: `-try` makes it free on a
    // Slingshot machine, so its absence was an omission rather than a design limit. The
    // directory rather than each node, because IB device names vary by HCA (`mlx5_0`, …)
    // and enumerating them IS the run-time work — binding the directory is not.
    "/dev/infiniband",
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
/// - Per-file `--ro-bind /dev/null` survives an absent DESTINATION only where bwrap can
///   create the mount point — true inside the bound workdir, false under the read-only
///   root, where it fails and takes the cage with it. Even in the workdir it is the wrong
///   trade: the bind leaves an EMPTY `settings.json` on the host, i.e. invalid JSON in the
///   user's project. A tmpfs leaves at most an empty directory, which is harmless.
///   (An absent SOURCE is a separate failure and always fatal — see `--ro-bind-try` and the
///   ghost-file incident at the denyWrite loop.)
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
    // `.Renviron` — rationale at `LOGIN_AUTO_EXEC_DENY` (it redirects via `R_PROFILE_USER`
    // and so DEFEATS the `.Rprofile` mask beside it). **A4-L2 named both halves; N6-F1 swept
    // only the login one and the finding was recorded as closed** — a half-applied fix, not
    // list drift. `FIX-ROUND.md` carries the correction.
    //
    // Belongs in THIS list, not `AUTO_EXEC_RO_FILES`: `--ro-bind-try` with an absent source
    // applies NO mask, so "read-only if present" leaves the plant open — demonstrated on
    // `.mcp.json`, which a job wrote to the host straight through its own present-only mask.
    //
    // TWO COSTS, both real, neither hypothetical:
    //   * an empty `./.Renviron` SHADOWS `~/.Renviron` — R takes the first startup file it
    //     finds and stops. On a cluster that is where `R_LIBS_USER` lives, so a leftover
    //     breaks `library()` for the next human in that directory. That is why the guard
    //     RECLAIMS the mount points it created (A4-S3); without the reclaim this entry
    //     trades a security hole for a usability one.
    //   * the mask is emitted at `{root}/{rel}` ONLY. A job can `mkdir analysis` and plant
    //     `analysis/.Renviron`, and the human's next `R` there runs it. `output_path_is_
    //     protected` is depth-aware for the same threat; this mount is not. Enumeration does
    //     not fix it — 6a does. Recorded as a residual, so "protects nothing -> now it does"
    //     is not read as closure.
    ".Renviron",
];

/// The same protection, owed by the LOGIN cage — and a list that exists because the two
/// cages disagreed.
///
/// **A4-F3.** The compute cage masked `.Rprofile` and `.hg/hgrc`; the login cage did not.
/// Both dotfiles live in the shared, agent-writable project dir, so a LOGIN-session agent
/// could delete and recreate either one with content of its choosing — and R sources
/// `.Rprofile` from the working directory at startup, Mercurial reads `.hg/hgrc` and trusts
/// it because the invoking user owns it. Neither needs the agent to be running: the payload
/// fires the next time a HUMAN runs `R` or `hg` in that directory, outside every cage. The
/// compute cage's re-masking hid the gap, because it made brokered jobs look protected.
///
/// The login cage is Anthropic's runtime, driven by husk's shipped `denyWrite`. So the fix
/// is a policy entry, not code — which is exactly why it needs the pairing test below. Two
/// lists of "what auto-executes", in two languages, in two files, is the duplication this
/// project has been bitten by three times; assert them against each other instead.
///
/// Both shapes are safe to state statically because the runtime resolves them per shape: an
/// absent LEAF gets `--ro-bind /dev/null` (creation blocked), while an absent INTERMEDIATE
/// (`.hg` where no repo exists) gets a read-only EMPTY DIRECTORY rather than a character
/// device, and both mount points are removed after the command. That is why `.git/config`
/// is deliberately NOT here: `.git` absent would mount an empty dir over it and break
/// `git init`, which is the same trap husk hit masking a path inside `.git` and fabricating
/// a repository. Shape-aware masking (compute) or the vendor's conditional (login) owns
/// that one; a static entry must never.
/// Not read by the broker at run time — the LOGIN cage is the vendor runtime's, driven by
/// the shipped JSON, so this constant's whole job is to be the thing that JSON is asserted
/// against. Deleting it because "nothing uses it" deletes the pairing.
#[allow(dead_code)]
pub use husk_slurm_broker::LOGIN_AUTO_EXEC_DENY;

/// The `--output`/`--error` specifier table's element type, and the only way to build one.
///
/// **`RA-3`: this table is a code-generation INPUT, so its shape check has to be a type.**
/// `policy.rs` splices `expansion` into the guard as shell, inside
/// `${_husk_nl//'%c'/EXPANSION}`. Until this type existed the only guard was a pair of
/// `assert!`s in a test, and a reviewer put
/// `"${USER:-}} ; _husk_ra=$(touch …/PWNED) ; _husk_rb=${USER:-}"` in the table, ran a
/// command from inside the guard *during the test suite*, and left all seven behavioural
/// tests green — only the byte-goldens noticed. `P6`: the control is the type, not the
/// assert beside it.
///
/// `new` is a `const fn` and the table is a `const`, so every entry is checked while the
/// crate COMPILES. A malformed entry is a build failure, not a run-time branch: there is
/// no path for it to be reached on and nobody to trigger it. The fields are private to
/// this module and its consumers are all outside it, so `Specifier { .. }` is not a
/// constructor anyone can reach — the encapsulation `RC-5` found missing. There is
/// deliberately no `Default`.
mod output_specifier {
    /// One accepted specifier: the character, the shell that expands it, and the sbatch
    /// options SLURM must have been given for that expansion to be defined.
    pub struct Specifier {
        spec: char,
        expansion: &'static str,
        requires: &'static [&'static str],
    }

    /// `true` for `[A-Za-z0-9]`. Written out rather than calling `char::is_ascii_alphanumeric`
    /// so this stays a `const fn` on every toolchain that builds husk.
    const fn is_alnum(c: u8) -> bool {
        (c >= b'a' && c <= b'z') || (c >= b'A' && c <= b'Z') || (c >= b'0' && c <= b'9')
    }

    impl Specifier {
        /// Accept `${IDENT}` or `${IDENT:-DEFAULT}` and nothing else.
        ///
        /// `IDENT` is `[A-Za-z_][A-Za-z0-9_]*` and `DEFAULT` is `[A-Za-z0-9_.-]*` — no `%`
        /// (which would put back the character the whole expansion exists to remove), no
        /// `$`, no `}`, no quote, no shell metacharacter. The specifier character is
        /// alphanumeric, because the guard emits it between single quotes and a `'` would
        /// end the quoting outright.
        pub const fn new(
            spec: char,
            expansion: &'static str,
            requires: &'static [&'static str],
        ) -> Specifier {
            let c = spec as u32;
            assert!(c < 128 && is_alnum(c as u8), "a specifier must be ASCII alphanumeric");
            let b = expansion.as_bytes();
            assert!(
                b.len() > 3 && b[0] == b'$' && b[1] == b'{' && b[b.len() - 1] == b'}',
                "an expansion must be a parameter expansion, dollar-brace ... brace"
            );
            // IDENT
            let mut i = 2;
            assert!(
                (b[i] >= b'a' && b[i] <= b'z') || (b[i] >= b'A' && b[i] <= b'Z') || b[i] == b'_',
                "a variable name must start with a letter or underscore"
            );
            while i < b.len() - 1 && (is_alnum(b[i]) || b[i] == b'_') {
                i += 1;
            }
            if i < b.len() - 1 {
                // …then exactly `:-` and a literal default made of harmless bytes.
                assert!(
                    b[i] == b':' && i + 1 < b.len() - 1 && b[i + 1] == b'-',
                    "the only accepted suffix is colon-dash then a literal default"
                );
                i += 2;
                while i < b.len() - 1 {
                    assert!(
                        is_alnum(b[i]) || b[i] == b'_' || b[i] == b'.' || b[i] == b'-',
                        "a default may only contain letters, digits and `_.-`"
                    );
                    i += 1;
                }
            }
            Specifier { spec, expansion, requires }
        }

        pub const fn spec(&self) -> char {
            self.spec
        }

        /// The shell `policy.rs` emits. Validated by `new`, so splicing it is safe.
        pub const fn expansion(&self) -> &'static str {
            self.expansion
        }

        /// The sbatch options SLURM must have been given, or `&[]`.
        pub const fn requires(&self) -> &'static [&'static str] {
            self.requires
        }

        /// The environment variable, PARSED out of the expansion rather than stored twice
        /// (`P8`). Total, because `new` accepted the shape.
        pub fn variable(&self) -> &'static str {
            let e: &'static str = self.expansion;
            let inner = &e[2..e.len() - 1];
            match inner.find(":-") {
                Some(i) => &inner[..i],
                None => inner,
            }
        }

        /// `true` when an UNSET variable expands to nothing, so the guard would silently
        /// drop the specifier and check a shorter name than the one slurmd opens
        /// (`RA-2`). A non-empty default is a deliberate stand-in and is left alone.
        pub fn unset_is_unnameable(&self) -> bool {
            let e: &'static str = self.expansion;
            let inner = &e[2..e.len() - 1];
            match inner.find(":-") {
                Some(i) => inner[i + 2..].is_empty(),
                None => true,
            }
        }
    }
}
pub use output_specifier::Specifier;

/// SLURM filename specifiers husk allows in an `--output`/`--error` pattern, **paired with
/// the shell that expands each one**, because there is exactly one list and this is it.
///
/// **The admission rule.** A specifier belongs here only if husk's compute-node job guard
/// can replace it with a `%`-free value THAT IS THE ONE SLURMD USES. The guard re-derives
/// the file slurmd will open so it can `lstat` the leaf (A1-F1); a specifier it cannot
/// expand leaves a `%` in the name, which means husk cannot state which file slurmd opens,
/// which means it cannot verify it. `B1-1` was that gap: `%J` was accepted here and absent
/// from the guard, and the guard's unmodelled branch then disarmed the refusal for the
/// *next* path in the loop.
///
/// **The second half of that rule is `RA-2`, and it is why entries carry `requires`.** An
/// expansion that is `%`-free is not thereby CORRECT. Measured on Santis 2026-08-31, on a
/// non-array batch job: `sbatch --output=probe-A%A-a%a-s%s.log --wrap=true` produced
/// `probe-A837636-a4294967294-sbatch.log`, while `SLURM_ARRAY_JOB_ID`/`SLURM_ARRAY_TASK_ID`
/// are unset there and the guard rendered `probe-A-a-sbatch.log`. Both leaf checks — the
/// symlink one and `N1`'s hard-link one — then ran on a file slurmd never opens. husk does
/// not model what SLURM substitutes instead; it REFUSES the specifier when the option that
/// makes the variable exist was not given, which is decidable from the request alone.
///
/// **Why `%x` is absent** — slurmd expands it AFTER husk has validated the string and the
/// job name is agent-supplied, so `<workdir>/%x` with a job name of `..` resolves one level
/// above the workdir: a parser differential of exactly the F13/F14 kind.
///
/// **Why `%J` is absent** — husk has not measured what SLURM substitutes for it on these
/// clusters, so a guard-side expansion would be a guess, and a guessed name is a name husk
/// cannot check. (Nothing here claims to know what that rendering is; the previous text
/// asserted `jobid.stepid` and the measurement contradicted it — `RA-10`.)
///
/// **Why `%` is absent, and must stay absent** — `%` is the grammar's ESCAPE character, not
/// a specifier: `%%` denotes a literal `%`. A literal `%` in the leaf is exactly the thing
/// that cannot be expanded away, so admitting it re-arms `B1-1` in four characters
/// (`x%%y.log`) with no knowledge of any other gap.
///
/// **Order is the guard's substitution order** and the golden shell's line order, and it is
/// load-bearing: `%u` runs LAST because `USER` is the one value that could itself contain a
/// `%j`, and an earlier `%j` pass would then not re-scan it. Keep new entries at the end
/// unless you have argued about overlap. Pinned by
/// `the_emitted_expander_runs_in_the_tables_order`.
///
/// Paired by `no_leaf_the_validator_accepts_keeps_a_percent_past_the_expander` (the
/// contract), `every_specifier_expands_to_a_percent_free_value` (the local invariant) and
/// `the_refusal_message_states_exactly_the_accepted_set` (`P8`, `P11`). `policy.rs` emits
/// the guard's expander lines *from this table*, so the two cannot drift.
///
/// **A `requires` entry may only name an option the REQUEST supplies**, never one husk
/// forces — husk would satisfy its own gate and the entry would never refuse.
/// `every_requires_name_is_an_option_the_request_supplies` asserts that against
/// `sbatch::REGISTRY`; the reference test below cannot, because it goes red on every table
/// edit and its red only asks for the reference row to be updated (`RAB3-A1`).
///
/// **What this table CANNOT be is its own oracle** (`RA-4`): every test above reads the
/// expansion out of the table it is checking, so a self-consistent corruption — swapping
/// two expansions, naming the wrong variable, dropping an entry — is invisible to all of
/// them. `the_specifier_table_agrees_with_the_recorded_measurements` holds the independent
/// reference, with the provenance of each claim, and is the only test that can fail on
/// those.
pub const OUTPUT_SPECIFIERS: &[Specifier] = &[
    Specifier::new('j', "${SLURM_JOB_ID:-}", &[]),
    Specifier::new('A', "${SLURM_ARRAY_JOB_ID:-}", &["-a", "--array"]),
    Specifier::new('a', "${SLURM_ARRAY_TASK_ID:-}", &["-a", "--array"]),
    Specifier::new('N', "${SLURMD_NODENAME:-}", &[]),
    Specifier::new('n', "${SLURM_NODEID:-0}", &[]),
    Specifier::new('t', "${SLURM_LOCALID:-0}", &[]),
    Specifier::new('s', "${SLURM_STEP_ID:-batch}", &[]),
    Specifier::new('u', "${USER:-}", &[]),
];

/// The specifiers `name` uses that need an sbatch option the request may not carry
/// (`RA-2`), decoded with `is_valid_output_filename`'s own scanner so `%` handling cannot
/// drift from the validator's.
///
/// Returns the table entries themselves, so the caller reads the option spellings, the
/// variable and the specifier from ONE place (`P8`). This function deliberately knows
/// nothing about the request; the caller asks it for the options.
pub fn output_specifiers_needing_an_option(name: &str) -> Vec<&'static Specifier> {
    let mut out = Vec::new();
    let mut chars = name.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            continue;
        }
        // `%` always consumes the next character, so `%%A` cannot be read as `%A`. The
        // validator refuses `%%` outright, but this function must not depend on having
        // been called after it.
        let Some(spec) = chars.next() else { break };
        if let Some(s) = OUTPUT_SPECIFIERS.iter().find(|s| s.spec() == spec) {
            if !s.requires().is_empty() {
                out.push(s);
            }
        }
    }
    out
}

/// Specifiers husk names in its refusal as deliberately excluded, so the message teaches
/// the narrowing instead of merely enumerating what is left (`P11`).
///
/// Asserted DISJOINT from `OUTPUT_SPECIFIERS` by
/// `the_refusal_message_states_exactly_the_accepted_set`, so moving one of these into the
/// table cannot hide behind the sentence that calls it refused.
///
/// **`RA-10`: a reason here may state husk's own policy or a MEASURED fact, never a guess
/// about what slurmd renders.** These strings are prose paired with nothing — no test can
/// check them — so the standing rule is the only control. The `%J` entry used to read
/// *"jobid.stepid, a pair the guard cannot reassemble"*; measured on Santis 2026-08-31,
/// `sbatch --output=jprobe-%J.log --wrap=true` produced `jprobe-837641.log`, a bare job id
/// with no pair in it. husk was teaching the confined party a false fact about the system
/// it is confined by, and `P11` says the agent will reason from it.
const OUTPUT_SPECIFIERS_NAMED_REFUSED: &[(&str, &str)] = &[
    ("%x", "the job name - the agent picks it, and slurmd expands it after husk confined the path"),
    ("%J", "a specifier husk has not measured on this cluster, so expanding it would be a guess"),
    ("%%", "a literal percent sign, which no expansion can remove"),
];

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
                Some(spec) if OUTPUT_SPECIFIERS.iter().any(|s| s.spec() == spec) => continue,
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

/// The ONE refusal every confinement failure gives back to the agent.
///
/// **A7-1.** This used to be two messages, and telling them apart was an existence oracle
/// for the host filesystem. The broker canonicalises OUTSIDE the cage — correctly, that is
/// where SLURM writes — so `canonicalize` answers about paths the cage deliberately hides.
/// A caged agent that asked for `--output=/users/me/.ssh/x` got back
/// `"…" resolves to /users/me/.ssh which is outside …`, and for `/users/me/.gnupg/x` got
/// `"…" cannot be resolved (No such file or directory)`. One probe per candidate, no read
/// permission needed, and `ls` inside the cage says ENOENT to both. Husk's own refusal was
/// the only in-cage channel that confirmed `~/.ssh` exists (measured, A7).
///
/// So: identical bytes for "the workdir will not resolve", "the path will not resolve",
/// "it resolves outside the set" and "its last component is a symlink". The message may
/// still echo the agent's OWN input and name the directory it was confined to — the agent
/// supplied one and was told the other — but it carries no host fact it did not already
/// have: no resolved target, no errno, no present-vs-absent tell.
///
/// The detail is not lost, it is REDIRECTED: `confine_detail` writes it to the broker's own
/// stderr, outside the cage, where the operator reads it and the agent cannot. An
/// unattributed denial invites confident wrong remediation; an attributed one aimed at the
/// wrong party is a disclosure. Both audiences get what they need, separately.
///
/// `confine_under_any` already worked this way (it discards the inner error and reports the
/// writable SET); this makes the primitive itself safe, so the next caller cannot re-open
/// the oracle by forwarding what it returns.
fn confine_refusal(path: &str, workdir: &str) -> String {
    format!(
        "{path:?} is not a path this job may write. husk confines --chdir/--output/--error \
         to {workdir:?} and below, because SLURM writes those files as you and OUTSIDE the \
         sandbox. Such a path must already exist (SLURM does not create output \
         directories), must still be inside that directory once every symlink is resolved, \
         and its final component must not itself be a symlink."
    )
}

/// The refusal detail, for the OPERATOR only. Broker stderr is outside the cage.
///
/// Suppressed in the one mode where it is not: the wrapper falls back to a log inside the
/// SPOOL when `$HOME` is unusable, and the spool is agent-readable by construction (the
/// stub has to reach it). It sets `HUSK_LOG_AGENT_READABLE` from where the log actually
/// went. Unset is treated as reachable — a broker started by hand, or by a future caller
/// that forgets, must not silently start narrating host paths into the agent's log.
fn confine_detail(path: &str, workdir: &str, why: &str) {
    if std::env::var("HUSK_LOG_AGENT_READABLE").as_deref() == Ok("0") {
        eprintln!("husk-broker: refused {path:?} under {workdir:?}: {why}");
    } else {
        eprintln!("husk-broker: refused {path:?} (detail withheld: this log is agent-readable)");
    }
}

pub fn confine_under_workdir(path: &str, workdir: &str) -> Result<String, String> {
    let root = std::fs::canonicalize(workdir).map_err(|e| {
        confine_detail(path, workdir, &format!("the working directory does not resolve: {e}"));
        confine_refusal(path, workdir)
    })?;
    let target = std::fs::canonicalize(path).map_err(|e| {
        confine_detail(path, workdir, &format!("does not resolve: {e}"));
        confine_refusal(path, workdir)
    })?;
    if !target.starts_with(&root) {
        confine_detail(
            path,
            workdir,
            &format!("resolves to {}, outside {}", target.display(), root.display()),
        );
        return Err(confine_refusal(path, workdir));
    }
    Ok(target.to_string_lossy().to_string())
}

/// Validate an `--output`/`--error` value and return it canonicalised.
///
/// Splits directory from filename: the directory is resolved and confined, the filename is
/// checked as a pattern. A `%` anywhere in the DIRECTORY part is refused rather than
/// guessed at — husk cannot resolve a path it cannot expand, and validating an
/// unexpanded string would be validating something other than what slurmd opens.
///
/// **A1 (CRITICAL, found 2026-08-04).** The split is the whole difficulty: the filename may
/// carry `%j`, so it cannot be canonicalised, so only the PARENT went through
/// `confine_under_workdir` and the leaf was appended as text. A leaf that already existed as
/// a SYMLINK was therefore never resolved by husk — and slurmd, opening the path later as
/// the user and outside the cage, follows it. One `ln -s` inside the writable workdir turned
/// `--output` into an arbitrary write anywhere the user can write, with content the job
/// controls. The witness landed in a directory husk itself refuses.
///
/// Two disagreeing notions of "the same path" (husk's canonicalise-the-parent vs the
/// kernel's open-follows-the-final-symlink) is the F13/F14 shape again, and the fix is the
/// same shape too: make the two agree. Because the parent is FULLY canonical by the time we
/// get here, the leaf is the only unresolved component left, so one `symlink_metadata` on it
/// closes the gap without re-walking the path.
///
/// It closes the gap **at submission**. It does not close the window between husk's check
/// and slurmd's `open()` — the job may sit PENDING for hours in a directory the agent can
/// still write, and husk cannot make slurmd use `O_NOFOLLOW`. That half is enforced at the
/// other end, by the job guard, which refuses to run a body whose stdout/stderr does not
/// resolve inside the writable set (`policy.rs`, `--open-mode=append` + the fd check). This
/// check is the one that can TEACH; that one is the one that HOLDS.
/// Paths inside the writable root that `--output`/`--error` must nevertheless refuse.
///
/// **A1-F2 (CRITICAL, 2026-08-19).** Confinement asked one question — *is it under the writable
/// root?* — and that is not the same question as *may this be written*. husk masks
/// `.claude/*`, `.mcp.json`, `.git/hooks`, shell rc files and credentials **inside the cage**,
/// and `--output` is written by slurmd **outside** it, as the user, with `--open-mode=append`
/// forced. So `-o <root>/.claude/hooks/x.sh` was accepted, the run-time guard was satisfied
/// (the path IS under the root), the body ran, and its stdout was appended to a file Claude
/// Code executes on the next session. Attacker-chosen content, no race, no timing.
///
/// The lesson is the one husk keeps relearning: a mask inside the cage protects nothing from a
/// writer outside it. Every in-cage protection needs its out-of-cage twin, and `--output` is an
/// out-of-cage write primitive that nobody had classified as one.
///
/// Matched on the RESOLVED path so `.//.claude/../.claude/hooks/x` cannot spell its way past,
/// and on a path COMPONENT so `<root>/sub/.claude/hooks/x` is caught too — a nested project
/// directory is still a project directory to the agent runtime that reads it.
fn output_path_is_protected(resolved: &str, workdir: &str) -> Option<&'static str> {
    let rel = resolved.strip_prefix(workdir)?.trim_start_matches('/');
    let first = rel.split('/').next().unwrap_or("");
    // Directories husk masks wholesale, at any depth.
    for c in rel.split('/') {
        if AUTO_EXEC_DIRS.contains(&c) || c == ".git" || c == ".hg" {
            return Some("a directory husk masks because its contents are executed or trusted by a tool");
        }
    }
    // Individual files husk protects, at the root or nested.
    let leaf = rel.rsplit('/').next().unwrap_or("");
    for f in AUTO_EXEC_RO_FILES.iter().chain(AUTO_EXEC_RO_OR_EMPTY.iter()) {
        if leaf == *f {
            return Some("a file husk protects because a tool reads it as configuration");
        }
    }
    if LOGIN_AUTO_EXEC_DENY.contains(&leaf) || OUTPUT_PROTECTED_LEAVES.contains(&leaf) {
        return Some("a file husk protects because a tool reads it as configuration");
    }
    let _ = first;
    None
}

/// Names that must not be an `--output` target, beyond husk's own mask lists.
///
/// **The union is what matters here, and husk's half is not the whole set.** Shell rc files,
/// `.gitconfig` and `.ripgreprc` are masked on the login side by the VENDOR's protected-file
/// list, so husk never needed its own copy of them. But `--output` is refused by husk, using
/// husk's lists — so a name husk does not know is a name husk will happily write to, however
/// carefully the other layer hides it. A1-F2 surfaced `.bashrc` exactly that way.
///
/// Listed here rather than added to `AUTO_EXEC_DIRS`/`LOGIN_AUTO_EXEC_DENY` on purpose: those
/// two drive *mounts* and have their own pairing test, and widening them would change the cage
/// rather than the output check. This list answers one question — may a job's stdout be
/// appended here — and that is a different question from what the cage masks.
const OUTPUT_PROTECTED_LEAVES: &[&str] = &[
    ".gitconfig", ".gitmodules",
    ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
    ".zshrc", ".zprofile", ".zshenv", ".kshrc", ".cshrc", ".tcshrc",
    ".ripgreprc", ".gdbinit",
];

/// The refusal for an unacceptable `--output`/`--error` leaf — **generated from
/// `OUTPUT_SPECIFIERS`, not re-typed beside it** (`P8`).
///
/// This message is the ONLY statement of the accepted set the confined party can ever see:
/// `SKILL.md` lists option names, `constraints.md` and `THREAT-MODEL.md` say only that the
/// set excludes `%x`. So a hand-maintained copy here is a third list that drifts silently
/// into telling the agent that a string husk just refused is allowed — which `P11` says
/// will be read as a broken parser and retried verbatim.
///
/// It also says WHY the set is narrower than SLURM's, because "authorization, not
/// availability" is only half of `P11`: an agent that thinks husk's parser is buggy will go
/// looking for a way round it, and an agent told husk refuses what it cannot verify will
/// rename the file.
fn output_filename_refusal(file: &str) -> String {
    let allowed: Vec<String> =
        OUTPUT_SPECIFIERS.iter().map(|s| format!("%{}", s.spec())).collect();
    let refused: Vec<String> = OUTPUT_SPECIFIERS_NAMED_REFUSED
        .iter()
        .map(|(tok, why)| format!("{tok} is {why}"))
        .collect();
    format!(
        "{file:?} is not an acceptable output filename. Allowed: letters, digits, `._+-`, \
         and the SLURM specifiers {}. That set is NARROWER than SLURM's own, on purpose: \
         husk's job guard re-derives this filename on the compute node so it can check what \
         SLURM will actually open, and a specifier the guard cannot expand leaves husk \
         unable to name that file at all - so husk refuses it here, in a second, rather \
         than after the queue wait. Refused for that reason: {}. Rename the file; no option \
         re-enables them.",
        allowed.join(" "),
        refused.join("; ")
    )
}

pub fn confine_output_pattern(value: &str, workdir: &str) -> Result<String, String> {
    let (dir, file) = match value.rsplit_once('/') {
        Some((d, f)) => (if d.is_empty() { "/" } else { d }, f),
        // A bare filename is relative to --chdir, which is itself confined.
        None => (workdir, value),
    };
    // A RELATIVE directory means "relative to the job's working directory" — that is what
    // `--output=logs/x.out` means to SLURM. Resolve it against `workdir` explicitly instead
    // of letting `canonicalize` resolve it against the BROKER's cwd, which is a different
    // directory that the confinement result must not depend on.
    let joined;
    let dir = if dir.starts_with('/') {
        dir
    } else {
        joined = format!("{}/{}", workdir.trim_end_matches('/'), dir);
        &joined
    };
    if dir.contains('%') {
        // `RA-8`: this literal carried fourteen run-on spaces — the same broken
        // continuation the round-3 fix repaired in `output_filename_refusal`, five lines
        // away, in the same function, in the same diff. A refusal an agent cannot read
        // cleanly is a refusal it re-reads as a parser bug (`P11`).
        return Err(format!(
            "{value:?} puts a SLURM % specifier in a DIRECTORY component. husk cannot \
             resolve a directory it cannot expand, so only the filename may contain them."
        ));
    }
    if !is_valid_output_filename(file) {
        return Err(output_filename_refusal(file));
    }
    let dir = confine_under_workdir(dir, workdir)?;
    let full = format!("{dir}/{file}");
    // The leaf, and only the leaf: everything left of it is already canonical, so this one
    // `lstat` is the difference between the path husk validated and the path slurmd opens.
    // `symlink_metadata` does NOT follow, which is the entire point — `metadata` here would
    // report on the TARGET and pass a symlink pointing at the home directory.
    //
    // A leaf that does not exist is fine and must stay fine: `slurm-%j.out` never exists at
    // submission, and neither does the file of a first run. Absent is not a symlink.
    //
    // `RA-7`/`P15`: and ONLY for a leaf with no specifier in it. `full` is the UNEXPANDED
    // pattern, so for `slurm-%j.out` this `lstat`s a name slurmd will never open — the
    // control was aimed at the wrong object. It could not catch what it was written for,
    // and it could be TRIPPED: one `ln -s /etc/passwd '<workdir>/slurm-%j.out'` inside the
    // writable set, which the agent can create, refused every default submission for the
    // life of that directory. An agent-triggerable denial of service is a poor price for a
    // check that answers nothing. The expanded leaf is checked where it can be named — in
    // the compute-node guard, by `_husk_name_bad`, after the substitutions have run.
    if !file.contains('%')
        && std::fs::symlink_metadata(&full).map(|m| m.file_type().is_symlink()).unwrap_or(false)
    {
        confine_detail(value, workdir, "its final component is a symlink");
        return Err(confine_refusal(value, workdir));
    }
    // UNDER THE ROOT IS NOT THE SAME QUESTION AS MAY BE WRITTEN (A1-F2).
    let root = std::fs::canonicalize(workdir)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| workdir.to_string());
    if let Some(why) = output_path_is_protected(&full, &root) {
        return Err(format!(
            "{value:?} names {why}. husk hides that path from the job, but --output is written \
             by SLURM OUTSIDE the cage, as you, and husk forces --open-mode=append — so \
             directing output there would append the job's stdout to the real file, or create \
             a new one that a tool later executes. Choose another name inside {workdir}."
        ));
    }
    Ok(full)
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
/// Read one settings layer, or `None` if it makes no claims.
///
/// **An EMPTY file is treated as an ABSENT file**, and that is a deliberate definition
/// rather than a leniency. `resolve` already says why absence is safe — *"the human made no
/// claims in a file they did not write"* — and a zero-byte file is precisely that case: there
/// are no denies in it to lose, so failing closed protects nothing.
///
/// It is also, empirically, the normal state of these paths. Anthropic's runtime creates
/// zero-byte `settings.json` / `settings.local.json` in a project's `.claude/` directory on
/// its own, and a human who opens one in vim and `:wq`s leaves the same thing. Refusing to
/// start on it made husk unusable in a directory it had itself been run in (2026-08-06: four
/// consecutive sessions in one project dir died at startup, and every `sbatch` and `squeue`
/// the agent made then timed out at 120s against a broker that was no longer there).
///
/// What must NOT change: a file with CONTENT that does not parse still refuses. That one is a
/// typo in real policy, where denies genuinely are being lost, and "deny that cannot be read
/// must never resolve to deny nothing" still holds. Whitespace counts as empty.
/// What must ALSO not change, and did not until `RE-1`: the read has to finish. Two of the
/// three sources live in the directory the CONFINED AGENT writes, and this was a bare
/// `read_to_string` — no bound on the size, and no check on what it was opening. One `mkfifo`
/// there refused every later launch of husk, permanently, and a 200 MB file cost 207 MB of
/// RSS per read on a login node. Both are now decided by `read_settings_layer`, in the lib,
/// so the wrapper's preflight and the network allowlist get the same bound from the same
/// place rather than three copies of it (`P8`).
pub(crate) fn settings_layer(path: &Path) -> Layer {
    use husk_slurm_broker::SettingsLayer as Raw;
    let bytes = match husk_slurm_broker::read_settings_layer(path) {
        Raw::Absent => return Layer::Absent,
        // The DISPOSITION stays "contributes nothing", which is unchanged behaviour: the old
        // `read_to_string(path).ok()?` skipped an unreadable layer too, and turning that into
        // a refusal is a separate question from this fix — not one to answer by adding a
        // third refusal to the launch path in the same pass.
        //
        // What does NOT stay is the SENTENCE. husk used to print "is empty, so it sets no
        // policy" for a `chmod 000` layer holding real `denyRead` entries: a false statement
        // of fact, about a file whose denies were being silently dropped, three lines below a
        // comment reading "deny that cannot be read must never resolve to deny nothing". The
        // error is carried out of the reader for exactly this (`P7`, `P11`).
        Raw::Unreadable(e) => {
            return Layer::Unreadable(format!(
                "{} exists but husk could not read it ({e}), so it is setting NO policy for                  this session — any denyRead, denyWrite or credential mask in it is not in                  effect. That is not the same as an empty file, and husk is not guessing which                  it is. Fix the permissions and start husk again if it was meant to apply.",
                path.display()
            ))
        }
        Raw::NotARegularFile => {
            return Layer::Refused(format!(
                "{} is not a regular file. husk reads the sandbox policy for this session \
                 from that path, and will not open a directory, a device or a FIFO to find \
                 it — a FIFO in particular blocks until something writes to it, and this read \
                 runs before husk launches, again on every job submission, and inside the \
                 job's own egress proxy, so husk would simply stop with nothing naming the \
                 cause. Remove it — `rm`, or `rmdir` if it is a directory — or put a JSON \
                 file there.",
                path.display()
            ))
        }
        Raw::TooLarge(n) => {
            return Layer::Refused(format!(
                "{} is {n} bytes and husk reads at most {} from a settings layer. That is far \
                 larger than any settings file — the ones this repository ships are a few \
                 hundred bytes to a few kilobytes — so if this is the right path, something \
                 other than a person wrote it. husk will not read it into memory to find out.",
                path.display(),
                husk_slurm_broker::MAX_SETTINGS_BYTES
            ))
        }
        Raw::Bytes(b) => b,
    };
    // Strict UTF-8, and a layer that is not valid UTF-8 reads as absent — again UNCHANGED:
    // `read_to_string` rejected those bytes and `.ok()?` dropped the layer. The wrapper
    // decodes the SAME files leniently on purpose (`RC-2`), because it is modelling what the
    // vendor runtime does with them; this reader is husk's own policy, not a model of
    // somebody else's, so it is left exactly as it was.
    let Ok(text) = String::from_utf8(bytes) else { return Layer::Absent };
    if text.trim().is_empty() { Layer::Absent } else { Layer::Text(text) }
}

/// One settings layer, and the one disposition husk reached about it.
///
/// `pub(crate)` because the network allowlist reads the SAME three files and used to do it
/// with its own bare `read_to_string`. Two readers of one policy that disagree is the
/// divergence class this project keeps paying for (A4-F3); there is one reader now.
pub(crate) enum Layer {
    /// Not there, or nothing in it. Contributes no policy.
    Absent,
    /// Present, and husk could not read it. Contributes no policy either — the SAME
    /// disposition as `Absent`, deliberately and unchanged — but not the same sentence, and
    /// husk must not claim such a file is empty (`P7`).
    Unreadable(String),
    /// The layer's text.
    Text(String),
    /// husk will not read this file. Carries the sentence an operator gets: which file, why,
    /// and what to do about it (`P11`). The measured symptom of NOT carrying one was an
    /// operator sent to look at a spool for a problem in a settings layer.
    Refused(String),
}

/// Append `src` to `dst`, keeping order and dropping duplicates, in linear time.
///
/// **`if !dst.contains(&p) { dst.push(p) }` is quadratic in a list the CONFINED AGENT
/// authors, and it appeared EIGHT times, not six.** Bounding the settings READ (`RE-1`) caps
/// the bytes, not the work done with them — and a one-megabyte `denyRead` is tens of
/// thousands of entries.
///
/// **The first version of this fix replaced the six in `union` and left the two below it, and
/// the benchmark did not notice** — which is the whole lesson, so it is written down rather
/// than quietly corrected. `union` was measured with entries naming paths that DO NOT EXIST:
/// 5,000 entries 0.03 s, 20,000 0.41 s, 88,291 **10.96 s**, and 0.08 s after. But
/// `split_file_denies` only moves an entry into `deny_files` when `is_file()` says the path is
/// real, so a benchmark of nonexistent paths never enters the loop that survived. **The
/// attacker picks the paths.** Re-measured end to end on the release broker with a 1 MiB layer
/// naming 38,828 REAL files: **2.575 s** with only `union` fixed, 0.02 s with all eight.
///
/// So: sweep the expression, do not fix the instance (`P5`), and benchmark the input an
/// adversary would choose, not the one that is easy to generate (`P9`).
///
/// The byte bound is what makes the input finite; this is what makes the cost linear in it,
/// and neither is sufficient alone.
fn extend_deduped(dst: &mut Vec<String>, src: Vec<String>) {
    let mut seen: std::collections::HashSet<String> = dst.iter().cloned().collect();
    for p in src {
        if seen.insert(p.clone()) {
            dst.push(p);
        }
    }
}

pub const SETTINGS_SOURCES: [(bool, &str); 3] = [
    (true, ".claude/settings.json"),   // ~/.claude/settings.json
    (false, ".claude/settings.json"),  // <project>/.claude/settings.json
    (false, ".claude/settings.local.json"),
];

/// The home roots the compute cage must never expose — and, separately, the subset husk
/// will actually ask bwrap to mask.
///
/// **Two sets, because the two questions have different safe answers.** This was one
/// hard-coded `&["/users"]` and nothing derived it from `$HOME` (`B2-1`), which failed in
/// both directions off CSCS:
///
/// * where `/users` does not exist — Euler's homes are `/cluster/home/<user>`, and Euler is
///   already named in `FABRIC_DEVICES` — `--tmpfs /users` is emitted with no `-try` (there
///   is no `--tmpfs-try`), so **every brokered job dies in cage setup**:
///   `bwrap: Can't mkdir /users: Read-only file system`, a bare bwrap error that never says
///   "husk". That is the failure `CREDENTIAL_SOCKET_DIRS` documents 900 lines above for
///   `/run/munge`; the fix moved one instance and not this one.
/// * where `/users` exists but homes are elsewhere — fail OPEN. The mask covers an
///   irrelevant directory, `abs_for_cage` throws away every `~/…` entry on the premise that
///   the floor covers it, and `is_workdir_allowed` will accept a home as a writable
///   `--chdir`.
///
/// So:
///
/// * `hidden` is the REFUSAL set — "may this path be a carve-out / a writable workdir?".
///   It is the site defaults **plus** the real `$HOME`, always. Refusing more can only ever
///   fail closed, and a site literal that means nothing here refuses nothing that exists.
/// * `masked` is the EMISSION set — "which `--tmpfs` do we hand bwrap?". A wrong entry here
///   kills the job, so it holds only roots husk can VOUCH FOR: `$HOME` itself, or a site
///   default that `$HOME` sits under and which therefore provably exists.
///
/// **No stat here, deliberately.** Deciding emission by `Path::exists()` would read a
/// login-node shape at submit time to choose a compute-node mount minutes later — `C3-4`'s
/// class. `$HOME` is the same string on both nodes, and a site default is emitted only when
/// `$HOME` is under it. (`drop_unmountable_hides` does take one existence reading, once, at
/// startup, and states its own trade.)
///
/// **Textual only, like `normalize_abs`.** A `$HOME` reached through a symlink
/// (`/users/me -> /lustre/users/me`) is masked at the spelling `$HOME` has, which is the
/// spelling every process on the node sees; a workdir spelled through the *other* path is
/// not recognised as a home. Canonicalising would fix that and would put a blocking Lustre
/// stat on the startup path, so it is a stated residual, not an oversight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Floor {
    hidden: Vec<String>,
    masked: Vec<String>,
}

impl Default for Floor {
    /// The CSCS shape, taken on faith.
    ///
    /// Every production `FsPolicy` comes from `resolve`, which derives the floor from
    /// `$HOME`; nothing outside `#[cfg(test)]` constructs one any other way. `Default`
    /// exists for the unit tests and for both guard goldens, which record `--tmpfs /users`
    /// and would otherwise have to be regenerated to say nothing at all. Derived through
    /// `for_home_str` rather than re-spelling the constant, so there is ONE derivation
    /// (`P8`).
    fn default() -> Floor {
        // A home under the first site default: the shape Balfrin and Santis actually have.
        Floor::for_home_str(&format!("{}/husk-default-home", SITE_FLOOR_DEFAULTS[0]))
            .expect("the site default is an absolute path")
    }
}

impl Floor {
    /// Derive the floor from the broker's `$HOME`, or refuse — never guess.
    ///
    /// An unusable `$HOME` (unset, empty, relative, containing `..`, or `/`) means husk
    /// cannot say which home the cage is supposed to hide. The alternatives are to guess
    /// the site literal — which is what `B2-1` is — or to mask nothing, which is the
    /// fail-open half of the same finding. It refuses instead, with the cause named, because
    /// an unattributed denial invites confident wrong remediation (`P11`) and the caller's
    /// follow-up line talks about JSON.
    pub fn for_home(home: &Path) -> Result<Floor, String> {
        Floor::for_home_str(&home.to_string_lossy())
    }

    fn for_home_str(home: &str) -> Result<Floor, String> {
        let Some(norm) = normalize_abs(home) else {
            return Err(format!(
                "HOME is {home:?}, which is not a usable absolute path, so husk cannot work \
                 out which home directory the compute cage must hide. The cage masks the \
                 submitting user's home root — that is what keeps a job from reading \
                 ~/.claude/.credentials.json — and husk will not build a cage it cannot aim. \
                 This is about the ENVIRONMENT husk was started in, not about any settings \
                 file: set HOME to the user's home directory and start husk again."
            ));
        };
        if norm == "/" {
            return Err(
                "HOME is \"/\", so the home root husk would hide is the whole filesystem. \
                 The compute cage masks the submitting user's home; masking / would leave \
                 every job with nothing at all. This is about the ENVIRONMENT husk was \
                 started in, not about any settings file: set HOME to the user's home \
                 directory and start husk again."
                    .to_string(),
            );
        }
        // A site default is CONFIRMED when this user's home sits under it: then it provably
        // exists on every node that has this home, and masking the whole of it is what husk
        // has always done at CSCS. Unconfirmed, it stays in `hidden` (refusing costs
        // nothing) and never reaches bwrap.
        let confirmed: Vec<String> = SITE_FLOOR_DEFAULTS
            .iter()
            .filter(|f| norm == **f || norm.starts_with(&format!("{f}/")))
            .map(|f| (*f).to_string())
            .collect();
        let mut hidden: Vec<String> = SITE_FLOOR_DEFAULTS.iter().map(|f| (*f).to_string()).collect();
        if !hidden.contains(&norm) {
            hidden.push(norm.clone());
        }
        let masked = if confirmed.is_empty() { vec![norm] } else { confirmed };
        Ok(Floor { hidden, masked })
    }

    /// The roots bwrap is asked to `--tmpfs`. Shallowest-first ordering is the ops loop's
    /// job, not this one's.
    fn masked(&self) -> &[String] {
        &self.masked
    }

    /// True if `p` equals or is nested under a hidden root. Such a path must never be
    /// re-exposed by an allow carve-out (the floor must hold regardless of config) and is
    /// not an acceptable writable workdir. (F18/F15)
    ///
    /// This doc block used to sit on `usable_carveout` — the item below it — leaving the
    /// predicate it describes undocumented. Same mechanism as `B1-4`'s seven, in a second
    /// file.
    fn covers(&self, p: &str) -> bool {
        // A path that will not normalise (relative, or containing `..`) is not a path we can
        // vouch for, so it counts as under the floor: the caller's question is always "may I
        // expose this?", and the safe answer to an unresolvable path is no.
        let Some(norm) = normalize_abs(p) else {
            return true;
        };
        self.hidden
            .iter()
            .any(|floor| norm == *floor || norm.starts_with(&format!("{floor}/")))
    }

    /// May this configured path become an allow carve-out at all?
    ///
    /// No if it is under a hidden root (the floor must hold regardless of config, F18), and
    /// no if it is the filesystem ROOT. The root is not "under" the floor but it dissolves
    /// the whole cage: `--bind / /` is emitted after every mask and re-covers the floor,
    /// `--dev`, `--proc` and both tmpfs mounts, so the job sees the host's real /dev and
    /// /proc despite `--unshare-pid`. Measured: 280 device nodes instead of 14.
    fn usable_carveout(&self, p: &str) -> bool {
        !self.covers(p) && !matches!(normalize_abs(p).as_deref(), None | Some("/"))
    }
}

/// The refusal-only floor for the callers that hold no `FsPolicy`.
///
/// `is_workdir_allowed` is a free function called from `step.rs`, which has no resolved
/// policy in hand. Reading `$HOME` here is safe in a way it would NOT be in `bwrap_args`:
/// this set only ever REFUSES, so an environment husk cannot read makes it refuse the same
/// things it refused before and never fewer. An unusable `$HOME` is fatal in `resolve`,
/// where the emission depends on it; here it degrades to the site defaults rather than
/// taking the process down on the request path.
fn ambient_floor() -> Floor {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    Floor::for_home(&home).unwrap_or_else(|_| Floor {
        hidden: SITE_FLOOR_DEFAULTS.iter().map(|f| (*f).to_string()).collect(),
        masked: Vec::new(),
    })
}

/// Is `cwd` an acceptable working directory to force as `--chdir` and bind WRITABLE into
/// the compute cage? The agent controls `req.cwd`, and the workdir is re-bound writable
/// on top of the read-only root + the `--tmpfs` floor, so an unconfined `cwd` re-mounts
/// root read-write (`cwd="/"`) or re-exposes a home (`cwd="/users/x"`). Reject: relative
/// or empty, `/`, any path with a `..` component, and any path equal to or under a hidden
/// root. Jobs must run from a scratch/project path. (F15/F19)
///
/// The hidden set now includes the real `$HOME`, not only the site literal, which is the
/// half of `B2-1` that fails OPEN: on a site whose homes are outside `/users` this used to
/// accept `/cluster/home/victim` as an agent-supplied `req.cwd` and bind it WRITABLE.
///
/// `policy::decide` asks `FsPolicy::workdir_allowed` instead, which can also see the
/// operator's `denyRead` roots. This form is for the caller that has no policy.
pub fn is_workdir_allowed(cwd: &str) -> bool {
    is_workdir_allowed_under(cwd, &ambient_floor())
}

/// `is_workdir_allowed` against an explicit floor — the form the tests pin, so the property
/// asserted is "a home is refused" and not "the string `/users` is refused" (`P15`).
pub fn is_workdir_allowed_under(cwd: &str, floor: &Floor) -> bool {
    match normalize_abs(cwd) {
        None => false,
        Some(n) => n != "/" && !floor.covers(&n),
    }
}

/// What husk hides but cannot PROVE, said out loud once at startup.
///
/// `Floor::for_home` masks the home root it can vouch for: `$HOME`, or a site default that
/// `$HOME` sits under. On a site where neither applies — homes somewhere husk has never seen
/// — that is this user's home and no more, so OTHER users' homes are protected by POSIX
/// permissions and not by husk.
///
/// **This is a line, not a refusal, and that is deliberate.** Refusing to start on every
/// site whose homes are not under `/users` would be an operator-aimed denial of service in
/// the name of a property the cage never had there anyway; guessing `$HOME`'s parent would
/// be worse, because on a site where `$HOME` is `/scratch/<user>` it would `--tmpfs` the
/// whole scratch filesystem. So husk states exactly what it masks, and names the one-line
/// configuration change that widens it (`P7`, `P11`).
fn floor_scope_note(floor: &Floor, present: &dyn Fn(&str) -> bool) -> Option<String> {
    if floor.masked().iter().any(|m| SITE_FLOOR_DEFAULTS.contains(&m.as_str())) {
        return None;
    }
    // WHICH of the two situations is this? The note used to assert the first without asking,
    // and the two want opposite remediations (`M-3`, `P11` with the polarity flipped — a
    // confident wrong DIAGNOSIS rather than an unattributed one). On a Balfrin node with a
    // mis-set `HOME` an operator was told, in husk's voice, that their site's homes are not
    // under `/users`, and sent to add a `denyRead` line the shipped config already carries.
    //
    // One existence reading settles it, and it is taken ONLY on this branch — the CSCS shape
    // returned above without touching the filesystem, so Balfrin and Santis pay nothing.
    // Injected rather than called directly so the answer is a test input; `resolve` passes
    // `shape_at_submit`, which does NOT follow symlinks and so cannot be walked into a
    // hanging network mount below the root it is asked about (`C3-4`'s reader, `P15`).
    let here: Vec<&str> = SITE_FLOOR_DEFAULTS.iter().copied().filter(|f| present(f)).collect();
    if !here.is_empty() {
        // The site root husk knows IS on this machine and `$HOME` is somewhere else. The
        // likeliest cause by far is a wrong `HOME`, and the remedy is not a config line.
        return Some(format!(
            "{} exists on this machine, but HOME ({}) is not under it — so the cage hides \
             THIS user's home and not the site-wide home root, and other users' homes are \
             protected by POSIX permissions and not by husk. husk derives the cage from \
             HOME and will not guess: if HOME is wrong here, fix it and start husk again. \
             If homes on this site really do live outside {}, add the real home root to \
             sandbox.filesystem.denyRead and husk will mask it and refuse it as a working \
             directory as well.",
            here.join(", "),
            if floor.masked().is_empty() { "<none>".to_string() } else { floor.masked().join(", ") },
            here.join(", ")
        ));
    }
    // Unchanged, deliberately: this is the sentence husk has always printed, and it is now
    // printed only when it has been CHECKED. `FIX-M.md` quotes it verbatim.
    Some(format!(
        "this site's homes are not under any root husk knows ({}), so the cage hides THIS \
         user's home and not a site-wide home root. If all homes here live under one \
         directory, add it to sandbox.filesystem.denyRead and husk will mask it and refuse \
         it as a working directory as well.",
        SITE_FLOOR_DEFAULTS.join(", ")
    ))
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

/// Resolve a filesystem-policy entry to an absolute path for the COMPUTE cage:
/// - absolute (`/x`) → itself
/// - home-relative (`~/x`) → `None`: it lives under a home, already hidden by the floor's
///   `--tmpfs`, so there is nothing to bind
/// - workdir-relative (`x`, `./x`) → joined onto the workdir
///
/// **That `None` is only sound because the floor is derived from `$HOME`.** It was not:
/// with a hard-coded `/users` this discarded 19 of the shipped config's 20 `denyRead`
/// entries — the OAuth-token mask included — on a premise that was false anywhere else
/// (`B2-1`). `Floor::for_home` makes the premise true, and `FsPolicy::dispositions` now
/// says so per entry instead of leaving it to be inferred.
///
/// **Why `~` is still not expanded here.** Emitting the 19 entries as real mounts under the
/// home would (a) duplicate a mask that already covers all of them, (b) route each one
/// through `path_has_symlink_component`, which drops any path with a symlinked component —
/// and `$HOME` on a cluster is very often behind one, so entries would start vanishing
/// quietly (`B2-5`), and (c) add 19 more submit-time shape observations to the nine
/// `C3-4` already counts. The cheaper and more honest fix is to make the premise hold and
/// state it.
///
/// (the writable project
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


/// The shape of a mount TARGET, as husk found it.
///
/// **`Symlink` is a variant of its own on purpose.** Every one of these call sites used
/// `symlink_metadata`, whose `is_file()`/`is_dir()` are both false for a link; folding that
/// into "other" is how a shape check silently stops applying to a whole class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Dir,
    File,
    Symlink,
    /// A socket, fifo, device node — or a path husk could not stat for any reason other
    /// than absence.
    Other,
    /// Not there (and, as with the `Path::exists()` this replaces, not distinguishable from
    /// "there but not stat-able").
    Absent,
}

/// Read a mount target's shape **on the login node, at submit time** — the one place that
/// does, so the residual below is stated once instead of on three of ten sites.
///
/// **THE RESIDUAL, and it belongs to every caller.** bwrap runs on a COMPUTE node minutes
/// to hours later, and it creates the mount points it is given: `--tmpfs` needs a directory
/// or nothing, `--ro-bind /dev/null` needs a file or nothing. Both mismatches kill the cage
/// before the job starts, with a message that never says "husk" (measured, bubblewrap
/// 0.6.1):
///
/// ```text
/// submit saw a DIRECTORY, mount finds a FILE:
///   bwrap: Can't mkdir …/.mask: Not a directory                  exit=1
/// submit saw a FILE, mount finds a DIRECTORY:
///   bwrap: Can't create file at …/.mask: Is a directory           exit=1
/// ```
///
/// This is not hypothetical and not only an operator's problem: on 2026-08-09 **3 of 4
/// concurrent brokered jobs died in cage setup** this way, because the LOGIN cage
/// ghost-creates `/dev/null` placeholders in the same project directory for the duration of
/// one Bash command. The window is also reachable from inside the cage — the project
/// directory is agent-writable, so a name the credential scan classified as a secret can be
/// turned from a file into a directory while the job is PENDING. That direction is
/// fail-closed (the job dies) and self-inflicted, which is why it is a residual and not a
/// containment finding.
///
/// **Closing it means resolving the shape on the compute node**, the way the credential
/// socket masks already are, or a per-job private mount. That moves work into the generated
/// guard and belongs with `ROADMAP` F2. What could land now, and did, is the enumeration:
/// every site, one reader, and `every_submit_time_shape_read_goes_through_one_function`
/// fails if another appears. `C3-4`, `C4`.
fn shape_at_submit(path: &str) -> Shape {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => Shape::Dir,
        Ok(m) if m.is_file() => Shape::File,
        Ok(m) if m.file_type().is_symlink() => Shape::Symlink,
        Ok(_) => Shape::Other,
        Err(_) => Shape::Absent,
    }
}

/// "Is there something here worth preserving?" — the other submit-time question, and it
/// FOLLOWS symlinks where `shape_at_submit` does not.
///
/// Kept separate rather than folded into a `Shape` predicate because the two really are
/// different questions and the answers differ for exactly the input that matters: a symlink
/// to a real `.Rprofile`. Same residual as `shape_at_submit` — see there.
fn present_at_submit(path: &str) -> bool {
    std::fs::metadata(path).is_ok()
}

/// `shape_at_submit` for a configured policy entry, resolved into the cage the way the
/// emission resolves it. An entry that has no place in this cage (`~/x`) has no shape.
fn resolved_shape(entry: &str, workdir: &str) -> Shape {
    match abs_for_cage(entry, workdir) {
        Some(abs) => shape_at_submit(&abs),
        None => Shape::Absent,
    }
}

/// What became of one line of `sandbox.filesystem` / `sandbox.credentials`.
///
/// **Every line gets exactly one of these, and there is no fifth answer.** Before this,
/// `resolve` printed a tailored refusal for two of the four ways an entry could vanish, one
/// of the other two was silent (`B2-5`), and the message that did print was wrong for a
/// whole class (`C3-2`: the shipped config's own `allowRead: ["./"]` was refused on the
/// grounds that the project directory "is inside a home directory"). Measured on the
/// shipped `user-config/settings.json`: 21 of 27 entries produced **no bwrap argument and
/// no line of output**, and the 2 that spoke were wrong.
///
/// This is `C2` — one disposition per input line — as a type rather than a `bool` inside a
/// `retain`. `netallow::EntryError` is the same shape and is the only other place in the
/// crate that has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// It reaches the compute cage's mount table. `cage_path` says as what.
    Applied,
    /// Already in effect by construction, so emitting it would be a no-op — not a refusal.
    /// `allowRead: "./"` is this: the project directory is the workdir and is bound
    /// writable before any carve-out is considered.
    Redundant(&'static str),
    /// Nothing to emit because the floor already masks the whole region. Carries the root
    /// that does the masking, which is the sentence `B2-1` needed and nobody could print:
    /// on CSCS it reads `/users`, on a site whose homes are elsewhere it reads that site's
    /// home root, and if it ever read something surprising the operator would see it.
    CoveredByFloor(String),
    /// Dropped. The string is what the human is told, and it is the only place that text
    /// exists.
    Refused(String),
}

/// One line of configured filesystem policy and what happened to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEntry {
    /// The settings field it came from — `"allowRead"`, `"denyWrite"`, … Used in messages
    /// so an operator can find the line in the file.
    pub field: &'static str,
    /// Exactly as written in the settings file.
    pub raw: String,
    /// The absolute path it would appear as in the mount table, when it appears at all.
    /// `None` means it cannot be resolved for this cage.
    pub cage_path: Option<String>,
    /// The single answer.
    pub disposition: Disposition,
}

impl PolicyEntry {
    /// Does this entry reach bwrap? The `dispositions` ↔ `bwrap_args` pairing test asks
    /// this and then checks the argument list, so the ledger cannot claim an effect the
    /// mount table does not have (`P15` — the mount table is the oracle).
    pub fn is_applied(&self) -> bool {
        matches!(self.disposition, Disposition::Applied)
    }
}

/// `FsPolicy`, and everything that can build or change one, in a module the rest of this
/// file is OUTSIDE of.
///
/// **The module is the control**, for the reason `P6` states in those words: Rust's
/// encapsulation unit is the MODULE, not the type. `FsPolicy` had nine `pub` fields and a
/// derived `Default`, so
///
/// ```ignore
/// let fs_policy = FsPolicy { allow_write: vec!["/".into()], ..Default::default() };
/// ```
///
/// was a legal expression in `main.rs`, `step.rs` and `policy.rs` — a cage with no operator
/// denies, no credential masks, `--bind / /` emitted last over every mask husk had just
/// placed, and a floor guessed at CSCS's shape on a site that may not have it. One line,
/// no new warning, and it reads like ordinary construction. `FsPolicy::unchecked_for_test()` was the
/// same thing in six characters. That is `B5-1` in a type that carries CONTENT instead of a
/// type that carries "the check ran", and `P17` is the rule that says to go find the rest
/// of them rather than fix the one that was reported.
///
/// The four conditions `P6` lists for the wrapper's witnesses, restated for this one:
///
///   1. **every field is private to this module**, so neither a struct literal nor a
///      `..base` update nor a post-hoc `pol.deny_read.clear()` compiles outside it
///      (E0451/E0616). The parent module is not exempt — `mod tests` lives there, and the
///      thirty-six hand-built policies in it are exactly where this habit came from;
///   2. **no `Default`, and no trait `impl` that introduces one.** `RC-5` was three
///      characters against the wrapper's witnesses (`.unwrap_or_default()`), and this type
///      shipped with the derive;
///   3. **the only `pub fn` returning an `FsPolicy` is `resolve`**, which is the function
///      that runs the validation. `parse` returns an unvalidated *layer* — no floor, no
///      shape split, no drops — so it is `pub(super)`: this file and its tests, nowhere
///      else;
///   4. **the test door is named `unchecked_for_test`**, is `#[cfg(test)]` so it exists in
///      no production build, and is what every hand-built policy in the suite now says
///      about itself at its own call site.
///
/// `the_policy_type_stays_unmintable_outside_resolve` compiles all four against a real
/// rustc, one mutation per compilation, and derives its field list from the struct below —
/// so a tenth field is covered on the day it is added, not on the day someone remembers to
/// extend a list (`P8`).
///
/// **What no module boundary can cover**, and `P6` says it in its own last paragraph: the
/// BODY of `resolve`. A validation that returns `Ok` without checking anything is
/// indistinguishable from one that checks. Nor does any of this survive `unsafe`
/// (`mem::zeroed`, `transmute`), which remains possible by design.
mod fs_policy {
    use super::*;

    /// The slice of settings we act on: `sandbox.filesystem.{allowRead,denyRead,
    /// allowWrite,denyWrite}` plus credential files to mask (`sandbox.credentials.files`).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FsPolicy {
        allow_read: Vec<String>,
        deny_read: Vec<String>,
        /// Writable roots (`sandbox.filesystem.allowWrite`). The compute cage is
        /// default-deny for writes (root is `--ro-bind`), so each is bound read-write.
        allow_write: Vec<String>,
        /// Paths made read-only within writable roots (`sandbox.filesystem.denyWrite`);
        /// takes precedence over allowWrite, so applied after the write binds.
        deny_write: Vec<String>,
        /// `sandbox.filesystem.allowGitConfig` — when true, `.git/config` stays
        /// writable (git remote-url edits); `.git/hooks` is protected regardless.
        allow_git_config: bool,
        /// Credential files made unreadable (from `sandbox.credentials.files`): bound
        /// with `/dev/null` so the job reads empty, mirroring the login cage which
        /// masks them. `mask` mode is degraded to deny — husk does not implement
        /// value-masking yet, and deny is the safe degrade (same as the runtime does).
        deny_files: Vec<String>,
        /// Credential env-var names to drop (`sandbox.credentials.envVars`): emitted
        /// as bwrap `--unsetenv` so a secret in the broker's session env doesn't ride
        /// into the job. (`mask` mode degrades to unset, same as files.) Not strictly
        /// filesystem, but it's the same credential-protection policy from settings.
        unset_env: Vec<String>,
        /// Absolute `denyRead` roots husk REFUSES as a working directory but does NOT emit as a
        /// `--tmpfs`, because they are not on this machine when the broker starts.
        ///
        /// **`Floor` already split exactly this pair and `deny_read` did not** (`M-2`).
        /// `deny_read` has the same two consumers as the floor — an EMISSION consumer
        /// (`bwrap_args`, where a wrong entry kills every job) and a REFUSAL consumer
        /// (`workdir_allowed`, where over-refusing costs nothing) — and one list served both, so
        /// `drop_unmountable_hides` deleted a mount and a control in the same statement. The
        /// disclosed residual was a confidentiality one ("the path is readable"); the undisclosed
        /// half was an INTEGRITY one, because `req.cwd` is agent-supplied and the workdir is
        /// `--bind`-ed read-WRITE and forced as `--chdir`. An operator `denyRead` root that
        /// materialises after broker start — autofs, a late mount, a directory an operator
        /// creates mid-session — became a legal writable working directory for a brokered job.
        ///
        /// Nothing in a settings file can put an entry here; `drop_unmountable_hides` is the only
        /// writer, and it moves entries out of `deny_read` rather than copying them, so no path
        /// is ever in both lists and there is nothing for the two to disagree about (`P8`).
        deny_read_unmountable: Vec<String>,
        /// The home roots this policy hides, derived from `$HOME` by `resolve` (`B2-1`).
        ///
        /// It lives on the policy rather than in a constant because `bwrap_args` is a METHOD
        /// and `bwrap_args` is where the mask is emitted — the alternative was a process-global
        /// read of `$HOME` inside the function that decides mounts, which is exactly the
        /// implicit-state shape this file spent `RE-1` removing. `pub`, but `Floor`'s own fields
        /// are private, so the only ways to get one are `Floor::for_home` and `Floor::default`.
        floor: Floor,
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

    /// The complete READ surface, and it is complete on purpose.
    ///
    /// Only two of the nine have a production caller today (`allow_write` in `policy.rs`,
    /// `unset_env` in `step.rs`); the rest are what the suite asks a resolved policy. They are
    /// here as a set rather than one-at-a-time because the alternative — add the accessor when
    /// someone needs it — is how a `pub` field comes back, and `#[allow(dead_code)]` on the
    /// block is the cheaper half of that trade. Nothing here can widen a cage: a reader forges
    /// nothing.
    #[allow(dead_code)]
    impl FsPolicy {
        // A reader cannot forge a cage, so these are `pub` while every mutator is not.
        // They return slices, not `&Vec`, so a caller cannot reach `push` through one; that is
        // not pedantry, it is the same hole in a second spelling (`P5` — the class, not the
        // instance).
        pub fn allow_read(&self) -> &[String] {
            &self.allow_read
        }
        pub fn deny_read(&self) -> &[String] {
            &self.deny_read
        }
        pub fn allow_write(&self) -> &[String] {
            &self.allow_write
        }
        pub fn deny_write(&self) -> &[String] {
            &self.deny_write
        }
        pub fn deny_files(&self) -> &[String] {
            &self.deny_files
        }
        pub fn unset_env(&self) -> &[String] {
            &self.unset_env
        }
        /// The `denyRead` roots husk refuses as a workdir but does NOT mount — see the field.
        pub fn deny_read_unmountable(&self) -> &[String] {
            &self.deny_read_unmountable
        }
        pub fn allow_git_config(&self) -> bool {
            self.allow_git_config
        }
        pub fn floor(&self) -> &Floor {
            &self.floor
        }
    }

    impl FsPolicy {
        /// The seed `resolve` starts from: the derived floor, and nothing else at all.
        ///
        /// Private to this module, and it replaces `FsPolicy { floor, ..Default::default() }` —
        /// the last production caller of a `Default` that every module in the crate could reach.
        /// Every field is written out rather than defaulted in, for the reason the literal in
        /// `parse` gives: a tenth field then has to be ANSWERED here.
        fn empty_with_floor(floor: Floor) -> FsPolicy {
            FsPolicy {
                allow_read: Vec::new(),
                deny_read: Vec::new(),
                allow_write: Vec::new(),
                deny_write: Vec::new(),
                allow_git_config: false,
                deny_files: Vec::new(),
                unset_env: Vec::new(),
                deny_read_unmountable: Vec::new(),
                floor,
            }
        }

        // ---- the test door, and it says so ------------------------------------------------
        //
        // `#[cfg(test)]`, so none of this exists in a shipped broker: the probe
        // `unchecked_for_test_is_not_reachable_in_a_production_build` compiles the non-test
        // configuration and requires E0599 on this very name.
        //
        // It is deliberately NOT impossible to hand-build a policy — a test that can only reach
        // `resolve` cannot drive `drop_unmountable_hides` past an absent path, and the suite
        // needs to. What changed is that the bypass now NAMES ITSELF at every call site instead
        // of looking like construction. `RJMK` found the cost of the old spelling:
        // `the_floor_is_the_home_the_site_has_and_not_the_string_users` hand-built its policy,
        // so `drop_unmountable_hides` never ran on it and the test stayed green under the
        // mutation that restored `M-1`'s bug. A reader of that test could not see the gap. A
        // reader of `FsPolicy::unchecked_for_test()` can.

        /// A policy **no validation has ever run on** — no floor derivation, no ledger, no
        /// shape split, no symlink or floor-overlap drop, no credential scan. Tests only.
        #[cfg(test)]
        pub(crate) fn unchecked_for_test() -> FsPolicy {
            // `Floor::default()` and not a real derivation, which is what `FsPolicy::unchecked_for_test()`
            // did before it and is why both guard goldens still record `--tmpfs /users`
            // byte-for-byte.
            FsPolicy::empty_with_floor(Floor::default())
        }

        // The setters are `with_*` and take `self`, so every chain has to START at
        // `unchecked_for_test()`; there is no way to spell one that does not carry the word.
        #[cfg(test)]
        pub(crate) fn with_allow_read(mut self, v: Vec<String>) -> FsPolicy {
            self.allow_read = v;
            self
        }
        #[cfg(test)]
        pub(crate) fn with_deny_read(mut self, v: Vec<String>) -> FsPolicy {
            self.deny_read = v;
            self
        }
        #[cfg(test)]
        pub(crate) fn with_allow_write(mut self, v: Vec<String>) -> FsPolicy {
            self.allow_write = v;
            self
        }
        #[cfg(test)]
        pub(crate) fn with_deny_write(mut self, v: Vec<String>) -> FsPolicy {
            self.deny_write = v;
            self
        }
        #[cfg(test)]
        pub(crate) fn with_deny_files(mut self, v: Vec<String>) -> FsPolicy {
            self.deny_files = v;
            self
        }
        #[cfg(test)]
        pub(crate) fn with_unset_env(mut self, v: Vec<String>) -> FsPolicy {
            self.unset_env = v;
            self
        }
        #[cfg(test)]
        pub(crate) fn with_allow_git_config(mut self, v: bool) -> FsPolicy {
            self.allow_git_config = v;
            self
        }
        #[cfg(test)]
        pub(crate) fn with_floor(mut self, v: Floor) -> FsPolicy {
            self.floor = v;
            self
        }
        /// Parse one settings file. Unknown keys are ignored; malformed JSON or an
        /// absent `sandbox.filesystem` block -> empty policy (fail-safe: no carve-outs).
        pub(super) fn parse(json: &str) -> Result<FsPolicy, String> {
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
                // Empty, always, and the compiler is what keeps it that way: this is an explicit
                // struct literal, so a new field has to be answered here rather than defaulted in
                // silently. No settings file can name a path husk refuses to mount — that is a
                // fact about the MACHINE, decided once by `drop_unmountable_hides`.
                deny_read_unmountable: Vec::new(),
                // A LAYER is not a cage: the floor belongs to the resolved policy, and
                // `resolve` sets it from `$HOME` before anything reads it. `union` deliberately
                // does not merge it — there is nothing in a settings file that can move it.
                floor: Floor::default(),
            })
        }


        /// Say, for every line the human wrote, what the compute cage does with it.
        ///
        /// Called on the UNIONED, pre-drop policy — `resolve` runs it before
        /// `drop_floor_overlapping_allows` and `drop_symlinked_carveouts`, because after those
        /// the refused entries are gone and there is nothing left to explain. It answers using
        /// the same predicates the emission uses (`Floor::usable_carveout`, `abs_for_cage`,
        /// `path_has_symlink_component`) rather than a second copy of the rules, and the
        /// pairing test drives it against the real `compute_bwrap_args` so the two cannot
        /// drift.
        ///
        /// `is_symlink` is the same closure `drop_symlinked_carveouts` takes: the real
        /// `path_has_symlink_component` in `resolve`, a stub in tests.
        ///
        /// **What it does not cover.** It classifies entries that came from settings. The
        /// credential AUTO-SCAN's results are added afterwards and are not configured lines, so
        /// they have no ledger entry; the scan already announces its own truncation. It also
        /// says nothing about `allowGitConfig`, which is a flag and not a path.
        pub fn dispositions(&self, workdir: &str, is_symlink: &dyn Fn(&str) -> bool) -> Vec<PolicyEntry> {
            let mut out = Vec::new();

            // --- allowRead / allowWrite: the carve-outs, and the only field that can be REFUSED
            for (field, list) in [("allowRead", &self.allow_read), ("allowWrite", &self.allow_write)] {
                for p in list {
                    let entry = |d, c| PolicyEntry { field, raw: p.clone(), cage_path: c, disposition: d };
                    if p == "./" || p == "." {
                        // NOT a refusal, and this is the whole of `C3-2`. `bwrap_args` skips it
                        // by name with the comment "the project dir == workdir, bound writable
                        // below" — it is already in effect, so calling it refused and telling
                        // the operator to "allow a project path instead" sent them to do the
                        // thing they had already done (`P11`, `P13`).
                        out.push(entry(
                            Disposition::Redundant(
                                "the project directory is the job's workdir and is bound writable \
                                 before any carve-out is considered",
                            ),
                            None,
                        ));
                        continue;
                    }
                    if matches!(normalize_abs(p).as_deref(), Some("/")) {
                        out.push(entry(Disposition::Refused(format!(
                            "{p:?} is not in effect, and jobs get the normal cage. Binding the root \
                             would also undo /dev, /proc and the private /tmp and /dev/shm, which is \
                             more than that line asks for. List the roots you actually need instead \
                             — e.g. \"/scratch\", \"/capstor\" — and they will be bound exactly as \
                             written."
                        )), None));
                        continue;
                    }
                    if p.starts_with('~') {
                        // A `~/x` carve-out. The old message was RIGHT for this one and wrong
                        // for everything else it fired on, which is why it is kept here and
                        // narrowed to here.
                        out.push(entry(Disposition::Refused(format!(
                            "{p:?} is not in effect. It is inside a home directory ({}), which husk \
                             hides from every job regardless of config. Copy what the job needs to a \
                             scratch or project path and allow that.",
                            self.floor.masked().join(", ")
                        )), None));
                        continue;
                    }
                    if !p.starts_with('/') {
                        // A relative carve-out other than `./`. It CANNOT be emitted — the
                        // emission filters on `starts_with('/')` — and it is not a home path, so
                        // the old message was wrong here too.
                        out.push(entry(Disposition::Refused(format!(
                            "{p:?} is not in effect: a filesystem carve-out must be an ABSOLUTE path. \
                             Anything inside the project directory is already in the job's writable \
                             workdir and needs no carve-out; anything outside it must be named in \
                             full — e.g. \"/capstor/scratch/cscs/you/data\"."
                        )), None));
                        continue;
                    }
                    if self.floor.covers(p) {
                        out.push(entry(Disposition::Refused(format!(
                            "{p:?} is not in effect. It is inside a home directory ({}), which husk \
                             hides from every job regardless of config. Copy what the job needs to a \
                             scratch or project path and allow that.",
                            self.floor.masked().join(", ")
                        )), None));
                        continue;
                    }
                    if is_symlink(p) {
                        // Reported, where it used to be dropped in silence 40 lines above a
                        // sibling whose own comment condemns exactly that (`B2-5`). On HPC this
                        // is not exotic: `/scratch -> /lustre/scratch` voids every carve-out
                        // under it, and the operator's only symptom was a job that could not
                        // find its data.
                        out.push(entry(Disposition::Refused(format!(
                            "{p:?} is not in effect: one of its path components is a SYMLINK, and husk \
                             will not bind a carve-out whose source it cannot vouch for — bwrap \
                             follows the link, so the job would get whatever it points at rather than \
                             what you wrote. Name the target directly (`readlink -f` shows it)."
                        )), None));
                        continue;
                    }
                    out.push(entry(Disposition::Applied, Some(p.clone())));
                }
            }

            // --- the denies: they cannot be refused, only resolved or covered by the floor
            for (field, list) in [
                ("denyRead", &self.deny_read),
                ("denyWrite", &self.deny_write),
                ("credentials.files", &self.deny_files),
            ] {
                for p in list {
                    let entry = |d, c| PolicyEntry { field, raw: p.clone(), cage_path: c, disposition: d };
                    match abs_for_cage(p, workdir) {
                        // `~/x`. Nothing is emitted, and nothing needs to be — the floor masks
                        // the whole home. THAT SENTENCE IS THE FINDING: it was asserted with a
                        // hard-coded `/users` and was false anywhere else (`B2-1`). Now it names
                        // the root that actually does the masking, so if it is ever wrong it is
                        // wrong out loud.
                        None => out.push(entry(
                            Disposition::CoveredByFloor(self.floor.masked().join(", ")),
                            None,
                        )),
                        Some(abs) if field != "credentials.files" && self.floor.covers(&abs) => {
                            // A `denyWrite`/`denyRead` under the floor. The floor already hides
                            // it and a `--ro-bind` would UN-hide it (a deny that grants), so the
                            // entry is dropped — correctly, and now visibly.
                            out.push(entry(Disposition::CoveredByFloor(self.floor.masked().join(", ")), None))
                        }
                        Some(abs) => out.push(entry(Disposition::Applied, Some(abs))),
                    }
                }
            }
            out
        }

        /// Drop the hides bwrap cannot mount, and say which — the OTHER source of `B2-1`'s
        /// mode (a).
        ///
        /// `--tmpfs DEST` makes bwrap `mkdir` DEST, and by then the root is `--ro-bind`, so an
        /// absent DEST is `bwrap: Can't mkdir /users: Read-only file system` and **the job never
        /// starts**. There is no `--tmpfs-try`.
        ///
        /// Deriving the FLOOR from `$HOME` fixes only half of it, and this was measured rather
        /// than reasoned: husk's own shipped `user-config/settings.json` carries
        /// `denyRead: ["/users"]` as an explicit entry, so on a site with no `/users` the
        /// argument comes back from the config even after the floor stops producing it. The
        /// derived floor and the operator's entry are two independent sources of one mount, and
        /// `B2-1` saw only the first because `extend_deduped` merges them before anyone looks.
        ///
        /// **The trade, stated because it is a real one — and it is smaller than it was.**
        /// Dropping an absent hide is FAIL-OPEN for the MOUNT: if the path appears after broker
        /// startup it is not `--tmpfs`-ed for the rest of the session. It is NOT fail-open for
        /// the WORKDIR: the entry moves to `deny_read_unmountable` and `workdir_allowed` still
        /// refuses it. That distinction is `M-2`, and it was the difference between a
        /// confidentiality residual and an integrity one — the dropped path used to become a
        /// legal agent-supplied `req.cwd`, bound read-WRITE and forced as `--chdir`.
        ///
        /// Keeping the mount is fail-closed and costs the operator every job, on a site husk has
        /// never run on, with a message that does not say "husk" — the shape this round has
        /// already reverted one fix for. So: drop the MOUNT, keep the REFUSAL, and say so at
        /// startup in husk's voice with the remedy attached (`P7`, `P11`). Dropping the mount is
        /// also the posture `denyWrite` has always had, one loop below: `--ro-bind-try p p` skips
        /// an absent `p`, under a comment that reasons it out. `denyRead` was the field where the
        /// class was named and the other instance left — `C4` again.
        ///
        /// What is NOT traded is the home mask: the floor is derived from `$HOME`, which exists
        /// wherever the broker is running. A hide nested under another hide is kept too — bwrap
        /// creates it inside that tmpfs, parents and all (measured: `--tmpfs /mnt --tmpfs
        /// /mnt/absent` and `--tmpfs /mnt --tmpfs /mnt/a/b/c` both exit 0) — **but only under a
        /// hide that SURVIVES this function**, which is `M-1` and is why the ancestor set is read
        /// after the floor loop and not before.
        pub(super) fn drop_unmountable_hides(&mut self, workdir: &str) {
            let report = |p: &str, what: &str| {
                eprintln!(
                    "husk: DROPPED the {what} {p:?} — nothing is there on this machine, and a \
                     mask of a path that does not exist is not a weaker cage, it is NO CAGE AT \
                     ALL: bwrap creates its own mount points and the job's root is read-only, so \
                     husk would have killed every job with `Can't mkdir {p}: Read-only file \
                     system` and no mention of husk. If this path is supposed to exist here, fix \
                     that; if it belongs to another site, remove the entry."
                );
            };
            let mut kept_floor = Vec::new();
            for m in std::mem::take(&mut self.floor.masked) {
                if shape_at_submit(&m) == Shape::Absent {
                    report(&m, "hidden home root");
                } else {
                    kept_floor.push(m);
                }
            }
            self.floor.masked = kept_floor;
            let mut kept = Vec::new();
            let mut refuse_only = std::mem::take(&mut self.deny_read_unmountable);
            for p in std::mem::take(&mut self.deny_read) {
                let ops_loop = p.starts_with('/') && !is_under_writable_root(&p, workdir, &self.allow_write);
                // READ FROM THE FIELD, NOT FROM A SNAPSHOT — `M-1`, and the snapshot is deleted
                // rather than moved so there is no earlier moment for a future edit to take it at.
                //
                // "A hide nested under another hide is kept, because bwrap creates it inside that
                // tmpfs" is sound, and it is sound only about a tmpfs husk is still going to
                // EMIT. Taken before the loop above, this list still held the floor roots that
                // loop had just dropped, so a `denyRead` under an absent `$HOME` was kept on the
                // strength of an ancestor that no longer existed — `B2-1` mode (a) surviving
                // inside the function written to prevent it. Reproduced against bwrap 0.6.1:
                // `bwrap: Can't mkdir parents for /<absent-home>/.ssh: Read-only file system`,
                // exit=1, every job.
                let covered = self.floor.masked.iter().any(|a| p.starts_with(&format!("{a}/")));
                if !ops_loop || covered || shape_at_submit(&p) != Shape::Absent {
                    kept.push(p);
                } else {
                    report(&p, "denyRead entry");
                    // The MOUNT goes; the REFUSAL stays (`M-2`). Only the ops-loop arm reaches
                    // here, so `p` is absolute — the spelling `workdir_allowed` compares against.
                    refuse_only.push(p);
                }
            }
            self.deny_read = kept;
            self.deny_read_unmountable = refuse_only;
        }

        /// Is `cwd` an acceptable working directory FOR THIS POLICY?
        ///
        /// `is_workdir_allowed`'s ambient form cannot see the operator's configuration; this one
        /// can, and it is what `policy::decide` asks. Two sources, both fail-closed:
        ///
        /// * the derived floor — `$HOME` and any site default `$HOME` confirms;
        /// * every ABSOLUTE `denyRead` root. `config.rs` already says of the explicit entry that
        ///   "the floor is CSCS-shaped, and a site whose homes are elsewhere would lose the
        ///   protection with nothing to notice — **the explicit entry is what survives that**".
        ///   It did not survive: the entry masked the path and left it a legal writable
        ///   `--chdir`. Now an operator on a site with homes under `/cluster/home` writes one
        ///   `denyRead` line and gets both halves.
        ///
        /// **Including the entries husk will not MOUNT** — `deny_read_unmountable`, and this is
        /// `M-2`. The first version of this function read `deny_read` alone, and
        /// `drop_unmountable_hides` runs LAST in `resolve`, so for a path that was not there at
        /// broker start the returned policy had already lost the refusal the sentence above
        /// promises. Measured: `deny_read after resolve = []`, `workdir_allowed(that path) =
        /// true`. Refusing a path husk cannot mount costs nothing and is the safe direction; a
        /// mount husk cannot make costs every job. Two questions, two sets — the split `Floor`
        /// already has.
        ///
        /// **What it does not cover:** `step.rs` still calls the ambient `is_workdir_allowed`
        /// for a STEP's cwd. That is inside an already-built cage and a strictly smaller
        /// question, but it is a second reader of one policy and it belongs in this function;
        /// `step.rs` is another pass's file this round.
        pub fn workdir_allowed(&self, cwd: &str) -> bool {
            let Some(n) = normalize_abs(cwd) else { return false };
            if n == "/" || self.floor.covers(&n) {
                return false;
            }
            !self
                .deny_read
                .iter()
                .chain(self.deny_read_unmountable.iter())
                .filter(|d| d.starts_with('/'))
                .any(|d| {
                    let d = d.trim_end_matches('/');
                    n == d || n.starts_with(&format!("{d}/"))
                })
        }

        /// One line an operator can read at startup that says what the policy file actually
        /// does — the line `B2-1` was invisible for want of.
        ///
        /// Deliberately a SUMMARY and not 27 lines: `resolve` runs once per broker, the
        /// refusals are printed in full beside it, and a per-entry list every launch is the
        /// crying-wolf failure this file already reasons about for the empty-layer notice.
        pub(super) fn ledger_summary(&self, ledger: &[PolicyEntry]) -> String {
            let count = |f: &dyn Fn(&PolicyEntry) -> bool| ledger.iter().filter(|e| f(e)).count();
            format!(
                "compute cage: hiding the home root(s) {}; of {} configured filesystem-policy \
                 entries {} reach the mount table, {} are already covered by that mask, {} are \
                 redundant and {} were refused (each refusal is printed above).",
                if self.floor.masked().is_empty() { "<none>".to_string() } else { self.floor.masked().join(", ") },
                ledger.len(),
                count(&|e| e.is_applied()),
                count(&|e| matches!(e.disposition, Disposition::CoveredByFloor(_))),
                count(&|e| matches!(e.disposition, Disposition::Redundant(_))),
                count(&|e| matches!(e.disposition, Disposition::Refused(_))),
            )
        }

        /// Union another layer in (dedup). All layers are trusted and carve-outs are
        /// additive, so a higher layer can only ADD allows/denies — never remove a
        /// deny (which keeps the merge fail-safe regardless of layer precedence).
        pub(super) fn union(&mut self, other: FsPolicy) {
            extend_deduped(&mut self.allow_read, other.allow_read);
            extend_deduped(&mut self.deny_read, other.deny_read);
            // Merged for the same reason as the line above it, and it is a REFUSAL set, so the
            // merge can only ever refuse more. `parse` leaves this empty, so no settings layer
            // reaches here today; omitting it would mean a hand-built policy silently loses a
            // workdir refusal on union, which is the precise failure `M-2` was.
            extend_deduped(&mut self.deny_read_unmountable, other.deny_read_unmountable);
            extend_deduped(&mut self.allow_write, other.allow_write);
            extend_deduped(&mut self.deny_write, other.deny_write);
            extend_deduped(&mut self.deny_files, other.deny_files);
            extend_deduped(&mut self.unset_env, other.unset_env);
            // A trusted layer opting into git-config writes wins (OR).
            self.allow_git_config = self.allow_git_config || other.allow_git_config;
        }

        /// Resolve the full hierarchy: global `~/.claude/settings.json`, then the
        /// project's `settings.json`, then `settings.local.json` (where the CLI
        /// `/sandbox` toggle and permission grants land). Missing/unreadable files
        /// are skipped — fail-safe.
        /// Would `resolve` choke on the settings files as they stand right now? **Parse only.**
        ///
        /// `resolve` is not a read, it is a CONSTRUCTION. After parsing it stats every deny
        /// entry, lstats every path component of every carve-out, and ends in `scan_credentials`
        /// — a walk of the workdir bounded at `SCAN_MAX_ENTRIES` (20 000) and depth 4, guarded
        /// by a comment stating the reason it is affordable: **"Scan-once at construction"**.
        ///
        /// Calling it per request put that walk on the submission path. On Lustre, in a workdir
        /// the size of a LETKF benchmark, every `sbatch` then blew through the stub's 120-second
        /// wall and the agent saw `timed out after 120s waiting for the SLURM broker` — with the
        /// broker perfectly healthy and merely stat-ing (2026-08-06, production). Same shape as
        /// the original husk freezes: an in-process tree walk blocking on Lustre metadata, moved
        /// onto a path that runs often.
        ///
        /// This reads at most three JSON files — at most `MAX_SETTINGS_BYTES` each, which is what
        /// makes "small" a property of the code and not a hope about the agent (`RE-1`) — and
        /// parses them, which is the entire question the submit-time check asks — *would the compute side refuse these?* — and the
        /// answer does not depend on a single directory entry in the workdir.
        pub fn settings_parse_ok(home: &Path, project_dir: &Path) -> Result<(), String> {
            let files = SETTINGS_SOURCES.map(|(from_home, rel)| {
                if from_home { home.join(rel) } else { project_dir.join(rel) }
            });
            for f in files {
                // The SAME rule `resolve` uses — via the same function, not a second copy of the
                // condition. Two readers of one policy that disagree about what "empty" means is
                // the divergence class this project keeps paying for (A4-F3).
                match settings_layer(&f) {
                    Layer::Absent => {}
                    // Silent HERE and announced in `resolve`, and that asymmetry is the point:
                    // this runs on every `sbatch`, and a line per submit for a condition that
                    // does not change is the crying-wolf failure. The operator was told once, at
                    // startup, on the same fact.
                    Layer::Unreadable(_) => {}
                    // The submit path, and the one that runs while the agent is RUNNING. A layer
                    // husk will not read is refused here for the same reason it is refused at
                    // startup: this check exists to answer "would the compute side choke on
                    // these?", and the compute side would. Refusing a job is the mild half —
                    // before `RE-1` this call BLOCKED on a FIFO the agent had just created, and
                    // the broker's request loop never came back, so every later `sbatch` and
                    // `squeue` in the session timed out at 120s against a live broker.
                    Layer::Refused(why) => return Err(why),
                    Layer::Text(text) => {
                        FsPolicy::parse(&text).map_err(|e| format!("{}: {e}", f.display()))?;
                    }
                }
            }
            Ok(())
        }

        pub fn resolve(home: &Path, project_dir: &Path) -> Result<FsPolicy, String> {
            // FIRST, and fatal. Everything below decides mounts, and husk cannot decide which
            // home to hide from a `$HOME` it cannot read. Refusing here beats the two
            // alternatives `B2-1` measured in the field: guess the site literal and either kill
            // every job (`bwrap: Can't mkdir /users: Read-only file system`, no `--tmpfs-try`
            // exists) or mask an irrelevant directory and leave the real home readable.
            let floor = Floor::for_home(home)?;
            let mut pol = FsPolicy::empty_with_floor(floor);
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
                // Empty == absent; see `settings_layer`. Announced rather than silent,
                // because this runs ONCE at startup: an operator who truncated a real policy
                // file should see that husk read nothing from it, and a per-request warning
                // would be the crying-wolf failure instead.
                match settings_layer(&f) {
                    // A layer husk WILL NOT READ is not the same as a layer that says nothing,
                    // and the difference is a launch: this arm is the FIFO and the 200 MB file
                    // (`RE-1`). It is fail-closed for the same reason the unparseable arm below
                    // is — the file may hold denies, and deny that cannot be read must never
                    // resolve to deny nothing. It refuses in 0.001s with the file named, where
                    // before it hung forever with the operator reading about a Lustre walk.
                    Layer::Refused(why) => return Err(why),
                    // Said out loud, once, at startup. It used to fall into the arm below and be
                    // reported as "is empty", which was false whenever the file had content husk
                    // simply could not reach (`P7`).
                    Layer::Unreadable(why) => eprintln!("husk: {why}"),
                    Layer::Absent if f.exists() => eprintln!(
                        "husk: {} is empty, so it sets no policy — husk is treating it as absent. \
                         If you meant to configure something, it did not take effect.",
                        f.display()
                    ),
                    Layer::Absent => {}
                    Layer::Text(text) => {
                        let layer = FsPolicy::parse(&text)
                            .map_err(|e| format!("{}: {e}", f.display()))?;
                        pol.union(layer);
                    }
                }
            }
            // SAY WHAT HAPPENED TO EVERY LINE, before anything drops one.
            //
            // The order matters and is the whole of `C3-2`: after the two `retain`s below the
            // refused entries are gone, so a ledger computed afterwards can only describe the
            // survivors. Computed once, printed once, and the two `drop_*` functions are now
            // silent — one input line, one disposition, one place that says it (`C2`, `P7`).
            let wd = project_dir.to_string_lossy().to_string();
            let ledger = pol.dispositions(&wd, &(path_has_symlink_component as fn(&str) -> bool));
            for e in &ledger {
                if let Disposition::Refused(why) = &e.disposition {
                    eprintln!("husk: REFUSED the {} entry {why}", e.field);
                }
            }
            eprintln!("husk: {}", pol.ledger_summary(&ledger));
            if let Some(note) = floor_scope_note(&pol.floor, &|p: &str| shape_at_submit(p) != Shape::Absent) {
                eprintln!("husk: {note}");
            }

            // Route every deny to the emission its SHAPE allows: `--tmpfs` for a directory,
            // `--ro-bind /dev/null` for a file.
            pol.split_denies_by_shape(|p| resolved_shape(p, &wd));
            // Never let an allow carve-out re-expose a hidden home root: drop any
            // allowRead/allowWrite equal to or under a floor. The floor must hold "regardless
            // of config" — this fixes that over-promise and backstops the F17 chain. (F18)
            //
            // BEFORE the symlink filter now, and the swap is free: both are `retain`s, so the
            // surviving set is the same either way. Only the ORDER OF EXPLANATION changed, and
            // the ledger evaluates the same way — an entry that can never be a carve-out is
            // told so on grounds of its spelling, whatever happens to be on disk (`B2-5`).
            pol.drop_floor_overlapping_allows();
            // Drop allow carve-outs where ANY path component (leaf OR an intermediate
            // directory) is a symlink: bwrap follows symlinks on the bind source, so a
            // symlinked component could expose a target the human didn't configure. A
            // leaf-only lstat would miss an intermediate symlink (`/a/b/c` where `/a/b`
            // is the symlink), so walk every component. (F20)
            pol.drop_symlinked_carveouts(path_has_symlink_component);
            // F6a — bounded credential auto-scan of the WORKDIR only (never
            // /users-wide): deny un-declared secret files the user didn't list in
            // credentials.files, so a brokered job can't read (and, once the net cage
            // relaxes, exfiltrate) them. Scan-once at construction — a compute job is
            // structurally single-construction (bwrap is frozen mid-job). Depth- and
            // count-capped; fail-safe (fewer denies on error, base cage still holds).
            let scan = scan_credentials(project_dir);
            extend_deduped(&mut pol.deny_files, scan.files);
            // Whole credential DIRECTORIES go to `deny_read`, which is the `--tmpfs` side. They
            // must not go to `deny_files`: that is a `/dev/null` bind, and bwrap refuses to put
            // a file over a directory — the same mistake `split_denies_by_shape` exists to stop
            // an operator making by hand.
            extend_deduped(&mut pol.deny_read, scan.dirs);
            // LAST, so it sees the final hide set — including anything the credential scan just
            // added. Reported once here rather than per job, and acted on here rather than in
            // `bwrap_args`, so the emission stays free of filesystem calls (`C3-4`).
            pol.drop_unmountable_hides(&wd);
            // F21 — the scan is best-effort; if the entry budget was exhausted before
            // the walk finished (a deeply/widely-populated workdir, or an agent padding
            // the tree to starve the scanner), it is INCOMPLETE and a secret may be left
            // unmasked. Never fail silently: warn to stderr so the operator knows to
            // declare deep secrets explicitly. The base cage (the floor + explicit
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
        ///
        /// **This used to be the silent one** (`B2-5`): it dropped a line a human deliberately
        /// wrote with no output at all, forty lines above a sibling whose comment condemns
        /// exactly that, and — because it ran FIRST — it also swallowed the message that
        /// sibling would have printed. The report now comes from `FsPolicy::dispositions`,
        /// which reaches this case through the same predicate.
        pub(super) fn drop_symlinked_carveouts(&mut self, is_symlink: impl Fn(&str) -> bool) {
            self.allow_read.retain(|p| !is_symlink(p));
            self.allow_write.retain(|p| !is_symlink(p));
        }

        /// Drop allow carve-outs that equal or nest under a hidden root, so a config
        /// `allowRead:["/users"]` can never re-expose the floor inside the cage. (F18)
        ///
        /// **It no longer prints.** It used to print two tailored refusals here while its
        /// sibling `drop_symlinked_carveouts`, forty lines above and running FIRST, dropped a
        /// human's line in silence (`B2-5`) — and the message it did print was wrong for a
        /// third of the entries it fired on, telling an operator that `allowRead: "./"` "is
        /// inside a home directory" (`C3-2`). One line of config now gets exactly one stated
        /// disposition, computed once by `FsPolicy::dispositions` and printed once by
        /// `resolve`. This function just enforces it. (`C2`)
        pub(super) fn drop_floor_overlapping_allows(&mut self) {
            // ...and the filesystem ROOT, which is not "under" the floor but dissolves the
            // entire cage. `allowWrite: ["/"]` emits `--bind / /` LAST, so it re-covers not
            // just the floor but `--dev`, `--proc`, `--tmpfs /tmp` and `--tmpfs /dev/shm` as
            // well: measured, the job then saw 280 host device nodes instead of 14, and read
            // host PID 1 through the real /proc despite `--unshare-pid`. One config entry
            // undoing every mount that came before it is not a carve-out, it is an off switch.
            // Say what was refused, and why, and what to write instead.
            //
            // Silently dropping a line a human deliberately wrote is the defect this review
            // found four times over in other places. It is worse here than most, because
            // refusing `/` is not husk overruling a choice about write access — it is husk
            // saying the setting does something OTHER than what it says. `--bind / /` is
            // emitted after every mask, so it re-covers /dev, /proc and both tmpfs mounts too.
            // Somebody who asked for broad write access got device and /proc exposure they did
            // not ask for and could not see. Naming actual roots gets them exactly what they
            // wanted, with the rest of the cage intact.
            let floor = self.floor.clone();
            self.allow_read.retain(|p| floor.usable_carveout(p));
            self.allow_write.retain(|p| floor.usable_carveout(p));
        }

        /// Route every deny entry to the emission its SHAPE allows — **both directions**.
        ///
        /// bwrap's `--tmpfs` only works on a directory and `--ro-bind /dev/null` only on a file,
        /// so a `denyRead` that is a file and a `credentials.files` that is a directory are the
        /// same mistake mirrored. Only the first half existed. The second was a live kill: an
        /// operator writing
        ///
        /// ```json
        /// "credentials": { "files": [ { "path": "/capstor/scratch/you/proj/.secrets" } ] }
        /// ```
        ///
        /// where `.secrets` is a DIRECTORY got `--ro-bind /dev/null /…/.secrets` with no shape
        /// check anywhere on the path, and **every brokered job died in cage setup** with
        /// `bwrap: Can't create file at /…/.secrets: Is a directory` — no husk in it. Moving it
        /// to `deny_read` makes it a `--tmpfs`, which masks the whole directory rather than
        /// nothing at all. `C3-4`, and the "fix the sibling in the same pass" rule.
        ///
        /// The shape is read through `resolved_shape`, so a relative entry is classified at the
        /// path the CAGE will use rather than wherever the broker process happens to be
        /// standing — which is what the old `std::fs::metadata(p)` on the raw entry did.
        ///
        /// **What this does NOT cover:** the shape can still change between here and the mount.
        /// See `shape_at_submit`.
        ///
        /// `shape` classifies each entry (`resolved_shape` in `resolve`; a closure in tests).
        pub(super) fn split_denies_by_shape(&mut self, shape: impl Fn(&str) -> Shape) {
            let (files, dirs): (Vec<String>, Vec<String>) = std::mem::take(&mut self.deny_read)
                .into_iter()
                .partition(|p| shape(p) == Shape::File);
            self.deny_read = dirs;
            let (cred_dirs, cred_rest): (Vec<String>, Vec<String>) =
                std::mem::take(&mut self.deny_files).into_iter().partition(|p| shape(p) == Shape::Dir);
            self.deny_files = cred_rest;
            extend_deduped(&mut self.deny_files, files);
            extend_deduped(&mut self.deny_read, cred_dirs);
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
                // Why the RANK cage does not add it. A rank JOINS the holder's PID namespace
                // (`bwrap --pidns <fd>`, see rank.rs) and must not also `--unshare-pid`, which
                // would nest it in a fresh namespace of its own where it cannot name its peers.
                // That is precisely how sibling USER namespaces broke Cray MPICH's Cross Memory
                // Attach — the same mistake one layer down (P1). Verified on hardware by two
                // arms that must both hold: `steps.pidns` (a rank sees its own namespace, not
                // the node) and `steps.pidns_peers` (ranks can name each other, so CMA has
                // peers). The job cage holds no ranks, so unsharing costs nothing there, and MPI
                // started directly from the batch script stays in ONE namespace and keeps CMA.
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
            //
            // THE EIGHTH INSTANCE of the quadratic dedup, and the one that mirrors
            // `split_file_denies`: that one costs when the entries name paths that EXIST, this one
            // when they do not, because a `denyRead` that is not a file stays in `deny_read` and
            // lands here. Between them the agent has no cheap input, which is exactly why the
            // expression had to be swept rather than fixed where it was noticed (`extend_deduped`,
            // `P5`). This also runs per job, in `compute_bwrap_args`, not once at startup.
            let mut hide: Vec<String> = Vec::new();
            extend_deduped(&mut hide, self.floor.masked().to_vec());
            extend_deduped(
                &mut hide,
                self.deny_read
                    .iter()
                    .filter(|p| p.starts_with('/'))
                    // ...and NOT one the re-hide loop below owns. An absolute `denyRead` inside
                    // the workdir or an `allowWrite` root was emitted TWICE: once here, where
                    // the workdir `--bind` that follows re-exposes it, and once after that bind,
                    // where it works. The first copy did nothing — except when the path did not
                    // exist, and then it killed the cage: this loop runs while the root is still
                    // `--ro-bind`, so bwrap's mkdir hits a read-only filesystem, while the same
                    // mount AFTER the writable bind succeeds. Measured (bubblewrap 0.6.1):
                    //
                    //   --ro-bind / / --tmpfs <wd>/absent --bind <wd> <wd>   -> Can't mkdir …
                    //   --ro-bind / / --bind <wd> <wd> --tmpfs <wd>/absent   -> exit 0
                    //
                    // The predicate is `is_under_writable_root` in both places, so what this
                    // skips is exactly what the re-hide loop emits — one rule, two readers that
                    // cannot disagree (`P8`).
                    .filter(|p| !is_under_writable_root(p, workdir, &self.allow_write))
                    .cloned()
                    .collect(),
            );
            let mut allow: Vec<String> = Vec::new();
            extend_deduped(
                &mut allow,
                self.allow_read
                    .iter()
                    // "./" / "." is the project dir == workdir, bound writable below. Only
                    // absolute carve-outs are safe to re-expose; skip relative ones.
                    .filter(|p| *p != "./" && *p != "." && p.starts_with('/'))
                    .cloned()
                    .collect(),
            );

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
                        // `-try`: a carve-out whose source is missing must not kill every job
                        // with a bwrap message that never says husk. A bad carve-out is already
                        // reported loudly at resolve time ("REFUSED the filesystem carve-out").
                        a.push("--ro-bind-try".into());
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
                if p.starts_with('/') && self.floor.usable_carveout(p) {
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
                //
                // **B3-F8.** `deny_write` was the one field F22 never reached: it tested
                // `starts_with('/')` directly, so a RELATIVE entry — the natural spelling for a
                // project file, and the spelling the shipped config uses for `.claude/…`,
                // `.Rprofile` and `.hg/hgrc` — was silently dropped here while the login cage
                // honoured it. The two cages disagreed about the same policy line, in the
                // direction that fails OPEN: the user wrote a deny, read a deny in their
                // settings, and got one on login and none on compute. `abs_for_cage` is the
                // helper F22 introduced for exactly this, and it also gets `~/x` right (there
                // is nothing to re-bind under a hidden home).
                let Some(p) = abs_for_cage(p, workdir) else { continue };
                // **`-try`, because a stat here cannot be trusted** (`P3`). A bind with a
                // missing source kills the cage: bwrap exits before the job runs, with a message
                // that never says "husk".
                //
                // The stat is DROPPED rather than kept as decoration. It ran on the login node at
                // submit time while bwrap binds on a compute node minutes later, and the window
                // is not idle: `sbatch` runs inside a login-cage Bash command, and the vendor
                // runtime ghost-creates `/dev/null` mount points in this very directory for the
                // duration of that command. husk stat'd `.claude/settings.json` during the one
                // moment it existed and every ICON job died. Whether the file is there is a
                // question only the compute node can answer, so bwrap answers it.
                //
                // For a DENY, tolerating a missing source means "protect it if it is there". Not
                // a hole: stopping a dangerous path from being CREATED is the auto-exec mask's
                // job below, which is shape-aware and absent-safe, and `.claude` sits inside a
                // `--tmpfs` there — strictly stronger than a read-only bind.
                if p.starts_with('/') && !self.floor.covers(&p) {
                    a.push("--ro-bind-try".into());
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
                // Masked BY SHAPE, for the same reason `.git` is — and this one was found the
                // hard way. `--tmpfs <path>` makes bwrap create `<path>` as a DIRECTORY, so it
                // dies with "Can't mkdir …/.git/hooks: Not a directory" the moment something
                // has already put a FILE there. Something has: the LOGIN cage protects a
                // non-existent deny path by binding `/dev/null` over it, which leaves an empty
                // FILE on the host for as long as that sandbox is live. Two cages, one shared
                // project directory, disagreeing about what shape a placeholder is — 3 of 4
                // concurrent brokered jobs died in bwrap setup (A3/A5/A8).
                //
                // Fail-closed, so not an escape; but a job that dies before it starts, with a
                // bwrap error that never says "husk", is an availability bug on exactly the
                // shared project dir husk is meant to make usable. Mask what is THERE:
                // a directory (or nothing) gets the tmpfs, a file gets `/dev/null`, and either
                // way the job cannot read or plant through that path.
                //
                // NOTE the residual: this reads the shape at SUBMIT time on the login node,
                // while bwrap runs later on the compute node. A placeholder that changes shape
                // in between still collides. Closing that means resolving the shape ON THE
                // COMPUTE NODE, the way the credential-socket masks already are — or the
                // durable fix, a per-job private mount.
                for rel in AUTO_EXEC_DIRS {
                    let path = format!("{root}/{rel}");
                    match shape_at_submit(&path) {
                        // A file — the login cage's ghost placeholder, or anything else. A
                        // tmpfs cannot go over it; `/dev/null` can, and masks it just as dead.
                        Shape::File => {
                            a.push("--ro-bind".into());
                            a.push("/dev/null".into());
                            a.push(path);
                        }
                        // A real directory, or absent, or stranger: tmpfs. Absent is the normal
                        // case and must stay cheap — bwrap makes the directory, the job writes
                        // into RAM, and none of it survives the job.
                        _ => {
                            a.push("--tmpfs".into());
                            a.push(path);
                        }
                    }
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
                    match shape_at_submit(&format!("{root}/{dir}")) {
                        // A real repository. Mask the hooks directory where git keeps them;
                        // Mercurial has no hooks directory, only the hgrc protected below.
                        Shape::Dir => {
                            if !inner.is_empty() {
                                // THE LEAF NEEDS THE SAME SHAPE CHECK AS ITS PARENT.
                                //
                                // The comment above this loop describes exactly this failure —
                                // "--tmpfs dies with Can't mkdir .git/hooks: Not a directory the
                                // moment something has already put a FILE there" — and the fix
                                // was applied to `.git` and not to `.git/hooks`. One level too
                                // shallow, and it bit again on 2026-08-09: a project directory
                                // where every brokered job died in cage setup, self-perpetuating
                                // because the login cage's own placeholder is what created the
                                // file (a /dev/null bind leaves a zero-byte FILE on the host).
                                //
                                // So: tmpfs only where tmpfs can work — an absent leaf, which
                                // bwrap creates as a directory, or one that already is one.
                                // Anything else (a file, a symlink, a socket) gets /dev/null,
                                // which needs no mkdir and masks it just as completely.
                                let leaf = format!("{root}/{dir}/{inner}");
                                match shape_at_submit(&leaf) {
                                    Shape::File | Shape::Symlink | Shape::Other => {
                                        a.push("--ro-bind-try".into());
                                        a.push("/dev/null".into());
                                        a.push(leaf);
                                    }
                                    _ => {
                                        a.push("--tmpfs".into());
                                        a.push(leaf);
                                    }
                                }
                            }
                        }
                        // A `git worktree` or submodule checkout: the metadata entry is a FILE
                        // pointing at the real repository. A tmpfs cannot go under a file, so
                        // the old rule made bwrap fail and took the whole cage with it, with a
                        // bare bwrap error that never mentioned husk. Bind it read-only: the
                        // pointer is what must not be rewritten, and what it names is outside.
                        Shape::File => {
                            let p = format!("{root}/{dir}");
                            // `-try`: the SHAPE was read on the login node at submit time and
                            // acted on by a compute node later. If it changed in between there is
                            // nothing to protect, and killing the job is the wrong answer.
                            a.push("--ro-bind-try".into());
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
                if !self.allow_git_config && shape_at_submit(&format!("{root}/.git")) == Shape::Dir {
                    protect(".git/config");
                }
                // `.hg/hgrc` — only where a real `.hg` exists; otherwise the whole `.hg` is
                // already masked above and binding into it would recreate the fabrication bug.
                // Unlike `.git/config`, an hgrc very often does NOT exist in a real repo, so
                // "read-only if present" would leave the plant open. Bind an EMPTY file over it
                // instead: an empty hgrc is valid, so nothing breaks, and it cannot be created.
                if shape_at_submit(&format!("{root}/.hg")) == Shape::Dir {
                    let path = format!("{root}/.hg/hgrc");
                    let src = if present_at_submit(&path) { path.clone() } else { "/dev/null".to_string() };
                    // `-try`, for the reason spelled out at the denyWrite loop: this stat runs on
                    // the LOGIN node at submit time while bwrap binds on a COMPUTE node later, and
                    // the login cage creates and deletes ghost mount points in this very
                    // directory. `.Rprofile` and `.hg/hgrc` are BOTH in the shipped login
                    // denyWrite (A4-F3), so both are ghost-created there — a hard bind on either
                    // is the same outage as `.claude/settings.json`, waiting its turn.
                    a.push("--ro-bind-try".into());
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
                    let src = if present_at_submit(&path) { path.clone() } else { "/dev/null".to_string() };
                    // `-try`, for the reason spelled out at the denyWrite loop: this stat runs on
                    // the LOGIN node at submit time while bwrap binds on a COMPUTE node later, and
                    // the login cage creates and deletes ghost mount points in this very
                    // directory. `.Rprofile` and `.hg/hgrc` are BOTH in the shipped login
                    // denyWrite (A4-F3), so both are ghost-created there — a hard bind on either
                    // is the same outage as `.claude/settings.json`, waiting its turn.
                    a.push("--ro-bind-try".into());
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
}

pub use fs_policy::FsPolicy;

/// Bounded credential auto-scan limits — keep it from ever becoming a filesystem-
/// wide walk. `MAX_DEPTH` counts subdirectory levels below the workdir; `MAX_ENTRIES`
/// is a circuit-breaker on total directory entries visited across the whole scan.
const SCAN_MAX_DEPTH: usize = 4;
const SCAN_MAX_ENTRIES: usize = 20_000;

/// True if `name` (a file BASENAME) looks like a credential file.
///
/// **It does not "mirror the `permissions.deny` Read() globs", and saying so was the
/// finding** (`B2-7(b)`). This matches a basename; half the shipped globs are PATH-shaped,
/// and no basename rule can express them. Measured against the shipped
/// `user-config/settings.json`, six glob families had no counterpart here:
///
/// | shipped `Read()` deny | covered by a basename? |
/// |---|---|
/// | `//**/*.crt`, `//**/*.cer` | no — **and deliberately not added**: these are usually PUBLIC certificates, and masking every `.crt` in a workdir would break ordinary TLS clients for no confidentiality gain |
/// | `//**/.docker/config.json`, `//**/.kube/**` | no — **now covered**, as DIRECTORIES, by `CREDENTIAL_DIRS` |
/// | `//**/.gnupg/**`, `//**/.config/gcloud/**` | no — same |
/// | `//**/.ssh/**`, `//**/.aws/**` | partly (`id_rsa*`, `credentials`) — now whole directories |
///
/// A path-shaped glob needs a path-shaped rule, so the four that hold bearer tokens or
/// private keys are handled one level up, by `matches_credential_dir`, which masks the
/// whole directory instead of guessing at the leaves inside it. `config` and `config.json`
/// are far too common as basenames to add here — that is the reason the mirroring was never
/// possible, and it is now written down instead of claimed away.
///
/// This is a best-effort defense-in-depth scan of the WORKDIR only — the authoritative masks
/// are the human's explicit `sandbox.credentials.files` and the floor.
fn matches_credential(name: &str) -> bool {
    name.starts_with(".env")            // .env, .env.local   (Read(//**/.env*))
        // NOT `*.env`: see `is_ambiguous_env`. `<name>.env` is resolved by CONTENT.
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

/// Directory names inside the workdir whose whole CONTENTS are credentials.
///
/// The path-shaped half of `B2-7(b)`. Each entry is `(basename, required parent)`; a parent
/// of `None` means any. Masking the directory rather than named files inside it is what makes
/// this express `//**/.kube/**` rather than approximate it, and it is why the scan does not
/// recurse into one — there is nothing to find in a directory that is about to become a
/// tmpfs.
///
/// **What it costs, and who pays.** A job whose project directory contains one of these
/// reads an EMPTY directory instead of the real one. That is already true on the login side,
/// where the shipped `permissions.deny` refuses the same paths, so this removes an asymmetry
/// rather than adding a restriction — but it is a behaviour change for anyone who kept a
/// `.docker` or `.kube` inside a project dir and expected a brokered job to use it. The
/// remedy is the same as for any other mask: name what the job actually needs in
/// `sandbox.filesystem.allowRead`.
const CREDENTIAL_DIRS: &[(&str, Option<&str>)] = &[
    (".ssh", None),
    (".aws", None),
    (".gnupg", None),
    (".docker", None),
    (".kube", None),
    // `//**/.config/gcloud/**` — qualified, because `.config/` at a project root is an
    // ordinary thing that holds ordinary configuration.
    ("gcloud", Some(".config")),
];

/// True if a DIRECTORY called `name`, sitting directly inside `parent`, is one whose whole
/// contents are credentials. See `CREDENTIAL_DIRS`.
fn matches_credential_dir(name: &str, parent: Option<&str>) -> bool {
    CREDENTIAL_DIRS
        .iter()
        .any(|(want, want_parent)| *want == name && want_parent.map_or(true, |wp| parent == Some(wp)))
}

/// `<name>.env` — a dotenv secret file, or an HPC environment script?
///
/// **Both, depending on the site, and the extension cannot tell you which.** The rule used to
/// be a flat `ends_with(".env")`, copied from the vendor's `Read(//**/*.env)` glob. On an HPC
/// system that is wrong more often than it is right: `var3d.env` is DACE's module-load script,
/// named that way by the operational benchmark data and by the build instructions.
///
/// It cost three failed 128-rank jobs and a misdiagnosis (LETKF session, 2026-08-05/06):
/// `source var3d.env` failed with a bare `Permission denied`, no modules loaded, and every
/// rank died on `libnetcdff.so.7: cannot open shared object file`. Two layers agreed the file
/// was a credential and neither said so.
///
/// `.env` and `.env.local` stay masked unconditionally — that basename IS the dotenv
/// convention and is not ambiguous. Only `<name>.env` gets asked what is in it.
fn is_ambiguous_env(name: &str) -> bool {
    name.ends_with(".env") && !name.starts_with(".env")
}

/// Environment-variable names that make a file look like secrets rather than a module script.
const SECRET_KEY_HINTS: &[&str] = &[
    "TOKEN", "SECRET", "PASSWORD", "PASSWD", "APIKEY", "API_KEY", "ACCESS_KEY",
    "PRIVATE_KEY", "CREDENTIAL", "AUTH", "SESSION_KEY", "CLIENT_SECRET",
];

/// Does an ambiguous `<name>.env` actually hold secrets?
///
/// Looks for `KEY=VALUE` where KEY reads like a secret. Deliberately NOT "contains an `=`":
/// a module script is full of `export PATH=...`, and that is the whole false positive.
///
/// **Unreadable means masked.** That keeps the previous behaviour whenever we cannot tell, so
/// this change can only ever mask FEWER files than before on evidence, never more, and never
/// silently on a guess. Only the first 64 KiB is read — a dotenv file is small, and a
/// multi-megabyte `.env` is not one.
fn env_content_looks_like_secrets(path: &Path) -> bool {
    use std::io::Read;
    let mut buf = vec![0u8; 64 * 1024];
    let n = match std::fs::File::open(path).and_then(|mut f| f.read(&mut buf)) {
        Ok(n) => n,
        Err(_) => return true, // cannot tell -> previous behaviour
    };
    let text = String::from_utf8_lossy(&buf[..n]);
    text.lines().any(|line| {
        let line = line.trim_start().trim_start_matches("export ").trim_start();
        match line.split_once('=') {
            Some((key, _)) => {
                let k = key.trim().to_ascii_uppercase();
                SECRET_KEY_HINTS.iter().any(|h| k.contains(h))
            }
            None => false,
        }
    })
}

/// Result of a credential auto-scan: the matched files plus whether the scan ran
/// to completion. `truncated` is set only when the entry BUDGET was exhausted (the
/// agent-gameable, anomalous case) — the depth cap is a designed bound and is not
/// flagged, so a normal deep project doesn't spam the warning. (F21)
struct ScanResult {
    files: Vec<String>,
    /// Whole directories to mask (`CREDENTIAL_DIRS`). They become `denyRead` entries — a
    /// `--tmpfs`, not a `/dev/null` bind, because bwrap cannot bind a file over a directory.
    dirs: Vec<String>,
    truncated: bool,
}

// Counts calls to the workdir walk, so a test can assert which code paths reach it.
//
// THREAD-LOCAL, not a global: cargo runs tests as threads of one process, and a shared
// counter is bumped by whatever else happens to be running — the first version of this
// failed 7 != 8 for exactly that reason.
//
// Test-only, and it exists because the obvious test does not work: the submit-time settings
// check must never trigger this walk, but "the verdict is the same either way" is satisfied
// by the BUGGY version too — `resolve` returns Ok whether the tree is empty or full. A
// verdict-comparison test passes against the very bug it was written for. Counting the walk
// is the assertion that actually discriminates.
#[cfg(test)]
thread_local! {
    pub static SCAN_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Bounded walk of `root` (the workdir) returning absolute paths of files whose
/// basename matches a credential pattern. Depth- and entry-count-capped so it can
/// never turn into a filesystem-wide walk; symlinks are not followed. Any error
/// yields fewer results (fail-safe — the base cage still hides homes).
fn scan_credentials(root: &Path) -> ScanResult {
    #[cfg(test)]
    SCAN_CALLS.with(|c| c.set(c.get() + 1));

    scan_credentials_capped(root, SCAN_MAX_DEPTH, SCAN_MAX_ENTRIES)
}

/// Inner scan with explicit caps, so tests can drive the entry budget cheaply
/// without materializing SCAN_MAX_ENTRIES files.
fn scan_credentials_capped(root: &Path, depth: usize, max_entries: usize) -> ScanResult {
    let mut out = Vec::new();
    let mut dirs = Vec::new();
    let mut budget = max_entries;
    let mut truncated = false;
    scan_credentials_rec(root, depth, &mut budget, &mut out, &mut dirs, &mut truncated);
    ScanResult { files: out, dirs, truncated }
}

fn scan_credentials_rec(
    dir: &Path,
    depth: usize,
    budget: &mut usize,
    out: &mut Vec<String>,
    out_dirs: &mut Vec<String>,
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
            let name = entry.file_name().to_string_lossy().to_string();
            let parent = dir.file_name().map(|p| p.to_string_lossy().to_string());
            if matches_credential_dir(&name, parent.as_deref()) {
                // Mask the whole thing and do NOT descend: the tmpfs covers everything
                // inside it, so walking further spends budget to find paths that are already
                // gone. (`B2-7(b)`)
                if let Some(s) = entry.path().to_str() {
                    out_dirs.push(s.to_string());
                }
            } else if depth > 0 {
                scan_credentials_rec(&entry.path(), depth - 1, budget, out, out_dirs, truncated);
            }
        } else if ft.is_file() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Name decides, EXCEPT for `<name>.env`, where the extension is genuinely
            // ambiguous on an HPC and the content is asked instead. See `is_ambiguous_env`.
            let is_cred = matches_credential(&name)
                || (is_ambiguous_env(&name) && env_content_looks_like_secrets(&entry.path()));
            if is_cred {
                if let Some(s) = entry.path().to_str() {
                    out.push(s.to_string());
                }
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
    fn an_empty_settings_file_is_absent_but_a_broken_one_still_refuses() {
        // **2026-08-06, production.** A zero-byte `.claude/settings.json` in the project dir
        // stopped the LOGIN broker from starting. It printed a good message and exited; the
        // wrapper had already exec'd the agent, so the broker became a zombie and every
        // sbatch/squeue the agent made timed out at 120s against a spool nobody was watching.
        // Four consecutive sessions in that directory died the same way.
        //
        // Empty files are the NORMAL state of these paths: Anthropic's runtime creates them,
        // and `:wq` on an empty vim buffer leaves one. So empty is now defined as absent —
        // there are no denies in a zero-byte file to lose, which is why that is safe.
        //
        // The half that must never regress is the other one, so both are asserted here.
        let base = std::env::temp_dir().join(format!("husk-emptyset-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        let proj = base.join("proj");
        std::fs::create_dir_all(proj.join(".claude")).unwrap();
        std::fs::create_dir_all(&home).unwrap();

        let nothing = FsPolicy::resolve(&home, &proj).expect("no settings at all must resolve");

        for empty in ["", "   ", "\n", " \n\t\n "] {
            std::fs::write(proj.join(".claude/settings.json"), empty).unwrap();
            let got = FsPolicy::resolve(&home, &proj)
                .unwrap_or_else(|e| panic!("{empty:?} must be treated as absent, got: {e}"));
            assert_eq!(got, nothing, "{empty:?} must resolve exactly like no file at all");
            assert!(
                FsPolicy::settings_parse_ok(&home, &proj).is_ok(),
                "and the submit-time check must agree about {empty:?}"
            );
        }

        // A file with CONTENT that does not parse is a typo in real policy — denies ARE
        // being lost there, so it still fails closed, on both readers.
        for broken in ["{", "{\"permissions\": }", "not json at all"] {
            std::fs::write(proj.join(".claude/settings.json"), broken).unwrap();
            assert!(
                FsPolicy::resolve(&home, &proj).is_err(),
                "{broken:?} has content and must still refuse"
            );
            assert!(
                FsPolicy::settings_parse_ok(&home, &proj).is_err(),
                "and the two readers must not disagree about {broken:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// `RE-1`. Both readers of the settings hierarchy — the startup construction and the
    /// per-request parse check — must reach a DECISION on every layer, in bounded time and in
    /// bounded memory, and say which file when they refuse.
    ///
    /// Two of the three layers live in `<project>/.claude/`, which the confined agent can
    /// create: the compute cage protects those two files with `--ro-bind-try`, and `-try`
    /// skips a path that is not there yet. Neither shape below needs any privilege.
    ///
    /// **FALSE FRIENDS, and this finding has an unusually good set of them.**
    ///   - `resolve_fails_closed_on_a_settings_file_it_cannot_read` — the name is this bug,
    ///     word for word, and it is green for both shapes. It is about JSON that does not
    ///     parse, and neither of these is about content.
    ///   - `an_empty_settings_file_is_absent_but_a_broken_one_still_refuses` — same reason.
    ///   - `the_submit_time_check_never_walks_the_workdir` — pins this exact call's COST, and
    ///     passes while the same call blocks forever, because it counts directory walks.
    ///   - in the wrapper, `no_settings_file_can_make_the_preflight_hang` — the name IS the
    ///     property, and it stayed green through a 15-second measured hang, because it hands
    ///     a `&str` to the decoder and never touches a file.
    ///
    /// A test that reads a file is what discriminates, which is why this one does.
    ///
    /// **MUTATIONS that turn this red:** drop `.custom_flags(O_NONBLOCK)` in
    /// `read_settings_layer` (the FIFO arm hangs and this FAILS at five seconds instead of
    /// blocking the suite); drop the `is_file()` check (the FIFO reads as a zero-byte layer,
    /// so `resolve` returns `Ok` and the first assertion fails); drop either size check (the
    /// oversized arm returns `Ok` and the second fails). Deleting the `Layer::Refused` arm in
    /// either reader turns it red too, which is the point of asserting through `resolve` and
    /// `settings_parse_ok` rather than through the reader alone — a bound nobody consults is
    /// not a bound.
    #[test]
    fn a_settings_layer_husk_cannot_read_in_bounded_time_is_refused_rather_than_read() {
        let base = std::env::temp_dir().join(format!("husk-re1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        let proj = base.join("proj");
        std::fs::create_dir_all(proj.join(".claude")).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        let layer = proj.join(".claude/settings.local.json");

        // (1) TOO LARGE. Fails fast either way, so it carries the message assertions.
        let cap = husk_slurm_broker::MAX_SETTINGS_BYTES;
        std::fs::write(&layer, vec![b'x'; (cap + 1) as usize]).unwrap();
        let e = FsPolicy::resolve(&home, &proj).expect_err("an oversized layer must be refused");
        assert!(e.contains("settings.local.json"), "name the file (`P11`): {e}");
        assert!(e.contains(&format!("{}", cap + 1)), "say how big it is: {e}");
        assert!(e.contains("husk reads at most"), "say it is a bound, not a parse error: {e}");
        let e2 = FsPolicy::settings_parse_ok(&home, &proj)
            .expect_err("and the submit-time reader must agree");
        assert_eq!(e, e2, "two readers of one policy must not disagree about it (A4-F3)");

        // ...and a layer just UNDER the bound is still honoured. A limit a real config hits is
        // a defect, so the boundary is asserted from both sides.
        //
        // The witness deny names a path that EXISTS. It used to be `/secret`, and that made
        // this test's own subject — "the layer was read and its denies applied" —
        // indistinguishable from "husk kept an entry it cannot mount".
        // `drop_unmountable_hides` now removes the latter, so the fixture has to be a real
        // directory or the assertion proxies the wrong contract.
        let witness = home.to_string_lossy().to_string();
        let mut fat = format!("{{\"sandbox\":{{\"filesystem\":{{\"denyRead\":[\"{witness}\",");
        while fat.len() < (cap as usize) - 64 {
            fat.push_str("\"/pad\",");
        }
        fat.push_str(r#""/last"]}}}"#);
        assert!(fat.len() as u64 <= cap);
        std::fs::write(&layer, &fat).unwrap();
        let ok = FsPolicy::resolve(&home, &proj).expect("a large but VALID layer must resolve");
        assert!(ok.deny_read().iter().any(|p| *p == witness), "and its denies must apply: {ok:?}");

        // (2) A FIFO. On a thread, because the POINT is that the alternative never returns,
        // and a test that hangs teaches nobody anything. Measured at `608618e`: this call
        // blocked for the full 20 s a `timeout` allowed it, with the operator's last line
        // naming a Lustre walk.
        std::fs::remove_file(&layer).unwrap();
        let made = std::process::Command::new("mkfifo")
            .arg(&layer)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if made {
            let (tx, rx) = std::sync::mpsc::channel();
            let (h, p) = (home.clone(), proj.clone());
            std::thread::spawn(move || {
                let _ = tx.send((
                    FsPolicy::resolve(&h, &p),
                    FsPolicy::settings_parse_ok(&h, &p),
                ));
            });
            match rx.recv_timeout(std::time::Duration::from_secs(5)) {
                Ok((r, s)) => {
                    let e = r.expect_err("a FIFO must not read as a settings layer husk trusts");
                    assert!(e.contains("settings.local.json"), "name the file: {e}");
                    assert!(e.contains("not a regular file"), "say what it is: {e}");
                    assert!(e.contains("FIFO"), "an operator who ran mkfifo must recognise it: {e}");
                    assert_eq!(e, s.unwrap_err(), "both readers, one sentence");
                    // IDENTICAL ON RETRY — a denial that varies reads as flakiness.
                    assert_eq!(e, FsPolicy::resolve(&home, &proj).unwrap_err());
                }
                Err(_) => panic!(
                    "reading a FIFO settings layer blocked for 5s. `open` waits for a writer \
                     unless O_NONBLOCK is set. This call runs inside the broker's 15s launch \
                     budget AND on every sbatch, so it is not a slow start — it is husk \
                     refusing to launch, or a live session's every request timing out at 120s, \
                     with nothing naming the file (`RE-1`, `P11`)."
                ),
            }
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_submit_time_check_never_walks_the_workdir() {
        // The submit-time check first shipped calling `resolve`, which is a CONSTRUCTION: it
        // ends in a 20 000-entry depth-4 walk of the workdir whose own comment says
        // "scan-once at construction". Per request, on Lustre, that is a timeout generator.
        //
        // The obvious test does not catch it: comparing verdicts passes against the bug,
        // because `resolve` returns Ok whether the tree is empty or full. Counting the walk
        // is the only assertion that discriminates.
        let base = std::env::temp_dir().join(format!("husk-nowalk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join(".claude")).unwrap();
        std::fs::write(base.join(".claude/settings.json"), b"{}").unwrap();
        let home = base.join("nonexistent-home");

        let before = SCAN_CALLS.with(|c| c.get());
        FsPolicy::settings_parse_ok(&home, &base).expect("valid settings parse");
        assert_eq!(
            SCAN_CALLS.with(|c| c.get()), before,
            "the submit-time check must not trigger the workdir credential walk"
        );

        // ...and the counter is not vacuous: the construction path DOES walk.
        FsPolicy::resolve(&home, &base).expect("resolve");
        assert!(
            SCAN_CALLS.with(|c| c.get()) > before,
            "resolve must still walk, or this test proves nothing"
        );
        let _ = std::fs::remove_dir_all(&base);
    }


    // ---------------------------------------------------------------- B2-1 / C3-2 / C3-4

    /// Load the shipped `user-config/settings.json`, or skip. Same guard the other
    /// shipped-config tests use: the file is not present in every checkout layout.
    fn shipped_settings_text() -> Option<String> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../user-config/settings.json");
        std::fs::read_to_string(p).ok()
    }

    /// THE FLOOR IS THE HOME THE SITE ACTUALLY HAS — not the string `/users`.
    ///
    /// **The eight tests that hard-code `/users` are the named false friends.**
    /// `default_policy_still_hides_homes_and_isolates_net`,
    /// `drop_floor_overlapping_allows_protects_the_floor`,
    /// `floor_predicates_normalise_before_comparing`, `is_workdir_allowed_confines_to_safe_paths`,
    /// `a_write_root_under_the_floor_is_refused`,
    /// `a_steps_working_directory_gets_the_same_check_as_a_jobs` and both guard goldens all
    /// fail when the constant is mutated — and every one of them fails because it spells
    /// `/users` too. They pin the CONTROL to itself and say nothing about the OBJECT (`P15`).
    /// The four out-of-crate checks are worse: `selftest.sh`, `hello.sh`, `hello-gpu.sh` and
    /// `srun-probe.sh` all run `ls -A /users | wc -l` and report PASS on `0`, which a site
    /// with no `/users` supplies for free.
    ///
    /// This asserts the object: given a home, that home is hidden, and the mask husk hands
    /// bwrap names something that exists.
    ///
    /// **MUTATION that turns this red:** make `Floor::for_home` ignore its argument and
    /// return the site defaults — i.e. put `B2-1` back. The Euler arms fail on both counts:
    /// `/cluster/home/me/proj` becomes an acceptable writable workdir, and the emitted cage
    /// asks bwrap for `--tmpfs /users`.
    ///
    /// **The axis it does not cover:** a `$HOME` reached through a SYMLINK. The floor is
    /// textual (see `Floor`), so a workdir spelled through the other path is not recognised
    /// as a home. Nothing here would notice, and closing it needs a canonicalisation this
    /// deliberately does not do.
    #[test]
    fn the_floor_is_the_home_the_site_has_and_not_the_string_users() {
        // --- Balfrin and Santis: homes under /users. Nothing changes, byte for byte.
        let cscs = Floor::for_home_str("/users/hpcuser").expect("a normal CSCS home");
        assert_eq!(
            cscs.masked(),
            ["/users"],
            "where $HOME is under the site default, husk keeps masking the whole root — that \
             is what both guard goldens record"
        );
        assert!(cscs.covers("/users/victim/.ssh"), "another user's home is still hidden");
        assert!(!is_workdir_allowed_under("/users/hpcuser/proj", &cscs));
        assert!(is_workdir_allowed_under("/capstor/scratch/cscs/hpcuser/run", &cscs));

        // --- Euler: /cluster/home/<user>, and no /users at all. Both halves of B2-1.
        let euler = Floor::for_home_str("/cluster/home/me").expect("a normal Euler home");
        assert_eq!(
            euler.masked(),
            ["/cluster/home/me"],
            "the mask must name the home this site HAS"
        );
        assert!(
            !euler.masked().iter().any(|m| m == "/users"),
            "and must NOT ask bwrap to tmpfs a path this site does not have: that is \
             `bwrap: Can't mkdir /users: Read-only file system` on every single job, and \
             there is no --tmpfs-try"
        );
        assert!(euler.covers("/cluster/home/me/.claude/.credentials.json"));
        assert!(
            !is_workdir_allowed_under("/cluster/home/me/proj", &euler),
            "the fail-OPEN half: req.cwd is agent-supplied and the workdir is bound WRITABLE, \
             so THIS user's home must not be an acceptable --chdir"
        );
        assert!(
            euler.covers("/users/anything"),
            "the site literal stays in the REFUSAL set — refusing more can only fail closed, \
             and it is what keeps the eight /users tests honest rather than merely passing"
        );
        // ...and the residual, asserted so it cannot change without a decision. husk masks
        // the home root it can PROVE. Another user's home on a site husk has never seen is
        // not one of those, and the remedy is a `denyRead` line — which `workdir_allowed`
        // now honours, unlike the ambient predicate.
        assert!(
            is_workdir_allowed_under("/cluster/home/victim", &euler),
            "documented residual: without a site-wide home root husk can vouch for, only \
             $HOME is hidden"
        );
        let with_entry = FsPolicy::unchecked_for_test()
            .with_deny_read(vec!["/cluster/home".into()])
            .with_floor(euler.clone());
        assert!(
            !with_entry.workdir_allowed("/cluster/home/victim"),
            "and the explicit entry is what survives that (config.rs) — it must now do BOTH \
             halves, mask AND refuse"
        );
        assert!(with_entry.workdir_allowed("/capstor/scratch/cscs/you/run"));

        // --- and the emitted cage agrees with the floor, which is the only oracle that counts.
        let p = FsPolicy::unchecked_for_test()
            .with_floor(euler);
        let args = p.compute_bwrap_args("/scratch/proj");
        assert!(
            !args.contains(&"/users".to_string()),
            "no argument may name /users on a site that has no /users: {args:?}"
        );
        let hidden: Vec<&String> = args
            .windows(2)
            .filter(|w| w[0] == "--tmpfs")
            .map(|w| &w[1])
            .collect();
        assert!(
            hidden.contains(&&"/cluster/home/me".to_string()),
            "the real home must be tmpfs'd: {hidden:?}"
        );
    }

    /// An unusable `$HOME` is refused, loudly, and the sentence says it is not about JSON.
    ///
    /// The alternative was to guess — and both guesses are `B2-1`: assume the site literal
    /// and kill every job where it does not exist, or mask nothing and leave the home
    /// readable. `resolve`'s caller in `main.rs` follows this error with a line about fixing
    /// the settings file, which is the wrong remedy here, so the message has to carry its
    /// own attribution (`P11`).
    ///
    /// **MUTATION:** make `for_home_str` fall back to the site defaults instead of `Err`.
    ///
    /// **Not covered:** whether the operator ever sees it. That is `main.rs`'s two `exit(2)`
    /// paths, which this pass does not own.
    #[test]
    fn an_unusable_home_is_refused_with_its_own_reason_not_a_guess() {
        for bad in ["", "relative/home", "/users/../etc", "/"] {
            let e = Floor::for_home_str(bad).expect_err("must not yield a floor");
            assert!(e.contains("HOME"), "the message must name HOME, got: {e}");
            assert!(
                e.contains("not about any settings file"),
                "and must say what it is NOT about, because the caller's next line says \
                 'Fix the JSON': {e}"
            );
        }
        assert!(Floor::for_home_str("/users/me").is_ok());
        assert!(Floor::for_home_str("/cluster/home/me").is_ok());
    }

    /// EVERY LINE OF THE SHIPPED CONFIG HAS EXACTLY ONE STATED DISPOSITION.
    ///
    /// Measured before this change: of the shipped file's 27 filesystem-policy entries, 21
    /// produced no bwrap argument and no output at all, and the 2 that DID speak were wrong
    /// — `allowRead: "./"` was refused on the grounds that the project directory "is inside
    /// a home directory", advice that tells the operator to do the thing they already did
    /// (`C3-2`, `P11`, `P13`).
    ///
    /// The assertion is deliberately about the SHIPPED file rather than a fixture: this is
    /// the configuration every husk install actually runs, and it is the input that made all
    /// three findings survive three review rounds.
    ///
    /// **MUTATION that turns this red:** delete the `p == "./"` arm from `dispositions` —
    /// `./` becomes `Refused` and the assertion below fails with the wrong sentence quoted.
    /// Or remove `Disposition::CoveredByFloor` in favour of a silent skip: the totality
    /// count drops from 27.
    ///
    /// **Axes it does not cover:** `is_symlink` is stubbed to `false`, so this says nothing
    /// about the symlinked-carve-out disposition (that one is asserted separately); and it
    /// classifies the CONFIGURED entries only — the credential auto-scan's results are not
    /// configured lines and have no ledger entry.
    #[test]
    fn every_shipped_policy_line_gets_exactly_one_stated_disposition() {
        let Some(text) = shipped_settings_text() else { return };
        let cfg: serde_json::Value = serde_json::from_str(&text).expect("shipped settings valid JSON");
        let fsj = &cfg["sandbox"]["filesystem"];
        let configured: usize = ["allowRead", "denyRead", "allowWrite", "denyWrite"]
            .iter()
            .map(|k| fsj[k].as_array().map(|a| a.len()).unwrap_or(0))
            .sum();

        let pol = FsPolicy::parse(&text).expect("shipped settings must parse");
        let workdir = "/capstor/scratch/cscs/you/proj";
        let ledger = pol.dispositions(workdir, &|_| false);

        assert_eq!(
            ledger.len(),
            configured,
            "one entry in, one disposition out — no line may be dropped on the way (C2)"
        );

        let by_raw = |raw: &str| ledger.iter().find(|e| e.raw == raw).unwrap_or_else(|| {
            panic!("no disposition for {raw:?}; ledger={ledger:?}")
        });

        // The line that was loud and wrong on every launch.
        match &by_raw("./").disposition {
            Disposition::Redundant(why) => assert!(
                why.contains("workdir"),
                "'./' is the project directory and is already bound writable: {why}"
            ),
            other => panic!("'./' must not be refused — it IS the project path: {other:?}"),
        }
        // The 19 that were discarded in silence on a premise nothing checked.
        match &by_raw("~/.claude/.credentials.json").disposition {
            Disposition::CoveredByFloor(root) => assert_eq!(
                root, "/users",
                "and the ledger must NAME the root that does the masking, so a site where it \
                 is something else says so"
            ),
            other => panic!("a ~/… deny is covered by the floor, not {other:?}"),
        }
        // ~/.local IS a home path, so the home message is the RIGHT one here — which is why
        // it was kept and narrowed rather than deleted.
        match &by_raw("~/.local").disposition {
            Disposition::Refused(why) => assert!(why.contains("home directory"), "{why}"),
            other => panic!("~/.local must be refused as a home carve-out: {other:?}"),
        }
        assert!(by_raw(".claude/settings.json").is_applied(), "the settings write-deny must bite");

        // THE PAIRING: the ledger is checked against the mount table, not against itself.
        // A ledger that agreed only with its own rules would be the P15 failure over again.
        let args = pol.compute_bwrap_args(workdir);
        for e in &ledger {
            match (&e.disposition, &e.cage_path) {
                (Disposition::Applied, Some(path)) => assert!(
                    args.contains(path),
                    "{:?} is recorded as Applied but {path:?} is not in the mount table: {args:?}",
                    e.raw
                ),
                (Disposition::Applied, None) => panic!("Applied without a cage path: {e:?}"),
                (Disposition::Refused(_), _) => assert!(
                    !args.contains(&e.raw),
                    "{:?} is recorded as Refused and must not reach bwrap: {args:?}",
                    e.raw
                ),
                _ => {}
            }
        }
    }

    /// The ledger's one summary line is the sentence `B2-1` needed and nobody could print.
    ///
    /// **MUTATION:** hard-code `/users` in `ledger_summary` — the Euler arm fails.
    ///
    /// **Not covered:** whether the operator reads it. It goes to the broker's stderr at
    /// startup, which the wrapper relays.
    #[test]
    fn the_startup_summary_names_the_home_root_it_actually_masks() {
        let Some(text) = shipped_settings_text() else { return };
        let mut pol = FsPolicy::parse(&text).expect("shipped settings must parse");
        pol = pol.with_floor(Floor::for_home_str("/cluster/home/me").unwrap());
        let ledger = pol.dispositions("/scratch/proj", &|_| false);
        let line = pol.ledger_summary(&ledger);
        assert!(line.contains("/cluster/home/me"), "{line}");
        assert!(!line.contains("/users"), "it must not claim a root this site does not have: {line}");
        assert!(line.contains("27 configured"), "and it must account for every line: {line}");
    }

    /// THE CAGE TYPE MUST NOT BE MINTABLE BY ANYONE WHO DID NOT RUN THE CHECKS, AND ONLY
    /// THE COMPILER CAN SAY SO.
    ///
    /// Every other test in this file asserts behaviour. This one asserts a TYPE-SYSTEM
    /// property, so it runs a compiler — the same instrument, and the same self-check, as
    /// `the_witnesses_stay_unforgeable_and_so_does_the_next_one` in the wrapper (`B5-1`).
    ///
    /// **What it is defending.** `FsPolicy` is the output of `resolve`, which is where every
    /// check in this file lives: the floor derivation that refuses an unusable `$HOME`, the
    /// ledger, the shape split, the two carve-out drops, the credential scan and
    /// `drop_unmountable_hides`. `compute_bwrap_args` then turns the result into the mount
    /// table with no further question asked, because by then there is nothing left to ask.
    /// While the fields were `pub` and the type had a `Default`, the two lines
    ///
    /// ```ignore
    /// let fs_policy = FsPolicy { allow_write: vec!["/".into()], ..Default::default() };
    /// let args = fs_policy.compute_bwrap_args(&workdir);
    /// ```
    ///
    /// were legal in `main.rs` — and `--bind / /` is emitted LAST, over `--dev`, `--proc`,
    /// both tmpfs mounts and every mask husk had just placed. `drop_floor_overlapping_allows`
    /// refuses exactly that entry, and this expression walks around it without touching it.
    ///
    /// **The probes are derived, not listed.** The field names come from the struct itself,
    /// so field ten is covered on the day it is added rather than the day someone remembers
    /// to extend a list (`P8`) — the property `RC2-4` bought the hard way when a hard-coded
    /// witness list left a fourth witness untested and green.
    ///
    /// **Cost:** eight `rustc` invocations, ~0.2 s each, no new dependency and no `trybuild`.
    /// It type-checks the REAL `settings.rs` rather than a miniature that could drift from
    /// it, in both positions that matter: inside this module (where `mod tests` lives, and
    /// where the thirty-six hand-built policies were) and outside it via `#[path]` (where
    /// `main.rs`, `policy.rs` and `step.rs` live).
    ///
    /// **Axes it does not cover.** (1) The BODY of `resolve` — a validation that returns
    /// `Ok` without checking is indistinguishable from one that checks (`P6`, last
    /// paragraph); that half is review. (2) `unsafe`: `mem::zeroed`/`transmute` remain
    /// possible by design. (3) It compiles the NON-test configuration, so it cannot see
    /// what `#[cfg(test)]` adds — which is the point of probe (h), and is also why a
    /// `#[cfg(test)] impl Default` would slip past probe (e). (4) It says nothing about
    /// `spool::Broker.fs_policy` and `step::StepBroker.fs_policy`, which are still `pub`
    /// FIELDS: they can be re-pointed at another `FsPolicy`, but no longer at a forged one,
    /// because there are none. (5) It needs `settings.rs` to keep compiling on its own —
    /// production code here uses only `serde`, `serde_json` and the lib crate, and a new
    /// `crate::…` reference in non-test code would turn the self-check RED; the message
    /// there says what to do about it. (6) Rules (1a)–(1c) read text, so a name inside a
    /// comment is a false RED — the safe direction, and the same trade the wrapper's module
    /// audit makes.
    #[test]
    fn the_policy_type_stays_unmintable_outside_resolve() {
        let src_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/settings.rs");
        let pristine = std::fs::read_to_string(&src_path)
            .unwrap_or_else(|e| panic!("cannot read my own source at {}: {e}", src_path.display()));

        // (0) THE MODULE IS THE BOUNDARY, so the module is where the list comes from.
        let module = {
            let start = pristine.find("\nmod fs_policy {").expect(
                "`mod fs_policy` is gone. If `FsPolicy` moved back beside its consumers, the \
                 control is gone with it — a type declared in the same module as its callers \
                 has no boundary, which is the state `B5-1` measured.",
            );
            let end = pristine
                .find("\npub use fs_policy::FsPolicy;")
                .expect("the re-export line is gone");
            assert!(start < end, "the re-export must follow the module it re-exports");
            &pristine[start..end]
        };
        let fields: Vec<String> = {
            let s = module.find("    pub struct FsPolicy {").expect("the struct is gone");
            let body = &module[s..];
            let e = body.find("\n    }\n").expect("the struct must end");
            body[..e]
                .lines()
                .filter_map(|l| {
                    let t = l.trim_start();
                    if t.starts_with("//") || t.starts_with("pub struct") {
                        return None;
                    }
                    let (name, _) = t.split_once(':')?;
                    // A `pub ` prefix is STRIPPED rather than skipped: a field that went
                    // public again must reach probe (d) and be named there, not vanish out
                    // of the list and turn into an arithmetic surprise about its length.
                    let name = name.trim().rsplit(' ').next().unwrap_or("").trim();
                    name.chars().all(|c| c.is_alphanumeric() || c == '_').then(|| name.to_string())
                })
                .collect()
        };
        for known in ["deny_read", "allow_write", "deny_files", "floor"] {
            assert!(
                fields.iter().any(|f| f == known),
                "`{known}` is no longer a field of `FsPolicy`. If it was renamed, fine; if the \
                 scan stopped seeing the struct, every probe below is testing nothing. \
                 Found: {fields:?}"
            );
        }
        assert!(fields.len() >= 9, "only {} fields parsed out of the struct: {fields:?}", fields.len());

        // …and the DERIVE LINE on that struct, which is a second introduction form and the
        // one `RC-5` actually used. Only `FsPolicy`'s own: the private `Deserialize` structs
        // beside it are wire types and are SUPPOSED to be constructible.
        let derive_line = module[..module.find("    pub struct FsPolicy {").unwrap()]
            .lines()
            .rev()
            .find(|l| l.trim_start().starts_with("#[derive("))
            .expect("`FsPolicy` has no derive line — if that is deliberate, delete this check");
        for banned in ["Default", "Deserialize"] {
            assert!(
                !derive_line.contains(banned),
                "`{banned}` on `FsPolicy` mints one from nothing, and a private field behind a \
                 module boundary does not survive a derive (`RC-5`):\n    {derive_line}"
            );
        }

        // (1) WHAT MAY APPEAR INSIDE THE MODULE — shapes, not a list of names (`P5`).
        //
        // (1a) NO TRAIT IMPL FOR `FsPolicy`. Every introduction form a trait can add
        //      (`Default`, `From`, `Deserialize`, `FromStr`, …) has this one shape, and no
        //      compiler probe can enumerate the traits. `RC-5` was `#[derive(Default)]` plus
        //      three characters at a call site.
        // (1b) THE DERIVE LINE MAY NOT INTRODUCE ONE EITHER. `Debug`, `Clone`, `PartialEq`
        //      and `Eq` cannot; `Default` and `Deserialize` can.
        // (1c) EXACTLY ONE `pub fn` MAY RETURN AN `FsPolicy`, and it is the one that runs the
        //      checks. `parse` returns an unvalidated LAYER — no floor, no drops, no scan —
        //      and is `pub(super)` for that reason; making it `pub` again would put
        //      `FsPolicy::parse(r#"{"sandbox":{"filesystem":{"allowWrite":["/"]}}}"#)` back
        //      in reach of every module in the crate, which is the same cage-off-switch by
        //      another door.
        for line in module.lines() {
            let t = line.trim_start();
            assert!(
                !(t.starts_with("impl ") && t.contains(" for FsPolicy")),
                "a trait impl for `FsPolicy` is an introduction form, and no probe here can \
                 enumerate the traits. Inherent impls only:\n    {t}"
            );
            if let Some(rest) = t.strip_prefix("pub fn ") {
                let name = rest.split(['(', '<']).next().unwrap_or("");
                let returns_policy = rest.contains("-> FsPolicy")
                    || rest.contains("-> Result<FsPolicy")
                    || rest.contains("-> Option<FsPolicy");
                assert!(
                    !returns_policy || name == "resolve",
                    "`{name}` is a second public way to obtain an `FsPolicy`. There is one, and \
                     it is `resolve`, because `resolve` is where the checks are. Make it \
                     `pub(super)` (like `parse`) or fold the checks into it:\n    {t}"
                );
            }
        }

        // ---- the compile harness ------------------------------------------------------
        //
        // The test binary lives in `<target>/<profile>/deps/`, so its own directory IS the
        // dependency directory — derived, never assumed, so a custom CARGO_TARGET_DIR works.
        let exe = std::env::current_exe().expect("test binary has a path");
        let deps = exe.parent().expect("…/deps/<test-binary>").to_path_buf();
        let rlib = |prefix: &str| -> std::path::PathBuf {
            std::fs::read_dir(&deps)
                .unwrap_or_else(|e| panic!("cannot list {}: {e}", deps.display()))
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.extension().is_some_and(|x| x == "rlib")
                        && p.file_name().is_some_and(|n| n.to_string_lossy().starts_with(prefix))
                })
                .max_by_key(|p| p.metadata().and_then(|m| m.modified()).ok())
                .unwrap_or_else(|| {
                    panic!(
                        "no {prefix}*.rlib in {} — this crate links it, so cargo must have built \
                         one; refusing to pass without checking",
                        deps.display()
                    )
                })
        };
        let serde = rlib("libserde-");
        let serde_json = rlib("libserde_json-");
        let lib = rlib("libhusk_slurm_broker-");

        let scratch = std::env::temp_dir().join(format!("husk-fspolicy-forge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();

        // Returns rustc's stderr, or None if it compiled clean.
        let compile = |tag: &str, text: &str| -> Option<String> {
            let f = scratch.join(format!("{tag}.rs"));
            std::fs::write(&f, text).unwrap();
            let out =
                std::process::Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
                    .args(["--edition", "2021", "--crate-type", "lib", "--emit=metadata"])
                    .arg("--extern").arg(format!("serde={}", serde.display()))
                    .arg("--extern").arg(format!("serde_json={}", serde_json.display()))
                    .arg("--extern").arg(format!("husk_slurm_broker={}", lib.display()))
                    .arg("-L").arg(format!("dependency={}", deps.display()))
                    .arg("-o").arg(scratch.join(format!("{tag}.meta")))
                    .arg(&f)
                    .output()
                    .unwrap_or_else(|e| panic!("could not run rustc: {e}"));
            if out.status.success() { None } else { Some(String::from_utf8_lossy(&out.stderr).into_owned()) }
        };
        // OUTSIDE the module, which is where `main.rs`, `policy.rs` and `step.rs` stand.
        // `#[path]` at the real file, so the thing being type-checked is the shipped source.
        let outside = |tag: &str, snippet: &str| -> Option<String> {
            compile(
                tag,
                &format!(
                    "#[path = {:?}]\nmod settings;\n#[allow(unused_imports)]\nuse settings::FsPolicy;\n{snippet}\n",
                    src_path.display().to_string()
                ),
            )
        };

        // (2) THE HARNESS SELF-CHECKS, and they are the important ones: if the UNMUTATED
        //     source did not compile here — wrong flags, missing rlib, `RUSTC=/bin/true` —
        //     every "must not compile" assertion below would pass for the wrong reason and
        //     this test would be a green light bolted to a disconnected wire (`P9`).
        //     Verified: `RUSTC=/bin/true`, `RUSTC=/bin/false` and a missing binary each turn
        //     this test RED rather than silent.
        if let Some(err) = compile("pristine_inside", &pristine) {
            panic!(
                "the UNMUTATED settings.rs must compile standalone, or nothing below proves \
                 anything.\n\nTHIS IS A BROKEN HARNESS, NOT A BROKEN CONTROL, and there is one \
                 way to break it that is nobody's mistake: this file's production code today \
                 needs only `serde`, `serde_json` and the `husk_slurm_broker` lib, which is what \
                 lets a probe type-check the REAL source instead of a miniature. A new \
                 `crate::…` reference in non-test code here ends that. If you added one \
                 deliberately, either pass its crate to `compile` or accept that this test \
                 cannot cover the type any more — do not delete it quietly.\n{err}"
            );
        }
        // …and the second self-check is also the POSITIVE control: the one door that IS
        // supposed to be open, from the position that matters. A change that seals the type
        // by sealing it from its own callers fails here rather than shipping.
        if let Some(err) = outside(
            "pristine_outside",
            "use std::path::Path;\n\
             pub fn _the_one_door(h: &Path, p: &Path) -> Result<FsPolicy, String> { FsPolicy::resolve(h, p) }\n\
             pub fn _reads_are_open(p: &FsPolicy) -> usize { p.allow_write().len() + p.unset_env().len() }",
        ) {
            panic!(
                "`FsPolicy::resolve` is no longer callable from outside `mod settings`, or the \
                 reads are not. This is the harness AND the door husk actually uses:\n{err}"
            );
        }

        // (3) THE FORGERIES. One mutation per compilation, except where one compilation
        //     yields per-field evidence — see (c) and (d), where rustc names every field it
        //     refused, so the conjunction is not hiding a conjunct.
        //
        // (c) the measured edit, from INSIDE this module — the position `mod tests` and its
        //     thirty-six hand-built policies occupy. `..loop {}` rather than a real base so
        //     the refusal is about PRIVACY and not about a missing `Default`.
        let err = compile(
            "literal_inside",
            &format!(
                "{pristine}\n#[allow(unreachable_code, dead_code)]\nfn _forge_literal() -> FsPolicy {{ FsPolicy {{ {}: loop {{}}, ..loop {{}} }} }}\n",
                fields[0]
            ),
        )
        .unwrap_or_else(|| {
            panic!(
                "REGRESSION: a struct literal builds an `FsPolicy` inside `settings.rs` again. \
                 That is the whole of `B5-1` in a value type: `resolve`'s twenty checks are \
                 optional for anyone in this file, and `mod tests` is in this file."
            )
        });
        assert!(err.contains("E0451"), "expected a PRIVATE FIELD refusal (E0451), got:\n{err}");
        for f in &fields {
            assert!(
                err.contains(&format!("`{f}`")),
                "rustc refused the literal but did not name `{f}` among the private fields, so \
                 that field is reachable and this probe passed for the wrong reason:\n{err}"
            );
        }

        // (d) every field, from OUTSIDE. One compilation, and the evidence is per field:
        //     rustc reports an independent E0616 for each, so a field that went `pub` again
        //     is a missing line in this stderr rather than a silent pass.
        let reads = fields
            .iter()
            .enumerate()
            .map(|(i, f)| format!("pub fn _r{i}(p: &FsPolicy) {{ let _ = &p.{f}; }}"))
            .collect::<Vec<_>>()
            .join("\n");
        let err = outside("fields_outside", &reads).unwrap_or_else(|| {
            panic!("REGRESSION: `FsPolicy`'s fields are readable — and therefore writable — from outside `mod settings`")
        });
        for f in &fields {
            assert!(
                err.contains(&format!("field `{f}` of struct")) && err.contains("E0616"),
                "`{f}` is reachable from outside the module. A field that can be READ from \
                 there can be assigned from there too, and `pol.deny_read.clear()` after \
                 `resolve` is the same cage-off-switch as building one by hand:\n{err}"
            );
        }

        // (e) `Default`. `RC-5` was three characters; here it would be six.
        let err = outside("default_outside", "pub fn _d() -> FsPolicy { Default::default() }")
            .unwrap_or_else(|| {
                panic!(
                    "REGRESSION: `FsPolicy` has a `Default` again. `FsPolicy::default()` is a \
                     cage with no operator denies, no credential masks and a floor GUESSED at \
                     the CSCS shape — on a site whose homes are elsewhere that is the \
                     fail-open half of `B2-1`, in six characters, from any module."
                )
            });
        assert!(err.contains("E0277"), "expected the missing trait bound (E0277), got:\n{err}");

        // (f) `parse` — an unvalidated LAYER is not a cage, and it is one call away from
        //     looking like one.
        let err = outside("parse_outside", "pub fn _p() { let _ = FsPolicy::parse(\"{}\"); }")
            .unwrap_or_else(|| {
                panic!(
                    "REGRESSION: `FsPolicy::parse` is public again. It returns a layer with no \
                     floor, no shape split and no drops, so \
                     `parse(r#\"{{\\\"sandbox\\\":{{\\\"filesystem\\\":{{\\\"allowWrite\\\":[\\\"/\\\"]}}}}}}\"#)` \
                     is the same off switch as the struct literal, spelled as a parse."
                )
            });
        assert!(err.contains("E0624"), "expected a PRIVATE ASSOCIATED FUNCTION refusal (E0624), got:\n{err}");

        // (g) `union` — the mutator that can only ADD, which is fail-safe for denies and
        //     wide open for `allowWrite`. It runs BEFORE `drop_floor_overlapping_allows` in
        //     `resolve`; called after one, it walks around it.
        let err = outside("union_outside", "pub fn _u(a: &mut FsPolicy, b: FsPolicy) { a.union(b); }")
            .unwrap_or_else(|| {
                panic!(
                    "REGRESSION: `union` is reachable from outside the module. Every drop in \
                     `resolve` runs after it, so a union applied to a RESOLVED policy is an \
                     un-validated carve-out with the validation already behind it."
                )
            });
        assert!(err.contains("E0624"), "expected a PRIVATE METHOD refusal (E0624), got:\n{err}");

        // (h) and the honest door stays shut in a shipped broker. This harness compiles the
        //     NON-test configuration, which is exactly the build an operator runs.
        let err = outside("unchecked_outside", "pub fn _t() -> FsPolicy { FsPolicy::unchecked_for_test() }")
            .unwrap_or_else(|| {
                panic!(
                    "REGRESSION: `unchecked_for_test` exists in a production build. Its name is \
                     the whole control for the test suite; in a shipped binary it is just a \
                     public constructor that skips every check."
                )
            });
        assert!(
            err.contains("E0599"),
            "expected `no associated function` (E0599) — anything else means the name resolved \
             to something in a non-test build:\n{err}"
        );

        let _ = std::fs::remove_dir_all(&scratch);
    }

    /// ONE READER FOR THE SUBMIT-TIME SHAPE, AND `bwrap_args` IS NOT IT.
    ///
    /// Nine filesystem observations taken on the LOGIN node decided what bwrap is asked to
    /// mount on a COMPUTE node, and the residual note covered three of them (`C3-4`). The
    /// note now lives on `shape_at_submit` and the sites cannot get out of its way without
    /// this test noticing.
    ///
    /// **MUTATION that turns this red:** put `std::fs::symlink_metadata(&path)` back into
    /// the `AUTO_EXEC_DIRS` loop.
    ///
    /// **The axis it does not cover:** it is a text scan, so it sees `settings.rs` only. A
    /// site that opened in `policy.rs` or `rank.rs` would not be caught here — and the two
    /// shape questions it allows in `resolve` are settings-FILE existence checks, which it
    /// cannot distinguish from a mount-target stat if one is ever added there.
    #[test]
    fn every_submit_time_shape_read_goes_through_one_function() {
        let src = include_str!("settings.rs");
        let prod = src.split("#[cfg(test)]\nmod tests").next().unwrap();

        // (1) `bwrap_args` — the function that decides the mount table — touches no
        //     filesystem directly at all. Its body runs from its signature to the next
        //     closing brace at method indentation.
        //
        //     BOTH ANCHORS COUNT SPACES, and the method moved one module deeper when
        //     `FsPolicy` went into `mod fs_policy` (`P17`). The start anchor kept matching —
        //     four spaces are a substring of eight — but the end anchor stopped matching the
        //     method's own brace and found the enclosing `impl`'s instead, which is one line
        //     further and only happens to be nearly right because `bwrap_args` is the last
        //     method in that block. Green, and reading a region nobody chose (`P15`). The
        //     anchors are spelled at the real indentation, and the length is asserted so the
        //     next move is a RED rather than a silent re-aim.
        let start = prod.find("        fn bwrap_args(").expect("bwrap_args must exist");
        let body = &prod[start..];
        let end = body.find("\n        }\n").expect("bwrap_args must end");
        let body = &body[..end];
        assert!(
            body.lines().count() > 300 && body.contains("--unshare-net"),
            "the `bwrap_args` region this test scans is {} lines and does not look like the \
             cage builder. An anchor that still matches something is worse than one that does \
             not match at all: re-aim it.",
            body.lines().count()
        );
        for pat in ["symlink_metadata(", "fs::metadata(", ".exists()", "read_dir("] {
            assert!(
                !body.contains(pat),
                "bwrap_args must ask `shape_at_submit`/`present_at_submit`, never the \
                 filesystem directly — found {pat:?}. That is how the residual note came to \
                 cover three of nine sites (C3-4)."
            );
        }

        // (2) crate-wide: only these functions may take a shape.
        const MAY_STAT: &[&str] = &[
            "shape_at_submit",        // the one reader, and where the residual is stated
            "present_at_submit",      // its follow-symlinks companion
            "path_has_symlink_component", // a different question: is a COMPONENT a link (F20)
            "resolve",                // settings-FILE existence, for the empty-vs-absent line
            "settings_layer",         // ditto
            // The output leaf. Also a submit-time observation, and the ONE that already has
            // the compute-node twin `C3-4` asks for: the generated guard re-checks the same
            // leaf by name before the job writes (`A1-F1`,
            // `the_guard_names_the_output_paths_it_emitted`). Listed here rather than routed
            // through `shape_at_submit` because it asks a different question — "is this leaf
            // a symlink" — and because its residual is already closed.
            "confine_output_pattern",
            // The one existence reading husk DOES act on for a mount, taken once at startup
            // and reported; its trade is stated on the function.
            "drop_unmountable_hides",
        ];
        let mut current = String::new();
        for (n, line) in prod.lines().enumerate() {
            let t = line.trim_start();
            // Comments quote these names on purpose — the residual note names the very calls
            // it is about — so only CODE is scanned. That is also the limit worth knowing:
            // this reads text, not an AST.
            if t.starts_with("//") {
                continue;
            }
            // EVERY visibility spelling, and the omission was not cosmetic: `current` kept
            // the PREVIOUS function's name across a `pub(crate) fn` or `pub(super) fn`, so a
            // stat added in one of those was attributed to whatever came before it — and if
            // that neighbour was on `MAY_STAT`, the scan allowed it. Latent at `db5d8bd`
            // (`settings_layer` is `pub(crate) fn` and takes no shape through these
            // spellings) and made live by `P17`, which gives `union`, `split_denies_by_shape`
            // and both `drop_*` carve-outs a `pub(super)` — three of them sitting directly
            // after `resolve`, which IS on the list. Measured on the unfixed scan: a planted
            // `.exists()` in `drop_symlinked_carveouts` passed.
            let head = ["pub(crate) ", "pub(super) ", "pub(in crate::settings) "]
                .iter()
                .find_map(|v| t.strip_prefix(v))
                .unwrap_or(t);
            if let Some(rest) = head.strip_prefix("fn ").or_else(|| head.strip_prefix("pub fn ")) {
                current = rest.split(['(', '<']).next().unwrap_or("").to_string();
            }
            if ["symlink_metadata(", "fs::metadata(", ".exists()"]
                .iter()
                .any(|p| line.contains(p))
            {
                assert!(
                    MAY_STAT.contains(&current.as_str()),
                    "settings.rs:{} takes a filesystem shape inside `{current}`, which is not \
                     one of the functions allowed to. Route it through `shape_at_submit` so \
                     it inherits the submit-vs-mount residual (C3-4, C4): {line}",
                    n + 1
                );
            }
        }
    }

    /// A MASK OF A PATH THAT IS NOT THERE IS DROPPED AND NAMED — it does not kill every job.
    ///
    /// The second source of `B2-1`'s mode (a), and the reason deriving the floor from `$HOME`
    /// is not sufficient on its own: husk's OWN shipped config carries
    /// `denyRead: ["/users"]`, so on a site with no `/users` the fatal `--tmpfs` comes back
    /// from the configuration after the floor stops producing it. Found by handing the real
    /// emitted argument list to a real bwrap rather than by reading the diff.
    ///
    /// It also asserts the ops-loop/re-hide complement: an absolute `denyRead` INSIDE the
    /// workdir is emitted once, after the writable bind, where bwrap can create it — the
    /// same predicate on both sides, so they cannot disagree (`P8`).
    ///
    /// **MUTATION that turns this red:** delete the `shape_at_submit(&p) != Shape::Absent`
    /// arm from `drop_unmountable_hides` — the bwrap arm fails with
    /// `Can't mkdir …: Read-only file system`, which is exactly the production symptom.
    /// Delete the `is_under_writable_root` filter from the ops loop and the workdir arm fails
    /// the same way.
    ///
    /// **The axis it does not cover, and it is a real trade:** a `denyRead` path that is
    /// absent at broker startup and appears LATER is not masked for the rest of the session.
    /// `denyWrite` has always behaved this way — `--ro-bind-try p p` skips an absent p, with
    /// the reasoning written at that loop — so this makes the two fields consistent rather
    /// than introducing a new posture, but it IS fail-open in that direction and the operator
    /// is told at startup rather than protected by the code.
    #[test]
    fn a_mask_of_a_path_that_is_not_there_is_dropped_and_named() {
        let base = std::env::temp_dir().join(format!("husk-unmountable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        let wd = base.join("proj");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(wd.join("real")).unwrap();
        let w = wd.to_string_lossy().to_string();

        let mut p = FsPolicy::unchecked_for_test()
            .with_deny_read(vec![
                format!("{w}/real"),    // exists, inside the workdir  -> re-hide loop
                format!("{w}/absent"),  // absent, inside the workdir  -> re-hide loop, safe
                "/no-such-root-fixm".into(), // absent, read-only parent -> FATAL, must go
            ])
            .with_floor(Floor::for_home(&home).unwrap());
        p.drop_unmountable_hides(&w);
        assert!(
            !p.deny_read().iter().any(|d| d == "/no-such-root-fixm"),
            "a mask husk cannot mount must not reach bwrap: {:?}",
            p.deny_read()
        );
        assert!(p.deny_read().iter().any(|d| *d == format!("{w}/absent")),
            "...but one INSIDE a writable root is created by bwrap after the bind, so it stays");

        let args = p.compute_bwrap_args(&w);
        let pos = |x: &str| args.iter().position(|a| a == x);
        assert!(
            pos(&format!("{w}/absent")).unwrap() > pos(&w).unwrap(),
            "the workdir bind must come first, or the mkdir hits a read-only root: {args:?}"
        );
        assert_eq!(
            args.iter().filter(|a| **a == format!("{w}/real")).count(),
            1,
            "emitted once, not once uselessly and once effectively: {args:?}"
        );

        // THE ORACLE: a real bwrap, on the real argument list.
        let probe = std::process::Command::new("bwrap")
            .args(["--ro-bind", "/", "/", "/bin/true"])
            .output();
        if matches!(&probe, Ok(o) if o.status.success()) {
            let out = std::process::Command::new("bwrap")
                .args(args.iter().filter(|a| *a != "--unshare-net" && *a != "--die-with-parent"))
                .arg("/bin/true")
                .output()
                .expect("bwrap");
            assert!(
                out.status.success(),
                "the emitted cage must actually build: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Run the emitted argument list through a real `bwrap`, minus the two arguments a test
    /// harness cannot take. `--unshare-net` needs a namespace this suite does not always get
    /// and `--die-with-parent` would kill the probe with the test binary. Returns `None`
    /// where bwrap itself cannot run here (no user namespaces), which is a SKIP and is said
    /// out loud, because a silent skip turns the only real oracle in this file into a
    /// no-op (`P10`).
    fn bwrap_verdict(args: &[String]) -> Option<(bool, String)> {
        let probe = std::process::Command::new("bwrap")
            .args(["--ro-bind", "/", "/", "/bin/true"])
            .output();
        if !matches!(&probe, Ok(o) if o.status.success()) {
            eprintln!(
                "SKIPPED THE ONLY REAL ORACLE: bwrap will not run in this harness, so this \
                 test fell back to reading the argument list — which is exactly how `M` \
                 shipped with `M-1` in it."
            );
            return None;
        }
        let out = std::process::Command::new("bwrap")
            .args(args.iter().filter(|a| *a != "--unshare-net" && *a != "--die-with-parent"))
            .arg("/bin/true")
            .output()
            .expect("bwrap");
        Some((out.status.success(), String::from_utf8_lossy(&out.stderr).to_string()))
    }

    /// A MASK NESTED UNDER A HOME ROOT HUSK JUST DROPPED IS DROPPED WITH IT (`M-1`).
    ///
    /// `drop_unmountable_hides` keeps a hide that sits under another hide, because bwrap
    /// creates it inside that tmpfs. The rule is sound; the ancestor list it was checked
    /// against was taken BEFORE the same function dropped the floor's own absent roots, so
    /// the nested entry was kept on the strength of a tmpfs that was no longer going to be
    /// emitted. `B2-1` mode (a), surviving inside the function written to prevent it.
    ///
    /// **The trigger is the SITE ENVIRONMENT, and it is the one the fix's own writeup
    /// flags:** `$HOME` absent when the broker starts — a compute node whose home is autofs
    /// and not yet materialised — plus one absolute `denyRead` under `$HOME`, which is the
    /// shape of every shipped credential mask. `Floor::for_home` does not refuse a missing
    /// `$HOME` (only an unusable one), so the broker starts and the CAGE dies later, with a
    /// bwrap message that never says husk.
    ///
    /// **THE ORACLE IS `bwrap`, NOT THE ARGUMENT LIST.** `M` shipped because argv-level
    /// tests passed; the argv here is legal-looking and fatal. Both checks are made and the
    /// argv one is the weaker: it is what stays behind on a harness with no user namespaces.
    ///
    /// **THE FALSE FRIEND:** `a_mask_of_a_path_that_is_not_there_is_dropped_and_named` is
    /// the crate's first test to hand a real argument list to a real bwrap, it names
    /// `drop_unmountable_hides` in its title, and it passes with this bug present — its hide
    /// set is FLAT, so it never pairs the nesting rule with the dropping rule (`P9`).
    ///
    /// **MUTATION that turns this red:** move `let ancestors: Vec<String> =
    /// self.floor().masked.clone();` back above the floor loop in `drop_unmountable_hides` and
    /// compare against it — bwrap answers `Can't mkdir parents for <HOME>/.ssh: Read-only
    /// file system`, exit=1.
    ///
    /// **The axis it does not cover:** one absent ancestor, one nesting level, one bwrap
    /// version (0.6.1) on one machine at test time. It does not prove the compute node's
    /// bwrap agrees, which is `shape_at_submit`'s standing submit-vs-mount residual
    /// (`C3-4`), and it says nothing about the four `--tmpfs` producers outside this file
    /// (`policy.rs:2086`, `rank.rs:544` and the two static ones).
    #[test]
    fn a_mask_under_a_home_root_husk_just_dropped_is_dropped_with_it() {
        let base = std::env::temp_dir().join(format!("husk-m1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let wd = base.join("proj");
        std::fs::create_dir_all(wd.join(".claude")).unwrap();
        let w = wd.to_string_lossy().to_string();

        // A `$HOME` that is NOT THERE. Not under a site default either, so the floor masks
        // the home itself — the off-CSCS derivation this whole function exists for.
        let home = PathBuf::from(format!("/husk-m1-nohome-{}", std::process::id()));
        let home_s = home.to_string_lossy().to_string();
        assert_eq!(
            shape_at_submit(&home_s),
            Shape::Absent,
            "the fixture is only a fixture if this really is absent"
        );
        std::fs::write(
            wd.join(".claude/settings.json"),
            format!("{{\"sandbox\":{{\"filesystem\":{{\"denyRead\":[\"{home_s}/.ssh\"]}}}}}}"),
        )
        .unwrap();

        let pol = FsPolicy::resolve(&home, &wd)
            .expect("an ABSENT home is not an unusable one — husk must still start");
        assert!(
            pol.floor().masked().is_empty(),
            "the home root itself is dropped, and that half already worked: {:?}",
            pol.floor().masked()
        );

        // THE ORACLE, FIRST — so that when this test fails it fails with the sentence the
        // operator would have read from the job log, not with a Rust `assert_eq!` on a list.
        // The argv checks below are the FALLBACK for a harness with no user namespaces.
        let args = pol.compute_bwrap_args(&w);
        if let Some((ok, stderr)) = bwrap_verdict(&args) {
            assert!(
                ok,
                "the emitted cage must actually build — this is the reproduction, and \
                 before the fix it was `bwrap: Can't mkdir parents for {home_s}/.ssh: \
                 Read-only file system`, exit=1, on every job: {stderr}"
            );
        }
        assert!(
            !pol.deny_read().iter().any(|d| d.starts_with(&home_s)),
            "and so must the mask NESTED under it — there is no tmpfs left to create it \
             inside: {:?}",
            pol.deny_read()
        );
        assert!(
            !args.iter().any(|a| a.starts_with(&home_s)),
            "no argument may name a path under a home root husk has dropped: {args:?}"
        );

        // ...and the refusal did NOT go with the mount. Same entry, other half (`M-2`).
        assert!(
            !pol.workdir_allowed(&format!("{home_s}/.ssh/run")),
            "dropping the MOUNT must not drop the REFUSAL"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A `denyRead` ROOT HUSK CANNOT MOUNT IS STILL REFUSED AS A WORKING DIRECTORY (`M-2`).
    ///
    /// `drop_unmountable_hides` mutates `deny_read`, and `deny_read` is also
    /// `workdir_allowed`'s refusal list. It runs LAST in `resolve`, so the policy handed to
    /// `policy::decide` had already lost the entry: measured, `deny_read after resolve =
    /// []` and `workdir_allowed(<that path>/run) = true`.
    ///
    /// **Why this is worse than the residual `FIX-M §5` disclosed.** That one is
    /// confidentiality — the path is readable. This one is INTEGRITY: `req.cwd` is
    /// AGENT-supplied, and the workdir is `--bind`-ed read-WRITE and forced as `--chdir`. An
    /// operator `denyRead` root that materialises after broker start (autofs, a late mount,
    /// a directory an operator makes mid-session) became a legal writable working directory
    /// for a brokered job — reachable by the confined agent, through a control husk had
    /// deleted.
    ///
    /// **THE FALSE FRIEND:** the `with_entry` assertion inside
    /// `the_floor_is_the_home_the_site_has_and_not_the_string_users` — *"it must now do BOTH
    /// halves, mask AND refuse"* — builds its `FsPolicy` BY HAND, so
    /// `drop_unmountable_hides` never runs on it and the refusal is intact. It pins the
    /// control one level above the code that deletes it (`P9`). This test goes through the
    /// real `resolve`.
    ///
    /// **MUTATION that turns this red:** drop the `.chain(self.deny_read_unmountable().iter())`
    /// from `workdir_allowed`, or stop `drop_unmountable_hides` pushing to `refuse_only`.
    ///
    /// **The axes it does not cover:** it does not exercise `policy::decide`, which is the
    /// caller that acts on the answer (another pass's file this round), and it says nothing
    /// about `step.rs`'s ambient `is_workdir_allowed`, which still cannot see the operator's
    /// configuration at all — named in `workdir_allowed`'s own doc, still not fixed.
    #[test]
    fn a_denyread_root_husk_cannot_mount_is_still_refused_as_a_working_directory() {
        let base = std::env::temp_dir().join(format!("husk-m2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        let wd = base.join("proj");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(wd.join(".claude")).unwrap();
        let w = wd.to_string_lossy().to_string();
        // Absent at broker start, and NOT under the workdir — so it takes the ops-loop arm,
        // the one `drop_unmountable_hides` drops.
        let late = base.join("late-mounted-secrets");
        let late_s = late.to_string_lossy().to_string();
        assert_eq!(shape_at_submit(&late_s), Shape::Absent);
        std::fs::write(
            wd.join(".claude/settings.json"),
            format!("{{\"sandbox\":{{\"filesystem\":{{\"denyRead\":[\"{late_s}\"]}}}}}}"),
        )
        .unwrap();

        let pol = FsPolicy::resolve(&home, &wd).expect("resolve");

        // The MOUNT is still dropped — the availability half of the fix is untouched, and
        // this assertion is what stops the obvious wrong repair (keep the entry, kill every
        // job) from passing.
        let args = pol.compute_bwrap_args(&w);
        if let Some((ok, stderr)) = bwrap_verdict(&args) {
            assert!(ok, "the cage must still build: {stderr}");
        }
        assert!(
            !pol.deny_read().contains(&late_s),
            "husk must still not ask bwrap to mkdir a path that is not there: {:?}",
            pol.deny_read()
        );
        assert!(
            !args.contains(&late_s),
            "and it must not reach the mount table by another route either: {args:?}"
        );

        // The REFUSAL is not.
        assert!(
            pol.deny_read_unmountable().contains(&late_s),
            "the entry must survive as a refusal: {:?}",
            pol.deny_read_unmountable()
        );
        assert!(
            !pol.workdir_allowed(&format!("{late_s}/run")),
            "an operator's denyRead root must not become an agent-supplied writable --chdir \
             just because it was not mounted yet"
        );
        assert!(
            !pol.workdir_allowed(&late_s),
            "the root itself as well as anything under it"
        );
        assert!(
            pol.workdir_allowed(&format!("{w}/run")),
            "and this must stay a TIGHTENING and not a workdir DoS: an ordinary path is \
             still allowed"
        );

        // No path may be in both lists: the entry MOVES. Two lists of the same thing drift
        // unless one is derived from the other (`P8`); here they are disjoint by
        // construction and this is what says so.
        assert!(
            !pol.deny_read().iter().any(|d| pol.deny_read_unmountable().contains(d)),
            "emission and refusal-only must be disjoint: {:?} / {:?}",
            pol.deny_read(),
            pol.deny_read_unmountable()
        );

        // ...and a union cannot lose it. `union`'s own comment promises a merge can only
        // ever ADD a deny; a refusal set it did not merge would have broken that quietly.
        let mut merged = FsPolicy::unchecked_for_test();
        merged.union(pol.clone());
        assert!(
            !merged.workdir_allowed(&format!("{late_s}/run")),
            "a merge must never drop a refusal"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// THE FLOOR NOTE SAYS WHICH OF THE TWO SITUATIONS IT IS IN (`M-3`, `P11`).
    ///
    /// `floor_scope_note` asserted *"this site's homes are not under any root husk knows
    /// (/users)"* without ever asking whether `/users` is on this machine. On a Balfrin node
    /// with a mis-set `HOME` an operator was told, in husk's voice, a fact about their site
    /// that is false, and sent to add a `denyRead` line the shipped config already carries —
    /// `P11`'s failure with the polarity flipped: a confident wrong DIAGNOSIS rather than an
    /// unattributed one. The two situations want opposite remedies (fix `HOME` vs. configure
    /// a home root), which is what makes a wrong diagnosis expensive.
    ///
    /// **MUTATION that turns this red:** delete the `if !here.is_empty()` branch, or make
    /// the note ignore its `present` argument.
    ///
    /// **The axes it does not cover.** It INJECTS the existence answer, so it pins the
    /// sentence and not the wiring: it does not prove `resolve` passes a reader that really
    /// stats, and it cannot — this machine has no `/users`, which is why the answer had to
    /// become an argument in the first place. The startup check in `FIX-M §8`, run on
    /// Balfrin, is the only oracle that closes that (`M-6`, still open). It also does not
    /// cover a `/users` that exists but is a hung network mount, where the reading itself is
    /// the cost; `shape_at_submit` does not follow symlinks and the path is a root, not a
    /// leaf inside an autofs map, which bounds it but does not remove it.
    #[test]
    fn the_floor_note_says_which_of_the_two_situations_it_is_in() {
        let euler = Floor::for_home_str("/cluster/home/me").expect("absolute");

        // (1) No site root here at all. The sentence husk has always printed — unchanged, so
        //     `FIX-M §3`'s verbatim quote of it stays true — but now CHECKED before it is
        //     asserted.
        let absent = floor_scope_note(&euler, &|_| false).expect("an unconfirmed floor speaks");
        assert!(
            absent.contains("not under any root husk knows"),
            "the diagnosis for a site with no /users must be unchanged: {absent}"
        );
        assert!(
            !absent.contains("exists on this machine"),
            "and must not claim the opposite: {absent}"
        );

        // (2) The site root IS here and `$HOME` is not under it.
        let here = floor_scope_note(&euler, &|p| p == "/users").expect("still speaks");
        assert!(
            here.contains("/users exists on this machine"),
            "husk must name the actual cause, not the one it guessed (`P11`): {here}"
        );
        assert!(
            here.contains("/cluster/home/me"),
            "and quote the HOME it is complaining about, so the operator can see it is \
             wrong: {here}"
        );
        assert!(
            here.contains("start husk again"),
            "and give the remedy that matches THIS cause — fix HOME, not add a config \
             line: {here}"
        );
        assert!(
            !here.contains("not under any root husk knows"),
            "the two diagnoses are mutually exclusive; printing both teaches nothing: {here}"
        );

        // (3) The CSCS shape still says nothing — and pays nothing. The early return has to
        //     come FIRST, or Balfrin and Santis take a Lustre stat at every broker start for
        //     a line they will never print. That is the operator-aimed DoS shape this round
        //     has already reverted one fix for, so it is asserted rather than intended.
        let cscs = Floor::for_home_str("/users/me").expect("absolute");
        let asked = std::cell::Cell::new(false);
        assert!(
            floor_scope_note(&cscs, &|_| {
                asked.set(true);
                true
            })
            .is_none(),
            "a confirmed floor has nothing to disclose"
        );
        assert!(
            !asked.get(),
            "and must not touch the filesystem to find that out"
        );
    }

    /// `.mcp.json`'s stated backstop, asserted (`B2-4`).
    ///
    /// `AUTO_EXEC_RO_FILES` is a PRESENT-ONLY mask — an absent source means no mask, and the
    /// file's own comment records a job writing `.mcp.json` to the host straight through it.
    /// What makes that an accepted residual rather than a live hole is one JSON value:
    /// `enableAllProjectMcpServers: false`, which means a planted server is never
    /// auto-started. Nothing asserted it, and flipping it to `true` passed 328/328.
    ///
    /// **MUTATION:** set it to `true` in `user-config/settings.json`.
    ///
    /// **Not covered:** what the runtime does with the key. This is a shape test against
    /// JSON — it pins that husk's own shipped file still carries the value husk's comment
    /// cites, not that the vendor honours it.
    #[test]
    fn the_shipped_config_keeps_the_mcp_auto_start_backstop_switched_off() {
        let Some(text) = shipped_settings_text() else { return };
        let cfg: serde_json::Value = serde_json::from_str(&text).expect("shipped settings valid JSON");
        assert!(
            AUTO_EXEC_RO_FILES.contains(&".mcp.json"),
            "if .mcp.json ever stops being present-only-masked, revisit this pairing"
        );
        assert_eq!(
            cfg["enableAllProjectMcpServers"],
            serde_json::json!(false),
            "AUTO_EXEC_RO_FILES' comment names this key as the reason a plantable .mcp.json \
             is an accepted residual. If it is true, or absent, the residual is live: a \
             server the job wrote is auto-started on the login side."
        );
    }

    /// A credential DIRECTORY is masked as a directory (`B2-7(b)`).
    ///
    /// The compute scan matched basenames while the shipped `permissions.deny` globs are
    /// path-shaped, so `.docker/config.json`, `.kube/**`, `.gnupg/**` and
    /// `.config/gcloud/**` had no compute-side counterpart at all — and on a compute node
    /// this scan plus the floor IS the credential policy, because the shipped config
    /// declares no `sandbox.credentials` block.
    ///
    /// **MUTATION:** empty `CREDENTIAL_DIRS`, or make the scan recurse into one — the
    /// directory stops being masked and only `id_rsa` inside it is caught.
    ///
    /// **Axes not covered:** `.crt`/`.cer` are deliberately absent (usually public
    /// certificates); and the parent qualifier is one level only, so `x/.config/gcloud` is
    /// matched and `x/gcloud` is not.
    #[test]
    fn whole_credential_directories_are_masked_not_guessed_at_leaf_by_leaf() {
        assert!(matches_credential_dir(".ssh", Some("proj")));
        assert!(matches_credential_dir(".kube", None));
        assert!(matches_credential_dir("gcloud", Some(".config")));
        assert!(!matches_credential_dir("gcloud", Some("src")), "the parent qualifier must bite");
        assert!(!matches_credential_dir("config", Some(".kube")), "a plain `config` is not a rule");

        let base = std::env::temp_dir().join(format!("husk-creddir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join(".docker")).unwrap();
        std::fs::create_dir_all(base.join(".config/gcloud/x")).unwrap();
        std::fs::create_dir_all(base.join("src")).unwrap();
        std::fs::write(base.join(".docker/config.json"), "{}").unwrap();
        std::fs::write(base.join("src/key.pem"), "k").unwrap();

        let scan = scan_credentials(&base);
        let root = base.to_string_lossy().to_string();
        let dirs: Vec<String> = scan.dirs.iter().map(|d| d.replace(&root, "")).collect();
        assert!(dirs.iter().any(|d| d == "/.docker"), "{dirs:?}");
        assert!(dirs.iter().any(|d| d == "/.config/gcloud"), "{dirs:?}");
        assert!(
            !scan.files.iter().any(|f| f.ends_with(".docker/config.json")),
            "the directory is masked, so husk does not also enumerate what is inside it"
        );
        assert!(scan.files.iter().any(|f| f.ends_with("src/key.pem")), "the basename rules still run");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_shipped_config_masks_the_credential_dir_children_and_feeds_the_relay() {
        // The login-cage confidentiality fix (2026-08-24). The runtime binds ~/.claude back
        // read-only over the home mask so the agent has its config, and that bind carries the
        // OAuth token and the prompt history. A denyRead on the top-level ~/.claude is IGNORED
        // (the runtime's bind wins on mount ordering), but a denyRead on a CHILD works: a file
        // becomes /dev/null, a subdir becomes tmpfs. So the shipped config masks the sensitive
        // children by name. `projects` is deliberately NOT masked -- memory lives there.
        //
        // THIS IS A SHAPE CHECK ONLY. A config listing a path is NOT proof the mask took: the
        // runtime, mount ordering and the file-vs-directory rule all decide that, and only an
        // ACTUAL READ on the deployed cage proves it (ls showing /dev/null, or a read that
        // fails). `test -r` is a FALSE FRIEND here -- access() passes on /dev/null. The deploy
        // checklist verifies by real read; this test only stops a sensitive path being dropped
        // from the list.
        let shipped = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../user-config/settings.json");
        let text = match std::fs::read_to_string(&shipped) {
            Ok(t) => t,
            Err(_) => return,
        };
        let cfg: serde_json::Value = serde_json::from_str(&text).expect("shipped settings valid JSON");
        let fs = &cfg["sandbox"]["filesystem"];
        let deny: Vec<String> = fs["denyRead"].as_array().unwrap_or(&vec![])
            .iter().map(|v| v.as_str().unwrap_or_default().to_string()).collect();
        let allow: Vec<String> = fs["allowRead"].as_array().unwrap_or(&vec![])
            .iter().map(|v| v.as_str().unwrap_or_default().to_string()).collect();

        // The crown jewel and the prompt history MUST be listed (mechanism: file -> /dev/null).
        for want in ["~/.claude/.credentials.json", "~/.claude/history.jsonl"] {
            assert!(deny.iter().any(|d| d == want),
                "shipped config must denyRead {want:?} (login-cage credential/history leak); deny={deny:?}");
        }
        // The relay carve-out must be present (CSCS egress needs ~/.local/share/claude).
        assert!(allow.iter().any(|a| a == "~/.local"),
            "shipped config must allowRead ~/.local or the srt relay cannot start on CSCS: {allow:?}");
        // ...but the carve-out must NOT reach ~/.claude (that is where the token lives).
        assert!(!allow.iter().any(|a| a == "~/.claude" || a.starts_with("~/.claude/")),
            "allowRead must not re-expose ~/.claude past the ~/.local relay carve-out: {allow:?}");
        // The mask-and-see children (plugins/tasks) are on the list too -- if a new sensitive
        // dir is added but not masked, this catches the drop.
        // `daemon` carries `control.key` and was found readable in-cage by a whitebox
        // reviewer (W1-4). It is the drift this list is FOR: the runtime re-binds ~/.claude
        // read-only over the home mask, so every child upstream adds arrives readable until
        // someone names it. P5 — the list is a bug list, and 6a's constructed home retires it.
        for want in ["~/.claude/sessions", "~/.claude/session-env", "~/.claude/shell-snapshots",
                     "~/.claude/paste-cache", "~/.claude/file-history", "~/.claude/plugins",
                     "~/.claude/tasks", "~/.claude/daemon"] {
            assert!(deny.iter().any(|d| d == want),
                "shipped config must denyRead {want:?} (login-cage confidentiality); deny={deny:?}");
        }
        // Memory must stay reachable -- projects is deliberately left readable.
        assert!(!deny.iter().any(|d| d == "~/.claude/projects"),
            "~/.claude/projects must stay readable (memory lives there); masking it breaks recall");
        // projects is read-only: allowWrite must not grant ~/.claude write (memory not writable,
        // accepted -- husk memory is project-local).
        let allow_write: Vec<String> = fs["allowWrite"].as_array().unwrap_or(&vec![])
            .iter().map(|v| v.as_str().unwrap_or_default().to_string()).collect();
        assert!(!allow_write.iter().any(|w| w.starts_with("~/.claude")),
            "allowWrite must not grant ~/.claude write (projects is read-only): {allow_write:?}");
    }

    #[test]
    fn the_shipped_config_protects_the_confiner_binaries() {
        // F17 one level down from the config: ~/.claude/settings.json is the cage's CONFIG,
        // but ~/.local/bin holds the cage's CODE -- husk, seccomp-wrapper, husk-slurm-broker,
        // husk-slurm-wrapper and socat all install there ($PREFIX = ~/.local). That directory
        // sits INSIDE the ~/.local carve-out we open so the egress relay can start, so the
        // agent can read it. If it could also WRITE there it would rewrite its own confiner and
        // the next launch would run attacker bytes as the operator, outside every cage.
        //
        // `allowWrite: []` is the PRIMARY control and already denies this; a synergizer pass
        // argued exactly that and therefore called the exposure refuted. This entry is the pin
        // on the load-bearing set, so that widening allowWrite later cannot silently hand the
        // agent its own confiner -- the failure would be silent, which is the shape husk exists
        // to prevent.
        //
        // SHAPE CHECK ONLY -- same caveat as the mask test above: this proves husk ASKED, not
        // that the harness OBEYED. `husk-verify.sh` proves the effect, by attempting a real
        // zero-byte open-for-append against each binary in a live cage.
        let shipped = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../user-config/settings.json");
        let text = match std::fs::read_to_string(&shipped) {
            Ok(t) => t,
            Err(_) => return,
        };
        let cfg: serde_json::Value = serde_json::from_str(&text).expect("shipped settings valid JSON");
        let fs = &cfg["sandbox"]["filesystem"];
        let deny_write: Vec<String> = fs["denyWrite"].as_array().unwrap_or(&vec![])
            .iter().map(|v| v.as_str().unwrap_or_default().to_string()).collect();
        // THE CONTRACT: the agent cannot rewrite the code that cages it. I first pinned
        // this as "~/.local/bin must appear in denyWrite" — a MECHANISM, and the same
        // false-friend shape (P9) as the two policy-input tests. ~/.local/bin is in the
        // home, outside the writable set, so `allowWrite: []` already denies it: MEASURED
        // 2026-08-25, a home path absent from denyWrite still fails `touch` with EROFS.
        //
        // The contract is measured by `husk-verify.sh`, which attempts a real zero-byte
        // open-for-append against husk, seccomp-wrapper, the broker, the wrapper and socat
        // in a LIVE cage. A widening of allowWrite therefore surfaces as a loud BREACH
        // instead of being silently absorbed by a config entry nobody remembers.
        //
        // What remains a SHAPE question, and is asserted here: nothing may grant write
        // inside the ~/.local carve-out that the egress relay forces us to expose for READ.
        let _ = &deny_write;
        let allow_write: Vec<String> = fs["allowWrite"].as_array().unwrap_or(&vec![])
            .iter().map(|v| v.as_str().unwrap_or_default().to_string()).collect();
        assert!(!allow_write.iter().any(|w| w == "~/.local" || w.starts_with("~/.local/")),
            "allowWrite must not grant write inside the ~/.local carve-out: {allow_write:?}");
        assert!(!allow_write.iter().any(|w| w == "~" || w == "~/" || w.starts_with("~/")),
            "allowWrite must not reach into the home at all — the confiner binaries live \
             there and the carve-out already exposes them for read: {allow_write:?}");
    }

    #[test]
    fn the_shipped_config_enforces_the_egress_allowlist_strictly() {
        // The allowlist is POLICY, not a prompt-suppression hint. In the runtime,
        // `allowedDomains` alone means "do not ASK about these" -- a host that is not listed
        // falls through to the ask-callback, which auto-approves in auto mode, so every
        // unlisted host is reachable. `strictAllowlist: true` is what makes an unlisted host
        // DENIED without consulting the callback. Without it husk's egress confinement (AV7
        // credential confidentiality, AV8 broker-bypass when the net opens) does not confine.
        // Pinned so the flag cannot be dropped and quietly turn the boundary back into a hint.
        let shipped = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../user-config/settings.json");
        let text = match std::fs::read_to_string(&shipped) {
            Ok(t) => t,
            Err(_) => return, // not every checkout layout ships it; install-time path covers deploy
        };
        let cfg: serde_json::Value = serde_json::from_str(&text).expect("shipped settings valid JSON");
        let net = &cfg["sandbox"]["network"];
        let allowed = net["allowedDomains"].as_array();
        // Only meaningful when an allowlist is actually configured.
        if allowed.map(|a| !a.is_empty()).unwrap_or(false) {
            assert_eq!(
                net["strictAllowlist"].as_bool(),
                Some(true),
                "sandbox.network.allowedDomains is set but strictAllowlist is not true, so the                  allowlist is a prompt hint, not enforcement: unlisted hosts auto-approve in auto                  mode. Set \"strictAllowlist\": true."
            );
        }
    }

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
        //
        // ...AND THE LOOP BELOW ITERATES THE LIST IT CHECKS, which cannot notice the list
        // SHRINKING (`B2-6`, the `P15` corollary). Removing an entry from `SETTINGS_SOURCES`
        // leaves it green. Pin the length, so a layer husk stops reading is a decision
        // somebody had to make here rather than a diff nobody looked at. The consequence is
        // bounded — `SettingsIntact` in the wrapper refuses to launch on a `"sandbox":` key
        // in any of them whether or not this file still reads it — but the same construction
        // reopened a hole silently once already.
        assert_eq!(
            SETTINGS_SOURCES.len(),
            3,
            "husk reads exactly three settings layers. If that changed, the shipped denyWrite \
             and `SettingsIntact::establish` in bin/husk-slurm-wrapper.rs both need the same \
             change, and neither is reachable from this test."
        );
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

        // THE CONTRACT IS "the agent cannot change these", NOT "these appear in denyWrite".
        // A string in a config proves husk ASKED; it is a mechanism, and asserting a
        // mechanism is how a shape test becomes a false friend (P9). Three mechanisms
        // satisfy the contract, and which one applies depends on WHERE the file is:
        //
        //   * a CWD-RELATIVE source lives inside the one writable area, so denyWrite is
        //     the only thing covering it — load-bearing, asserted below;
        //   * a HOME source is already outside the writable set (`allowWrite: []`), so it
        //     is unwritable whether or not denyWrite names it. MEASURED 2026-08-25: a home
        //     path absent from denyWrite still fails `touch` with EROFS.
        //
        // `husk-verify.sh` tests the contract itself, by attempting a real zero-byte
        // open-for-append against each source in a LIVE cage — absent-or-unwritable. That
        // is the check that would catch a regression; this one only stops the writable-area
        // sources losing the single mechanism that covers them.
        let allow_write: Vec<String> = cfg["sandbox"]["filesystem"]["allowWrite"]
            .as_array().unwrap_or(&vec![])
            .iter().map(|v| v.as_str().unwrap_or_default().to_string()).collect();

        for (from_home, rel) in SETTINGS_SOURCES {
            if from_home {
                // Contract via the writable set: nothing may grant write into the home.
                assert!(
                    !allow_write.iter().any(|w| w == "~" || w == "~/" || w.starts_with("~/")),
                    "allowWrite must not reach into the home, or ~/{rel} — which the broker \
                     reads policy from — becomes agent-writable: {allow_write:?}"
                );
                continue;
            }
            let want = rel.to_string();
            assert!(
                deny.iter().any(|d| d == &want),
                "the broker reads policy from {want:?} but the shipped denyWrite does not \
                 protect it - the agent could edit its own cage. denyWrite = {deny:?}"
            );
        }
    }

    #[test]
    fn every_auto_exec_file_the_compute_cage_masks_is_write_denied_on_the_login_side_too() {
        // **A4-F3.** THE SECOND PAIRING, and the one the review found missing. husk masked
        // `.Rprofile` and `.hg/hgrc` on compute and not on login, so a login-session agent
        // could plant either in the shared project dir and have it auto-exec as the user
        // the next time a HUMAN ran `R` or `hg` there — outside every cage. The compute
        // cage's re-masking made brokered jobs look protected and hid it.
        //
        // Two directions, because either alone rots:
        //   * a file husk masks on compute because it AUTO-EXECUTES must be write-denied on
        //     login (add one to the compute list and this fails until login follows), and
        //   * every login entry must actually be in the shipped config (the file is what
        //     the runtime reads; a constant nobody ships protects nothing).
        for f in AUTO_EXEC_RO_OR_EMPTY {
            assert!(
                LOGIN_AUTO_EXEC_DENY.contains(f),
                "{f:?} auto-executes (that is why the compute cage masks it), so the login \
                 cage must write-deny it too — that gap WAS A4-F3"
            );
        }

        let shipped = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../user-config/settings.json");
        let text = match std::fs::read_to_string(&shipped) {
            Ok(t) => t,
            Err(_) => return, // not every checkout layout has it; see the pairing above
        };
        let cfg: serde_json::Value =
            serde_json::from_str(&text).expect("shipped settings must be valid JSON");
        let deny: Vec<String> = cfg["sandbox"]["filesystem"]["denyWrite"]
            .as_array()
            .expect("shipped settings must carry sandbox.filesystem.denyWrite")
            .iter()
            .map(|v| v.as_str().unwrap_or_default().to_string())
            .collect();
        for want in LOGIN_AUTO_EXEC_DENY {
            assert!(
                deny.iter().any(|d| d == want),
                "the shipped login config does not write-deny {want:?}, so an agent can \
                 plant it in the project dir and have it run as the user. denyWrite = {deny:?}"
            );
        }

        // `.git/config` must NOT be added here, however tempting the symmetry: with no
        // `.git`, a static deny mounts an empty read-only directory over it and `git init`
        // stops working. Shape-aware masking owns that case. Pinned so a later "complete the
        // list" commit has to read the reason first.
        assert!(
            !LOGIN_AUTO_EXEC_DENY.iter().any(|d| d.starts_with(".git/")),
            "`.git/*` is shape-dependent — a static deny breaks `git init`; see the doc comment"
        );
    }

    #[test]
    fn output_filenames_allow_slurm_specifiers_but_not_the_job_name() {
        // %x is the parser differential: slurmd expands it AFTER husk validates, and the
        // job name is agent-supplied, so <workdir>/%x with a job name of `..` resolves
        // above the workdir. Everything allowed expands to a number, node or user.
        for ok in ["LOG.exp.mch_icon-ch1_small.run.%j.o", "slurm-%j.out", "a_%A_%a-%N.log"] {
            assert!(is_valid_output_filename(ok), "must accept {ok}");
        }
        // `x%%y` and `out-%J.log` were ACCEPTED here until B1-1/D2. Both leave a residual
        // `%` after the guard's expander: `%J` because nothing expands it, `%%` because the
        // guard turns it INTO a `%`. Either one made the guard's leaf check give up on the
        // path, which - before the guard was made to fail closed - also gave up on the NEXT
        // path in the loop. See the two contract tests at the foot of this file.
        for bad in ["x%%y", "lit%%.log", "out-%J.log", "%x.log", "log.%q", "trailing%", "a/b", "..", ".", "", "with space.o"] {
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

    #[test]
    fn output_pattern_refuses_a_leaf_that_is_a_symlink() {
        // **A1 (CRITICAL).** THIS is the level the bug lived at, and it is why the test
        // above is a FALSE FRIEND: `confinement_follows_symlinks_and_rejects_traversal`
        // passes a whole path to `confine_under_workdir`, which canonicalises all of it and
        // duly rejects a symlink. `confine_output_pattern` never passes the whole path —
        // it SPLITS at the last `/`, confines only the parent, and appends the leaf as
        // text, because the leaf may be `slurm-%j.out` and cannot be canonicalised. So the
        // one component the attacker controls was the one component nothing resolved. The
        // suite was green with an arbitrary-write escape open; a test one layer above the
        // defect proves the layer, not the defect.
        //
        // Reproduces the reviewer's Balfrin escape in miniature: the symlink lives INSIDE
        // the writable workdir (so its parent confines fine) and points OUTSIDE it.
        let root = std::env::temp_dir().join(format!("husk-a1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("work")).unwrap();
        let outside = root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let w = root.join("work").to_string_lossy().to_string();

        // The escape, exactly: a leaf symlink inside the workdir aimed at a directory the
        // broker itself refuses.
        let target = outside.join("PWNED.out");
        symlink(&target, std::path::Path::new(&w).join("link.out")).unwrap();
        let err = confine_output_pattern(&format!("{w}/link.out"), &w)
            .expect_err("a symlink leaf must be refused — this is A1");
        assert!(
            !err.contains("PWNED") && !err.contains(&outside.to_string_lossy().to_string()),
            "the refusal must not name where the symlink pointed (A7-1): {err}"
        );

        // A relative spelling of the same thing reaches the same code path, so it must get
        // the same answer. `--output=link.out` with the leaf pre-planted is the cheapest
        // spelling of the escape and must not be the one that survives.
        assert!(
            confine_output_pattern("link.out", &w).is_err(),
            "a bare filename naming a symlink leaf must be refused too"
        );
        assert!(
            confine_output_pattern("./link.out", &w).is_err(),
            "a `./`-prefixed symlink leaf must be refused too"
        );

        // …and everything legitimate must still pass, or the fix is a denial of service.
        // A leaf that does not exist yet is the NORMAL case: no job's output file exists at
        // submission, and `%j` never resolves to a real path at all.
        for ok in ["fresh.out", "slurm-%j.out", "LOG.exp.mch_icon-ch1_small.run.%j.o"] {
            assert!(
                confine_output_pattern(ok, &w).is_ok(),
                "an absent leaf is not a symlink and must still be accepted: {ok}"
            );
        }
        // An existing REGULAR file is fine — a second run overwriting its own log is not
        // an attack, and refusing it would break every fixed-name output.
        std::fs::write(std::path::Path::new(&w).join("plain.out"), b"").unwrap();
        assert!(
            confine_output_pattern("plain.out", &w).is_ok(),
            "an existing regular file must still be accepted"
        );
        // A symlink leaf pointing back INSIDE the writable set is still refused. The rule
        // is deliberately the shape ("no symlink leaf"), not the destination: the
        // destination is what the agent can change after we look at it.
        symlink(
            std::path::Path::new(&w).join("plain.out"),
            std::path::Path::new(&w).join("inward.out"),
        )
        .unwrap();
        assert!(
            confine_output_pattern("inward.out", &w).is_err(),
            "a symlink leaf is refused on shape, not on where it currently points"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn no_output_refusal_carries_a_broken_line_continuation() {
        // `RA-8`, and it is the CLASS that is pinned here, not the instance. A Rust string
        // literal split across lines without a trailing `\` keeps every space of the next
        // line's indentation, so the agent receives "husk cannot              resolve a
        // directory". This has now happened three times in this file; the round-3 fix
        // repaired one occurrence and left its neighbour, five lines away, in the same
        // function, in the same diff — which is what a fix for an instance rather than a
        // class looks like.
        //
        // The false friend: asserting the exact repaired sentence. That pins one string and
        // says nothing about the next one somebody wraps. A run of spaces INSIDE a refusal
        // is never intentional, so assert that instead.
        let root = std::env::temp_dir().join(format!("husk-ra8-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let w = root.to_string_lossy().to_string();

        let mut refusals = vec![output_filename_refusal("has space.o")];
        for bad in [
            "%x/log.out",          // a `%` in a DIRECTORY component  (the RA-8 sentence)
            "sub%j/log.out",       // …and a partial one
            "has space.o",         // an unacceptable leaf
            "../escape.out",       // traversal
            "/etc/passwd",         // outside the writable set
        ] {
            refusals.push(confine_output_pattern(bad, &w).expect_err("{bad} must be refused"));
        }
        for r in &refusals {
            assert!(
                !r.contains("   "),
                "a refusal carries a run of spaces, which means a string literal was \
                 wrapped without a trailing backslash: {r:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_leaf_symlink_check_is_not_run_on_a_name_slurmd_will_never_open() {
        // `RA-7`, `P15`: the `lstat` above runs on the UNEXPANDED leaf. For `slurm-%j.out`
        // that is a name slurmd never opens — the file it opens is `slurm-4991406.out` —
        // so the check could not catch what it was written for, and it COULD be tripped:
        // one `ln -s /etc/passwd '<workdir>/slurm-%j.out'` inside the writable set, which
        // the agent can create, refused **every default submission** from that directory
        // for as long as the link existed. A fail-closed control aimed at the wrong object
        // is not a safety margin, it is an agent-triggerable denial of service, and the
        // round-3 fix newly extended it to husk's own default.
        //
        // The false friend this test must not become: asserting that the pattern is merely
        // ACCEPTED proves nothing, because an absent leaf is accepted too. The link has to
        // be there, and a literal-named sibling has to be refused in the same breath, or a
        // deleted `lstat` would pass this as easily as a corrected one.
        let root = std::env::temp_dir().join(format!("husk-ra7-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let w = root.to_string_lossy().to_string();

        symlink("/etc/passwd", root.join("slurm-%j.out")).unwrap();
        symlink("/etc/passwd", root.join("literal.out")).unwrap();

        assert!(
            confine_output_pattern("slurm-%j.out", &w).is_ok(),
            "a symlink at the UNEXPANDED name is not the file slurmd opens, so it must not \
             refuse the job — the expanded leaf is checked by the compute-node guard"
        );
        assert!(
            confine_output_pattern("literal.out", &w).is_err(),
            "a symlink at a LITERAL leaf IS the file slurmd opens and must still be refused \
             — this is A1, and skipping it for `%` names must not skip it for names husk \
             can resolve"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_confinement_refusal_tells_the_agent_nothing_about_the_host_filesystem() {
        // **A7-1.** The broker canonicalises OUTSIDE the cage, so its refusal used to
        // answer questions the cage exists to refuse: "resolves to X" for a directory that
        // is really there, "cannot be resolved (No such file or directory)" for one that is
        // not. A caged agent measured `~/.ssh` and `~/.config` as EXISTING and `~/.gnupg`
        // as ABSENT that way, while `ls` inside the cage said ENOENT to all three.
        //
        // The property: two probes that differ only in a path the agent typed must come
        // back differing only in that path. Anything else is a bit of host state crossing
        // the boundary. Asserted by normalising the echoed input away and comparing BYTES,
        // so a future "helpful" addition of an errno or a resolved target fails here.
        let root = std::env::temp_dir().join(format!("husk-a7-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let w = root.to_string_lossy().to_string();

        // Two sibling paths outside the workdir: one that exists on this host, one that
        // does not. This is the exact discrimination the oracle offered.
        let present = std::env::temp_dir().join(format!("husk-a7-PRESENT-{}", std::process::id()));
        std::fs::create_dir_all(&present).unwrap();
        let absent = std::env::temp_dir().join(format!("husk-a7-ABSENT-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&absent);

        let e_present = confine_output_pattern(&format!("{}/x.out", present.display()), &w)
            .expect_err("outside the workdir must be refused");
        let e_absent = confine_output_pattern(&format!("{}/x.out", absent.display()), &w)
            .expect_err("outside the workdir must be refused");
        assert_eq!(
            e_present.replace("PRESENT", "_"),
            e_absent.replace("ABSENT", "_"),
            "existent and non-existent host paths must be indistinguishable in the refusal"
        );
        // And the specific tells, named so the regression reads as prose.
        for e in [&e_present, &e_absent] {
            assert!(!e.contains("os error"), "no errno may reach the agent: {e}");
            assert!(!e.contains("No such file"), "no errno text may reach the agent: {e}");
            assert!(!e.contains("resolves to"), "no resolved host path may be quoted: {e}");
        }

        // A symlink must not have its TARGET printed either — that was the same leak in its
        // most useful form, since a symlink is how an agent asks about an arbitrary path.
        symlink("/etc", std::path::Path::new(&w).join("linkroot")).unwrap();
        let e_link = confine_output_pattern(&format!("{w}/linkroot/passwd"), &w)
            .expect_err("a path resolving outside must be refused");
        assert!(!e_link.contains("/etc"), "the resolved target must not be echoed: {e_link}");

        // Still teaching, though: silence would just move the failure. The message must say
        // what husk did, why, and which directory the job may actually write.
        assert!(e_link.contains("husk confines"), "must name the mechanism: {e_link}");
        assert!(e_link.contains(&w), "must name the writable directory: {e_link}");

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&present);
    }

    #[test]
    fn a_relative_output_directory_resolves_against_the_job_workdir_not_the_brokers_cwd() {
        // `--output=logs/x.out` means "relative to --chdir" to SLURM. It used to reach
        // `canonicalize` as the bare string "logs", which the kernel resolves against the
        // BROKER's cwd — a different directory entirely. The confinement verdict then
        // depended on where the broker happened to be started, which is not a boundary.
        let root = std::env::temp_dir().join(format!("husk-relout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("logs")).unwrap();
        let w = root.to_string_lossy().to_string();

        let got = confine_output_pattern("logs/x.out", &w).expect("a real subdir must confine");
        assert_eq!(got, format!("{}/logs/x.out", std::fs::canonicalize(&w).unwrap().display()));
        // …and it is still CONFINEMENT, not concatenation: climbing out must fail.
        assert!(confine_output_pattern("../x.out", &w).is_err(), "`..` must not escape");
        assert!(confine_output_pattern("logs/../../x.out", &w).is_err(), "nor must a deeper one");

        let _ = std::fs::remove_dir_all(&root);
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
        let mut p = FsPolicy::unchecked_for_test()
            .with_allow_read(vec!["/users".into(), "/users/victim".into(), "/scratch/x".into()])
            .with_allow_write(vec!["/users/me/out".into(), "/data".into()]);
        p.drop_floor_overlapping_allows();
        // Floor-overlapping entries are gone; unrelated ones stay.
        assert_eq!(p.allow_read(), vec!["/scratch/x".to_string()]);
        assert_eq!(p.allow_write(), vec!["/data".to_string()]);
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
        let p = FsPolicy::unchecked_for_test();

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
            a.contains(&format!("--ro-bind-try {}/.git {}/.git", wt.display(), wt.display())),
            "a .git file is a pointer to a real repo and must be read-only: {a}"
        );

        // 4. Mercurial gets the identical treatment, and `.Rprofile` — which needs no
        //    repository at all — is masked with an EMPTY file when absent rather than
        //    merely protected when present. "Read-only if it exists" is what left
        //    `.git/config` plantable, and it would leave every not-normally-present
        //    auto-exec file plantable too.
        let a = p.compute_bwrap_args(&bare.to_string_lossy()).join(" ");
        assert!(a.contains(&format!("--tmpfs {}/.hg ", bare.display())), "{a}");
        // ANCHORED ON THE CONTRACT, NOT ON THE LIST UNDER TEST. My first version looped
        // `AUTO_EXEC_RO_OR_EMPTY`, so a reviewer's mutation that MOVED `.Renviron` to the
        // weaker `AUTO_EXEC_RO_FILES` also removed the assertion covering it, and the test
        // stayed green with the plant hole reopened. An assertion that iterates the thing it
        // is checking cannot notice that thing shrinking (P9, one level up).
        //
        // `LOGIN_AUTO_EXEC_DENY` is the contract — these auto-execute as the human — and the
        // ABSENT case is what must hold, because `--ro-bind-try` with an absent source applies
        // no mask at all. Two shapes satisfy it, matching what the emitter really does:
        // a `/dev/null` bind on the leaf, or a tmpfs over its parent directory (`.hg/hgrc`).
        for entry in husk_slurm_broker::LOGIN_AUTO_EXEC_DENY {
            let leaf_masked =
                a.contains(&format!("--ro-bind-try /dev/null {}/{entry}", bare.display()));
            let parent = entry.split('/').next().unwrap_or(entry);
            let dir_masked = entry.contains('/')
                && a.contains(&format!("--tmpfs {}/{parent} ", bare.display()));
            assert!(
                leaf_masked || dir_masked,
                "{entry:?} auto-executes as the human and is write-denied on the login side, but \
                 the compute cage emits no mask covering its ABSENT case — neither a /dev/null \
                 bind on the leaf nor a tmpfs over {parent:?}. `--ro-bind-try` with an absent \
                 source applies NO mask, so a job can simply create it: {a}"
            );
        }

        let hg = base.join("hg");
        std::fs::create_dir_all(hg.join(".hg")).unwrap();
        let a = p.compute_bwrap_args(&hg.to_string_lossy()).join(" ");
        assert!(
            a.contains(&format!("--ro-bind-try /dev/null {}/.hg/hgrc", hg.display())),
            "an hgrc that does not exist yet must not be creatable: {a}"
        );

        // A real .Rprofile keeps working inside the job — read-only, not blanked.
        let with_r = base.join("withr");
        std::fs::create_dir_all(&with_r).unwrap();
        std::fs::write(with_r.join(".Rprofile"), "options(digits=7)\n").unwrap();
        let a = p.compute_bwrap_args(&with_r.to_string_lossy()).join(" ");
        assert!(
            a.contains(&format!("--ro-bind-try {}/.Rprofile {}/.Rprofile", with_r.display(), with_r.display())),
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
        // A REAL path for the ordinary case: a denyWrite is emitted only when its source
        // exists, because a bind with a missing source kills the cage (Balfrin 5014767).
        let real = std::env::temp_dir().join(format!("husk-dwreal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&real);
        std::fs::create_dir_all(&real).unwrap();
        let realp = real.to_string_lossy().to_string();
        let p = FsPolicy::unchecked_for_test()
            .with_deny_write(vec!["/users".into(), realp.clone()]);
        let a = p.compute_bwrap_args("/proj").join(" ");
        assert!(
            !a.contains("--ro-bind /users /users"),
            "a denyWrite under the floor must not bind the floor back into the cage: {a}"
        );
        assert!(a.contains(&format!("--ro-bind-try {realp} {realp}")), "ordinary denyWrite still works: {a}");
        let _ = std::fs::remove_dir_all(&real);

        for bad in ["/", "//", "/."] {
            let p = FsPolicy::unchecked_for_test()
                .with_allow_write(vec![bad.into()]);
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
        assert_eq!(p.deny_read(), vec!["/users"]);
        assert_eq!(p.allow_read(), vec!["./"]);
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
        assert_eq!(FsPolicy::parse("{}").unwrap(), FsPolicy::unchecked_for_test());
        assert_eq!(FsPolicy::parse(r#"{"sandbox":{}}"#).unwrap(), FsPolicy::unchecked_for_test());
    }

    /// `RE-1`'s second half: the byte bound makes the input finite, and this keeps the WORK
    /// linear in it. A bound on the read alone is not a bound on the launch.
    ///
    /// A valid one-megabyte `denyRead` — the largest layer husk will now read — is 88,291
    /// entries, and `union` deduped with `Vec::contains`, which is quadratic. Measured on the
    /// release broker end to end, from a file a job can write: 5,000 entries 0.03 s, 20,000
    /// entries 0.41 s, 88,291 entries **10.96 s**, against the wrapper's 15-second budget.
    /// After: 0.08 s. This asserts LINEARITY, not a wall-clock budget — the same shape and the
    /// same reasoning as the wrapper's `no_settings_file_can_make_the_preflight_hang`, because
    /// a tight bound here would be a flaky test, and on this project a flaky test is a deleted
    /// one.
    ///
    /// **MUTATION that turns this red:** put `if !dst.contains(&p) { dst.push(p) }` back in
    /// `extend_deduped`. Debug build, same machine, this test: 0.13 s becomes 62.5 s.
    #[test]
    fn merging_a_layer_the_size_of_the_read_bound_stays_linear() {
        let n = 88_291; // what fits in MAX_SETTINGS_BYTES as `"/padNNNNN",` entries
        let layer = FsPolicy::unchecked_for_test()
            .with_deny_read((0..n).map(|i| format!("/pad{i}")).collect())
            .with_deny_files((0..n).map(|i| format!("/f{i}")).collect());
        let started = std::time::Instant::now();
        let mut pol = FsPolicy::unchecked_for_test();
        pol.union(layer);
        let elapsed = started.elapsed();
        assert_eq!(pol.deny_read().len(), n, "every entry must still land, in order");
        assert_eq!(pol.deny_read()[0], "/pad0");
        assert_eq!(pol.deny_read()[n - 1], format!("/pad{}", n - 1));
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "merging a {n}-entry layer took {elapsed:?}. That layer fits inside the bound husk \
             reads, and the agent writes the file — so this is not slowness, it is the \
             wrapper's 15-second launch budget spent on a `Vec::contains` (`RE-1`)."
        );
    }

    /// The sibling of the test above, and the one that was MISSING — which is how two more
    /// copies of the quadratic shipped inside the fix that claimed to remove it (`RE-1`).
    ///
    /// `merging_a_layer_…` exercises `union` and nothing else. The expression appeared EIGHT
    /// times, and the two that survived are reached by inputs `union`'s benchmark never
    /// produced:
    ///
    ///   - `split_file_denies` moves an entry only when `is_file()` is true, so a benchmark
    ///     built from paths that DO NOT EXIST never enters its loop. Measured end to end on
    ///     the release broker with a 1 MiB layer naming 38,828 **real** files: **2.575 s**,
    ///     against a writeup claiming 0.08 s.
    ///   - the `bwrap_args` de-dup is the mirror: a `denyRead` that is not a file STAYS in
    ///     `deny_read`, so the paths that were cheap above are the expensive ones there, and
    ///     it runs per job rather than once at startup.
    ///
    /// Between them the agent has no cheap input, which is the argument for sweeping the
    /// expression rather than fixing it where it was noticed (`P5`).
    ///
    /// Both are driven through their existing seams — `split_file_denies` takes its
    /// classifier as a closure — so this costs no filesystem and cannot flake on I/O.
    ///
    /// **MUTATION that turns this red:** put `if !dst.contains(&p) { dst.push(p) }` back in
    /// either site. Debug profile, same machine: 0.2 s becomes 48 s (`split_file_denies`) and
    /// 41 s (`bwrap_args`).
    #[test]
    fn every_stage_after_the_read_stays_linear_in_the_entries_the_agent_wrote() {
        let n = 88_291; // what fits in MAX_SETTINGS_BYTES as `"/padNNNNN",` entries
        let entries: Vec<String> = (0..n).map(|i| format!("/pad{i}")).collect();

        // (1) EVERY entry is a real file — the case `union`'s benchmark could not produce.
        let mut pol = FsPolicy::unchecked_for_test()
            .with_deny_read(entries.clone());
        let started = std::time::Instant::now();
        pol.split_denies_by_shape(|_| Shape::File);
        let split = started.elapsed();
        assert_eq!(pol.deny_files().len(), n, "every file deny must still land");
        assert!(pol.deny_read().is_empty(), "and none may be left behind");
        assert!(
            split < std::time::Duration::from_secs(5),
            "split_file_denies took {split:?} on {n} entries that all exist. The read bound \
             caps the BYTES; this is the work done with them, on the submit path and in the \
             wrapper's launch budget (`RE-1`)."
        );

        // (2) NOT ONE entry is a file — so they stay in deny_read and land in the bwrap
        //     de-dup instead. Same budget, opposite input.
        let pol2 = FsPolicy::unchecked_for_test()
            .with_deny_read(entries);
        let started = std::time::Instant::now();
        let args = pol2.compute_bwrap_args("/work");
        let build = started.elapsed();
        assert!(args.iter().any(|a| a == "/pad0"), "the denies must still be emitted");
        assert!(
            build < std::time::Duration::from_secs(5),
            "compute_bwrap_args took {build:?} on {n} non-file denies, and it runs PER JOB."
        );
    }

    /// `chmod 000` on a settings layer, which husk used to answer with a false statement.
    ///
    /// The disposition is unchanged and deliberate — a layer husk cannot read sets no policy,
    /// exactly as `read_to_string(..).ok()?` did — but husk announced it as *"is empty, so it
    /// sets no policy"* about a file holding real `denyRead` entries, three lines below a
    /// comment reading "deny that cannot be read must never resolve to deny nothing" (`P7`).
    ///
    /// **MUTATION that turns this red:** collapse `Layer::Unreadable` back into
    /// `Layer::Absent`. The layer then takes the `f.exists()` arm and is called empty again.
    #[test]
    fn a_layer_husk_cannot_read_is_not_reported_as_an_empty_one() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("husk-unreadable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (home, proj) = (base.join("home"), base.join("proj"));
        std::fs::create_dir_all(proj.join(".claude")).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        let f = proj.join(".claude/settings.local.json");
        std::fs::write(&f, r#"{"sandbox":{"filesystem":{"denyRead":["/s3cret"]}}}"#).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();

        // Running as root makes mode 000 readable, and then this test proves nothing.
        if std::fs::read_to_string(&f).is_ok() {
            let _ = std::fs::remove_dir_all(&base);
            return;
        }
        match settings_layer(&f) {
            Layer::Unreadable(why) => {
                assert!(why.contains("settings.local.json"), "name the file (`P11`): {why}");
                assert!(
                    !why.contains("is empty"),
                    "husk must not state as fact that a file it could not open is empty: {why}"
                );
                assert!(
                    why.contains("NO policy"),
                    "and it must say what was LOST, which is the part that matters: {why}"
                );
            }
            _ => panic!("an unreadable layer must be its own disposition, not folded into absent"),
        }
        // The disposition is still "contributes nothing" — this test is about the sentence.
        assert!(
            FsPolicy::resolve(&home, &proj).is_ok(),
            "and it must NOT become a third refusal on the launch path"
        );
        let _ = std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn union_dedups_and_is_additive() {
        let mut a = FsPolicy::unchecked_for_test()
            .with_allow_read(vec!["./".into()])
            .with_deny_read(vec!["/users".into()])
            .with_deny_files(vec!["/proj/.env".into()])
            .with_allow_write(vec!["/scratch".into()]);
        a.union(FsPolicy::unchecked_for_test()
            .with_allow_read(vec!["./".into(), "/users/x/miniconda3".into()])
            .with_deny_files(vec!["/proj/.env".into(), "/proj/key.pem".into()])
            .with_allow_write(vec!["/scratch".into(), "/capstor/scr".into()]));
        assert_eq!(a.allow_read(), vec!["./", "/users/x/miniconda3"]);
        assert_eq!(a.deny_read(), vec!["/users"]);
        assert_eq!(a.deny_files(), vec!["/proj/.env", "/proj/key.pem"]);
        assert_eq!(a.allow_write(), vec!["/scratch", "/capstor/scr"]);
    }

    fn joined(p: &FsPolicy, workdir: &str) -> String {
        p.compute_bwrap_args(workdir).join(" ")
    }

    #[test]
    fn default_policy_still_hides_homes_and_isolates_net() {
        // Fail-safe floor: even with NO config, /users is hidden and net unshared.
        let cmd = joined(&FsPolicy::unchecked_for_test(), "/work");
        assert!(cmd.contains("--ro-bind / /"));
        assert!(cmd.contains("--tmpfs /users"));
        assert!(cmd.contains("--unshare-net"));
        assert!(cmd.contains("--bind /work /work"));
    }

    #[test]
    fn allowread_carveout_is_reexposed_after_the_hide() {
        let p = FsPolicy::unchecked_for_test()
            .with_allow_read(vec!["./".into(), "/users/x/miniconda3".into()])
            .with_deny_read(vec!["/users".into()]);
        let args = p.compute_bwrap_args("/users/x/proj");
        let cmd = args.join(" ");
        // miniconda carve-out present as a read-only bind...
        assert!(cmd.contains("--ro-bind-try /users/x/miniconda3 /users/x/miniconda3"));
        // ...and applied AFTER the /users tmpfs so it actually re-exposes it.
        let hide = args.iter().position(|a| a == "/users").unwrap();
        let allow = args.iter().position(|a| a == "/users/x/miniconda3").unwrap();
        assert!(hide < allow, "the /users hide must precede the miniconda carve-out");
        // "./" is not bound as a carve-out; it's the writable workdir instead.
        assert!(cmd.contains("--bind /users/x/proj /users/x/proj"));
    }

    #[test]
    fn extra_denyread_becomes_a_tmpfs() {
        let p = FsPolicy::unchecked_for_test()
            .with_allow_read(vec![])
            .with_deny_read(vec!["/capstor/secret".into()]);
        assert!(joined(&p, "/work").contains("--tmpfs /capstor/secret"));
    }

    #[test]
    fn exposes_gpus_and_shm_for_single_node_multigpu() {
        // GPU device carve-outs + /dev/shm are present even with no config, so a
        // single-process multi-GPU NVLink job can see the devices inside the cage.
        let cmd = joined(&FsPolicy::unchecked_for_test(), "/work");
        assert!(cmd.contains("--tmpfs /dev/shm"));
        assert!(cmd.contains("--dev-bind-try /dev/nvidiactl /dev/nvidiactl"));
        assert!(cmd.contains("--dev-bind-try /dev/nvidia0 /dev/nvidia0"));
        assert!(cmd.contains("--dev-bind-try /dev/nvidia-uvm /dev/nvidia-uvm"));
    }

    #[test]
    fn rank_cage_gets_the_fabric_and_no_private_shm() {
        // The two measured differences from the job cage, and the only two.
        let job = joined(&FsPolicy::unchecked_for_test(), "/work");
        let rank = FsPolicy::unchecked_for_test().rank_bwrap_args("/work").join(" ");

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
    // A RANK joins that namespace rather than unsharing into one of its own: `--pidns <fd>`
    // without `--unshare-pid`, so every rank of a step lands in the holder's namespace and
    // can name its peers. Adding `--unshare-pid` there would nest each rank alone, unable to
    // see the others — exactly how sibling USER namespaces broke Cray MPICH's Cross Memory
    // Attach and killed ICON. Same mistake, one layer down (P1).
    #[test]
    fn only_the_job_cage_unshares_pids_because_a_rank_must_still_name_its_peers() {
        let job = joined(&FsPolicy::unchecked_for_test(), "/work");
        let rank = FsPolicy::unchecked_for_test().rank_bwrap_args("/work").join(" ");

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
        let p = FsPolicy::unchecked_for_test()
            .with_allow_read(vec![])
            .with_deny_read(vec!["/users".into()]);
        let rank = p.rank_bwrap_args("/work").join(" ");
        assert!(rank.contains("--ro-bind / /"), "{rank}");
        assert!(rank.contains("--tmpfs /users"), "{rank}");
        assert!(rank.contains("--unshare-net"), "single node needs no IP - measured: {rank}");
    }

    #[test]
    fn every_cage_gets_a_private_tmp_so_a_sibling_sessions_egress_socket_is_not_even_nameable() {
        // **O1.** The reviewer counted 35 live proxy sockets in a shared `/tmp`, with
        // predictable names, and made the right argument: connecting to an AF_UNIX socket
        // needs only WRITE permission on the file, and file permissions do not separate two
        // sessions of the SAME user. Two concurrent husk sessions on different projects have
        // different egress allowlists and the same uid, so if one could reach the other's
        // socket it would egress under the other's policy.
        //
        // For husk's own socket that fails at the first step: it lives at
        // `/tmp/husk-<uid>-<jobid>/net.sock`, and every cage mounts a FRESH tmpfs over
        // `/tmp` — so inside a job, `/tmp` contains nothing but what husk binds back in,
        // which is this job's own socket file and not its directory. A sibling's socket
        // cannot be opened because its path does not exist in that mount namespace. Naming
        // is the boundary here, not permission, which is the only kind that works between
        // processes of one user.
        //
        // That property is currently a side effect of a `--tmpfs /tmp` that is there for
        // other reasons. Pinned here, in both cages, so a later "let jobs share /tmp for
        // scratch" cannot silently reopen it. (The 0755 sockets the reviewer actually
        // listed are the vendor runtime's `srt-mux`, not husk's 0600 `net.sock`; those are
        // the login side and belong to the 6a work.)
        let p = FsPolicy::unchecked_for_test();
        assert!(
            joined(&p, "/work").contains("--tmpfs /tmp "),
            "the job cage must get a private /tmp"
        );
        assert!(
            p.rank_bwrap_args("/work").join(" ").contains("--tmpfs /tmp"),
            "so must the rank cage — a rank binds the same socket into its own namespace"
        );
    }

    #[test]
    fn credential_masks_are_not_static_bwrap_args() {
        // The MUNGE mask is applied by the re-exec guard on the COMPUTE NODE, never here:
        // `--tmpfs DEST` kills bwrap when DEST is absent under a read-only root, and again
        // when two list entries resolve to the same directory (/var/run -> /run). Both
        // shipped once and took the whole cage down. Only the compute node knows which
        // paths exist, so the decision cannot be made at submit time.
        // Behaviour is pinned by policy::tests::credential_mask_is_applied_only_for_paths_that_exist.
        let cmd = joined(&FsPolicy::unchecked_for_test(), "/work");
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
        let p = FsPolicy::unchecked_for_test()
            .with_allow_read(vec![])
            .with_deny_read(vec!["/users".into()]);
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
        assert_eq!(p.deny_files(), vec!["/proj/.env", "/proj/key.pem"]);
    }

    #[test]
    fn parse_no_credentials_block_means_no_deny_files() {
        let json = r#"{ "sandbox": { "filesystem": { "denyRead": ["/users"] } } }"#;
        assert!(FsPolicy::parse(json).unwrap().deny_files().is_empty());
        // empty-path entries are dropped, not emitted as a bind over "/".
        let empty = r#"{ "sandbox": { "credentials": { "files": [ { "path": "" } ] } } }"#;
        assert!(FsPolicy::parse(empty).unwrap().deny_files().is_empty());
    }

    #[test]
    fn credential_file_is_devnull_bound_after_the_workdir() {
        // A secret inside the writable workdir must be re-denied, so the
        // /dev/null bind has to come AFTER the workdir --bind.
        let p = FsPolicy::unchecked_for_test()
            .with_deny_files(vec!["/users/x/proj/.env".into()]);
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
        let p = FsPolicy::unchecked_for_test()
            .with_deny_files(vec!["/proj/.env".into()]);
        let cmd = joined(&p, "/proj");
        assert!(cmd.contains("--ro-bind /dev/null /proj/.env"));
        assert!(!cmd.contains("/proj/data.txt"));
    }

    #[test]
    fn relative_credential_path_is_skipped_covered_by_home_tmpfs() {
        // ~/.aws/... lives under home, already hidden by the /users tmpfs; a
        // non-absolute entry must NOT become a bind over a bogus path.
        let p = FsPolicy::unchecked_for_test()
            .with_deny_files(vec!["~/.aws/credentials".into()]);
        assert!(!joined(&p, "/work").contains("--ro-bind /dev/null ~"));
    }

    // ── symlink-escape guard on allow carve-outs ────────────────────────────

    #[test]
    fn drop_symlinked_carveouts_removes_symlink_leaf_allows() {
        let mut p = FsPolicy::unchecked_for_test()
            .with_allow_read(vec!["/users/x/miniconda3".into(), "/users/x/evil-link".into()])
            .with_allow_write(vec!["/scr/real".into(), "/scr/link".into()]);
        // classifier: the *-link / .../link paths are symlinks; the rest are real.
        p.drop_symlinked_carveouts(|path| path.ends_with("-link") || path.ends_with("/link"));
        assert_eq!(p.allow_read(), vec!["/users/x/miniconda3"], "symlink-leaf read carve-out dropped");
        assert_eq!(p.allow_write(), vec!["/scr/real"], "symlink-leaf write carve-out dropped");
    }

    // ── env credential masking (sandbox.credentials.envVars) ────────────────

    #[test]
    fn parse_extracts_credential_env_vars() {
        let json = r#"{ "sandbox": { "credentials": { "envVars": [
            { "name": "AWS_SECRET_ACCESS_KEY", "mode": "deny" },
            { "name": "GH_TOKEN", "mode": "mask" }
        ] } } }"#;
        let p = FsPolicy::parse(json).unwrap();
        assert_eq!(p.unset_env(), vec!["AWS_SECRET_ACCESS_KEY", "GH_TOKEN"]);
    }

    #[test]
    fn credential_env_vars_become_unsetenv() {
        let p = FsPolicy::unchecked_for_test()
            .with_unset_env(vec!["AWS_SECRET_ACCESS_KEY".into()]);
        assert!(joined(&p, "/work").contains("--unsetenv AWS_SECRET_ACCESS_KEY"));
        // an empty name must not emit a bare --unsetenv
        let empty = FsPolicy::unchecked_for_test()
            .with_unset_env(vec!["".into()]);
        assert!(!joined(&empty, "/work").contains("--unsetenv"));
    }

    // ── write model (sandbox.filesystem.allowWrite / denyWrite) ─────────────

    #[test]
    fn parse_extracts_allow_and_deny_write() {
        let json = r#"{ "sandbox": { "filesystem": {
            "allowWrite": ["/capstor/scratch/x"], "denyWrite": ["/capstor/scratch/x/.git"]
        } } }"#;
        let p = FsPolicy::parse(json).unwrap();
        assert_eq!(p.allow_write(), vec!["/capstor/scratch/x"]);
        assert_eq!(p.deny_write(), vec!["/capstor/scratch/x/.git"]);
    }

    #[test]
    fn default_write_policy_is_ro_root_plus_writable_workdir_only() {
        // No allowWrite: the cage is default-deny for writes — root is read-only,
        // and the ONLY writable bind is the workdir.
        let args = FsPolicy::unchecked_for_test().compute_bwrap_args("/work");
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
        let p = FsPolicy::unchecked_for_test()
            .with_allow_write(vec!["/capstor/scratch/x".into()]);
        assert!(joined(&p, "/work").contains("--bind /capstor/scratch/x /capstor/scratch/x"));
    }

    #[test]
    fn split_denies_by_shape_routes_files_to_devnull_keeps_dirs_as_tmpfs() {
        let mut p = FsPolicy::unchecked_for_test()
            .with_deny_read(vec!["/users".into(), "/etc/secret.conf".into()]);
        // classifier: only /etc/secret.conf is a file (the rest are dirs).
        p.split_denies_by_shape(|path| {
            if path == "/etc/secret.conf" { Shape::File } else { Shape::Dir }
        });
        assert_eq!(p.deny_read(), vec!["/users"], "dir stays in deny_read (tmpfs)");
        assert_eq!(p.deny_files(), vec!["/etc/secret.conf"], "file moves to /dev/null");
        let cmd = p.compute_bwrap_args("/work").join(" ");
        assert!(cmd.contains("--tmpfs /users"));
        assert!(cmd.contains("--ro-bind /dev/null /etc/secret.conf"));
        assert!(!cmd.contains("--tmpfs /etc/secret.conf"), "a file must not be tmpfs'd");
    }

    /// THE MIRROR IMAGE, which did not exist and was a live kill (`C3-4`).
    ///
    /// `sandbox.credentials.files` had no shape check anywhere on its path: the entry went
    /// straight to `--ro-bind /dev/null <path>`. Point one at a DIRECTORY — an ordinary
    /// thing to do, the field is one line below `denyRead` in the same block — and bwrap
    /// refuses to build the cage: `Can't create file at /…/.secrets: Is a directory`,
    /// exit 1, on EVERY brokered job, with no husk in the message.
    ///
    /// **Pinned at the bug's level:** the assertion is about the ARGUMENT LIST, not about
    /// which internal list the entry ended up on — the mount table is the oracle.
    ///
    /// **MUTATION that turns this red:** delete the `cred_dirs` partition from
    /// `split_denies_by_shape`. The directory goes back to `--ro-bind /dev/null` and the
    /// last two assertions fail.
    ///
    /// **The axis this does not cover:** the shape is still read at submit time. A
    /// `credentials.files` entry that is a file HERE and a directory when bwrap runs still
    /// kills the job — see `shape_at_submit`, and `ROADMAP` F2 for the only real fix.
    #[test]
    fn a_credential_entry_that_is_a_directory_is_masked_not_used_to_kill_the_cage() {
        let mut p = FsPolicy::unchecked_for_test()
            .with_deny_files(vec!["/scratch/proj/.secrets".into(), "/scratch/proj/id_rsa".into()]);
        p.split_denies_by_shape(|path| {
            if path.ends_with(".secrets") { Shape::Dir } else { Shape::File }
        });
        let cmd = p.compute_bwrap_args("/scratch/proj").join(" ");
        assert!(
            cmd.contains("--ro-bind /dev/null /scratch/proj/id_rsa"),
            "a credential FILE is still masked with /dev/null: {cmd}"
        );
        assert!(
            cmd.contains("--tmpfs /scratch/proj/.secrets"),
            "a credential DIRECTORY must be masked as a tmpfs — bwrap cannot bind /dev/null \
             over a directory: {cmd}"
        );
        assert!(
            !cmd.contains("--ro-bind /dev/null /scratch/proj/.secrets"),
            "…and must NOT still be emitted as the bind that kills the cage: {cmd}"
        );
    }

    #[test]
    fn deny_write_rebinds_read_only_after_allow_write() {
        // denyWrite takes precedence: a subpath of a writable root is re-bound
        // read-only, and that ro-bind must come AFTER the allowWrite --bind.
        // Real directories on disk: a denyWrite is emitted only when its source exists,
        // because bwrap exits when a bind source is missing (Balfrin 5014767).
        let scr = std::env::temp_dir().join(format!("husk-dworder-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scr);
        std::fs::create_dir_all(scr.join("protected")).unwrap();
        let (s_scr, s_prot) = (
            scr.to_string_lossy().to_string(),
            scr.join("protected").to_string_lossy().to_string(),
        );
        let p = FsPolicy::unchecked_for_test()
            .with_allow_write(vec![s_scr.clone()])
            .with_deny_write(vec![s_prot.clone()]);
        let args = p.compute_bwrap_args("/work");
        assert!(args.join(" ").contains(&format!("--ro-bind-try {s_prot} {s_prot}")));
        let wr = args.iter().position(|a| a == &s_scr).unwrap();
        let ro = args.iter().position(|a| a == &s_prot).unwrap();
        assert!(wr < ro, "denyWrite ro-bind must follow the allowWrite bind to win");
        let _ = std::fs::remove_dir_all(&scr);
    }

    #[test]
    fn every_bind_husk_emits_has_a_source_that_exists() {
        // **THE REGRESSION THIS EXISTS FOR (Balfrin, jobs 5014767/8/9).** A bind whose
        // SOURCE is missing does not degrade — bwrap exits before the job runs, with a
        // message that never mentions husk. Three real compute jobs died with:
        //
        //   bwrap: Can't find source path <workdir>/.claude/settings.json: No such file
        //
        // because relative denyWrite entries started resolving and the shipped config lists
        // a file most projects do not have.
        //
        // It reached hardware because NOTHING off-cluster runs bwrap: the selftest's guard
        // arm substitutes a stub for `seccomp-wrapper` that drops its arguments and execs,
        // so the cage is never actually built and a malformed argument list looks perfect.
        // This test is the off-cluster substitute — it checks the one property that makes an
        // argument list survive contact with bwrap.
        //
        // `-try` variants are exempt: tolerating a missing source is exactly what they are
        // for, which is also why they must never be used for a DENY (a silently skipped deny
        // is a deny that did not happen).
        let root = std::env::temp_dir().join(format!("husk-binds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("notes")).unwrap();
        std::fs::write(root.join("notes/real.txt"), b"").unwrap();
        let w = root.to_string_lossy().to_string();

        let p = FsPolicy::unchecked_for_test()
            // One that exists, three that do not — the shipped config's own shape.
            .with_deny_write(vec![
                "notes/real.txt".into(),
                ".claude/settings.json".into(),
                ".claude/settings.local.json".into(),
                "/nowhere/absolute/absent".into(),
            ]);
        let args = p.compute_bwrap_args(&w);
        let mut i = 0;
        while i < args.len() {
            let op = args[i].as_str();
            // Ops of the form `<op> SOURCE DEST` that REQUIRE the source to be there.
            if matches!(op, "--bind" | "--ro-bind" | "--dev-bind") {
                let src = &args[i + 1];
                assert!(
                    std::path::Path::new(src).exists(),
                    "`{op} {src} …` would kill the cage: bwrap exits when a bind source is \
                     missing, before the job runs. Full args: {args:?}"
                );
                i += 3;
            } else {
                i += 1;
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn nothing_inside_the_project_dir_is_bound_hard_because_that_directory_moves() {
        // **THE INVARIANT THE ICON OUTAGE TAUGHT, and the one worth keeping.**
        //
        // husk builds bwrap arguments on the LOGIN node at submit time; bwrap consumes them
        // on a COMPUTE node when the job starts. Every existence check in between is a
        // TOCTOU across two machines and an unbounded queue wait — and the project directory
        // is the one place where something is actively creating and deleting files in that
        // window. `sbatch` runs inside a login-cage Bash command, and the vendor runtime
        // protects a non-existent deny path by binding `/dev/null` over it, which makes bwrap
        // create an empty file ON THE HOST as its mount point, in the project directory, for
        // exactly as long as that command runs.
        //
        // So husk stat'd `.claude/settings.json` during the one moment it existed, emitted a
        // hard bind, the command ended, the runtime deleted its ghost, and every ICON job
        // died minutes later with a bwrap error that never said "husk". `.Rprofile` and
        // `.hg/hgrc` were the same bug waiting its turn — both are in the shipped login
        // denyWrite, so both get ghost-created too.
        //
        // The rule, asserted rather than remembered: **anything strictly below the workdir
        // is bound with `-try`.** The workdir bind ITSELF stays hard — if the project
        // directory is gone the job must die, and that is not a race, it is a fact.
        let root = std::env::temp_dir().join(format!("husk-noharden-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".claude")).unwrap();
        std::fs::create_dir_all(root.join(".hg")).unwrap();
        std::fs::create_dir_all(root.join("notes")).unwrap();
        // Everything the login cage might have ghosted into existence a moment ago.
        for f in [".claude/settings.json", ".hg/hgrc", ".Rprofile", ".mcp.json", "notes/x.txt"] {
            std::fs::write(root.join(f), b"").unwrap();
        }
        let w = root.to_string_lossy().to_string();
        let p = FsPolicy::unchecked_for_test()
            .with_deny_write(vec![
                ".claude/settings.json".into(),
                ".hg/hgrc".into(),
                "notes/x.txt".into(),
            ]);
        let args = p.compute_bwrap_args(&w);

        let mut i = 0;
        while i < args.len() {
            let op = args[i].as_str();
            if matches!(op, "--bind" | "--ro-bind" | "--dev-bind") {
                let (src, dest) = (&args[i + 1], &args[i + 2]);
                let below = dest.starts_with(&format!("{w}/"));
                assert!(
                    !below || src == "/dev/null",
                    "`{op} {src} {dest}` is a HARD bind below the project dir. That directory \
                     has files created and removed in it while husk is deciding — the ICON \
                     outage was exactly this. Use --ro-bind-try."
                );
                i += 3;
            } else {
                i += 1;
            }
        }
        // …and the workdir itself is still hard, because its absence is not a race.
        assert!(
            args.windows(3).any(|c| c[0] == "--bind" && c[1] == w && c[2] == w),
            "the workdir bind must stay unconditional: {args:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_relative_deny_write_is_honoured_on_compute_too() {
        // **B3-F8.** `deny_write` was the one field F22 never reached. It tested
        // `starts_with('/')` directly, so a RELATIVE entry — the natural spelling for a
        // project file, and the one the SHIPPED config uses for `.claude/settings.json`,
        // `.Rprofile` and `.hg/hgrc` — was silently dropped on compute while the login cage
        // honoured it. One policy line, two cages, two answers, and the disagreement fails
        // OPEN: the user wrote a deny, read a deny back, and got one on login only.
        // On disk, because a denyWrite is emitted only for a path that EXISTS — bwrap exits
        // when a bind source is missing, which is what killed three Balfrin jobs (5014767/8/9)
        // the first time relative entries started resolving.
        let root = std::env::temp_dir().join(format!("husk-relwrite-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("notes")).unwrap();
        std::fs::create_dir_all(root.join(".claude")).unwrap();
        std::fs::write(root.join(".claude/settings.json"), b"{}").unwrap();
        std::fs::write(root.join("notes/protected.txt"), b"").unwrap();
        let abs = std::env::temp_dir().join(format!("husk-relwrite-abs-{}", std::process::id()));
        std::fs::create_dir_all(&abs).unwrap();
        let (w, a_abs) = (root.to_string_lossy().to_string(), abs.to_string_lossy().to_string());

        let p = FsPolicy::unchecked_for_test()
            .with_deny_write(vec![
                ".claude/settings.json".into(),
                "./notes/protected.txt".into(),
                a_abs.clone(),
                "~/.ssh/config".into(),
            ]);
        let args = p.compute_bwrap_args(&w).join(" ");
        assert!(
            args.contains(&format!("--ro-bind-try {w}/.claude/settings.json {w}/.claude/settings.json")),
            "a relative denyWrite must be resolved against the workdir: {args}"
        );
        assert!(
            args.contains(&format!("--ro-bind-try {w}/notes/protected.txt")),
            "`./` is the same spelling: {args}"
        );
        assert!(args.contains(&format!("--ro-bind-try {a_abs}")), "absolute still works: {args}");
        // `~/x` stays dropped, and that is correct rather than an oversight: a bind EXPOSES
        // ITS SOURCE, so re-binding a home path would punch it back through the `--tmpfs
        // /users` floor that exists to remove it — a deny that grants.
        assert!(!args.contains(".ssh/config"), "a home path must not be bound back in: {args}");
        // And the case that killed the Balfrin jobs, in its final form. The first attempt
        // SKIPPED an entry whose path did not exist — which fixed the selftest and not the
        // cluster, because the stat runs on the login node and bwrap runs on a compute node
        // later. The answer is not a better check; it is to stop checking and let bwrap
        // decide at the only moment that can be right.
        let p2 = FsPolicy::unchecked_for_test()
            .with_deny_write(vec![".claude/settings.local.json".into()]);
        let a2 = p2.compute_bwrap_args(&w).join(" ");
        assert!(
            !a2.contains(&format!("--ro-bind {w}/.claude/settings.local.json")),
            "an absent denyWrite must never be a HARD bind — bwrap exits before the job runs: {a2}"
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&abs);
    }

    // ── F6a: bounded credential auto-scan ───────────────────────────────────

    #[test]
    fn matches_credential_recognizes_secrets_and_ignores_normal_files() {
        for n in [
            // NOTE `prod.env` is deliberately absent: `<name>.env` is no longer decided by
            // name — see `is_ambiguous_env` and the test below it.
            ".env", ".env.local", "server.pem", "tls.key", "credentials",
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

    /// `--output` may not name a path husk protects, even inside the writable root.
    ///
    /// **A1-F2, and it needed no race.** Confinement asked "is it under the root?" and stopped.
    /// `--output` is written by SLURM outside the cage with `--open-mode=append` forced, so
    /// `-o <root>/.claude/hooks/x.sh` put the job's own stdout into a file Claude Code executes
    /// next session. The run-time guard was satisfied throughout — the path IS under the root —
    /// which is why nothing caught it.
    ///
    /// The false friend: `confine_output_pattern` already had thorough tests for traversal,
    /// symlinks, `//`, `%` specifiers and `/proc` paths, and every one of them passed. They all
    /// asked the same question the code asked. A test can only fail if it asks something the
    /// code does not already assume.
    #[test]
    fn output_may_not_name_a_path_husk_protects() {
        let dir = std::env::temp_dir().join(format!("husk-outprot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in [".claude/hooks", ".git/hooks", "sub/.claude/hooks", "logs"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        std::fs::write(dir.join(".bashrc"), "").unwrap();
        std::fs::write(dir.join(".mcp.json"), "{}").unwrap();
        let root = std::fs::canonicalize(&dir).unwrap().to_string_lossy().to_string();

        for bad in [
            ".claude/hooks/evil.sh",   // create a runnable
            ".claude/settings.json",   // rewrite the policy that defines the cage
            ".mcp.json",               // a server definition is a command
            ".bashrc",                 // appended to on the next login
            "sub/.claude/hooks/x.sh",  // nested project dir is still a project dir
            ".git/hooks/pre-commit",   // runs on the operator's next commit
        ] {
            let r = confine_output_pattern(bad, &root);
            assert!(r.is_err(), "--output {bad:?} must be refused, got {r:?}");
            let why = r.unwrap_err();
            assert!(why.contains("OUTSIDE the cage"), "say WHY the in-cage mask does not help: {why}");
        }

        // ...and ordinary output paths inside the root still work, including the default shape.
        for good in ["out.log", "logs/run-%j.out", "slurm-%j.out"] {
            assert!(
                confine_output_pattern(good, &root).is_ok(),
                "{good} is an ordinary output path and must be allowed"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_git_hooks_placeholder_that_is_a_file_does_not_kill_the_cage() {
        // **2026-08-09, Balfrin.** Every brokered job from one project directory died in
        // bwrap setup with `Can't mkdir .git/hooks: Not a directory`, and it was
        // self-perpetuating: the login cage protects a non-existent deny path by binding
        // /dev/null over it, which leaves a zero-byte FILE on the host; husk then tried to
        // `--tmpfs` that path, and tmpfs needs to mkdir.
        //
        // The comment above the shape loop already described this exact failure. The fix had
        // been applied to `.git` and not to `.git/hooks` — one level too shallow.
        let dir = std::env::temp_dir().join(format!("husk-githooks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        let root = dir.to_string_lossy().to_string();

        let args_for = |pol: &FsPolicy| pol.compute_bwrap_args(&root).join(" ");
        let pol = FsPolicy::unchecked_for_test()
            .with_allow_write(vec![root.clone()]);

        // A real hooks DIRECTORY still gets the tmpfs — that is the masking this exists for.
        std::fs::create_dir_all(dir.join(".git/hooks")).unwrap();
        let a = args_for(&pol);
        assert!(
            a.contains(&format!("--tmpfs {root}/.git/hooks")),
            "a real hooks dir must still be masked with a tmpfs: {a}"
        );

        // The placeholder the LOGIN cage leaves: a zero-byte file. tmpfs cannot mkdir over
        // it, so it must be masked with /dev/null instead.
        std::fs::remove_dir(dir.join(".git/hooks")).unwrap();
        std::fs::write(dir.join(".git/hooks"), b"").unwrap();
        let a = args_for(&pol);
        assert!(
            !a.contains(&format!("--tmpfs {root}/.git/hooks")),
            "tmpfs over a FILE is what killed the cage: {a}"
        );
        assert!(
            a.contains(&format!("/dev/null {root}/.git/hooks")),
            "it must still be masked, just with a shape bwrap can mount: {a}"
        );

        // Absent is fine as a tmpfs — bwrap creates it as a directory, which is what we want.
        std::fs::remove_file(dir.join(".git/hooks")).unwrap();
        let a = args_for(&pol);
        assert!(
            a.contains(&format!("--tmpfs {root}/.git/hooks")),
            "an absent leaf is still masked so it cannot be created: {a}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_name_dot_env_is_judged_by_content_not_by_extension() {
        // **LETKF session, 2026-08-05/06. Cost: three failed 128-rank jobs and a
        // misdiagnosis.** `var3d.env` is DACE's module-load script — the operational
        // benchmark data ships it under that name and the build instructions use it. The
        // flat `ends_with(".env")` rule, copied from the vendor's `Read(//**/*.env)` glob,
        // masked it. `source var3d.env` then failed with a bare `Permission denied`, no
        // modules loaded, and all 128 ranks died on a missing libnetcdff.
        //
        // On an HPC the extension is wrong more often than right, so `<name>.env` is asked
        // what is inside it. `.env`/`.env.local` are NOT ambiguous and stay masked by name.
        let dir = std::env::temp_dir().join(format!("husk-envscan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // The real thing that broke: a module script.
        std::fs::write(
            dir.join("var3d.env"),
            "#!/bin/bash\nmodule load netcdf-fortran\nexport PATH=/opt/bin:$PATH\n\
             export DACE_ROOT=/scratch/dace\n",
        )
        .unwrap();
        // A real dotenv file that happens to be named <name>.env.
        std::fs::write(dir.join("prod.env"), "API_TOKEN=abc123\nDB_HOST=localhost\n").unwrap();
        // The unambiguous convention, masked by name regardless of content.
        std::fs::write(dir.join(".env"), "module load foo\n").unwrap();

        let found = scan_credentials(&dir).files;
        let has = |n: &str| found.iter().any(|f| f.ends_with(n));

        assert!(!has("var3d.env"), "a module script must not be masked: {found:?}");
        assert!(has("prod.env"), "a <name>.env holding a token must still be masked: {found:?}");
        assert!(has("/.env"), ".env is the dotenv convention and is not ambiguous: {found:?}");

        // `export PATH=` must not be enough to call something secrets — that is the whole
        // false positive, and a module script is full of them.
        assert!(!env_content_looks_like_secrets(&dir.join("var3d.env")));
        assert!(env_content_looks_like_secrets(&dir.join("prod.env")));

        // Unreadable means masked: this change may only ever mask FEWER files on evidence,
        // never more, and never on a guess.
        assert!(
            env_content_looks_like_secrets(&dir.join("does-not-exist.env")),
            "when husk cannot read it, it keeps the old behaviour"
        );
        let _ = std::fs::remove_dir_all(&dir);
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
        let p = FsPolicy::unchecked_for_test()
            .with_deny_read(vec!["secrets".into(), "./nested/creds".into()]);
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
        let p = FsPolicy::unchecked_for_test()
            .with_deny_read(vec!["/scratch/proj/secret".into()]);
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
        let p = FsPolicy::unchecked_for_test()
            .with_deny_read(vec!["~/.aws".into()])
            .with_deny_files(vec!["~/.aws/credentials".into()]);
        let cmd = p.compute_bwrap_args("/scratch/proj").join(" ");
        assert!(!cmd.contains("/scratch/proj/~"), "~ entry must not be joined onto the workdir");
        assert!(!cmd.contains("--ro-bind /dev/null /scratch/proj/~"));
    }

    #[test]
    fn relative_credential_file_under_workdir_is_masked() {
        // A workdir-relative credential file is resolved onto the workdir and masked
        // with /dev/null (previously dropped, since only absolute paths were emitted).
        let p = FsPolicy::unchecked_for_test()
            .with_deny_files(vec!["config/secret.pem".into()]);
        let cmd = p.compute_bwrap_args("/scratch/proj").join(" ");
        assert!(cmd.contains("--ro-bind /dev/null /scratch/proj/config/secret.pem"));
    }

    // ── F6b: write-protect auto-exec files in writable roots ─────────────────

    #[test]
    fn auto_exec_paths_are_masked_in_workdir_and_allow_write_roots() {
        let p = FsPolicy::unchecked_for_test()
            .with_allow_write(vec!["/scratch/run".into()]);
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
    fn an_auto_exec_dir_that_is_already_a_file_is_masked_as_a_file() {
        // **The cage-build collision (A3/A5/A8).** THE TEST GAP: every F6b test above uses
        // paths that do not exist, so all of them take the tmpfs branch and none of them
        // ever meets the shape that actually broke jobs on Balfrin. `--tmpfs <path>` makes
        // bwrap MKDIR the path, so it dies with "Can't mkdir …/.git/hooks: Not a directory"
        // when a FILE is already there — and one is: the login cage protects a non-existent
        // deny path by binding /dev/null over it, leaving an empty file on the host in the
        // shared project dir. 3 of 4 concurrent brokered jobs died in bwrap setup.
        //
        // So build the collision for real, on disk, and assert husk masks what is there.
        let root = std::env::temp_dir().join(format!("husk-shape-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let r = root.to_string_lossy().to_string();

        // `.vscode` as the login cage's ghost placeholder: an empty FILE.
        std::fs::write(root.join(".vscode"), b"").unwrap();
        // `.idea` as a real directory, the ordinary case.
        std::fs::create_dir_all(root.join(".idea")).unwrap();
        // `.claude` absent entirely, the other ordinary case.

        let cmd = joined(&FsPolicy::unchecked_for_test(), &r);
        assert!(
            cmd.contains(&format!("--ro-bind /dev/null {r}/.vscode")),
            "a file placeholder must be masked with /dev/null, not mkdir'd: {cmd}"
        );
        assert!(
            !cmd.contains(&format!("--tmpfs {r}/.vscode")),
            "a tmpfs over an existing FILE is the bwrap failure this fixes: {cmd}"
        );
        // …while the shapes that always worked keep working. Fixing the collision must not
        // cost the masking: both of these still have to be masked, just differently.
        assert!(cmd.contains(&format!("--tmpfs {r}/.idea")), "a real dir still gets tmpfs: {cmd}");
        assert!(cmd.contains(&format!("--tmpfs {r}/.claude")), "an absent dir still does: {cmd}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn auto_exec_masks_apply_to_absent_paths_too() {
        // The hole this closes: `--ro-bind-try` SKIPS a source that doesn't exist, so in
        // the common case of a project with no `.claude/settings.local.json`, a job could
        // simply CREATE one and have the next login-side session honour its permission
        // grants (AV2). A tmpfs over the whole `.claude` dir applies whether or not
        // anything is there, and covers config files upstream hasn't invented yet.
        let cmd = joined(&FsPolicy::unchecked_for_test(), "/proj");
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

        let p = FsPolicy::unchecked_for_test()
            .with_allow_git_config(true);
        let cmd = joined(&p, &root);
        assert!(!cmd.contains(&format!("{root}/.git/config")), "config writable: {cmd}");
        assert!(cmd.contains(&format!("--tmpfs {root}/.git/hooks")), "hooks protected: {cmd}");

        let p = FsPolicy::unchecked_for_test();
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
        let args = FsPolicy::unchecked_for_test().compute_bwrap_args("/proj");
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
        // A REAL directory, so this asserts "the layer was read and its deny applied" and not
        // "husk kept a mask bwrap cannot mount" — see `drop_unmountable_hides`.
        let secret = d.join("secret");
        std::fs::create_dir_all(&secret).unwrap();
        let secret = secret.to_string_lossy().to_string();
        std::fs::write(&f, format!("{{\"sandbox\":{{\"filesystem\":{{\"denyRead\":[\"{secret}\"]}}}}}}")).unwrap();
        let ok = FsPolicy::resolve(&home, &proj).expect("valid settings must resolve");
        assert!(ok.deny_read().iter().any(|p| *p == secret), "{ok:?}");

        // The same file with a typo must ERROR, and the error must name the file — the
        // operator has three candidates and no reason to guess.
        std::fs::write(&f, format!("{{\"sandbox\":{{\"filesystem\":{{\"denyRead\":[\"{secret}\"]}}}}")).unwrap();
        let e = FsPolicy::resolve(&home, &proj).expect_err("a broken settings file must fail");
        assert!(e.contains("settings.json"), "the error must name the file: {e}");

        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn parse_reads_allow_git_config_flag() {
        let json = r#"{ "sandbox": { "filesystem": { "allowGitConfig": true } } }"#;
        assert!(FsPolicy::parse(json).unwrap().allow_git_config());
        assert!(!FsPolicy::parse("{}").unwrap().allow_git_config()); // default false
    }
}

/// The `--output`/`--error` specifier CONTRACT, asserted directly.
///
/// **`B1-1`/`D2` in one sentence.** A specifier the submit-time validator ACCEPTS but the
/// compute-node guard cannot EXPAND leaves a `%` in the leaf; a `%` in the leaf is a
/// filename husk cannot state; a filename husk cannot state is a file husk cannot check.
/// So the contract is not a relation between two lists — it is:
///
/// > **no leaf `is_valid_output_filename` accepts may still contain a `%` once the guard's
/// > expander has run.**
///
/// `D2 §3.5` measured that *neither direction* of a set comparison expresses that. Both
/// were tried: `accepted ⊆ emitted` stayed **green** with `'%'` put back into the accepted
/// set (the four-character `x%%y.log` trigger, restored, unnoticed), and `emitted ⊆
/// accepted` was **red on a correct tree** because the guard's `%%`→`%` line PRODUCES a
/// `%` rather than consuming one.
///
/// These tests also read no source text. The probe they replace scraped the expander out
/// of `policy.rs`: shell-commenting one line kept it green while the guard stopped
/// expanding (`D2-3`), and a behaviour-preserving reformat of one line made it print a
/// security accusation about a guard that was correct (`D2-4`). There is now one table,
/// `policy.rs` GENERATES the guard's expander lines from it, and
/// `the_emitted_guard_expands_every_specifier_the_validator_accepts` in `policy.rs` checks
/// the emitted shell by RUNNING it.
#[cfg(test)]
mod output_specifier_contract {
    use super::{
        confine_output_pattern, is_valid_output_filename, output_filename_refusal,
        OUTPUT_SPECIFIERS, OUTPUT_SPECIFIERS_NAMED_REFUSED,
    };
    use std::collections::BTreeSet;

    /// The guard's substitution, modelled in Rust.
    ///
    /// bash's `${v//'PAT'/REP}` with a QUOTED pattern is a literal global replace — exactly
    /// `str::replace` — so the leaf can be reasoned about without a shell. A replacement
    /// that is a `${…}` parameter expansion stands for a value read at run time and is
    /// modelled by a `%`-free token: the BEST case for the guard, so this test
    /// under-approximates the damage and never over-approximates it. Anything else is used
    /// LITERALLY, which is what makes re-admitting `%` (whose expansion is a literal `%`)
    /// visible here.
    ///
    /// `P10` — what this harness substitutes: the eight run-time values. `D2-6` is exactly
    /// the case it cannot see (`USER=c%mueller` with `--output=a%u.log` puts the `%` back),
    /// and the guard's fail-closed branch, not this test, is what answers that.
    fn expand(leaf: &str) -> String {
        let mut s = leaf.to_string();
        for spec in OUTPUT_SPECIFIERS {
            // Every accepted expansion is a `${…}` by construction now (`Specifier::new`),
            // so the model is uniform: a `%`-free token standing for a run-time value.
            s = s.replace(&format!("%{}", spec.spec()), "V");
        }
        s
    }

    /// `RA-4`: THE ONE TEST THAT IS NOT THE TABLE READING ITSELF.
    ///
    /// Every other assertion about `OUTPUT_SPECIFIERS` takes its expected value out of
    /// `OUTPUT_SPECIFIERS`. `expand()` above does; `guard_value` in `policy.rs` does; the
    /// behavioural test that runs the emitted bash does, and it supplies its own values for
    /// all eight variables, which is exactly the substitution that hides a wrong one. A
    /// reviewer ran five independent corruptions — swap the expansions of `%n` and `%t`,
    /// point `%N` at `SLURM_JOB_ID`, delete the `%t` entry, reverse the generator's order,
    /// and correct `%A`/`%a` to match measured slurmd — and **all five were caught by the
    /// byte-goldens and by nothing else**: `333 passed` whether the table was right or
    /// wrong. A table cannot be its own oracle (`P15`'s corollary), and the goldens are
    /// scheduled to be expired by `ROADMAP` Track `F2`.
    ///
    /// So the oracle is written out here, INDEPENDENTLY, with the provenance of each claim
    /// — because the question this answers is not "does husk agree with husk" (`P8`, and
    /// the table already settles it) but "does husk agree with SLURM" (`P15`), and only a
    /// measurement can answer that. An entry marked *unmeasured* is a standing admission,
    /// not a passing grade: `ROADMAP`'s probe `P2` is what turns those into measurements.
    ///
    /// Changing the table now costs a deliberate edit HERE, where the edit has to be a
    /// claim about a cluster with a date on it.
    #[test]
    fn the_specifier_table_agrees_with_the_recorded_measurements() {
        // (specifier, variable, expansion, requires, what justifies the pairing)
        const REFERENCE: &[(char, &str, &str, &[&str], &str)] = &[
            ('j', "SLURM_JOB_ID", "${SLURM_JOB_ID:-}", &[],
             "set for every batch job; Santis 2026-08-31, %j and the id sbatch returned agreed"),
            ('A', "SLURM_ARRAY_JOB_ID", "${SLURM_ARRAY_JOB_ID:-}", &["-a", "--array"],
             "Santis 2026-08-31: on a NON-array job slurmd rendered %A as the job id while \
              this variable was unset, so the pairing holds only under --array (RA-2)"),
            ('a', "SLURM_ARRAY_TASK_ID", "${SLURM_ARRAY_TASK_ID:-}", &["-a", "--array"],
             "Santis 2026-08-31: on a NON-array job slurmd rendered %a as 4294967294 while \
              this variable was unset, so the pairing holds only under --array (RA-2)"),
            ('N', "SLURMD_NODENAME", "${SLURMD_NODENAME:-}", &[],
             "slurmd sets it on the node that runs the step; not independently measured"),
            ('n', "SLURM_NODEID", "${SLURM_NODEID:-0}", &[],
             "the batch step is node 0; the `:-0` default is husk's, and UNMEASURED"),
            ('t', "SLURM_LOCALID", "${SLURM_LOCALID:-0}", &[],
             "the batch step is local task 0; the `:-0` default is husk's, and UNMEASURED"),
            ('s', "SLURM_STEP_ID", "${SLURM_STEP_ID:-batch}", &[],
             "Santis 2026-08-31: %s rendered as `batch` on the batch step, which is the \
              `:-batch` default; whether SLURM_STEP_ID is itself set there is UNMEASURED"),
            ('u', "USER", "${USER:-}", &[],
             "slurmd renders the submitting user's name; USER is the job environment's own \
              name for it. Not independently measured"),
        ];

        assert_eq!(
            OUTPUT_SPECIFIERS.len(),
            REFERENCE.len(),
            "the table and its reference disagree on HOW MANY specifiers husk accepts — an \
             entry was added or deleted without recording what justifies it"
        );
        for (i, (c, var, expansion, requires, why)) in REFERENCE.iter().enumerate() {
            let got = &OUTPUT_SPECIFIERS[i];
            // ORDER too, not just membership: the guard substitutes in this order and `%u`
            // is last because USER is the one value that could itself contain a `%j`.
            assert_eq!(got.spec(), *c, "entry {i} is %{} where the reference says %{c}", got.spec());
            assert_eq!(got.expansion(), *expansion, "%{c}: {why}");
            assert_eq!(got.variable(), *var, "%{c} must read {var}: {why}");
            assert_eq!(got.requires(), *requires, "%{c}: {why}");
        }
    }

    /// `RAB3-A1`. A `requires` entry may only name an option the REQUEST supplies.
    ///
    /// **What this replaces is a false claim, not a missing test.** `policy.rs` used to say
    /// "the reference test is what catches that" about a `requires` naming a husk-FORCED
    /// option. It does not.
    /// `the_specifier_table_agrees_with_the_recorded_measurements` above goes red on ANY
    /// table edit, correct ones included, so its red is an instruction to update the
    /// reference row — not a diagnosis. A reviewer wrote the edit an author making this
    /// mistake would actually write (give `%N` `requires = ["-N", "--nodes"]` AND update the
    /// reference row in the same edit) and the whole suite was byte-identical to pristine.
    /// `%N`'s gate would then have been a permanent no-op. `P9`: a passing test can be a
    /// false friend, and the change-detector above is the false friend here.
    ///
    /// The hazard is semantic, so assert the semantics. `policy.rs` satisfies a `requires`
    /// by scanning `options`, which is the argv husk is about to submit — and that holds
    /// husk's own forced options (`--partition`, `--nodes=1`, `--export=ALL`, `--chdir`,
    /// `--output`, `--error`, `--open-mode`, `--account`). A `requires` naming one of those
    /// is satisfied by husk itself on every submission and can never refuse anything, which
    /// leaves the run-time unset guard as the only defence: the exact state `RA2-2` was.
    ///
    /// Derived from `sbatch::REGISTRY` rather than restated as a second denylist of forced
    /// spellings (`P8`, `P5`), so reclassifying an option moves this assertion with it. A
    /// test and not a run-time check, deliberately: a `requires` naming a forced option is a
    /// bug in husk's own table, not something an agent can send, so refusing at run time
    /// would cost a submission and buy nothing.
    ///
    /// MUTATION that turns it red: give any entry `requires = ["-N", "--nodes"]` or
    /// `["-p", "--partition"]`. Both are `Class::Forced`. `--array`/`-a`, the only entry
    /// today, is `Class::Allowed` — and `lookup` resolves short spellings, so `-a` is
    /// checked as the same object `policy.rs` will match on.
    #[test]
    fn every_requires_name_is_an_option_the_request_supplies() {
        for spec in OUTPUT_SPECIFIERS {
            let c = spec.spec();
            for name in spec.requires() {
                let opt = crate::sbatch::lookup(name).unwrap_or_else(|| {
                    panic!(
                        "%{c} requires {name:?}, which is not an sbatch option husk knows: \
                         `policy.rs` matches this name against the argv it emits, and an \
                         option that is not in the registry is never emitted, so the gate \
                         would refuse EVERY use of %{c}"
                    )
                });
                assert_eq!(
                    opt.class,
                    crate::sbatch::Class::Allowed,
                    "%{c} requires {name:?}, which is Class::{:?}. `requires` must name an \
                     option the REQUEST supplies. husk emits its own {name:?} on every \
                     submission, so this gate would be satisfied by husk itself and could \
                     never refuse — a no-op gate that reads as a control (`RAB3-A1`)",
                    opt.class
                );
            }
        }
    }

    #[test]
    fn percent_is_the_escape_character_and_must_never_be_a_specifier() {
        // `%%` is SLURM's escape for a literal `%`. A literal `%` is by construction the
        // one thing no expansion can remove, so admitting it makes `x%%y.log` — four
        // characters, no knowledge of any other gap — a leaf the guard cannot name. Before
        // `D2` this was accepted BY DESIGN and was the larger half of B1-1's reachability.
        assert!(
            !OUTPUT_SPECIFIERS.iter().any(|s| s.spec() == '%'),
            "`%` is the escape character, not a specifier: with it accepted, `x%%y` reaches \
             the guard as a literal `%` and no expander can remove it"
        );
    }

    #[test]
    fn every_specifier_expands_to_a_percent_free_value() {
        // The admission rule for the table, asserted where the table lives. A replacement
        // that could itself contain a `%` re-opens the class one level down.
        for spec in OUTPUT_SPECIFIERS {
            let (c, replacement) = (spec.spec(), spec.expansion());
            assert!(
                !replacement.contains('%'),
                "the expansion of %{c} is {replacement:?}, which contains a `%` — the leaf \
                 would still be unnameable after it ran"
            );
            assert!(
                replacement.starts_with("${") && replacement.ends_with('}'),
                "the expansion of %{c} is {replacement:?}; the guard emits these into \
                 `${{_husk_nl//'%{c}'/…}}`, so anything that is not a parameter expansion \
                 needs an argument nobody has made yet"
            );
        }
    }

    #[test]
    fn no_leaf_the_validator_accepts_keeps_a_percent_past_the_expander() {
        // The alphabet STRESSES the grammar rather than covering it: the escape itself, a
        // specifier that is in the table (`j`, `u`, `a`), two that deliberately are not
        // (`J`, `x`), and two ordinary characters. Length ≤ 5 reaches `%%`-doubling, a
        // trailing `%`, `%%` in front of a specifier, and every pairing of the escape with
        // a table entry.
        const ALPHABET: &[char] = &['%', 'j', 'J', 'x', 'u', 'a', '.', 'o'];
        let mut accepted = 0usize;
        let mut leaked = 0usize;
        let mut first: Vec<String> = Vec::new();
        for len in 1..=5usize {
            for n in 0..ALPHABET.len().pow(len as u32) {
                let mut i = n;
                let mut leaf = String::with_capacity(len);
                for _ in 0..len {
                    leaf.push(ALPHABET[i % ALPHABET.len()]);
                    i /= ALPHABET.len();
                }
                if !is_valid_output_filename(&leaf) {
                    continue;
                }
                accepted += 1;
                let expanded = expand(&leaf);
                if expanded.contains('%') {
                    leaked += 1;
                    if first.len() < 6 {
                        first.push(format!("{leaf} -> {expanded}"));
                    }
                }
            }
        }
        // P10/P15: a sweep that accepted nothing would pass for the wrong reason, and a
        // narrowing of the validator is exactly the change that could cause it.
        assert!(accepted > 500, "the sweep only accepted {accepted} leaves — it is not \
                                 exercising the grammar any more");
        assert_eq!(
            leaked, 0,
            "{leaked} of {accepted} accepted leaves still carry a `%` after the guard's \
             expander, so husk cannot name the file SLURM will open for them: {first:?}"
        );
    }

    #[test]
    fn the_refusal_message_states_exactly_the_accepted_set() {
        // `P8` for the THIRD statement of this set. `SKILL.md` lists option names only and
        // `constraints.md`/`THREAT-MODEL.md` say just "excludes %x", so this message is the
        // ONLY enumeration the confined party can read — and it was hand-edited into
        // advertising `%%` and `%J` as allowed at the moment husk started refusing them
        // (`D2-1`). `P11`: a refusal that contradicts itself reads as a broken parser and
        // gets retried verbatim.
        //
        // The probe filename carries no `%`, so every token below comes from husk's own
        // prose rather than from the echoed input.
        let msg = output_filename_refusal("has space.o");
        let chars: Vec<char> = msg.chars().collect();
        let mut found: BTreeSet<String> = BTreeSet::new();
        let mut i = 0;
        while i + 1 < chars.len() {
            // A specifier token is `%` followed by an alphanumeric or by `%`; `%` followed
            // by anything else is prose ("a % specifier") and is not a claim about the set.
            if chars[i] == '%' && (chars[i + 1].is_ascii_alphanumeric() || chars[i + 1] == '%') {
                found.insert(format!("%{}", chars[i + 1]));
                i += 2; // `%%` is ONE token, not two overlapping ones
                continue;
            }
            i += 1;
        }
        let allowed: BTreeSet<String> =
            OUTPUT_SPECIFIERS.iter().map(|s| format!("%{}", s.spec())).collect();
        let refused: BTreeSet<String> =
            OUTPUT_SPECIFIERS_NAMED_REFUSED.iter().map(|(t, _)| (*t).to_string()).collect();
        assert!(
            allowed.is_disjoint(&refused),
            "a specifier cannot be both accepted and named as refused — the message would \
             be false either way: {:?}",
            allowed.intersection(&refused).collect::<Vec<_>>()
        );
        assert_eq!(
            found,
            allowed.union(&refused).cloned().collect::<BTreeSet<_>>(),
            "the refusal must name every ACCEPTED specifier, plus exactly the ones it \
             explicitly calls refused, and nothing else.\n  in message: {found:?}\n  \
             accepted : {allowed:?}\n  refused  : {refused:?}"
        );
        // …and the bytes above must be the bytes an agent actually receives.
        let live = confine_output_pattern("has space.o", "/tmp")
            .expect_err("a name with a space is not a valid output filename");
        assert_eq!(live, msg, "the refusal this test reads must be the one husk returns");
    }
}
