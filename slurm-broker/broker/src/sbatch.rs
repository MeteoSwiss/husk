//! sbatch argument MODEL for the broker — an allowlist, not a permissive parser.
//! The broker does not forward the agent's options; it CONSTRUCTS the real sbatch
//! invocation: it forces every security-relevant option, parses the small set of
//! benign resource options into validated values and RE-EMITS them canonically, and
//! REJECTS anything it does not recognise. Agent bytes are interpreted, never
//! forwarded into slurmd's parser — so a spelling/channel we didn't enumerate
//! (glued shorts, `#SBATCH`, `--wrap`, unknown flags) fails closed by construction,
//! not open. See THREAT-MODEL.md "Design principle (the gate)".
//!
//! `REGISTRY` is the single source of truth: which options exist, their arity,
//! their class, and their value grammar. `option_tokens`/`split_glued_short_opts`/
//! `option_value` derive arity from it; `interpret_cli` and `body_reject_reason`
//! enforce the allowlist.

/// How the broker treats an option it recognises.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Class {
    /// Broker owns the value. On the CLI the agent's occurrence is dropped (the
    /// broker forces its own); in the body it is rejected — except `--partition`,
    /// which policy.rs validates + forces with its own message.
    Forced,
    /// Benign resource option the agent may set: the value must pass `validate` and
    /// is re-emitted canonically as `--long=value` (flags as bare `--long`).
    Allowed,
    /// Recognised but irrelevant/undesirable (mail, `--parsable`, verbosity):
    /// accepted so it isn't a hard error, and dropped (never re-emitted).
    Ignored,
    /// Recognised and REFUSED, carrying the reason. Distinct from `Forced` (silently
    /// dropped) because dropping an option the user meant — an `srun --task-prolog`
    /// that never runs — changes what their job does without telling them. And
    /// distinct from being absent from the registry, which yields only a generic
    /// "unsupported option": these have a specific reason worth stating.
    Rejected(&'static str),
}

/// The option contract, as markdown, for husk's user-facing skill.
///
/// GENERATED FROM `REGISTRY`, because the alternative is a second statement of the same
/// contract in prose, and two statements of one thing drift (`P8`). Every friction report so
/// far has been about this table — options silently dropped, options refused without a
/// reason — so a stale copy of it would actively mislead the party it exists to help.
///
/// Emitted by `husk-slurm-broker --print-option-contract` and pasted into the skill by
/// `slurm-broker/skill/build.sh`, so regenerating is one command and reviewing is a diff.
pub fn option_contract_markdown() -> String {
    let mut forced = Vec::new();
    let mut allowed = Vec::new();
    let mut ignored = Vec::new();
    let mut rejected = Vec::new();
    for spec in REGISTRY {
        let name = if spec.short.is_empty() {
            format!("`{}`", spec.long)
        } else {
            format!("`{}` / `{}`", spec.long, spec.short)
        };
        match spec.class {
            Class::Forced => forced.push(name),
            Class::Allowed => allowed.push(name),
            Class::Ignored => ignored.push(name),
            Class::Rejected(why) => rejected.push(format!("{name} — {why}")),
        }
    }
    let mut m = String::new();
    m.push_str("### husk FORCES these — your value is discarded and husk emits its own\n\n");
    m.push_str(&forced.join(", "));
    m.push_str("\n\nThese are the security-relevant ones. Setting them is not an error; it \
                simply has no effect, and husk announces what it forced.\n\n");
    // Four classes cannot express the fifth thing husk actually does, and an agent read the
    // contract against the behaviour and found the gap. `--partition` and `--account` are
    // Forced in the registry — husk emits the bytes — but the job DOES choose, from a set
    // the operator bounded. Saying only "your value is discarded" is false for them in the
    // direction that wastes a session: it reads as "do not bother asking".
    m.push_str("**Two of those are selections, not overrides.** `--partition` and \
                `--account` are resolved against a set your operator configured: name one \
                from the set and husk emits that entry; name one outside it and husk refuses \
                and lists the set; name none and husk picks the first and says so. The bytes \
                that reach sbatch are always husk's own copy, which is why they are listed \
                here rather than as pass-throughs.\n\n");
    m.push_str("### husk PASSES THROUGH these, after checking the value\n\n");
    m.push_str(&allowed.join(", "));
    m.push_str("\n\nValues are charset-checked (no whitespace, no shell metacharacters) and \
                re-emitted canonically. If one is refused, the message names the option.\n\n");
    m.push_str("### husk ACCEPTS but does NOT APPLY these\n\n");
    m.push_str(&ignored.join(", "));
    m.push_str("\n\nThe submission succeeds and the option is not forwarded to sbatch. \
                husk says so on stderr — read it, because this is where a script quietly does \
                the wrong thing. Job mail in particular is never sent, and `--mail-user` \
                would be a way out of the cluster that husk's egress allowlist cannot see.\n\n\
                **Exception: `--parsable` IS honoured.** There is nothing to forward — husk \
                builds its own sbatch invocation — but it is an output contract, so the stub \
                prints the bare job id as you asked. `jobid=$(sbatch --parsable job.sh)` \
                works. It appears in this list because of where it sits in the registry, not \
                because it is ignored.\n\n");
    m.push_str("### husk REFUSES these, with a reason\n\n");
    for r in &rejected {
        m.push_str(&format!("- {r}\n"));
    }
    m.push_str("\nAnything not listed anywhere is refused as an unsupported option: husk \
                submits an explicit set and rejects what it does not model, so a new option \
                is a conversation with your operator rather than a silent pass-through.\n");
    m
}

/// One option's spelling(s), arity, class, and value grammar.
///
/// **There is deliberately no alias / abbreviation slot.** There was one — `aliases:
/// &'static [&'static str]` — and it was `&[]` in all 97 entries of both registries, so
/// `lookup_in`'s alias clause could not fire; deleting the clause left the suite green
/// (`B3-3`, mutation-verified). An empty mechanism is worse than no mechanism: it answers
/// "does husk model every spelling of an option?" with a yes that nothing implements, which
/// is `P12` in miniature. The real answer is on `lookup_in`, where it can be read.
pub struct OptSpec {
    pub long: &'static str,
    pub short: &'static str, // "" when there is no short form
    pub takes_value: bool,
    pub class: Class,
    /// The value grammar. `interpret_cli_in` consults it in the `Class::Allowed` arm and
    /// nowhere else, so on any other entry it is decoration that reads as enforcement —
    /// which is what four of them were (`B3-3`). Every entry that is not `Allowed` +
    /// `takes_value` carries `always_true`, and
    /// `only_a_class_allowed_value_option_carries_a_value_grammar` keeps it that way in
    /// both directions.
    pub validate: fn(&str) -> bool,
}

pub(crate) fn always_true(_: &str) -> bool {
    true
}

// --- value grammars: charset + length bounds. Resource options are not
// security-critical (every dangerous decision is Forced), so the grammar's job is to
// keep values free of whitespace / newlines / shell metacharacters and bounded in
// length; slurmd validates the semantics.
//
// `pub(crate)` because `srun.rs` USES these. It used to re-declare nine of them, and two
// copies had already drifted: the same `--mem-bind` value was legal in a `#SBATCH` line
// and refused by an in-cage `srun` at 65 characters (`B3-5`, measured). Nine grammars was
// nine places for the next divergence, and the suite was blind to all of them — mutating
// either copy left the other's tests green. One definition, two tables. ---
fn bounded(s: &str, max: usize, ok: impl Fn(char) -> bool) -> bool {
    !s.is_empty() && s.len() <= max && s.chars().all(ok)
}

/// The kernel's ceiling on **one** argv element: `MAX_ARG_STRLEN`, `32 * PAGE_SIZE`, which
/// is 128 KiB on both architectures husk runs on. It is not tunable, `getconf` does not
/// report it, and exceeding it is an `E2BIG` from `execve` that names nothing.
///
/// It is here to be **derived from**, not to be enforced: no husk value is allowed
/// anywhere near it. `MAX_REEMITTED_ARGV_BYTES` bounds the whole command line at 256 KiB
/// and `MAX_LIST_VALUE_BYTES` bounds one element at 1/16 of this, so both husk bounds bite
/// long before the kernel does — which is the point, because husk's refusal names the
/// option and the kernel's does not (`P11`).
const MAX_ARG_STRLEN: usize = 128 * 1024;

/// **The ceiling for a value whose LENGTH IS A COUNT the real work chooses.**
///
/// Four options in these two tables carry a list with one entry per *thing*: per task
/// (`--cpu-bind`/`--gpu-bind`/`--mem-bind`), per node (`--nodelist`/`--exclude`), per array
/// index (`--array`), per job depended on (`--dependency`). For those, a character count is
/// a job-size limit wearing a charset's clothes, and picking it by eye means picking a
/// maximum ensemble size by eye.
///
/// **All four were picked by eye, and three of them bit.** Fix `J` found the first
/// (`--cpu-bind` at 64 characters, a false reject on eight explicit per-rank masks) and
/// derived that one bound — but left its three siblings in the same table at the numbers the
/// same hand had guessed. Measured at `a441428`, on the shipped tables:
///
/// | option | old bound | refused from | the real workload it refuses |
/// |---|---|---|---|
/// | `--dependency` | 128 | **16 jobs** (135 B; 15 = 127 B accepted) | an ensemble whose members are chained `afterok:` — the LETKF shape (`J-1`) |
/// | `--array` | 64 | **22 two-digit indices**, or 16 three-digit ones (n=20 -> 56 B accepted, n=40 -> 123 B refused) | re-running the members of an ensemble that failed: `--array=3,7,11,…` |
/// | `--exclude`/`--nodelist` | 256 | **26 node names** (259 B; 25 = 249 B accepted) | steering around a site's drained-node list |
/// | `--cpu-bind` etc. | 64 (srun's copy) | 8 masks | fixed by `J`, and this constant is that fix's number |
///
/// A message telling an operator that `afterok:` on sixteen of their own job ids "must match
/// the option's safe grammar" is the *opposite* failure from the denial-of-service this
/// round kept shipping, and just as real: **a bound a real job hits is a defect, not a
/// virtue.**
///
/// **What 8 KiB is derived from.** One re-emitted option is exactly one argv element
/// (`P4`'s corollary: the emission form is what makes a value safe, so the element is the
/// unit), and the only real ceiling on one element is `MAX_ARG_STRLEN`. 1/16 of it leaves
/// the other fifteen sixteenths for everything else husk builds, and the aggregate is
/// bounded independently at `MAX_REEMITTED_ARGV_BYTES`. What that buys, per option:
///
/// * `--dependency`: ~1020 job ids at Balfrin's current seven-digit width (measured: 940
///   ids accepted at 7527 bytes), ~900 at eight digits, or ~630 array-task ids
///   (`12345678_901`).
/// * `--array`: ~2000 explicit three-digit indices (measured: 1000 mixed-width indices
///   accepted at 3892 bytes).
/// * `--nodelist`/`--exclude`: 819 `nid001234`-shaped names, measured — more nodes than any partition
///   husk can submit to, since `Profile::select` forces `--nodes=1`.
/// * `--cpu-bind`: 234 tasks x a 128-bit mask (Balfrin's node width), or 108 tasks x 288 bits
///   (a Santis GH200 node) — `J`'s own derivation, unchanged in value.
///
/// **One constant and not four**, because four numbers for one question is four places for
/// the next wrong guess (`P8`), and because the question really is one: how long may a
/// single argv element get. The *security* property is per-grammar and untouched — the
/// charset is what keeps whitespace and shell syntax out, and every one of these values is
/// re-emitted as one `--long=value` element that never meets a shell.
pub(crate) const MAX_LIST_VALUE_BYTES: usize = MAX_ARG_STRLEN / 16;

// The bounds BELOW this line are on values with a FIXED shape — their length does not grow
// with the size of anybody's job — so a character count is an honest sanity bound rather
// than a hidden job-size limit. Each was re-measured against a real submission at `a441428`
// (`FIX-JK2 §1.1`); the number in the comment is what a real value spends, so the next
// reader can see the margin instead of re-deriving it:
//
//   v_uint      9  --ntasks=999999999 accepted; a real count is 4-6 digits
//   v_time     15  --time=7-00:00:00 is 10; 10000-23:59:59 (14) still accepted
//   v_time_at  32  --begin=2026-09-01T12:00:00 is 19
//   v_size     16  --mem=490000M is 7
//   v_name     64  a real ensemble-member job name measured 42. THIS IS THE THINNEST
//                  MARGIN in the table and the one to widen next if a site's workflow
//                  generator produces longer names; it is left alone because it also
//                  governs `is_valid_account`, where tight is cheap, and because no
//                  measured name has exceeded it.
//   v_gres    128  --gres=gpu:4 is 5; the list is bounded by the node's GRES types
//   v_expr    256  --constraint=gpu is 3; feature expressions do not scale with job size
//   v_signal   24  --signal=B:USR1@120 is 10
//   v_dist     40  --distribution=plane=4 is 7
//   v_comment 256  free text, not a list
//   v_switches 24  --switches=2@00:30:00 is 10
//   v_view    256  one or two uenv views
pub(crate) fn v_uint(s: &str) -> bool { bounded(s, 9, |c| c.is_ascii_digit()) }
pub(crate) fn v_time(s: &str) -> bool { bounded(s, 15, |c| c.is_ascii_digit() || c == ':' || c == '-') }
fn v_time_at(s: &str) -> bool { bounded(s, 32, |c| c.is_ascii_alphanumeric() || ":+.-".contains(c)) }
pub(crate) fn v_size(s: &str) -> bool { bounded(s, 16, |c| c.is_ascii_digit() || c == '.' || "KMGTPEkmgtpe".contains(c)) }
fn v_name(s: &str) -> bool { bounded(s, 64, |c| c.is_ascii_alphanumeric() || "._+-".contains(c)) }
/// The account grammar, applied to the **operator's** configured accounts
/// (`config.rs:252`, `session.rs:42`) — `HUSK_SLURM_ACCOUNT` and `~/.husk/config.json`.
///
/// It used to say it existed "so the operator's `HUSK_SLURM_ACCOUNT` is held to the same
/// rule as an account arriving on the command line. One grammar, one definition." **That
/// parity was never there and cannot be** (`B3-3`): `--account` is `Class::Forced`, so an
/// account arriving on the command line is dropped without `validate` ever running, and
/// the selection it makes is decided by exact membership in the operator's set — a
/// stricter test than any charset. The sentence mattered because it told the next reader
/// that moving `--account` to `Class::Allowed` was already covered by a tested grammar. It
/// is not covered, and it is not tested.
pub fn is_valid_account(s: &str) -> bool { v_name(s) }
/// `--nodelist` / `--exclude`: one entry per NODE, so it is `MAX_LIST_VALUE_BYTES`-class
/// (see there). At the old 256 it refused a 26-name list — measured, 259 bytes — which is
/// smaller than the drained-node list a site hands out after a bad week.
fn v_nodelist(s: &str) -> bool {
    bounded(s, MAX_LIST_VALUE_BYTES, |c| c.is_ascii_alphanumeric() || "_,-[]".contains(c))
}
/// A `--view` value: `[uenv:]view-name[,<uenv:view-name>]*`, and nothing else.
///
/// **This validator became load-bearing the day a job could choose its own uenv.** Until
/// then `--view` was `Class::Forced` from the trusted session and `always_true` was honest.
/// Now the value can be the agent's, so this is the charset boundary on bytes that reach
/// sbatch's command line — the F13/F14 surface.
///
/// The grammar is uenv's own (`--view [uenv:]view-name[,<uenv:view-name>]*`), so commas and
/// one colon per element are legal and everything else is not: no whitespace, no shell
/// metacharacter, no `/` or leading `.` (which would make an element a PATH to uenv's lexer,
/// the same trap the config file's uenv rule exists for).
pub fn v_view(s: &str) -> bool {
    if s.is_empty() || s.len() > 256 {
        return false;
    }
    s.split(',').all(|elem| {
        !elem.is_empty()
            && !elem.starts_with('.')
            && !elem.starts_with('-')
            && elem.matches(':').count() <= 1
            && elem
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c))
    })
}

pub(crate) fn v_gres(s: &str) -> bool { bounded(s, 128, |c| c.is_ascii_alphanumeric() || "_,:.-".contains(c)) }
/// Task-binding lists: `--cpu-bind`, `--gpu-bind`, `--mem-bind`. Shared by BOTH registries.
///
/// The charset is the security property, and it is `v_gres`'s: no whitespace, no shell
/// metacharacter, and the value is re-emitted into a single ARGV element that never meets a
/// shell. **The length is a sanity bound, and the old ones were a false reject on the
/// workload this file exists for.** `srun.rs` carried its own copy at 64 characters while
/// `sbatch.rs` used `v_gres`'s 128, so a 65-character `--mem-bind` was accepted at submit
/// and refused per step (`B3-5`, measured). Worse, 64 was too small for the option only
/// `srun` has: `--cpu-bind=mask_cpu:<mask>,...` carries one NODE-WIDTH hex mask per task,
/// so it grows as tasks x node width — eight masks already exceed 64 characters, and
/// explicit pinning is exactly what the ICON run scripts at `--hint` below do.
///
/// The length is now `MAX_LIST_VALUE_BYTES`, which is where that derivation lives and where
/// its three siblings joined it (`J-1`): 8 KiB covers 234 tasks x a 128-bit mask (Balfrin's
/// node width) or 108 tasks x a 288-bit mask (a Santis GH200 node), and any `map_cpu:` list
/// on either. Fix `J` wrote that number here as a literal; three other options in this table
/// asked the same question and still held a guess, which is exactly the drift `P8` predicts
/// from one fact stated in four places.
pub(crate) fn v_bind(s: &str) -> bool {
    bounded(s, MAX_LIST_VALUE_BYTES, |c| c.is_ascii_alphanumeric() || "_,:.-".contains(c))
}
/// `--array`: one entry per ARRAY INDEX when the indices are listed explicitly, so it is
/// `MAX_LIST_VALUE_BYTES`-class (see there). The range forms (`1-1000%50`) are short and
/// were never at risk; the shape that bit is the one an ensemble uses to re-run the members
/// that failed — `--array=3,7,11,…`, refused from 22 two-digit indices at the old 64.
fn v_array(s: &str) -> bool {
    bounded(s, MAX_LIST_VALUE_BYTES, |c| c.is_ascii_digit() || "-,:%".contains(c))
}
/// `--dependency`: one entry per JOB DEPENDED ON, so it is `MAX_LIST_VALUE_BYTES`-class
/// (see there). This is `J-1`, and it is the one that was measured against a live workload:
/// at the old 128 an `afterok:` chain over an ensemble was refused **from the sixteenth
/// job** — 15 ids accepted at 127 bytes, 16 refused at 135 — with the message *"is not
/// allowed (must match the option's safe grammar)"*, which tells an operator their ordinary
/// ensemble workflow has a syntax error (`P11`: an unattributed denial invites confident
/// wrong remediation, and this one is worse than unattributed — it is misattributed).
fn v_dep(s: &str) -> bool {
    bounded(s, MAX_LIST_VALUE_BYTES, |c| c.is_ascii_alphanumeric() || "_,:.+?-".contains(c))
}
fn v_expr(s: &str) -> bool { bounded(s, 256, |c| c.is_ascii_alphanumeric() || "_,&|()!*.-".contains(c)) }
fn v_signal(s: &str) -> bool { bounded(s, 24, |c| c.is_ascii_alphanumeric() || ":@".contains(c)) }
/// `--distribution` covers `block`, `cyclic`, `arbitrary`, `*`, colon-separated
/// second/third levels, an optional `,Pack|NoPack`, and `plane=<size>` — which is why
/// `=` is in the charset. ICON submits `--distribution=plane=4` (Balfrin 2026-07-30) and
/// the first attempt rejected it.
///
/// Charset-bounded rather than an exact grammar: the value is re-emitted as
/// `--distribution=<value>` into an ARGV element and never reaches a shell, so the job
/// of this check is to keep whitespace and shell syntax out, not to re-implement SLURM's
/// parser. An invalid-but-safe value is srun's to reject, with a better message than we
/// would write.
pub(crate) fn v_dist(s: &str) -> bool { bounded(s, 40, |c| c.is_ascii_alphanumeric() || ",:*=".contains(c)) }
fn v_comment(s: &str) -> bool { bounded(s, 256, |c| c.is_ascii_alphanumeric() || " _.,:@/+-".contains(c)) }
fn v_switches(s: &str) -> bool { bounded(s, 24, |c| c.is_ascii_digit() || "@:-".contains(c)) }
/// `--hint` takes one of four fixed keywords — an exact enum is tighter than any charset,
/// and closed sets are exactly where an allowlist should be an allowlist.
pub(crate) fn v_hint(s: &str) -> bool {
    matches!(s, "compute_bound" | "memory_bound" | "multithread" | "nomultithread")
}

macro_rules! spec {
    ($long:expr, $short:expr, $val:expr, $class:expr, $validate:expr) => {
        OptSpec {
            long: $long,
            short: $short,
            takes_value: $val,
            class: $class,
            validate: $validate,
        }
    };
}

/// The allowlist. Anything not here is rejected. Seeded with the common HPC job
/// options; an operator extends it as real job scripts require (rejections are
/// logged, so gaps surface as "unsupported option X", never as a silent escape).
pub const REGISTRY: &[OptSpec] = &[
    // ---- Forced: broker owns the value ----
    spec!("--partition", "-p", true, Class::Forced, always_true),
    spec!("--output", "-o", true, Class::Forced, always_true),
    spec!("--error", "-e", true, Class::Forced, always_true),
    spec!("--chdir", "-D", true, Class::Forced, always_true),
    // Forced to `append`, and Forced rather than merely absent from the allowlist because
    // an option the broker EMITS must be one the agent cannot also emit — two copies on one
    // command line and the last one wins. It decides whether slurmd opens the output file
    // with O_TRUNC. Under `truncate`, a job whose --output was swapped for a symlink between
    // husk's check and slurmd's open() empties the target before anything of husk's runs;
    // under `append` there is nothing to destroy and nothing but husk's own bytes to add.
    // (A1's run-time half; the fd check in the job guard is the other one.)
    spec!("--open-mode", "", true, Class::Forced, always_true),
    spec!("--export", "", true, Class::Forced, always_true),
    spec!("--uenv", "", true, Class::Forced, always_true),
    spec!("--view", "", true, Class::Forced, always_true),
    spec!("--repo", "", true, Class::Forced, always_true),
    spec!("--wrap", "", true, Class::Forced, always_true),
    // ---- Allowed: benign resource options, validated + re-emitted ----
    // Forced, not Allowed: the cage profile is a function of the node count, so the
    // broker emits it (see profile.rs). policy.rs validates the agent's request first and
    // REJECTS anything but one node - forcing alone would silently downgrade a 4-node job.
    //
    // `always_true`, not a node grammar. The slot held `v_nodes`, which `interpret_cli_in`
    // could never call: it consults `validate` in the `Class::Allowed` arm only, and this
    // entry is `Forced` (`B3-3` — replacing `v_nodes` with `|_| false` left the suite green).
    // What actually bounds the value is `profile::Profile::select`, which accepts `None` or
    // `"1"` and nothing else, and policy.rs, which refuses the rest with a reason.
    spec!("--nodes", "-N", true, Class::Forced, always_true),
    spec!("--ntasks", "-n", true, Class::Allowed, v_uint),
    spec!("--ntasks-per-node", "", true, Class::Allowed, v_uint),
    spec!("--ntasks-per-core", "", true, Class::Allowed, v_uint),
    spec!("--ntasks-per-socket", "", true, Class::Allowed, v_uint),
    spec!("--cpus-per-task", "-c", true, Class::Allowed, v_uint),
    spec!("--cpus-per-gpu", "", true, Class::Allowed, v_uint),
    // CPU/NUMA topology + binding. Real MPI run scripts (ICON) pin explicitly; none of
    // these can affect what code runs, where output goes, or the cage — those families
    // are all Forced — so the risk is confined to a job asking for an odd shape.
    spec!("--hint", "", true, Class::Allowed, v_hint),
    spec!("--threads-per-core", "", true, Class::Allowed, v_uint),
    spec!("--sockets-per-node", "", true, Class::Allowed, v_uint),
    spec!("--cores-per-socket", "", true, Class::Allowed, v_uint),
    // `v_bind`, and the SAME `v_bind` `srun.rs` uses — these two are the pair whose two
    // copies had already drifted apart at 65 characters (`B3-5`).
    spec!("--gpu-bind", "", true, Class::Allowed, v_bind),
    spec!("--mem-bind", "", true, Class::Allowed, v_bind),
    spec!("--oversubscribe", "-s", false, Class::Allowed, always_true),
    spec!("--time", "-t", true, Class::Allowed, v_time),
    spec!("--time-min", "", true, Class::Allowed, v_time),
    spec!("--deadline", "", true, Class::Allowed, v_time_at),
    spec!("--begin", "", true, Class::Allowed, v_time_at),
    spec!("--mem", "", true, Class::Allowed, v_size),
    spec!("--mem-per-cpu", "", true, Class::Allowed, v_size),
    spec!("--mem-per-gpu", "", true, Class::Allowed, v_size),
    spec!("--gres", "", true, Class::Allowed, v_gres),
    spec!("--gpus", "-G", true, Class::Allowed, v_gres),
    spec!("--gpus-per-node", "", true, Class::Allowed, v_gres),
    spec!("--gpus-per-task", "", true, Class::Allowed, v_gres),
    spec!("--gpus-per-socket", "", true, Class::Allowed, v_gres),
    spec!("--constraint", "-C", true, Class::Allowed, v_expr),
    spec!("--nodelist", "-w", true, Class::Allowed, v_nodelist),
    spec!("--exclude", "-x", true, Class::Allowed, v_nodelist),
    spec!("--array", "-a", true, Class::Allowed, v_array),
    spec!("--dependency", "-d", true, Class::Allowed, v_dep),
    spec!("--job-name", "-J", true, Class::Allowed, v_name),
    // The resource envelope IS the threat model on a shared cluster, and the partition is
    // what carries it. A QOS moves priority and limits out from under that partition; a
    // reservation grants nodes set aside for somebody else. Neither is the agent's to
    // choose, and THREAT-MODEL.md already said this family was forced.
    spec!("--qos", "-q", true, Class::Rejected(
        "husk does not let a job choose its QOS: the partition husk forces is what bounds \
         what this job may consume, and a QOS moves those limits out from under it. Submit \
         without --qos. If your work genuinely needs a different QOS, that is a decision for \
         whoever configured husk, not for this job."
    // `always_true`: `Class::Rejected` returns before `interpret_cli_in` looks at a value,
    // so a grammar here is unreachable (`B3-3`). Membership in the operator's set is what
    // decides an account or a QOS, and it is stricter than any charset.
    ), always_true),
    // FORCED, not Allowed. The account is who gets BILLED, so letting the agent name it
    // would let a caged job charge another project's allocation — and on sites whose
    // cli_filter requires an account (Santis), it is also mandatory for any job to run at
    // all. Same treatment as the partition: taken from the operator's trusted config, never
    // from the request.
    // `always_true` for the same reason as `--nodes`: a `Forced` option's value is dropped
    // before `validate` is reached. The account grammar IS live — on the OPERATOR's value,
    // as `is_valid_account`, from config.rs and session.rs. It was never live here.
    spec!("--account", "-A", true, Class::Forced, always_true),
    spec!("--reservation", "", true, Class::Rejected(
        "husk does not let a job claim a reservation: reserved nodes are set aside for \
         particular people and particular work, and a brokered job is neither. Submit \
         without --reservation."
    ), always_true),
    spec!("--comment", "", true, Class::Allowed, v_comment),
    spec!("--distribution", "-m", true, Class::Allowed, v_dist),
    spec!("--signal", "", true, Class::Allowed, v_signal),
    spec!("--switches", "", true, Class::Allowed, v_switches),
    // ---- Allowed flags (no value) ----
    spec!("--exclusive", "", false, Class::Allowed, always_true),
    spec!("--requeue", "", false, Class::Allowed, always_true),
    spec!("--no-requeue", "", false, Class::Allowed, always_true),
    spec!("--hold", "-H", false, Class::Allowed, always_true),
    spec!("--overcommit", "-O", false, Class::Allowed, always_true),
    spec!("--spread-job", "", false, Class::Allowed, always_true),
    spec!("--use-min-nodes", "", false, Class::Allowed, always_true),
    spec!("--contiguous", "", false, Class::Allowed, always_true),
    // ---- Ignored: recognised, accepted, dropped ----
    spec!("--parsable", "", false, Class::Ignored, always_true),
    // TWO reasons, and they answer different questions. **Why it cannot be HONOURED:**
    // `--wait` blocks until the job COMPLETES, and the broker is single-threaded, so one
    // `--wait` wedges it for the whole job runtime — `scancel` included, meaning the agent
    // could no longer stop the job that did it. That is the F2/F16 DoS shape. (Making the
    // broker concurrent does not fix this and costs more than it buys; the analysis, and the
    // design that WOULD retire this rejection — poll in the stub, not in the broker — are in
    // ROADMAP.md under Smaller items.)
    //
    // **Why it is REJECTED rather than Ignored.** `--wait` blocks until the job finishes
    // and returns its exit status, so silently dropping it makes `sbatch --wait && collect_results` proceed as
    // though a job that is still queued had already succeeded. That is the same failure as
    // the silently-dropped `--parsable` (LETKF, 2026-08-07) with a far worse consequence, and
    // it is a control-flow contract rather than a preference — the caller cannot compensate
    // for it, because from the outside a dropped `--wait` is indistinguishable from a job
    // that finished instantly. Refusing teaches; dropping misleads. (P13)
    spec!(
        "--wait",
        "-W",
        false,
        Class::Rejected(
            "husk cannot block until a job finishes: the broker answers each request and \
             returns, so --wait would exit immediately and your script would treat a queued \
             job as a completed one. Submit without it and poll with `squeue -j <id>` or \
             `sacct -j <id> -o State`."
        ),
        always_true
    ),
    spec!("--quiet", "-Q", false, Class::Ignored, always_true),
    spec!("--verbose", "-v", false, Class::Ignored, always_true),
    // IGNORED — dropped, never forwarded — and the reason is a SECURITY one, which is why
    // it is written here rather than left as taste.
    //
    // SLURM's job mail is sent by slurmctld, not by the job, so it leaves the cluster without
    // touching the job's network namespace, the egress proxy or the allowlist. It carries the
    // JOB NAME, and `--job-name` is Class::Allowed with a 64-character agent-controlled
    // value. `--mail-user=attacker@example.com --job-name=<payload>` would therefore be a
    // covert egress channel that every network control husk has is blind to.
    //
    // Dropping closes it. What was missing was this paragraph: the class said "recognised but
    // irrelevant/undesirable", so nothing recorded that it must STAY dropped — one helpful
    // refactor from being reopened, on exactly the reasoning that made `--parsable`
    // honourable the same day. (AV6/AV8 over a channel that is not the network.)
    //
    // NOT Rejected, deliberately. `#SBATCH --mail-user` is ubiquitous in real run scripts, and
    // refusing the whole job over a directive husk would simply drop is the false-reject cost
    // this project keeps paying (`.env`, `config/`). Dropping is already the safe behaviour;
    // the fix P13 asks for is to SAY SO, which the stub now does.
    spec!("--mail-type", "", true, Class::Ignored, always_true),
    spec!("--mail-user", "", true, Class::Ignored, always_true),
];

/// A tool's complete option registry. The parsing machinery below is parameterised by
/// one of these so that `sbatch` and `srun` share a SINGLE parser: two copies would be
/// two things to keep in sync, and a gate that drifts from its twin is the same failure
/// mode the allowlist redesign existed to remove. Only the option TABLE differs per tool.
pub type Registry = &'static [OptSpec];

/// Look up an option by its long or short spelling — EXACTLY, and by nothing else.
///
/// There was a third clause, `|| s.aliases.contains(&name)`, and it was unreachable: no
/// entry in either registry ever had an alias, so deleting the clause changed nothing
/// (`B3-3`). It read as the place husk models SLURM's spelling equivalences, and husk
/// models none — which is the right answer, stated here instead of implied by an empty
/// array:
///
/// **husk does not accept abbreviations.** SLURM's own `getopt_long` resolves any
/// unambiguous prefix (`--ntas` is `--ntasks`). Resolving them here would put a second,
/// husk-written prefix resolver in front of slurmd's, and a spelling the two resolve
/// differently is a parser differential on the one command line husk constructs — the
/// F13/F14 shape, arrived at from the other end. An unrecognised spelling is refused BY
/// NAME instead, so the caller is told what to write rather than guessed at (`P11`).
pub fn lookup_in(reg: Registry, name: &str) -> Option<&'static OptSpec> {
    reg.iter()
        .find(|s| s.long == name || (!s.short.is_empty() && s.short == name))
}

/// `lookup_in` against the sbatch registry.
pub fn lookup(name: &str) -> Option<&'static OptSpec> {
    lookup_in(REGISTRY, name)
}

fn takes_value_in(reg: Registry, tok: &str) -> bool {
    lookup_in(reg, tok).map(|s| s.takes_value).unwrap_or(false)
}

fn takes_value(tok: &str) -> bool {
    takes_value_in(REGISTRY, tok)
}

/// Option tokens that appear before the first positional (the script path).
pub fn option_tokens(argv: &[String]) -> Vec<String> {
    option_tokens_in(REGISTRY, argv)
}

/// `option_tokens` against an explicit registry.
pub fn option_tokens_in(reg: Registry, argv: &[String]) -> Vec<String> {
    split_options_and_rest_in(reg, argv).0
}

/// Split argv into (option region, everything after it). For sbatch the remainder is
/// the script path + its args; for srun it is the command to run. A `--` separator ends
/// the options and is not part of either half.
pub fn split_options_and_rest_in(reg: Registry, argv: &[String]) -> (Vec<String>, Vec<String>) {
    let mut out = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a == "--" {
            i += 1; // consume the separator itself
            break;
        }
        if a.starts_with("--") && a.contains('=') {
            out.push(argv[i].clone());
            i += 1;
        } else if a.starts_with('-') && a != "-" {
            out.push(argv[i].clone());
            if takes_value_in(reg, a) && i + 1 < argv.len() {
                out.push(argv[i + 1].clone());
                i += 2;
            } else {
                i += 1;
            }
        } else {
            break; // first positional
        }
    }
    (out, argv[i.min(argv.len())..].to_vec())
}

/// Split getopt-glued short options into (flag, value) token pairs BEFORE parsing, so
/// the broker's force-safe / detect logic can't be bypassed by gluing the value onto
/// the flag: `-o/path` -> `-o`, `/path`; `-ppancake` -> `-p`, `pancake`. Only
/// value-taking short options (per the REGISTRY) with a glued value are split;
/// everything else (bare flags, long options, `--`, already-separated forms) passes
/// through unchanged. Fixes F13 (glued `-o` defeating the forced `--output`) and F14
/// (glued `-p` slipping past the partition gate).
pub fn split_glued_short_opts(argv: &[String]) -> Vec<String> {
    split_glued_short_opts_in(REGISTRY, argv)
}

/// `split_glued_short_opts` against an explicit registry.
pub fn split_glued_short_opts_in(reg: Registry, argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    for tok in argv {
        if tok.len() > 2 {
            if let Some(short) = tok.get(..2) {
                let sb = short.as_bytes();
                if sb[0] == b'-' && sb[1] != b'-' && takes_value_in(reg, short) {
                    out.push(short.to_string());
                    out.push(tok[2..].to_string());
                    continue;
                }
            }
        }
        out.push(tok.clone());
    }
    out
}

/// Last value for any of `names` among `tokens`, handling `--name=val`,
/// `--name val`, and `-x val`.
pub fn option_value(tokens: &[String], names: &[&str]) -> Option<String> {
    let mut found = None;
    let mut i = 0;
    while i < tokens.len() {
        let t = tokens[i].as_str();
        for &n in names {
            if t == n {
                if i + 1 < tokens.len() {
                    found = Some(tokens[i + 1].clone());
                }
            } else if let Some(rest) = t.strip_prefix(format!("{n}=").as_str()) {
                found = Some(rest.to_string());
            }
        }
        i += 1;
    }
    found
}

/// Ceiling on the bytes `interpret_cli_in` may re-emit onto a real SLURM command line.
///
/// The same class as `rank::MAX_FORWARDED_ENV_BYTES`, one layer up, and the half nobody had
/// bounded. Every `Class::Allowed` option is re-emitted per OCCURRENCE and an option may
/// occur any number of times, so a request carrying `--comment=<256 bytes>` ten thousand
/// times builds a 2.5 MiB argv — and the spool reads the request with an uncapped
/// `read_to_end`, so nothing upstream stops it. The consequence is an `E2BIG` from the real
/// `sbatch` at exec time: a failure whose errno says nothing about the option list that
/// caused it (`P11`).
///
/// 256 KiB is about 1/8 of a 2 MiB `ARG_MAX` — leaving room for the rest of the command
/// line husk builds — and roughly 1000x a large real job: the biggest realistic directive
/// block measured here (`accepts_a_realistic_multi_option_job`) re-emits under 200 bytes,
/// and `a_realistic_job_is_orders_of_magnitude_below_the_argv_bound` pins that ratio so the
/// bound cannot quietly be tightened onto a job somebody meant to submit. Per-option length
/// is not this constant's business; the value grammars own that.
const MAX_REEMITTED_ARGV_BYTES: usize = 256 * 1024;

/// Interpret the agent's CLI option region (already glued-split + `option_tokens`'d)
/// as an ALLOWLIST and return the canonical resource options to append to the real
/// sbatch invocation — or a rejection message. `Forced`/`Ignored` options are dropped
/// (the broker forces its own / they're irrelevant); `Allowed` options are validated
/// and re-emitted as `--long=value` (flags as bare `--long`); anything unrecognised or
/// with an invalid value is rejected. The returned tokens are the ONLY agent-influenced
/// options that reach the real sbatch, and none of them is a raw agent token.
pub fn interpret_cli(cli: &[String]) -> Result<Vec<String>, String> {
    interpret_cli_in(REGISTRY, "sbatch", cli)
}

/// `interpret_cli` against an explicit registry. `tool` only names the command in the
/// rejection message, so an srun rejection does not talk about sbatch.
pub fn interpret_cli_in(reg: Registry, tool: &str, cli: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut emitted = 0usize;
    let mut i = 0;
    while i < cli.len() {
        let tok = &cli[i];
        if !tok.starts_with('-') || tok == "-" {
            return Err(format!("unexpected argument {tok:?} in the option list"));
        }
        let (name, inline_val) = match tok.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (tok.clone(), None),
        };
        let spec = match lookup_in(reg, &name) {
            Some(s) => s,
            None => {
                return Err(format!(
                    "unsupported {tool} option '{name}'. husk submits a restricted, explicit set \
                     of options; remove it (or ask your operator to add it to the allowlist)."
                ))
            }
        };
        // Determine the value, consuming a following token for the separated form.
        let value = if spec.takes_value {
            match inline_val {
                Some(v) => Some(v),
                None => {
                    if i + 1 < cli.len() {
                        i += 1;
                        Some(cli[i].clone())
                    } else {
                        None
                    }
                }
            }
        } else {
            if inline_val.is_some() {
                return Err(format!("option '{}' does not take a value", spec.long));
            }
            None
        };
        match spec.class {
            Class::Rejected(why) => {
                return Err(format!(
                    "{tool} option '{}' is not permitted here: {why}",
                    spec.long
                ))
            }
            Class::Forced | Class::Ignored => {} // dropped
            Class::Allowed => {
                let arg = if spec.takes_value {
                    let v = value
                        .ok_or_else(|| format!("option '{}' requires a value", spec.long))?;
                    if !(spec.validate)(&v) {
                        return Err(format!(
                            "value {v:?} for '{}' is not allowed (must match the option's safe grammar)",
                            spec.long
                        ));
                    }
                    format!("{}={}", spec.long, v)
                } else {
                    spec.long.to_string()
                };
                // +1 for the NUL the kernel counts with every argv element.
                emitted += arg.len() + 1;
                if emitted > MAX_REEMITTED_ARGV_BYTES {
                    return Err(format!(
                        "this {tool} option list is too long: the options husk accepted \
                         already exceed {MAX_REEMITTED_ARGV_BYTES} bytes, and '{}' is where \
                         it stopped. husk builds the real {tool} command line itself, and \
                         that command line has to fit in the kernel's ARG_MAX; refusing here \
                         names the option, whereas forwarding it would fail later as \
                         'Argument list too long' with nothing pointing back at this \
                         request. Submit fewer or shorter options.",
                        spec.long
                    ));
                }
                out.push(arg);
            }
        }
        i += 1;
    }
    Ok(out)
}

/// Reject dangerous `#SBATCH` directives in the body.
///
/// This used to say the body "is submitted verbatim (never rewritten), so `#SBATCH`
/// directives reach slurmd directly". **That has not been true since Fix 1**: husk submits
/// its own script on sbatch's stdin and the agent's body travels as a data file, so no
/// directive in it is ever parsed by slurmd. The check is still right, but not for the
/// reason it claimed — husk now READS these lines and re-emits what it allows onto the real
/// command line, so a directive husk mis-handles is husk emitting the wrong thing under its
/// own name, not a parser differential with the scheduler. Reasoning about a gate from a
/// stale model of where the bytes go is how F13/F14/F26 happened.
///
/// Detect-and-reject the dangerous ones: burst-buffer/DataWarp
/// lines (`#BB`/`#DW`), any `Forced` option other than `--partition`/`--uenv`/`--view`/
/// `--repo` (those have dedicated validation + messages in policy.rs), and any
/// UNRECOGNISED option (strict allowlist — a directive we don't model could be the next
/// escape). Benign `Allowed`/`Ignored` directives are accepted. Returns `Some(reason)`
/// to reject the submission.
pub fn body_reject_reason(body: &str) -> Option<String> {
    // Header only, column 0 — same rule and same reason as `sbatch_directives`: a `#BB` in
    // a heredoc is data for a generated script, not a burst-buffer request for this job,
    // and rejecting it stopped a legal submission (A3).
    for line in header_lines(body) {
        let t = line;
        if t.starts_with("#BB") || t.starts_with("#DW") {
            return Some(
                "burst-buffer / DataWarp directives (#BB / #DW) are not permitted in a brokered \
                 job. Remove them."
                    .to_string(),
            );
        }
    }
    let directives = match sbatch_directives(body) {
        Ok(d) => d,
        Err(reason) => return Some(reason),
    };
    let mut i = 0;
    while i < directives.len() {
        let tok = &directives[i];
        if !tok.starts_with('-') {
            i += 1;
            continue;
        }
        let name = tok.split_once('=').map(|(n, _)| n).unwrap_or(tok);
        // Options with dedicated handling in policy.rs: accept here (consume a
        // separated value so it isn't misread as the next option).
        // DOMINATED: the broker emits these unconditionally on the real CLI, and sbatch
        // precedence is `command line > environment > #SBATCH`, so a body directive can
        // never take effect on its own. Rejecting them outright would break essentially
        // every real HPC run script (ICON and friends all set `#SBATCH --output=...`).
        // NB this is only safe BECAUSE the emission is unconditional — `--export` became
        // dominated when the F24 fix stopped skipping it in the no-uenv branch. Anything
        // only CONDITIONALLY emitted must stay in the reject path below (that is why
        // --uenv/--view/--repo are `dedicated`, not here).
        //
        // For `--output`/`--error`/`--chdir` the directive is not merely ignored: policy.rs
        // READS it, confines it to the job working directory, and re-emits its own
        // canonical value — so a run script gets its logs where it wants them without any
        // agent bytes reaching slurmd's parser. `--export` remains ignored outright.
        let dominated = matches!(
            name,
            "--output" | "-o" | "--error" | "-e" | "--chdir" | "-D" | "--export"
        );
        // Options with dedicated validation + teaching messages in policy.rs. Membership is
        // decided by that ONE property — does policy.rs own this option's answer — and every
        // option that has one must be here, or the generic Forced arm below answers first and
        // the better message is unreachable.
        //
        // `--account` was missing and it cost a production session. policy.rs has both of its
        // branches already: with an operator account it emits its own on the CLI, which
        // DOMINATES a body directive (sbatch precedence is command line > #SBATCH); with none
        // it refuses the submission and names the install flag to fix it. Rejecting here
        // pre-empted both, contradicted husk's own published option contract — which documents
        // Forced as discarded-not-refused — and answered with a parenthetical that lists
        // output/error/chdir/export, none of which is `--account`.
        let dedicated = matches!(
            name,
            "--partition"
                | "-p"
                | "--uenv"
                | "--view"
                | "--repo"
                | "--nodes"
                | "-N"
                | "--account"
                | "-A"
        );
        if dominated || dedicated {
            if takes_value(name) && !tok.contains('=') {
                i += 1;
            }
        } else {
            match lookup(name) {
                None => {
                    return Some(format!(
                        "#SBATCH {name} is not on husk's allowed-option list. Moving it to the \
                         command line will not help — the same list applies there. Remove the \
                         directive, or ask your operator to add {name} to the broker's option \
                         registry (sbatch.rs) if the job genuinely needs it."
                    ))
                }
                Some(s) if s.class == Class::Forced => {
                    return Some(format!(
                        "#SBATCH {name} is set by husk itself, so the job cannot choose it. \
                         Remove the directive; husk announces the value it used in the job banner."
                    ))
                }
                // A REJECTED option carries its own reason, and the body is the channel
                // it most needs to be enforced on: the CLI path refuses it loudly while
                // the body path used to fall into the catch-all below and accept it. Same
                // shape as the `Ignored` gap one class over — a registry with four classes
                // and a gate that only distinguished two.
                Some(s) => {
                    if let Class::Rejected(why) = s.class {
                        return Some(format!("#SBATCH {name}: {why}"));
                    }
                    if s.takes_value && !tok.contains('=') {
                        i += 1;
                    }
                }
            }
        }
        i += 1;
    }
    None
}

/// The script HEADER: the leading run of blank and comment lines, i.e. everything before
/// the first command.
///
/// **A3.** husk used to scan the WHOLE body for `#SBATCH`, at any indentation. That is not
/// where directives live — sbatch stops looking at the first command — and it made husk
/// reject scripts that are perfectly legal: a run script whose heredoc GENERATES an inner
/// job script carries `#SBATCH` lines that are data, meant for a different submission
/// entirely, and husk read them as if they were its own. Same for `#BB` inside a heredoc.
/// A false reject on a real ICON-shaped workflow is a usability bug with the blast radius
/// of a security one: the scientist cannot submit and nothing explains why.
///
/// Narrowing is safe here, and this is the only reason it is safe: **the agent's body no
/// longer reaches slurmd at all** — husk submits its own script and runs the body as data
/// inside the cage. A directive husk does not read is therefore INERT, not smuggled. When
/// the body was forwarded verbatim, scanning less than slurmd's parser would have been an
/// escape; now it is just an option husk declines to honour, and the note below says so.
///
/// Blank lines do NOT end the header, because real run scripts space their directives out.
fn header_lines(body: &str) -> impl Iterator<Item = &str> {
    body.lines().take_while(|l| {
        let t = l.trim_start();
        t.is_empty() || t.starts_with('#')
    })
}

/// Is this line a directive husk reads? Column 0, like sbatch: an indented `#SBATCH` is not
/// a directive to sbatch either (it stops the scan outright there).
fn directive_body(line: &str) -> Option<&str> {
    line.strip_prefix("#SBATCH")
}

/// Split one `#SBATCH` line into option tokens, honouring quotes.
///
/// This used to be `split_whitespace()`, which is wrong in the ordinary case rather than the
/// exotic one: `#SBATCH --job-name="my run"` became the two tokens `--job-name="my` and
/// `run"`, and `#SBATCH --job-name="myrun"` kept its quotes inside the value. Both were
/// refused — the value grammar forbids `"` for every option, so they failed on the grammar,
/// not on the tokeniser. **The failure was closed, and it was still a bug**: quoting a
/// directive value is normal in real run scripts, and husk rejected the script.
///
/// It also made one deliberate design decision unreachable. `v_comment` is widened to permit a
/// space precisely so `--comment` can carry a sentence; a whitespace-splitting tokeniser meant
/// no value with a space could ever arrive. The grammar and the tokeniser disagreed about what
/// was expressible, and the tokeniser silently won (P7).
///
/// Rules, chosen to match what a job-script author expects rather than to re-implement a
/// shell: whitespace separates tokens outside quotes; `'` and `"` group and are removed; a
/// quote may open mid-token, so `--comment="a b"` is one token; the other quote character is
/// literal inside a quoted run. **An unterminated quote is an error, not a best guess** — the
/// author's intent is genuinely unknown at that point, and silently guessing is how a
/// directive comes to mean one thing to husk and another to its author.
///
/// Stripping quotes cannot widen what reaches slurmd. The value grammar still runs afterwards
/// and still forbids `" ' \ ; $ ` < >` for every `Allowed` option, and the result is re-emitted
/// into an ARGV element that never meets a shell. The only new capability is a space in the
/// one grammar that already permits spaces.
fn split_directive_line(rest: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut building = false;
    let mut quote: Option<char> = None;

    for c in rest.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => cur.push(c),
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                building = true; // `--x=""` is an empty value, not an absent one
            }
            // An unquoted `#` that STARTS a token begins a trailing comment, as it does in
            // the shell and in sbatch's own directive handling. Without this,
            // `#SBATCH --job-name=x # a note` tokenised to `["--job-name=x", "#", "a",
            // "note"]` and `interpret_cli` refused the submission on the stray `#` — another
            // false reject on an ordinary line, from the same missing-lexer root as the
            // quotes. Only at a token boundary: a `#` mid-token is left alone and judged by
            // the value grammar, which accepts it for no option, so guessing there buys
            // nothing.
            None if c == '#' && !building => break,
            None if c.is_whitespace() => {
                if building {
                    out.push(std::mem::take(&mut cur));
                    building = false;
                }
            }
            None => {
                cur.push(c);
                building = true;
            }
        }
    }
    if let Some(q) = quote {
        return Err(format!(
            "unterminated {} quote in a #SBATCH directive. Close the quote, or remove it if \
             the value has no spaces.",
            if q == '\'' { "single" } else { "double" }
        ));
    }
    if building {
        out.push(cur);
    }
    Ok(out)
}

/// Collect option tokens from `#SBATCH` directive lines in a script HEADER.
///
/// Fallible because a line can be unquotable — see `split_directive_line`. Returning the
/// tokens it *could* parse would hand the caller a directive list that silently means
/// something other than what the script says.
pub fn sbatch_directives(body: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for line in header_lines(body) {
        if let Some(rest) = directive_body(line) {
            out.extend(split_directive_line(rest)?);
        }
    }
    // Glue-split the SAME way the CLI does (N9/R1). Without this a body `#SBATCH -Axval` was
    // looked up whole, missed, and refused with "moving it to the command line will not help"
    // — which was false, because the CLI path splits `-Axval` into `-A xval` and resolves the
    // account. Splitting here makes the two channels agree on every glued short, so the
    // account/partition resolvers and the reject check all see `-A`/`-p`, not `-Axval`.
    Ok(split_glued_short_opts_in(REGISTRY, &out))
}

/// `#SBATCH`-looking lines husk did NOT read, as advice for a SUCCESSFUL submit.
///
/// Narrowing the scan trades a false reject for a silent ignore, and a silent ignore is the
/// failure mode this project keeps having to fix — so say it. But say it only where a human
/// plausibly MEANT the line for this job: indented in the header (sbatch ignores those too,
/// and it is an easy mistake), or below the header but before any heredoc. Lines after a
/// heredoc opener are the generated-inner-script case that motivated the fix, and warning
/// about them on every ICON submit would be exactly the crying wolf that gets a message
/// switched off.
/// The delimiter of a heredoc this line OPENS, or `None`. Not a full shell parser — a
/// single left-to-right pass that tracks quote state, so `<<` is an opener only when it is NOT
/// inside a string, and a `#` starts a comment only at a word boundary. When a real `<<` is
/// found, the delimiter may itself be quoted (`<<'EOF'` / `<<"EOF"`, the no-expansion form) or
/// bare (`<<EOF`, `<<-EOF`). A bare `<<` with no word (`a << b`, a bit-shift) opens nothing,
/// and `<<<` is a herestring, not a heredoc.
fn heredoc_opener(line: &str) -> Option<String> {
    let b = line.as_bytes();
    let mut i = 0;
    let (mut in_s, mut in_d) = (false, false);
    while i < b.len() {
        let c = b[i];
        if in_s {
            if c == b'\'' {
                in_s = false;
            }
            i += 1;
            continue;
        }
        if in_d {
            if c == b'"' {
                in_d = false;
            }
            i += 1;
            continue;
        }
        match c {
            b'\'' => in_s = true,
            b'"' => in_d = true,
            // `#` is a comment only at a word boundary (start of line or after whitespace).
            b'#' if i == 0 || b[i - 1] == b' ' || b[i - 1] == b'\t' => break,
            b'<' if i + 1 < b.len() && b[i + 1] == b'<' => {
                let mut j = i + 2;
                if j < b.len() && b[j] == b'<' {
                    i = j + 1; // `<<<` herestring — not a heredoc, keep scanning after it
                    continue;
                }
                if j < b.len() && b[j] == b'-' {
                    j += 1;
                }
                while j < b.len() && (b[j] == b' ' || b[j] == b'\t') {
                    j += 1;
                }
                // The delimiter itself may be quoted (no-expansion heredoc). Consume the
                // quote, read the word, and do not require the closing quote — the word is
                // what names the terminator.
                if j < b.len() && (b[j] == b'\'' || b[j] == b'"') {
                    j += 1;
                }
                let start = j;
                while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                    j += 1;
                }
                if j > start {
                    return Some(line[start..j].to_string());
                }
                // a bare `<<` with no delimiter word: not a heredoc opener
                i = j;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    None
}

pub fn unread_directive_note(body: &str) -> Option<String> {
    let header_count = header_lines(body).count();
    let mut missed: Vec<usize> = Vec::new();
    // Track heredocs PROPERLY so the note is silenced only for the generated-inner-script
    // case it exists for. `line.contains("<<")` was three bugs: it matched `<<` inside a
    // string or a comment, it matched a bit-shift with no delimiter, and it NEVER RESET, so
    // one `<<` anywhere below the header silenced every later `#SBATCH` line (A3). Now: find
    // a REAL opener on the quote/comment-stripped line, remember its delimiter, and reset when
    // that delimiter closes the heredoc — so a directive AFTER a heredoc is warned again.
    let mut heredoc_delim: Option<String> = None;
    for (i, line) in body.lines().enumerate() {
        // Inside a heredoc body: the only thing that matters is whether this line closes it.
        // The closing word may be indented only when the opener used `<<-`; husk accepts a
        // trimmed match either way, which errs toward LESS suppression (closing sooner => more
        // warnings), the safe direction for a defense-in-depth note.
        if let Some(delim) = &heredoc_delim {
            if line.trim() == delim.as_str() {
                heredoc_delim = None;
            }
            continue;
        }
        let t = line.trim_start();
        if t.starts_with("#SBATCH") {
            let read = i < header_count && directive_body(line).is_some();
            if !read {
                missed.push(i + 1);
            }
            continue;
        }
        // Not in a heredoc and not a directive: does THIS line open a heredoc?
        if i >= header_count {
            if let Some(delim) = heredoc_opener(line) {
                heredoc_delim = Some(delim);
            }
        }
    }
    if missed.is_empty() {
        return None;
    }
    let where_ = missed.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ");
    Some(format!(
        "husk read this job's #SBATCH directives from the script HEADER only — the lines \
         before the first command, starting at column 0. Line(s) {where_} look like \
         directives but are indented or sit below the first command, so they were NOT used \
         (real sbatch stops there too). If one was meant for this job, move it into the \
         header at column 0."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn split_glued_short_opts_splits_only_value_taking_shorts() {
        assert_eq!(
            split_glued_short_opts(&v(&["-o/tmp/x", "-ppreempt", "-N2", "job.sh"])),
            v(&["-o", "/tmp/x", "-p", "preempt", "-N", "2", "job.sh"])
        );
        // bare flag, separated form, long option, and `--` are left untouched
        assert_eq!(
            split_glued_short_opts(&v(&["-p", "debug", "--partition=x", "--", "-x"])),
            v(&["-p", "debug", "--partition=x", "--", "-x"])
        );
    }

    #[test]
    fn option_tokens_stops_at_first_positional() {
        let toks = option_tokens(&v(&["--partition", "preemptible", "job.sh", "42"]));
        assert_eq!(toks, v(&["--partition", "preemptible"]));
    }

    #[test]
    fn option_tokens_handles_equals_and_flags_and_double_dash() {
        // --name=val kept whole; bare flag kept; `--` ends options.
        let toks = option_tokens(&v(&["--export=NONE", "--hold", "--", "--nodes", "2"]));
        assert_eq!(toks, v(&["--export=NONE", "--hold"]));
    }

    #[test]
    fn option_tokens_consumes_value_for_value_opts() {
        let toks = option_tokens(&v(&["-N", "2", "-p", "preemptible", "script"]));
        assert_eq!(toks, v(&["-N", "2", "-p", "preemptible"]));
    }

    #[test]
    fn option_value_reads_all_three_forms_and_last_wins() {
        assert_eq!(
            option_value(&v(&["--partition=foo"]), &["-p", "--partition"]).as_deref(),
            Some("foo")
        );
        assert_eq!(
            option_value(&v(&["--partition", "bar"]), &["-p", "--partition"]).as_deref(),
            Some("bar")
        );
        assert_eq!(option_value(&v(&["-p", "baz"]), &["-p", "--partition"]).as_deref(), Some("baz"));
        // last occurrence wins
        assert_eq!(
            option_value(&v(&["-p", "a", "--partition=b"]), &["-p", "--partition"]).as_deref(),
            Some("b")
        );
        assert_eq!(option_value(&v(&["--nodes", "2"]), &["-p", "--partition"]), None);
    }

    /// The two tool lists must PARTITION the known tool set — every tool in exactly one.
    ///
    /// `--tools` is an allowlist and `permissions.deny` is a denylist, and husk ships both
    /// because they fail differently: the flag is invocation state and evaporates on
    /// `/compact` or a session re-entry (measured 2026-08-11), while the settings file is
    /// re-read per session and survives. So on the re-entry path the DENYLIST is the only
    /// control — and a denylist is a bug list (`P5`). A tool in neither list is allowed
    /// after a compact, silently.
    ///
    /// That makes this test the thing standing between us and the failure husk avoids
    /// everywhere else. It is the same pairing discipline as `LOGIN_AUTO_EXEC_DENY`.
    ///
    /// KNOWN_TOOLS is hand-maintained on purpose: it cannot be derived, because the
    /// enumeration behind it needs a LIVE session — `AskUserQuestion` and `Artifact` appear
    /// in no `-p` probe at all, and `Artifact` publishes to claude.ai, so the one that most
    /// needed denying was the one headless testing could not see. Refresh it from a live
    /// session, not from a script.
    #[test]
    fn the_tool_allowlist_and_denylist_partition_the_known_set() {
        const KNOWN_TOOLS: &[&str] = &[
            // selectable via --tools, enumerated 2026-08-10
            "Agent", "Bash", "Edit", "Glob", "Grep", "ListAgents", "Read", "ReportFindings",
            "ScheduleWakeup", "Skill", "ToolSearch", "Workflow", "Write", "CronCreate",
            "CronDelete", "CronList", "DesignSync", "EnterWorktree", "ExitWorktree", "LSP",
            "Monitor", "NotebookEdit", "PushNotification", "RemoteTrigger", "SendMessage",
            "TaskCreate", "TaskGet", "TaskList", "TaskOutput", "TaskStop", "TaskUpdate",
            "WebFetch", "WebSearch",
            // interactive-only: invisible to every headless probe, found 2026-08-13
            "AskUserQuestion", "Artifact", "EndConversation", "EnterPlanMode", "ExitPlanMode",
        ];
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
        let (Ok(installer), Ok(settings)) = (
            std::fs::read_to_string(format!("{root}/install-husk.sh")),
            std::fs::read_to_string(format!("{root}/user-config/settings.json")),
        ) else {
            return; // release tarballs ship the broker without the repo around it
        };
        let allow: Vec<&str> = installer
            .lines()
            .find(|l| l.starts_with("HUSK_TOOLS="))
            .expect("install-husk.sh must define HUSK_TOOLS")
            .split('"')
            .nth(1)
            .expect("HUSK_TOOLS must be quoted")
            .split(',')
            .collect();

        for t in KNOWN_TOOLS {
            let allowed = allow.contains(t);
            // Bare tool names only: `Read(//**/.ssh/**)` is a path rule, not a tool deny.
            let denied = settings
                .lines()
                .any(|l| l.trim().trim_end_matches(',').trim_matches('"') == *t);
            assert!(
                allowed != denied,
                "{t} is in {} — every known tool must be in exactly one of HUSK_TOOLS or \
                 permissions.deny, or a /compact decides it for us",
                if allowed { "BOTH lists" } else { "NEITHER list" }
            );
        }
    }

    /// The shipped skill must match the registry it is generated from — BYTE FOR BYTE.
    ///
    /// **This replaces an assertion on the wrong axis.** The old body checked that every
    /// registry name appears SOMEWHERE in `SKILL.md`. Measured (`C1-4`): moving
    /// `--use-min-nodes` from `Class::Allowed` to `Class::Ignored` — from *passed through
    /// after checking the value* to *silently dropped* — left the whole suite green with
    /// the shipped skill still telling the agent husk "PASSES THROUGH" it. The name was
    /// still there; only the SECTION moved, and the section IS the contract. That edit is
    /// the maintainer's plausible one — reclassifying an option is a one-token change
    /// somebody makes on purpose — which is why an invisible one is the dangerous kind.
    ///
    /// It was also `P15`'s corollary in the other direction: an assertion that iterates
    /// `REGISTRY` cannot notice `REGISTRY` shrinking, so DELETING an option removed the
    /// only check on it and left the skill advertising an option husk no longer accepts.
    ///
    /// Comparing the generated block against `option_contract_markdown()` closes both
    /// directions at once — membership, class, order, spelling and wording — because the
    /// block is not summarised, it is reproduced. It is what `skill/build.sh --check` does,
    /// run in-process, so it cannot be defeated by a stale debug binary; that is exactly
    /// how the manual check failed the first time.
    ///
    /// **Axes this still does not cover.** (1) The hand-written prose OUTSIDE the markers,
    /// including the sentence inside the generator that promises husk announces an ignored
    /// option on stderr — false for `--quiet`/`-Q` (`C1-5`). (2) `sbatch-stub.py`'s
    /// `UNAPPLIED`, the third statement of this contract, which is hand-kept and is not
    /// generated from anything. Both belong to fix batch `I`. (3) That the skill is the
    /// file the agent actually reads: this asserts about a path in the checkout, not about
    /// what `install-husk.sh` copied into `~/.claude/skills/`.
    #[test]
    fn the_shipped_skill_matches_the_generated_option_contract() {
        const BEGIN: &str =
            "<!-- BEGIN GENERATED: husk-slurm-broker --print-option-contract -->";
        const END: &str = "<!-- END GENERATED -->";

        let dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../skill"));
        let path = dir.join("SKILL.md");
        // READ from build.sh, not re-typed here (`P8`). This literal used to be a second
        // hand-maintained copy of the one in `skill/build.sh`, and the two drifted the first
        // time anybody corrected the path in either — the note named a directory
        // (`slurm-broker/skill/`) that does not exist, so an agent told to regenerate would
        // `cd` into nothing. Deriving it means build.sh is the single source and this test
        // checks that SKILL.md was generated by THIS build.sh.
        let build_sh = dir.join("build.sh");
        let note_src = std::fs::read_to_string(&build_sh)
            .unwrap_or_else(|e| panic!("{} is unreadable ({e})", build_sh.display()));
        let note: String = note_src
            .lines()
            .find_map(|l| l.strip_prefix("NOTE='")?.strip_suffix('\'').map(str::to_string))
            .unwrap_or_else(|| {
                panic!("no `NOTE='...'` line in {} — has it been renamed?", build_sh.display())
            });
        let note: &str = &note;

        let skill = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                // Only a checkout with no skill directory at all may skip — a release
                // tarball ships the broker alone. If the directory IS there and the file
                // is not, the path is wrong, and a bare `return` would read as a pass
                // (`P9`): the old body had exactly that hole.
                assert!(
                    !dir.exists(),
                    "{} exists but {} could not be read ({e}) — the test is looking in the \
                     wrong place, which is not the same as having nothing to check",
                    dir.display(),
                    path.display()
                );
                return;
            }
        };

        let after = skill
            .split_once(BEGIN)
            .unwrap_or_else(|| panic!("no BEGIN marker in {}", path.display()))
            .1;
        let block = after
            .split_once(END)
            .unwrap_or_else(|| panic!("no END marker in {}", path.display()))
            .0;
        // Exactly what skill/build.sh writes between the markers: the do-not-edit note,
        // a blank line, the contract, a blank line.
        let want = format!("\n{note}\n\n{}\n", option_contract_markdown());
        if block != want {
            let first_diff = block
                .lines()
                .zip(want.lines())
                .find(|(a, b)| a != b)
                .map(|(a, b)| format!("\n  SKILL.md: {a}\n  registry: {b}"))
                .unwrap_or_else(|| {
                    format!(
                        "\n  (no differing line; lengths differ: skill {} vs registry {})",
                        block.lines().count(),
                        want.lines().count()
                    )
                });
            panic!(
                "{} is STALE — the option registry says something the shipped skill does \
                 not. Regenerate it with skill/build.sh. First difference:{first_diff}",
                path.display()
            );
        }
    }

    #[test]
    fn interpret_cli_drops_forced_and_ignored_reemits_allowed_canonically() {
        // Forced (--export/--chdir/--nodes) and Ignored (--mail-user) are dropped;
        // Allowed options are re-emitted in canonical --long=value form regardless of
        // the spelling the agent used (glued -c4, separated -c 4, --time=..).
        let cli = option_tokens(&split_glued_short_opts(&v(&[
            "--partition=preemptible", "--export=NONE", "--chdir=/evil",
            "-N2", "-c", "4", "--time=01:00:00", "--mail-user=x@y.z", "--exclusive",
        ])));
        let out = interpret_cli(&cli).expect("should be accepted");
        // partition/export/chdir Forced → gone; mail Ignored → gone.
        assert!(!out.iter().any(|x| x.contains("NONE") || x.contains("/evil") || x.contains("mail") || x.contains("partition")));
        // --nodes is Forced too: the cage profile owns the topology, so the agent's
        // glued -N2 must not survive to the real command line (policy.rs rejects >1
        // node outright, and emits --nodes=1 itself).
        assert!(!out.iter().any(|x| x.contains("nodes")), "{out:?}");
        // resource options canonicalised:
        assert!(out.contains(&"--cpus-per-task=4".to_string()), "{out:?}");
        assert!(out.contains(&"--time=01:00:00".to_string()), "{out:?}");
        assert!(out.contains(&"--exclusive".to_string()), "flag re-emitted bare: {out:?}");
    }

    #[test]
    fn interpret_cli_rejects_unknown_options() {
        // An option not in the registry is rejected outright (default-deny), not
        // passed through — this is the class-closing behaviour.
        assert!(interpret_cli(&v(&["--frobnicate"])).is_err());
        assert!(interpret_cli(&v(&["--get-user-env"])).is_err()); // real sbatch opt, not allowlisted
        assert!(interpret_cli(&v(&["--prolog", "/tmp/eatme.sh"])).is_err());
    }

    #[test]
    fn accepts_topology_and_pinning_options_icon_uses() {
        // The ICON run script's actual directives (--hint=nomultithread + explicit
        // pinning). Accepted, validated, re-emitted canonically.
        let cli = option_tokens(&split_glued_short_opts(&v(&[
            "--hint=nomultithread", "--threads-per-core=1", "--cores-per-socket=64",
            "--gpu-bind=closest", "--oversubscribe",
        ])));
        let out = interpret_cli(&cli).expect("ICON topology options must be accepted");
        for want in ["--hint=nomultithread", "--threads-per-core=1", "--cores-per-socket=64",
                     "--gpu-bind=closest", "--oversubscribe"] {
            assert!(out.contains(&want.to_string()), "missing {want} in {out:?}");
        }
        // --hint is a closed set: anything else is rejected.
        assert!(interpret_cli(&v(&["--hint", "nomultithred"])).is_err(), "typo must not pass");
        assert!(interpret_cli(&v(&["--hint", "$(id)"])).is_err());
        // #SBATCH forms of the same options are fine in the body.
        assert!(body_reject_reason("#SBATCH --hint=nomultithread\n#SBATCH --threads-per-core=1\n").is_none());
    }

    #[test]
    fn wait_is_refused_because_silently_dropping_it_misleads_the_caller() {
        // This test used to assert the opposite — that `--wait` is swallowed and "must not be
        // a hard error". That was right about the mechanism and wrong about the contract.
        //
        // `sbatch --wait` blocks until the job COMPLETES and returns its exit status, so it
        // must not be forwarded (it would wedge the broker for the whole runtime). But
        // dropping it SILENTLY means `sbatch --wait && collect_results` runs the collection
        // immediately, against a job that is still queued — and from the caller's side a
        // dropped `--wait` is indistinguishable from a job that finished instantly, so it
        // cannot compensate.
        //
        // The same class cost a run the day this changed: `--parsable` was also Ignored, so a
        // driver's `jobid=$(sbatch --parsable ...)` captured "Submitted batch job N" and its
        // wait loop exited at once. `--parsable` is honoured now (it is an output format, and
        // husk has the id either way); `--wait` cannot be honoured, so it is refused with the
        // reason. Refusing teaches, dropping misleads (P13), and the registry's own doc for
        // `Rejected` already says so: dropping an option the user meant changes what their job
        // does without telling them.
        let e = interpret_cli(&v(&["--wait"])).expect_err("--wait must be refused, not dropped");
        assert!(e.contains("--wait"), "the refusal must name it: {e}");
        assert!(
            e.contains("squeue") || e.contains("sacct"),
            "and must say what to do instead, or it is a wall: {e}"
        );
        // The short form is the same option and must not slip through.
        assert!(interpret_cli(&v(&["-W"])).is_err(), "-W is --wait");
    }

    #[test]
    fn interpret_cli_rejects_out_of_grammar_values() {
        // A value carrying shell metacharacters / spaces / wrong shape is rejected.
        assert!(interpret_cli(&v(&["--time", "; rm -rf /"])).is_err());
        assert!(interpret_cli(&v(&["--cpus-per-task", "2;evil"])).is_err());
        // NB --nodes is Forced, so a hostile value is DROPPED here rather than rejected;
        // it never reaches sbatch either way, and policy.rs rejects anything but one node
        // before this runs (see policy::tests::rejects_multi_node_and_hostile_node_values).
        assert!(interpret_cli(&v(&["--job-name", "a b`whoami`"])).is_err());
        assert!(interpret_cli(&v(&["--mem", "4G"])).is_ok());
        assert!(interpret_cli(&v(&["--gpus", "a100:2"])).is_ok());
    }

    #[test]
    fn r1_a_glued_short_in_the_body_agrees_with_the_cli() {
        // N9/R1: `#SBATCH -Axval` must be treated the way the CLI treats `-Axval` — as
        // `-A xval` (an account, dedicated handling), not as an unknown option refused with a
        // "moving it to the command line will not help" message that was false.
        assert_eq!(
            sbatch_directives("#!/bin/bash
#SBATCH -Axval
"),
            Ok(v(&["-A", "xval"])),
            "a glued short in the body must split like the CLI"
        );
        // So the account is a DEDICATED option here, not the unknown-option reject path.
        let reason = body_reject_reason("#!/bin/bash
#SBATCH -Axval
srun a
");
        assert!(
            reason.is_none(),
            "a glued -A in the body must not hit the unknown-option message: {reason:?}"
        );
        // The CLI already did this; the body now matches it (no channel divergence).
        assert_eq!(
            split_glued_short_opts_in(REGISTRY, &v(&["-Axval"])),
            v(&["-A", "xval"]),
        );
    }

    #[test]
    fn body_reject_reason_flags_forced_and_unknown_and_burst_buffer() {
        // DOMINATED options are accepted in the body — the forced CLI value outranks them,
        // and real run scripts (ICON) legitimately carry `#SBATCH --output=...`. That the
        // force actually wins is asserted in policy.rs (forced_cli_dominates_body_*).
        assert!(body_reject_reason("#SBATCH --output=/evil\necho hi\n").is_none());
        assert!(body_reject_reason("#SBATCH --export=ALL,_HUSK_RESANDBOXED=1\n").is_none());
        assert!(body_reject_reason("#SBATCH -o /evil\n#SBATCH -D /evil\n").is_none());
        // --wrap is forced but NOT dominated (it is not a real #SBATCH directive) → reject.
        assert!(body_reject_reason("#SBATCH --wrap=curl evil\n").is_some());
        // Unknown directive → reject (strict allowlist).
        assert!(body_reject_reason("#SBATCH --prolog=/tmp/x\n").is_some());
        // Burst-buffer / DataWarp → reject.
        assert!(body_reject_reason("#!/bin/bash\n#BB stage_in\n").is_some());
        assert!(body_reject_reason("#DW jobdw type=scratch\n").is_some());
        // Benign resource directives (incl. separated value) → accepted.
        assert!(body_reject_reason("#SBATCH --nodes=2\n#SBATCH -c 4\nsrun hostname\n").is_none());
        // --partition / --uenv are dedicated (handled in policy.rs) → not rejected here.
        assert!(body_reject_reason("#SBATCH --partition=preemptible\n#SBATCH --uenv=x\n").is_none());
    }

    /// A `#SBATCH` directive for an option policy.rs owns must reach policy.rs.
    ///
    /// `--account` did not: the directive scan answered first with the generic Forced
    /// refusal, so the operator never saw "re-run install-husk.sh --slurm-account", and a
    /// job that named an account was refused outright while husk's published contract says
    /// a Forced option is discarded rather than rejected. Three statements of one option's
    /// disposition, and the two the user meets disagreed.
    ///
    /// Pinned at the level of the property, not the instance: EVERY option policy.rs has a
    /// dedicated message for must pass the directive scan, so adding another dedicated
    /// message cannot silently reintroduce this.
    ///
    /// The false friend, which this test hit on its first run: asserting against
    /// `sbatch_directives` instead of `body_reject_reason` passes no matter what the gate
    /// does, because that function only LEXES. The unknown-option control below is what
    /// exposed it — a test whose negative case cannot fail is testing nothing.
    #[test]
    fn directives_defer_every_option_policy_owns() {
        for name in ["--account", "-A", "--partition", "-p", "--nodes", "-N", "--uenv"] {
            let body = format!("#!/bin/bash\n#SBATCH {name}=x\necho hi\n");
            assert_eq!(
                body_reject_reason(&body),
                None,
                "#SBATCH {name} must reach policy.rs, not be refused by the directive scan"
            );
        }
        // The false friend this replaces: an unknown option must STILL be refused here, so
        // the test cannot pass by the scan simply accepting everything.
        let body = "#!/bin/bash\n#SBATCH --gres-flags=enforce-binding\necho hi\n";
        assert!(
            body_reject_reason(body).is_some(),
            "an option in no class must still be refused by the directive scan"
        );
    }

    #[test]
    fn value_grammars_reject_whitespace_and_metacharacters() {
        for bad in ["a b", "a;b", "a|b", "a$b", "a`b", "a\nb", "a&b"] {
            assert!(!v_name(bad), "{bad:?} must be rejected by v_name");
        }
        assert!(v_size("4G") && v_time("01:00:00") && v_uint("16") && v_gres("gpu:a100:4"));
        assert!(v_expr("gpu&highmem")); // constraint expressions legitimately use &,|,()
    }

    // ── registry invariants: guard the security properties against FUTURE edits ──
    // These loop the whole REGISTRY, so a newly-added option, a reclassified family,
    // or a too-loose validator is caught automatically — the point of the allowlist.

    #[test]
    fn no_allowed_value_grammar_accepts_injection_chars() {
        // Characters no option value may ever contain (shell / scheduler / file
        // injection). `&|()!*` (constraint) and space (comment) are legitimately used by
        // specific grammars, so they're excluded; THESE stay forbidden for every grammar.
        let forbidden = ['\n', '\r', '\t', ';', '`', '$', '\'', '"', '\\', '<', '>', '\0'];
        for s in REGISTRY.iter().filter(|s| s.class == Class::Allowed && s.takes_value) {
            for c in forbidden {
                assert!(
                    !(s.validate)(&format!("x{c}y")),
                    "value grammar for {} accepts forbidden char {c:?}",
                    s.long
                );
            }
            assert!(
                !(s.validate)("$(rm -rf ~)"),
                "{} accepts a command-substitution payload",
                s.long
            );
        }
    }

    #[test]
    fn interpret_cli_never_reemits_a_forced_option() {
        // However the agent spells a Forced option, it is dropped (the broker forces its
        // own). Reclassifying e.g. --output to Allowed would break this test loudly.
        for s in REGISTRY.iter().filter(|s| s.class == Class::Forced) {
            let eq = interpret_cli(&[format!("{}=x", s.long)]).expect("forced =form parses");
            assert!(eq.is_empty(), "{} (=form) was re-emitted: {eq:?}", s.long);
            if s.takes_value {
                let sep = interpret_cli(&[s.long.to_string(), "x".to_string()])
                    .expect("forced separated form parses");
                assert!(sep.is_empty(), "{} (separated) was re-emitted: {sep:?}", s.long);
            }
        }
    }

    #[test]
    fn registry_is_well_formed() {
        use std::collections::HashSet;
        let (mut longs, mut shorts) = (HashSet::new(), HashSet::new());
        for s in REGISTRY {
            assert!(s.long.starts_with("--"), "long {:?} must start with --", s.long);
            assert!(longs.insert(s.long), "duplicate long {:?}", s.long);
            if !s.short.is_empty() {
                assert!(
                    s.short.len() == 2 && s.short.starts_with('-') && !s.short.starts_with("--"),
                    "short {:?} malformed",
                    s.short
                );
                assert!(shorts.insert(s.short), "duplicate short {:?}", s.short);
            }
        }
        // The dangerous families must exist and be Forced (never silently reclassified).
        for name in [
            "--output", "--error", "--chdir", "--export", "--partition", "--uenv", "--view",
            "--repo", "--wrap",
        ] {
            let s = lookup(name).unwrap_or_else(|| panic!("{name} missing from registry"));
            assert_eq!(s.class, Class::Forced, "{name} must be Forced");
        }
    }

    /// A spelling husk does not know is refused BY NAME, and never resolved by prefix.
    ///
    /// This is what `OptSpec::aliases` implied and did not do. The field was `&[]` in all
    /// 97 entries and `lookup_in`'s `s.aliases.contains(&name)` clause was unreachable
    /// (`B3-3`, mutation-verified: deleting it left the suite green), so a reviewer asking
    /// "does husk model every spelling of an option?" got a yes from a mechanism that had
    /// never run. Deleting it leaves a real property behind, and this is it.
    ///
    /// **The mutation this is aimed at is the maintainer's plausible one**, not an
    /// artificial one: the natural way to "be helpful about spellings" is a prefix match in
    /// `lookup_in` (`s.long.starts_with(name)`), which is what SLURM's own `getopt_long`
    /// does. That would put a second prefix resolver in front of slurmd's, and any
    /// abbreviation the two resolve differently is a parser differential on the command
    /// line husk constructs. Adding the clause turns this test red on `--ntas`.
    ///
    /// **Axis it does not cover:** it says nothing about which spellings husk SHOULD know.
    /// A registry missing an option a real script uses still fails here as "unsupported",
    /// correctly and unhelpfully; that is `B3-1`'s stub gap, not this.
    #[test]
    fn an_abbreviated_or_unknown_spelling_is_refused_by_name_not_resolved() {
        for (reg, tool) in [(REGISTRY, "sbatch"), (crate::srun::REGISTRY, "srun")] {
            for abbrev in ["--ntas", "--cpus-per", "--n", "--tim", "--exclu"] {
                assert!(
                    lookup_in(reg, abbrev).is_none(),
                    "{tool}: {abbrev} resolved to an option — husk must not accept \
                     abbreviations, because slurmd\'s getopt_long resolves them too and a \
                     disagreement is a parser differential"
                );
                let err = interpret_cli_in(reg, tool, &v(&[abbrev]))
                    .expect_err("an abbreviation must be refused");
                assert!(
                    err.contains(&format!("unsupported {tool} option")) && err.contains(abbrev),
                    "the refusal must name the spelling that was refused: {err}"
                );
            }
        }
        // Exact long and short spellings still resolve, so this is not just "everything
        // fails": the test would pass on a broken lookup without these.
        assert!(lookup("--ntasks").is_some() && lookup("-n").is_some());
        assert!(lookup_in(crate::srun::REGISTRY, "--cpu-bind").is_some());
    }

    /// A value grammar sits only where `interpret_cli_in` can run it.
    ///
    /// Both directions, because the two failures are different and both happened.
    /// **Downward:** four entries carried a grammar the parser could never reach —
    /// `--nodes`/`v_nodes` and `--account`/`v_name` are `Forced` (value dropped before
    /// `validate`), `--qos` and `--reservation` are `Rejected` (the function returns
    /// first). Replacing `v_nodes` with `|_| false` left the suite green (`B3-3`). A
    /// grammar parked on such an entry reads as a live check, and `is_valid_account` sold
    /// exactly that parity in a doc comment on a `pub fn`.
    /// **Upward:** an `Allowed` value option whose grammar is `always_true` forwards an
    /// unchecked agent value onto a real SLURM command line.
    ///
    /// The mutation for each direction is the plausible edit, not a synthetic one: putting
    /// a grammar back on `--account` "so it is validated too" (red downward), or adding a
    /// new `Allowed` option with `always_true` because it looked harmless (red upward).
    ///
    /// **Axis it does not cover:** it compares function POINTERS, so a grammar that is not
    /// `always_true` but is equally permissive passes here. `no_allowed_value_grammar_
    /// accepts_injection_chars` is the check on what a grammar refuses; this one is about
    /// whether anything runs at all. Identical-body function merging could in principle
    /// make a different trivial validator compare equal to `always_true` — that direction
    /// is a false pass, never a false failure.
    #[test]
    fn only_a_class_allowed_value_option_carries_a_value_grammar() {
        let neutral = always_true as fn(&str) -> bool as usize;
        for (reg, tool) in [(REGISTRY, "sbatch"), (crate::srun::REGISTRY, "srun")] {
            for s in reg {
                let reachable = s.class == Class::Allowed && s.takes_value;
                if reachable {
                    assert_ne!(
                        s.validate as usize, neutral,
                        "{tool} {}: Class::Allowed + takes_value means the agent\'s value is \
                         re-emitted onto the real command line, so it needs a grammar, not \
                         always_true",
                        s.long
                    );
                } else {
                    assert_eq!(
                        s.validate as usize, neutral,
                        "{tool} {}: interpret_cli_in consults `validate` in the \
                         Class::Allowed arm only, so a grammar here can never run. It reads \
                         as enforcement and is not (B3-3). Use always_true, and name what \
                         actually enforces the value in a comment.",
                        s.long
                    );
                }
            }
        }
    }

    /// The option list husk re-emits is bounded in BYTES, and the refusal names the option.
    ///
    /// `Class::Allowed` options are re-emitted per occurrence and may occur any number of
    /// times, and the spool reads the request with an uncapped `read_to_end`, so nothing
    /// stopped an agent-written request from building a multi-megabyte command line for the
    /// real `sbatch`. It would have failed at `execvp` with `E2BIG` — "Argument list too
    /// long" — an errno with nothing in it that points back at the request (`P11`).
    ///
    /// **Axis it does not cover:** the bytes husk itself adds (the forced options, the
    /// wrapper, the script path) are not counted here, so this bounds the agent-influenced
    /// share of the command line, not the whole of it. That is the right half to bound —
    /// husk\'s own share is fixed and small — but it is not the same statement.
    #[test]
    fn the_reemitted_option_list_is_bounded_in_bytes() {
        let one = "--comment=".len() + 250 + 1;
        let many: Vec<String> = (0..(MAX_REEMITTED_ARGV_BYTES / one + 8))
            .map(|_| format!("--comment={}", "c".repeat(250)))
            .collect();
        let err = interpret_cli(&many).expect_err(
            "an option list larger than husk can put on a command line must be refused, \
             not handed to execvp",
        );
        assert!(err.contains("too long"), "{err}");
        assert!(err.contains("--comment"), "the refusal must name where it stopped: {err}");
        assert!(err.contains("ARG_MAX"), "the refusal must say whose limit it is: {err}");
        // Identical on retry (P11): the same request gets the same sentence.
        assert_eq!(err, interpret_cli(&many).unwrap_err());
    }

    /// ...and the bound is nowhere near a job somebody meant to submit.
    ///
    /// The bound above is a REFUSAL on the submission surface, which is the shape this
    /// project has twice shipped as a denial of service aimed at the operator. This pins
    /// the margin, so tightening the constant onto real jobs is a red test rather than a
    /// judgement call: the largest realistic option list in this file must stay at least
    /// 100x below the ceiling.
    ///
    /// **Axis it does not cover:** "realistic" here is the ICON-shaped line the suite
    /// already models. A site whose run scripts are much larger would not be represented,
    /// and the honest answer is that the margin, not this sample, is the argument.
    #[test]
    fn a_realistic_job_is_orders_of_magnitude_below_the_argv_bound() {
        let cli = option_tokens(&split_glued_short_opts(&v(&[
            "--partition=preemptible", "--ntasks-per-node=4", "-c", "8",
            "--time=24:00:00", "--mem=0", "--gpus=4", "-C", "gpu", "-A", "myproj",
            "-J", "train-run_1", "--exclusive", "--hint=nomultithread",
            "--distribution=plane=4", "--gpu-bind=closest", "--comment=nightly ICON run",
        ])));
        let out = interpret_cli(&cli).expect("a normal job must be accepted");
        let bytes: usize = out.iter().map(|o| o.len() + 1).sum();
        assert!(
            bytes * 100 < MAX_REEMITTED_ARGV_BYTES,
            "a realistic job re-emits {bytes} bytes against a {MAX_REEMITTED_ARGV_BYTES}-byte \
             ceiling — under 100x of margin means the bound is close enough to real work to \
             become a false reject"
        );
    }

    /// **`J-1`.** Every value whose length is a COUNT the real work chooses is bounded by
    /// `MAX_LIST_VALUE_BYTES` and by nothing else — so an ensemble cannot be refused for
    /// being an ensemble.
    ///
    /// This is at the bug's level: the defect was not "128 is too small", it was that four
    /// options asking one question each carried a separately guessed answer, so fixing one
    /// (`J` fixed `--cpu-bind`) left three. The first half of this test therefore asserts
    /// the DERIVATION — all four grammars accept a value at the shared ceiling and refuse
    /// one byte past it, which can only hold while they share the constant — and the second
    /// half asserts the WORKLOAD, at the sizes measured as refused at `a441428`.
    ///
    /// **The false friend it replaces nothing of, and that is the finding.** There was no
    /// test for `v_dep`, `v_array` or `v_nodelist` at all. `only_a_class_allowed_value_option_carries_a_value_grammar`
    /// passes for every bound in the table because it only asks whether a grammar EXISTS,
    /// and `accepts_a_realistic_multi_option_job` passes because its sample job carries no
    /// list-shaped value. A whole class was unpinned and the suite was uniformly green —
    /// `P9` in the "the test proves the disposition it was written for" form.
    ///
    /// **Mutations that turn it red.** Restoring any one of the four literals
    /// (`v_dep` -> 128, `v_array` -> 64, `v_nodelist` -> 256, `v_bind` -> 64) fails both
    /// halves for that option and leaves the other three green — which is precisely the
    /// per-option independence that let `J` fix one and miss three, now visible.
    /// Changing `MAX_LIST_VALUE_BYTES` itself fails all four at once.
    ///
    /// **Axes it does not cover.** (1) It says nothing about whether SLURM accepts the
    /// value — an 800-node `--exclude` is husk-legal and slurmctld's to reject, with a
    /// better message than husk would write. (2) The ensemble sizes are the shapes that
    /// were MEASURED as refused, not a survey of what sites run; the margin (~930 job ids)
    /// is the argument, not the sample. (3) It does not cover the fixed-shape grammars'
    /// margins, which are recorded as numbers in the table above `v_uint` and are checked
    /// by `a_fixed_shape_grammar_did_not_get_swept_along_with_the_list_shaped_ones`.
    #[test]
    fn a_value_whose_length_is_a_job_count_is_bounded_by_the_kernel_not_by_a_guess() {
        // (1) THE DERIVATION. One ceiling, four options, no per-option literal left.
        let at_bound: &[(&str, char)] = &[
            ("--dependency", '1'),
            ("--array", '1'),
            ("--exclude", 'n'),
            ("--nodelist", 'n'),
            ("--gpu-bind", 'a'),
            ("--mem-bind", 'a'),
        ];
        for (opt, fill) in at_bound {
            let ok = format!("{opt}={}", fill.to_string().repeat(MAX_LIST_VALUE_BYTES));
            assert!(
                interpret_cli(&[ok]).is_ok(),
                "{opt} must accept a value of exactly MAX_LIST_VALUE_BYTES — it is a \
                 list-shaped value and this is the one ceiling they share"
            );
            let too_long = format!("{opt}={}", fill.to_string().repeat(MAX_LIST_VALUE_BYTES + 1));
            assert!(
                interpret_cli(&[too_long]).is_err(),
                "{opt} must still have a ceiling; widening is not removing"
            );
        }

        // (2) THE WORKLOAD, at the sizes measured as REFUSED at `a441428`.
        //
        // An ensemble chained on its predecessors. 16 was the first refused size.
        for members in [16usize, 40, 100] {
            let ids: Vec<String> =
                (0..members).map(|i| (4_900_000 + i).to_string()).collect();
            let dep = format!("--dependency=afterok:{}", ids.join(":"));
            assert!(
                interpret_cli(&[dep]).is_ok(),
                "an afterok: chain over {members} jobs is an ordinary ensemble, not a \
                 syntax error"
            );
        }
        // Re-running the members of an ensemble that failed. 22 two-digit indices was the
        // first refused size.
        let failed: Vec<String> = (1..=60).map(|i| (i * 3).to_string()).collect();
        assert!(
            interpret_cli(&[format!("--array={}", failed.join(","))]).is_ok(),
            "an explicit list of the 60 array indices to re-run must be accepted"
        );
        // Steering around a site's drained nodes. 26 names was the first refused size.
        let drained: Vec<String> = (1..=64).map(|i| format!("nid{i:06}")).collect();
        assert!(
            interpret_cli(&[format!("--exclude={}", drained.join(","))]).is_ok(),
            "excluding 64 drained nodes must be accepted"
        );

        // (3) THE CHARSET IS UNTOUCHED. Length was the guess; the charset is the control,
        // and widening one must not have relaxed the other (`P4`: the emission form is
        // what makes the value safe, and that argument only holds for these bytes).
        for hostile in [
            "--dependency=afterok:$(id)",
            "--dependency=afterok:1;rm -rf /",
            "--array=1,2 3",
            "--exclude=nid001|evil",
            "--nodelist=`hostname`",
        ] {
            let e = interpret_cli(&[hostile.to_string()])
                .expect_err("a wider bound must not admit a new character");
            assert!(e.contains("safe grammar"), "{hostile} -> {e}");
        }
    }

    /// The other direction: the sweep must not have widened the grammars it was not about.
    ///
    /// `J-1`'s class is "the length is a count somebody's job chooses". A value with a
    /// FIXED shape — a time, a size, a keyword — has no such count, so its bound is a real
    /// sanity bound and must stay tight. Without this, "derive it from the kernel" reads as
    /// licence to put every grammar at 8 KiB, which would turn a swept class into a removed
    /// control.
    ///
    /// **Axis it does not cover:** it pins that these bounds are *small*, not that each
    /// specific number is right. The margins against real values are recorded as a table in
    /// the source above `v_uint`, and RJMK's independent measurement of `v_name` (64
    /// accepted, 65 refused, SLURM's own comparable) is the only one checked on hardware.
    #[test]
    fn a_fixed_shape_grammar_did_not_get_swept_along_with_the_list_shaped_ones() {
        for (opt, fill) in [
            ("--time", '1'),
            ("--begin", '1'),
            ("--mem", '1'),
            ("--job-name", 'a'),
            ("--comment", 'a'),
            ("--constraint", 'a'),
            ("--signal", 'a'),
            ("--switches", '1'),
            ("--distribution", 'a'),
            ("--gres", 'a'),
            ("--ntasks", '1'),
        ] {
            let long = format!("{opt}={}", fill.to_string().repeat(1024));
            assert!(
                interpret_cli(&[long]).is_err(),
                "{opt} takes a fixed-shape value; 1 KiB of it is not a job somebody meant \
                 to submit, and this grammar must not have inherited the list-shaped ceiling"
            );
        }
        // ...and the values a real job does carry still pass.
        for real in [
            "--time=7-00:00:00", "--begin=2026-09-01T12:00:00", "--mem=490000M",
            "--job-name=icon-ch1-eps-member-042-restart", "--constraint=gpu",
            "--signal=B:USR1@120", "--switches=2@00:30:00", "--distribution=plane=4",
            "--gres=gpu:4", "--ntasks=999999999",
        ] {
            assert!(
                interpret_cli(&[real.to_string()]).is_ok(),
                "{real} is what a real submission carries"
            );
        }
    }

    #[test]
    fn accepts_a_realistic_multi_option_job() {
        // The other direction: a normal resource request must NOT be over-rejected, and
        // is canonicalised regardless of spelling (separated -c 8, =-forms). -N is
        // absent because it is Forced — the cage profile emits it.
        let cli = option_tokens(&split_glued_short_opts(&v(&[
            "--partition=preemptible", "--ntasks-per-node=4", "-c", "8",
            "--time=24:00:00", "--mem=0", "--gpus=4", "-C", "gpu", "-A", "myproj",
            "-J", "train-run_1", "--exclusive",
        ])));
        let out = interpret_cli(&cli).expect("a normal job must be accepted");
        for want in [
            "--ntasks-per-node=4", "--cpus-per-task=8", "--time=24:00:00",
            "--mem=0", "--gpus=4", "--constraint=gpu",
            "--job-name=train-run_1", "--exclusive",
        ] {
            assert!(out.contains(&want.to_string()), "missing {want} in {out:?}");
        }
        // ...but NOT the account. It became Forced when Santis turned out to require one:
        // the account decides which project is BILLED, so an agent-chosen value could
        // charge someone else's allocation. policy.rs emits the operator's value instead.
        assert!(
            !out.iter().any(|o| o.contains("myproj")),
            "the agent's --account must be dropped, not re-emitted: {out:?}"
        );
    }

    #[test]
    fn directives_are_collected_from_the_header_only() {
        // **A3.** This test used to assert the BUG: it required `-t 10` — written AFTER
        // `echo hi` — to be collected. Scanning the whole file is not what sbatch does and
        // is not what a script means; it is what made husk reject legal run scripts.
        let body = "#!/bin/bash\n#SBATCH --partition=preemptible --nodes=2\necho hi\n#SBATCH -t 10\n";
        assert_eq!(sbatch_directives(body), Ok(v(&["--partition=preemptible", "--nodes=2"])));

        // Blank and comment lines do NOT end the header — real run scripts space their
        // directives out and comment them, and stopping at the first blank line would
        // silently drop half of a legitimate header.
        let spaced = "#!/bin/bash\n#SBATCH -p x\n\n# why we need two nodes\n#SBATCH -N 2\n\nsrun hostname\n";
        assert_eq!(sbatch_directives(spaced), Ok(v(&["-p", "x", "-N", "2"])));

        // Column 0, like sbatch: an indented `#SBATCH` is not a directive there either.
        assert_eq!(sbatch_directives("#!/bin/bash\n  #SBATCH -p x\n"), Ok(vec![]));
    }

    #[test]
    fn a3_the_heredoc_latch_no_longer_swallows_a_later_directive() {
        // A3's controlled table: line 5 varies, the probe is a col-0 `#SBATCH --qos=debug`
        // on line 6 that sits BELOW the first command, so it is correctly NOT READ. The
        // question is only whether it is WARNED. Every `<<` variant used to silence it (the
        // latch); now only a REAL, still-open heredoc does.
        let head = "#!/bin/bash
#SBATCH -p x
srun a
";
        let probe = "#SBATCH --qos=debug
";
        let warned = |line5: &str| {
            let body = format!("{head}{line5}
{probe}");
            unread_directive_note(&body).is_some()
        };
        // control: an ordinary command on line 5 -> the later directive IS warned about.
        assert!(warned("echo hi"), "control: a misplaced directive must be warned");
        // `<<` inside strings / comments / a bare shift must NOT silence it any more.
        assert!(warned("echo \"use <<EOF here\""), "<< in double quotes must not latch");
        assert!(warned("# see <<HDOC in docs"), "<< in a comment must not latch");
        assert!(warned("echo 'x <<HDOC y'"), "<< in single quotes must not latch");
        assert!(warned("echo \"a << b\""), "a bare << bit-shift (no word) must not latch");

        // A REAL heredoc still suppresses directives INSIDE its body (the case the note exists
        // to avoid crying wolf over), and RESUMES warning after the delimiter closes it.
        let inside = format!("{head}cat <<EOF
{probe}EOF
srun b
");
        assert!(
            unread_directive_note(&inside).is_none(),
            "a #SBATCH inside a real heredoc body is inner-script content, not a directive"
        );
        let after = format!("{head}cat <<EOF
inner
EOF
{probe}");
        assert!(
            unread_directive_note(&after).is_some(),
            "a #SBATCH AFTER the heredoc closes must be warned again — the latch is gone"
        );
    }

    #[test]
    fn a_heredoc_that_generates_an_inner_job_script_is_not_read_as_this_jobs_directives() {
        // **A3, the case that actually bit.** A run script that writes ANOTHER job script
        // carries `#SBATCH` (and `#BB`) lines that are DATA for a different submission.
        // husk read them as its own and refused to submit — a false reject on an
        // ICON-shaped workflow, with no way for the scientist to comply short of not
        // generating a script.
        //
        // Safe to narrow ONLY because the agent's body no longer reaches slurmd: husk
        // submits its own script and runs the body as data inside the cage, so a directive
        // husk does not read is inert rather than smuggled.
        let body = "#!/bin/bash\n#SBATCH --partition=preemptible\n\
                    cat > inner.sh <<'EOF'\n\
                    #SBATCH --qos=elevated\n\
                    #SBATCH --reservation=maint\n\
                    #BB stage_in source=/x destination=/y\n\
                    EOF\n\
                    sbatch inner.sh\n";
        assert_eq!(sbatch_directives(body), Ok(v(&["--partition=preemptible"])));
        assert!(
            body_reject_reason(body).is_none(),
            "generating an inner script must not be a rejection — that was A3"
        );
        // …and it must not nag about them either: these are the lines the fix exists for,
        // so a note on every submit would be the crying-wolf failure in message form.
        assert!(unread_directive_note(body).is_none(), "no note for heredoc content");

        // The header is still enforced, so the escape-shaped cases still reject.
        assert!(body_reject_reason("#!/bin/bash\n#SBATCH --qos=elevated\n").is_some());
        assert!(body_reject_reason("#!/bin/bash\n#BB stage_in\n").is_some());
    }

    // ── N5: the directive tokeniser honours quotes ───────────────────────────────────────
    // These pin the level the bug lived at — the TOKENISER, not the option parser. A test
    // written against `interpret_cli` alone would pass with the whitespace splitter still in
    // place, because the splitter's damage was already done by the time the parser saw it.

    #[test]
    fn a_quoted_directive_value_is_one_token_with_the_quotes_removed() {
        // Before: `--job-name="my run"` split into `--job-name="my` and `run"`, and
        // `--job-name="myrun"` kept its quotes. Both were REFUSED — by the value grammar,
        // which forbids `"` — so husk rejected ordinary run scripts.
        assert_eq!(
            sbatch_directives("#!/bin/bash\n#SBATCH --job-name=\"myrun\"\n"),
            Ok(v(&["--job-name=myrun"]))
        );
        assert_eq!(
            sbatch_directives("#!/bin/bash\n#SBATCH --job-name='myrun'\n"),
            Ok(v(&["--job-name=myrun"]))
        );
        // A quote that opens mid-token still yields ONE token.
        assert_eq!(
            sbatch_directives("#!/bin/bash\n#SBATCH --comment=\"a b\"\n"),
            Ok(v(&["--comment=a b"]))
        );
        // And the whole thing now survives the option parser.
        let toks = sbatch_directives("#!/bin/bash\n#SBATCH --job-name=\"myrun\"\n").unwrap();
        assert_eq!(interpret_cli(&toks), Ok(v(&["--job-name=myrun"])));
    }

    #[test]
    fn a_directive_value_may_contain_a_space_where_the_grammar_permits_one() {
        // `v_comment` is deliberately widened to allow a space. With a whitespace-splitting
        // tokeniser that decision was UNREACHABLE: no value with a space could ever arrive.
        // The grammar and the tokeniser disagreed about what was expressible.
        let toks = sbatch_directives("#!/bin/bash\n#SBATCH --comment=\"nightly ICON run\"\n").unwrap();
        assert_eq!(interpret_cli(&toks), Ok(v(&["--comment=nightly ICON run"])));

        // ...and a grammar that does NOT permit a space still refuses one. The tokeniser's
        // job is to deliver the author's value; the grammar's job is to judge it. Fixing the
        // first must not soften the second.
        let jn = sbatch_directives("#!/bin/bash\n#SBATCH --job-name=\"my run\"\n").unwrap();
        assert_eq!(jn, v(&["--job-name=my run"]), "tokenised as one value");
        assert!(interpret_cli(&jn).is_err(), "but the grammar still rejects a space here");
    }

    #[test]
    fn a_trailing_comment_on_a_directive_line_is_not_read_as_options() {
        // Before: `#SBATCH --job-name=x # a note` tokenised to
        // `["--job-name=x", "#", "a", "note"]`, and `interpret_cli` refused the whole
        // submission on the stray `#`. An ordinary, documented way to write a run script.
        //
        // Note the two readers disagreed about those tokens: `body_reject_reason` skips
        // anything not starting with `-` (that is how it steps over a separated value) and
        // saw nothing wrong, while `interpret_cli` rejected. Two functions, one token
        // stream, two verdicts — the F13/F14 shape, inside husk rather than against slurmd.
        // The stricter one runs, so it failed closed; it still meant the refusal came from
        // the place least able to explain it.
        let toks = sbatch_directives("#!/bin/bash\n#SBATCH --job-name=x # a note\n").unwrap();
        assert_eq!(toks, v(&["--job-name=x"]), "the comment is not options");
        assert_eq!(interpret_cli(&toks), Ok(v(&["--job-name=x"])));
        assert!(body_reject_reason("#!/bin/bash\n#SBATCH --job-name=x # a note\n").is_none());

        // A `#` inside quotes is literal — and then judged by the grammar, which takes it
        // for no option, so this still refuses. Failing on the VALUE is the honest failure.
        let q = sbatch_directives("#!/bin/bash\n#SBATCH --comment=\"a # b\"\n").unwrap();
        assert_eq!(q, v(&["--comment=a # b"]), "quoted # is data, not a comment");
        assert!(interpret_cli(&q).is_err(), "and the grammar refuses it");
    }

    #[test]
    fn an_unterminated_quote_in_a_directive_is_refused_rather_than_guessed() {
        // The author's intent is genuinely unknown here. Guessing is how a directive comes to
        // mean one thing to husk and another to the person who wrote it.
        let e = sbatch_directives("#!/bin/bash\n#SBATCH --job-name=\"oops\n")
            .expect_err("an unterminated quote must be an error");
        assert!(e.contains("unterminated"), "and must say so: {e}");
        // It must reject the SUBMISSION, not be swallowed somewhere.
        assert!(body_reject_reason("#!/bin/bash\n#SBATCH --job-name=\"oops\n").is_some());
    }

    #[test]
    fn stripping_quotes_cannot_fuse_two_options_into_something_accepted() {
        // The security question the fix has to answer: removing quote characters joins text
        // that used to be separate. Could that build an option out of two harmless halves?
        // No — fusing produces ONE token whose name is not in the registry, and an unknown
        // option is a hard reject (default-deny), not a skip.
        let fused = sbatch_directives("#!/bin/bash\n#SBATCH --job-name=a\" \"--qos=elevated\n").unwrap();
        assert_eq!(fused, v(&["--job-name=a --qos=elevated"]), "one token, not two");
        assert!(
            interpret_cli(&fused).is_err(),
            "a fused token must not resolve to an accepted option"
        );
    }

    #[test]
    fn the_value_grammar_still_runs_after_the_quotes_come_off() {
        // Quotes are removed BEFORE validation, so validation is what stands between a
        // directive and sbatch's command line. Confirm the grammar is still the gate — this
        // is the property that makes quote-stripping safe rather than merely convenient.
        for hostile in [
            "#!/bin/bash\n#SBATCH --job-name=\"a;rm -rf ~\"\n",
            "#!/bin/bash\n#SBATCH --job-name=\"a$(id)\"\n",
            "#!/bin/bash\n#SBATCH --job-name=\"a`id`\"\n",
            "#!/bin/bash\n#SBATCH --comment=\"a\\\\b\"\n",
        ] {
            let toks = sbatch_directives(hostile).expect("tokenises");
            assert!(
                interpret_cli(&toks).is_err(),
                "grammar must still refuse {toks:?}"
            );
        }
    }

    #[test]
    fn a_directive_husk_did_not_read_is_reported_rather_than_silently_ignored() {
        // Narrowing the scan trades a false reject for a silent ignore, and silence is the
        // failure mode this project keeps fixing. The two cases a human plausibly MEANT:
        // indented in the header, and below the first command with no heredoc in sight.
        let indented = "#!/bin/bash\n  #SBATCH --time=01:00:00\nsrun hostname\n";
        let note = unread_directive_note(indented).expect("an indented directive must be reported");
        assert!(note.contains('2'), "the note must name the line: {note}");
        assert!(note.contains("column 0"), "and the remedy: {note}");

        let after_command = "#!/bin/bash\nmodule load icon\n#SBATCH --time=01:00:00\n";
        assert!(
            unread_directive_note(after_command).is_some(),
            "a directive below the first command is the classic mistake and must be reported"
        );
        // A clean script says nothing at all.
        assert!(unread_directive_note("#!/bin/bash\n#SBATCH -p x\nsrun hostname\n").is_none());
    }
}


