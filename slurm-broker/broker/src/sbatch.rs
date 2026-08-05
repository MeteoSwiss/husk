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

/// One option's spelling(s), arity, class, and value grammar.
pub struct OptSpec {
    pub long: &'static str,
    pub short: &'static str, // "" when there is no short form
    pub aliases: &'static [&'static str],
    pub takes_value: bool,
    pub class: Class,
    pub validate: fn(&str) -> bool, // value grammar for Allowed value opts; always_true otherwise
}

fn always_true(_: &str) -> bool {
    true
}

// --- value grammars: charset + length bounds. Resource options are not
// security-critical (every dangerous decision is Forced), so the grammar's job is to
// keep values free of whitespace / newlines / shell metacharacters and bounded in
// length; slurmd validates the semantics. ---
fn bounded(s: &str, max: usize, ok: impl Fn(char) -> bool) -> bool {
    !s.is_empty() && s.len() <= max && s.chars().all(ok)
}
fn v_uint(s: &str) -> bool { bounded(s, 9, |c| c.is_ascii_digit()) }
fn v_nodes(s: &str) -> bool { bounded(s, 12, |c| c.is_ascii_digit() || c == '-') }
fn v_time(s: &str) -> bool { bounded(s, 15, |c| c.is_ascii_digit() || c == ':' || c == '-') }
fn v_time_at(s: &str) -> bool { bounded(s, 32, |c| c.is_ascii_alphanumeric() || ":+.-".contains(c)) }
fn v_size(s: &str) -> bool { bounded(s, 16, |c| c.is_ascii_digit() || c == '.' || "KMGTPEkmgtpe".contains(c)) }
fn v_name(s: &str) -> bool { bounded(s, 64, |c| c.is_ascii_alphanumeric() || "._+-".contains(c)) }
/// The `--account` grammar, exposed so the operator's `HUSK_SLURM_ACCOUNT` is held to the
/// same rule as an account arriving on the command line. One grammar, one definition.
pub fn is_valid_account(s: &str) -> bool { v_name(s) }
fn v_nodelist(s: &str) -> bool { bounded(s, 256, |c| c.is_ascii_alphanumeric() || "_,-[]".contains(c)) }
fn v_gres(s: &str) -> bool { bounded(s, 128, |c| c.is_ascii_alphanumeric() || "_,:.-".contains(c)) }
fn v_array(s: &str) -> bool { bounded(s, 64, |c| c.is_ascii_digit() || "-,:%".contains(c)) }
fn v_dep(s: &str) -> bool { bounded(s, 128, |c| c.is_ascii_alphanumeric() || "_,:.+?-".contains(c)) }
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
fn v_dist(s: &str) -> bool { bounded(s, 40, |c| c.is_ascii_alphanumeric() || ",:*=".contains(c)) }
fn v_comment(s: &str) -> bool { bounded(s, 256, |c| c.is_ascii_alphanumeric() || " _.,:@/+-".contains(c)) }
fn v_switches(s: &str) -> bool { bounded(s, 24, |c| c.is_ascii_digit() || "@:-".contains(c)) }
/// `--hint` takes one of four fixed keywords — an exact enum is tighter than any charset,
/// and closed sets are exactly where an allowlist should be an allowlist.
fn v_hint(s: &str) -> bool {
    matches!(s, "compute_bound" | "memory_bound" | "multithread" | "nomultithread")
}

macro_rules! spec {
    ($long:expr, $short:expr, $val:expr, $class:expr, $validate:expr) => {
        OptSpec {
            long: $long,
            short: $short,
            aliases: &[],
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
    spec!("--nodes", "-N", true, Class::Forced, v_nodes),
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
    spec!("--gpu-bind", "", true, Class::Allowed, v_gres),
    spec!("--mem-bind", "", true, Class::Allowed, v_gres),
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
    ), v_name),
    // FORCED, not Allowed. The account is who gets BILLED, so letting the agent name it
    // would let a caged job charge another project's allocation — and on sites whose
    // cli_filter requires an account (Santis), it is also mandatory for any job to run at
    // all. Same treatment as the partition: taken from the operator's trusted config, never
    // from the request.
    spec!("--account", "-A", true, Class::Forced, v_name),
    spec!("--reservation", "", true, Class::Rejected(
        "husk does not let a job claim a reservation: reserved nodes are set aside for \
         particular people and particular work, and a brokered job is neither. Submit \
         without --reservation."
    ), v_name),
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
    // `--wait` makes sbatch block until the job COMPLETES, which would wedge the
    // single-threaded broker for the whole job runtime (the F2/F16 DoS shape). Dropped
    // rather than rejected: the submission is still perfectly valid without it, the
    // agent just gets its job id immediately and polls with squeue.
    spec!("--wait", "-W", false, Class::Ignored, always_true),
    spec!("--quiet", "-Q", false, Class::Ignored, always_true),
    spec!("--verbose", "-v", false, Class::Ignored, always_true),
    spec!("--mail-type", "", true, Class::Ignored, always_true),
    spec!("--mail-user", "", true, Class::Ignored, always_true),
];

/// A tool's complete option registry. The parsing machinery below is parameterised by
/// one of these so that `sbatch` and `srun` share a SINGLE parser: two copies would be
/// two things to keep in sync, and a gate that drifts from its twin is the same failure
/// mode the allowlist redesign existed to remove. Only the option TABLE differs per tool.
pub type Registry = &'static [OptSpec];

/// Look up an option by any of its spellings (long / short / alias).
pub fn lookup_in(reg: Registry, name: &str) -> Option<&'static OptSpec> {
    reg.iter()
        .find(|s| s.long == name || (!s.short.is_empty() && s.short == name) || s.aliases.contains(&name))
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
                if spec.takes_value {
                    let v = value
                        .ok_or_else(|| format!("option '{}' requires a value", spec.long))?;
                    if !(spec.validate)(&v) {
                        return Err(format!(
                            "value {v:?} for '{}' is not allowed (must match the option's safe grammar)",
                            spec.long
                        ));
                    }
                    out.push(format!("{}={}", spec.long, v));
                } else {
                    out.push(spec.long.to_string());
                }
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
        // Options with dedicated validation + teaching messages in policy.rs.
        let dedicated = matches!(
            name,
            "--partition" | "-p" | "--uenv" | "--view" | "--repo" | "--nodes" | "-N"
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
                        "#SBATCH {name} is controlled by the broker and can't be set by the job \
                         (output/error/chdir/export are forced to safe values). Remove it."
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
    Ok(out)
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
pub fn unread_directive_note(body: &str) -> Option<String> {
    let header_count = header_lines(body).count();
    let mut missed: Vec<usize> = Vec::new();
    let mut heredoc_seen = false;
    for (i, line) in body.lines().enumerate() {
        let t = line.trim_start();
        if i >= header_count && line.contains("<<") {
            heredoc_seen = true;
        }
        if !t.starts_with("#SBATCH") {
            continue;
        }
        let read = i < header_count && directive_body(line).is_some();
        if !read && !heredoc_seen {
            missed.push(i + 1);
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
    fn wait_is_dropped_not_forwarded() {
        // sbatch --wait blocks until the job COMPLETES, which would wedge the broker for
        // the whole runtime. It must be swallowed, not passed through.
        let out = interpret_cli(&v(&["--wait"])).expect("--wait must not be a hard error");
        assert!(out.is_empty(), "--wait leaked into the submission: {out:?}");
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


