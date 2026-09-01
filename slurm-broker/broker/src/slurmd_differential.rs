//! Grade a `slurmd-differential.sh` artefact against husk's model of slurmd.
//!
//! # Why this is here and not in Python
//!
//! The question is "does `settings::OUTPUT_SPECIFIERS` say what slurmd does", and the only
//! honest way to answer it is to compute husk's side **with husk's own code**. A Python
//! grader would have to re-type the table, the `${VAR:-default}` semantics, the
//! `unset_is_unnameable` rule, the `requires` gate and the leaf grammar — six copies of
//! things that already exist, in a file no test compiles. That is `P8` exactly, and it is
//! the shape of the bug this whole instrument exists to catch: `B1-1` was the guard's
//! expander hand-written beside the table it was supposed to mirror, and the two drifted by
//! two entries.
//!
//! Three concrete costs of the Python version, all avoidable and none hypothetical:
//!
//! * `main.rs:896` records that a shell/python re-derivation of the operator config drifted
//!   from the config file the same day it was written, **and that `python3` was not on PATH
//!   where it ran**. Cargo is on the machine that grades; that machine is the one with the
//!   repo.
//! * `OUTPUT_SPECIFIERS` lives in the **binary** crate, not in `lib.rs` (which is
//!   deliberately dependency-free and holds only what the wrapper shares). Nothing outside
//!   this crate can read it without a refactor that widens the wrapper's audit surface.
//! * The strongest oracle available is not the table at all — it is the **generated guard
//!   shell**, run under `bash` with the environment slurmd actually handed the batch step.
//!   `policy::tests::emitted_name_check` already lifts that block out of a real guard so it
//!   can be executed; `D2-3`/`D2-4` are the record of what happens when an oracle reads the
//!   generator as text instead. Only a Rust test can reach it.
//!
//! So the division is: the cluster script RECORDS, this module DECIDES, and what it decides
//! with is husk's own `settings::confine_output_pattern`, husk's own
//! `settings::output_specifiers_needing_an_option`, and husk's own emitted bash.
//!
//! # The four dispositions, and why "not measured" is one of them
//!
//! | disposition | meaning |
//! |---|---|
//! | `Agree` | the guard, run on the recorded environment, names exactly the file slurmd created |
//! | `Disagree` | it names a different file — the `RA-2` shape. Both names are printed |
//! | `HuskRefuses` | husk never accepts this pattern, so no disagreement is possible. Recorded anyway, because slurmd's rendering is the evidence the refusal is or is not conservative |
//! | `NotMeasured` | no file, an unparseable name, a job that never ran, a failed control |
//!
//! `NotMeasured` is never folded into `Agree`. That fold is precisely `B8-1`: thirteen of
//! thirteen variants unmeasured, reported as "husk's parser and this site's Slurm agree on
//! every spelling probed".
//!
//! # How to run it
//!
//! ```text
//! HUSK_DIFFERENTIAL_ARTEFACT=/path/to/artefact \
//!   cargo test --manifest-path slurm-broker/broker/Cargo.toml \
//!              slurmd_differential -- --nocapture
//! ```

use crate::settings;
use std::collections::BTreeMap;
use std::fmt::Write as _;

// ---------------------------------------------------------------------------------------
// The artefact
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvVal {
    Set(String),
    Unset,
}

#[derive(Debug, Clone)]
pub struct FileRec {
    pub name: String,
    pub kind: String,
    pub size: String,
}

#[derive(Debug, Clone)]
pub struct Case {
    pub tag: String,
    pub id: String,
    pub channel: String,
    pub where_: String,
    pub pattern: String,
    pub dir: String,
}

#[derive(Debug, Default)]
pub struct Artefact {
    pub meta: BTreeMap<String, String>,
    pub controls: Vec<(String, String, String)>,
    pub cases: Vec<Case>,
    pub argv: BTreeMap<String, Vec<(u32, String)>>,
    pub opts: BTreeMap<String, BTreeMap<String, String>>,
    pub notes: BTreeMap<String, String>,
    pub files: BTreeMap<String, Vec<FileRec>>,
    pub filecount: BTreeMap<String, String>,
    /// tag -> (jobid, status, detail)
    pub jobs: BTreeMap<String, (String, String, String)>,
    pub jobstate: BTreeMap<String, String>,
    /// (jobkey, task) -> variable -> value
    pub env: BTreeMap<(String, String), BTreeMap<String, EnvVal>>,
    pub pwd: BTreeMap<(String, String), String>,
    pub end: Option<String>,
    /// Lines this parser did not understand. NOT a skip list: any entry here makes the
    /// artefact ungradeable. A record type added on the cluster and not here means the two
    /// halves have drifted, and the half that would report green is this one.
    pub unknown: Vec<String>,
}

pub fn parse(text: &str) -> Result<Artefact, String> {
    let mut a = Artefact::default();
    let mut saw_header = false;
    for (lineno, raw) in text.lines().enumerate() {
        if raw.is_empty() {
            continue;
        }
        let f: Vec<&str> = raw.split('\t').collect();
        let g = |i: usize| -> String { f.get(i).copied().unwrap_or("").to_string() };
        match f[0] {
            "HUSKDIFF" => {
                saw_header = true;
                if g(1) != "1" {
                    return Err(format!(
                        "artefact schema version {:?}, this grader speaks 1. A newer harness \
                         wrote records this grader may silently ignore.",
                        g(1)
                    ));
                }
            }
            "META" => {
                a.meta.insert(g(1), g(2));
            }
            "CONTROL" => a.controls.push((g(1), g(2), g(3))),
            "CASE" => a.cases.push(Case {
                tag: g(1),
                id: g(2),
                channel: g(3),
                where_: g(4),
                pattern: g(5),
                dir: g(6),
            }),
            "ARGV" => {
                let n: u32 = g(2).parse().unwrap_or(u32::MAX);
                a.argv.entry(g(1)).or_default().push((n, g(3)));
            }
            "OPT" => {
                a.opts.entry(g(1)).or_default().insert(g(2), g(3));
            }
            "NOTE" => {
                a.notes.insert(g(1), g(2));
            }
            "FILE" => a.files.entry(g(1)).or_default().push(FileRec {
                name: g(2),
                kind: g(3),
                size: g(4),
            }),
            "FILES" => {
                a.filecount.insert(g(1), g(2));
            }
            "JOB" => {
                a.jobs.insert(g(1), (g(2), g(3), g(4)));
            }
            "JOBSTATE" => {
                a.jobstate.insert(g(1), g(3));
            }
            "ENV" => {
                let v = match f.get(4).copied().unwrap_or("") {
                    "SET" => EnvVal::Set(g(5)),
                    "UNSET" => EnvVal::Unset,
                    other => {
                        return Err(format!(
                            "line {}: ENV disposition {other:?} is neither SET nor UNSET. \
                             husk's `${{VAR:-}}` and its `[ -n ]` guard treat unset and \
                             set-empty the same, so this grader must be able to tell them \
                             apart and refuses to guess.",
                            lineno + 1
                        ))
                    }
                };
                a.env.entry((g(1), g(2))).or_default().insert(g(3), v);
            }
            "PWD" => {
                a.pwd.insert((g(1), g(2)), g(3));
            }
            "END" => a.end = Some(g(1)),
            _ => a.unknown.push(format!("line {}: {raw}", lineno + 1)),
        }
    }
    if !saw_header {
        return Err("no `HUSKDIFF 1` header — this is not a slurmd-differential artefact".into());
    }
    Ok(a)
}

// ---------------------------------------------------------------------------------------
// husk's side
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    Agree { name: String },
    Disagree { husk: String, slurmd: String },
    HuskRefuses {
        when: &'static str,
        why: String,
        slurmd: String,
        /// What husk's table alone renders, with the `RA-2` unset guard NOT applied — i.e.
        /// the name the guard checked BEFORE that fix. Printed when it differs from the
        /// file slurmd opened, because that difference is the whole finding: it is the
        /// evidence the refusal is buying something.
        unguarded: Option<String>,
    },
    NotMeasured { why: String },
}

impl Disposition {
    pub fn label(&self) -> &'static str {
        match self {
            Disposition::Agree { .. } => "AGREE",
            Disposition::Disagree { .. } => "DISAGREE",
            Disposition::HuskRefuses { .. } => "husk-REFUSES",
            Disposition::NotMeasured { .. } => "not-measured",
        }
    }
}

/// The `:-default` out of a table entry's expansion, parsed rather than restated (`P8`).
fn default_of(spec: &settings::Specifier) -> &'static str {
    let e = spec.expansion();
    let inner = &e[2..e.len() - 1];
    match inner.find(":-") {
        Some(i) => &inner[i + 2..],
        None => "",
    }
}

/// What husk's guard would compute for `leaf`, from `OUTPUT_SPECIFIERS` and the environment
/// slurmd handed the step.
///
/// This is the NAMING half, so the report can say which file each side means. It is not the
/// deciding half: `disposition_of` runs the real emitted bash and cross-checks it against
/// this, because a table cannot be its own oracle (`RA-4`) and neither can a
/// re-implementation of it.
fn husk_expand(
    leaf: &str,
    env: &BTreeMap<String, EnvVal>,
    apply_unset_guard: bool,
) -> Result<String, String> {
    let mut s = leaf.to_string();
    for spec in settings::OUTPUT_SPECIFIERS {
        let tok = format!("%{}", spec.spec());
        let present = match env.get(spec.variable()) {
            Some(EnvVal::Set(v)) => !v.is_empty(),
            _ => false,
        };
        if apply_unset_guard && spec.unset_is_unnameable() && s.contains(&tok) && !present {
            return Err(format!(
                "%{} needs {}, which is not set on this node, so husk cannot name the file \
                 SLURM will open",
                spec.spec(),
                spec.variable()
            ));
        }
        let value = if present {
            match env.get(spec.variable()) {
                Some(EnvVal::Set(v)) => v.clone(),
                _ => unreachable!("present implies Set"),
            }
        } else {
            default_of(spec).to_string()
        };
        s = s.replace(&tok, &value);
    }
    if s.contains('%') {
        return Err("a % specifier survived expansion".into());
    }
    if s.contains('/') {
        return Err("an expanded value contains a /".into());
    }
    Ok(s)
}

/// Run husk's REAL generated guard block on the recorded environment, with a symlink
/// planted at the name slurmd created.
///
/// The oracle is behavioural and needs no model of husk at all:
///
/// * the guard refuses a symlink leaf, and it can only do that by having resolved to
///   exactly that name — so a refusal naming the symlink means husk and slurmd agree;
/// * exit 0 means the guard looked somewhere else and was satisfied by the absence of a
///   file it named itself. That is `RA-S2` verbatim, and it is the escape.
///
/// Returns `(rc, transcript)`.
fn run_guard(root: &std::path::Path, emitted: &str, env: &BTreeMap<String, EnvVal>) -> (i32, String) {
    let roots = vec![root.to_string_lossy().to_string()];
    let block = crate::policy::emitted_name_check(&roots, emitted, "");
    // Only SET variables are passed. `run_name_check` clears the environment first, so an
    // UNSET recording becomes a genuinely absent variable and a set-empty recording becomes
    // a present, empty one — the distinction husk's `[ -n "${VAR:-}" ]` guard turns on.
    let owned: Vec<(String, String)> = env
        .iter()
        .filter_map(|(k, v)| match v {
            EnvVal::Set(s) => Some((k.clone(), s.clone())),
            EnvVal::Unset => None,
        })
        .collect();
    let pairs: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let log = root.join("guard.log");
    let _ = std::fs::remove_file(&log);
    crate::policy::run_name_check(&block, &log, &pairs)
}

/// Everything the grader concluded about one (case, task) pair.
#[derive(Debug, Clone)]
pub struct Row {
    pub case: String,
    pub tag: String,
    pub task: String,
    pub channel: String,
    pub where_: String,
    pub pattern: String,
    pub disposition: Disposition,
    /// Set when the Rust expansion and the emitted bash do not tell the same story. This is
    /// a defect in the GRADER, not a finding about slurmd, and it is reported as loudly as
    /// one so it cannot be read as a divergence.
    pub oracle_conflict: Option<String>,
}

fn disposition_of(
    pattern: &str,
    array_given: bool,
    env: &BTreeMap<String, EnvVal>,
    slurmd_names: &[String],
) -> (Disposition, Option<String>) {
    // ── submit time, decided by husk's own function ─────────────────────────────────────
    let work = std::env::temp_dir().join(format!(
        "husk-diff-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    if std::fs::create_dir_all(&work).is_err() {
        return (
            Disposition::NotMeasured { why: "could not create a scratch directory".into() },
            None,
        );
    }
    let workdir = work.to_string_lossy().to_string();
    let slurmd = slurmd_names.first().cloned().unwrap_or_default();
    let leaf = pattern.rsplit_once('/').map(|(_, f)| f).unwrap_or(pattern);
    // What the table alone renders, with `RA-2`'s unset guard switched OFF. Reported beside
    // every refusal so the report shows what husk WOULD have checked, which is the whole
    // content of the `%A` finding.
    // Only where the comparison means something: if slurmd's own name has a directory
    // component then husk's leaf expansion is not the same kind of object, and printing it
    // beside slurmd's path would invite exactly the wrong reading.
    let unguarded = husk_expand(leaf, env, false)
        .ok()
        .filter(|n| *n != slurmd && !slurmd.contains('/'));

    let confined = match settings::confine_output_pattern(pattern, &workdir) {
        Ok(p) => p,
        Err(why) => {
            let _ = std::fs::remove_dir_all(&work);
            return (
                Disposition::HuskRefuses { when: "submit", why, slurmd, unguarded },
                None,
            );
        }
    };
    // The `requires` gate, which lives in `policy::decide` rather than in
    // `confine_output_pattern` — mirrored here by calling the same table function `decide`
    // calls, so a table edit moves both.
    for spec in settings::output_specifiers_needing_an_option(leaf) {
        let satisfied = spec.requires().iter().any(|opt| {
            matches!(*opt, "-a" | "--array") && array_given
        });
        if !satisfied {
            let _ = std::fs::remove_dir_all(&work);
            return (
                Disposition::HuskRefuses {
                    when: "submit",
                    why: format!(
                        "%{} needs {} on the request, and it is absent",
                        spec.spec(),
                        spec.requires().join("/")
                    ),
                    slurmd,
                    unguarded,
                },
                None,
            );
        }
    }

    if slurmd_names.is_empty() {
        let _ = std::fs::remove_dir_all(&work);
        return (
            Disposition::NotMeasured {
                why: "no file appeared, so there is nothing to compare husk's name against"
                    .into(),
            },
            None,
        );
    }

    // ── run time, decided by husk's own emitted bash ────────────────────────────────────
    let rust_side = husk_expand(leaf, env, true);
    let mut conflict = None;

    // Plant the symlink at the name slurmd created and ask the guard.
    let planted = work.join(&slurmd);
    if let Some(parent) = planted.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(&planted);
    if std::os::unix::fs::symlink("/etc/passwd", &planted).is_err() {
        let _ = std::fs::remove_dir_all(&work);
        return (
            Disposition::NotMeasured {
                why: format!("could not plant a probe symlink at {slurmd:?}"),
            },
            None,
        );
    }
    let (rc, text) = run_guard(&work, &confined, env);
    let _ = std::fs::remove_dir_all(&work);

    let disp = if rc == 1 && text.contains("is not set on this node") {
        Disposition::HuskRefuses {
            when: "run time (the guard, on the compute node)",
            why: first_reason(&text),
            slurmd: slurmd.clone(),
            unguarded: unguarded.clone(),
        }
    } else if rc == 1 && text.contains("final component is a symlink") {
        Disposition::Agree { name: slurmd.clone() }
    } else if rc == 1 {
        Disposition::HuskRefuses {
            when: "run time (the guard, on the compute node)",
            why: first_reason(&text),
            slurmd: slurmd.clone(),
            unguarded: unguarded.clone(),
        }
    } else {
        // The guard was satisfied while a symlink sat at the name slurmd opened. It named
        // something else.
        let husk = match &rust_side {
            Ok(n) => n.clone(),
            Err(e) => format!("<unnameable: {e}>"),
        };
        Disposition::Disagree { husk, slurmd: slurmd.clone() }
    };

    // Cross-check the two oracles. They answer the same question by different routes, and a
    // disagreement between them is a bug in this file.
    match (&disp, &rust_side) {
        (Disposition::Agree { name }, Ok(expanded)) if expanded != name => {
            conflict = Some(format!(
                "the emitted guard refused the symlink at {name:?} (so it named that file), \
                 but this module's expansion of the same table says {expanded:?}"
            ));
        }
        (Disposition::Disagree { husk, .. }, Ok(expanded)) if husk == &slurmd => {
            conflict = Some(format!(
                "the emitted guard did not see a symlink at {slurmd:?}, but this module's \
                 expansion says husk names exactly that file ({expanded:?})"
            ));
        }
        _ => {}
    }
    (disp, conflict)
}

/// The refusal line the guard logged, without the surrounding transcript.
fn first_reason(text: &str) -> String {
    for line in text.lines() {
        if line.contains("JOB REFUSED") || line.contains("husk:") {
            return line.trim().to_string();
        }
    }
    text.lines().next().unwrap_or("").trim().to_string()
}

// ---------------------------------------------------------------------------------------
// Known answers — the harness's own calibration
// ---------------------------------------------------------------------------------------

/// Measurements the operator took BY HAND on Santis, 2026-08-31, before this harness
/// existed. They live HERE and not in the cluster script deliberately: a recorder that
/// knows the expected answer is a recorder that can be tuned until it produces it.
///
/// `{job}` is replaced by the job id the artefact recorded for that case's job.
///
/// A known answer that comes out wrong is a statement about the HARNESS, not about slurmd —
/// the corpus row, the directory scan or the fixture is wrong — and the grader says so in
/// those words rather than filing it as a divergence.
const KNOWN: &[(&str, &str, &str)] = &[
    (
        "j03-o",
        "probe-A{job}-a4294967294-sbatch.log",
        "RA §6: `sbatch --output=probe-A%A-a%a-s%s.log --wrap=true` on a NON-array job \
         rendered %A as the job id, %a as 4294967294 (NO_VAL) and %s as `batch`",
    ),
    (
        "j06-o",
        "jprobe-{job}.log",
        "RA §8: `sbatch --output=jprobe-%J.log --wrap=true` rendered %J as the BARE job id \
         on the batch step — no dot, no stepid, contradicting husk's earlier prose",
    ),
    (
        "j11-o",
        "chd%x/slurm-{job}.out",
        "RA §7: slurmd does not expand %  in --chdir, so the default output lands in the \
         LITERAL `chd%x` directory. If it lands in `chdhuskdiffc/` instead, --chdir is \
         expanded and D2-7's premise is wrong",
    ),
];

// ---------------------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Report {
    pub gradeable: bool,
    pub refusal: Option<String>,
    pub rows: Vec<Row>,
    pub known: Vec<(String, bool, String)>,
    pub text: String,
}

impl Report {
    pub fn count(&self, label: &str) -> usize {
        self.rows.iter().filter(|r| r.disposition.label() == label).count()
    }
    pub fn row(&self, case: &str) -> Option<&Row> {
        self.rows.iter().find(|r| r.case == case)
    }
}

/// Refuse an artefact that cannot support a conclusion, and say which check refused.
///
/// This is the offline half of the cluster script's own controls. The script decides
/// nothing; it records what it saw, and the decision to trust it is taken here, by someone
/// reading a report — which is the only arrangement in which "the run was fine" is not the
/// claim of the thing being checked (`P2`).
fn refusal_reason(a: &Artefact) -> Option<String> {
    if !a.unknown.is_empty() {
        return Some(format!(
            "the artefact holds {} record(s) this grader does not understand. The harness \
             and the grader have drifted, and the half that would report green is this one:\n  {}",
            a.unknown.len(),
            a.unknown.join("\n  ")
        ));
    }
    match a.end.as_deref() {
        Some("ok") => {}
        Some("dry-run") => {
            return Some(
                "this is a DRY RUN artefact: the harness printed the invocations and \
                 submitted nothing. Nothing was measured."
                    .into(),
            )
        }
        Some(other) => return Some(format!("the artefact ends with `END {other}`")),
        None => {
            return Some(
                "the artefact has no `END` line, so the run did not finish. A run killed \
                 halfway is not a partial measurement; the cases it never scanned are \
                 indistinguishable from cases that produced no file."
                    .into(),
            )
        }
    }
    let failed: Vec<String> = a
        .controls
        .iter()
        .filter(|(_, verdict, _)| verdict != "PASS")
        .map(|(name, verdict, detail)| format!("{name}: {verdict} — {detail}"))
        .collect();
    if !failed.is_empty() {
        return Some(format!(
            "{} control(s) did not pass on the cluster, so nothing here can be read as \
             agreement (B8-1):\n  {}",
            failed.len(),
            failed.join("\n  ")
        ));
    }
    if a.cases.is_empty() {
        return Some("the artefact records no cases at all".into());
    }
    // The harness writes both a `FILE` line per entry and one `FILES <case> <count>`
    // summary. They are two statements about the same scan, so make one assert the other
    // (`P8`): a truncated or interleaved artefact shows up here rather than as a case that
    // quietly lost a file.
    for case in &a.cases {
        let Some(declared) = a.filecount.get(&case.id) else {
            return Some(format!("case {} has no FILES summary line", case.id));
        };
        let Ok(declared) = declared.parse::<usize>() else {
            return Some(format!(
                "case {}'s FILES line reads {declared:?}, so the directory scan itself failed",
                case.id
            ));
        };
        let seen = a
            .files
            .get(&case.id)
            .map(|v| v.iter().filter(|f| f.kind == "file").count())
            .unwrap_or(0);
        if declared != seen {
            return Some(format!(
                "case {} declares {declared} file(s) and carries {seen} FILE record(s) — the \
                 artefact is inconsistent with itself",
                case.id
            ));
        }
    }
    None
}

pub fn grade(a: &Artefact) -> Report {
    let mut r = Report::default();
    let mut out = String::new();

    let version = a.meta.get("sbatch_version").cloned().unwrap_or_default();
    let looks_like_slurm = version.to_ascii_lowercase().contains("slurm")
        && !version.to_ascii_lowercase().contains("fixture");

    let _ = writeln!(out, "== slurmd `%` differential — offline grading ==");
    let _ = writeln!(out, "host      : {}", a.meta.get("host").cloned().unwrap_or_default());
    let _ = writeln!(out, "sbatch    : {version}");
    let _ = writeln!(
        out,
        "recorded  : {}",
        a.meta.get("generated").cloned().unwrap_or_default()
    );
    if !looks_like_slurm {
        let _ = writeln!(
            out,
            "\n*** SOURCE IS NOT SLURM ***\n\
             `sbatch --version` did not identify itself as SLURM. This grades the HARNESS,\n\
             not any cluster: every row below is a statement about the fixture's model.\n"
        );
    }

    if let Some(why) = refusal_reason(a) {
        r.gradeable = false;
        r.refusal = Some(why.clone());
        let _ = writeln!(out, "\nREFUSED — this artefact cannot be graded.\n\n{why}\n");
        let _ = writeln!(
            out,
            "Nothing above or below is agreement. Re-run the harness on the cluster once the\n\
             instrument is in a state to answer; do not read the absence of a file as slurmd\n\
             declining to create one."
        );
        r.text = out;
        return r;
    }
    r.gradeable = true;

    // ── per-case ────────────────────────────────────────────────────────────────────────
    for case in a.cases.iter().filter(|c| c.where_ != "none") {
        let jobid = a.jobs.get(&case.tag).map(|(id, _, _)| id.clone()).unwrap_or_default();
        let status = a.jobs.get(&case.tag).map(|(_, s, _)| s.clone()).unwrap_or_default();
        let array_given = a
            .opts
            .get(&case.id)
            .and_then(|m| m.get("array"))
            .map(|v| v != "ABSENT")
            .unwrap_or(false);

        if status != "SUBMITTED" {
            let detail = a.jobs.get(&case.tag).map(|(_, _, d)| d.clone()).unwrap_or_default();
            r.rows.push(Row {
                case: case.id.clone(),
                tag: case.tag.clone(),
                task: "-".into(),
                channel: case.channel.clone(),
                where_: case.where_.clone(),
                pattern: case.pattern.clone(),
                disposition: Disposition::NotMeasured {
                    why: format!("sbatch did not accept the job: {detail}"),
                },
                oracle_conflict: None,
            });
            continue;
        }

        let recorded: Vec<FileRec> =
            a.files.get(&case.id).cloned().unwrap_or_default();
        if recorded.iter().any(|f| f.name == "UNPARSEABLE") {
            r.rows.push(Row {
                case: case.id.clone(),
                tag: case.tag.clone(),
                task: "-".into(),
                channel: case.channel.clone(),
                where_: case.where_.clone(),
                pattern: case.pattern.clone(),
                disposition: Disposition::NotMeasured {
                    why: "a created filename held a tab or a newline and could not be \
                          recorded verbatim"
                        .into(),
                },
                oracle_conflict: None,
            });
            continue;
        }
        let names: Vec<String> =
            recorded.iter().filter(|f| f.kind == "file").map(|f| f.name.clone()).collect();

        // Every recorded task of this job. A non-array job has exactly one, keyed "none".
        let tasks: Vec<(String, BTreeMap<String, EnvVal>)> = a
            .env
            .iter()
            .filter(|((k, _), _)| *k == jobid)
            .map(|((_, t), v)| (t.clone(), v.clone()))
            .collect();

        if tasks.is_empty() {
            r.rows.push(Row {
                case: case.id.clone(),
                tag: case.tag.clone(),
                task: "-".into(),
                channel: case.channel.clone(),
                where_: case.where_.clone(),
                pattern: case.pattern.clone(),
                disposition: Disposition::NotMeasured {
                    why: format!(
                        "job {jobid} recorded no environment, so the batch step never ran \
                         (state: {})",
                        a.jobstate.get(&case.tag).cloned().unwrap_or_else(|| "unknown".into())
                    ),
                },
                oracle_conflict: None,
            });
            continue;
        }

        for (task, env) in tasks {
            // Which of the recorded files belongs to THIS task? For a non-array job there
            // is one. For an array, husk's expansion for the task decides — and if it is
            // not among the recorded names, that IS the disagreement.
            let leaf = case.pattern.rsplit_once('/').map(|(_, f)| f).unwrap_or(&case.pattern);
            let mine: Vec<String> = if names.len() <= 1 {
                names.clone()
            } else {
                match husk_expand(leaf, &env, true) {
                    Ok(n) if names.contains(&n) => vec![n],
                    // Cannot pick one: hand the whole set to the disposition, which will
                    // compare against the first and report a divergence with the set shown.
                    _ => names.clone(),
                }
            };
            let (disposition, oracle_conflict) =
                disposition_of(&case.pattern, array_given, &env, &mine);
            r.rows.push(Row {
                case: case.id.clone(),
                tag: case.tag.clone(),
                task,
                channel: case.channel.clone(),
                where_: case.where_.clone(),
                pattern: case.pattern.clone(),
                disposition,
                oracle_conflict,
            });
        }
    }

    // ── known answers ───────────────────────────────────────────────────────────────────
    let _ = writeln!(out, "\n-- known-answer controls (measured by hand before this harness) --");
    for (case_id, expected_tpl, provenance) in KNOWN {
        let Some(case) = a.cases.iter().find(|c| c.id == *case_id) else {
            r.known.push(((*case_id).into(), false, "case not present in this artefact".into()));
            let _ = writeln!(out, "  {case_id:<8} SKIPPED  not in this run (--only?)");
            continue;
        };
        let jobid = a.jobs.get(&case.tag).map(|(id, _, _)| id.clone()).unwrap_or_default();
        let expected = expected_tpl.replace("{job}", &jobid);
        let got: Vec<String> = a
            .files
            .get(*case_id)
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter(|f| f.kind == "file")
            .map(|f| f.name.clone())
            .collect();
        let ok = got.contains(&expected);
        r.known.push(((*case_id).into(), ok, expected.clone()));
        if ok {
            let _ = writeln!(out, "  {case_id:<8} ok       {expected}");
        } else {
            let _ = writeln!(
                out,
                "  {case_id:<8} UNEXPECTED\n    expected : {expected}\n    got      : {}\n    \
                 provenance: {provenance}\n    THIS IS ABOUT THE HARNESS. A known answer that \
                 comes out wrong means the corpus row, the\n    scan or the cluster changed — \
                 settle that before reading any row below as a finding.",
                if got.is_empty() { "<nothing>".to_string() } else { got.join(", ") }
            );
        }
    }

    // ── the table ───────────────────────────────────────────────────────────────────────
    let _ = writeln!(out, "\n-- husk vs slurmd, case by case --");
    let _ = writeln!(
        out,
        "{:<8} {:<5} {:<7} {:<5} {:<14} {}",
        "CASE", "WHERE", "CHANNEL", "TASK", "DISPOSITION", "PATTERN"
    );
    for row in &r.rows {
        let jobid = a.jobs.get(&row.tag).map(|(id, _, _)| id.clone()).unwrap_or_default();
        let _ = writeln!(
            out,
            "{:<8} {:<5} {:<7} {:<5} {:<14} {}",
            row.case,
            row.where_,
            row.channel,
            row.task,
            row.disposition.label(),
            row.pattern
        );
        if let Some(note) = a.notes.get(&row.case) {
            let _ = writeln!(out, "         [{}] {note}", if jobid.is_empty() { "-" } else { &jobid });
        }
        // A file that exists but is EMPTY was opened and never written, which is a different
        // fact from a file that was written to — and it is the fact that says whether
        // slurmstepd got as far as running the body.
        if let Some(fs) = a.files.get(&row.case) {
            for f in fs.iter().filter(|f| f.kind == "file" && f.size == "0") {
                let _ = writeln!(out, "         note: {} was created but is empty", f.name);
            }
        }
        if let Some(p) = a.pwd.iter().find(|((k, t), _)| *k == jobid && *t == row.task) {
            if row.where_ == "none" {
                let _ = writeln!(
                    out,
                    "         the step's working directory was {} — this is the --chdir answer",
                    p.1
                );
            }
        }
        match &row.disposition {
            Disposition::Agree { name } => {
                let _ = writeln!(out, "         both name {name}");
            }
            Disposition::Disagree { husk, slurmd } => {
                let _ = writeln!(
                    out,
                    "         slurmd opens : {slurmd}\n         husk checks  : {husk}\n\
                     \x20        Both leaf checks — the symlink one and N1's hard-link one — run on\n\
                     \x20        husk's name, so neither runs on the file slurmd opens (RA-2)."
                );
            }
            Disposition::HuskRefuses { when, why, slurmd, unguarded } => {
                let _ = writeln!(
                    out,
                    "         husk refuses at {when}: {}\n         slurmd opens: {}",
                    first_sentence(why),
                    if slurmd.is_empty() { "<no file>" } else { slurmd }
                );
                if let Some(u) = unguarded {
                    let _ = writeln!(
                        out,
                        "         had husk NOT refused, its table renders {u} — a different\n                         \x20        file from the one slurmd opens, so both leaf checks would have\n                         \x20        run on a name that does not exist. THIS IS WHAT THE REFUSAL BUYS."
                    );
                }
            }
            Disposition::NotMeasured { why } => {
                let _ = writeln!(out, "         {why}");
            }
        }
        if let Some(c) = &row.oracle_conflict {
            let _ = writeln!(out, "         !! GRADER DEFECT — two oracles disagree: {c}");
        }
        // The exact invocation, for the rows a human will want to reproduce by hand. It is
        // recorded argument by argument, so this is the command and not a rendering of it.
        if matches!(row.disposition, Disposition::Disagree { .. }) {
            if let Some(mut argv) = a.argv.get(&row.case).cloned() {
                argv.sort_by_key(|(n, _)| *n);
                let cmd: Vec<String> = argv.into_iter().map(|(_, v)| shell_quote(&v)).collect();
                let _ = writeln!(out, "         reproduce: {}", cmd.join(" "));
            }
        }
    }

    // ── the directory questions (D2-7) ──────────────────────────────────────────────────
    //
    // A case with no `--output` at all is not a comparison and must not be filed as one:
    // husk REFUSES a `--chdir` carrying a `%` at submit (`RA-6`), so there is no husk-side
    // name to disagree with. What the run produces is a fact about slurmd that `D2-7` has
    // been INCONCLUSIVE on since the round opened, and it is reported on its own terms.
    let dircases: Vec<&Case> = a.cases.iter().filter(|c| c.where_ == "none").collect();
    if !dircases.is_empty() {
        let _ = writeln!(
            out,
            "\n-- directory questions (D2-7): no --output was given, so this is not a \
             comparison --"
        );
        for case in &dircases {
            let jobid = a.jobs.get(&case.tag).map(|(id, _, _)| id.clone()).unwrap_or_default();
            let mut argv = a.argv.get(&case.id).cloned().unwrap_or_default();
            argv.sort_by_key(|(n, _)| *n);
            let chdir = argv
                .iter()
                .map(|(_, v)| v.clone())
                .find(|v| v.starts_with("--chdir="))
                .unwrap_or_else(|| "<none>".into());
            let _ = writeln!(out, "  {} (job {jobid})", case.id);
            let _ = writeln!(out, "    requested        : {chdir}");
            match a.pwd.iter().find(|((k, _), _)| *k == jobid) {
                Some((_, p)) => {
                    let _ = writeln!(out, "    the step ran in  : {p}");
                    // Compare the two STRINGS rather than looking for a `%` in the result.
                    // "it still has a % in it" happens to be true here and would be false
                    // for a `--chdir` whose expansion also contained one; the question is
                    // whether slurmd changed the value, and that is what is asked.
                    let requested = chdir.strip_prefix("--chdir=").unwrap_or("");
                    let _ = writeln!(
                        out,
                        "    -> {}",
                        if requested.is_empty() {
                            "no --chdir was requested, so this says nothing about it".to_string()
                        } else if requested == p {
                            "slurmd took --chdir LITERALLY — the value it ran in is byte-for-byte \
                             the value submitted. D2-7's premise holds.".to_string()
                        } else {
                            format!(
                                "slurmd CHANGED --chdir: submitted {requested:?}, ran in {p:?}. \
                                 D2-7's premise is wrong and the --chdir control needs re-deriving."
                            )
                        }
                    );
                }
                None => {
                    let _ = writeln!(out, "    the step ran in  : <not recorded — NOT MEASURED>");
                }
            }
            let files: Vec<String> = a
                .files
                .get(&case.id)
                .cloned()
                .unwrap_or_default()
                .iter()
                .filter(|f| f.kind == "file")
                .map(|f| f.name.clone())
                .collect();
            if files.is_empty() {
                let _ = writeln!(
                    out,
                    "    default output   : <nothing appeared — NOT MEASURED, not agreement>"
                );
            } else {
                for f in &files {
                    let _ = writeln!(out, "    default output   : {} (under {})", f, case.dir);
                }
                let _ = writeln!(
                    out,
                    "    -> the DIRECTORY component of the default --output was {}",
                    if files.iter().any(|f| f.contains('%')) {
                        "NOT expanded — D2-7 is refuted for the default path"
                    } else {
                        "expanded — D2-7 is CONFIRMED for the default path"
                    }
                );
            }
            let _ = writeln!(
                out,
                "    husk never submits this: `decide` refuses a --chdir holding a % (RA-6), \
                 so there is no husk-side name here to agree or disagree with."
            );
        }
    }

    // ── what slurmd rendered, per specifier ─────────────────────────────────────────────
    let _ = writeln!(out, "\n-- what slurmd rendered, per specifier --");
    let _ = writeln!(
        out,
        "Decoded from the all-specifier cases by splitting on their literal separators. A\n\
         slot that cannot be decoded unambiguously is printed as AMBIGUOUS, never guessed.\n\
         This is the datum `the_specifier_table_agrees_with_the_recorded_measurements` wants\n\
         for the rows it still records as UNMEASURED."
    );
    for case in &a.cases {
        if !case.pattern.contains("_j-%j_") {
            continue;
        }
        let names: Vec<String> = a
            .files
            .get(&case.id)
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter(|f| f.kind == "file")
            .map(|f| f.name.clone())
            .collect();
        let Some(actual) = names.first() else { continue };
        let _ = writeln!(out, "  {} ({})", case.id, actual);
        for (spec, value) in decode(&case.pattern, actual) {
            let jobid = a.jobs.get(&case.tag).map(|(id, _, _)| id.clone()).unwrap_or_default();
            let env = a
                .env
                .iter()
                .find(|((k, _), _)| *k == jobid)
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            let var = settings::OUTPUT_SPECIFIERS
                .iter()
                .find(|s| s.spec() == spec)
                .map(|s| s.variable())
                .unwrap_or("<not in husk's table>");
            let seen = match env.get(var) {
                Some(EnvVal::Set(v)) => format!("{var}={v:?}"),
                Some(EnvVal::Unset) => format!("{var} UNSET"),
                None => format!("{var} not recorded"),
            };
            let _ = writeln!(out, "    %{spec} -> {value:<20} guard reads {seen}");
        }
    }

    // ── summary ─────────────────────────────────────────────────────────────────────────
    let (ag, dis, ref_, nm) = (
        r.count("AGREE"),
        r.count("DISAGREE"),
        r.count("husk-REFUSES"),
        r.count("not-measured"),
    );
    let conflicts = r.rows.iter().filter(|x| x.oracle_conflict.is_some()).count();
    let _ = writeln!(
        out,
        "\n-- summary --\n  {ag} agree · {dis} DISAGREE · {ref_} husk refuses · {nm} NOT MEASURED"
    );
    if conflicts > 0 {
        let _ = writeln!(
            out,
            "  {conflicts} row(s) where this grader's two oracles disagree. Fix the grader \
             first; those rows are not findings."
        );
    }
    if !dircases.is_empty() {
        let _ = writeln!(
            out,
            "  {} case(s) are in the directory section above rather than the table, because \
             husk refuses them at submit and no comparison exists.",
            dircases.len()
        );
    }
    if nm > 0 {
        let _ = writeln!(
            out,
            "  The {nm} NOT MEASURED row(s) are not agreement. They are cases this run could \
             not answer."
        );
    }
    if !looks_like_slurm {
        let _ = writeln!(
            out,
            "  SOURCE IS NOT SLURM — this exercised the harness. It is not evidence about \
             any cluster."
        );
    }
    r.text = out;
    r
}

/// husk's refusal messages are long by design — they teach the narrowing (`P11`) — and the
/// same one appears on a dozen rows here. The table shows the first sentence; the full text
/// is in the message husk actually emits, which is where a user reads it.
fn first_sentence(why: &str) -> String {
    match why.find(". ") {
        Some(i) if i + 1 < why.len() => format!("{} […]", &why[..=i]),
        _ => why.to_string(),
    }
}

/// Single-quote an argument so the printed `reproduce:` line can be pasted into a shell.
fn shell_quote(a: &str) -> String {
    if !a.is_empty() && a.chars().all(|c| c.is_ascii_alphanumeric() || "-_=/.,:+".contains(c)) {
        a.to_string()
    } else {
        format!("'{}'", a.replace('\'', "'\\''"))
    }
}

/// Split `pattern` into literal segments and `%c` slots and read each slot's value out of
/// `actual`. Returns nothing for a slot it cannot bound on both sides.
fn decode(pattern: &str, actual: &str) -> Vec<(char, String)> {
    let mut slots: Vec<char> = Vec::new();
    let mut lits: Vec<String> = vec![String::new()];
    let mut it = pattern.chars().peekable();
    while let Some(c) = it.next() {
        if c == '%' {
            if let Some(s) = it.next() {
                slots.push(s);
                lits.push(String::new());
            }
        } else {
            lits.last_mut().expect("always one").push(c);
        }
    }
    let mut out = Vec::new();
    let mut pos = 0usize;
    // The leading literal must match exactly, or the whole decode is meaningless.
    if !actual[pos..].starts_with(&lits[0]) {
        return out;
    }
    pos += lits[0].len();
    for (i, spec) in slots.iter().enumerate() {
        let next_lit = &lits[i + 1];
        let end = if next_lit.is_empty() {
            actual.len()
        } else {
            match actual[pos..].find(next_lit.as_str()) {
                Some(k) => pos + k,
                None => {
                    out.push((*spec, "AMBIGUOUS".to_string()));
                    return out;
                }
            }
        };
        out.push((*spec, actual[pos..end].to_string()));
        pos = end + next_lit.len();
    }
    out
}
// ---------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------
//
// WHAT THESE CAN AND CANNOT SHOW (`P10`). Every fixture below was produced by
// `slurm-broker/slurmd-differential-fixture/sbatch`, a fake whose substitution model is a
// copy of what the operator measured by hand on Santis. So these tests prove that the
// harness produces a parseable artefact, that the grader reads it, and that it reaches all
// four dispositions and can reach them in both directions. **They prove nothing about
// slurmd.** No line of this instrument has ever run against a real slurmd; that is what the
// operator's first cluster run is for, and the three known-answer controls are what will
// tell him whether the instrument arrived in one piece.
#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Artefact {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/slurmd-differential")
            .join(name);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("fixture {path:?} must be readable: {e}"));
        parse(&text).unwrap_or_else(|e| panic!("fixture {name} must parse: {e}"))
    }

    #[test]
    fn the_measured_world_records_what_the_refusal_of_percent_a_is_buying() {
        // `RA-2`, end to end and offline. In the world the operator measured, slurmd opens
        // `probe-A<jobid>-a4294967294-sbatch.log` for `--output=probe-A%A-a%a-s%s.log` on a
        // NON-array job, while husk's table renders `${SLURM_ARRAY_JOB_ID:-}` — empty,
        // because the variable is unset there.
        //
        // Since `FIX-A2` husk REFUSES that pattern rather than mis-naming it, so the right
        // disposition is `husk-REFUSES` and not `DISAGREE`. That is the case the brief calls
        // "husk refuses the case entirely, so no disagreement is possible — record it, it
        // justifies the refusal", and this test is what makes the justification concrete:
        // the report must still name BOTH files, because a refusal whose report does not
        // show what it prevented is indistinguishable from a refusal that prevents nothing.
        let a = fixture("measured.artefact");
        let r = grade(&a);
        assert!(r.gradeable, "the measured fixture must grade:\n{}", r.text);
        let row = r.row("j03-o").expect("j03-o is in the corpus");
        match &row.disposition {
            Disposition::HuskRefuses { slurmd, unguarded, .. } => {
                assert!(
                    slurmd.starts_with("probe-A") && slurmd.ends_with("-a4294967294-sbatch.log"),
                    "slurmd's name must be recorded verbatim, got {slurmd:?}"
                );
                assert_eq!(
                    unguarded.as_deref(),
                    Some("probe-A-a-sbatch.log"),
                    "the report must state the name husk's table renders with the RA-2 unset \
                     guard off — that is the file both leaf checks used to run on"
                );
            }
            other => panic!("j03-o must be a refusal, got {other:?}\n{}", r.text),
        }
        assert!(
            r.text.contains("probe-A-a-sbatch.log"),
            "the printed report must name husk's file, not only the artefact's:\n{}",
            r.text
        );
        assert!(
            r.text.contains("THIS IS WHAT THE REFUSAL BUYS"),
            "the report must say what the refusal prevented:\n{}",
            r.text
        );
    }

    #[test]
    fn a_specifier_husk_accepts_and_slurmd_renders_differently_is_a_disagreement() {
        // Can this instrument go RED at all? `B8` is two probes that could not, and both
        // shipped a false green. So one fixture models a world where slurmd renders `%s` as
        // `0` on the batch step while `SLURM_STEP_ID` stays unset — which is not invented:
        // `the_specifier_table_agrees_with_the_recorded_measurements` records `%s`'s pairing
        // as "whether SLURM_STEP_ID is itself set there is UNMEASURED", and RA's probe `P2`
        // asks the question in as many words. husk's `${SLURM_STEP_ID:-batch}` renders
        // `batch`; slurmd renders `0`; the guard would check a file that does not exist.
        //
        // This is the row the real cluster run exists to produce or to rule out.
        let a = fixture("stepid-drift.artefact");
        let r = grade(&a);
        assert!(r.gradeable, "the drift fixture must grade:\n{}", r.text);
        let row = r.row("j01-e").expect("j01-e uses %j only");
        assert_eq!(row.disposition.label(), "AGREE", "%j must still agree:\n{}", r.text);

        let dis: Vec<&Row> =
            r.rows.iter().filter(|x| x.disposition.label() == "DISAGREE").collect();
        assert!(
            !dis.is_empty(),
            "a world where slurmd renders %s differently must produce at least one \
             DISAGREE — an instrument that cannot go red is not an instrument:\n{}",
            r.text
        );
        let d = dis
            .iter()
            .find(|x| x.case == "j02-e")
            .unwrap_or_else(|| panic!("j02-e carries %s:\n{}", r.text));
        match &d.disposition {
            Disposition::Disagree { husk, slurmd } => {
                assert!(husk.contains("s-batch"), "husk names the :-batch default: {husk}");
                assert!(slurmd.contains("s-0"), "slurmd rendered 0: {slurmd}");
            }
            other => panic!("expected a divergence, got {other:?}"),
        }
        assert!(
            r.text.contains("slurmd opens :") && r.text.contains("husk checks  :"),
            "the report must name which file each side means:\n{}",
            r.text
        );
    }

    #[test]
    fn a_world_where_slurmd_matches_husks_table_grades_as_agreement() {
        // The other direction, and it is the one that makes the test above worth anything: a
        // grader that reported DISAGREE unconditionally would pass that test too.
        let a = fixture("husk-world.artefact");
        let r = grade(&a);
        assert!(r.gradeable, "{}", r.text);
        assert_eq!(
            r.count("DISAGREE"),
            0,
            "in a world where slurmd does exactly what husk's table says there is nothing \
             to disagree about:\n{}",
            r.text
        );
        assert!(
            r.count("AGREE") > 0,
            "…and something must actually have been compared:\n{}",
            r.text
        );
    }

    #[test]
    fn the_known_answer_controls_are_checked_and_pass_on_the_measured_fixture() {
        let a = fixture("measured.artefact");
        let r = grade(&a);
        assert_eq!(r.known.len(), KNOWN.len(), "every known answer must be reported on");
        for (case, ok, expected) in &r.known {
            assert!(*ok, "known answer {case} expected {expected:?}\n{}", r.text);
        }
        assert!(r.text.contains("known-answer controls"), "{}", r.text);
    }

    #[test]
    fn a_known_answer_that_comes_out_wrong_is_reported_as_a_harness_fault() {
        // Not as a divergence. A harness whose calibration is wrong is telling you about
        // itself, and the report has to say so in those words or the first cluster run
        // produces a confident finding about the wrong thing (`P11`).
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/slurmd-differential/measured.artefact"),
        )
        .expect("fixture");
        let broken = text.replace("jprobe-", "WRONGPREFIX-");
        let a = parse(&broken).expect("still parses");
        let r = grade(&a);
        assert!(
            r.known.iter().any(|(c, ok, _)| c == "j06-o" && !ok),
            "the %J known answer must go red when the recorded name changes"
        );
        assert!(
            r.text.contains("THIS IS ABOUT THE HARNESS"),
            "the report must attribute it to the harness:\n{}",
            r.text
        );
    }

    #[test]
    fn every_husk_refusal_is_reported_as_a_refusal_and_never_as_agreement() {
        // `%%`, `%J`, `%x`, an unknown `%q`, and a `%` in a directory component are all
        // outside husk's grammar. The grader must not be able to call any of them agreement,
        // and it must still record what slurmd did with them — that record is the only thing
        // that can ever justify or overturn the refusal (`RA-10`: a reason may state husk's
        // policy or a MEASURED fact, never a guess).
        let a = fixture("measured.artefact");
        let r = grade(&a);
        for case in ["j05-o", "j06-o", "j07-o", "j08-o", "j10-o"] {
            let row = r.row(case).unwrap_or_else(|| panic!("{case} missing\n{}", r.text));
            assert_eq!(
                row.disposition.label(),
                "husk-REFUSES",
                "{case} is outside husk's grammar and must be reported as a refusal, got \
                 {:?}\n{}",
                row.disposition,
                r.text
            );
            match &row.disposition {
                Disposition::HuskRefuses { slurmd, .. } => assert!(
                    !slurmd.is_empty(),
                    "{case}: what slurmd did with it is the evidence, and it must be in the \
                     report"
                ),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn a_case_with_no_file_is_not_measured_and_is_never_counted_as_agreement() {
        // The `B8-1` fold, made impossible. An empty case directory is an absence, and an
        // absence is not evidence of agreement.
        let a = fixture("absent-file.artefact");
        let r = grade(&a);
        assert!(r.gradeable, "{}", r.text);
        let row = r.row("j01-o").expect("j01-o");
        assert_eq!(row.disposition.label(), "not-measured", "{:?}\n{}", row.disposition, r.text);
        assert!(
            r.text.contains("NOT MEASURED row(s) are not agreement"),
            "the summary must say so where a reader will see it:\n{}",
            r.text
        );
    }

    #[test]
    fn an_artefact_whose_cluster_side_control_failed_is_refused_outright() {
        let a = fixture("control-failed.artefact");
        let r = grade(&a);
        assert!(!r.gradeable, "a failed control must make the artefact ungradeable:\n{}", r.text);
        assert!(r.refusal.as_deref().unwrap_or("").contains("literal_control_file"));
        assert_eq!(r.count("AGREE"), 0, "and it must produce no rows at all");
        assert!(r.text.contains("Nothing above or below is agreement"), "{}", r.text);
    }

    #[test]
    fn an_artefact_that_stops_mid_run_is_refused_rather_than_read_as_partial() {
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/slurmd-differential/measured.artefact"),
        )
        .expect("fixture");
        let truncated: String = text
            .lines()
            .filter(|l| !l.starts_with("END\t"))
            .collect::<Vec<_>>()
            .join("\n");
        let a = parse(&truncated).expect("parses");
        let r = grade(&a);
        assert!(!r.gradeable);
        assert!(r.refusal.as_deref().unwrap_or("").contains("no `END` line"), "{:?}", r.refusal);
    }

    #[test]
    fn a_dry_run_artefact_is_refused_because_it_measured_nothing() {
        let a = fixture("dry-run.artefact");
        let r = grade(&a);
        assert!(!r.gradeable);
        assert!(r.refusal.as_deref().unwrap_or("").contains("DRY RUN"), "{:?}", r.refusal);
    }

    #[test]
    fn a_record_type_this_grader_does_not_know_makes_the_artefact_ungradeable() {
        // `P8` in the one direction that matters here: the harness and the grader are two
        // halves of one format, and the half that would report green on a drift is this one.
        // So an unrecognised record is a refusal, not a skipped line.
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/slurmd-differential/measured.artefact"),
        )
        .expect("fixture");
        let a = parse(&format!("{text}\nNEWTHING\tj03-o\tsomething the cluster measured\n"))
            .expect("parses");
        assert_eq!(a.unknown.len(), 1);
        let r = grade(&a);
        assert!(!r.gradeable, "{}", r.text);
        assert!(r.refusal.as_deref().unwrap_or("").contains("does not understand"));
    }

    #[test]
    fn an_env_record_that_is_neither_set_nor_unset_is_an_error() {
        // husk's `${VAR:-}` and its `[ -n "${VAR:-}" ]` guard treat unset and set-empty the
        // same, and this grader has to be able to tell them apart to reproduce either. It
        // must not default one to the other.
        let err = parse("HUSKDIFF\t1\nENV\t1\tnone\tUSER\tMAYBE\tx\n").unwrap_err();
        assert!(err.contains("neither SET nor UNSET"), "{err}");
    }

    #[test]
    fn an_artefact_from_something_that_is_not_slurm_is_flagged_in_every_summary() {
        // The `B8-2` shape. The harness records `sbatch --version` verbatim; the grader is
        // what decides whether that string is SLURM, because the party being checked must
        // not author the record that clears it (`P2`).
        let a = fixture("measured.artefact");
        let r = grade(&a);
        assert!(
            r.text.contains("SOURCE IS NOT SLURM"),
            "every fixture artefact must be labelled as one, at the top and in the \
             summary:\n{}",
            r.text
        );
    }

    #[test]
    fn the_two_oracles_agree_on_every_fixture_row() {
        // `RA-4` turned on this file. The disposition comes from running husk's REAL emitted
        // bash; the NAME comes from this module's own expansion of the same table. They are
        // two routes to one answer, and a conflict is a defect HERE. It is surfaced as
        // loudly as a finding so it can never be read as one.
        for name in ["measured.artefact", "husk-world.artefact", "stepid-drift.artefact"] {
            let r = grade(&fixture(name));
            let bad: Vec<&Row> = r.rows.iter().filter(|x| x.oracle_conflict.is_some()).collect();
            assert!(
                bad.is_empty(),
                "{name}: {} row(s) where the emitted guard and this module's expansion tell \
                 different stories:\n{:#?}",
                bad.len(),
                bad
            );
        }
    }

    #[test]
    fn the_report_states_what_slurmd_rendered_for_each_specifier() {
        // The datum `the_specifier_table_agrees_with_the_recorded_measurements` still lacks
        // for `%N`, `%n`, `%t`, `%s` and `%u`. Decoding it is the point of the all-specifier
        // case; a slot that cannot be bounded is printed AMBIGUOUS rather than guessed.
        let r = grade(&fixture("measured.artefact"));
        assert!(r.text.contains("what slurmd rendered, per specifier"), "{}", r.text);
        for spec in settings::OUTPUT_SPECIFIERS {
            assert!(
                r.text.contains(&format!("%{} ->", spec.spec())),
                "%{} must appear in the per-specifier decode:\n{}",
                spec.spec(),
                r.text
            );
        }
        assert!(
            r.text.contains("guard reads SLURM_STEP_ID UNSET"),
            "…paired with what the guard would have read, which is the half that decides \
             whether husk's default is a stand-in or a guess:\n{}",
            r.text
        );
    }

    #[test]
    fn the_directory_case_is_reported_on_its_own_terms_and_never_as_a_comparison() {
        // `D2-7` has been INCONCLUSIVE since the round opened, and `RA §7` names the one job
        // that settles it. That job has no `--output` at all, so there is no husk-side name:
        // husk refuses a `--chdir` holding a `%` at submit (`RA-6`). Filing it as AGREE or
        // DISAGREE would be inventing a comparison, so it gets its own section — and the
        // section has to state BOTH halves, because `RA §7` is the record of a `--chdir`
        // measurement being read as an answer about `--output`.
        let r = grade(&fixture("measured.artefact"));
        assert!(r.row("j11-o").is_none(), "j11-o must not appear as a comparison row");
        assert!(r.text.contains("directory questions (D2-7)"), "{}", r.text);
        assert!(
            r.text.contains("slurmd took --chdir LITERALLY"),
            "the --chdir half must be decided by comparing the submitted value with the \
             directory the step ran in, and stated:\n{}",
            r.text
        );
        assert!(
            r.text.contains("D2-7 is refuted for the default path"),
            "…and the --output half must be decided separately, from where the default \
             output landed:\n{}",
            r.text
        );
        assert!(
            r.text.contains("no husk-side name here to agree or disagree with"),
            "…and the section must say why it is not in the table:\n{}",
            r.text
        );
    }

    #[test]
    fn decoding_refuses_to_guess_a_slot_it_cannot_bound() {
        assert_eq!(
            decode("a-%j_b-%N.log", "a-77_b-nid1.log"),
            vec![('j', "77".to_string()), ('N', "nid1".to_string())]
        );
        // The separator is missing from the actual name, so the second slot has no left
        // bound. It must say so, not split somewhere plausible.
        assert_eq!(
            decode("a-%j_b-%N.log", "a-77XXXnid1.log"),
            vec![('j', "AMBIGUOUS".to_string())]
        );
    }

    /// Grade the artefact named by `HUSK_DIFFERENTIAL_ARTEFACT`, and claim nothing without
    /// one.
    ///
    /// **A green here with the variable unset means nothing at all** — it is the one test in
    /// this file that can be vacuous, and it says so on stdout rather than looking like a
    /// pass. The meaningful greens are the fixture tests above, which always run. The
    /// meaningful RED is this one, on a real cluster artefact.
    #[test]
    fn a_named_artefact_agrees_with_husks_table_and_nothing_is_claimed_without_one() {
        let Ok(path) = std::env::var("HUSK_DIFFERENTIAL_ARTEFACT") else {
            println!(
                "slurmd-differential: NOT GRADED — HUSK_DIFFERENTIAL_ARTEFACT is unset, so \
                 this test asserted nothing about any cluster."
            );
            return;
        };
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read the artefact at {path}: {e}"));
        let a = parse(&text).unwrap_or_else(|e| panic!("{path} is not a valid artefact: {e}"));
        let r = grade(&a);
        println!("{}", r.text);
        assert!(
            r.gradeable,
            "the artefact at {path} cannot be graded: {}",
            r.refusal.unwrap_or_default()
        );
        for (case, ok, expected) in &r.known {
            assert!(
                *ok,
                "known-answer control {case} did not come back as {expected:?}. Settle the \
                 harness before reading anything else in this run as a finding."
            );
        }
        assert_eq!(
            r.count("DISAGREE"),
            0,
            "husk's table disagrees with this site's slurmd — see the report above. Each row \
             names the file slurmd opens and the file husk's guard checks; the guard's leaf \
             controls run on the second one."
        );
        assert_eq!(
            r.count("not-measured"),
            0,
            "some cases produced no answer. That is not agreement — re-run those cases."
        );
    }
}
