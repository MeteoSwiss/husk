//! The **step** allowlist: what an in-cage `srun` may ask the step-broker to launch.
//!
//! Same discipline as `sbatch.rs`, one level down — see SRUN-MPI-DESIGN.md "What the
//! step-broker validates". The broker does not forward the agent's command line; it
//! BUILDS the `srun` invocation from this registry, so an option nobody modelled cannot
//! reach `slurmstepd`. The parsing machinery is shared with `sbatch.rs` (one parser, one
//! set of getopt edge cases) and only the option table differs.
//!
//! Two things make this different from the sbatch surface:
//!
//! 1. **The command is not allowlisted — it is WRAPPED.** srun's trailing positional is
//!    the user's program, and vetting arbitrary program names would be theatre. Instead
//!    every task is launched as
//!    `srun <validated opts> -- seccomp-wrapper --profile=... bwrap <rank cage> -- <cmd>`,
//!    so whatever runs is caged. The wrap is forced by the broker and cannot be opted
//!    out of by the stub.
//! 2. **Some options must be REJECTED, not dropped.** An option that runs code outside
//!    the per-task wrap defeats (1) entirely. Dropping it silently would also change
//!    what the job does without saying so, so they carry `Class::Rejected` with a reason.
//!
//! Deliberately NOT here, and why: `--nodelist`/`--exclude` (avoiding a flaky node is a
//! JOB-level choice — both are already Allowed in `sbatch.rs`, and a single-node step has
//! exactly one node to pick from), and `--cpu-freq` (site-restricted, nothing needs it;
//! the rejection message names it if that changes).
//!
//! The registry starts deliberately SMALL. Rejecting an option a real workload needs
//! costs one line and produces a message that says exactly what to add; allowing one
//! nobody has thought about is how gates get holes. Same loop as "unsupported sbatch
//! option → add it to the registry" (BRINGUP.md, Probe F).

use crate::sbatch::{Class, OptSpec, Registry};

macro_rules! spec {
    ($long:expr, $short:expr, $takes:expr, $class:expr, $validate:expr) => {
        OptSpec {
            long: $long,
            short: $short,
            aliases: &[],
            takes_value: $takes,
            class: $class,
            validate: $validate,
        }
    };
}

fn always_true(_: &str) -> bool {
    true
}
fn bounded(s: &str, max: usize, ok: impl Fn(char) -> bool) -> bool {
    !s.is_empty() && s.len() <= max && s.chars().all(ok)
}
fn v_uint(s: &str) -> bool {
    bounded(s, 9, |c| c.is_ascii_digit())
}
fn v_time(s: &str) -> bool {
    bounded(s, 15, |c| c.is_ascii_digit() || c == ':' || c == '-')
}
fn v_size(s: &str) -> bool {
    bounded(s, 16, |c| {
        c.is_ascii_digit() || c == '.' || "KMGTPEkmgtpe".contains(c)
    })
}
fn v_gres(s: &str) -> bool {
    bounded(s, 128, |c| c.is_ascii_alphanumeric() || "_,:.-".contains(c))
}
fn v_bind(s: &str) -> bool {
    bounded(s, 64, |c| c.is_ascii_alphanumeric() || "_,:.-".contains(c))
}
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
fn v_dist(s: &str) -> bool {
    bounded(s, 40, |c| c.is_ascii_alphanumeric() || ",:*=".contains(c))
}
/// `--hint` is a closed set of four keywords; an exact enum beats any charset.
fn v_hint(s: &str) -> bool {
    matches!(
        s,
        "compute_bound" | "memory_bound" | "multithread" | "nomultithread"
    )
}

/// The step option table. Anything absent is rejected with the generic
/// "unsupported srun option" message — default-deny, by construction.
pub const REGISTRY: &[OptSpec] = &[
    // ---- resource shape the agent may choose (validated + re-emitted canonically) ----
    spec!("--ntasks", "-n", true, Class::Allowed, v_uint),
    spec!("--ntasks-per-node", "", true, Class::Allowed, v_uint),
    spec!("--cpus-per-task", "-c", true, Class::Allowed, v_uint),
    spec!("--threads-per-core", "", true, Class::Allowed, v_uint),
    spec!("--gpus", "-G", true, Class::Allowed, v_gres),
    spec!("--gpus-per-task", "", true, Class::Allowed, v_gres),
    spec!("--gres", "", true, Class::Allowed, v_gres),
    spec!("--mem", "", true, Class::Allowed, v_size),
    spec!("--mem-per-cpu", "", true, Class::Allowed, v_size),
    spec!("--time", "-t", true, Class::Allowed, v_time),
    spec!("--cpu-bind", "", true, Class::Allowed, v_bind),
    spec!("--gpu-bind", "", true, Class::Allowed, v_bind),
    // NUMA memory placement (`local`, `map_mem:0,1`, `mask_mem:0x3`). Binding is
    // naturally per-task, so the step is where it belongs; it is already Allowed for
    // sbatch, and it is the same family as `numactl --membind`, which ICON's own
    // launcher uses. Performance, not containment: set_mempolicy/mbind cannot reach
    // outside the job's cpuset.
    spec!("--mem-bind", "", true, Class::Allowed, v_bind),
    spec!("--distribution", "-m", true, Class::Allowed, v_dist),
    spec!("--hint", "", true, Class::Allowed, v_hint),
    spec!("--exclusive", "", false, Class::Allowed, always_true),
    spec!("--overlap", "", false, Class::Allowed, always_true),
    spec!("--label", "-l", false, Class::Allowed, always_true),
    spec!("--unbuffered", "-u", false, Class::Allowed, always_true),
    // ---- broker-owned: the agent's occurrence is dropped, the broker emits its own ----
    // --nodes: the cage profile owns the topology (single node), exactly as for sbatch.
    spec!("--nodes", "-N", true, Class::Forced, always_true),
    spec!("--chdir", "-D", true, Class::Forced, always_true),
    spec!("--output", "-o", true, Class::Forced, always_true),
    spec!("--error", "-e", true, Class::Forced, always_true),
    // --mpi selects the PMI plugin. MpiDefault=cray_shasta works on Alps (measured), so
    // the broker leaves it alone rather than forcing a value; an agent-chosen plugin is
    // dropped because picking pmix silently produced independent single-rank jobs
    // instead of one communicator (run 8) — a wrong answer that looks like success.
    spec!("--mpi", "", true, Class::Forced, always_true),
    // ---- recognised and refused, with a reason ----
    // Each of these runs code, or names code to run, OUTSIDE the per-task wrap — which
    // is the one thing the wrap exists to prevent.
    spec!("--task-prolog", "", true, Class::Rejected(
        "it runs a script around every task, outside husk's per-task sandbox. Put the setup \
         in your job script instead, which runs inside the cage."), always_true),
    spec!("--task-epilog", "", true, Class::Rejected(
        "it runs a script around every task, outside husk's per-task sandbox. Put the teardown \
         in your job script instead, which runs inside the cage."), always_true),
    spec!("--prolog", "", true, Class::Rejected(
        "it runs a script outside husk's per-task sandbox."), always_true),
    spec!("--epilog", "", true, Class::Rejected(
        "it runs a script outside husk's per-task sandbox."), always_true),
    spec!("--multi-prog", "", true, Class::Rejected(
        "it maps ranks to different programs through a config file husk does not parse, so the \
         per-task sandbox could not be applied uniformly. Launch one program per step."), always_true),
    spec!("--bcast", "", true, Class::Rejected(
        "it copies a file onto the compute nodes outside the cage's filesystem policy. Stage \
         data through your workdir instead."), always_true),
    spec!("--bcast-exclude", "", true, Class::Rejected(
        "it only qualifies --bcast, which is not permitted."), always_true),
    spec!("--pty", "", false, Class::Rejected(
        "it starts an interactive terminal session, which husk does not broker."), always_true),
    spec!("--export", "", true, Class::Rejected(
        "the job environment is inherited from the submission, not chosen per step."), always_true),
    spec!("--get-user-env", "", false, Class::Rejected(
        "it re-imports a login environment into the step, bypassing the submission's env."), always_true),
];

/// A validated step: the options to hand `srun`, and the command to wrap.
#[derive(Debug, PartialEq, Eq)]
pub struct Step {
    /// Canonical, re-emitted options — never a raw agent token.
    pub options: Vec<String>,
    /// The user's program and its arguments, to be launched INSIDE the rank cage.
    /// Not validated: it is wrapped, not vetted.
    pub command: Vec<String>,
}

const REG: Registry = REGISTRY;

/// Interpret an in-cage `srun` argv as an allowlist. Returns the canonical options plus
/// the command to wrap, or a rejection message meant to be read by whoever wrote the
/// job script.
pub fn interpret(argv: &[String]) -> Result<Step, String> {
    // Normalise getopt-glued short options FIRST (`-n4` -> `-n`, `4`), so a glued form
    // cannot slip past the same gate its separated spelling would hit. (F13/F14, one
    // level down.)
    let split = crate::sbatch::split_glued_short_opts_in(REG, argv);
    let (opts, command) = crate::sbatch::split_options_and_rest_in(REG, &split);

    if command.is_empty() {
        return Err(
            "srun needs a command to run. husk launches it inside a per-task sandbox, so \
             the interactive forms (srun with no command, --pty) are not available."
                .to_string(),
        );
    }
    let options = crate::sbatch::interpret_cli_in(REG, "srun", &opts)?;
    Ok(Step { options, command })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn accepts_the_icon_shape_and_canonicalises_it() {
        // What ICON's runscript actually issues, in its actual spelling.
        let st = interpret(&v(&[
            "-n1",
            "--ntasks-per-node",
            "1",
            "--threads-per-core=1",
            "/path/to/icon",
        ]))
        .expect("a real single-rank launch must be accepted");
        assert_eq!(
            st.options,
            v(&["--ntasks=1", "--ntasks-per-node=1", "--threads-per-core=1"]),
            "options must be re-emitted canonically, with no raw agent token"
        );
        assert_eq!(st.command, v(&["/path/to/icon"]));
    }

    #[test]
    fn keeps_the_command_and_its_arguments_intact() {
        // The command is wrapped, not vetted — including args that look like options.
        let st = interpret(&v(&["-n", "2", "--", "./solver", "--verbose", "-x"])).unwrap();
        assert_eq!(st.options, v(&["--ntasks=2"]));
        assert_eq!(st.command, v(&["./solver", "--verbose", "-x"]));
    }

    #[test]
    fn rejects_options_that_run_code_outside_the_wrap() {
        // The wrap is the whole mechanism; anything that escapes it must not be dropped
        // silently, it must be refused WITH the reason.
        for (argv, needle) in [
            (v(&["--task-prolog=/tmp/p.sh", "./a"]), "per-task sandbox"),
            (v(&["--task-epilog", "/tmp/e.sh", "./a"]), "per-task sandbox"),
            (v(&["--multi-prog", "conf", "./a"]), "one program per step"),
            (v(&["--bcast=/tmp/x", "./a"]), "workdir"),
            (v(&["--pty", "./a"]), "interactive"),
            (v(&["--export=ALL", "./a"]), "inherited from the submission"),
            (v(&["--get-user-env", "./a"]), "login environment"),
        ] {
            let err = interpret(&argv).expect_err("must be rejected");
            assert!(err.contains("not permitted"), "{argv:?} -> {err}");
            assert!(err.contains(needle), "reason must be specific: {argv:?} -> {err}");
        }
    }

    #[test]
    fn rejects_an_unmodelled_option_rather_than_forwarding_it() {
        let err = interpret(&v(&["--wckey=abc", "./a"])).expect_err("must be rejected");
        assert!(err.contains("unsupported srun option"), "{err}");
        assert!(!err.contains("sbatch"), "message must name srun, not sbatch: {err}");
    }

    #[test]
    fn drops_broker_owned_options_instead_of_forwarding_them() {
        // The agent may not choose the topology, the working directory, where output
        // goes, or the PMI plugin: the broker emits those itself.
        let st = interpret(&v(&[
            "-N", "4", "--chdir=/evil", "-o", "/users/victim/.bashrc", "--mpi=pmix", "./a",
        ]))
        .expect("owned options are dropped, not rejected");
        assert!(st.options.is_empty(), "nothing agent-chosen may survive: {:?}", st.options);
    }

    #[test]
    fn rejects_an_out_of_grammar_value() {
        let err = interpret(&v(&["--cpu-bind=cores;id", "./a"])).expect_err("must be rejected");
        assert!(err.contains("not allowed"), "{err}");
    }

    #[test]
    fn rejects_a_step_with_no_command() {
        // srun with no command is the interactive form; there is nothing to wrap.
        let err = interpret(&v(&["-n", "4"])).expect_err("must be rejected");
        assert!(err.contains("needs a command"), "{err}");
    }

    #[test]
    fn glued_short_options_cannot_evade_the_gate() {
        // -c4 must be validated exactly as -c 4 is; and a glued form of a dropped
        // option must still be dropped rather than forwarded.
        let st = interpret(&v(&["-c4", "./a"])).unwrap();
        assert_eq!(st.options, v(&["--cpus-per-task=4"]));
        let st = interpret(&v(&["-N4", "./a"])).unwrap();
        assert!(st.options.is_empty(), "{:?}", st.options);
    }

    #[test]
    fn node_selection_stays_a_job_level_choice() {
        // --nodelist/--exclude are how you avoid a flaky node, and that is decided when
        // the JOB picks its node: both are Allowed in sbatch.rs. A single-node step has
        // one node to choose from, so allowing them here would be dead surface.
        for argv in [
            v(&["--nodelist=nid001000", "./a"]),
            v(&["-x", "nid001000", "./a"]),
            v(&["--cpu-freq=High", "./a"]),
        ] {
            let err = interpret(&argv).expect_err("must be rejected");
            assert!(err.contains("unsupported srun option"), "{argv:?} -> {err}");
        }
    }

    #[test]
    fn accepts_icons_real_distribution_value() {
        // The first option ICON's runscript tripped on (Balfrin 2026-07-30):
        //   srun -n 4 --ntasks-per-node 4 --threads-per-core=1 --distribution=plane=4 ...
        let st = interpret(&v(&[
            "-n", "4", "--ntasks-per-node", "4", "--threads-per-core=1",
            "--distribution=plane=4", "/path/wrapper.sh", "/path/icon",
        ]))
        .expect("ICON's real srun line must be accepted");
        assert!(st.options.contains(&"--distribution=plane=4".to_string()), "{:?}", st.options);
        assert_eq!(st.command, v(&["/path/wrapper.sh", "/path/icon"]));
    }

    #[test]
    fn distribution_still_refuses_shell_syntax() {
        for bad in ["plane=4;id", "block cyclic", "plane=$(id)"] {
            assert!(interpret(&v(&[&format!("--distribution={bad}"), "./a"])).is_err(), "{bad}");
        }
    }

    #[test]
    fn allows_numa_memory_binding() {
        let st = interpret(&v(&["--mem-bind=local", "./a"])).unwrap();
        assert_eq!(st.options, v(&["--mem-bind=local"]));
        let st = interpret(&v(&["--mem-bind", "map_mem:0,1", "./a"])).unwrap();
        assert_eq!(st.options, v(&["--mem-bind=map_mem:0,1"]));
    }

    #[test]
    fn every_value_grammar_refuses_shell_metacharacters() {
        // Registry invariant: no Allowed value option may accept whitespace or a shell
        // metacharacter, whatever else it permits. Loops the whole table, so a newly
        // added option is covered the day it lands.
        for s in REGISTRY {
            if !matches!(s.class, Class::Allowed) || !s.takes_value {
                continue;
            }
            for bad in ["a b", "a;b", "a|b", "a&b", "a$b", "a`b", "a\nb", "a'b", "a\"b", "../x"] {
                assert!(
                    !(s.validate)(bad),
                    "{} accepts {bad:?} — a value grammar must never admit shell syntax",
                    s.long
                );
            }
        }
    }
}
