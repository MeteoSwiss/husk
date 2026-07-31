//! The per-task wrapper: how the step-broker turns a validated step into caged ranks.
//!
//! The step-broker launches
//!
//! ```text
//! srun <validated opts> -- sh -c <SCRIPT> husk-rank <user command...>
//! ```
//!
//! and `SCRIPT` re-execs into the rank cage. Two of the cage's paths cannot be computed
//! by the broker and must be resolved **inside the task**:
//!
//! * the per-step `apinfo` directory — the step id does not exist until slurmctld
//!   creates the step, which is after the broker has finished building the command line;
//! * the per-job `/dev/shm` subdirectory — created on whichever node the task lands on.
//!
//! Same "glob in the guard, not in the broker" pattern as the GPU device binds and the
//! MUNGE mask: the compute node knows things the submitting side cannot.
//!
//! **The user's command is never interpolated into the script.** It is passed as
//! separate argv elements after `$0`, so the script reaches it as `"$@"` and no amount
//! of shell metacharacters in a program name or argument can change what runs. Only
//! broker-derived values are substituted, and those are shell-quoted.

use crate::profile::Profile;
use crate::settings::sh_quote;

/// Scheduler- and PMI-owned name prefixes. These are INPUTS TO srun's own option
/// handling and to the MPI bootstrap, so letting the caged side set them is the same
/// mistake as forwarding raw option bytes into a second parser: `SLURM_NTASKS` would
/// contradict the validated `--ntasks`, `SLURM_EXPORT_ENV` would redirect propagation,
/// and `PMI_*`/`PALS_*` steer the wire-up whose apinfo path the cage binds.
/// `HUSK_` is ours for the same reason: `HUSK_STEP_SPOOL` tells a stub where to send
/// requests, so letting the caged side set it would let a rank redirect its own
/// brokering. Our control plane is no more forwardable than the scheduler's.
const RESERVED_ENV_PREFIXES: &[&str] =
    &["SLURM_", "SBATCH_", "PMI_", "PMIX_", "PALS_", "HUSK_"];

/// Upper bound on forwarded variables. The spool is agent-writable, so an enormous
/// environment would otherwise become an enormous command line in the trusted process.
const MAX_FORWARDED_ENV: usize = 512;

/// A POSIX environment variable name. Enforced rather than assumed because these names
/// become ARGUMENTS to bwrap: a name like `--bind` or `-i` would be read as an option by
/// whatever parses them next. Restricting to the portable charset makes an option-shaped
/// name unrepresentable instead of merely unlikely.
fn is_valid_env_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 128
        && n.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Turn the job script's environment into cage arguments — but only the DELTA against
/// the environment the ranks already inherit.
///
/// **Why a delta.** `srun` propagates its own environment to the tasks, and the
/// step-broker's environment is the job's, so the ranks already have almost everything.
/// Forwarding the lot re-sets hundreds of identical values, buries the meaningful ones,
/// and puts an enormous command line through the trusted process. What a run script
/// actually needs carried across is what it CHANGED:
/// ```text
/// export OMP_NUM_THREADS=4
/// srun ./solver          # <- this, and nothing else
/// ```
/// So: added or modified names become `--setenv`, and names the script removed become
/// `--unsetenv`. Both directions, because a half-carried environment differs silently
/// from what the script asked for, which is the failure mode this exists to remove.
///
/// **Why through bwrap rather than srun's environment.** A brokered `srun` breaks the
/// chain by which a run script's `export` reaches its ranks: the script runs inside the
/// cage, the real `srun` outside it. Handing these to `srun` would fix that and open an
/// escape — the rank wrapper's first process is a dynamically linked `/bin/sh` running as
/// the user BEFORE any cage exists, so an `LD_PRELOAD` in that environment would execute
/// arbitrary code with `/users` fully visible. (`seccomp-wrapper` is statically linked and
/// immune; `sh` and `bwrap` are not.) bwrap applies `--setenv` to the process it launches
/// INSIDE the sandbox, so the pre-cage chain never sees these values. `LD_PRELOAD` then
/// reaches only the caged command, where it buys nothing — a rank can already run whatever
/// it likes in its own cage. Structural, not a denylist of loader names.
///
/// `deny` is the configured credential list (`sandbox.credentials.envVars`), which the
/// cage masks with `--unsetenv`. bwrap applies arguments IN ORDER, so re-setting one of
/// those here would silently undo the masking — hence they are dropped outright.
pub fn env_args(
    job_env: &std::collections::BTreeMap<String, String>,
    base_env: &std::collections::BTreeMap<String, String>,
    deny: &[String],
) -> Vec<String> {
    let forwardable = |k: &String| {
        is_valid_env_name(k)
            && !RESERVED_ENV_PREFIXES.iter().any(|p| k.starts_with(p))
            && !deny.iter().any(|d| d == k)
    };

    let mut out = Vec::new();
    let mut n = 0;
    // Added or changed by the job script.
    for (k, v) in job_env {
        if !forwardable(k) || base_env.get(k) == Some(v) {
            continue;
        }
        if n >= MAX_FORWARDED_ENV {
            eprintln!(
                "step-broker: job changed more than {MAX_FORWARDED_ENV} environment \
                 variables; the rest are not carried into the step"
            );
            break;
        }
        out.push("--setenv".to_string());
        out.push(k.clone());
        out.push(v.clone());
        n += 1;
    }
    // Removed by the job script. `unset FOO; srun ...` must not leave FOO set.
    for k in base_env.keys() {
        if forwardable(k) && !job_env.contains_key(k) {
            out.push("--unsetenv".to_string());
            out.push(k.clone());
        }
    }
    out
}

/// Build the argv that follows srun's options: `sh -c <script> husk-rank <command...>`.
///
/// `spool_dir` is Slurm's `SlurmdSpoolDir` as resolved by the step-broker (trusted);
/// `rank_args` are the static bwrap arguments from `FsPolicy::rank_bwrap_args`.
pub fn wrap_command(
    profile: Profile,
    rank_args: &[String],
    spool_dir: &str,
    holder_pid: u32,
    command: &[String],
) -> Vec<String> {
    let bwrap = rank_args
        .iter()
        .map(|s| sh_quote(s))
        .collect::<Vec<_>>()
        .join(" ");
    let userns = crate::cage::userns_path(holder_pid);

    // NOTE on the /dev/shm directory: /dev/shm is world-writable and sticky, so another
    // user on the node could PRE-CREATE `husk-<jobid>` (job ids are guessable) and then
    // read this job's shared-memory segments. The sticky bit stops them deleting our
    // entries, not creating the directory first. So the script refuses to proceed unless
    // the directory is owned by us — `mkdir -m 700` for the normal case, `[ -O ]` for the
    // adversarial one. Ranks race to create it; all but one get EEXIST, which is fine.
    // The rank joins the JOB'S SHARED USER NAMESPACE instead of letting bwrap make its
    // own. That single share is what legalises rank-to-rank CMA: sibling user namespaces
    // cannot ptrace_may_access each other, so Cray MPICH's intra-node transfers died with
    // EPERM regardless of the seccomp filter. Mount and network namespaces stay per rank —
    // identical copies from identical arguments, and they never cost a capability.
    //
    // Checked before use so the failure is a sentence rather than a shell diagnostic: if
    // the holder is gone the rank must DIE, never fall back to a namespace of its own,
    // which would run the workload in a cage that cannot talk to its peers and would look
    // like an MPI bug. `bwrap --userns` is itself fail-closed — it exits rather than
    // inventing a namespace — so this is the readable half of a belt-and-braces pair.
    let script = format!(
        "set -u\n\
         _u={userns}\n\
         if [ ! -r \"$_u\" ]; then\n\
         echo \"husk: the job's cage holder is gone ($_u) - refusing to run this rank\" >&2\n\
         exit 1\n\
         fi\n\
         exec 9<\"$_u\"\n\
         _d=/dev/shm/husk-${{SLURM_JOB_ID}}\n\
         mkdir -m 700 \"$_d\" 2>/dev/null || true\n\
         if [ ! -O \"$_d\" ]; then\n\
         echo \"husk: $_d exists and is not owned by this user - refusing to share it\" >&2\n\
         exit 1\n\
         fi\n\
         _s={spool}/mpi_cray_shasta/${{SLURM_JOB_ID}}.${{SLURM_STEP_ID}}\n\
         exec seccomp-wrapper --profile={sec} bwrap --userns 9 {bwrap} \
         --bind \"$_d\" /dev/shm --bind-try \"$_s\" \"$_s\" -- \"$@\"\n",
        userns = sh_quote(&userns),
        spool = sh_quote(spool_dir),
        sec = profile.seccomp_profile(),
    );

    let mut argv = vec![
        "sh".to_string(),
        "-c".to_string(),
        script,
        // $0 for the script. Never the user's program: that must land in "$@".
        "husk-rank".to_string(),
    ];
    argv.extend(command.iter().cloned());
    argv
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::FsPolicy;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    /// A pid whose `/proc/<pid>/ns/user` really exists, so the script's fail-closed
    /// holder check passes and the rest of the script gets to run. Our own pid is the
    /// natural stand-in for a live cage holder.
    fn live_holder() -> u32 {
        std::process::id()
    }

    fn built(command: &[&str]) -> Vec<String> {
        let rank = FsPolicy::default().rank_bwrap_args("/work");
        wrap_command(Profile::SingleNode, &rank, "/var/spool/slurmd", live_holder(), &v(command))
    }

    fn envmap(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn forwards_the_job_scripts_variables_into_the_cage() {
        let base = envmap(&[("PATH", "/bin"), ("HOME", "/home/u")]);
        let job = envmap(&[("PATH", "/bin"), ("HOME", "/home/u"),
                           ("OMP_NUM_THREADS", "4"), ("MPICH_GPU_SUPPORT_ENABLED", "1")]);
        let args = env_args(&job, &base, &[]);
        assert!(!args.contains(&"PATH".to_string()), "unchanged vars must not be re-set: {args:?}");
        assert!(args.windows(3).any(|w| w == ["--setenv", "OMP_NUM_THREADS", "4"]), "{args:?}");
        assert!(args.windows(3).any(|w| w == ["--setenv", "MPICH_GPU_SUPPORT_ENABLED", "1"]), "{args:?}");
    }

    #[test]
    fn a_variable_the_script_removed_is_unset_in_the_step() {
        // `unset MPICH_FOO; srun ...` must not leave it set: a half-carried environment
        // differs silently from what the script asked for.
        let base = envmap(&[("MPICH_FOO", "1"), ("PATH", "/bin")]);
        let job = envmap(&[("PATH", "/bin")]);
        let args = env_args(&job, &base, &[]);
        assert_eq!(args, vec!["--unsetenv", "MPICH_FOO"], "{args:?}");
    }

    #[test]
    fn scheduler_owned_names_are_never_forwarded() {
        // These steer srun's own option handling and the PMI bootstrap. Letting the
        // caged side set them is the same mistake as forwarding raw option bytes into a
        // second parser: SLURM_NTASKS would contradict the validated --ntasks.
        let args = env_args(
            &envmap(&[
                ("SLURM_NTASKS", "99"),
                ("SLURM_EXPORT_ENV", "ALL"),
                ("SBATCH_PARTITION", "other"),
                ("PMI_RANK", "7"),
                ("PMIX_NAMESPACE", "x"),
                ("PALS_APINFO", "/tmp/evil"),
                ("HUSK_STEP_SPOOL", "/tmp/evil-spool"),
                ("KEEPME", "yes"),
            ]),
            &envmap(&[]),
            &[],
        );
        assert!(!args.iter().any(|a| a.starts_with("SLURM_")), "{args:?}");
        assert!(!args.iter().any(|a| a.starts_with("SBATCH_")), "{args:?}");
        assert!(!args.iter().any(|a| a.starts_with("PMI")), "{args:?}");
        assert!(!args.iter().any(|a| a.starts_with("PALS_")), "{args:?}");
        assert!(!args.iter().any(|a| a.starts_with("HUSK_")),
                "a rank must not be able to redirect its own brokering: {args:?}");
        assert!(args.contains(&"KEEPME".to_string()), "benign vars still pass: {args:?}");
    }

    #[test]
    fn a_forwarded_variable_cannot_undo_credential_masking() {
        // The cage masks configured credentials with --unsetenv, and bwrap applies
        // arguments IN ORDER — so re-setting one here would silently re-expose it.
        let args = env_args(&envmap(&[("AWS_SECRET_ACCESS_KEY", "sk-leaked"), ("PATH", "/bin")]),
                            &envmap(&[]), &["AWS_SECRET_ACCESS_KEY".to_string()]);
        assert!(!args.iter().any(|a| a.contains("sk-leaked")), "{args:?}");
        assert!(args.contains(&"PATH".to_string()), "{args:?}");
    }

    #[test]
    fn option_shaped_and_malformed_names_are_dropped() {
        // Names become ARGUMENTS to bwrap, so one that looks like an option would be
        // read as one by whatever parses them next.
        let args = env_args(
            &envmap(&[("--bind", "/etc"), ("-i", "x"), ("a b", "x"), ("1FIRST", "x"),
                      ("HAS=EQUALS", "x"), ("", "x"), ("GOOD_1", "ok")]),
            &envmap(&[]),
            &[],
        );
        assert_eq!(args, vec!["--setenv", "GOOD_1", "ok"], "only a portable name survives: {args:?}");
    }

    #[test]
    fn ld_preload_reaches_only_the_caged_command() {
        // THE POINT OF THE DESIGN. The rank wrapper's first process is a dynamically
        // linked /bin/sh running BEFORE any cage exists; an LD_PRELOAD in ITS environment
        // would run arbitrary code as the user with /users visible. Via bwrap --setenv the
        // value is applied to the sandboxed process instead, where it buys nothing.
        let cage = {
            let mut c = FsPolicy::default().rank_bwrap_args("/work");
            c.extend(env_args(&envmap(&[("LD_PRELOAD", "/tmp/evil.so")]), &envmap(&[]), &[]));
            c
        };
        let argv =
            wrap_command(Profile::SingleNode, &cage, "/var/spool/slurmd", 4242, &v(&["./a.out"]));
        let script = &argv[2];
        // It must arrive as a --setenv pair, i.e. consumed by bwrap...
        assert!(script.contains("'--setenv' 'LD_PRELOAD' '/tmp/evil.so'"), "{script}");
        // ...and the pre-cage part of the script must not export it.
        let before_bwrap = script.split("exec seccomp-wrapper").next().unwrap();
        assert!(
            !before_bwrap.contains("LD_PRELOAD"),
            "nothing may set LD_PRELOAD before the cage: {before_bwrap}"
        );
    }

    #[test]
    fn the_command_is_passed_as_argv_never_interpolated() {
        // The one property that matters: a program name full of shell syntax must end up
        // as an ARGUMENT, not as script text. If this ever regresses, a job could run
        // arbitrary shell OUTSIDE the rank cage — the wrapper is what puts it inside.
        let argv = built(&["./solver; rm -rf /", "--flag=$(whoami)", "`id`"]);
        let script = &argv[2];
        assert!(!script.contains("rm -rf"), "command leaked into the script: {script}");
        assert!(!script.contains("whoami"), "command leaked into the script: {script}");
        assert!(!script.contains("`id`"), "command leaked into the script: {script}");
        assert_eq!(
            &argv[3..],
            &v(&["husk-rank", "./solver; rm -rf /", "--flag=$(whoami)", "`id`"])[..],
            "the command must follow $0 as separate argv elements"
        );
        assert!(script.contains("\"$@\""), "the script must exec \"$@\": {script}");
    }

    #[test]
    fn execs_the_cage_and_cannot_be_opted_out_of() {
        let argv = built(&["./a.out"]);
        let script = &argv[2];
        assert!(script.contains("exec seccomp-wrapper --profile=single-node bwrap"), "{script}");
        assert!(script.contains("--unshare-net"), "a rank keeps IP isolation: {script}");
        assert!(script.contains("--dev-bind-try"), "the fabric is bound: {script}");
    }

    #[test]
    fn resolves_the_per_step_and_per_job_paths_inside_the_task() {
        // Neither path can be known by the broker: the step id does not exist until the
        // step is created, and the shm dir lives on whichever node the task lands on.
        let script = built(&["./a.out"])[2].clone();
        assert!(script.contains("${SLURM_STEP_ID}"), "{script}");
        assert!(script.contains("${SLURM_JOB_ID}"), "{script}");
        assert!(script.contains("--bind-try"), "apinfo bind must tolerate absence: {script}");
        assert!(script.contains("--bind \"$_d\" /dev/shm"), "{script}");
    }

    #[test]
    fn refuses_a_shm_directory_it_does_not_own() {
        // /dev/shm is world-writable and sticky, so another user could pre-create
        // husk-<jobid> (job ids are guessable) and read this job's segments.
        let script = built(&["./a.out"])[2].clone();
        assert!(script.contains("mkdir -m 700"), "{script}");
        assert!(script.contains("[ ! -O \"$_d\" ]"), "must verify ownership: {script}");
        assert!(script.contains("exit 1"), "must refuse, not continue: {script}");
    }

    #[test]
    fn broker_supplied_values_are_shell_quoted() {
        let rank = FsPolicy::default().rank_bwrap_args("/work");
        let argv = wrap_command(Profile::SingleNode, &rank, "/odd path/spool", 4242, &v(&["./a"]));
        assert!(argv[2].contains("'/odd path/spool'"), "{}", argv[2]);
    }

    #[test]
    fn the_rank_joins_the_jobs_shared_user_namespace() {
        // The single share that legalises rank-to-rank CMA. `--userns` must be present
        // AND must precede the policy arguments, because bwrap otherwise creates its own
        // user namespace and the ranks end up siblings again - which is exactly the
        // configuration that fails with EPERM.
        let argv = wrap_command(
            Profile::SingleNode,
            &FsPolicy::default().rank_bwrap_args("/work"),
            "/var/spool/slurmd",
            4242,
            &v(&["./a.out"]),
        );
        let script = &argv[2];
        assert!(script.contains("--userns 9"), "rank must join the shared userns: {script}");
        assert!(
            script.contains("/proc/4242/ns/user"),
            "the holder's namespace must be named: {script}"
        );
        assert!(
            !script.contains("--unshare-user"),
            "a rank must never make its own user namespace: {script}"
        );
    }

    #[test]
    fn a_rank_refuses_to_run_when_the_cage_holder_is_gone() {
        // Fail CLOSED. Falling back to a private user namespace would run the workload in
        // a cage that cannot CMA its peers, which surfaces as an obscure MPI abort rather
        // than as the containment change it actually is. pid 1 is the wrong namespace but
        // readable; a pid that does not exist must stop the rank outright.
        let argv = wrap_command(
            Profile::SingleNode,
            &FsPolicy::default().rank_bwrap_args("/work"),
            "/var/spool/slurmd",
            4_000_000_000, // above any pid_max: cannot exist
            &v(&["./a.out"]),
        );
        let out = std::process::Command::new("/bin/sh")
            .args(&argv[1..])
            .env("SLURM_JOB_ID", "1")
            .env("SLURM_STEP_ID", "0")
            .output()
            .expect("run the wrapper script");
        assert!(!out.status.success(), "a rank without a cage holder must not run");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("cage holder is gone"), "must say why: {err}");
    }

    #[test]
    fn executing_it_passes_a_hostile_command_through_untouched() {
        // The decisive test: RUN the script with a stub standing in for
        // seccomp-wrapper, and check what actually arrives. String inspection can miss a
        // quoting bug that a shell would happily execute; this cannot.
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("husk-rank-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let stub = dir.join("seccomp-wrapper");
        // Print each argument on its own line so we can compare exactly.
        std::fs::write(&stub, "#!/bin/sh\nfor a in \"$@\"; do echo \"ARG:$a\"; done\n").unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();

        let hostile = "./solver; touch /tmp/husk-pwned-$$";
        let argv = built(&[hostile, "--x=$(id)"]);
        let job_id = format!("test{}", std::process::id());
        let out = std::process::Command::new("/bin/sh")
            .args(&argv[1..]) // -c <script> husk-rank <command...>
            .env("PATH", format!("{}:/usr/bin:/bin", dir.display()))
            .env("SLURM_JOB_ID", &job_id)
            .env("SLURM_STEP_ID", "7")
            .output()
            .expect("run the wrapper script");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir(format!("/dev/shm/husk-{job_id}"));

        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "script failed: {}", String::from_utf8_lossy(&out.stderr));
        // The hostile string arrives as ONE argument, unexpanded and unexecuted.
        assert!(
            stdout.contains(&format!("ARG:{hostile}")),
            "command must arrive verbatim as one argv element:\n{stdout}"
        );
        assert!(
            stdout.contains("ARG:--x=$(id)"),
            "arguments must not be command-substituted:\n{stdout}"
        );
        // ...and the per-step path was resolved from the task's environment.
        assert!(
            stdout.contains(&format!("ARG:/var/spool/slurmd/mpi_cray_shasta/{job_id}.7")),
            "per-step apinfo path must be resolved in-task:\n{stdout}"
        );
    }

    #[test]
    fn the_generated_script_is_valid_shell() {
        // Cheap guard against a quoting mistake in the format! above: ask a real shell.
        let script = built(&["./a.out"])[2].clone();
        let out = std::process::Command::new("/bin/sh")
            .arg("-n")
            .arg("-c")
            .arg(&script)
            .output()
            .expect("run sh -n");
        assert!(
            out.status.success(),
            "generated script is not valid shell: {}\n{script}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
