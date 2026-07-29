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

/// Build the argv that follows srun's options: `sh -c <script> husk-rank <command...>`.
///
/// `spool_dir` is Slurm's `SlurmdSpoolDir` as resolved by the step-broker (trusted);
/// `rank_args` are the static bwrap arguments from `FsPolicy::rank_bwrap_args`.
///
/// Not yet called from the binary — the step-broker that would issue the `srun` does not
/// exist yet. Landed with the allowlist and the rank cage so the security-critical
/// construction is written and executed under test before the process plumbing.
#[allow(dead_code)]
pub fn wrap_command(
    profile: Profile,
    rank_args: &[String],
    spool_dir: &str,
    command: &[String],
) -> Vec<String> {
    let bwrap = rank_args
        .iter()
        .map(|s| sh_quote(s))
        .collect::<Vec<_>>()
        .join(" ");

    // NOTE on the /dev/shm directory: /dev/shm is world-writable and sticky, so another
    // user on the node could PRE-CREATE `husk-<jobid>` (job ids are guessable) and then
    // read this job's shared-memory segments. The sticky bit stops them deleting our
    // entries, not creating the directory first. So the script refuses to proceed unless
    // the directory is owned by us — `mkdir -m 700` for the normal case, `[ -O ]` for the
    // adversarial one. Ranks race to create it; all but one get EEXIST, which is fine.
    let script = format!(
        "set -u\n\
         _d=/dev/shm/husk-${{SLURM_JOB_ID}}\n\
         mkdir -m 700 \"$_d\" 2>/dev/null || true\n\
         if [ ! -O \"$_d\" ]; then\n\
         echo \"husk: $_d exists and is not owned by this user - refusing to share it\" >&2\n\
         exit 1\n\
         fi\n\
         _s={spool}/mpi_cray_shasta/${{SLURM_JOB_ID}}.${{SLURM_STEP_ID}}\n\
         exec seccomp-wrapper --profile={sec} bwrap {bwrap} \
         --bind \"$_d\" /dev/shm --bind-try \"$_s\" \"$_s\" -- \"$@\"\n",
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

    fn built(command: &[&str]) -> Vec<String> {
        let rank = FsPolicy::default().rank_bwrap_args("/work");
        wrap_command(Profile::SingleNode, &rank, "/var/spool/slurmd", &v(command))
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
        let argv = wrap_command(Profile::SingleNode, &rank, "/odd path/spool", &v(&["./a"]));
        assert!(argv[2].contains("'/odd path/spool'"), "{}", argv[2]);
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
