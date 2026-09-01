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
//! Same "glob in the guard, not in the broker" pattern as the GPU device binds: the
//! compute node knows things the SUBMITTING side cannot.
//!
//! The credential-socket mask further down is **not** a third instance of that, and the
//! comment beside it used to claim it was (`B3-7`). The submitting side is not the only
//! trusted side that knows: `step.rs` runs inside the allocation, on the node, and
//! `main.rs:1034` constructs it with `Profile::SingleNode` as a literal — so for every
//! topology husk brokers, the trusted Rust process already knows everything the task
//! knows. The mask is resolved in the task for one reason, and it is a schedule: moving
//! it is a `MaskSet` minted in `step.rs` and passed to [`wrap_command`] the way
//! `slurmd_spool` already is (`P6` — put the decision in the layer that can enforce it),
//! and that is Track F work. Until then the loop below fails CLOSED, which is the half
//! that is not a rewrite.
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
///
/// `_HUSK_` is here because husk already uses it — `_HUSK_RESANDBOXED` is the variable the
/// job guard reads to decide whether it is inside the cage yet — and the filter did not
/// cover it. Nothing on the RANK path reads a `_HUSK_` value today, so the gap was inert;
/// it is reserved now precisely because "inert" is a property of the current code and not
/// of the interface. The next person to add an underscore-prefixed internal would inherit
/// a forwardable control variable and no reason to suspect it, which is how a landmine
/// works. Reserving a prefix costs nothing; the name is ours either way.
const RESERVED_ENV_PREFIXES: &[&str] =
    &["SLURM_", "SBATCH_", "PMI_", "PMIX_", "PALS_", "HUSK_", "_HUSK_"];

/// Proxy variables are never forwarded — they are a property of the namespace you are in.
///
/// The job cage exports these pointing at its own relay. A rank has its OWN network
/// namespace with its own empty loopback, so that address means something different here:
/// forwarding the job's value would hand a rank a proxy setting for a socket it cannot
/// reach. The rank script sets them itself, and only after confirming it could start a
/// relay — so a rank without egress looks like a machine with no network rather than one
/// with a broken proxy.
///
/// The general rule, worth keeping: values that describe a NAMESPACE do not travel across
/// one. Inherit facts about the job; re-derive facts about where you are.
const PROXY_ENV: &[&str] = &[
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
];

/// Names that change what a process EXECUTES rather than what it computes.
///
/// **A5, 2026-08-19.** The reviewer walked the chain and found the one value the two brokers
/// gate to different standards: the login broker enforces an allowlist on the submit
/// environment and strips `LD_PRELOAD`; the srun stub forwards the whole job environment; and
/// this filter dropped only scheduler-owned, credential and namespace names. So a name hop 1
/// removes came back if the job set it in its body one hop later. `P8` — two lists of the same
/// thing, and they drifted.
///
/// **Measured before fixing, from outside the cage**, because the interesting half was not
/// visible from inside: every process carrying the forwarded `LD_PRELOAD` was in the job cage
/// or the rank cage. The real `srun`, both `bwrap` invocations and the guard were clean, which
/// is what the code predicts — the step-broker's environment is captured before the body runs
/// and nothing rewrites it, so `env_args` can only ever produce `--setenv` arguments. **Not an
/// escape.**
///
/// It is fixed anyway, for one reason that is not tidiness: the value reaches the inner shell
/// that runs [`CLOSE_NS_FDS`], the line that drops the job's shared namespace handles before
/// the workload starts (`B4-F8`). A preloaded object's constructor runs before that shell's
/// first command. That process is the last thing in the chain that should be extensible by the
/// job it is containing, and "inside the cage" is not a reason to let the contained side inject
/// code into husk's own cleanup.
///
/// The list is dynamic-linker and shell-startup names — the ones whose whole purpose is to run
/// something the caller did not name. A job that genuinely needs a library path sets it inside
/// its own workload, where it belongs.
const EXEC_HIJACK_ENV: &[&str] = &[
    // ld.so: load, audit or redirect objects before main().
    "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "LD_ORIGIN_PATH", "LD_DEBUG_OUTPUT",
    // shell startup files: code that runs before the command does.
    "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "PS4",
    // interpreter-level equivalents of the same idea.
    "PYTHONSTARTUP", "PERL5OPT", "PERL5LIB", "RUBYOPT", "NODE_OPTIONS",
];

/// Upper bound on the NUMBER of variables `env_args` carries in either direction.
///
/// It used to be the whole control, under a comment that named the size — "an enormous
/// environment would otherwise become an enormous command line in the trusted process".
/// A count is not a size, and the gap was not marginal: values are not length-bounded
/// (names are, at [`is_valid_env_name`]), so 511 variables at the kernel's per-string
/// ceiling (`MAX_ARG_STRLEN`, 128 KiB) produced **63.9 MiB of argv against a 2 MiB
/// `ARG_MAX`** — 32x what a process can be handed (`B3-6`, measured). The count is kept
/// because it is the honest bound on the `--unsetenv` half, where names are already capped
/// at 128 characters; [`MAX_FORWARDED_ENV_BYTES`] is the one that bounds the class the
/// comment always claimed.
const MAX_FORWARDED_ENV: usize = 512;

/// Upper bound on the BYTES the carried-across (`--setenv`) half may add to a step's
/// command line.
///
/// **What a legitimate large environment looks like**, because a limit a real job hits is
/// a defect. This bounds the DELTA a job script makes, not the environment it runs in: a
/// run script that `module load`s a full Cray PE and a Spack stack changes on the order of
/// 100-300 names, and the long ones are path lists — `MODULEPATH`, `_LMFILES_`,
/// `LOADEDMODULES`, `PKG_CONFIG_PATH`, `CRAY_LD_LIBRARY_PATH` — of a few KiB each. Call it
/// 20-30 KiB for a heavy one. 256 KiB is an order of magnitude above that and about 1/8 of
/// a 2 MiB `ARG_MAX`, which leaves the rest of the command line — the bwrap arguments, the
/// validated srun options, the workload's own argv — the room it needs. A job that reaches
/// it is not carrying an environment; it is carrying data, and a file is the way to do that.
///
/// **Disposition: truncate loudly, never fail.** Both bounds stop carrying and say on the
/// step's stderr WHICH bound fired and at which variable — deliberately the same
/// disposition the count bound already had. Turning either into an error would make a step
/// that runs today fail tomorrow on a limit nobody asked for, which is the shape this
/// project keeps paying for. The message is the control (`P7`: a control that declines
/// silently has already failed); the refusal is not.
const MAX_FORWARDED_ENV_BYTES: usize = 256 * 1024;

/// Upper bound on ONE forwarded value.
///
/// The total above is not the same bound as this one, and finding that out is why this
/// constant exists: the kernel enforces a SECOND, per-argument ceiling, `MAX_ARG_STRLEN`,
/// and a single 200 KiB value fits comfortably inside a 256 KiB total while still being
/// unexecutable on its own. Measured here: `execve` of `/bin/true` with one 131,071-byte
/// argument succeeds and one 131,072-byte argument fails with `E2BIG`, so
/// `MAX_ARG_STRLEN` is 32 pages INCLUDING the NUL. Bounding only the total would have been
/// the same defect one level down from the one it was fixing.
///
/// 64 KiB is half that ceiling on a 4 KiB-page machine, and `MAX_ARG_STRLEN` is
/// `32 * PAGE_SIZE`, so the constant is safe on every page size husk meets rather than
/// only on the one it was measured on. What it has to clear is a path list: the longest
/// values a real run script sets are `_LMFILES_` and `CRAY_LD_LIBRARY_PATH`, both a few
/// KiB. An over-long value is SKIPPED and named rather than truncating the rest — one
/// impossible value should not cost the environment behind it — and the skips are reported
/// as ONE line however many there are. Measured while writing this fix: the shape `B3-6`
/// used (511 variables at the ceiling) produced 511 identical paragraphs on the job's
/// stderr, which is not a better failure than the `E2BIG` it replaced (`P13` — a message
/// nobody can read does not explain anything).
const MAX_FORWARDED_ENV_VALUE_BYTES: usize = 64 * 1024;

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
            && !PROXY_ENV.contains(&k.as_str())
            && !EXEC_HIJACK_ENV.contains(&k.as_str())
            && !deny.iter().any(|d| d == k)
    };

    let mut out = Vec::new();
    let mut n = 0;
    let mut bytes = 0usize;
    let mut oversize: Vec<&String> = Vec::new();
    // Added or changed by the job script.
    for (k, v) in job_env {
        if !forwardable(k) || base_env.get(k) == Some(v) {
            continue;
        }
        if n >= MAX_FORWARDED_ENV {
            eprintln!(
                "step-broker: this job script changed more than {MAX_FORWARDED_ENV} \
                 environment variables, which is husk's limit on how many it carries into \
                 a step. It stopped at {k:?}: that name and every one after it is NOT set \
                 in the ranks. Export fewer names, or write the values to a file the \
                 workload reads."
            );
            break;
        }
        // The kernel's per-argument ceiling, which the total below does NOT imply: a value
        // that fits the budget can still be too large to be one argv element on its own.
        if v.len() + 1 > MAX_FORWARDED_ENV_VALUE_BYTES {
            oversize.push(k);
            continue;
        }
        // +1 per element for the NUL the kernel counts. This is what the step's argv grows
        // by, which is the quantity ARG_MAX is about.
        let cost = "--setenv".len() + 1 + k.len() + 1 + v.len() + 1;
        if bytes + cost > MAX_FORWARDED_ENV_BYTES {
            eprintln!(
                "step-broker: this job script's environment changes are too LARGE to carry \
                 into a step - {n} variables came to {bytes} bytes and {k:?} would add \
                 {cost} more, over husk's {MAX_FORWARDED_ENV_BYTES}-byte budget. (It is the \
                 size, not the count: the count limit is {MAX_FORWARDED_ENV}.) {k:?} and \
                 every name after it is NOT set in the ranks. A step's command line has to \
                 fit in the kernel's ARG_MAX alongside the sandbox arguments, so a large \
                 value belongs in a file the workload reads, not in the environment."
            );
            break;
        }
        out.push("--setenv".to_string());
        out.push(k.clone());
        out.push(v.clone());
        n += 1;
        bytes += cost;
    }
    if !oversize.is_empty() {
        let named: Vec<&str> = oversize.iter().take(4).map(|k| k.as_str()).collect();
        eprintln!(
            "step-broker: {} of this job script's environment variables are each larger than \
             husk's {MAX_FORWARDED_ENV_VALUE_BYTES}-byte limit on a single forwarded value, so \
             they are NOT set in the ranks - the rest are: {}{}. The kernel refuses any one \
             command-line argument over MAX_ARG_STRLEN (32 pages) whatever husk does, so a \
             value this size has to travel in a file the workload reads.",
            oversize.len(),
            named.join(", "),
            if oversize.len() > named.len() { ", ..." } else { "" }
        );
    }
    // Removed by the job script. `unset FOO; srun ...` must not leave FOO set.
    //
    // Bounded too, and it was not. This half had no limit of any kind — not a count, not a
    // size — which is the same defect as `B3-6` one loop lower: `base_env` is the
    // step-broker's own environment, inherited from a submission the agent writes, so a
    // submission carrying tens of thousands of short names makes this loop ALONE outgrow
    // ARG_MAX. Its own budget rather than a shared one, so neither half can starve the
    // other; a count is enough here because `is_valid_env_name` already caps a name at 128
    // characters, which puts the worst case at ~70 KiB.
    let mut cleared = 0;
    for k in base_env.keys() {
        if !forwardable(k) || job_env.contains_key(k) {
            continue;
        }
        if cleared >= MAX_FORWARDED_ENV {
            eprintln!(
                "step-broker: the job script removed more than {MAX_FORWARDED_ENV} \
                 environment variables, which is husk's limit on how many it clears in a \
                 step. It stopped at {k:?}: that name and every one after it is still SET \
                 in the ranks, with the value the job inherited."
            );
            break;
        }
        out.push("--unsetenv".to_string());
        out.push(k.clone());
        cleared += 1;
    }
    out
}

/// Where `socat` appears INSIDE any husk cage.
///
/// A fixed destination in the cage's own tmpfs (`--tmpfs /tmp` is already in the cage
/// arguments), never a file on the host. bwrap creates the mountpoint in its own namespace,
/// so the binary is usable inside and **nothing exists on the host afterwards** — which is
/// the whole point: the previous design bind-mounted socat over a placeholder file in the
/// step spool, and a dentry that is still a mountpoint cannot be unlinked, so the cleanup's
/// `rm` failed with EBUSY and every job that ran a step left its spool behind.
///
/// Both cages bind it themselves, to the same path, from the same host source. A rank
/// cannot inherit the job cage's mount — bwrap namespaces do not propagate — which is why
/// ranks previously found an EMPTY placeholder here and silently ran with no egress.
pub const CAGED_SOCAT: &str = "/tmp/husk-socat";

/// Everything a rank needs to reach the egress proxy.
///
/// Both values are INHERITED from the guard through the step-broker rather than rebuilt
/// here. The socat path in particular could be derived from the socket path — they live in
/// the same directory — but a derivation is a second construction of the same fact, and
/// two constructions of one fact is how this project keeps getting caught.
#[derive(Clone, Copy)]
pub struct Egress<'a> {
    pub sock: &'a str,
    pub socat: &'a str,
}

/// The final line of the rank script: enter the cage and run the workload.
///
/// Two shapes, chosen by the BROKER rather than branched on at run time, so a job with no
/// egress produces exactly the script it produced before this feature existed — no extra
/// process, no extra shell, nothing to regress.
///
/// With egress, the workload is preceded inside the cage by a relay: `socat` forwarding
/// loopback:3128 to the proxy's unix socket. Each rank needs its own because each rank has
/// its own network namespace — the relay is a per-namespace adapter, not a per-rank policy.
/// The single proxy outside the cage still makes every decision and writes every log.
///
/// **The inner script is a shell VARIABLE, not an interpolated literal.** Nesting a quoted
/// script inside a quoted script inside a Rust format string is how the srun bind once
/// shipped literal quote characters into bwrap and killed every job; assigning it once and
/// passing `"$_husk_inner"` keeps exactly one level of quoting. The socket path travels in
/// an exported variable for the same reason — `sh_quote` produces single quotes, which
/// cannot appear inside the single-quoted assignment.
/// Drop the job's shared namespace handles before the workload starts (B4-F8).
///
/// One origin for both shapes, because two copies of a security-relevant line in two
/// branches is how the cleanup set drifted from the files it was supposed to remove.
const CLOSE_NS_FDS: &str = "exec 8<&- 9<&-";

fn exec_line(profile: Profile, bwrap: &str, net: Option<Egress<'_>>) -> String {
    let sec = profile.seccomp_profile();
    let cage = match net {
        None => format!(
            "seccomp-wrapper --profile={sec} bwrap --userns 9 --pidns 8 {bwrap} \
             $_m \
             --bind \"$_d\" /dev/shm --bind-try \"$_s\" \"$_s\" --"
        ),
        // The rank binds socat itself, from the host source, to the same in-cage path the
        // job cage uses. Inheriting was never possible: bwrap mount namespaces do not
        // propagate, so a rank saw the job cage's placeholder rather than its contents.
        Some(e) => format!(
            "seccomp-wrapper --profile={sec} bwrap --userns 9 --pidns 8 {bwrap} \
             $_m \
             --bind \"$_d\" /dev/shm --bind-try \"$_s\" \"$_s\" \
             --ro-bind-try {src} {CAGED_SOCAT} --ro-bind-try {sock} {sock} --",
            src = sh_quote(e.socat),
            sock = sh_quote(e.sock)
        ),
    };
    // **B4-F8.** fds 8 and 9 are the job's shared PID and user namespace handles. bwrap
    // consumes them during setup and does NOT close them, so they were inherited straight
    // through into the workload — measured inside a real rank as `8 -> pid:[…]`,
    // `9 -> user:[…]`. Nothing was reachable through them (`NS_GET_PARENT` → EPERM on both,
    // `setns` on our own userns → EINVAL), so this is hygiene rather than a hole; but "no use
    // found" is a weaker claim than "closed", and a handle to the namespace that IS the
    // cage's shared identity is not something a workload should be holding by accident.
    //
    // They cannot be closed before `exec bwrap` — bwrap needs them — and bwrap has no flag
    // to drop them: any fd it is handed is inherited by whatever it execs. So the close has
    // to happen on the far side of the cage, in the one instant between bwrap's exec and the
    // workload's. That instant is only reachable from a process bwrap starts, so both shapes
    // now go through a one-line inner shell whose entire job is to close the two fds and
    // exec the workload.
    //
    // The networked shape already had that shell — the socat relay needs it — so the close
    // was free there. The plain shape did not, and an earlier note here said the no-network
    // case had to stay BYTE-FOR-BYTE what it was before egress existed. That was too strong:
    // the property worth protecting is that a job which never asked for a network gets the
    // same SEMANTICS as before — no relay, no proxy environment, no socat, and the workload
    // still exec'd from its own argv — not that the script text is unchanged. One exec that
    // immediately replaces itself is not a regression to a job that asked for nothing.
    match net {
        None => format!(
            "_husk_inner='{CLOSE_NS_FDS}\n\
             exec \"$@\"'\n\
             exec {cage} /bin/sh -c \"$_husk_inner\" husk-rank \"$@\"\n"
        ),
        Some(e) => format!(
            "export _HUSK_NET_SOCK={sock}\n\
             export _HUSK_SOCAT={caged}\n\
             _husk_inner='{CLOSE_NS_FDS}\n\
             if [ -x \"$_HUSK_SOCAT\" ]; then\n\
             \"$_HUSK_SOCAT\" TCP-LISTEN:3128,fork,reuseaddr,bind=127.0.0.1 \
             UNIX-CONNECT:\"$_HUSK_NET_SOCK\" >/dev/null 2>&1 &\n\
             export HTTP_PROXY=http://127.0.0.1:3128 HTTPS_PROXY=http://127.0.0.1:3128\n\
             export http_proxy=http://127.0.0.1:3128 https_proxy=http://127.0.0.1:3128\n\
             export ALL_PROXY=http://127.0.0.1:3128 all_proxy=http://127.0.0.1:3128\n\
             export NO_PROXY=localhost,127.0.0.1 no_proxy=localhost,127.0.0.1\n\
             fi\n\
             exec \"$@\"'\n\
             exec {cage} /bin/sh -c \"$_husk_inner\" husk-rank \"$@\"\n",
            sock = sh_quote(e.sock),
            caged = CAGED_SOCAT
        ),
    }
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
    net: Option<Egress<'_>>,
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
    //
    // **B4-F7: `|| exit 1` on each redirection, because the belt was not actually fastened.**
    // The `-r` test and the `exec 9<` that follows it are two operations with a window
    // between them, and the redirection was unguarded — so what happens if it fails is the
    // SHELL's choice, not ours: `dash` exits, `bash` prints an error and CARRIES ON with fd
    // 9 unopened. The outcome stayed fail-closed only because `bwrap --userns 9` then dies
    // with "Bad file descriptor". That is bwrap's guarantee while the comment above credits
    // this script, and a guarantee attributed to the wrong layer is one that quietly
    // disappears when that layer is replaced (6a replaces exactly this layer). Whether
    // `/bin/sh` is bash or dash on a given cluster then decides which half is load-bearing,
    // which is not a thing husk should be depending on.
    let script = format!(
        "set -u\n\
         _u={userns}\n\
         if [ ! -r \"$_u\" ]; then\n\
         echo \"husk: the job's cage holder is gone ($_u) - refusing to run this rank\" >&2\n\
         exit 1\n\
         fi\n\
         exec 9<\"$_u\" || exit 1\n\
         _p={pidns}\n\
         if [ ! -r \"$_p\" ]; then\n\
         echo \"husk: the job's PID namespace is gone ($_p) - refusing to run this rank\" >&2\n\
         exit 1\n\
         fi\n\
         exec 8<\"$_p\" || exit 1\n\
         _d=/dev/shm/husk-${{SLURM_JOB_ID}}\n\
         mkdir -m 700 \"$_d\" 2>/dev/null || true\n\
         # -O FOLLOWS SYMLINKS, and /dev/shm is world-writable. A co-tenant who won the\n\
         # race to create this path could point it at a directory of OURS: -O then\n\
         # resolved the link, saw a directory this user owns, passed - and bwrap bound\n\
         # that directory as /dev/shm inside every rank, read-write, through a cage whose\n\
         # whole job is to hide such things. Someone outside the job chose what was\n\
         # mounted inside it. -L tests the link itself and does not follow, so it has to\n\
         # come first; -d then rejects anything that is not a directory at all.\n\
         if [ -L \"$_d\" ] || [ ! -d \"$_d\" ] || [ ! -O \"$_d\" ]; then\n\
         echo \"husk: refusing to use $_d - it is a symlink, not a directory, or not owned\" >&2\n\
         echo \"husk: by this user. Another user on this node may have created it first.\" >&2\n\
         exit 1\n\
         fi\n\
         # The MUNGE socket, masked per rank. bwrap mount namespaces do not propagate, so\n\
         # a rank building a fresh --ro-bind / / saw the real one however carefully the\n\
         # job guard had masked it. That gap sat directly under profile.rs, which justifies\n\
         # the single-node seccomp profile by saying the MOUNT mask is what keeps the\n\
         # escape-relevant destination unreachable - and ranks are the side that will lose\n\
         # --unshare-net first when multi-node MPI arrives.\n\
         #\n\
         # Resolved on the NODE, not baked into the static args: --tmpfs DEST kills bwrap\n\
         # when DEST is absent under a read-only root, and kills it again when two entries\n\
         # resolve to the same directory (/var/run -> /run). Both shipped once and took\n\
         # the whole cage down, so each path is tested and resolved before it is mounted.\n\
         #\n\
         # POSIX sh, so a string rather than an array - this script is validated with\n\
         # /bin/sh and dash has no arrays. That means the value is expanded UNQUOTED and\n\
         # word-split, which is the trap the srun bind fell into once (word-split but not\n\
         # quote-removed, so bwrap got literal quotes). A path that cannot survive that\n\
         # expansion is therefore a path this script cannot mask.\n\
         #\n\
         # ONE DISPOSITION PER ARM (B3-7). Absent is not a failure: there is no credential\n\
         # socket to hide, and mounting over a path that is not there is what kills the\n\
         # cage. Every other outcome - a credential path that EXISTS and cannot be masked\n\
         # - is a failure of the control profile.rs calls load-bearing for this profile,\n\
         # so the rank REFUSES TO START rather than running with the real socket visible.\n\
         # ONE OF TWO ENFORCERS, and they now take the SAME decision on the same node:\n\
         # policy.rs's job-cage loop was left at `[ -d ] || continue` by this fix and\n\
         # refuses too since `K-2`. The pair shares settings::CREDENTIAL_SOCKET_DIRS for\n\
         # the path list and policy.rs's\n\
         # `the_two_credential_mask_enforcers_agree_on_a_path_neither_can_mask` for the\n\
         # disposition - it EXECUTES both slices and compares them, including the one arm\n\
         # where they differ by decision (a whitespace-resolving path: a bash array can\n\
         # carry it, this string concatenation cannot, so the guard masks and announces\n\
         # while the rank refuses). These two are the only node-side `--tmpfs` producers;\n\
         # `every_producer_of_a_tmpfs_argument_is_enumerated` is the full set (`M-4`).\n\
         # Dropping it was the bug: `continue` on a whitespace-resolving path left $_m\n\
         # short, bwrap built the cage anyway, and nothing on any channel said the mask\n\
         # had not been applied (P7). The rank is where this must be caught - bwrap mount\n\
         # namespaces do not propagate, so the job guard's mask is not inherited here.\n\
         _m=\n\
         _seen=\n\
         _why=\n\
         for _c in {mask_paths}; do\n\
         if [ ! -d \"$_c\" ]; then\n\
         [ -e \"$_c\" ] || continue\n\
         _why=\"$_c exists but is not a directory, so a tmpfs cannot be mounted over it\"\n\
         break\n\
         fi\n\
         _r=$(readlink -f \"$_c\" 2>/dev/null || echo \"$_c\")\n\
         case \"$_r\" in\n\
         \"\" | *[[:space:]]*)\n\
         _why=\"$_c resolves to '$_r', which cannot be passed to bwrap as a single word\"\n\
         break\n\
         ;;\n\
         esac\n\
         case \" $_seen \" in *\" $_r \"*) continue ;; esac\n\
         _seen=\"$_seen $_r\"\n\
         _m=\"$_m --tmpfs $_r\"\n\
         done\n\
         if [ -n \"$_why\" ]; then\n\
         echo \"husk: cannot mask this node's credential socket directory - $_why.\" >&2\n\
         echo \"husk: Refusing to run this rank. That mask is what keeps the MUNGE socket\" >&2\n\
         echo \"husk: out of the cage, and without it a job can authenticate to SLURM and\" >&2\n\
         echo \"husk: submit work husk never sees. Nothing your job did causes this - it is\" >&2\n\
         echo \"husk: how this node is configured, so report the path above to your site.\" >&2\n\
         exit 1\n\
         fi\n\
         _s={spool}/mpi_cray_shasta/${{SLURM_JOB_ID}}.${{SLURM_STEP_ID}}\n\
         {exec_line}",
        userns = sh_quote(&userns),
        pidns = sh_quote(&crate::cage::pidns_path(holder_pid)),
        spool = sh_quote(spool_dir),
        mask_paths = crate::settings::CREDENTIAL_SOCKET_DIRS.join(" "),
        exec_line = exec_line(profile, &bwrap, net),
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
        let rank = FsPolicy::unchecked_for_test().rank_bwrap_args("/work");
        wrap_command(Profile::SingleNode, &rank, "/var/spool/slurmd", live_holder(), None, &v(command))
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
    fn proxy_settings_are_not_forwarded_into_a_rank() {
        // A rank has its own network namespace and its own empty loopback, so the job
        // cage's 127.0.0.1:3128 reaches nothing there. Forwarding the setting would make
        // a download inside srun fail with "cannot connect to proxy", which blames husk
        // for the wrong thing. No egress should look like no network.
        let base = envmap(&[("PATH", "/bin")]);
        let job = envmap(&[
            ("PATH", "/bin"),
            ("HTTP_PROXY", "http://127.0.0.1:3128"),
            ("https_proxy", "http://127.0.0.1:3128"),
            ("NO_PROXY", "localhost"),
            ("OMP_NUM_THREADS", "4"),
        ]);
        let args = env_args(&job, &base, &[]);
        for bad in ["HTTP_PROXY", "https_proxy", "NO_PROXY"] {
            assert!(!args.iter().any(|a| a == bad), "{bad} must not reach a rank: {args:?}");
        }
        assert!(
            args.windows(3).any(|w| w == ["--setenv", "OMP_NUM_THREADS", "4"]),
            "ordinary variables must still be carried: {args:?}"
        );
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
    fn the_underscore_husk_prefix_is_reserved_too() {
        // The filter reserved `HUSK_` and not `_HUSK_`, while husk itself uses the latter:
        // `_HUSK_RESANDBOXED` is what the job guard reads to decide whether it is inside
        // the cage yet. Nothing on the RANK path reads a `_HUSK_` value, so the gap was
        // inert — but "inert" describes today's code, not the interface, and the next
        // underscore-prefixed internal would arrive forwardable with nothing to hint at it.
        //
        // Asserted on the PREFIX, not on the one name, so a future `_HUSK_ANYTHING` is
        // covered the day it is written rather than the day someone remembers this.
        let args = env_args(
            &envmap(&[
                ("_HUSK_RESANDBOXED", "1"),
                ("_HUSK_SOMETHING_INVENTED_LATER", "x"),
                ("HUSK_STEP_SPOOL", "/tmp/mine"),
                ("KEEPME", "ok"),
            ]),
            &envmap(&[]),
            &[],
        );
        for reserved in ["_HUSK_RESANDBOXED", "_HUSK_SOMETHING_INVENTED_LATER", "HUSK_STEP_SPOOL"] {
            assert!(
                !args.contains(&reserved.to_string()),
                "husk's own control plane is not forwardable by the caged side: {args:?}"
            );
        }
        assert!(args.contains(&"KEEPME".to_string()), "benign vars still pass: {args:?}");
    }

    /// The argv `env_args` produces must be one the kernel will actually accept.
    ///
    /// The contract, at the level the defect lived. `MAX_FORWARDED_ENV` bounds the NUMBER
    /// of variables; its comment bounded the SIZE ("an enormous environment would otherwise
    /// become an enormous command line in the trusted process"). Those are not the same
    /// statement, and the gap was not marginal: values were never length-bounded, so 511
    /// variables at the kernel\'s per-argument ceiling built **63.9 MiB of argv against a
    /// 2 MiB ARG_MAX** — 32x what a process can be handed (`B3-6`, reproduced here before
    /// fixing). `step.rs:433` survives the failed spawn, so the cost was a step that died
    /// with `could not launch srun: Argument list too long`: an errno with nothing in it
    /// that points back at the job script\'s own `export` (`P11`).
    ///
    /// **This asserts by EXECUTING, not by arithmetic**, because arithmetic is what got the
    /// original wrong. The kernel enforces TWO limits — a total (`ARG_MAX`) and a
    /// per-argument one (`MAX_ARG_STRLEN`, 32 pages) — and a bound on either alone still
    /// produces command lines it refuses. A real `execve` is the only oracle that covers
    /// both, and it caught the second one in this very fix: a 200 KiB value passes a
    /// 256 KiB total and is still unexecutable by itself.
    ///
    /// **The false friend is `MAX_FORWARDED_ENV` itself.** It is live, correct, and green
    /// on every input below: 511 is under 512, so it never fires, and no test named the
    /// constant at all.
    ///
    /// **Axis it does not cover:** it execs `env_args`\' output alone. `step.rs` adds the
    /// bwrap arguments, the validated srun options and the workload\'s own argv to the same
    /// command line, and none of that is counted here — the budget is sized at 1/8 of
    /// ARG_MAX to leave room for it, but this test does not check that it did.
    #[test]
    fn the_environment_argv_is_one_the_kernel_will_accept() {
        // The kernel is the oracle. `/bin/true` is a POSIX-required utility and the
        // arguments are ignored by it, so this measures execve and nothing else.
        let execs = |args: &[String]| -> Result<(), std::io::Error> {
            std::process::Command::new("/bin/true").args(args).status().map(|_| ())
        };
        assert!(execs(&[]).is_ok(), "/bin/true must be runnable for this test to mean anything");

        // (a) The shape B3-6 measured: 511 variables at the per-argument ceiling.
        let huge = "x".repeat(128 * 1024);
        let job: std::collections::BTreeMap<String, String> = (0..511)
            .map(|i| (format!("BIG_{i:03}"), huge.clone()))
            .collect();
        let args = env_args(&job, &envmap(&[]), &[]);
        let bytes: usize = args.iter().map(|a| a.len() + 1).sum();
        execs(&args).unwrap_or_else(|e| {
            panic!("env_args produced {bytes} bytes of argv that execve refuses: {e}")
        });

        // (b) The other kernel limit, which a total-bytes bound alone does NOT cover: one
        // value that fits the total budget and still exceeds MAX_ARG_STRLEN on its own.
        // The rest of the environment must survive it — an impossible value is not a
        // reason to drop the variables behind it.
        let job = envmap(&[]);
        let mut job = job;
        job.insert("ONE_ENORMOUS_VALUE".into(), "y".repeat(200 * 1024));
        job.insert("OMP_NUM_THREADS".into(), "4".into());
        let args = env_args(&job, &envmap(&[]), &[]);
        execs(&args).expect("a single over-long value must not produce an unexecutable argv");
        assert!(
            !args.iter().any(|a| a == "ONE_ENORMOUS_VALUE"),
            "the over-long value must be dropped by name: {:?}",
            args.iter().take(6).collect::<Vec<_>>()
        );
        assert!(
            args.windows(3).any(|w| w == ["--setenv", "OMP_NUM_THREADS", "4"]),
            "the rest of the environment must still be carried: {args:?}"
        );

        // (c) It is the SIZE that stopped (a), not the count: the count never fired.
        let job: std::collections::BTreeMap<String, String> = (0..511)
            .map(|i| (format!("MID_{i:03}"), "z".repeat(32 * 1024)))
            .collect();
        let args = env_args(&job, &envmap(&[]), &[]);
        let carried = args.iter().filter(|a| *a == "--setenv").count();
        assert!(carried < MAX_FORWARDED_ENV, "the count bound must not be what stopped this");
        assert!(carried >= 1, "the bound must not refuse everything: {carried}");
        execs(&args).expect("still executable");
    }

    /// ...and a real module-heavy job is carried whole.
    ///
    /// The bound above is only correct if no job anybody meant to run reaches it. A run
    /// script that `module load`s a Cray PE plus a Spack stack changes a few hundred names,
    /// of which a handful are multi-KiB path lists. All of it must arrive: a half-carried
    /// environment differs silently from what the script asked for, which is the failure
    /// `env_args` exists to remove, and turning that into husk\'s own doing would be a
    /// denial of service aimed at the operator rather than at the agent.
    ///
    /// **Axis it does not cover:** "realistic" is this sample. It is deliberately built at
    /// the top of the range rather than the middle — 300 names and 40 KiB against a
    /// measured 100-300 and 20-30 KiB — but a site whose scripts are larger still is not
    /// represented, and the argument for those is the order-of-magnitude margin, not this.
    #[test]
    fn a_module_heavy_environment_is_carried_whole() {
        let mut job = std::collections::BTreeMap::new();
        for i in 0..300 {
            job.insert(format!("SPACK_VAR_{i:03}"), format!("/scratch/spack/pkg-{i}/lib"));
        }
        // The long ones: module machinery and path lists, at the size Lmod really makes them.
        for name in ["MODULEPATH", "_LMFILES_", "LOADEDMODULES", "PKG_CONFIG_PATH", "CPATH"] {
            let entry = format!("/opt/cray/pe/{name}/very/long/prefix/component");
            job.insert(name.to_string(), vec![entry; 120].join(":"));
        }
        let total_env: usize = job.iter().map(|(k, v)| k.len() + v.len() + 2).sum();
        assert!(total_env > 40 * 1024, "the probe must be a big one: {total_env}");

        let args = env_args(&job, &envmap(&[]), &[]);
        assert_eq!(
            args.iter().filter(|a| *a == "--setenv").count(),
            job.len(),
            "every variable a realistic module-heavy job script sets must be carried: \
             a bound a real job hits is a defect, not a control"
        );
    }

    /// Clearing removed variables is bounded too — it had no limit at all.
    ///
    /// `B3-6` bounded the half it was about. Its class is "`env_args` builds a command line
    /// from input the agent influences", and the `--unsetenv` half is the same class one
    /// loop lower: it walked every key of `base_env` with no count and no size. `base_env`
    /// is the step-broker\'s own environment, inherited from a submission the agent writes,
    /// so a submission carrying tens of thousands of short names makes this loop alone
    /// outgrow ARG_MAX — with the setenv half completely empty and both of its bounds
    /// satisfied. Fixing the named instance and not its sibling is the shape this round
    /// found five times.
    ///
    /// **Axis it does not cover:** the truncation is a fidelity loss — a name the script
    /// `unset` stays set in the ranks — and this asserts the bound, not that the loss is
    /// acceptable. It is acceptable because credential masking does not come through here:
    /// `deny` names are dropped from the setenv half outright and the cage applies its own
    /// `--unsetenv` for them, so nothing security-relevant depends on this loop finishing.
    #[test]
    fn clearing_removed_variables_is_bounded_too() {
        let base: std::collections::BTreeMap<String, String> = (0..20_000)
            .map(|i| (format!("V{i:05}"), "1".to_string()))
            .collect();
        let args = env_args(&std::collections::BTreeMap::new(), &base, &[]);
        assert_eq!(
            args.iter().filter(|a| *a == "--unsetenv").count(),
            MAX_FORWARDED_ENV,
            "the unsetenv half must be bounded by the same count as the setenv half"
        );
        let total: usize = args.iter().map(|a| a.len() + 1).sum();
        assert!(total < 128 * 1024, "{total} bytes of --unsetenv argv");
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

    /// Names that hijack execution are not forwarded to a rank at all.
    ///
    /// **This test replaces one that passed against the gap A5 found**, and the false friend
    /// is worth naming: `ld_preload_reaches_only_the_caged_command` asserted that
    /// `LD_PRELOAD` arrives as a `--setenv` pair and that nothing sets it before the cage. Both
    /// were true, and both stayed true while the login broker stripped the same name from the
    /// submit environment and this one forwarded it — `P8`, two lists, drifted. The old test
    /// asked "is the forwarded value contained?" and never "should it be forwarded?", so it
    /// could not fail.
    ///
    /// The escape property it did check is kept below, because A5's measurement confirmed it
    /// holds and it is the reason this was hygiene rather than a breach.
    #[test]
    fn execution_hijacking_names_are_not_forwarded_at_all() {
        let args = env_args(
            &envmap(&[
                ("LD_PRELOAD", "/tmp/evil.so"),
                ("LD_AUDIT", "/tmp/evil.so"),
                ("BASH_ENV", "/tmp/rc"),
                ("NODE_OPTIONS", "--require /tmp/x"),
                ("OMP_NUM_THREADS", "4"),
            ]),
            &envmap(&[]),
            &[],
        );
        for bad in ["LD_PRELOAD", "LD_AUDIT", "BASH_ENV", "NODE_OPTIONS"] {
            assert!(
                !args.iter().any(|a| a == bad),
                "{bad} must not be forwarded to a rank at all: {args:?}"
            );
        }
        // ...and an ordinary variable a run script exported still reaches its ranks, which is
        // the whole reason this forwarding exists.
        assert_eq!(
            args,
            vec!["--setenv", "OMP_NUM_THREADS", "4"],
            "benign values must still travel: {args:?}"
        );
    }

    /// The escape property, unchanged: whatever IS forwarded arrives only via `--setenv`.
    ///
    /// The rank wrapper's first process is a dynamically linked `/bin/sh` running BEFORE any
    /// cage exists; a hijacking name in ITS environment would run arbitrary code as the user
    /// with `/users` visible. Measured on Balfrin 2026-08-19 from outside the cage: of every
    /// process carrying a forwarded `LD_PRELOAD`, all were in the job or rank cage, and the
    /// guard, both `bwrap` invocations and the real `srun` were clean.
    #[test]
    fn forwarded_values_never_appear_before_the_cage() {
        let cage = {
            let mut c = FsPolicy::unchecked_for_test().rank_bwrap_args("/work");
            c.extend(env_args(&envmap(&[("MY_VAR", "/tmp/x")]), &envmap(&[]), &[]));
            c
        };
        let argv =
            wrap_command(Profile::SingleNode, &cage, "/var/spool/slurmd", 4242, None, &v(&["./a.out"]));
        let script = &argv[2];
        assert!(script.contains("'--setenv' 'MY_VAR' '/tmp/x'"), "{script}");
        let before_bwrap = script.split("exec seccomp-wrapper").next().unwrap();
        assert!(
            !before_bwrap.contains("MY_VAR"),
            "nothing may set a forwarded value before the cage: {before_bwrap}"
        );
    }

    #[test]
    fn the_rank_script_fails_closed_in_any_shell_not_just_the_one_we_happen_to_get() {
        // **B4-F7.** `[ -r "$_u" ]` and the `exec 9<"$_u"` that follows it are two operations
        // with a window between them, and the redirection was unguarded — so what happened
        // when it failed was the SHELL's decision, not husk's:
        //
        //     dash:  exec 9</missing  → the shell EXITS
        //     bash:  exec 9</missing  → prints an error and CARRIES ON, fd 9 unopened
        //
        // The result stayed fail-closed only because `bwrap --userns 9` then dies with "Bad
        // file descriptor" — i.e. the guarantee belonged to bwrap while the comment credited
        // this script. A guarantee attributed to the wrong layer is one that vanishes when
        // that layer is replaced, and 6a replaces exactly this layer.
        //
        // Two halves, because either alone is hollow: that the construct really does make
        // the two shells agree, and that husk actually emits it.
        for sh in ["bash", "dash"] {
            let Ok(out) = std::process::Command::new(sh)
                .arg("-c")
                .arg("exec 9</husk-no-such-namespace-file || exit 1\necho REACHED_THE_WORKLOAD")
                .output()
            else {
                continue; // dash is not installed everywhere; bash carries the assertion
            };
            assert!(
                !String::from_utf8_lossy(&out.stdout).contains("REACHED_THE_WORKLOAD"),
                "{sh} continued past a failed namespace open — the guard must not depend on \
                 which shell the cluster ships"
            );
            assert!(!out.status.success(), "{sh} must exit nonzero");
        }

        let argv = built(&["./a.out"]);
        let script = &argv[2];
        assert!(
            script.contains("exec 9<\"$_u\" || exit 1"),
            "the userns open must be guarded by husk, not by the shell's disposition: {script}"
        );
        assert!(
            script.contains("exec 8<\"$_p\" || exit 1"),
            "and so must the pidns open: {script}"
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
        // The MUNGE mask, resolved on the node like the job guard does it. It cannot be a
        // static arg: --tmpfs on an absent DEST under a read-only root kills bwrap, and so
        // does masking /run and /var/run when they are the same directory. Both shipped
        // once and took the cage down, which is why a sibling test forbids the static form.
        assert!(script.contains("for _c in /run/munge /var/run/munge"), "{script}");
        assert!(script.contains("_m=\"$_m --tmpfs $_r\""), "{script}");
        assert!(script.contains("$_m "), "the mask must reach bwrap: {script}");
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
        let rank = FsPolicy::unchecked_for_test().rank_bwrap_args("/work");
        let argv = wrap_command(Profile::SingleNode, &rank, "/odd path/spool", 4242, None, &v(&["./a"]));
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
            &FsPolicy::unchecked_for_test().rank_bwrap_args("/work"),
            "/var/spool/slurmd",
            4242,
            None,
            &v(&["./a.out"]),
        );
        let script = &argv[2];
        assert!(script.contains("--userns 9"), "rank must join the shared userns: {script}");
        // The PID namespace is the SECOND share, and it must be joined the same way — as a
        // namespace the holder owns, never created per rank. `bwrap --unshare-pid` here
        // would give every rank its own namespace where it cannot name its peers, which is
        // the sibling-user-namespace failure that killed ICON, one layer down.
        assert!(script.contains("--pidns 8"), "rank must join the shared pidns: {script}");
        assert!(
            !script.contains("--unshare-pid"),
            "a rank must JOIN the job's pid namespace, never create its own: {script}"
        );
        // Both namespaces are named by ONE holder pid, and both are checked before use so
        // a dead holder is a sentence rather than a shell diagnostic.
        assert!(script.contains("/ns/pid"), "{script}");
        assert!(script.contains("/ns/user"), "{script}");
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
            &FsPolicy::unchecked_for_test().rank_bwrap_args("/work"),
            "/var/spool/slurmd",
            4_000_000_000, // above any pid_max: cannot exist
            None,
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
    fn a_rank_without_egress_gets_no_network_semantics_whatsoever() {
        // A job that never asked for a network must be UNAFFECTED by the fact that egress
        // exists: no relay, no proxy environment, no socat, nothing listening. That is the
        // property, and it is why the broker chooses the shape up front instead of letting
        // the script branch at run time.
        //
        // This assertion used to be "byte-for-byte what it was before egress existed — no
        // extra shell, no extra process". That was a corollary written as a law: it was true
        // of the implementation at the time, not a thing anyone needed. Held literally it
        // also forbade the B4-F8 fix, since closing the shared namespace fds is only possible
        // from a process bwrap starts. Semantics are what must not regress; script text is
        // not semantics.
        let script = &built(&["./a.out"])[2];
        assert!(!script.contains("SOCAT"), "no relay without egress: {script}");
        assert!(!script.contains("TCP-LISTEN"), "nothing listening: {script}");
        assert!(!script.contains("HTTP_PROXY"), "no proxy environment: {script}");
        assert!(!script.contains("net.sock"), "no socket bound in: {script}");
        // The workload is still exec'd from its own argv, never interpolated into script
        // text — the one property the inner shell must not cost us.
        assert!(script.contains("exec \"$@\"'"), "the inner shell execs argv: {script}");
        assert!(script.ends_with("husk-rank \"$@\"\n"), "the command is passed as argv: {script}");
    }

    #[test]
    fn a_networked_rank_closes_the_shared_namespace_fds_before_the_workload() {
        // **B4-F8.** fds 8 and 9 are the job's shared PID and user namespace handles. bwrap
        // consumes them at setup and does not close them, so they were inherited straight
        // into the workload — measured in a real rank as `8 -> pid:[…]`, `9 -> user:[…]`.
        // Nothing was reachable through them (NS_GET_PARENT → EPERM on both, setns on our
        // own userns → EINVAL), so this is hygiene; but "no use found" is a weaker claim
        // than "closed", and a handle to the namespace that IS the cage's shared identity
        // should not be in a workload's fd table by accident.
        //
        // Closed in the inner shell, which is the only place it CAN be done: not before
        // `exec bwrap` (bwrap needs them) and not by bwrap (it has no flag to drop them).
        let argv = wrap_command(
            Profile::SingleNode,
            &FsPolicy::unchecked_for_test().rank_bwrap_args("/work"),
            "/var/spool/slurmd",
            live_holder(),
            Some(Egress { sock: "/work/.husk-step-spool-7/net.sock", socat: "/work/.husk-step-spool-7/socat" }),
            &v(&["./a.out"]),
        );
        let script = &argv[2];
        assert!(script.contains("exec 8<&- 9<&-"), "the namespace fds must be closed: {script}");
        // Before the workload, not after — the point is that the workload never has them.
        let closed = script.find("exec 8<&- 9<&-").unwrap();
        let workload = script.rfind("exec \"$@\"").unwrap();
        assert!(closed < workload, "the close must precede the exec: {script}");
    }

    #[test]
    fn every_rank_shape_closes_the_namespace_fds_not_just_the_networked_one() {
        // The second half of B4-F8. The networked shape got this free (it already had an
        // inner shell for the relay); the plain shape needed one of its own, which is the
        // MPI-critical path — so assert BOTH, from one origin, because a security-relevant
        // line duplicated across two branches is exactly how husk's cleanup set once drifted
        // from the files it was meant to remove.
        let plain = built(&["./a.out"])[2].clone();
        let networked = wrap_command(
            Profile::SingleNode,
            &FsPolicy::unchecked_for_test().rank_bwrap_args("/work"),
            "/var/spool/slurmd",
            live_holder(),
            Some(Egress { sock: "/work/sp/net.sock", socat: "/work/sp/socat" }),
            &v(&["./a.out"]),
        )[2]
        .clone();
        for (what, script) in [("plain", &plain), ("networked", &networked)] {
            assert!(
                script.contains(CLOSE_NS_FDS),
                "{what} rank must drop the shared namespace handles: {script}"
            );
            let closed = script.find(CLOSE_NS_FDS).expect("close present");
            let workload = script.rfind("exec \"$@\"").expect("workload exec present");
            assert!(closed < workload, "{what}: the close must precede the exec: {script}");
        }
    }

    #[test]
    fn a_rank_with_egress_starts_its_own_relay() {
        // Each rank has its OWN network namespace, so the job cage's relay is unreachable
        // from here - the per-rank relay is a per-namespace adapter, not a second policy.
        // The single proxy outside the cage still decides everything.
        let argv = wrap_command(
            Profile::SingleNode,
            &FsPolicy::unchecked_for_test().rank_bwrap_args("/work"),
            "/var/spool/slurmd",
            live_holder(),
            Some(Egress { sock: "/work/.husk-step-spool-7/net.sock", socat: "/work/.husk-step-spool-7/socat" }),
            &v(&["./a.out"]),
        );
        let script = &argv[2];
        assert!(script.contains("TCP-LISTEN:3128"), "{script}");
        assert!(script.contains("/work/.husk-step-spool-7/socat"), "the bound socat: {script}");
        assert!(script.contains("bind=127.0.0.1"), "the relay listens on loopback only: {script}");
        assert!(script.contains("/work/.husk-step-spool-7/net.sock"), "{script}");
        assert!(script.contains("HTTPS_PROXY=http://127.0.0.1:3128"), "{script}");
        // The proxy variables are exported only when the socat husk bound in is actually
        // executable: a rank that cannot start a relay must look like a machine with no
        // network, not one with a broken proxy.
        assert!(script.contains("[ -x \"$_HUSK_SOCAT\" ]"), "{script}");
    }

    #[test]
    fn executing_it_with_egress_still_passes_the_command_through_untouched() {
        // THE QUOTING HAZARD. Adding the relay turns the exec target into a shell, so the
        // workload's argv now crosses one more quoting boundary - and shipping literal
        // quote characters into bwrap is precisely how the srun bind once took every job
        // down. Inspecting the text cannot catch that; running it and reading the
        // arguments can.
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("husk-ranknet-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let stub = dir.join("seccomp-wrapper");
        std::fs::write(&stub, "#!/bin/sh\nfor a in \"$@\"; do echo \"ARG:$a\"; done\n").unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();

        let hostile = "./solver; touch /tmp/husk-pwned-$$";
        let argv = wrap_command(
            Profile::SingleNode,
            &FsPolicy::unchecked_for_test().rank_bwrap_args("/work"),
            "/var/spool/slurmd",
            live_holder(),
            Some(Egress { sock: "/work/net.sock", socat: "/work/socat" }),
            &v(&[hostile, "--x=$(id)"]),
        );
        let job_id = format!("t{}", std::process::id());
        let out = std::process::Command::new("/bin/sh")
            .args(&argv[1..])
            .env("PATH", format!("{}:/usr/bin:/bin", dir.display()))
            .env("SLURM_JOB_ID", &job_id)
            .env("SLURM_STEP_ID", "0")
            .output()
            .expect("run the wrapper script");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir(format!("/dev/shm/husk-{job_id}"));
        let stdout = String::from_utf8_lossy(&out.stdout);

        assert!(out.status.success(), "script failed: {}", String::from_utf8_lossy(&out.stderr));
        assert!(
            stdout.contains(&format!("ARG:{hostile}")),
            "the command must still arrive verbatim as ONE argument:\n{stdout}"
        );
        assert!(stdout.contains("ARG:--x=$(id)"), "no command substitution:\n{stdout}");
        assert!(!stdout.contains("ARG:'"), "no literal quotes may reach the cage:\n{stdout}");
        assert!(
            !std::path::Path::new(&format!("/tmp/husk-pwned-{}", std::process::id())).exists(),
            "the hostile command must not have executed"
        );
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

    /// The rank script is ONE argv element on a real `srun` command line, so its own size
    /// is a resource. `JK2` added a dozen comment lines to it (the pointer to the job-cage
    /// twin), which is the moment to pin the margin rather than assume it.
    ///
    /// **Axis it does not cover:** it measures the script, not the whole `srun` command
    /// line — the options and the user's command are separate elements, each with its own
    /// `MAX_ARG_STRLEN` headroom, and `sbatch::MAX_LIST_VALUE_BYTES` bounds those.
    #[test]
    fn the_rank_script_is_a_small_fraction_of_one_argv_element() {
        let script = &built(&["true"])[2];
        // MAX_ARG_STRLEN, the kernel's per-element ceiling. Same number sbatch.rs derives
        // its list-value bound from; stated here because this is a different element.
        const MAX_ARG_STRLEN: usize = 128 * 1024;
        assert!(
            script.len() * 8 < MAX_ARG_STRLEN,
            "the rank script is {} bytes against a {MAX_ARG_STRLEN}-byte per-argument \
             kernel ceiling. Under 8x of margin means the next comment block is a job \
             that fails at execve with E2BIG and nothing naming why.",
            script.len()
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

    /// A5 cross-hop question (b), part 1 — the decisive answer. The rank wrapper builds the
    /// MUNGE-socket mask (`$_m`) by iterating CREDENTIAL_SOCKET_DIRS and expanding the result
    /// UNQUOTED in the bwrap exec line. That list is a compile-time constant of two root-owned
    /// system paths, and `wrap_command` takes NO mask-path argument — so a rank has no channel
    /// through which to add, remove, or alter a masked path. Anything job-derived reaching the
    /// loop could unmask the real MUNGE socket or mis-split the exec line.
    #[test]
    fn credential_mask_list_is_a_fixed_root_owned_constant_no_rank_can_influence() {
        assert_eq!(
            crate::settings::CREDENTIAL_SOCKET_DIRS,
            ["/run/munge", "/var/run/munge"],
            "the mask list must stay a fixed pair of root-owned dirs"
        );
        // The generated script iterates over exactly those literals — nothing job-derived is
        // spliced into the `for _c in ...` list, and the rank's own command rides in argv
        // AFTER the script rather than inside its body.
        let argv = wrap_command(
            Profile::SingleNode,
            &FsPolicy::unchecked_for_test().rank_bwrap_args("/work"),
            "/var/spool/slurmd",
            live_holder(),
            None,
            &v(&["ZZ_RANK_CMD_SENTINEL"]),
        );
        let script = &argv[2];
        assert!(
            script.contains("for _c in /run/munge /var/run/munge; do"),
            "the mask loop must iterate the constant verbatim:\n{script}"
        );
        assert!(
            !script.contains("ZZ_RANK_CMD_SENTINEL"),
            "the rank command must never be interpolated into the script body:\n{script}"
        );
        assert_eq!(
            argv.last().map(String::as_str),
            Some("ZZ_RANK_CMD_SENTINEL"),
            "the rank command must ride in argv after the script"
        );
    }

    /// **`B3-7`.** The rank's credential-socket mask is what `profile.rs` names as the
    /// load-bearing control for the only shipped profile — the seccomp layer adds no
    /// syscall rules there, so the MUNGE socket is kept out of a rank by this mount and
    /// by nothing else. It was chosen by a `for` loop in generated shell whose failure
    /// arm was a bare `continue`: a credential path that existed and could not be masked
    /// was dropped, `$_m` came up short, bwrap built the cage anyway, and no channel
    /// carried the fact that the control had not been applied (`P7`).
    ///
    /// This drives the REAL loop bytes — pulled out of a generated script, including the
    /// refusal block after `done` — under both `bash` and `dash`, against a controlled
    /// tree. Five dispositions, because the point of the fix is that the loop now has one
    /// disposition per arm rather than one for everything:
    ///
    /// * nothing there at all -> mask nothing, exit 0. **This is the case that must not
    ///   become a refusal**: a node with no munge has no credential socket to hide, and
    ///   `--tmpfs` on an absent DEST is what killed the cage twice.
    /// * ordinary pair -> masked once, de-duplicated (`/var/run` -> `/run`), exit 0.
    /// * resolves through whitespace -> **exit non-zero, nothing masked, and a message**.
    /// * resolves through a tab -> same.
    /// * exists but is not a directory -> same.
    ///
    /// **The false friend it replaces** is
    /// `mask_loop_whitespace_guard_refuses_space_or_tab_resolving_paths`, which asserted
    /// the token list `["--tmpfs", <plain>]` and `status.success()` — i.e. it pinned the
    /// silent drop AS CORRECT, and the suite ratified the fail-open. Its real contract
    /// (an unquoted `$_m` must never be mis-split into stray bwrap tokens) is kept and
    /// strengthened here: the refusal cases assert **zero** tokens, not merely the absence
    /// of the bad one.
    ///
    /// **Mutations that turn this red**, each run against the full suite:
    /// * `break` -> `continue` in the whitespace arm: `whitespace`/`tab` exit 0 and emit
    ///   `["--tmpfs", <plain>]` — exactly what the old test asserted.
    /// * `[ -e "$_c" ] || continue` -> `continue` (i.e. the old `[ -d ] || continue`):
    ///   `not_a_directory` exits 0.
    /// * dropping the `if [ -n "$_why" ]` block: all three refusal cases exit 0.
    /// * making the absent case refuse: `only_absent` goes red, which is the point of
    ///   having it.
    ///
    /// **What it does not cover.** It exercises the loop with a substituted path list, so
    /// it says nothing about the real `/run/munge` (a compile-time constant, pinned by
    /// `credential_mask_list_is_a_fixed_root_owned_constant_no_rank_can_influence`) and
    /// nothing about whether bwrap then actually mounts a tmpfs there — that is
    /// `selftest.sh`'s `cred.munge` probe, and only hardware answers it. It also does not
    /// cover what `srun` does with the rank's non-zero exit, or a mask path containing a
    /// newline (unreachable while the list is that constant).
    #[test]
    fn a_credential_path_that_cannot_be_masked_stops_the_rank_instead_of_being_dropped() {
        use std::os::unix::fs::symlink;

        let dir = std::env::temp_dir().join(format!("husk-mask-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Real targets, two of them with whitespace IN THEIR PATH, reached by
        // absolute-target symlinks so `readlink -f` resolves onto them. A duplicate of
        // `plain` exercises de-duplication, and `notdir` is a file where a credential
        // directory would be.
        let plain = dir.join("plain");
        let spaced = dir.join("spaced dir");
        let tabbed = dir.join("tab\tdir");
        std::fs::create_dir_all(&plain).unwrap();
        std::fs::create_dir_all(&spaced).unwrap();
        std::fs::create_dir_all(&tabbed).unwrap();
        symlink(&spaced, dir.join("link_space")).unwrap();
        symlink(&tabbed, dir.join("link_tab")).unwrap();
        symlink(&plain, dir.join("link_dup")).unwrap();
        std::fs::write(dir.join("notdir"), b"not a directory\n").unwrap();

        // Pull the real loop AND the refusal that follows it out of a generated script.
        // Ending at `done` is what let the old test miss the disposition entirely, so the
        // slice runs to the next statement instead.
        let full = built(&["true"])[2].clone();
        let lstart = full.find("_m=\n").expect("mask loop assignment not found");
        let lend = full[lstart..].find("\n_s=").expect("statement after the mask block not found");
        let loop_src = &full[lstart..lstart + lend];
        assert!(loop_src.contains("done\n"), "the slice must include the loop: {loop_src}");
        assert!(
            loop_src.contains("exit 1"),
            "the slice must include the refusal, or this test cannot see it: {loop_src}"
        );

        let list = |names: &[&str]| {
            names
                .iter()
                .map(|n| sh_quote(&dir.join(n).to_string_lossy()))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let real_plain =
            std::fs::canonicalize(&plain).unwrap().to_string_lossy().into_owned();

        // (name, path list, must exit 0, expected mask tokens, a string stderr must name)
        let cases: [(&str, String, bool, Vec<String>, &str); 5] = [
            ("only_absent", list(&["gone_a", "gone_b"]), true, vec![], ""),
            (
                "plain_and_dup",
                list(&["plain", "link_dup"]),
                true,
                vec!["--tmpfs".to_string(), real_plain.clone()],
                "",
            ),
            ("whitespace", list(&["plain", "link_space"]), false, vec![], "link_space"),
            ("tab", list(&["plain", "link_tab"]), false, vec![], "link_tab"),
            ("not_a_directory", list(&["plain", "notdir"]), false, vec![], "notdir"),
        ];

        for (name, paths, ok, want, names_path) in &cases {
            let body = loop_src.replace(
                "for _c in /run/munge /var/run/munge; do",
                &format!("for _c in {paths}; do"),
            );
            assert!(body.contains(paths.as_str()), "path substitution failed for {name}");
            // Expand `$_m` UNQUOTED exactly as the exec line does, one token per NUL.
            let program = format!("{body}\nfor w in $_m; do printf '%s\\0' \"$w\"; done\n");
            for sh in ["/bin/bash", "/bin/sh"] {
                let out = std::process::Command::new(sh)
                    .arg("-c")
                    .arg(&program)
                    .output()
                    .unwrap();
                let err = String::from_utf8_lossy(&out.stderr).into_owned();
                assert_eq!(
                    out.status.success(),
                    *ok,
                    "{name} under {sh}: wrong disposition (stderr: {err})"
                );
                let toks: Vec<String> = out
                    .stdout
                    .split(|b| *b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect();
                assert_eq!(&toks, want, "{name} under {sh}: wrong mask tokens");
                if *ok {
                    assert!(err.is_empty(), "{name} under {sh}: an accepted node must be quiet: {err}");
                    continue;
                }
                // The refusal has to be diagnosable by the person who can act on it, and
                // must not send the job owner looking at their own script (`P11`).
                assert!(
                    err.contains(names_path),
                    "{name} under {sh}: the refusal must name the path it refused: {err}"
                );
                assert!(
                    err.contains("MUNGE"),
                    "{name} under {sh}: the refusal must say which control failed: {err}"
                );
                assert!(
                    err.contains("Nothing your job did"),
                    "{name} under {sh}: the refusal must not point at the job: {err}"
                );
                // Whitespace must never reach bwrap's argv - the old test's real contract.
                for bad in ["spaced dir", "tab\tdir"] {
                    assert!(
                        !toks.iter().any(|t| t.contains(bad)),
                        "{name} under {sh}: a whitespace path leaked into the exec line: {toks:?}"
                    );
                }
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
