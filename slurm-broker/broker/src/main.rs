//! husk-slurm-broker — trusted out-of-sandbox SLURM broker for husk.
//! Watches the spool, validates agent sbatch requests as hostile input, forces
//! safe options, re-sandboxes the job, and submits. See BROKER.md / PROTOCOL.md.

mod cage;
mod policy;
mod profile;
mod rank;
mod protocol;
mod sbatch;
mod srun;
mod session;
mod settings;
mod spool;
mod step;

use session::Session;
use spool::Broker;
use std::path::PathBuf;
use std::time::Duration;

// Die with the session: the wrapper spawns us, then execs the agent (same PID).
// PR_SET_PDEATHSIG asks the kernel to SIGTERM us when that parent task exits, so we
// never linger as an orphan watching a dead spool. (Zero-dep: one libc symbol.)
const PR_SET_PDEATHSIG: std::os::raw::c_int = 1;
const SIGTERM: std::os::raw::c_ulong = 15;

/// `prctl(PR_SET_DUMPABLE, 0)` — refuse to be a ptrace/CMA target.
///
/// The broker is the one process in reach of a caged job that deliberately holds what the
/// cage removes: MUNGE, the daemon route, the real sbatch/srun. Everything on a compute
/// node runs as the SAME UID, and the kernel gates `process_vm_readv`/`process_vm_writev`
/// with the ptrace-attach check — so same-uid is normally enough to read another
/// process's memory. Yama's `ptrace_scope` would narrow that to descendants, but Balfrin
/// has no Yama at all (verified 2026-07-31), leaving credentials as the only gate.
///
/// Clearing the dumpable flag makes the kernel demand CAP_SYS_PTRACE instead, which an
/// unprivileged caged rank cannot have. So the broker stops being addressable even if
/// CMA is later allowed for MPI — which is exactly the concession being considered, since
/// Cray MPICH needs `process_vm_readv` for intra-node transfers.
///
/// Consistent rather than new policy: `ptrace` is already in seccomp-wrapper's deny-list.
/// This closes the same door from the other side, for the process that matters most.
///
/// Costs: no core dumps from the broker, and its `/proc/<pid>` entries become root-owned,
/// so `ls /proc/<pid>/fd` on it stops working for the user. Both acceptable for a daemon.
const PR_SET_DUMPABLE: std::os::raw::c_int = 4;
extern "C" {
    fn prctl(
        option: std::os::raw::c_int,
        arg2: std::os::raw::c_ulong,
        arg3: std::os::raw::c_ulong,
        arg4: std::os::raw::c_ulong,
        arg5: std::os::raw::c_ulong,
    ) -> std::os::raw::c_int;
}

/// Make this process unreadable to same-uid processes (see PR_SET_DUMPABLE).
fn refuse_to_be_read() {
    // SAFETY: PR_SET_DUMPABLE with a constant; the remaining args are ignored.
    if unsafe { prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        // Not fatal: it is a hardening measure, not the boundary. Say so rather than
        // failing a submission over it — but say it, so a kernel that refuses is visible.
        eprintln!("broker: warning: could not clear the dumpable flag; this process is \
                   readable by same-uid processes (process_vm_readv/ptrace)");
    }
}

fn die_with_parent() {
    // SAFETY: PR_SET_PDEATHSIG with a signal number; extra args are ignored.
    unsafe {
        prctl(PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0);
    }
    // Guard the race where the parent already died before the prctl call.
    // SAFETY: getppid takes no args and cannot fail.
    if unsafe { libc_getppid() } == 1 {
        std::process::exit(0);
    }
}

extern "C" {
    #[link_name = "getppid"]
    fn libc_getppid() -> std::os::raw::c_int;
}

/// `--hold-cage` — own the node cage's namespaces and nothing else.
///
/// Creates one **bare** user namespace, identity-maps this user into it, and does nothing
/// else for as long as the job needs it. No mounts, no network: every rank still builds
/// its own cage with `bwrap --userns <this>`, and sharing only the user namespace is what
/// makes rank-to-rank CMA legal (see the `cage` module).
///
/// Deliberately not `unshare(1) -- sleep`: the namespace is created in-process so the map
/// is ours to guarantee rather than a flag to trust, and so nothing sits between the
/// step-broker and this process to swallow the shutdown signal.
///
/// **The step-broker spawns this; it must never BE this.** The broker is defined by being
/// outside the cage — it holds MUNGE, the daemon route and the real `srun`, all of which
/// the cage removes. Sharing the ranks' user namespace would also make the broker a valid
/// `ptrace_may_access` target, and "the broker is not a target" is half the argument that
/// made the CMA read concession acceptable at all (`PR_SET_DUMPABLE` is the other half).
///
/// Prints its pid, then blocks until stdin reaches EOF. The pid is reported by the holder
/// itself rather than taken from `Child::id()` so that it is the pid actually inside the
/// namespace. Two independent shutdown paths, because a namespace leaked per job would
/// accumulate on a node: EOF on stdin when the step-broker drops the pipe, and `PDEATHSIG`
/// if the step-broker dies without dropping anything.
fn hold_cage_mode() -> ! {
    die_with_parent();

    if let Err(e) = cage::create_shared_userns() {
        eprintln!("husk: {e}");
        std::process::exit(1);
    }

    // NOTE: the holder deliberately does NOT call refuse_to_be_read().
    //
    // NOT because it cannot. Measured 2026-07-31 on kernel 6.8: a holder that clears
    // PR_SET_DUMPABLE can still be opened and joined with `bwrap --userns` by a sibling
    // process, so the flag is available here. An earlier comment claimed otherwise and
    // was never measured.
    //
    // It is left off because the trade is bad. The gain is a third layer on something
    // already protected twice over — a rank cannot read this process (measured), and it
    // holds no credentials, no daemon route and no memory worth reading. The risk is
    // kernel-dependent: that measurement is from 6.8, Balfrin runs 5.14 Cray Shasta, and
    // if joining did break there then EVERY step would die. Measure on the target before
    // trading a working MPI path for defence in depth on an empty process. It also makes
    // `/proc/<pid>` root-owned, which already misled one debugging session.
    //
    // It does not need the flag anyway: a rank is MEASURABLY unable to read this process
    // (2026-07-31, `process_vm_readv` -> EPERM with Yama neutralised, against a control
    // that reads a peer rank successfully). The likely reason — explanation, not
    // measurement — is that this process's mm belongs to the INITIAL user namespace,
    // since it was created at exec and the namespace came later, so the kernel's
    // ptrace-attach check demands CAP_SYS_PTRACE there, which a rank does not have.
    //
    // And the exposure would be nil regardless: no credentials, no daemon route, no
    // memory worth reading. It exists only to keep one namespace alive.

    use std::io::{Read, Write};
    println!("{}", std::process::id());
    if std::io::stdout().flush().is_err() {
        eprintln!("husk: cage holder could not report readiness");
        std::process::exit(1);
    }

    let mut buf = [0u8; 64];
    loop {
        match std::io::stdin().read(&mut buf) {
            Ok(0) | Err(_) => break, // broker closed the pipe, or it broke: either way, done
            Ok(_) => continue,       // nothing is expected on this channel; ignore it
        }
    }
    std::process::exit(0);
}

fn main() {
    // Before the daemon preamble: the holder must not run it — see hold_cage_mode.
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) == Some("--hold-cage") {
        hold_cage_mode();
    }

    die_with_parent();
    refuse_to_be_read();

    let mut dry_run = false;
    let mut once = false;
    let mut spool_arg: Option<String> = None;
    let mut poll_ms: u64 = 200;
    // --step-broker: the compute-node half. Same binary, so one artifact to install and
    // one thing to keep in sync; the modes share the spool protocol and nothing else.
    let mut step_broker = false;
    let mut workdir_arg: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--dry-run" => dry_run = true,
            "--step-broker" => step_broker = true,
            "--workdir" => workdir_arg = args.next(),
            "--once" => once = true,
            "--spool" => spool_arg = args.next(),
            "--poll-ms" => {
                poll_ms = args.next().and_then(|s| s.parse().ok()).unwrap_or(poll_ms)
            }
            "-h" | "--help" => {
                print_help();
                return;
            }
            other => {
                eprintln!("broker: unknown argument '{other}' (try --help)");
                std::process::exit(2);
            }
        }
    }

    let spool = spool_arg
        .or_else(|| std::env::var("HUSK_SLURM_SPOOL").ok())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_dir()
                .unwrap_or_default()
                .join(".husk-slurm-spool")
        });

    if let Err(e) = std::fs::create_dir_all(&spool) {
        eprintln!("broker: cannot create spool {spool:?}: {e}");
        std::process::exit(1);
    }

    // ---- step-broker mode: brokers srun for an ALREADY RUNNING job ----------------
    // It needs no Session (no uenv to inherit, no partition to force — the allocation
    // already exists) and does not submit anything; it launches steps within the job it
    // was started by.
    if step_broker {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
        let workdir = workdir_arg.unwrap_or_else(|| {
            std::env::current_dir().unwrap_or_default().to_string_lossy().to_string()
        });
        let fs_policy = settings::FsPolicy::resolve(&home, &PathBuf::from(&workdir));
        let mut sb = step::StepBroker::new(
            spool.clone(),
            fs_policy,
            profile::Profile::SingleNode,
            workdir,
            dry_run,
        );
        eprintln!("step-broker: watching {spool:?}{}", if dry_run { " (dry-run)" } else { "" });
        loop {
            if let Err(e) = sb.tick() {
                eprintln!("step-broker: scan error: {e}");
            }
            if once {
                break;
            }
            std::thread::sleep(Duration::from_millis(poll_ms));
        }
        return;
    }

    let session = Session::from_env();
    if session.uenv.is_none() {
        // No uenv loaded is a NORMAL state on an HPC — not an error. Inform, don't scold.
        eprintln!(
            "broker: no uenv session detected — jobs will run in the base HPC \
             environment (inherited login env / modules). This is fine; if you want \
             a uenv stack, `uenv start` it before launching husk."
        );
    }

    // Resolve the compute-cage filesystem policy ONCE, now, at startup — from the broker's
    // OWN working directory. The broker is spawned by the human in the project directory
    // (before the agent execs), so `current_dir()` is the TRUSTED project dir. This must
    // NOT come from the agent-controlled `req.cwd`, and capturing it pre-agent means the
    // agent cannot tamper with the settings files the cage is built from. (F17)
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    let project_dir = std::env::current_dir().unwrap_or_default();
    let fs_policy = settings::FsPolicy::resolve(&home, &project_dir);
    eprintln!("broker: compute-cage policy resolved from project dir {project_dir:?}");

    let broker = Broker {
        spool: spool.clone(),
        session,
        dry_run,
        fs_policy,
    };
    eprintln!(
        "broker: watching {spool:?}{}",
        if dry_run { " (dry-run)" } else { "" }
    );

    loop {
        if let Err(e) = broker.process_once() {
            eprintln!("broker: scan error: {e}");
        }
        if once {
            break;
        }
        std::thread::sleep(Duration::from_millis(poll_ms));
    }
}

fn print_help() {
    println!(
        "husk-slurm-broker — trusted out-of-sandbox SLURM broker for husk\n\
\n\
USAGE: husk-slurm-broker [--spool DIR] [--dry-run] [--once] [--poll-ms N]\n\
\n\
  --spool DIR   spool directory (default: $HUSK_SLURM_SPOOL or ./.husk-slurm-spool)\n\
  --dry-run     print the sbatch argv + staged script instead of submitting\n\
  --once        process the spool once and exit (for testing)\n\
  --poll-ms N   poll interval in milliseconds (default 200)\n\
\n\
Policy: see BROKER.md.  Wire protocol: see PROTOCOL.md."
    );
}
