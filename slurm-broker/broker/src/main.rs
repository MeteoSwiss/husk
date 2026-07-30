//! husk-slurm-broker — trusted out-of-sandbox SLURM broker for husk.
//! Watches the spool, validates agent sbatch requests as hostile input, forces
//! safe options, re-sandboxes the job, and submits. See BROKER.md / PROTOCOL.md.

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

fn main() {
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
