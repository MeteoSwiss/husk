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

use session::Session;
use spool::Broker;
use std::path::PathBuf;
use std::time::Duration;

// Die with the session: the wrapper spawns us, then execs the agent (same PID).
// PR_SET_PDEATHSIG asks the kernel to SIGTERM us when that parent task exits, so we
// never linger as an orphan watching a dead spool. (Zero-dep: one libc symbol.)
const PR_SET_PDEATHSIG: std::os::raw::c_int = 1;
const SIGTERM: std::os::raw::c_ulong = 15;
extern "C" {
    fn prctl(
        option: std::os::raw::c_int,
        arg2: std::os::raw::c_ulong,
        arg3: std::os::raw::c_ulong,
        arg4: std::os::raw::c_ulong,
        arg5: std::os::raw::c_ulong,
    ) -> std::os::raw::c_int;
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

    let mut dry_run = false;
    let mut once = false;
    let mut spool_arg: Option<String> = None;
    let mut poll_ms: u64 = 200;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--dry-run" => dry_run = true,
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
