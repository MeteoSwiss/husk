//! The **step-broker**: the trusted half of the srun pair, on the compute node.
//!
//! It runs OUTSIDE the job's bwrap cage but INSIDE the allocation, so it holds what the
//! caged job deliberately does not: MUNGE, a route to slurmctld/slurmd, and the job
//! credential. It reads step requests from the step-spool, validates them as hostile
//! input (`srun::interpret`), forces the per-task cage (`rank::wrap_command`), and runs
//! the real `srun`.
//!
//! ## Concurrency: spawn-and-poll, not thread-per-step
//!
//! Steps must be able to overlap. Packing many small `srun`s into one allocation
//! (`for i in …; do srun -n1 --exclusive … & done; wait`) is standard HPC practice for
//! sweeps and ensembles, coupled models run concurrent steps, and gate C7 measured that
//! Balfrin runs them concurrently with and without `--overlap`. A serial broker would
//! not merely be slower — the second stub would **hang** with no message, which is the
//! most expensive failure mode to diagnose.
//!
//! But this is a trusted process, so it does not spawn a thread per step. It `spawn()`s
//! the `srun`, keeps the child in a list, and `try_wait()`s each pass of the loop,
//! writing the response when one exits. Concurrency with no threads, no shared mutable
//! state and no locks. The stub tails the output files itself, so nothing has to pump
//! bytes here either.
//!
//! In-flight steps are **capped**. The spool is agent-writable, so without a bound a
//! flood of requests becomes a fork bomb in the one process that must not fall over —
//! the same class of denial-of-service as the read-only query flood fixed in v0.4. Past
//! the cap a request is rejected with a message that says so, rather than queued
//! invisibly.

use crate::profile::Profile;
use crate::protocol::{Request, Response};
use crate::rank;
use crate::settings::{self, FsPolicy};
use crate::spool::{is_valid_id, read_nofollow, write_atomic};
use crate::srun;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// Maximum steps running at once. Generous for real workloads (an ensemble of 32 small
/// tasks fits), small enough that a runaway request loop cannot exhaust the node.
const MAX_IN_FLIGHT: usize = 32;

/// Where Slurm's `mpi/cray_shasta` plugin writes the per-step `apinfo` file, when
/// `scontrol` cannot be reached. The rank cage binds `<dir>/mpi_cray_shasta/<job>.<step>`
/// read-write; getting it wrong costs the MPI bootstrap (EROFS), not containment.
const DEFAULT_SLURMD_SPOOL: &str = "/var/spool/slurmd";

struct Running {
    id: String,
    child: Child,
}

pub struct StepBroker {
    pub spool: PathBuf,
    pub fs_policy: FsPolicy,
    pub profile: Profile,
    pub dry_run: bool,
    /// The workdir the ranks run in — the job's, captured at guard time, never taken
    /// from a request.
    pub workdir: String,
    slurmd_spool: String,
    /// Our own environment, captured at startup. The ranks inherit it via srun, so it is
    /// the baseline against which a job script's changes are measured.
    base_env: std::collections::BTreeMap<String, String>,
    in_flight: Vec<Running>,
    /// The job's shared user namespace, owned by a child process. See `cage`.
    holder: Option<CageHolder>,
    /// The egress proxy's socket, inherited from the guard that started us.
    ///
    /// INHERITED rather than reconstructed from the job id: the guard builds this path
    /// once and exports it, so there is a single origin. Rebuilding it here from
    /// `SLURM_JOB_ID` would be a second copy of the same construction, and the two would
    /// eventually disagree — which is the failure this project keeps meeting.
    net_sock: Option<String>,
    /// The socat the guard bound into the cage. Inherited, not derived — see `rank::Egress`.
    net_socat: Option<String>,
}

/// The child that owns the job's shared user namespace.
///
/// Holding the `Child` is what keeps the namespace alive, and dropping it closes the
/// holder's stdin, which is one of its two shutdown paths (`PDEATHSIG` is the other).
/// Nothing else about the child is used — it is a handle to a namespace, not a worker.
struct CageHolder {
    pid: u32,
    _child: std::process::Child,
}

impl StepBroker {
    pub fn new(
        spool: PathBuf,
        fs_policy: FsPolicy,
        profile: Profile,
        workdir: String,
        dry_run: bool,
    ) -> Self {
        let slurmd_spool = resolve_slurmd_spool();
        eprintln!("step-broker: apinfo spool dir {slurmd_spool:?}");
        StepBroker {
            spool,
            fs_policy,
            profile,
            dry_run,
            workdir,
            slurmd_spool,
            base_env: std::env::vars().collect(),
            in_flight: Vec::new(),
            holder: None,
            net_sock: std::env::var("HUSK_NET_SOCK").ok().filter(|s| !s.is_empty()),
            net_socat: std::env::var("HUSK_SOCAT").ok().filter(|s| !s.is_empty()),
        }
    }

    /// One pass: reap finished steps, then admit new requests. Never blocks on a step.
    pub fn tick(&mut self) -> std::io::Result<()> {
        self.reap();
        self.scan()
    }

    /// Start the job's cage holder if it is not running yet, and return its pid.
    ///
    /// Lazy on purpose: a step-broker that never launches a step should not create a
    /// namespace. Created once per JOB rather than per step — nothing in it is
    /// step-specific, and a namespace per step would be a process per step to leak.
    fn ensure_holder(&mut self) -> Result<u32, String> {
        // A cached pid is a claim about a process, and processes end. If the holder died,
        // every later step in the job was handed its pid anyway and failed at its own
        // fail-closed gate on `/proc/<pid>/ns/user` — for the whole wall time, with no
        // attempt to recover. Worse in principle than a wedge: pids are recycled, so a
        // stale one can eventually name a DIFFERENT live process of this user's, and the
        // check would pass on a namespace that has nothing to do with this job.
        //
        // Verify it is still the holder we started before handing it out. The namespace
        // link is the evidence, not the pid: it is what the ranks will actually open, and
        // it disappears with the process.
        if let Some(h) = &self.holder {
            if std::path::Path::new(&crate::cage::userns_path(h.pid)).exists() {
                return Ok(h.pid);
            }
            eprintln!(
                "husk: the cage holder for this job (pid {}) is gone; starting a new one. \
                 Steps already running keep the namespace they joined.",
                h.pid
            );
            self.holder = None;
        }
        let exe = std::env::current_exe()
            .map_err(|e| format!("cannot locate the husk broker binary: {e}"))?;
        let mut child = std::process::Command::new(&exe)
            .arg("--hold-cage")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot start the cage holder ({}): {e}", exe.display()))?;

        // The holder reports the pid that is actually INSIDE the namespace. Taking
        // `child.id()` instead would be a guess about process arrangement.
        let mut line = String::new();
        let stdout = child.stdout.take().ok_or("cage holder has no stdout")?;
        std::io::BufRead::read_line(&mut std::io::BufReader::new(stdout), &mut line)
            .map_err(|e| format!("cage holder did not report readiness: {e}"))?;
        let pid: u32 = line
            .trim()
            .parse()
            .map_err(|_| format!("cage holder reported {line:?} instead of a pid"))?;

        // stdin stays OPEN inside `child` for the broker's lifetime: closing it is how
        // the holder learns to exit.
        self.holder = Some(CageHolder { pid, _child: child });
        Ok(pid)
    }

    /// Write the response for every step that has exited. `try_wait` does not block, so
    /// a four-hour step costs nothing here.
    fn reap(&mut self) {
        let spool = self.spool.clone();
        self.in_flight.retain_mut(|r| match r.child.try_wait() {
            Ok(None) => true, // still running
            Ok(Some(status)) => {
                let code = status.code().unwrap_or_else(|| {
                    // Killed by a signal: report it the way a shell would, so the number
                    // in the job log matches what a user would see uncaged.
                    use std::os::unix::process::ExitStatusExt;
                    128 + status.signal().unwrap_or(0)
                });
                let resp = if code == 0 {
                    Response::query(&r.id, String::new(), String::new(), 0)
                } else {
                    let mut resp = Response::query(&r.id, String::new(), String::new(), code);
                    resp.message = format!("step exited with status {code}");
                    resp
                };
                write_response(&spool, &r.id, &resp);
                false
            }
            Err(e) => {
                eprintln!("step-broker: wait failed for {}: {e}", r.id);
                let resp = Response::error(&r.id, format!("could not wait for the step: {e}"));
                write_response(&spool, &r.id, &resp);
                false
            }
        });
    }

    fn scan(&mut self) -> std::io::Result<()> {
        let mut requests: Vec<PathBuf> = Vec::new();
        for entry in fs::read_dir(&self.spool)? {
            let entry = entry?;
            // Regular files only: the spool is agent-writable, so a symlinked request
            // could turn the broker into a read oracle or point it at a FIFO. (F5)
            if !matches!(entry.file_type(), Ok(ft) if ft.is_file()) {
                continue;
            }
            let path = entry.path();
            if path
                .file_name()
                .and_then(|s| s.to_str())
                .map(|s| s.starts_with("req-") && s.ends_with(".json"))
                .unwrap_or(false)
            {
                requests.push(path);
            }
        }
        for path in requests {
            self.admit(&path);
        }
        Ok(())
    }

    fn admit(&mut self, req_path: &Path) {
        let data = match read_nofollow(req_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("step-broker: read {req_path:?}: {e}");
                let _ = fs::remove_file(req_path);
                return;
            }
        };
        let _ = fs::remove_file(req_path);
        let req: Request = match serde_json::from_slice(&data) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("step-broker: malformed request {req_path:?}: {e}");
                return;
            }
        };
        if !is_valid_id(&req.id) {
            eprintln!("step-broker: dropping request with unsafe id {:?}", req.id);
            return;
        }
        let id = req.id.clone();
        eprintln!("step-broker: request id={id} tool={} argv={:?}", req.tool, req.argv);

        // Only steps are brokered here. The sbatch broker on the login node handles
        // submissions; a job may not submit new jobs from inside its own cage (AV8).
        if req.tool != "srun" {
            let msg = format!(
                "'{}' is not brokered inside a job. Only srun is, and only for steps of \
                 this allocation.",
                req.tool
            );
            write_response(&self.spool, &id, &Response::rejected(&id, msg));
            return;
        }
        if self.in_flight.len() >= MAX_IN_FLIGHT {
            let msg = format!(
                "too many steps already running ({MAX_IN_FLIGHT}). husk caps concurrent \
                 steps so a runaway loop cannot exhaust the node; wait for one to finish."
            );
            write_response(&self.spool, &id, &Response::rejected(&id, msg));
            return;
        }

        let step = match srun::interpret(&req.argv) {
            Ok(s) => s,
            Err(reason) => {
                write_response(&self.spool, &id, &Response::rejected(&id, reason));
                return;
            }
        };

        // Build the real invocation: forced options, then the validated ones, then the
        // per-task wrapper that cages whatever the command turns out to be.
        // Run the ranks where the CALLER was, not where the job started. A run script
        // almost always `cd`s into its case directory before launching:
        //     cd $RUNDIR && srun ./icon
        // and ICON then opens `icon_master.namelist` relative to that. Forcing the
        // job's start directory instead sent the ranks somewhere else entirely
        // (Balfrin 2026-07-31: `open_nml: Could not open icon_master.namelist`).
        //
        // `req.cwd` is agent-controlled, so it gets the same check the sbatch path
        // applies to its workdir: absolute, no traversal, not `/`, not under a hidden
        // home. The cage's WRITABLE root is unchanged — this only decides where the
        // ranks start, so honouring it cannot widen what they may write.
        let cwd = if settings::is_workdir_allowed(&req.cwd) {
            req.cwd.clone()
        } else {
            let msg = format!(
                "the step's working directory {:?} is not allowed (it must be an absolute \
                 path, not '/', and not under a hidden home like /users)",
                req.cwd
            );
            write_response(&self.spool, &id, &Response::rejected(&id, msg));
            return;
        };

        let mut argv = vec!["srun".to_string()];
        argv.push("--chdir".to_string());
        argv.push(cwd);
        argv.extend(step.options);
        argv.push("--".to_string());
        // The rank cage, plus the job script's own environment as `--setenv` pairs.
        // A brokered srun otherwise breaks the chain by which a run script's `export`
        // reaches its ranks — the script runs inside the cage, the real srun outside it —
        // and `export OMP_NUM_THREADS=4; srun ./icon` would silently run with different
        // settings than it asked for. See rank::setenv_args for why these go through
        // bwrap rather than into srun's own environment.
        // The job's shared user namespace must exist before any rank starts. Fail the
        // step rather than fall back to per-rank namespaces: that fallback would run the
        // workload in cages that cannot CMA each other, which surfaces as an obscure MPI
        // error rather than as the containment change it actually is.
        let holder_pid = match self.ensure_holder() {
            Ok(pid) => pid,
            Err(e) => {
                let msg = format!("husk: cannot create the job's shared user namespace: {e}");
                eprintln!("step-broker: {msg}");
                write_response(&self.spool, &id, &Response::rejected(&id, msg));
                return;
            }
        };

        let mut cage = self.fs_policy.rank_bwrap_args(&self.workdir);
        // Only the DELTA against our own environment: srun propagates that to the tasks
        // already, so forwarding everything would re-set hundreds of identical values and
        // bury the handful the run script actually changed.
        cage.extend(rank::env_args(&req.env, &self.base_env, &self.fs_policy.unset_env));
        argv.extend(rank::wrap_command(
            self.profile,
            &cage,
            &self.slurmd_spool,
            holder_pid,
            match (self.net_sock.as_deref(), self.net_socat.as_deref()) {
                (Some(sock), Some(socat)) => Some(rank::Egress { sock, socat }),
                // Egress needs BOTH. With only one, a rank would start a relay that
                // cannot connect, or none at all while advertising a proxy — either way a
                // confusing failure in place of an honest "no network".
                _ => None,
            },
            &step.command,
        ));

        if self.dry_run {
            println!("---- DRY RUN step (request {id}) ----");
            println!("argv: {argv:?}");
            write_response(&self.spool, &id, &Response::query(&id, String::new(), String::new(), 0));
            return;
        }

        // The stub streams these while the step runs, which is why they are files and
        // not pipes: nothing here has to pump bytes, and a step that outlives a dead
        // stub still writes somewhere harmless.
        let out_path = self.spool.join(format!("out-{id}"));
        let err_path = self.spool.join(format!("err-{id}"));
        let (out, err) = match (fs::File::create(&out_path), fs::File::create(&err_path)) {
            (Ok(o), Ok(e)) => (o, e),
            _ => {
                let msg = "could not create the step's output files in the spool".to_string();
                write_response(&self.spool, &id, &Response::error(&id, msg));
                return;
            }
        };

        match Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
        {
            Ok(child) => {
                eprintln!("step-broker: launched step for {id} (pid {})", child.id());
                self.in_flight.push(Running { id, child });
            }
            Err(e) => {
                let msg = format!("could not launch srun: {e}");
                write_response(&self.spool, &id, &Response::error(&id, msg));
            }
        }
    }
}

fn write_response(spool: &Path, id: &str, resp: &Response) {
    let path = spool.join(format!("resp-{id}.json"));
    match serde_json::to_vec(resp) {
        Ok(bytes) => {
            if let Err(e) = write_atomic(&path, &bytes) {
                eprintln!("step-broker: failed to write response for {id}: {e}");
            }
        }
        Err(e) => eprintln!("step-broker: failed to serialize response for {id}: {e}"),
    }
}

/// Ask Slurm where slurmd's spool lives, since that is where the per-step `apinfo` file
/// the MPI bootstrap needs is written. Resolved once at startup, in the broker's trusted
/// context; a failure falls back to the documented default rather than aborting, because
/// the cost of being wrong is a failed MPI wire-up, not a containment hole.
fn resolve_slurmd_spool() -> String {
    let out = Command::new("scontrol").arg("show").arg("config").output();
    if let Ok(o) = out {
        let text = String::from_utf8_lossy(&o.stdout);
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("SlurmdSpoolDir") {
                if let Some((_, v)) = rest.split_once('=') {
                    let v = v.trim();
                    if v.starts_with('/') {
                        return v.to_string();
                    }
                }
            }
        }
    }
    eprintln!(
        "step-broker: could not read SlurmdSpoolDir from scontrol; \
         assuming {DEFAULT_SLURMD_SPOOL}"
    );
    DEFAULT_SLURMD_SPOOL.to_string()
}

#[cfg(test)]
mod tests {
    use crate::settings;

    #[test]
    fn a_steps_working_directory_gets_the_same_check_as_a_jobs() {
        // The step runs where the CALLER was — a run script cds into its case directory
        // before launching — so req.cwd is honoured rather than overridden. It is
        // agent-controlled, so it passes the same gate the sbatch path uses.
        assert!(settings::is_workdir_allowed("/scratch/proj/run"));
        for bad in ["/", "relative/path", "/users/victim", "/scratch/../users/x", ""] {
            assert!(
                !settings::is_workdir_allowed(bad),
                "{bad:?} must not be accepted as a step working directory"
            );
        }
    }
}
