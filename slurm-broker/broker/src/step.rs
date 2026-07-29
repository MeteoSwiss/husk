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
use crate::settings::FsPolicy;
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
    in_flight: Vec<Running>,
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
            in_flight: Vec::new(),
        }
    }

    /// One pass: reap finished steps, then admit new requests. Never blocks on a step.
    pub fn tick(&mut self) -> std::io::Result<()> {
        self.reap();
        self.scan()
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
        let mut argv = vec!["srun".to_string()];
        argv.push("--chdir".to_string());
        argv.push(self.workdir.clone());
        argv.extend(step.options);
        argv.push("--".to_string());
        argv.extend(rank::wrap_command(
            self.profile,
            &self.fs_policy.rank_bwrap_args(&self.workdir),
            &self.slurmd_spool,
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
