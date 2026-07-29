#!/usr/bin/env python3
# srun-stub.py — in-cage stub that shadows `srun` INSIDE a brokered job.
#
# The compute-node counterpart of sbatch-stub.py, one level down: the job runs
# caged, the step-broker runs outside the cage but inside the allocation, and this
# stub is the plumbing between them. Bound over /usr/bin/srun by the job guard.
#
# It is DUMB PLUMBING and makes no trust decisions. All policy — which srun options
# are permitted, and the forced per-task cage wrapper — lives in the step-broker.
# See SRUN-MPI-DESIGN.md and PROTOCOL.md. Protocol version: 1.
#
# NOT A SECURITY BOUNDARY. If this stub is bypassed (a script calling the real
# srun by some other path), the failure mode is "srun does not work", not an
# escape: the cage has no route to slurmctld (--unshare-net) and no MUNGE socket,
# so the real srun cannot create a step from in here. The stub exists so that
# ordinary run scripts keep working, not to contain anything.
#
# WHY THIS DIFFERS FROM THE SBATCH STUB: sbatch returns a job id immediately, but
# srun runs the tasks to completion and streams their output. So this stub tails
# the step's stdout/stderr out of the spool while it runs, rather than waiting for
# a single response and printing one line.
#
# Fails closed: any spool/IO problem exits non-zero and never reports success.

import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone

PROTOCOL_VERSION = 1
POLL_INTERVAL = 0.05  # seconds; also the output-streaming granularity


def die(msg, code=1):
    sys.stderr.write(f"srun: error: {msg}\n")
    sys.exit(code)


def spool_dir():
    # Set by the job guard before it re-execs the job into the cage. There is no
    # cwd-relative fallback: unlike the login side, a compute job's cwd is not a
    # reliable anchor (a run script may cd anywhere), and guessing wrong would
    # silently produce a request nobody reads.
    d = os.environ.get("HUSK_STEP_SPOOL")
    if not d:
        die("no step spool configured (HUSK_STEP_SPOOL unset) — is this job brokered by husk?")
    if not os.path.isdir(d):
        die(f"step spool directory not found: {d}")
    if not os.access(d, os.W_OK):
        die(f"step spool directory not writable: {d}")
    return d


def write_atomic(path, data):
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


class Tail:
    """Stream a file that another process is appending to, without re-reading it."""

    def __init__(self, path, sink):
        self.path = path
        self.sink = sink
        self.pos = 0

    def pump(self):
        try:
            with open(self.path, "rb") as f:
                f.seek(self.pos)
                chunk = f.read()
                self.pos += len(chunk)
        except FileNotFoundError:
            return
        if chunk:
            self.sink.buffer.write(chunk)
            self.sink.flush()


def main():
    argv = sys.argv[1:]
    spool = spool_dir()
    req_id = str(uuid.uuid4())

    request = {
        "version": PROTOCOL_VERSION,
        "id": req_id,
        "tool": "srun",
        "submitted_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "cwd": os.getcwd(),
        "argv": argv,
        # A step has no script to snapshot: the command is in argv, and the broker
        # wraps it rather than inspecting it.
        "script": {"source": "none", "name": None, "body": ""},
        "job_args": [],
        # The step-broker runs srun in the JOB's environment, which it already has;
        # sending ours would let the caged side influence it.
        "env": {},
    }

    req_path = os.path.join(spool, f"req-{req_id}.json")
    resp_path = os.path.join(spool, f"resp-{req_id}.json")
    out_path = os.path.join(spool, f"out-{req_id}")
    err_path = os.path.join(spool, f"err-{req_id}")
    write_atomic(req_path, json.dumps(request))

    # No default timeout: a step legitimately runs for hours, and killing a
    # simulation because a wall clock expired would be worse than waiting. The
    # step ends when the broker says so (or when SLURM tears the job down).
    out_tail = Tail(out_path, sys.stdout)
    err_tail = Tail(err_path, sys.stderr)
    try:
        while not os.path.exists(resp_path):
            out_tail.pump()
            err_tail.pump()
            time.sleep(POLL_INTERVAL)
        # The broker wrote the response after the step exited, but output written
        # just before that may still be unread — drain both before reporting.
        out_tail.pump()
        err_tail.pump()
        with open(resp_path) as f:
            resp = json.load(f)
    except KeyboardInterrupt:
        # Ctrl-C / SIGINT: leave the request in place; the broker owns the step's
        # lifetime and SLURM will tear it down with the job.
        die("interrupted while waiting for the step", code=130)
    finally:
        for p in (req_path, resp_path, out_path, err_path):
            try:
                os.remove(p)
            except OSError:
                pass

    if resp.get("status") == "ok":
        sys.exit(int(resp.get("exit_code", 0)))
    # Rejected by the step allowlist, or the launch failed. The message is written
    # for whoever wrote the job script, so pass it through unedited.
    die(resp.get("message", "step rejected by the husk step-broker"),
        code=int(resp.get("exit_code", 1)))


if __name__ == "__main__":
    main()
