#!/usr/bin/env python3
# sbatch-stub.py — in-sandbox stub that shadows `sbatch` for the husk
# SLURM broker. Bind-mounted over /usr/bin/sbatch by the outer wrapper.
#
# It is DUMB PLUMBING: it captures the sbatch invocation (argv + cwd + an inline
# snapshot of the job script + the SBATCH_*/SLURM_* env), drops a request in the
# spool, waits for the broker's response, and then behaves like sbatch toward the
# agent (prints "Submitted batch job <id>" / an error, exits accordingly).
#
# ALL policy lives in the broker (outside the sandbox). This file makes no trust
# decisions. See PROTOCOL.md for the wire contract. Protocol version: 1.
#
# Fails closed: any spool/timeout/IO problem exits non-zero with an error and
# never lets a submission be considered successful.

import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone

PROTOCOL_VERSION = 1
POLL_INTERVAL = 0.1  # seconds

def tool_name():
    # The command we were invoked as: the wrapper bind-mounts this stub over
    # sbatch AND the read-only SLURM commands; argv[0] tells us which. The stub
    # makes no allowlist decision — it forwards whatever it was invoked as and
    # the broker is the authoritative gate.
    return os.path.basename(sys.argv[0]) or "sbatch"


def die(msg, code=1):
    sys.stderr.write(f"{tool_name()}: error: {msg}\n")
    sys.exit(code)


def spool_dir():
    d = os.environ.get("HUSK_SLURM_SPOOL") or os.path.join(os.getcwd(), ".husk-slurm-spool")
    if not os.path.isdir(d):
        # The outer wrapper is expected to create this. Fail closed if absent —
        # do NOT silently bypass the broker.
        die(f"spool directory not found: {d} (is husk's SLURM broker running?)")
    if not os.access(d, os.W_OK):
        die(f"spool directory not writable: {d}")
    return d


# sbatch options that consume a following token as their value. Used only to
# locate the first positional (the script). NON-EXHAUSTIVE by design: the broker
# re-parses authoritatively; this just needs the common cases right. `--opt=val`
# is unambiguous and handled separately. Kept ALIGNED with the broker's VALUE_OPTS
# (sbatch.rs) for the options the broker gates — `--uenv`/`--view`/`--repo` — so a
# *separated* form (`--uenv myenv job.sh`) is parsed correctly and the request
# reaches the broker for reject-and-teach, instead of the stub mistaking `myenv`
# for the script and dying with a confusing error. (`--wrap` is special-cased in
# parse_invocation above the positional scan, so it isn't listed here.)
VALUE_OPTS = {
    "-A", "--account", "-a", "--array", "-C", "--constraint", "-c", "--cpus-per-task",
    "-d", "--dependency", "-D", "--chdir", "-e", "--error", "-J", "--job-name",
    "-m", "--distribution", "-n", "--ntasks", "-N", "--nodes", "-o", "--output",
    "-p", "--partition", "-q", "--qos", "-t", "--time", "--mem", "--mem-per-cpu",
    "--gres", "--gpus", "-G", "--export", "--begin", "--mail-type", "--mail-user",
    "-w", "--nodelist", "-x", "--exclude", "--ntasks-per-node", "--time-min",
    "--signal", "--reservation", "--comment", "--uenv", "--view", "--repo",
}


def parse_invocation(argv):
    """Split argv into (script_source, script_name, script_body, job_args).

    MVP best-effort: handles --wrap, `--opt=val`, `--opt val`/`-o val` via
    VALUE_OPTS, bare flags, then the first positional is the script and the rest
    are job args. No script and no --wrap => read the script from stdin.
    """
    # --wrap takes precedence; there is no script file in that case.
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--wrap" and i + 1 < len(argv):
            return ("wrap", None, argv[i + 1], [])
        if a.startswith("--wrap="):
            return ("wrap", None, a[len("--wrap="):], [])
        i += 1

    # Find the first positional (the script path).
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--":
            i += 1
            break
        if a.startswith("--") and "=" in a:
            i += 1
            continue
        if a.startswith("-") and a != "-":
            if a in VALUE_OPTS:
                i += 2  # consume the value token too
            else:
                i += 1  # bare flag
            continue
        break  # first non-option token

    if i >= len(argv):
        # No script on the command line — sbatch reads it from stdin.
        body = sys.stdin.read()
        return ("stdin", None, body, [])

    script_path = argv[i]
    job_args = argv[i + 1:]
    try:
        with open(script_path, "r") as f:
            body = f.read()  # immutable snapshot — see PROTOCOL.md (TOCTOU)
    except OSError as e:
        die(f"unable to read batch script {script_path}: {e}")
    return ("file", os.path.basename(script_path), body, job_args)


def write_atomic(path, text):
    tmp = os.path.join(os.path.dirname(path), "." + os.path.basename(path) + ".tmp")
    with open(tmp, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def main():
    tool = tool_name()
    argv = sys.argv[1:]
    spool = spool_dir()
    req_id = str(uuid.uuid4())

    if tool == "sbatch":
        source, name, body, job_args = parse_invocation(argv)
        script = {"source": source, "name": name, "body": body}
        env = {k: v for k, v in os.environ.items()
               if k.startswith("SBATCH_") or k.startswith("SLURM_")}
    else:
        # Read-only query (squeue/sinfo/...): no script, no job args. The broker
        # runs the command in its OWN env, so we send none.
        script = {"source": "none", "name": None, "body": ""}
        job_args = []
        env = {}

    request = {
        "version": PROTOCOL_VERSION,
        "id": req_id,
        "tool": tool,
        "submitted_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "cwd": os.getcwd(),
        "argv": argv,
        "script": script,
        "job_args": job_args,
        "env": env,
    }

    req_path = os.path.join(spool, f"req-{req_id}.json")
    resp_path = os.path.join(spool, f"resp-{req_id}.json")
    write_atomic(req_path, json.dumps(request))

    timeout = float(os.environ.get("HUSK_SLURM_TIMEOUT", "120"))
    deadline = time.monotonic() + timeout
    try:
        while not os.path.exists(resp_path):
            if time.monotonic() > deadline:
                die(f"timed out after {timeout:g}s waiting for the SLURM broker", code=1)
            time.sleep(POLL_INTERVAL)

        with open(resp_path) as f:
            resp = json.load(f)
    finally:
        # Stub owns its pair; clean up regardless of outcome.
        for p in (req_path, resp_path):
            try:
                os.remove(p)
            except OSError:
                pass

    status = resp.get("status")
    if tool == "sbatch":
        if status == "submitted":
            # Mirror real sbatch's success line so the agent's tooling parses it.
            print(f"Submitted batch job {resp.get('job_id')}")
            sys.exit(int(resp.get("exit_code", 0)))
        die(resp.get("message", "submission rejected by broker"),
            code=int(resp.get("exit_code", 1)))
    else:
        # Read-only query: replay the broker's captured output + exit code.
        if status == "ok":
            sys.stdout.write(resp.get("stdout", ""))
            sys.stderr.write(resp.get("message", ""))
            sys.exit(int(resp.get("exit_code", 0)))
        die(resp.get("message", "query rejected by broker"),
            code=int(resp.get("exit_code", 1)))


if __name__ == "__main__":
    main()
