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


def die(msg, code=1, from_husk=False):
    """Fail, and be honest about WHO refused.

    Every message used to go out as `sbatch: error: ...`, which is byte-for-byte what real
    sbatch prints. So husk's own rules arrived wearing SLURM's name, and an agent told
    `sbatch: error: --qos is not permitted` reasonably concluded the scheduler had rejected
    it and went looking for a scheduler-shaped workaround. Attribution is the difference
    between a rule an agent complies with and a failure it routes around.

    The prefix stays for messages that really are about invoking sbatch (a missing script
    file, a spool that is not there) so tooling that greps for it keeps working; anything
    that came back from the broker is husk speaking and says so.
    """
    if from_husk:
        sys.stderr.write(f"husk: {msg}\n")
    else:
        sys.stderr.write(f"{tool_name()}: error: {msg}\n")
    sys.exit(code)


def where_to_look():
    """Point at the broker's session log, if this session has one.

    An unattributed husk failure is worse than a slow one: it invites a confident,
    wrong fix. Every message that gives up should say where the other half of the
    story is. The log is readable and NOT writable from in here, which is why it is
    not in the spool.
    """
    log = os.environ.get("HUSK_SESSION_LOG")
    return f" The broker's log for this session is {log}." if log else ""


def spool_dir():
    # Set by the outer wrapper, which creates the directory. There is deliberately no
    # guess-the-path fallback: a stale spool from an earlier session in this directory
    # would look exactly like a live one, and picking it up silently is how a stale
    # project root gets read as the current one.
    d = os.environ.get("HUSK_SLURM_SPOOL")
    if not d:
        die(
            "HUSK_SLURM_SPOOL is not set, so there is no broker to talk to. "
            "This command only works inside a husk session on a SLURM machine."
        )
    if not os.path.isdir(d):
        # The outer wrapper is expected to create this. Fail closed if absent —
        # do NOT silently bypass the broker.
        die(f"spool directory not found: {d} (is husk's SLURM broker running?){where_to_look()}")
    if not os.access(d, os.W_OK):
        die(f"spool directory not writable: {d}{where_to_look()}")
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


# Options husk ACCEPTS and then does not apply, with the reason the caller needs.
#
# `Class::Ignored` in the registry means "recognised, dropped" — and a silent drop is a
# behaviour change the caller asked for and is not told about. That cost a run when
# `--parsable` was dropped (the driver parsed "Submitted batch job N" as a job id), and it
# had already cost an hour when `#SBATCH` resource options were dropped. Same class, twice.
# So the ones that cannot be honoured say so instead (P13).
#
# `--parsable` is not here: it IS honoured now. `--wait` is not here either: it is refused by
# the broker, because a dropped `--wait` makes a caller treat a queued job as a finished one
# and there is no way for it to notice.
UNAPPLIED = {
    "--mail-type": "husk does not forward job mail",
    "--mail-user": "husk does not forward job mail — it is sent by slurmctld and carries the "
                   "job name, so it would leave the cluster without passing husk's egress "
                   "allowlist",
    "--verbose": "husk constructs its own sbatch invocation; what it forced is in the job "
                 "banner and in husk's log for this session",
    "-v": "husk constructs its own sbatch invocation; what it forced is in the job banner "
          "and in husk's log for this session",
}


def export_note(argv):
    """`--export=ALL,VAR=val` silently loses the assignments — say so.

    `--export` is Forced: husk emits `--export=ALL` and discards whatever the caller wrote,
    because the uenv view lives in PATH and a narrowed export breaks it. But the value people
    actually pass is `ALL,VAR=val`, and the VAR=val half is how a scientific code is A/B'd
    without touching a tracked file. Dropping it means the run is subtly not the run that was
    asked for, and the KENDA session spent an unresolved investigation on exactly that:
    `--export=ALL,ICON_REPORT_AFFINITY=1` produced zero affinity lines in a 1.9 MB log, and
    the agent could not tell whether husk or the runscript had eaten it (2026-08-07).

    Only fires when there is something to lose: a bare `--export=ALL` is what husk emits
    anyway.
    """
    for a in argv:
        if a.startswith("--export=") and a != "--export=ALL":
            return ("--export was replaced with --export=ALL, so any VAR=val assignments in "
                    "it did NOT reach the job. husk forces ALL because the uenv view lives in "
                    "PATH. To set a variable for the job, export it before submitting (husk "
                    "forwards an allowlist) or set it inside the job script.")
    return None


def unapplied_note(argv):
    """One line naming every option husk accepted but did not apply, or None."""
    seen = []
    for a in argv:
        name = a.split("=", 1)[0]
        if name in UNAPPLIED and name not in [n for n, _ in seen]:
            seen.append((name, UNAPPLIED[name]))
    if not seen:
        return None
    if len(seen) == 1:
        return f"{seen[0][0]} was accepted but not applied: {seen[0][1]}."
    names = ", ".join(n for n, _ in seen)
    why = "; ".join(f"{n}: {w}" for n, w in seen)
    return f"these options were accepted but not applied: {names} ({why})."


def submitted_line(job_id, argv):
    """What sbatch prints on success — `--parsable` is an OUTPUT CONTRACT, not a preference.

    husk classed `--parsable` as Ignored (accepted, silently discarded) and the stub always
    printed the human line, so a driver doing `jobid=$(sbatch --parsable ...)` captured
    "Submitted batch job 5023456" as its job id and its wait loop exited immediately (LETKF
    session, 2026-08-07). The agent diagnosed it exactly and lost the run.

    Nothing here is security-relevant: husk already has the id and prints it either way. This
    is only which shape the caller asked for. Real sbatch prints `<jobid>`, or
    `<jobid>;<cluster>` on a federation — we have no federation, so the bare id is right.

    A function rather than an inline branch so it can be tested without a broker and a spool.
    """
    return str(job_id) if "--parsable" in argv else f"Submitted batch job {job_id}"


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
            # `--parsable` is an OUTPUT CONTRACT, so honour it here rather than dropping it.
            #
            # husk classed it Ignored — accepted, silently discarded — and the stub always
            # printed the human line. A driver doing `jobid=$(sbatch --parsable ...)` then got
            # "Submitted batch job 5023456" as its job id, and its wait loop exited at once
            # (LETKF session, 2026-08-07). The agent diagnosed it correctly and lost the run.
            #
            # Nothing about the format is security-relevant: husk already knows the id and
            # prints it either way. This is purely which shape the caller asked for.
            # Real sbatch prints `<jobid>` (or `<jobid>;<cluster>` on a federation).
            argv_rest = sys.argv[1:]
            print(submitted_line(resp.get("job_id"), argv_rest))
            # Advice (e.g. the wall limit this job just inherited) goes to STDERR, where
            # real sbatch puts its own warnings — stdout stays exactly the line above so
            # anything parsing it is unaffected. A guardrail that moves a job somewhere
            # with different limits should say so at submit time, not leave it to squeue.
            # `--quiet` is honoured for husk's OWN advisories, which are the analogue of the
            # informational messages real sbatch suppresses. stdout is left alone either way:
            # it is the machine-readable contract, and suppressing it would break a caller
            # that greps for the id — the very failure this whole change is about.
            quiet = "--quiet" in argv_rest or "-Q" in argv_rest
            note = resp.get("message", "")
            if note and not quiet:
                sys.stderr.write(f"{tool_name()}: husk: {note.strip()}\n")
            unapplied = unapplied_note(argv_rest)
            if unapplied and not quiet:
                sys.stderr.write(f"{tool_name()}: husk: {unapplied}\n")
            exported = export_note(argv_rest)
            if exported and not quiet:
                sys.stderr.write(f"{tool_name()}: husk: {exported}\n")
            sys.exit(int(resp.get("exit_code", 0)))
        die(resp.get("message", "submission rejected by broker"), from_husk=True,
            code=int(resp.get("exit_code", 1)))
    else:
        # Read-only query: replay the broker's captured output + exit code.
        if status == "ok":
            sys.stdout.write(resp.get("stdout", ""))
            sys.stderr.write(resp.get("message", ""))
            sys.exit(int(resp.get("exit_code", 0)))
        die(resp.get("message", "query rejected by broker"), from_husk=True,
            code=int(resp.get("exit_code", 1)))


if __name__ == "__main__":
    main()
