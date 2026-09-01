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


# sbatch options that consume a following token as their value.
#
# EXHAUSTIVE, and mechanically tied to the broker: `protocol.rs`'s
# `the_stubs_value_option_table_is_the_registrys_value_option_column` parses this literal out
# of this file and compares it BOTH DIRECTIONS against the `takes_value` column of the
# broker's REGISTRY. Adding a value option to the registry without adding it here is red.
#
# It used to say "NON-EXHAUSTIVE by design ... Kept ALIGNED with the broker's VALUE_OPTS
# (sbatch.rs)", and it was **16 spellings short** (`B3-1`). There is no constant called
# VALUE_OPTS in sbatch.rs to be aligned with — the counterpart is a column — which is part of
# why the copy drifted, and stating the alignment as an existing property is why no reader
# went to check.
#
# The shortfall was user-visible on the ordinary path: `sbatch --hint nomultithread job.sh`
# died IN THE CAGE with `unable to read batch script nomultithread`, because the stub took
# the option's value for the script. That message blames the script path for an
# option-parsing bug (`P11`), the glued `--hint=nomultithread` worked, so it read as a
# filesystem problem (`P13`) — and the compute cage, which holds the real sbatch, ran the
# same line fine.
#
# What this table is FOR: locating the first positional (the script), and giving the four
# caller-facing decisions below an arity-aware view of the option stream. The broker
# re-parses authoritatively and is the gate. Being wrong here costs a confusing local error,
# never an admission — every path through this file fails closed.
VALUE_OPTS = {
    "--account", "-A", "--array", "-a", "--begin", "--chdir", "-D", "--comment",
    "--constraint", "-C", "--cores-per-socket", "--cpus-per-gpu", "--cpus-per-task", "-c",
    "--deadline", "--dependency", "-d", "--distribution", "-m", "--error", "-e",
    "--exclude", "-x", "--export", "--gpu-bind", "--gpus", "-G", "--gpus-per-node",
    "--gpus-per-socket", "--gpus-per-task", "--gres", "--hint", "--job-name", "-J",
    "--mail-type", "--mail-user", "--mem", "--mem-bind", "--mem-per-cpu", "--mem-per-gpu",
    "--nodelist", "-w", "--nodes", "-N", "--ntasks", "-n", "--ntasks-per-core",
    "--ntasks-per-node", "--ntasks-per-socket", "--open-mode", "--output", "-o",
    "--partition", "-p", "--qos", "-q", "--repo", "--reservation", "--signal",
    "--sockets-per-node", "--switches", "--threads-per-core", "--time", "-t", "--time-min",
    "--uenv", "--view", "--wrap",
}


# ---------------------------------------------------------------------------
# WHAT THE SUBMISSION ASKS FOR — and it has TWO channels, not one.
#
# husk reads sbatch options from the command line AND from `#SBATCH` lines in the script
# header, and says so everywhere else: the broker parses both (`policy.rs:137-138`) and
# prefixes its refusals with the channel the option arrived on. Four caller-facing decisions
# in this file — the stdout shape for `--parsable`, the `--quiet` gate, the not-applied note
# and the `--export` note — read `sys.argv` and nothing else. That is ONE defect with four
# instances (`B7-4`), and two of the instances are incidents this repo has already paid for:
#
#   #SBATCH --parsable   -> `Submitted batch job 5023456`, the LETKF output-contract failure
#                           reproduced verbatim in the file written to end it
#   #SBATCH --export=ALL,ICON_REPORT_AFFINITY=1
#                        -> no note, which is the KENDA session's unresolved investigation
#
# So the option stream is built once, from both channels, and every decision below reads it.
# It is a LIST OF CHANNELS rather than one flat list for two reasons: a note can then name
# where the option came from (`P11` — attribution is what makes a message actionable), and
# an option's value cannot be read across the seam between two independently parsed streams.
#
# NOT a policy path. Nothing here can admit an option, change a value, or make a submission
# succeed that would otherwise fail; the broker sees the same two channels and decides. The
# worst a mistake here can do is print the wrong advisory or the wrong stdout shape.
# ---------------------------------------------------------------------------

CHANNEL_CLI = "the command line"
CHANNEL_DIRECTIVE = "a #SBATCH directive"


def split_glued_short_opts(argv):
    """`-ppancake` -> `-p`, `pancake`, for value-taking shorts only.

    A port of the broker's `split_glued_short_opts_in` (`sbatch.rs`), so that this file's view
    of the option stream is the broker's view. Only VALUE-TAKING shorts are split, exactly as
    there: a flag cluster like `-Qv` is left whole by both sides and refused by name, and
    reading it here as `--quiet` would make the stub act on a submission the broker rejects.

    No decision below turns on it TODAY, and that is stated rather than dressed up. It is
    here because every one of them now reads a token STREAM, and a stream one token different
    from the broker's is the seam every P8 finding in this file came through.

    NOT COVERED: the Rust version measures `tok.len() > 2` in BYTES and refuses to split on a
    non-character boundary; this one counts characters. The two differ only for a token whose
    second byte is inside a multi-byte character, which is not an option spelling in either
    registry.
    """
    out = []
    for tok in argv:
        if len(tok) > 2 and tok[0] == "-" and tok[1] != "-" and tok[:2] in VALUE_OPTS:
            out.append(tok[:2])
            out.append(tok[2:])
        else:
            out.append(tok)
    return out


def split_options_and_rest(argv):
    """(the sbatch option region, everything from the first positional on).

    A port of the broker's `split_options_and_rest_in`. Tokens after the script path are the
    SCRIPT's arguments, not sbatch's — real sbatch reads them that way and so must this file.
    `submitted_line` used to test the whole of argv, so `sbatch job.sh --parsable` printed a
    bare job id for an option the job script was going to receive as `$1`.

    NOT COVERED: this is arity, not validity. A dangling value option at the end of the
    region (`sbatch job.sh --time`) is consumed here and refused by the broker, which is the
    only place that can say why.
    """
    out = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--":
            i += 1  # the separator ends the options and belongs to neither half
            break
        if a.startswith("--") and "=" in a:
            out.append(a)
            i += 1
        elif a.startswith("-") and a != "-":
            out.append(a)
            if a in VALUE_OPTS and i + 1 < len(argv):
                out.append(argv[i + 1])
                i += 2
            else:
                i += 1
        else:
            break  # first positional
    return out, argv[i:]


def split_directive_line(rest):
    """One `#SBATCH` line's tokens, honouring quotes — or None if a quote is unterminated.

    A port of the broker's `split_directive_line`. Quoting a directive value is ordinary
    (`#SBATCH --job-name="my run"`), and a whitespace split would make this file disagree
    with the broker about what the script says.

    None rather than a best guess, and — unlike the broker, which REFUSES the submission —
    the caller here degrades to the command line alone. This file must never turn a
    submission the broker would accept into a local failure, and the broker refuses the
    unterminated quote itself with a message written for the person who wrote the script.

    NOT COVERED: nothing ties this to the broker's copy. A divergence between the two lexers
    is invisible to both suites; what bounds it is that this side cannot refuse, admit or
    alter anything — see the block comment above.
    """
    out = []
    cur = []
    building = False
    quote = None
    for c in rest:
        if quote is not None:
            if c == quote:
                quote = None
            else:
                cur.append(c)
        elif c == "'" or c == '"':
            quote = c
            building = True  # `--x=""` is an empty value, not an absent one
        elif c == "#" and not building:
            break  # an unquoted `#` at a token boundary starts a trailing comment
        elif c.isspace():
            if building:
                out.append("".join(cur))
                cur = []
                building = False
        else:
            cur.append(c)
            building = True
    if quote is not None:
        return None
    if building:
        out.append("".join(cur))
    return out


def directive_tokens(body):
    """Option tokens from the `#SBATCH` lines of a script HEADER.

    The header is the leading run of blank and `#` lines, and a directive is `#SBATCH` at
    COLUMN 0 — both rules are the broker's (`header_lines` / `directive_body`), which are in
    turn sbatch's. Taking only the header is what keeps a `#SBATCH` line inside a generated
    inner script (an ICON run script writing a job for a later submission) from being read as
    this job's own request.

    NOT COVERED: the same divergence axis as `split_directive_line`, plus the header rule
    itself — a script husk and this file disagree about the extent of would produce a note
    about an option the broker ignored, or no note about one it read.
    """
    out = []
    for line in body.splitlines():
        stripped = line.lstrip()
        if stripped and not stripped.startswith("#"):
            break  # the header ends at the first line that is not blank and not a comment
        if not line.startswith("#SBATCH"):
            continue
        toks = split_directive_line(line[len("#SBATCH"):])
        if toks is None:
            return []  # unparseable: say nothing here, the broker refuses it and explains
        out.extend(toks)
    return split_glued_short_opts(out)


def submission_options(argv, script_body):
    """Every option this submission asks for, as (channel name, tokens) pairs.

    The single input to all four caller-facing decisions below. Built once in `main` and
    passed down, so the two channels cannot be read in one place and forgotten in another —
    which is the whole of `B7-4`.
    """
    cli, _rest = split_options_and_rest(argv)
    return [
        (CHANNEL_CLI, split_glued_short_opts(cli)),
        (CHANNEL_DIRECTIVE, directive_tokens(script_body)),
    ]


def asked_for(channels, names):
    """The channel that first names one of `names`, or None. Exact token match only."""
    for channel, tokens in channels:
        for tok in tokens:
            if tok in names:
                return channel
    return None


def option_values(channels, name):
    """Every value given for `name`, honouring `--name=v` and `--name v`, per channel.

    ARITY-AWARE on purpose: a scan that matched the name anywhere would also match a token
    that is another option's VALUE, so `--comment --export` would be read as an `--export`.
    That is `B3-2`, live in the broker's `option_value` and owned by another batch; it is
    deliberately not reproduced here.

    NOT COVERED: last-wins. The caller gets every occurrence, because the notes below ask
    "was anything lost", not "what won".
    """
    vals = []
    glued = name + "="
    for _channel, tokens in channels:
        i = 0
        while i < len(tokens):
            t = tokens[i]
            if t == name:
                if i + 1 < len(tokens):
                    vals.append(tokens[i + 1])
                i += 2
            elif t.startswith(glued):
                vals.append(t[len(glued):])
                i += 1
            elif t in VALUE_OPTS:
                i += 2  # this token's successor is a value, not an option
            else:
                i += 1
    return vals


# Options husk ACCEPTS and then does not apply, with the reason the caller needs.
#
# `Class::Ignored` in the registry means "recognised, dropped" — and a silent drop is a
# behaviour change the caller asked for and is not told about. That cost a run when
# `--parsable` was dropped (the driver parsed "Submitted batch job N" as a job id), and it
# had already cost an hour when `#SBATCH` resource options were dropped. Same class, twice.
# So the ones that cannot be honoured say so instead (P13).
#
# `--wait` is not here: it is refused by the broker, because a dropped `--wait` makes a
# caller treat a queued job as a finished one and there is no way for it to notice.
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


# Options husk recognises and acts on HERE, instead of forwarding them.
#
# `Class::Ignored` has two members, and treating it as one is what made the shipped skill
# false. An Ignored option is either DROPPED — `UNAPPLIED` above, announced on stderr — or
# HONOURED BY THE STUB. `--parsable` is an output contract; `--quiet` / `-Q` is the request
# to stop announcing. Neither is forwarded (husk builds its own sbatch invocation) and
# neither is lost, so neither belongs in `UNAPPLIED`: announcing `--quiet` would be a line
# printed by the option asking for silence, and announcing `--parsable` would contradict the
# id it is there to produce.
#
# A table rather than three literals so the class is COMPLETE and stays complete.
# `protocol.rs`'s `every_ignored_option_has_a_disposition_in_the_sbatch_stub` walks
# `Class::Ignored` in the registry and requires every spelling to be in exactly one of these
# two tables, in both directions. Adding a sixth Ignored option without deciding what the
# caller is told is red — which is `C1-4`'s third consumer, the one its own test could not
# reach.
#
# The generated option contract in `skill/SKILL.md` still excepts only `--parsable` from
# "husk says so on stderr" (`C1-5`); the sentence lives in `option_contract_markdown()`
# and is named in FIX-I as the one line this fix could not reach.
HONOURED_LOCALLY = {
    "--parsable": "the bare job id is printed instead of `Submitted batch job <id>`",
    "--quiet": "husk's own advisories for this submission are suppressed",
    "-Q": "husk's own advisories for this submission are suppressed",
}


def export_note(channels):
    """`--export=ALL,VAR=val` silently loses the assignments — say so, on either channel.

    `--export` is Forced: husk emits `--export=ALL` and discards whatever the caller wrote,
    because the uenv view lives in PATH and a narrowed export breaks it. But the value people
    actually pass is `ALL,VAR=val`, and the VAR=val half is how a scientific code is A/B'd
    without touching a tracked file. Dropping it means the run is subtly not the run that was
    asked for, and the KENDA session spent an unresolved investigation on exactly that:
    `--export=ALL,ICON_REPORT_AFFINITY=1` produced zero affinity lines in a 1.9 MB log, and
    the agent could not tell whether husk or the runscript had eaten it (2026-08-07).

    It used to fire on ONE of the four ways to write that (`B7-4`): glued, on the command
    line. The separated `--export ALL,FOO=1` and both `#SBATCH` spellings — including the one
    the KENDA session's own run script used — got nothing.

    Only fires when there is something to lose: a bare `--export=ALL` is what husk emits
    anyway.

    NOT COVERED: what husk actually forwards. This reports what the CALLER wrote; the
    authoritative statement that `--export=ALL` was substituted is the broker's, and arrives
    in the response note.
    """
    for v in option_values(channels, "--export"):
        if v != "ALL":
            return ("--export was replaced with --export=ALL, so any VAR=val assignments in "
                    "it did NOT reach the job. husk forces ALL because the uenv view lives in "
                    "PATH. To set a variable for the job, export it before submitting (husk "
                    "forwards an allowlist) or set it inside the job script.")
    return None


def unapplied_note(channels):
    """One line naming every option husk accepted but did not apply, or None.

    Reads both channels: a run script's `#SBATCH --mail-user=...` used to be dropped in
    silence while the identical command-line option was announced, which is the same option
    meaning two different things depending on where it was written.

    A directive-only option says so, because "remove it" points at a different file than the
    command the agent just typed (`P11`).

    NOT COVERED: whether the option was dropped for the reason given. These strings are
    hand-written and only the NAMES are tied to the registry — see `HONOURED_LOCALLY`.
    """
    seen = []
    for channel, tokens in channels:
        for a in tokens:
            name = a.split("=", 1)[0]
            if name in UNAPPLIED and name not in [n for n, _, _ in seen]:
                seen.append((name, UNAPPLIED[name], channel))
    if not seen:
        return None
    if len(seen) == 1:
        name, why, channel = seen[0]
        where = f" (in {channel})" if channel != CHANNEL_CLI else ""
        return f"{name}{where} was accepted but not applied: {why}."
    names = ", ".join(n for n, _, _ in seen)
    why = "; ".join(f"{n}: {w}" for n, w, _ in seen)
    return f"these options were accepted but not applied: {names} ({why})."


def misplaced_option_note(job_args, script_name):
    """An sbatch option written AFTER the script path is the SCRIPT's argument.

    Real sbatch reads it that way and husk now does too — but husk did not always: the four
    decisions in this file used to scan the whole of argv, so `sbatch job.sh --parsable`
    printed a bare job id. Anyone who wrote that got husk's answer, not sbatch's, and would
    now silently get a different one. Silently changing an output contract is the failure
    this file exists to prevent, so the change announces itself rather than being discovered
    by a wait loop.

    NOT COVERED: options meant for the job script that merely LOOK like sbatch's. This names
    only spellings husk itself would have acted on, so an ordinary `--verbose` passed to a
    solver is reported once; it is advice, not a refusal.
    """
    acted_on = set(UNAPPLIED) | set(HONOURED_LOCALLY) | {"--export"}
    hits = [a for a in job_args if a.split("=", 1)[0] in acted_on]
    if not hits:
        return None
    where = script_name or "the script"
    return (f"{', '.join(sorted(set(hits)))} appears AFTER the script path, so it is an "
            f"argument to {where} and not an sbatch option — real sbatch reads it the same "
            f"way, and husk did not act on it. Put it before {where} if you meant it for "
            f"sbatch.")


def submitted_line(job_id, channels):
    """What sbatch prints on success — `--parsable` is an OUTPUT CONTRACT, not a preference.

    husk classed `--parsable` as Ignored (accepted, silently discarded) and the stub always
    printed the human line, so a driver doing `jobid=$(sbatch --parsable ...)` captured
    "Submitted batch job 5023456" as its job id and its wait loop exited immediately (LETKF
    session, 2026-08-07). The agent diagnosed it exactly and lost the run.

    The fix honoured one of its two spellings. A run script carrying `#SBATCH --parsable` —
    the ordinary way an HPC job records its own options, and the way real sbatch is asked —
    got the identical failure until this function was given both channels (`B7-4`).

    Nothing here is security-relevant: husk already has the id and prints it either way. This
    is only which shape the caller asked for. Real sbatch prints `<jobid>`, or
    `<jobid>;<cluster>` on a federation — we have no federation, so the bare id is right.

    NOT COVERED: `--parsable` written after the script path is a job argument and no longer
    changes this line; `misplaced_option_note` is what says so.
    """
    if asked_for(channels, ("--parsable",)):
        return str(job_id)
    return f"Submitted batch job {job_id}"


def parse_invocation(argv):
    """Split argv into (script_source, script_name, script_body, job_args).

    Handles --wrap, `--opt=val`, `--opt val`/`-o val` via VALUE_OPTS, bare flags, then the
    first positional is the script and the rest are job args. No script and no --wrap => read
    the script from stdin.
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

    _opts, rest = split_options_and_rest(argv)
    if not rest:
        # No script on the command line — sbatch reads it from stdin.
        body = sys.stdin.read()
        return ("stdin", None, body, [])

    script_path = rest[0]
    job_args = rest[1:]
    try:
        with open(script_path, "r") as f:
            body = f.read()  # immutable snapshot — see PROTOCOL.md (TOCTOU)
    except OSError as e:
        die(f"unable to read batch script {script_path}: {e}")
    return ("file", os.path.basename(script_path), body, job_args)


def response_mismatch(resp, req_id):
    """Every way the broker's answer fails to match the request this stub sent.

    NEVER a refusal, and that is the whole design of this function. By the time a response
    exists the job may already be QUEUED, so exiting non-zero here would throw away a job id
    the agent cannot get back — the LETKF failure with a worse ending. Each item is one line
    on stderr, and it is NOT suppressed by `--quiet`: `--quiet` asks husk to stop commenting
    on THIS JOB, and these say the two halves of husk disagree about what the fields mean.

    ONE function for both checks because they are one concept — "this is not the answer to
    the question I asked" — with two instances, and splitting a class into instances is what
    left three of the four decisions in this file reading the wrong input.

    `version` had four writers and, until this line, one reader (`policy.rs:101`). `id` had
    none at all: the stub paired request to response by the FILENAME it had constructed
    itself — the confined side taking its own word for whose answer it was reading (`P2`) —
    so the broker's own statement of which request it answered was never compared with
    anything. (`B7-8` names three unread Request fields; this is the fourth, on the response
    side, and it was found by the test written for the other three.)

    NOT COVERED: the request direction. A stub newer than the broker is refused by
    `policy.rs` on the login side and read anyway by `step.rs` on the compute side, which is
    `B7-8`'s live half and lives in a file this fix does not own.
    """
    out = []
    v = resp.get("version")
    if v != PROTOCOL_VERSION:
        out.append(
            f"the broker answered with protocol version {v!r}, but this stub speaks version "
            f"{PROTOCOL_VERSION}. husk's two halves are deployed separately, so this usually "
            f"means one of them was upgraded and the other was not. What is printed below "
            f"was read with the older schema.")
    rid = resp.get("id")
    if rid != req_id:
        out.append(
            f"the broker's answer names request {rid!r}, and this is request {req_id!r}. The "
            f"two are paired by filename, so an answer carrying a different id means the "
            f"pairing and the content disagree; treat anything below as belonging to another "
            f"request until husk's log for this session says otherwise.")
    return out


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

    channels = []
    script_name = None
    job_args = []
    if tool == "sbatch":
        source, script_name, body, job_args = parse_invocation(argv)
        script = {"source": source, "name": script_name, "body": body}
        env = {k: v for k, v in os.environ.items()
               if k.startswith("SBATCH_") or k.startswith("SLURM_")}
        # Built ONCE, here, from both channels husk reads, and passed to every decision
        # below. See the block comment above CHANNEL_CLI (`B7-4`).
        channels = submission_options(argv, body)
    else:
        # Read-only query (squeue/sinfo/...): no script, no job args. The broker
        # runs the command in its OWN env, so we send none.
        script = {"source": "none", "name": None, "body": ""}
        env = {}

    request = {
        "version": PROTOCOL_VERSION,
        "id": req_id,
        "tool": tool,
        "submitted_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "cwd": os.getcwd(),
        # The RAW argv, exactly as the caller wrote it. The splitting above is this file's
        # own view for its own messages; the broker does its own and is the gate.
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

    for line in response_mismatch(resp, req_id):
        sys.stderr.write(f"{tool_name()}: husk: {line}\n")

    status = resp.get("status")
    if tool == "sbatch":
        if status == "submitted":
            # `--parsable` is an OUTPUT CONTRACT, so honour it here rather than dropping it.
            # Nothing about the format is security-relevant: husk already knows the id and
            # prints it either way. This is purely which shape the caller asked for.
            print(submitted_line(resp.get("job_id"), channels))
            # Advice (e.g. the wall limit this job just inherited) goes to STDERR, where
            # real sbatch puts its own warnings — stdout stays exactly the line above so
            # anything parsing it is unaffected. A guardrail that moves a job somewhere
            # with different limits should say so at submit time, not leave it to squeue.
            # `--quiet` is honoured for husk's OWN advisories, which are the analogue of the
            # informational messages real sbatch suppresses. stdout is left alone either way:
            # it is the machine-readable contract, and suppressing it would break a caller
            # that greps for the id — the very failure this whole change is about.
            quiet = asked_for(channels, ("--quiet", "-Q")) is not None
            for note in (resp.get("message", ""),
                         unapplied_note(channels),
                         export_note(channels),
                         misplaced_option_note(job_args, script_name)):
                if note and not quiet:
                    sys.stderr.write(f"{tool_name()}: husk: {note.strip()}\n")
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
