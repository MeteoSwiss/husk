#!/usr/bin/env bash
# Does the sbatch stub read the WHOLE submission, and honour the contract its caller asked
# for?
#
# WHY THIS FILE EXISTS
# --------------------
# `--parsable` was classed Ignored — accepted and silently discarded — and the stub always
# printed the human line. So a driver doing
#
#     jobid=$(sbatch --parsable job.sh)
#
# captured "Submitted batch job 5023456" as its job id, and its wait loop exited immediately.
# The job ran fine; the run was lost anyway (LETKF session, 2026-08-07). The caged agent
# diagnosed it correctly and unaided, which is the only reason it was cheap.
#
# That is the P13 shape: husk changed what the caller asked for and said nothing. The same
# class in the same registry cost an hour a week earlier (#SBATCH resource directives), and
# `--wait` was still sitting there with a worse consequence — a silently dropped `--wait`
# makes `sbatch --wait && collect` run the collection against a queued job. `--wait` is now
# REFUSED with a reason, since it cannot be honoured; `--parsable` can be, so it is.
#
# WHY IT GREW (`B3-1`, `B7-4`)
# ----------------------------
# The fix above honoured ONE of `--parsable`'s two spellings. husk reads options from the
# command line AND from `#SBATCH` lines in the script header — the broker parses both — but
# all four of this stub's caller-facing decisions read `sys.argv` only, so a run script
# carrying `#SBATCH --parsable` got the identical LETKF failure, `#SBATCH --mail-user` was
# dropped in silence, and `--export`'s note fired on one of the four ways to write it. One
# defect, four instances. The arms below drive the REAL composition — `submission_options`,
# then the decision — rather than hand-building an argv, because "which input does it read"
# was the bug and a hand-built argv cannot see it.
#
# And `VALUE_OPTS` was 16 spellings short of the registry, so a SEPARATED value option
# (`sbatch --hint nomultithread job.sh`) made the stub take the value for the script and die
# with `unable to read batch script nomultithread`. The exhaustiveness is asserted in Rust
# (`protocol.rs`); what is asserted here is the CONSEQUENCE, over every entry.
#
# Needs no cluster, no broker, no spool.
set -u
STUB="${STUB:-$(dirname "$0")/sbatch-stub.py}"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
pass=0; fail=0

check() { # description expected actual
  if [ "$3" = "$2" ]; then
    pass=$((pass+1)); printf '  ok    %-52s %s\n' "$1" "$3"
  else
    fail=$((fail+1)); printf '  FAIL  %-52s got %-28s want %s\n' "$1" "$3" "$2"
  fi
}

contains() { # description needle actual
  case "$3" in
    *"$2"*) pass=$((pass+1)); printf '  ok    %-52s\n' "$1" ;;
    *) fail=$((fail+1)); printf '  FAIL  %-52s\n        got: %s\n        want substring: %s\n' "$1" "$3" "$2" ;;
  esac
}

# Every arm goes through the stub's own `submission_options`, i.e. the same composition
# `main` uses: the CLI option region plus the `#SBATCH` header of the body.
ask() { # body_file(or "") what argv...
  python3 - "$STUB" "$@" <<'PY'
import importlib.util as u, sys
spec = u.spec_from_file_location("stub", sys.argv[1])
m = u.module_from_spec(spec); spec.loader.exec_module(m)
body = open(sys.argv[2]).read() if sys.argv[2] else ""
what, argv = sys.argv[3], sys.argv[4:]
ch = m.submission_options(argv, body)
if what == "line":
    print(m.submitted_line(5023456, ch))
elif what == "unapplied":
    print(m.unapplied_note(ch) or "<none>")
elif what == "export":
    print(m.export_note(ch) or "<none>")
elif what == "quiet":
    print("quiet" if m.asked_for(ch, ("--quiet", "-Q")) else "loud")
elif what == "directives":
    print(" ".join(ch[1][1]) or "<none>")
else:
    raise SystemExit(f"unknown probe {what}")
PY
}

line()      { ask "" line "$@"; }
note()      { ask "" unapplied "$@"; }

hdr() { # write a job script whose HEADER is the given lines
  printf '#!/bin/bash\n' > "$T/job.sh"
  for l in "$@"; do printf '%s\n' "$l" >> "$T/job.sh"; done
  printf 'srun ./solver\n' >> "$T/job.sh"
}

echo "-- the default stays exactly what real sbatch prints --"
check "plain submission" "Submitted batch job 5023456" "$(line --partition=pp-short)"

echo "-- --parsable means the caller is parsing it, so give it the bare id --"
check "--parsable" "5023456" "$(line --parsable --partition=pp-short)"
check "--parsable, any position" "5023456" "$(line --partition=pp-short --parsable job.sh)"

echo "-- and it must not fire on something that merely looks like it --"
check "--parsable-ish is not --parsable" "Submitted batch job 5023456" "$(line --parsableX)"
check "a script named --parsable is not the flag" \
      "Submitted batch job 5023456" "$(line --comment=--parsable)"

echo "-- an option husk accepts and does not apply must SAY so (P13) --"
check "nothing dropped -> silent" "<none>" "$(note --partition=pp-short)"
contains "--mail-user names itself and the reason" \
         "--mail-user was accepted but not applied" "$(note --mail-user=a@b.c)"
contains "--mail-user says WHY (egress)" "egress" "$(note --mail-user=a@b.c)"
contains "two dropped options are listed together" "--mail-type, --mail-user" \
         "$(note --mail-type=END --mail-user=a@b.c)"
# --parsable is HONOURED, so it must never appear in the not-applied list.
check "--parsable is applied, not announced" "<none>" "$(note --parsable)"

echo
echo "== B7-4: the SCRIPT HEADER is the other half of the input =="
echo "-- #SBATCH --parsable is the LETKF failure, reproduced on the directive spelling --"
hdr '#SBATCH --parsable'
check "#SBATCH --parsable -> the bare id" "5023456" "$(ask "$T/job.sh" line job.sh)"
hdr '#SBATCH --time=00:10:00'
check "a header without it -> the human line" "Submitted batch job 5023456" \
      "$(ask "$T/job.sh" line job.sh)"

echo "-- a dropped option in the header is announced, and says WHERE it was written --"
hdr '#SBATCH --mail-user=a@b.c'
contains "#SBATCH --mail-user is announced" "--mail-user" "$(ask "$T/job.sh" unapplied job.sh)"
contains "and names the channel it came from" "#SBATCH directive" \
         "$(ask "$T/job.sh" unapplied job.sh)"
contains "the command-line message is unchanged" "--mail-user was accepted but not applied" \
         "$(note --mail-user=a@b.c)"

echo "-- --export loses VAR=val on all FOUR ways of writing it, so all four must say so --"
contains "1. --export=ALL,FOO=1 (glued, CLI)" "did NOT reach the job" \
         "$(ask "" export --export=ALL,FOO=1)"
contains "2. --export ALL,FOO=1 (separated, CLI)" "did NOT reach the job" \
         "$(ask "" export --export ALL,FOO=1)"
hdr '#SBATCH --export=ALL,ICON_REPORT_AFFINITY=1'
contains "3. #SBATCH --export=ALL,VAR=1 (the KENDA line)" "did NOT reach the job" \
         "$(ask "$T/job.sh" export job.sh)"
hdr '#SBATCH --export ALL,FOO=1'
contains "4. #SBATCH --export ALL,FOO=1 (separated)" "did NOT reach the job" \
         "$(ask "$T/job.sh" export job.sh)"
check "a bare --export=ALL loses nothing, so it says nothing" "<none>" \
      "$(ask "" export --export=ALL)"
hdr '#SBATCH --comment=--export'
check "a value that merely spells --export is not one" "<none>" \
      "$(ask "$T/job.sh" export job.sh)"

echo "-- --quiet is honoured from either channel --"
check "no --quiet -> loud" "loud" "$(ask "" quiet --partition=pp-short)"
check "--quiet on the CLI" "quiet" "$(ask "" quiet --quiet)"
check "-Q on the CLI" "quiet" "$(ask "" quiet -Q)"
hdr '#SBATCH --quiet'
check "#SBATCH --quiet" "quiet" "$(ask "$T/job.sh" quiet job.sh)"
# Glued shorts are split EXACTLY as the broker splits them — VALUE-taking shorts only.
# `-Qv` is a flag cluster husk does not model, so neither side splits it and the broker
# refuses the submission by name. The stub agreeing with the broker is the property under
# test; reading `-Qv` as `--quiet` here would make the stub act on a submission that fails.
contains "-v alone is announced" "-v was accepted but not applied" "$(note -v)"
check "-Qv is NOT split, so husk does not read it as --quiet" "loud" "$(ask "" quiet -Qv)"
check "a glued VALUE short IS split, as in the broker" "-t 01:00:00 job.sh" \
      "$(python3 - "$STUB" <<'PYG'
import importlib.util as u, sys
spec = u.spec_from_file_location("stub", sys.argv[1])
m = u.module_from_spec(spec); spec.loader.exec_module(m)
print(" ".join(m.split_glued_short_opts(["-t01:00:00", "job.sh"])))
PYG
)"

echo
echo "== which lines of the script are DIRECTIVES =="
hdr '#SBATCH --parsable' '# an ordinary comment' '' '#SBATCH --hold'
check "blank lines and comments do not end the header" "--parsable --hold" \
      "$(ask "$T/job.sh" directives job.sh)"
printf '#!/bin/bash\nsrun ./solver\n#SBATCH --parsable\n' > "$T/job.sh"
check "a #SBATCH line BELOW the header is not read" "<none>" \
      "$(ask "$T/job.sh" directives job.sh)"
hdr '  #SBATCH --parsable'
check "an indented #SBATCH is not a directive (column 0, like sbatch)" "<none>" \
      "$(ask "$T/job.sh" directives job.sh)"
hdr '#SBATCH --job-name="my run"   # why'
check "quotes group, and a trailing # is a comment" "--job-name=my run" \
      "$(ask "$T/job.sh" directives job.sh)"
# A second directive AFTER the broken one: skipping the unparseable LINE and keeping the
# rest would leave the stub acting on a reading of the script the broker refuses outright.
# The whole header goes, or the two halves of husk mean different things by one file.
hdr '#SBATCH --job-name="unterminated' '#SBATCH --parsable'
check "an unterminated quote discards the WHOLE header, it does not guess" "<none>" \
      "$(ask "$T/job.sh" directives job.sh)"
check "...and the stub still says nothing, leaving the refusal to the broker" \
      "Submitted batch job 5023456" "$(ask "$T/job.sh" line job.sh)"

echo
echo "== B3-1: a SEPARATED value option must not be mistaken for the script =="
printf '#!/bin/bash\nsrun ./solver\n' > "$T/job.sh"
sep=$(python3 - "$STUB" "$T/job.sh" <<'PY'
import importlib.util as u, sys
spec = u.spec_from_file_location("stub", sys.argv[1])
m = u.module_from_spec(spec); spec.loader.exec_module(m)
script = sys.argv[2]
bad = []
for opt in sorted(m.VALUE_OPTS):
    if opt == "--wrap":
        continue            # --wrap is answered above the positional scan; there is no script
    source, name, body, job_args = m.parse_invocation([opt, "somevalue", script])
    if (source, name) != ("file", "job.sh"):
        bad.append(f"{opt}->{source}/{name}")
print(" ".join(bad) if bad else "<all found the script>")
PY
)
check "every value option, separated form, finds the script" "<all found the script>" "$sep"
check "--hint nomultithread specifically (the reproduced case)" "file/job.sh" \
      "$(python3 - "$STUB" "$T/job.sh" <<'PYH'
import importlib.util as u, sys
spec = u.spec_from_file_location("stub", sys.argv[1])
m = u.module_from_spec(spec); spec.loader.exec_module(m)
src, name, _b, _a = m.parse_invocation(["--hint", "nomultithread", sys.argv[2]])
print(f"{src}/{name}")
PYH
)"

echo
echo "== an sbatch option written AFTER the script is the SCRIPT's argument =="
misplaced=$(python3 - "$STUB" "$T/job.sh" <<'PY'
import importlib.util as u, sys
spec = u.spec_from_file_location("stub", sys.argv[1])
m = u.module_from_spec(spec); spec.loader.exec_module(m)
script = sys.argv[2]
argv = [script, "--parsable"]
source, name, body, job_args = m.parse_invocation(argv)
ch = m.submission_options(argv, body)
print(m.submitted_line(5023456, ch))
print(m.misplaced_option_note(job_args, name) or "<none>")
PY
)
check "job.sh --parsable does NOT change stdout" "Submitted batch job 5023456" \
      "$(printf '%s' "$misplaced" | sed -n 1p)"
contains "...and husk says why, rather than changing shape in silence" \
         "appears AFTER the script path" "$(printf '%s' "$misplaced" | sed -n 2p)"

echo
echo "== the response must be the answer to the question this stub asked =="
mism=$(python3 - "$STUB" <<'PY'
import importlib.util as u, sys
spec = u.spec_from_file_location("stub", sys.argv[1])
m = u.module_from_spec(spec); spec.loader.exec_module(m)
ok = {"version": m.PROTOCOL_VERSION, "id": "req-1", "status": "submitted", "job_id": 5023456,
      "message": "", "exit_code": 0, "stdout": ""}
print("match:", len(m.response_mismatch(ok, "req-1")))
skew = dict(ok, version=m.PROTOCOL_VERSION + 1)
print("version:", (m.response_mismatch(skew, "req-1") or ["<none>"])[0][:60])
other = dict(ok, id="req-2")
print("id:", (m.response_mismatch(other, "req-1") or ["<none>"])[0][:60])
PY
)
check "a matching response says nothing" "match: 0" "$(printf '%s' "$mism" | sed -n 1p)"
contains "a version skew is named, not fatal" "protocol version" \
         "$(printf '%s' "$mism" | sed -n 2p)"
contains "an answer to another request is named, not fatal" "names request" \
         "$(printf '%s' "$mism" | sed -n 3p)"

echo
echo "== END TO END: the stub as a PROCESS, against a fake broker =="
# THE AXIS EVERY ARM ABOVE IS MISSING (`P10`: write down what the harness substitutes,
# because the substitution IS the blind spot), and it is not hypothetical: while writing this fix a
# refactor deleted `write_atomic` outright, and every arm above stayed green — they import
# the module and call pure functions, so a module that imports fine and a `main` that dies on
# its first write look identical to them. So does a NameError in a branch, a message written
# to the wrong stream, and an exit code nobody checks. The stub is bind-mounted over
# /usr/bin/sbatch: a stub that crashes is every job on the cluster failing at submit.
#
# Fake broker, not the real one: the subject here is the stub, and answering every request
# with a fixed "submitted" makes stdout/stderr/exit-code deterministic with no cluster, no
# broker binary and no policy.
E=$(mktemp -d); trap 'rm -rf "$T" "$E"' EXIT
mkdir -p "$E/spool" "$E/bin"
cp "$STUB" "$E/bin/sbatch"          # argv[0] IS the tool name — the stub reads it
printf '#!/bin/bash\n#SBATCH --time=00:10:00\nsrun ./solver\n' > "$E/plain.sh"
printf '#!/bin/bash\n#SBATCH --parsable\nsrun ./solver\n'      > "$E/parsable.sh"
printf '#!/bin/bash\n#SBATCH --mail-user=a@b.c\nsrun ./solver\n' > "$E/mail.sh"

fake_broker() {
  ( for _ in $(seq 1 200); do
      for r in "$E"/spool/req-*.json; do
        [ -e "$r" ] || continue
        id=$(python3 -c 'import json,sys
try: print(json.load(open(sys.argv[1]))["id"])
except Exception: pass' "$r" 2>/dev/null)
        [ -n "$id" ] || continue
        [ -e "$E/spool/resp-$id.json" ] && continue
        printf '{"version":1,"id":"%s","status":"submitted","job_id":5023456,"message":"","exit_code":0,"stdout":""}' "$id" > "$E/spool/.t"
        mv "$E/spool/.t" "$E/spool/resp-$id.json"
      done
      sleep 0.05
    done ) &
  BROKER_PID=$!
}
e2e() { # stream(out|err|rc) argv...
  local want="$1"; shift
  fake_broker
  ( cd "$E" && HUSK_SLURM_SPOOL="$E/spool" HUSK_SLURM_TIMEOUT=10 \
      python3 "$E/bin/sbatch" "$@" > "$E/o" 2> "$E/e"; echo $? > "$E/c" )
  kill $BROKER_PID 2>/dev/null; wait $BROKER_PID 2>/dev/null
  rm -f "$E"/spool/*
  case "$want" in
    out) tr -d '\n' < "$E/o" ;;
    err) tr '\n' ' ' < "$E/e" ;;
    rc)  cat "$E/c" ;;
  esac
}
check "a plain submission exits 0" "0" "$(e2e rc plain.sh)"
check "...and prints the human line on STDOUT" "Submitted batch job 5023456" \
      "$(e2e out plain.sh)"
check "...and nothing on stderr" "" "$(e2e err plain.sh)"
check "#SBATCH --parsable puts the bare id on stdout" "5023456" "$(e2e out parsable.sh)"
check "--hint nomultithread (SEPARATED) submits instead of dying" \
      "Submitted batch job 5023456" "$(e2e out --hint nomultithread plain.sh)"
check "...and exits 0" "0" "$(e2e rc --hint nomultithread plain.sh)"
contains "#SBATCH --mail-user is announced on STDERR, not stdout" \
         "--mail-user" "$(e2e err mail.sh)"
check "...and stdout stays the machine-readable line" "Submitted batch job 5023456" \
      "$(e2e out mail.sh)"
check "--quiet silences husk's advisories end to end" "" "$(e2e err --quiet mail.sh)"
check "...without touching stdout" "Submitted batch job 5023456" "$(e2e out --quiet mail.sh)"

echo
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
