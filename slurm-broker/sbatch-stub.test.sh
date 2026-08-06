#!/usr/bin/env bash
# Does the sbatch stub honour the OUTPUT CONTRACT its caller asked for?
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
# Needs no cluster, no broker, no spool.
set -u
STUB="${STUB:-$(dirname "$0")/sbatch-stub.py}"
pass=0; fail=0

check() { # description expected actual
  if [ "$3" = "$2" ]; then
    pass=$((pass+1)); printf '  ok    %-44s %s\n' "$1" "$3"
  else
    fail=$((fail+1)); printf '  FAIL  %-44s got %-28s want %s\n' "$1" "$3" "$2"
  fi
}

line() { # argv...
  python3 - "$STUB" "$@" <<'PY'
import importlib.util as u, sys
spec = u.spec_from_file_location("stub", sys.argv[1])
m = u.module_from_spec(spec); spec.loader.exec_module(m)
print(m.submitted_line(5023456, sys.argv[2:]))
PY
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

note() { # argv...
  python3 - "$STUB" "$@" <<'PY2'
import importlib.util as u, sys
spec = u.spec_from_file_location("stub", sys.argv[1])
m = u.module_from_spec(spec); spec.loader.exec_module(m)
print(m.unapplied_note(sys.argv[2:]) or "<none>")
PY2
}

echo "-- an option husk accepts and does not apply must SAY so (P13) --"
check "nothing dropped -> silent" "<none>" "$(note --partition=pp-short)"
case "$(note --mail-user=a@b.c)" in
  *"--mail-user was accepted but not applied"*egress*)
     pass=$((pass+1)); printf '  ok    %s\n' "--mail-user names itself and the reason" ;;
  *) fail=$((fail+1)); printf '  FAIL  --mail-user note: %s\n' "$(note --mail-user=a@b.c)" ;;
esac
case "$(note --mail-type=END --mail-user=a@b.c)" in
  *"--mail-type, --mail-user"*)
     pass=$((pass+1)); printf '  ok    %s\n' "two dropped options are listed together" ;;
  *) fail=$((fail+1)); printf '  FAIL  combined note: %s\n' "$(note --mail-type=END --mail-user=a@b.c)" ;;
esac
# --parsable is HONOURED, so it must never appear in the not-applied list.
check "--parsable is applied, not announced" "<none>" "$(note --parsable)"

echo
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
