#!/usr/bin/env bash
# resume-probe.sh — does `husk --resume <id>` work under the seccomp cage? (v0.4 check)
#
# WHY: a user on husk v0.2/v0.3 reported `--resume "<id>"` fails. Leading hypothesis
# (see the diagnosis notes): seccomp-wrapper's KILL_PROCESS deny-list kills `claude` on
# a syscall that RESUMING a session's transcript exercises but a normal start doesn't —
# prime suspect io_uring (libuv fs I/O reading the .jsonl). This probe checks whether
# v0.4 still reproduces it and, if so, confirms the seccomp filter is the cause via the
# wrapper's built-in SECCOMP_WRAPPER_DEBUG (blocked syscalls return ENOSYS instead of
# killing — if resume then works, a blocked syscall was the killer).
#
# FUNCTIONAL probe (does a feature work under the cage) — NOT a containment test. You
# run it; it reads the real exit code; no agent self-report is on the evidence path.
#
# RUN on a Balfrin login node, with husk installed and `claude` signed in:
#     slurm-broker/resume-probe.sh
#
# COST: ~2-3 short `claude -p` calls (uses your Claude usage). It uses a THROWAWAY
# project dir + forced session id and cleans both up; it never touches your real sessions.
set -uo pipefail

HUSK="${HUSK:-husk}"
command -v "$HUSK"  >/dev/null 2>&1 || { echo "resume-probe: '$HUSK' not on PATH (install husk first)"; exit 127; }
command -v claude   >/dev/null 2>&1 || { echo "resume-probe: 'claude' not on PATH / not signed in"; exit 127; }

PROJ="$(mktemp -d "${TMPDIR:-/tmp}/husk-resume-probe.XXXXXX")"
enc="${PROJ//[^a-zA-Z0-9]/-}"                       # claude's project-dir encoding (non-alnum -> '-')
cleanup(){ rm -rf "$PROJ" "$HOME/.claude/projects/$enc" 2>/dev/null; }
trap cleanup EXIT
cd "$PROJ" || { echo "resume-probe: cannot cd into $PROJ"; exit 1; }

uuid(){ cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null; }
SID="$(uuid)"; [ -n "$SID" ] || { echo "resume-probe: cannot generate a uuid"; exit 1; }

# A non-trivial seed so the transcript isn't tiny (a size/pattern-gated io_uring path
# might not fire on a one-line session). Bump the count if a small session passes.
SEED='Output the integers 1 through 120, one per line, and nothing else.'
FOLLOW='Reply with exactly: RESUME-OK'

say(){ printf '%s\n' "$*"; }
line(){ printf 'RESULT %-4s resume.%-14s %s\n' "$1" "$2" "${*:3}"; }
head2(){ printf '\n== %s ==\n' "$*"; }

# 0=ok; 159 = killed by SIGSYS (seccomp KILL_PROCESS on x86_64: 128+31); other >128 =
# some other signal; else a plain error exit.
classify(){ local s="$1"
  if   [ "$s" = 0 ];   then echo ok
  elif [ "$s" = 159 ]; then echo seccomp-kill
  elif [ "$s" -gt 128 ] 2>/dev/null; then echo "signal-$((s-128))"
  else echo "error-$s"; fi
}

say "resume-probe: husk=$HUSK  session-id=$SID  cwd=$PROJ"

head2 "1. create a seed session (husk -p, forced --session-id)"
"$HUSK" --session-id "$SID" -p "$SEED" >"$PROJ/create.out" 2>"$PROJ/create.err"; cstat=$?
say "   create exit=$cstat ($(classify "$cstat"))"
if [ "$cstat" != 0 ]; then
  line FAIL create "seed creation failed ($(classify "$cstat")) — can't test resume. stderr: $(tr '\n' ' ' <"$PROJ/create.err" | head -c 300)"
  say "   (if this is a seccomp-kill, the cage breaks even a plain -p run — a bigger problem than resume.)"
  exit 1
fi
tj="$HOME/.claude/projects/$enc/$SID.jsonl"
if [ -f "$tj" ]; then say "   transcript: $tj ($(wc -c <"$tj" 2>/dev/null) bytes)"
else say "   (transcript not at the guessed path — resume-by-id still valid; only the size note is affected)"; fi

head2 "2. resume that id (husk --resume <id> -p ...) — the reported scenario"
"$HUSK" --resume "$SID" -p "$FOLLOW" >"$PROJ/resume.out" 2>"$PROJ/resume.err"; rstat=$?
rclass="$(classify "$rstat")"
say "   resume exit=$rstat ($rclass)"
case "$rclass" in
  ok)
    line PASS by_id "husk --resume <id> WORKS on v0.4 (exit 0)"
    say "   CAVEAT: this seed transcript is small. If the original report was a LARGE/long"
    say "   session, resume one of your REAL sessions once before concluding v0.4 is clean"
    say "   (the suspected io_uring path may be size/pattern-gated):"
    say "     (cd <a real project>; husk --resume <a real session id> -p 'hi')"
    ;;
  seccomp-kill|signal-*)
    line FAIL by_id "husk --resume <id> was KILLED ($rclass) — v0.4 REPRODUCES the report"
    head2 "3. is it the seccomp filter? (SECCOMP_WRAPPER_DEBUG=1 -> blocked syscalls ENOSYS, not kill)"
    SECCOMP_WRAPPER_DEBUG=1 "$HUSK" --resume "$SID" -p "$FOLLOW" >"$PROJ/resume.dbg.out" 2>"$PROJ/resume.dbg.err"; dstat=$?
    say "   resume(DEBUG) exit=$dstat ($(classify "$dstat"))"
    if [ "$dstat" = 0 ]; then
      line PASS debug_confirms "in ENOSYS mode resume WORKS -> a BLOCKED SYSCALL was killing it (libuv fell back; prime suspect io_uring)"
      say "   FIX direction: export UV_USE_IO_URING=0 in the husk launcher before exec claude"
      say "   (keeps the io_uring block; libuv just uses ordinary fs syscalls). To name the syscall:"
      say "     strace -ff -e trace=io_uring_setup,io_uring_enter,openat $HUSK --resume $SID -p 'hi' 2>&1 | tail -30"
    else
      line INFO debug_confirms "still fails under DEBUG ($(classify "$dstat")) -> NOT (only) seccomp. Check the fs cage over ~/.claude/projects, or claude stderr: $(tr '\n' ' ' <"$PROJ/resume.dbg.err" | head -c 300)"
    fi
    ;;
  *)
    line FAIL by_id "resume failed but NOT a signal kill ($rclass) — likely a setup/CLI issue, not the seccomp bug. stderr: $(tr '\n' ' ' <"$PROJ/resume.err" | head -c 300)"
    ;;
esac

say ""
say "done (throwaway project + session cleaned up)."
