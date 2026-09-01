#!/usr/bin/env bash
# Does the real SLURM know every option husk allows?
#
# husk vets the read-only verbs against a per-verb allowlist (policy.rs::query_spec). That
# table was written from knowledge of the SLURM CLI on a machine with no SLURM on it, so
# every entry is a claim that could not be checked where it was made. A typo looks exactly
# like a correct entry until a user hits it.
#
# So ask the tools. For each verb and option husk allows, run the real binary and look for
# the specific complaint that means "I do not have that option". Anything else — an invalid
# partition, an empty result, no such job — means the option was RECOGNISED, which is all
# this probe is asking.
#
# The table is printed by the broker (`--query-options`), never restated here. A second copy
# of a list is a copy that drifts, and the copy that drifts is the one that reports green.
#
# Same instrument as directive-parity-probe.sh, which asks the site's own slurmd which
# `#SBATCH` spellings it honours. Both exist because husk's model of another program is a
# thing to verify, not to assume.
#
# RUN IT ON EVERY CLUSTER. Balfrin is SLURM 23.02.7 and Santis is 25.05.4 — two major
# versions apart — so husk's table has to be the INTERSECTION of what they support, not the
# union. An option that exists only on the newer one passes there and fails here, and the
# OLDER cluster is the floor. A green run on one cluster says nothing about the other, which
# is why the summary line below names the version it actually tested against.
#
# Note also that `--json` and `--yaml` are compile-time optional (libjson / libyaml). A site
# that built without them will report them missing, and that is a true result about that
# site rather than a typo in husk's table — the distinction to draw when reading a failure.
#
# Before editing husk's table in response to a failure here, CHECK THE MAN PAGE. SchedMD
# publish every version: https://slurm.schedmd.com/archive/slurm-<version>/<tool>.html —
# e.g. .../slurm-23.02.7/sacct.html. The docs say what a VERSION defines; this probe says
# what a SITE built. They answer different questions and you usually want both.
#
# WHAT MAKES THIS PROBE ABLE TO GO RED — added 2026-09-01, `B8-2`
# ---------------------------------------------------------------------------------------
# The PASS condition below is "no binary of that name printed a getopt complaint", and that
# is satisfied by ANY program of the right name. Measured: six executables named
# `squeue sinfo sacct sstat sprio sshare`, each reproducing byte-for-byte what husk's own
# stub does when it is invoked with no spool, produced
#     parity: all 147 allowed query options exist here (unknown version) [expect]
# and `selftest.sh` rendered it PASS. 147 options "verified" against a program that is not
# SLURM and answered nothing. That is not a hypothetical configuration: the login cage
# shadows the read-only verbs with husk's stub by BIND MOUNT, so it is what a reviewer who
# runs the selftest from inside a husk session actually has on PATH.
#
# Two additions close it, and neither needs a cluster:
#
#   * A POSITIVE CONTROL per tool. Before asking about husk's options, ask the tool about a
#     bogus one. A real getopt binary complains; nothing that is not parsing options does.
#     If NO tool complains, this probe cannot go red at all and says so instead of "all N".
#   * SCOPE. `command -v "$tool" || continue` used to skip a missing tool without counting
#     it and without naming it — with only `squeue` installed the verdict was
#     `parity: all 35 allowed query options exist here`, 112 of 147 entries never tested and
#     the word "all" still there. The table size is in hand (this probe reads it from the
#     broker's stdout); it is now compared, and anything not checked is named.
#
# `P7`: a control that can decline to apply and tell no one has already failed.
#
# Usage: query-parity-probe.sh /path/to/husk-slurm-broker
set -u

BROKER="${1:-}"
[ -x "$BROKER" ] || { echo "parity: no broker binary at ${BROKER:-<unset>}"; exit 0; }
command -v squeue >/dev/null 2>&1 || { echo "parity: no SLURM here - skipped"; exit 0; }

# Copied verbatim from directive-parity-probe.sh:79-84, which has had this guard since it
# was written while its sibling did not. With HUSK_SLURM_SPOOL set, `squeue` and friends are
# husk's own stub and this probe would be asking husk whether husk agrees with itself.
# NOTE the mechanism, because the comment in selftest.sh that unsets this variable gets it
# wrong: the read-only verbs are shadowed by a BIND MOUNT (husk-slurm-wrapper.rs
# `shadow_readonly_commands`), not by an environment variable. Unsetting it does not restore
# the real binary — it only makes the stub die earlier. The canary below is what actually
# detects the stub; this guard is the cheap, early, legible half.
if [ -n "${HUSK_SLURM_SPOOL:-}" ]; then
    echo "parity: instrument not measuring - HUSK_SLURM_SPOOL is set, so the query verbs on" >&2
    echo "        PATH here are husk's own stub. Run this outside a husk session." >&2
    echo "parity: instrument not measuring (HUSK_SLURM_SPOOL is set - these are husk's stubs)"
    exit 1
fi

# A value that is syntactically fine for every option that takes one and selects nothing.
# `--format` wants a format string; the others take names or ids. `zzz` is a legal name and
# matches no job, partition, user or account, so every one of these returns empty.
value_for() {
  case "$1" in
    -o|--format) echo "%i" ;;
    -i|--iterate) echo "1" ;;
    -j|--jobs)   echo "999999999" ;;
    *)           echo "zzz" ;;
  esac
}

ver=$(squeue --version 2>/dev/null | head -1)
bad=0
checked=0
listed=0          # entries the broker printed
skipped=0         # entries we did NOT put to a real binary
skip_why=""       # ...and why, named by tool

# canary_ok TOOL — true iff this tool complains about an option nobody has. That is the one
# behaviour the whole probe's PASS condition depends on, so establish it rather than assume
# it. `--husk-parity-canary` is not an option of any SLURM tool and never will be.
CANARY_SEEN=""    # tools asked
CANARY_BAD=""     # tools that did not complain
canary_ok() {
  case " $CANARY_SEEN " in
    *" $1 "*) case " $CANARY_BAD " in *" $1 "*) return 1 ;; *) return 0 ;; esac ;;
  esac
  CANARY_SEEN="$CANARY_SEEN $1"
  _c=$(timeout 5 "$1" --husk-parity-canary 2>&1 </dev/null)
  case "$_c" in
    *"unrecognized option"*|*"Unrecognized option"*|*"invalid option"*|*"illegal option"*) return 0 ;;
  esac
  CANARY_BAD="$CANARY_BAD $1"
  return 1
}

while IFS=$'\t' read -r tool kind opt; do
  [ -n "${tool:-}" ] || continue
  listed=$((listed + 1))
  if ! command -v "$tool" >/dev/null 2>&1; then
    skipped=$((skipped + 1))
    case " $skip_why " in *" $tool(absent) "*) : ;; *) skip_why="$skip_why $tool(absent)" ;; esac
    continue
  fi
  if ! canary_ok "$tool"; then
    skipped=$((skipped + 1))
    case " $skip_why " in *" $tool(blind) "*) : ;; *) skip_why="$skip_why $tool(blind)" ;; esac
    continue
  fi
  # EVERY invocation is time-boxed. These are meant to be instant commands that select
  # nothing, and 163 of them cost nothing — until one of them is not instant. `--iterate`
  # makes squeue and sinfo print forever, and it hung a whole selftest run on Balfrin before
  # it was removed from husk's allowlist. A probe that can hang is a probe that stops the
  # suite, so the guard stays even though that particular option is gone: the next streaming
  # option should cost 5 seconds, not an afternoon.
  #
  # A timeout counts as RECOGNISED, and that is the right reading: a tool that sat there
  # producing output plainly understood the option. Only an explicit complaint means it did
  # not.
  if [ "$kind" = value ]; then
    out=$(timeout 5 "$tool" "$opt" "$(value_for "$opt")" --noheader 2>&1 </dev/null)
  else
    out=$(timeout 5 "$tool" "$opt" 2>&1 </dev/null)
  fi
  checked=$((checked + 1))
  # The one thing being tested. getopt says "unrecognized option" / "invalid option";
  # SLURM tools add "Unrecognized option". Everything else is the tool doing its job.
  case "$out" in
    *"unrecognized option"*|*"Unrecognized option"*|*"invalid option"*|*"illegal option"*)
      # WHICH option did it complain about? This probe appends `--noheader` to every
      # value-taking invocation — a 21st option that is not in the table it read — so a tool
      # that lacks `--noheader` reported EVERY value option of that tool as missing, twenty
      # wrong findings from one true one (`B8-12`). If the complaint names --noheader and
      # not the option under test, say so: the finding is about the probe.
      case "$out" in
        *--noheader*)
          case "$out" in
            *"$opt"*) echo "parity: $tool does NOT have $opt (husk allows it) -- ${out%%$'\n'*}"
                      bad=$((bad + 1)) ;;
            *)        skipped=$((skipped + 1))
                      case " $skip_why " in
                        *" $tool(noheader) "*) : ;;
                        *) skip_why="$skip_why $tool(noheader)" ;;
                      esac ;;
          esac ;;
        *)
          echo "parity: $tool does NOT have $opt (husk allows it) -- ${out%%$'\n'*}"
          bad=$((bad + 1)) ;;
      esac
      ;;
  esac
done < <("$BROKER" --query-options 2>/dev/null)

# Name what was NOT checked, always, and BEFORE the verdict — so the verdict's own word
# "all" has a stated scope on the same screen.
[ -n "$skip_why" ] && \
  echo "parity: not checked - $skipped of $listed option(s), on:$skip_why"

if [ "$listed" -eq 0 ]; then
  echo "parity: nothing checked - the broker printed no table"
elif [ -n "$CANARY_SEEN" ] && [ "$checked" -eq 0 ]; then
  # Every tool that exists here failed its canary. That is the stub signature: the PASS
  # condition of this probe cannot be violated on this host, so a green would have been a
  # statement about nothing.
  echo "parity: instrument not measuring - no tool on PATH complained about a bogus option;" \
       "asked:$CANARY_SEEN. These are not SLURM binaries (husk's stub? a shim?)"
  exit 1
elif [ "$checked" -eq 0 ]; then
  echo "parity: nothing checked - the broker printed $listed entries and none reached a tool"
elif [ "$bad" -eq 0 ]; then
  echo "parity: all $checked of $listed allowed query options exist here (${ver:-unknown version}) [expect]"
else
  echo "parity: $bad of $checked allowed query options do not exist here (${ver:-unknown version})"
fi
