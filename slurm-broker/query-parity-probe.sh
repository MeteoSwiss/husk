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
# Usage: query-parity-probe.sh /path/to/husk-slurm-broker
set -u

BROKER="${1:-}"
[ -x "$BROKER" ] || { echo "parity: no broker binary at ${BROKER:-<unset>}"; exit 0; }
command -v squeue >/dev/null 2>&1 || { echo "parity: no SLURM here - skipped"; exit 0; }

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
while IFS=$'\t' read -r tool kind opt; do
  [ -n "${tool:-}" ] || continue
  command -v "$tool" >/dev/null 2>&1 || continue
  if [ "$kind" = value ]; then
    out=$("$tool" "$opt" "$(value_for "$opt")" --noheader 2>&1 </dev/null)
  else
    out=$("$tool" "$opt" 2>&1 </dev/null)
  fi
  checked=$((checked + 1))
  # The one thing being tested. getopt says "unrecognized option" / "invalid option";
  # SLURM tools add "Unrecognized option". Everything else is the tool doing its job.
  case "$out" in
    *"unrecognized option"*|*"Unrecognized option"*|*"invalid option"*|*"illegal option"*)
      echo "parity: $tool does NOT have $opt (husk allows it) -- ${out%%$'\n'*}"
      bad=$((bad + 1))
      ;;
  esac
done < <("$BROKER" --query-options 2>/dev/null)

if [ "$checked" -eq 0 ]; then
  echo "parity: nothing checked - the broker printed no table"
elif [ "$bad" -eq 0 ]; then
  echo "parity: all $checked allowed query options exist here (${ver:-unknown version}) [expect]"
else
  echo "parity: $bad of $checked allowed query options do not exist here (${ver:-unknown version})"
fi
