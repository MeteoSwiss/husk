#!/bin/bash
#SBATCH --job-name=husk-connparse
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --time=00:05:00
#
# Runs A9's CONNECT-parser battery against HUSK'S OWN egress proxy, from inside a
# brokered job cage — the context A9 could not reach and therefore never tested.
#
# Submit it from inside a husk session so the broker stages it:
#     sbatch --partition=<your partition> ~/husk/slurm-broker/connect-parser-job.sh
#
# The job needs egress configured, or there is no gate to test: set an allowlist in
# ~/.husk/config.json (or the settings the broker reads) before submitting. With no
# allowlist husk starts no relay at all, and the probe will correctly report that it
# found no proxy rather than inventing a verdict.
#
# Output lands in the job's SLURM output file; husk also names its own log in the job
# output. Read the "talking to:" line first — it says whether a finding is husk's or
# Anthropic's.
set -u

# Locate the probe. NOT `dirname $0`: the broker STAGES the job body, so at runtime $0 is
# the staged copy and the probe is not beside it. $SLURM_SUBMIT_DIR is the directory sbatch
# was invoked from, which is where the operator put both files.
PROBE=""
for _c in "${HUSK_PROBE:-}" \
          "${SLURM_SUBMIT_DIR:-}/connect-parser-probe.py" \
          "$(dirname "$(readlink -f "$0")")/connect-parser-probe.py" \
          "./connect-parser-probe.py"; do
    [ -n "$_c" ] && [ -r "$_c" ] && { PROBE="$_c"; break; }
done
if [ -z "$PROBE" ]; then
    echo "connect-parser-job: cannot find connect-parser-probe.py." >&2
    echo "  Put it beside the job script in the directory you submit from, or set" >&2
    echo "  HUSK_PROBE=/path/to/connect-parser-probe.py before submitting." >&2
    echo "  Looked in: \$HUSK_PROBE, \$SLURM_SUBMIT_DIR (${SLURM_SUBMIT_DIR:-unset})," >&2
    echo "  \$(dirname \$0) and the cwd. Note the broker STAGES the body, so \$0 is the" >&2
    echo "  staged copy and the probe is not beside it." >&2
    exit 2
fi
echo "husk connect-parser job on $(hostname) at $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "probe: $PROBE"
echo

echo "--- what the cage sees of its own egress ---"
echo "HTTP_PROXY=${HTTP_PROXY:-unset}  HTTPS_PROXY=${HTTPS_PROXY:-unset}"
command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | head -5
echo

python3 "$PROBE"
rc=$?
echo
echo "connect-parser-job: probe exit=$rc (0=no disagreement, 1=FINDINGS, 2=inconclusive)"
exit "$rc"
