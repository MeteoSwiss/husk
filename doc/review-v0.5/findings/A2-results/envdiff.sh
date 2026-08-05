#!/bin/sh
echo "@@GUARD_ENV_NAMES_BEGIN"
env | sed 's/=.*//' | sort
echo "@@GUARD_ENV_NAMES_END"
echo "@@GUARD_SENSITIVE_VALUES (names only shown for foreign; canaries below are mine)"
# battery of injected canaries (valid + reserved-prefix + case variants + overrides)
export HUSKREV_PLAIN=husk-review-a2env-plain
export SLURM_HUSKREV=husk-review-a2env-slurmprefix
export SBATCH_HUSKREV=husk-review-a2env-sbatchprefix
export slurm_huskrev=husk-review-a2env-lowerslurm
export Slurm_Huskrev=husk-review-a2env-mixedslurm
export HUSK_NET_SOCK=husk-review-a2env-OVERRIDE-netsock
export _HUSK_NET_SOCK=husk-review-a2env-OVERRIDE-_netsock
export HUSK_SOCAT=husk-review-a2env-OVERRIDE-socat
export SLURM_CONF=/tmp/husk-review-a2env-fake-slurm.conf
export HUSKREV_EQ='has=equals=and spaces'
echo "guard HUSK_NET_SOCK before srun = [${HUSK_NET_SOCK}]"
srun -n1 "$1" 2>"$2.srunerr"
echo "srun-exit=$?"
echo "@@SRUN_STDERR_BEGIN"; cat "$2.srunerr" 2>/dev/null; echo "@@SRUN_STDERR_END"
