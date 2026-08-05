#!/bin/sh
echo "@@RANK_ENV_NAMES_BEGIN"
env | sed 's/=.*//' | sort
echo "@@RANK_ENV_NAMES_END"
echo "@@RANK_CANARY_VALUES_BEGIN"
for v in HUSKREV_PLAIN SLURM_HUSKREV SBATCH_HUSKREV slurm_huskrev Slurm_Huskrev \
         HUSK_NET_SOCK _HUSK_NET_SOCK HUSK_SOCAT SLURM_CONF SLURM_JOB_ID SLURMD_NODENAME \
         PMI_SHARED_SECRET HUSKREV_EQ; do
  eval "s=\${$v+SET}"; eval "val=\${$v}"
  if [ "$s" = SET ]; then echo "$v=[$val]"; else echo "$v=<unset>"; fi
done
echo "@@RANK_CANARY_VALUES_END"
