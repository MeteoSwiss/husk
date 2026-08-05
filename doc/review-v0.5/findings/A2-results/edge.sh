#!/bin/sh
NL=$(printf 'aaa\nbbb')
env \
  ' SLURM_LEAD=husk-review-a2env-leadspace' \
  'SLURM_TRAILSP =husk-review-a2env-trailspace' \
  'Slurm_Mixed=husk-review-a2env-mixedcase' \
  'SLURMNOUND=husk-review-a2env-nounderscore' \
  'SLURM_=husk-review-a2env-bareprefix' \
  'SBATCH_X=husk-review-a2env-sbatchx' \
  "NLVAL=${NL}" \
  HUSKREV_OK=husk-review-a2env-control \
  srun -n1 "$1" 2>/dev/null
echo "srun-exit=$?"
