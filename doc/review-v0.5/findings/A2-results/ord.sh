#!/bin/sh
export HUSK_WRITABLE='husk-review-a2env-RESTORE-writable:/etc:/'
export CUDA_VISIBLE_DEVICES='husk-review-a2env-RESTORE-cuda'
export ROCR_VISIBLE_DEVICES='husk-review-a2env-RESTORE-rocr'
export ZE_AFFINITY_MASK='husk-review-a2env-RESTORE-ze'
export SLURM_GPUS_ON_NODE='husk-review-a2env-RESTORE-gpus'
export SLURM_NODE_ALIASES='husk-review-a2env-RESTORE-aliases'
export GPU_DEVICE_ORDINAL='husk-review-a2env-RESTORE-ord'
srun -n1 "$1" 2>/dev/null
echo "srun-exit=$?"
