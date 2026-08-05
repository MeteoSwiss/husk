#!/bin/sh
echo "@@ORD_BEGIN"
for v in HUSK_WRITABLE CUDA_VISIBLE_DEVICES ROCR_VISIBLE_DEVICES ZE_AFFINITY_MASK \
         SLURM_GPUS_ON_NODE SLURM_NODE_ALIASES GPU_DEVICE_ORDINAL; do
  eval "s=\${$v+SET}"; eval "val=\${$v}"
  if [ "$s" = SET ]; then echo "$v=[$val]"; else echo "$v=<unset:MASK_WINS>"; fi
done
echo "@@ORD_END"
