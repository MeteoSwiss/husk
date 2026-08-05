#!/bin/sh
echo "@@MASK2_BEGIN"
echo "AAA count in rank=$(env | grep -c '^AAA')"
for v in HUSK_WRITABLE CUDA_VISIBLE_DEVICES GPU_DEVICE_ORDINAL ROCR_VISIBLE_DEVICES \
         ZE_AFFINITY_MASK SLURM_NODE_ALIASES; do
  eval "s=\${$v+SET}"; eval "val=\${$v}"
  if [ "$s" = SET ]; then echo "$v=[$val]  <-- MASK DROPPED (stayed set)"; else echo "$v=<unset> (mask held)"; fi
done
echo "@@MASK2_END"
