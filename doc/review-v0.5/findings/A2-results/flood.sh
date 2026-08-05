#!/bin/sh
i=1
while [ "$i" -le 600 ]; do
  n=$(printf 'HUSKREV_F%04d' "$i")
  eval "export $n=v$i"
  i=$((i+1))
done
export HUSKREV_FLAST=husk-review-a2env-sentinel
echo "guard exported HUSKREV_F count=$(env | grep -c '^HUSKREV_F')"
srun -n1 "$1" 2>"$2.err"
echo "srun-exit=$?"
echo "@@SRUNERR"; cat "$2.err" 2>/dev/null | grep -iE 'husk|error|forward|512|truncat|limit' | head
