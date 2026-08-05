#!/bin/sh
i=1; while [ "$i" -le 520 ]; do n=$(printf 'AAA%04d' "$i"); eval "export $n=v$i"; i=$((i+1)); done
srun -n1 "$1" 2>/dev/null; echo "srun-exit=$?"
