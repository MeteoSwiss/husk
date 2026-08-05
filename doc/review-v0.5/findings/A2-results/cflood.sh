#!/bin/sh
# remove cosmetic vars from the job env, so delta would emit --unsetenv for any that are in base
unset PAGER LESS LESSOPEN LESSCLOSE MANPATH MORE COLORTERM MINICOM CSHEDIT
echo "== control srun (job lacks cosmetic vars, NO flood) =="
srun -n1 "$1" control 2>/dev/null
echo "== flood srun (job lacks cosmetic vars, +520 AAA to overflow 512) =="
i=1; while [ "$i" -le 520 ]; do n=$(printf 'AAA%04d' "$i"); eval "export $n=v$i"; i=$((i+1)); done
srun -n1 "$1" flood 2>/dev/null
echo "srun-exit=$?"
