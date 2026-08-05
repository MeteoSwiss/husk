#!/bin/sh
# 520 vars named to sort BEFORE husk's mask targets (C.., G.., H.., R.., S.., Z..)
i=1
while [ "$i" -le 520 ]; do
  n=$(printf 'AAA%04d' "$i")
  eval "export $n=v$i"
  i=$((i+1))
done
echo "guard AAA count=$(env | grep -c '^AAA'); guard HUSK_WRITABLE set? [${HUSK_WRITABLE+YES}]"
srun -n1 "$1" 2>/dev/null
echo "srun-exit=$?"
