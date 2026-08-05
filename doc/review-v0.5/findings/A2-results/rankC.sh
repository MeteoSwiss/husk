#!/bin/sh
tag="$1"
echo "@@C_${tag}_BEGIN"
for v in PAGER LESS LESSOPEN LESSCLOSE MANPATH MORE COLORTERM MINICOM CSHEDIT; do
  eval "s=\${$v+SET}"
  if [ "$s" = SET ]; then echo "$v=present"; else echo "$v=ABSENT"; fi
done
echo "AAA_count=$(env | grep -c '^AAA')"
echo "@@C_${tag}_END"
