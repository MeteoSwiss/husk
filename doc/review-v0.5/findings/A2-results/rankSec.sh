#!/bin/sh
echo "@@SEC_BEGIN"
echo "AAA_count=$(env | grep -c '^AAA')"
for v in HUSK_NET_SOCK HUSK_SOCAT _HUSK_NET_SOCK _HUSK_SOCAT PATH HOME USER \
         http_proxy HTTPS_PROXY HUSK_JOB_LOG HUSK_STEP_SPOOL HUSK_SESSION_LOG; do
  eval "s=\${$v+SET}"
  if [ "$s" = SET ]; then echo "$v=present"; else echo "$v=DROPPED/ABSENT"; fi
done
echo "@@SEC_END"
