#!/bin/sh
# A2 rank-view observation harness. Prints env NAMES (not foreign values),
# canary values only, plus cage structure. No exploit; pure observation.
echo "=== A2 HARNESS BEGIN ==="
echo "host=$(hostname)"
echo "id=$(id)"
echo "argv0=[$0]"
echo "numargs=$#"
n=0; for a in "$@"; do n=$((n+1)); echo "arg$n=[$a]"; done
echo "--- selected identity/exec-relevant vars (values shown; these are not secrets) ---"
for v in PATH LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT PYTHONPATH PERL5LIB BASH_ENV ENV IFS SHELL TMPDIR HOME USER; do
  eval "val=\${$v+SET}"; eval "cur=\${$v}"
  if [ "$val" = SET ]; then echo "$v=[$cur]"; else echo "$v=<unset>"; fi
done
echo "--- HUSKREV_* canaries (values shown) ---"
env | grep '^HUSKREV_' | sort || echo "(none)"
echo "--- ALL env NAMES (values redacted) ---"
env | sed 's/=.*//' | sort
echo "--- proxy-var NAMES present (values redacted) ---"
env | sed 's/=.*//' | grep -iE 'proxy|token|munge|cred|secret|key' | sort || echo "(none)"
echo "--- mountinfo (first 60) ---"
head -60 /proc/self/mountinfo 2>/dev/null
echo "--- am I caged? cwd + write test ---"
echo "cwd=$(pwd)"
echo "=== A2 HARNESS END ==="
