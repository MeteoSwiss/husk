#!/bin/sh
echo "@@EDGE_BEGIN"
echo "-- canary-valued names that reached the rank (name=value) --"
env | grep 'husk-review-a2env' | sort || echo "(none)"
echo "-- newline value NLVAL (od to reveal bytes) --"
printf '%s' "${NLVAL-<unset>}" | od -c | head
echo "@@EDGE_END"
