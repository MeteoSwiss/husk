#!/bin/sh
echo "@@FLOOD_BEGIN"
c=$(env | grep -c '^HUSKREV_F')
echo "rank HUSKREV_F count=$c"
echo "sentinel HUSKREV_FLAST=[${HUSKREV_FLAST-<unset>}]"
echo "first present: $(env | grep '^HUSKREV_F' | sort | head -1)"
echo "last present:  $(env | grep '^HUSKREV_F' | sort | tail -1)"
echo "victim (base var) test: PAGER=[${PAGER-<unset>}] LESS=[${LESS-<unset>}]"
echo "@@FLOOD_END"
