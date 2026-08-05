#!/bin/bash
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --time=00:05:00
#SBATCH --job-name=husk-review-A4b
# A4 probe #2: decisively test what the step-broker does with req.cwd (is it bound
# WRITABLE into the rank cage?), plus env/argv arrival, id-traversal defense, and
# symlink following. Evidence is snapshotted into a workdir dir (outside the spool) so
# the job-end cleanup cannot erase it. Canary writes go only into MY OWN dirs.
set +e
WR="${HUSK_WRITABLE:-$PWD}"
JID="${SLURM_JOB_ID:-nojob}"
SP="${HUSK_STEP_SPOOL:-}"
REPORT="$WR/husk-review-A4-report2-$JID.txt"
ART="$WR/husk-review-A4-artifacts2-$JID"
mkdir -p "$ART" 2>/dev/null
# target dir OUTSIDE HUSK_WRITABLE but owned by me (the cwd-bind escape witness lands here)
OUTDIR="/scratch/mch/cmueller/husk-review"
{
echo "################ A4 PROBE #2 ################"
echo "start_utc=$(date -u +%Y%m%dT%H%M%SZ) host=$(hostname) job=$JID"
echo "WR=$WR  SP=$SP  OUTDIR(outside writable)=$OUTDIR"
echo
if [ -z "$SP" ] || [ ! -d "$SP" ]; then echo "!! no step spool; aborting"; echo END; exit 0; fi

python3 - "$SP" "$WR" "$ART" "$JID" "$OUTDIR" <<'PYEOF'
import json, os, sys, time, glob, uuid, shutil
spool, wr, art, jid, outdir = sys.argv[1:6]
parent = os.path.dirname(wr)
def out(*a): print(*a, flush=True)
def drop(fname, obj):
    p=os.path.join(spool,fname); tmp=p+".tmp"
    open(tmp,"w").write(json.dumps(obj)); os.replace(tmp,p); return p
def base_req(rid, argv, cwd, env=None):
    return {"version":1,"id":rid,"tool":"srun","submitted_at":"1970-01-01T00:00:00Z",
            "cwd":cwd,"argv":argv,"script":{"source":"none","name":None,"body":""},
            "job_args":[],"env":(env or {})}
def snap(reason):
    # copy every non-symlink resp/out/err currently in the spool into the artifacts dir
    for f in os.listdir(spool):
        if f.startswith(("resp-","out-","err-")):
            s=os.path.join(spool,f)
            try:
                if os.path.islink(s): continue
                shutil.copy2(s, os.path.join(art, f))
            except Exception as e: out("  snap %s failed: %s"%(f,e))
def waitfor(idstr, timeout=15):
    dl=time.time()+timeout
    rp=os.path.join(spool,"resp-%s.json"%idstr)
    while time.time()<dl:
        if os.path.exists(rp): break
        time.sleep(0.1)
    snap("wait-%s"%idstr)
    res={}
    for k,pth in (("resp",os.path.join(spool,"resp-%s.json"%idstr)),
                  ("out",os.path.join(spool,"out-%s"%idstr)),
                  ("err",os.path.join(spool,"err-%s"%idstr))):
        try: res[k]=open(pth).read()
        except Exception as e: res[k]="<%s>"%e
    return res

out("===== [C1+C2] cwd bound WRITABLE into rank cage? + env/argv arrival =====")
rid="husk-review-A4-cwdbind-%s"%jid
mark="husk-review-A4-cwdwrite-%s"%jid
script = (
  'echo "IN-STEP pwd=$(pwd)";'
  'echo "IN-STEP whoami=$(id -u)";'
  '( : > "./%s" ) 2>&1 && echo "WRITE_OK: created ./%s in cwd (cwd is WRITABLE in the rank cage)" || echo "WRITE_FAIL rc=$? (cwd not writable)";'
  'ls -la "./%s" 2>&1;'
  'echo "MOUNTINFO for cwd:"; grep -F "$(pwd)" /proc/self/mountinfo 2>&1 | sed "s/ - .*//" | head;'
  'echo "ENV_ARRIVAL:"; env | grep -E "HUSK_REVIEW_A4|LD_PRELOAD|OMP_NUM_THREADS" | sort;'
  'echo "ARGV_ARRIVAL: dollar0=$0 rest=$*";'
) % (mark, mark, mark)
env={"HUSK_REVIEW_A4":"canary","LD_PRELOAD":"/nonexistent-husk-review-A4.so","OMP_NUM_THREADS":"4"}
drop("req-%s.json"%uuid.uuid4(), base_req(rid, ["/bin/sh","-c",script,"husk-review-A4-argv0","husk-review-A4-argvcanary"], outdir, env))
r=waitfor(rid, 25)
out("[C1] resp: %s"%r["resp"].strip())
out("[C1] STEP STDOUT:\n%s"%r["out"])
out("[C1] STEP STDERR:\n%s"%r["err"])
# decisive check from OUTSIDE the step: did the marker land in OUTDIR (outside HUSK_WRITABLE)?
landed=os.path.join(outdir, mark)
out("[C1] witness path %s exists=%s"%(landed, os.path.exists(landed)))
if os.path.exists(landed):
    st=os.stat(landed); out("[C1] !!! ESCAPE WITNESS: %s (uid=%d mode=%o) written via a step whose cwd was outside the project"%(landed,st.st_uid,st.st_mode))

out("")
out("===== [C3] id traversal: does broker validate id, or fail on glued path? =====")
for tag,rid in {"up1":"../husk-review-A4-up1b-%s"%jid,
                "slip":"x/../../husk-review-A4-slipb-%s"%jid,
                "abs":"/tmp/husk-review-A4-absb-%s"%jid}.items():
    drop("req-%s.json"%uuid.uuid4(), base_req(rid, ["/bin/true"], wr))
    out("[C3:%s] dropped id=%r"%(tag,rid))
time.sleep(8)
snap("c3")
out("[C3] recursive spool listing (looking for resp-.. dirs / glued files):")
for root,dirs,files in os.walk(spool):
    for n in dirs+files:
        p=os.path.join(root,n)
        if os.path.islink(p): continue
        out("   %s"%p)
for probe in ("resp-..","out-x","resp-x"):
    pp=os.path.join(spool,probe); out("[C3] %s exists=%s isdir=%s"%(pp,os.path.exists(pp),os.path.isdir(pp)))
# did broker basename the id and write a safe resp?
for tag in ("up1b","slipb","absb"):
    for pre in ("resp-husk-review-A4-%s-%s.json","out-husk-review-A4-%s-%s","err-husk-review-A4-%s-%s"):
        pp=os.path.join(spool, pre%(tag,jid))
        if os.path.exists(pp):
            out("[C3] BASENAMED artifact present: %s => %s"%(pp, open(pp).read()[:200] if os.path.isfile(pp) else "<dir>"))

out("")
out("===== [C4] symlink following: broker read a req via a symlink to an out-of-spool file? =====")
poison=os.path.join(wr,"husk-review-A4-sympoison-%s.json"%jid)
symid="husk-review-A4-SYMWIN-%s"%jid
open(poison,"w").write(json.dumps(base_req(symid, ["/bin/true"], wr)))
linkpath=os.path.join(spool,"req-%s.json"%uuid.uuid4())
try:
    os.symlink(poison, linkpath); out("[C4] created symlink %s -> %s"%(linkpath,poison))
except Exception as e:
    out("[C4] symlink create failed: %s"%e)
time.sleep(8)
snap("c4")
sp_resp=os.path.join(spool,"resp-%s.json"%symid)
out("[C4] SYMWIN resp present in spool = %s"%os.path.exists(sp_resp))
if os.path.exists(sp_resp):
    out("[C4] !!! broker FOLLOWED the symlink and processed an out-of-spool request: %s"%open(sp_resp).read().strip())
else:
    out("[C4] broker did NOT process the symlinked request (refuses symlinks / O_NOFOLLOW, or ignored)")
out("[C4] any SYMWIN artifacts anywhere:")
for base in (spool,wr,parent,outdir):
    try:
        for f in os.listdir(base):
            if "SYMWIN" in f: out("   %s"%os.path.join(base,f))
    except Exception: pass

out("")
out("===== final artifacts snapshot dir =====")
for f in sorted(os.listdir(art)): out("   ART/%s (%d bytes)"%(f, os.path.getsize(os.path.join(art,f))))
# tidy the spool of our injected reqs so normal cleanup can rmdir it
for f in os.listdir(spool):
    if f.startswith(("req-","resp-","out-","err-")):
        try: os.remove(os.path.join(spool,f))
        except Exception: pass
PYEOF
echo END
} > "$REPORT" 2>&1
cat "$REPORT"
