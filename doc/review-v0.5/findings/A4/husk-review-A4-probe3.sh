#!/bin/bash
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --time=00:05:00
#SBATCH --job-name=husk-review-A4c
# A4 probe #3: do request fields reach the trusted step-broker's audit log / response
# UNSANITIZED (newlines)? The broker's per-job log ($HOME/.husk/log/job-<jid>.log) is the
# audit trail the design says the audited party must not author. Log is unreadable from
# in-cage (correct), so: (a) prove non-sanitization via the READABLE resp.message
# reflection of cwd, and (b) plant clearly-marked husk-review-A4-LOGFORGE-* payloads for a
# human to verify in the job log. Benign marker text only; cleans up injected reqs.
set +e
WR="${HUSK_WRITABLE:-$PWD}"; JID="${SLURM_JOB_ID:-nojob}"; SP="${HUSK_STEP_SPOOL:-}"
REPORT="$WR/husk-review-A4-report3-$JID.txt"
{
echo "################ A4 PROBE #3 (field sanitization / audit-log injection) ################"
echo "start_utc=$(date -u +%Y%m%dT%H%M%SZ) host=$(hostname) job=$JID"
echo "step-broker audit log (HUMAN verifies here): ${HUSK_JOB_LOG:-?}"
if [ -z "$SP" ] || [ ! -d "$SP" ]; then echo "!! no step spool; abort"; echo END; exit 0; fi
python3 - "$SP" "$WR" "$JID" <<'PYEOF'
import json, os, sys, time, uuid
spool, wr, jid = sys.argv[1:4]
def out(*a): print(*a, flush=True)
def drop(obj):
    fn="req-%s.json"%uuid.uuid4(); p=os.path.join(spool,fn); tmp=p+".tmp"
    open(tmp,"w").write(json.dumps(obj)); os.replace(tmp,p); return fn
def base(rid, argv, cwd, sub="1970-01-01T00:00:00Z", env=None):
    return {"version":1,"id":rid,"tool":"srun","submitted_at":sub,"cwd":cwd,"argv":argv,
            "script":{"source":"none","name":None,"body":""},"job_args":[],"env":env or {}}
def waitresp(rid, t=12):
    dl=time.time()+t; rp=os.path.join(spool,"resp-%s.json"%rid)
    while time.time()<dl and not os.path.exists(rp): time.sleep(0.1)
    try: return open(rp).read()
    except Exception as e: return "<no resp: %s>"%e

FORGE="husk-review-A4-LOGFORGE"
# --- Vector 1: cwd reflected UNSANITIZED into resp.message (SELF-VERIFIABLE) ---
# cwd under /users -> rejected -> message echoes cwd verbatim. Embed a newline+forged line.
cwd_payload="/users/cmueller\n%s-cwd-%s: this line was authored by the caged rank\nhusk: "%(FORGE,jid)
rid="husk-review-A4-sanit-cwd-%s"%jid
drop(base(rid, ["/bin/true"], cwd_payload))
msg=waitresp(rid)
out("=== [V1] cwd newline reflection (readable proof of non-sanitization) ===")
out("resp raw: %r"%msg)
try:
    j=json.loads(msg); m=j.get("message","")
    out("newline present in resp.message: %s"%("\n" in m))
    out("forged marker present in resp.message: %s"%((FORGE+"-cwd") in m))
    out("resp.message rendered:\n%s"%m)
except Exception as e: out("parse: %s"%e)

# --- Vector 2: submitted_at logged verbatim (self-test showed submitted_at=<raw>) ---
sub_payload="1970-01-01T00:00:00Z\n%s-submitted-%s: forged audit line (submitted_at field)\nhusk: "%(FORGE,jid)
rid2="husk-review-A4-sanit-sub-%s"%jid
drop(base(rid2, ["/bin/true"], wr, sub=sub_payload))
out("\n=== [V2] submitted_at newline (HUMAN verifies in job log) ===")
out("resp: %s"%waitresp(rid2))

# --- Vector 3: argv logged? newline in argv element ---
rid3="husk-review-A4-sanit-argv-%s"%jid
drop(base(rid3, ["/bin/true","%s-argv-%s\nhusk: forged audit line (argv field)"%(FORGE,jid)], wr))
out("\n=== [V3] argv newline (HUMAN verifies in job log) ===")
out("resp: %s"%waitresp(rid3))

# --- Vector 4: id newline (id is logged as request id=<id>) ---
rid4="husk-review-A4-sanit-id-%s\nhusk: %s-id-%s forged audit line (id field)"%(jid,FORGE,jid)
fn=drop(base(rid4, ["/bin/true"], wr))
out("\n=== [V4] id newline (HUMAN verifies in job log; resp likely absent - glued path) ===")
# resp path is glued(id) with a newline -> may not be creatable; just note
time.sleep(3)
found=[f for f in os.listdir(spool) if "sanit-id" in f]
out("spool entries mentioning sanit-id: %s"%found)

out("\n=== HUMAN VERIFICATION ===")
out("Inspect the step-broker's per-job audit log OUTSIDE husk:")
out("  /users/cmueller/.husk/log/job-%s.log"%jid)
out("Grep for lines authored by the caged rank:  grep -n '%s' <that log>"%FORGE)
out("Any %s-* line present there = the audited party (a rank) forged audit-trail content."%FORGE)

# tidy: remove our injected reqs + any resp/out/err so the spool can clean up normally
for f in os.listdir(spool):
    if f.startswith(("req-","resp-","out-","err-")):
        try: os.remove(os.path.join(spool,f))
        except Exception: pass
PYEOF
echo END
} > "$REPORT" 2>&1
cat "$REPORT"
