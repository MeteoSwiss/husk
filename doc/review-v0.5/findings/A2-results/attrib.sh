#!/bin/sh
export LD_PRELOAD=/nonexistent/husk-review-a2env-preload.so
c(){ grep -c 'cannot be preloaded' "$1" 2>/dev/null; }
# stub launch cost (env -> python3), no step
env python3 -c pass 2>"$1.stub"; echo "stub-launch(env+python)=$(c "$1.stub")"
# one dynamically-linked binary in the COMPUTE cage
/bin/true 2>"$1.cc"; echo "compute-cage /bin/true=$(c "$1.cc")"
# srun scaling: n=1 vs n=2 (rank+wrapper scale per-task; stub is fixed)
srun -n1 /bin/true 2>"$1.n1"; echo "srun-n1 /bin/true=$(c "$1.n1")"
srun -n2 /bin/true 2>"$1.n2"; echo "srun-n2 /bin/true=$(c "$1.n2")"
# rank process tree: is the rank command wrapped by a caged /bin/sh?
echo "== rank proc tree =="
srun -n1 sh -c 'echo "self=$$ exe=$(readlink /proc/$$/exe)"; p=$(awk "/^PPid:/{print \$2}" /proc/$$/status); echo "PPid=$p ppexe=$(readlink /proc/$p/exe 2>/dev/null) ppcmd=$(tr "\0" " " </proc/$p/cmdline 2>/dev/null)"; gp=$(awk "/^PPid:/{print \$2}" /proc/$p/status 2>/dev/null); echo "GPPid=$gp gpexe=$(readlink /proc/$gp/exe 2>/dev/null) gpcmd=$(tr "\0" " " </proc/$gp/cmdline 2>/dev/null)"; echo "visible-pids:"; ls /proc | grep -E "^[0-9]+$" | tr "\n" " "; echo' 2>"$1.tree.err"
echo "-- tree stderr ld.so count=$(c "$1.tree.err")"
