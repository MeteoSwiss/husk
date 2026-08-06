#!/usr/bin/env bash
# fabric-probe.sh — Slingshot/CXI fabric DISCOVERY for the husk srun/MPI phase.
#
# WHAT THIS IS: a fact-gatherer, run by YOU (the trusted operator) on a COMPUTE node,
# to answer the hardware gates in SRUN-MPI-DESIGN.md (C1–C6). It is NOT a containment
# pass/fail suite (that's selftest.sh) — the srun/MPI containment policy doesn't exist
# yet; these are the facts that will inform it. Output is a report; read it back into
# the design doc's "verify-on-hardware" section.
#
# HOW TO RUN — inside your OWN allocation (you have the rights; this bypasses husk).
#
# USE sbatch. This probe must execute ON a compute node, and on Alps `salloc` returns a
# shell that is STILL ON THE LOGIN NODE — so running the script after `salloc` measures
# the login node while looking exactly like a compute-node run. That cost a full round
# (2026-08-05) and produced a C1 claim that had to be withdrawn. There is now a guard that
# warns when an allocation is held but the shell is not on a compute node; heed it rather
# than working around it.
#
#     sbatch -N2 -n4 -p <partition> --time=00:20:00 -o fabric-probe-%j.out \
#            --uenv=<label> --view=<view> slurm-broker/fabric-probe.sh
#
#   -N2 is the one that matters: a single node can satisfy 2 ranks over shared memory and
#   hide the netns x CXI question entirely. -N1 answers the intra-node arms only.
#   --uenv/--view so fi_info / cc / MPI are on PATH inside the job; without them the
#   compile arms skip and most of the report is empty.
#
# If you really want an interactive shell on the node: `srun --overlap --pty bash` from
# INSIDE an existing allocation, not `salloc` alone.
#
# SAFE: read-only discovery + two throwaway test binaries in a tempdir. No writes
# outside $TMPDIR, no scheduler state changed.
set -uo pipefail

say()  { printf '%s\n' "$*"; }
head2() { printf '\n== %s ==\n' "$*"; }
note() { printf '  %s\n' "$*"; }
# machine-greppable finding lines: FINDING <gate> <key> <value...>
fnd()  { printf 'FINDING %-4s %-22s %s\n' "$1" "$2" "${*:3}"; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/husk-fabric-probe.XXXXXX")"
# The multi-rank runs execute on OTHER nodes, so the test binary must live on a SHARED
# filesystem. $TMPDIR/mktemp is node-local /tmp on Alps: run 2 (2026-07-28) died with
# `execve(): No such file or directory` on the second node, which invalidated every
# 2-rank result. Build on the submit dir instead and VERIFY visibility (C5 below).
SHARED="${SLURM_SUBMIT_DIR:-$PWD}/.husk-fabric-probe.$$"
mkdir -p "$SHARED" 2>/dev/null || SHARED="$WORK"
trap 'rm -rf "$WORK" "$SHARED"' EXIT

# bwrap profile mirroring the compute cage (root ro + fresh /dev,/proc,/tmp). Callers
# append device binds / --unshare-net as needed. --dev gives a bare devtmpfs, so CXI
# nodes must be re-bound explicitly (that's the whole point of the C1/C4 questions).
BWRAP_BASE=(--ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --tmpfs /dev/shm)
# Only the numbered NIC nodes (/dev/cxi0…). Deliberately NOT /dev/cxi_sbl — Balfrin
# shows it as 0600 root:root (Slingshot base-link, an admin device), so a user job
# cannot open it anyway and the cage should not bind what it cannot use.
cxi_binds() { local d; for d in /dev/cxi[0-9]*; do [ -e "$d" ] && printf -- '--dev-bind-try %s %s ' "$d" "$d"; done; }

# ============================================================================
head2 "context"
say "host    : $(hostname)   arch=$(uname -m)   kernel=$(uname -r)"
say "date    : $(date -u +%FT%TZ)"
say "uenv    : ${UENV_VIEW:-<none>}  (label ${UENV_LABEL:-<none>})"
say "in slurm: JOB_ID=${SLURM_JOB_ID:-<none>}  NODES=${SLURM_JOB_NUM_NODES:-?}  NTASKS=${SLURM_NTASKS:-?}"

# WHERE AM I? `salloc` grants the allocation but leaves your shell on the LOGIN node
# (unless the site sets SallocDefaultCommand). Every arm below that does NOT go through
# srun then measures the login node's hardware — different NIC count, possibly different
# config — while looking exactly like a compute-node result. A C1 verdict taken that way
# is about the wrong machine, and the report gives no hint of it.
# SLURMD_NODENAME is set by slurmstepd inside a step, so it is present on a compute node
# and absent in a salloc shell: a clean discriminator that needs no hostname parsing.
if [ -n "${SLURM_JOB_ID:-}" ] && [ -z "${SLURMD_NODENAME:-}" ]; then
  say ""
  say "  *** WARNING: allocation held, but this shell is NOT on a compute node. ***"
  say "  Local arms (C4 inventory, C1 fi_info) will measure $(hostname) — a LOGIN node."
  say "  Only the srun-based arms reach compute. To measure the real hardware, either:"
  say "      sbatch -N2 --ntasks-per-node=2 -p <part> fabric-probe.sh     # whole probe on compute"
  say "  or  srun --pty --overlap bash    # then re-run this from the compute shell"
  say ""
elif [ -n "${SLURMD_NODENAME:-}" ]; then
  say "location: compute node ${SLURMD_NODENAME} (local arms measure real job hardware)"
fi
have() { command -v "$1" >/dev/null 2>&1; }
for t in bwrap fi_info srun cc mpicc seccomp-wrapper; do
  if have "$t"; then note "tool present : $t ($(command -v "$t"))"; else note "tool MISSING : $t"; fi
done
if ! have bwrap; then
  say "!! bwrap not found — this must run on a compute node where the cage tools exist. Aborting."
  exit 127
fi

# ============================================================================
head2 "C4 — fabric + accelerator device inventory (portable: reports whatever THIS node has)"
# A union of known fabric + accelerator device globs. The guard will --dev-bind-try over
# this SAME union → it opens exactly the nodes present and nothing more, so it adapts
# across Alps(cxi)/LUMI(cxi+kfd)/Euler,DKRZ(infiniband) and nvidia|amd unchanged. Run
# this probe on any of those sites to see its device surface.
found_any=0
for g in '/dev/cxi*' '/dev/infiniband/*' '/dev/hfi1*' '/dev/nvidia*' '/dev/kfd' '/dev/dri/*'; do
  if compgen -G "$g" >/dev/null 2>&1; then
    for d in $g; do [ -e "$d" ] && { note "$(ls -ld "$d")"; fnd C4 device "$d"; found_any=1; }; done
  fi
done
[ "$found_any" = 0 ] && fnd C4 device "NONE of the known fabric/accel device globs present here"
for p in /sys/class/cxi /sys/class/infiniband /dev/hugepages /dev/shm; do
  [ -e "$p" ] && { note "present: $p"; fnd C4 sys_path "$p"; }
done
note "hugepages: $(grep -i hugepages_total /proc/meminfo 2>/dev/null || echo '?')"

# ============================================================================
head2 "C2 — how VNIs / the fabric are exposed to the job (env)"
# The switch/hpe_slingshot plugin and libfabric set these; the VNI list is the crux of
# the 'checked hole'. We only RECORD them here — a true cross-VNI escape test needs a
# libfabric program (see the note at the end), it is not shell-doable.
env | grep -iE 'SLINGSHOT|(^|_)VNI|CXI|^FI_|PMI|SLURM_(NETWORK|STEP|JOB_ID|NTASKS|NODELIST)' \
    | sort | while IFS= read -r l; do note "$l"; done
env | grep -iqE 'VNI|SLINGSHOT' \
  && fnd C2 vni_env_job "VNI/Slingshot env present in the JOB env (see above)" \
  || fnd C2 vni_env_job "no VNI/Slingshot env in the JOB env — expected: the switch plugin sets it per STEP, see vni_env_step"

# The switch plugin allocates the VNIs. Which plugin is configured decides whether
# there IS hardware job isolation on this fabric at all — the premise of Chapter 2.
if have scontrol; then
  sw="$(scontrol show config 2>/dev/null | grep -iE '^(SwitchType|SwitchParameters)' | tr -s ' ' | paste -sd';' -)"
  fnd C2 switch_plugin "${sw:-<no SwitchType line — scontrol unreachable or switch/none>}"
fi

# VNI env is set on the STEP, not the batch/job environment — dump it from inside a step.
# Also captures PMI/PMIX paths, which Chapter 2 needs (the rendezvous socket the cage hides).
if have srun && [ -n "${SLURM_JOB_ID:-}" ]; then
  # Unanchored on purpose: run 2 reported "NONE" partly because `^PMI` cannot match
  # SLURM_PMI_*/PMIX_* spellings. Match the substrings anywhere in the variable name.
  step_env="$(srun -n1 env 2>/dev/null | grep -iE 'SLINGSHOT|VNI|CXI|PMI|PALS|APINFO|SPOOL|MPICH|^FI_' | sort)"
  if [ -n "$step_env" ]; then
    printf '%s\n' "$step_env" | while IFS= read -r l; do note "step: $l"; done
    fnd C2 vni_env_step "fabric/PMI env IS set at STEP scope (see 'step:' lines above)"
  else
    fnd C2 vni_env_step "NONE even inside a step — cross-check switch_plugin above"
  fi
fi

# ============================================================================
head2 "C1 — does --unshare-net break the CXI provider?  (fi_info -p cxi)"
# fi_info enumerates libfabric providers. If CXI enumerates uncaged AND under
# --unshare-net (with the device bound), netns and the fabric are orthogonal → the
# best-case cage (IP isolation + open fabric) is available. A full 2-rank MPI run is the
# definitive confirmation (C1-def below); this is the fast signal.
if have fi_info; then
  # Portable line: which libfabric providers exist here at all (cxi on Alps/LUMI,
  # verbs/psm2 on Euler/DKRZ, tcp everywhere). Tells you the fabric family before the
  # CXI-specific checks below.
  note "libfabric providers: $(fi_info 2>/dev/null | awk -F': ' '/^provider:/{print $2}' | sort -u | tr '\n' ' ')"
  cxi_count() { fi_info -p cxi 2>/dev/null | grep -c 'provider: cxi' ; }
  base_n="$(cxi_count)"; fnd C1 cxi_uncaged "$base_n cxi endpoint(s) enumerated (no cage)"

  read -r -a CXIB <<<"$(cxi_binds)"
  netns_n="$(bwrap "${BWRAP_BASE[@]}" "${CXIB[@]}" --unshare-net -- fi_info -p cxi 2>/dev/null | grep -c 'provider: cxi')"
  fnd C1 cxi_bwrap_unshare_net "$netns_n cxi endpoint(s) under bwrap --unshare-net + /dev/cxi bound"

  nonet_n="$(bwrap "${BWRAP_BASE[@]}" "${CXIB[@]}" -- fi_info -p cxi 2>/dev/null | grep -c 'provider: cxi')"
  fnd C1 cxi_bwrap_no_unshare "$nonet_n cxi endpoint(s) under bwrap + /dev/cxi bound, net NOT unshared"

  nodev_n="$(bwrap "${BWRAP_BASE[@]}" --unshare-net -- fi_info -p cxi 2>/dev/null | grep -c 'provider: cxi')"
  fnd C4 cxi_needs_device "$nodev_n cxi endpoint(s) with NO /dev/cxi bound (expect 0 → device is required)"

  if [ "${base_n:-0}" -gt 0 ] && [ "${netns_n:-0}" -gt 0 ]; then
    fnd C1 verdict "LEANS-ORTHOGONAL: CXI still enumerates under --unshare-net → best-case cage likely OK (confirm with C1-def)"
  elif [ "${base_n:-0}" -gt 0 ] && [ "${nonet_n:-0}" -gt 0 ]; then
    fnd C1 verdict "netns MAY break CXI (device-bound works only without --unshare-net) → data-plane cage can't use netns for IP isolation"
  else
    fnd C1 verdict "INCONCLUSIVE from fi_info alone (base=$base_n) — use the C1-def MPI run"
  fi
else
  fnd C1 verdict "SKIP — fi_info not on PATH (activate a uenv with libfabric/cray-mpich)"
fi

# ============================================================================
head2 "C3 — does per-task bwrap work when launched by slurmstepd (srun)?"
# The Chapter-1 mechanism wraps each task: srun ... -- bwrap ... -- cmd. Confirm the
# userns nesting survives stepd's task setup. Uses plain bwrap (the userns question);
# seccomp-wrapper adds the seccomp layer on top if installed.
if have srun && [ -n "${SLURM_JOB_ID:-}" ]; then
  WRAP=(bwrap "${BWRAP_BASE[@]}" --unshare-net -- /bin/hostname)
  if have seccomp-wrapper; then WRAP=(seccomp-wrapper "${WRAP[@]}"); fi
  if out="$(srun -n1 "${WRAP[@]}" 2>&1)"; then
    fnd C3 pertask_bwrap_n1 "OK ($out) — per-task bwrap launches under stepd"
  else
    fnd C3 pertask_bwrap_n1 "FAIL — $out"
  fi
  if out2="$(srun -n2 "${WRAP[@]}" 2>&1 | tr '\n' ' ')"; then
    fnd C3 pertask_bwrap_n2 "OK ($out2)"
  else
    fnd C3 pertask_bwrap_n2 "FAIL — $out2"
  fi
else
  fnd C3 pertask_bwrap "SKIP — not in a SLURM allocation (salloc first) or srun missing"
fi

# ============================================================================
head2 "C5/C6/C1-def — MPI: singleton, 1-rank NIC dependency, 2-rank over the cage"
# Optional: needs a compiler + MPI. Answers whether ICON-single-rank can skip srun
# (C5), whether 1 rank needs /dev/cxi (C6), and confirms C1 with a real 2-rank run.
cat > "$WORK/mpi_hello.c" <<'C'
#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>

/* Dump the sockets THIS process holds, after MPI_Init.
 *
 * Three earlier attempts to answer "which PMI transport is in use" all failed the same
 * way: they inspected a process that had no reason to open one — a singleton, then a
 * `sh -c`. Only a real rank that has completed MPI_Init holds the connection, so the
 * only honest place to look is from inside this program.
 *
 * Gated behind an env var because several probe arms parse this program's stdout and
 * COUNT its lines to detect singleton fallback; extra lines would break them.
 *
 * Resolved from our own fd table against the /proc/net tables, so it is process-scoped
 * construction — `ss` without filtering returned the whole node's Lustre mounts. */
static void fmt4(const char *hex, char *out, size_t n){
  unsigned a, port;
  if (sscanf(hex, "%8X:%4X", &a, &port) == 2)
    snprintf(out, n, "%u.%u.%u.%u:%u",
             a & 0xff, (a >> 8) & 0xff, (a >> 16) & 0xff, (a >> 24) & 0xff, port);
  else snprintf(out, n, "%s", hex);
}
static void scan_net(const char *file, unsigned long want, int rank, const char *host,
                     const char *fd, int v6){
  FILE *f = fopen(file, "r"); if (!f) return;
  char line[512]; if (!fgets(line, sizeof line, f)) { fclose(f); return; }
  while (fgets(line, sizeof line, f)) {
    char loc[128], rem[128], st[16]; unsigned long ino = 0;
    if (sscanf(line, " %*d: %127s %127s %15s %*s %*s %*s %*d %*d %lu",
               loc, rem, st, &ino) == 4 && ino == want) {
      char l[132], r[132];
      if (v6) { snprintf(l, sizeof l, "%s", loc); snprintf(r, sizeof r, "%s", rem); }
      else { fmt4(loc, l, sizeof l); fmt4(rem, r, sizeof r); }
      printf("SOCK rank=%d host=%s fd=%s proto=%s local=%s peer=%s st=%s\n",
             rank, host, fd, v6 ? "tcp6" : "tcp", l, r, st);
    }
  }
  fclose(f);
}
static void dump_sockets(int rank){
  if (!getenv("HUSK_PROBE_DUMP_SOCKETS")) return;
  char host[256] = "?"; gethostname(host, sizeof host);
  DIR *d = opendir("/proc/self/fd"); if (!d) return;
  struct dirent *e;
  while ((e = readdir(d))) {
    char p[512], t[512]; int n;
    if (e->d_name[0] == '.') continue;
    snprintf(p, sizeof p, "/proc/self/fd/%s", e->d_name);
    n = readlink(p, t, sizeof t - 1); if (n < 0) continue; t[n] = 0;
    if (strncmp(t, "socket:[", 8) != 0) continue;
    unsigned long ino = strtoul(t + 8, NULL, 10);
    scan_net("/proc/net/tcp",  ino, rank, host, e->d_name, 0);
    scan_net("/proc/net/tcp6", ino, rank, host, e->d_name, 1);
    /* A unix hit means the rendezvous is a filesystem path and a netns cannot block it. */
    FILE *u = fopen("/proc/net/unix", "r");
    if (u) { char line[512];
      while (fgets(line, sizeof line, u)) {
        unsigned long uino = 0; char path[256] = "";
        if (sscanf(line, "%*x: %*x %*x %*x %*x %*x %lu %255s", &uino, path) >= 1 && uino == ino)
          printf("SOCK rank=%d host=%s fd=%s proto=unix path=%s\n",
                 rank, host, e->d_name, path[0] ? path : "(unnamed)");
      }
      fclose(u); }
  }
  closedir(d);
}

int main(int argc, char** argv){
  int rank=0,size=1; MPI_Init(&argc,&argv);
  MPI_Comm_rank(MPI_COMM_WORLD,&rank); MPI_Comm_size(MPI_COMM_WORLD,&size);
  int sum=0; MPI_Allreduce(&rank,&sum,1,MPI_INT,MPI_SUM,MPI_COMM_WORLD);
  printf("MPI rank %d/%d allreduce=%d\n", rank, size, sum);
  dump_sockets(rank);
  MPI_Finalize(); return 0;
}
C
# Which compiler has MPI is NOT decidable by name: in a Cray-native environment `cc` IS
# the MPI wrapper, but under a uenv /usr/bin/cc is plain gcc with no mpi.h while the
# uenv's mpicc works (Balfrin 2026-07-28: picking `cc` by presence alone failed here).
# So try each candidate and keep the first that actually BUILDS — compiling is the only
# honest test of "this toolchain has MPI".
CCX=""
for c in mpicc cc; do
  have "$c" || continue
  if "$c" -o "$SHARED/mpi_hello" "$WORK/mpi_hello.c" >"$WORK/cc.$c.log" 2>&1; then CCX="$c"; break; fi
  note "compile with $(command -v "$c") failed: $(grep -m1 -iE 'error|fatal' "$WORK/cc.$c.log" 2>/dev/null || tail -1 "$WORK/cc.$c.log" 2>/dev/null)"
done

# Classify a failure blob. Run 2 reported a PMI bootstrap failure under the label
# "1-rank MPI_Init touches the NIC", which is a wrong attribution — never let the
# probe name a cause it did not isolate.
why() {
  case "$1" in
    *pals_init*|*PMI_Init*|*PMIX*|*pmi_*)        echo "PMI/launcher bootstrap" ;;
    *"No such file or directory"*|*"Can't find source path"*)
                                                 echo "binary not visible on that node" ;;
    *cxi*|*libfabric*|*ofi*|*"NIC"*)             echo "fabric/NIC" ;;
    *"Permission denied"*|*EACCES*)              echo "permissions" ;;
    *)                                           echo "unclassified" ;;
  esac
}
one_line() { printf '%s' "$1" | tr '\n' ' '; }

if [ -z "$CCX" ]; then
  fnd C5 mpi_build "FAIL — no compiler on PATH built an MPI hello (tried mpicc, cc; see notes above)"
elif ! have srun || [ -z "${SLURM_JOB_ID:-}" ]; then
  fnd C5 mpi_build "OK ($CCX = $(command -v "$CCX"))"
  if out="$("$SHARED/mpi_hello" 2>&1)"; then fnd C5 singleton_init "OK ($out)"
  else fnd C5 singleton_init "FAIL — $(one_line "$out")"; fi
  fnd C6 rank1 "SKIP — not in a SLURM allocation"
else
  fnd C5 mpi_build "OK ($CCX = $(command -v "$CCX"))"

  # C5 — singleton init, NO launcher (Stage 0 viability).
  #
  # `env -u PMI_* …` is load-bearing, not hygiene. If this probe is running INSIDE a step
  # — `srun --pty bash`, which is the natural way to get an interactive compute shell —
  # then PMI_RANK, PMI_CONTROL_PORT and PMI_SHARED_SECRET are all set, and a "singleton"
  # MPI_Init is not singleton: it tries to join the surrounding step's rendezvous and
  # BLOCKS FOREVER. Measured on Balfrin 2026-08-05: the probe hung here with no output and
  # no timeout, which reads as a broken node rather than a broken assumption.
  # Stripping the step's identity is what makes the word "singleton" true.
  if out="$(${TMO[@]+"${TMO[@]}"} env -u PMI_RANK -u PMI_SIZE -u PMI_LOCAL_RANK \
              -u PMI_LOCAL_SIZE -u PMI_UNIVERSE_SIZE -u PMI_JOBID -u PMI_CONTROL_PORT \
              -u PMI_SHARED_SECRET -u PMIX_RANK -u PMIX_NAMESPACE \
              "$SHARED/mpi_hello" 2>&1)"; then
    fnd C5 singleton_init "OK ($out) — Stage 0: ICON-1-rank may run with NO srun in the current cage"
  else
    fnd C5 singleton_init "FAIL [$(why "$out")] — $(one_line "$out")"
  fi

  # Is the binary actually on a shared filesystem? If not, every multi-node result below
  # is meaningless (run 2's failure mode) — so state it before reporting them.
  nn="${SLURM_JOB_NUM_NODES:-1}"
  if srun -N"$nn" -n"$nn" test -x "$SHARED/mpi_hello" >/dev/null 2>&1; then
    fnd C5 binary_shared "OK — $SHARED is visible on all $nn node(s)"
  else
    fnd C5 binary_shared "FAIL — $SHARED is NOT shared across nodes; multi-node results below are INVALID"
  fi

  # ---- launcher calibration -------------------------------------------------
  # Run 2: MPICH fell back to PALS (`pals_init2() failed`) and PMI_Init failed under a
  # bare `srun`. Whether that is the cage or the launcher cannot be told without an
  # UNCAGED baseline, so establish one first and reuse whatever bootstraps.
  fnd C5 mpi_default "$(scontrol show config 2>/dev/null | grep -iE '^MpiDefault' | tr -s ' ' || echo '<scontrol unavailable>')"
  types="$(srun --mpi=list 2>&1 | tr ',' '\n' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
           | grep -viE 'mpi plugin|possible values|^none$|^$' || true)"
  note "srun --mpi=list -> $(one_line "$types")"

  BASE_OK=0; MPIF=(); MPILBL="(default)"
  for m in "" $types; do
    if [ -z "$m" ]; then cand=(); lbl="(default)"; else cand=(--mpi="$m"); lbl="--mpi=$m"; fi
    if out="$(srun ${cand[@]+"${cand[@]}"} -n2 "$SHARED/mpi_hello" 2>&1)"; then
      BASE_OK=1; MPIF=(${cand[@]+"${cand[@]}"}); MPILBL="$lbl"
      fnd C1 mpi2_uncaged "OK with $lbl — $(one_line "$out")"
      break
    fi
    note "uncaged 2-rank with $lbl failed [$(why "$out")]: $(one_line "$out" | cut -c1-160)"
  done
  [ "$BASE_OK" = 1 ] || fnd C1 mpi2_uncaged \
    "FAIL for EVERY --mpi type (see notes) — NO uncaged baseline, so the caged runs below CANNOT be attributed to the cage"
  fnd C5 launcher_used "$MPILBL"

  SR=(srun ${MPIF[@]+"${MPIF[@]}"})
  # A hung probe burns the allocation and reports nothing (a local dry run wedged in
  # strace for 5+ minutes), so every diagnostic srun below runs under a wall clock.
  WALL=90
  TMO=(); have timeout && TMO=(timeout -k 5 "$WALL")
  srun_t() { ${TMO[@]+"${TMO[@]}"} "${SR[@]}" "$@"; }

  # Exit 0 is NOT success for a multi-rank run. Run 8: `--mpi=pmix` at 2 ranks printed
  # "MPI rank 0/1" TWICE and exited 0 — two INDEPENDENT singleton MPI jobs, not a
  # 2-rank communicator. MPICH falls back to singleton init when a PMI does not wire up,
  # so every multi-rank arm must assert the communicator it actually formed: N lines,
  # each reporting size N and the correct allreduce (0+1+...+(N-1)).
  ranks_ok() { # $1 output, $2 expected rank count
    local want=$(( $2 * ($2 - 1) / 2 ))
    [ "$(printf '%s\n' "$1" | grep -c "MPI rank [0-9]*/$2 allreduce=$want")" = "$2" ]
  }

  # C6 — control first (uncaged 1 rank), then the same rank in a cage with NO /dev/cxi.
  if out="$("${SR[@]}" -n1 "$SHARED/mpi_hello" 2>&1)"; then
    fnd C6 rank1_uncaged "OK ($(one_line "$out")) — baseline for the caged run below"
    if out="$("${SR[@]}" -n1 bwrap "${BWRAP_BASE[@]}" --unshare-net --bind "$SHARED" "$SHARED" -- "$SHARED/mpi_hello" 2>&1)"; then
      fnd C6 rank1_caged_no_cxi "OK — 1 rank runs caged WITHOUT /dev/cxi → Stage-1 cage can stay --unshare-net"
    else
      fnd C6 rank1_caged_no_cxi "FAIL [$(why "$out")] — differs from the uncaged baseline, so this IS the cage: $(one_line "$out" | cut -c1-200)"
    fi
  else
    fnd C6 rank1_uncaged "FAIL [$(why "$out")] — uncaged 1 rank already broken, cage not implicated: $(one_line "$out" | cut -c1-200)"
  fi

  # C1-def — 2 ranks through each cage shape, against the uncaged baseline above.
  read -r -a CXIB <<<"$(cxi_binds)"
  run2() { out="$("${SR[@]}" -n2 "$@" 2>&1)"; }
  run2 bwrap "${BWRAP_BASE[@]}" "${CXIB[@]}" --unshare-net --bind "$SHARED" "$SHARED" -- "$SHARED/mpi_hello" \
    && fnd C1 mpi2_unshare_net_cxi "OK — netns and CXI ARE orthogonal: $(one_line "$out")" \
    || fnd C1 mpi2_unshare_net_cxi "FAIL [$(why "$out")] — $(one_line "$out" | cut -c1-240)"
  run2 bwrap "${BWRAP_BASE[@]}" "${CXIB[@]}" --bind "$SHARED" "$SHARED" -- "$SHARED/mpi_hello" \
    && fnd C1 mpi2_no_unshare_cxi "OK — caged with the fabric, net NOT unshared: $(one_line "$out")" \
    || fnd C1 mpi2_no_unshare_cxi "FAIL [$(why "$out")] — $(one_line "$out" | cut -c1-240)"
fi

# ============================================================================
head2 "C8 — WHICH cage element breaks the PMI bootstrap?  (bisection)"
# Run 4 (Balfrin, 2026-07-29) killed the "a mask hides it" theory: EVERY variant failed,
# including `robind_only` = plain `bwrap --ro-bind / /` with no mask at all. That
# bisection was incomplete — every arm still had a READ-ONLY root, so the one property
# common to all failures was never varied. Bisect the cage's PROPERTIES this time
# (writability, then namespaces), widest-first, and stop guessing about paths: dump the
# launcher's actual env, list the candidate spool dirs caged vs uncaged, keep the FULL
# error text (run 4's was truncated at 100 chars, discarding the informative tail), and
# strace the failing open() if strace exists.
if [ -n "${CCX:-}" ] && have srun && [ -n "${SLURM_JOB_ID:-}" ] && [ "${BASE_OK:-0}" = 1 ]; then
  # Absolute path + a shell: run 5 got uncaged=0 lines from a bare `srun -n1 env` while
  # the caged variant returned 191, so the bare form resolves to something that prints
  # nothing here. Never trust a silent dump — the sample line below proves it worked.
  srun_t -n1 sh -c '/usr/bin/env' 2>/dev/null | sort > "$WORK/env.uncaged"
  srun_t -n1 bwrap "${BWRAP_BASE[@]}" --bind "$SHARED" "$SHARED" -- sh -c '/usr/bin/env' 2>/dev/null | sort > "$WORK/env.caged"
  fnd C8 env_dump_sample "uncaged first line: $(head -1 "$WORK/env.uncaged" 2>/dev/null)"
  # Sanity FIRST: run 4 reported "no env lost" and printed no task-env lines, which is
  # equally consistent with both dumps being EMPTY. Count them before believing either.
  fnd C8 env_dump_lines "uncaged=$(wc -l < "$WORK/env.uncaged" 2>/dev/null) caged=$(wc -l < "$WORK/env.caged" 2>/dev/null)"
  # Compare NAMES, not NAME=value: the two dumps come from two different steps, so
  # per-step values (PALS_APID, SLURM_STEP_ID, …) differ and a value-wise diff reports
  # them as "lost" when nothing was stripped at all (run 6 did exactly that).
  lost="$(comm -23 <(cut -d= -f1 "$WORK/env.uncaged" | sort -u) \
                   <(cut -d= -f1 "$WORK/env.caged"   | sort -u) 2>/dev/null | tr '\n' ' ')"
  fnd C8 env_lost_in_cage "${lost:-<none — the cage passes the environment through>}"
  # The whole uncaged task env, verbatim: we are looking for a variable whose spelling we
  # guessed wrong twice already, so stop filtering and read it.
  while IFS= read -r l; do note "task env: $l"; done < "$WORK/env.uncaged"

  # Candidate PMI/PALS spool locations, caged vs uncaged — the mount table as oracle.
  for p in /var/spool/slurmd /var/spool/slurmd/mpi_cray_shasta /var/run/palsd /run/palsd \
           /var/spool/pals /var/opt/cray/pals /tmp; do
    u="$(srun_t -n1 sh -c "ls -1 '$p' 2>&1 | head -5 | tr '\n' ' '" 2>/dev/null)"
    c="$(srun_t -n1 bwrap "${BWRAP_BASE[@]}" -- sh -c "ls -1 '$p' 2>&1 | head -5 | tr '\n' ' '" 2>/dev/null)"
    [ -z "$u$c" ] && continue
    fnd C8 "spool_$(printf '%s' "$p" | tr '/' '_')" "uncaged=[$u] caged=[$c]"
  done

  # Bisect the cage's PROPERTIES, widest first. rw_root is the key new arm: it has the
  # mount+user namespaces but a WRITABLE root, so it separates "read-only" from "namespace".
  bisect() {
    local lbl="$1"; shift
    if out="$(srun_t -n1 bwrap "$@" --bind "$SHARED" "$SHARED" -- "$SHARED/mpi_hello" 2>&1)"; then
      fnd C8 "bisect_$lbl" "OK — MPI_Init survives this cage shape"
    else
      fnd C8 "bisect_$lbl" "FAIL [$(why "$out")] $(one_line "$out" | cut -c1-140)"
    fi
  }
  bisect rw_root      --bind / /
  bisect rw_root_tmp  --bind / / --tmpfs /tmp
  bisect ro_root      --ro-bind / /
  bisect ro_root_rwtmp --ro-bind / / --bind /tmp /tmp
  bisect ro_root_rwvar --ro-bind / / --bind /var /var
  bisect ro_root_rwrun --ro-bind / / --bind /run /run
  bisect full         --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --tmpfs /dev/shm

  # Full, untruncated failure text of the minimal failing cage — the tail may name a path.
  out="$(srun_t -n1 bwrap --ro-bind / / --bind "$SHARED" "$SHARED" -- "$SHARED/mpi_hello" 2>&1)"
  printf '%s\n' "$out" | head -25 | while IFS= read -r l; do note "ro_root err: $l"; done

  # Name the missing file directly, if strace is available.
  if have strace; then
    st="$(srun_t -n1 bwrap --ro-bind / / --bind "$SHARED" "$SHARED" -- \
          strace -f -e trace=openat,open,connect,stat "$SHARED/mpi_hello" 2>&1 \
          | grep -iE 'ENOENT|EROFS|EACCES|EPERM' | tail -12)"
    if [ -n "$st" ]; then
      printf '%s\n' "$st" | while IFS= read -r l; do note "strace: $l"; done
      fnd C8 strace "captured — see 'strace:' lines for the failing syscall/path"
    else
      fnd C8 strace "ran but matched nothing (ptrace may be blocked in the userns)"
    fi
  else
    fnd C8 strace "SKIP — strace not on PATH"
  fi
else
  fnd C8 bisect "SKIP — needs a working uncaged MPI baseline in a SLURM allocation"
fi

# ============================================================================
head2 "C9 — candidate fixes for the apinfo EROFS"
# Run 5 (Balfrin, job 4965492) named the mechanism exactly, via strace:
#   openat("/var/spool/slurmd/mpi_cray_shasta/<jobid>.<stepid>/apinfo", O_RDWR) = EROFS
# Cray MPICH opens the per-step apinfo file READ-WRITE; `--ro-bind / /` makes the whole
# tree read-only. The file is VISIBLE — nothing is masked — it is WRITABILITY that is
# missing, which is why no mask-removal arm ever helped. Two candidate fixes:
#   (a) a minimal read-write carve-out for that one per-step directory, and
#   (b) a PMI implementation that does not need to write at all (pmi2 / pmix).
# Each caged arm gets an UNCAGED control, so a failing --mpi type is never mistaken for
# a cage failure.
if [ -n "${CCX:-}" ] && have srun && [ -n "${SLURM_JOB_ID:-}" ] && [ "${BASE_OK:-0}" = 1 ]; then
  spooldir="$(scontrol show config 2>/dev/null | awk -F'=' '/^SlurmdSpoolDir/{gsub(/ /,"",$2); print $2}')"
  [ -n "$spooldir" ] || spooldir=/var/spool/slurmd
  CRAYDIR="$spooldir/mpi_cray_shasta"
  export CRAYDIR SHARED
  fnd C9 spool_dir "$CRAYDIR"
  # Ownership/mode decides whether a read-write BIND is even enough: if the file is
  # root-owned and not user-writable, the wall is kernel permissions, not the namespace.
  note "step dirs : $(srun_t -n1 sh -c "ls -ln '$CRAYDIR' 2>&1 | head -4 | tr '\n' ' '" 2>/dev/null)"
  note "apinfo    : $(srun_t -n1 sh -c "ls -ln '$CRAYDIR'/*/apinfo 2>&1 | head -3 | tr '\n' ' '" 2>/dev/null)"

  try9() { local lbl="$1"; shift
    if out="$("$@" 2>&1)"; then fnd C9 "$lbl" "OK — MPI_Init succeeds"
    else fnd C9 "$lbl" "FAIL [$(why "$out")] $(one_line "$out" | cut -c1-140)"; fi; }

  # (a1) whole mpi_cray_shasta dir bound read-write (coarse, all steps on this node)
  try9 rw_spool_dir srun_t -n1 bwrap "${BWRAP_BASE[@]}" --bind "$SHARED" "$SHARED" \
       --bind "$CRAYDIR" "$CRAYDIR" -- "$SHARED/mpi_hello"

  # (a2) ONLY this step's directory, computed INSIDE the task from SLURM_STEP_ID — the
  # shape the real guard would use (the broker cannot know the step id at submit time).
  try9 rw_this_step_only srun_t -n1 sh -c '
    s="$CRAYDIR/$SLURM_JOB_ID.$SLURM_STEP_ID"
    exec bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --tmpfs /dev/shm \
         --bind "$SHARED" "$SHARED" --bind "$s" "$s" -- "$SHARED/mpi_hello"'

  # (b) a PMI that may not need to write — each with its own uncaged control.
  for m in pmi2 pmix; do
    try9 "uncaged_mpi_$m" ${TMO[@]+"${TMO[@]}"} srun "--mpi=$m" -n1 "$SHARED/mpi_hello"
    try9 "caged_mpi_$m"   ${TMO[@]+"${TMO[@]}"} srun "--mpi=$m" -n1 \
         bwrap "${BWRAP_BASE[@]}" --bind "$SHARED" "$SHARED" -- "$SHARED/mpi_hello"
  done

  # If a fix works at -n1, confirm it still works at -n2 across nodes (the real target).
  try9 rw_this_step_2rank ${TMO[@]+"${TMO[@]}"} srun -n2 sh -c '
    s="$CRAYDIR/$SLURM_JOB_ID.$SLURM_STEP_ID"
    exec bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --tmpfs /dev/shm \
         --unshare-net --bind "$SHARED" "$SHARED" --bind "$s" "$s" -- "$SHARED/mpi_hello"'
else
  fnd C9 fixes "SKIP — needs a working uncaged MPI baseline in a SLURM allocation"
fi

# ============================================================================
head2 "C10 — netns x geometry matrix for the PMI control plane"
# Run 6 fixed the apinfo EROFS (per-step rw bind, or --mpi=pmi2/pmix which need no bind)
# — but its 2-rank arm changed TWO things at once (rank count AND --unshare-net) and
# failed with `_pmi_set_af_in_use: Unable to obtain IP address information`. The task env
# explains why: cray_shasta PMI is TCP (PMI_CONTROL_PORT=29468, SLURM_STEP_RESV_PORTS,
# SLURM_STEP_LAUNCHER_PORT). So the open question is exactly where --unshare-net stops
# being affordable. Vary ONE thing at a time: PMI type x geometry x netns.
# NOTE: needs >=2 tasks per node in the allocation — submit with -N2 --ntasks-per-node=2.
# WHAT THIS MATRIX DOES *NOT* TEST: the shared holder. Every arm here runs a plain
# `bwrap --ro-bind / /`, which gives each rank its OWN user namespace. husk's real rank
# cage instead JOINS a holder's namespace (`--userns <fd>`), because same-node ranks need
# one shared userns for CMA (P1). That is a design gap rather than an unknown — a
# namespace is a kernel object on one machine, so multi-node needs one holder PER NODE,
# and the rank wrapper must find-or-create it. No experiment is needed to know that; what
# needs measuring is only what is below.
# Run 7 corrections, all of them probe bugs in this helper:
#   * every pmix/pmi2 arm died on `bwrap: Can't find source path .../mpi_cray_shasta/<id>`
#     — those PMIs never create the cray_shasta step dir, and `--bind` is fatal on a
#     missing source. Use `--bind-try`.
#   * no arm bound /dev/cxi*, so the 2-node arms had no NIC at all (one segfaulted). The
#     rank cage binds the fabric; the matrix must too, or it tests a cage nobody proposes.
#   * a hung step was reported as an ordinary FAIL. A timeout is a distinct outcome.
# Plus a new axis worth one column: /dev/shm private-per-task (today) vs shared, because
# same-node ranks talk over shared memory and per-task `--tmpfs /dev/shm` cuts that.
if [ -n "${CCX:-}" ] && have srun && [ -n "${SLURM_JOB_ID:-}" ] && [ "${BASE_OK:-0}" = 1 ]; then
  CXI_ARGS="$(cxi_binds)"
  c10() { # $1 label  $2 mpi ("" = site default)  $3 geometry  $4 netns yes/no
          # $5 shm private|shared|jobdir   $6 expected rank count
    local lbl="$1" m="$2" sel="$3" ns="$4" shm="${5:-private}" nr="${6:-1}" mflag=() body rc
    [ -n "$m" ] && mflag=(--mpi="$m")
    body='s="$CRAYDIR/$SLURM_JOB_ID.$SLURM_STEP_ID"; exec bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp'
    case "$shm" in
      shared) body="$body --bind /dev/shm /dev/shm" ;;
      # The proposed design: a per-JOB subdirectory of the node's real /dev/shm, bound
      # onto /dev/shm inside each rank's cage. Ranks of this job share segments; other
      # users' segments stay invisible — unlike a plain --bind of the whole /dev/shm.
      jobdir) body='mkdir -p "/dev/shm/husk-$SLURM_JOB_ID" 2>/dev/null; '"$body"' --bind "/dev/shm/husk-$SLURM_JOB_ID" /dev/shm' ;;
      *)      body="$body --tmpfs /dev/shm" ;;
    esac
    body="$body $CXI_ARGS"
    [ "$ns" = yes ] && body="$body --unshare-net"
    body="$body"' --bind "$SHARED" "$SHARED" --bind-try "$s" "$s" -- "$SHARED/mpi_hello"'
    out="$(${TMO[@]+"${TMO[@]}"} srun ${mflag[@]+"${mflag[@]}"} $sel sh -c "$body" 2>&1)"; rc=$?
    if   [ "$rc" = 124 ] || [ "$rc" = 137 ]; then
      fnd C10 "$lbl" "HANG (killed at the ${WALL}s wall) — no wire-up: $(one_line "$out" | cut -c1-90)"
    elif [ "$rc" != 0 ]; then
      fnd C10 "$lbl" "FAIL rc=$rc [$(why "$out")] $(one_line "$out" | cut -c1-120)"
    elif ranks_ok "$out" "$nr"; then
      fnd C10 "$lbl" "OK — real $nr-rank communicator: $(one_line "$out" | cut -c1-70)"
    else
      fnd C10 "$lbl" "WRONG SIZE (exit 0 but not one $nr-rank job — singleton fallback?): $(one_line "$out" | cut -c1-90)"
    fi
  }
  #    label                    mpi    geometry                       netns  shm      ranks
  c10 cs_1rank_netns            ""     "-N1 -n1"                       yes    private  1
  c10 cs_1node2rank_netns       ""     "-N1 -n2"                       yes    private  2
  c10 cs_1node2rank_netns_shm   ""     "-N1 -n2"                       yes    shared   2
  c10 cs_1node2rank_netns_jobdir ""    "-N1 -n2"                       yes    jobdir   2
  c10 cs_1node2rank_nonet_jobdir ""    "-N1 -n2"                       no     jobdir   2
  c10 cs_2node2rank_nonet       ""     "-N2 -n2 --ntasks-per-node=1"   no     jobdir   2
  c10 cs_2node2rank_netns       ""     "-N2 -n2 --ntasks-per-node=1"   yes    jobdir   2
  # Re-run with the rank assertion: run 8 scored these OK on exit status alone, but they
  # were pairs of singletons. If they stay WRONG SIZE, the pmix/pmi2 route is dead.
  c10 pmix_1node2rank_netns_shm pmix   "-N1 -n2"                       yes    shared   2
  c10 pmix_2node2rank_netns     pmix   "-N2 -n2 --ntasks-per-node=1"   yes    jobdir   2
  c10 pmix_2node2rank_nonet     pmix   "-N2 -n2 --ntasks-per-node=1"   no     jobdir   2
  c10 pmi2_2node2rank_nonet     pmi2   "-N2 -n2 --ntasks-per-node=1"   no     jobdir   2

  # THE REALISTIC SHAPE, and the only arms where intra-node and inter-node have to work at
  # the same time. Every 2-node arm above puts ONE rank on each node, so nothing on a node
  # has a peer: shared memory is never used, CMA is never exercised, and the fabric is the
  # only path. ICON is 2+ ranks per node across several nodes, where a rank talks to its
  # node-mates over /dev/shm and to the far node over the NIC — and the cage must allow
  # both at once. If the matrix disagrees anywhere, it will be here.
  c10 cs_2node4rank_nonet       ""     "-N2 -n4 --ntasks-per-node=2"   no     jobdir   4
  c10 cs_2node4rank_netns       ""     "-N2 -n4 --ntasks-per-node=2"   yes    jobdir   4
  c10 pmix_2node4rank_netns     pmix   "-N2 -n4 --ntasks-per-node=2"   yes    jobdir   4
  # UNCAGED 2-rank pmix control: run 9 showed caged pmix produces singletons with AND
  # without the netns, so the cage is not implicated — but that was never shown directly.
  # Irrelevant on Alps (cray_shasta is the site default and works); it matters at a site
  # where pmix is the only option, so keep the control.
  if out="$(${TMO[@]+"${TMO[@]}"} srun --mpi=pmix -N1 -n2 "$SHARED/mpi_hello" 2>&1)"; then
    ranks_ok "$out" 2 \
      && fnd C10 pmix_2rank_UNCAGED "OK — real 2-rank uncaged, so caged singletons ARE the cage" \
      || fnd C10 pmix_2rank_UNCAGED "WRONG SIZE uncaged too — this MPICH does not speak Slurm pmix; not a cage problem"
  else
    fnd C10 pmix_2rank_UNCAGED "FAIL rc=$? [$(why "$out")] — pmix unusable here regardless of the cage"
  fi
else
  fnd C10 matrix "SKIP — needs a working uncaged MPI baseline in a SLURM allocation"
fi

# ============================================================================
head2 "C11 — is the CAGED job actually on CXI, or silently degraded to TCP?"
# libfabric lists cxi AND tcp providers here. If the cage gets the device binds wrong,
# MPI does not fail — it falls back to the tcp provider and merely runs SLOW. That is a
# containment bug disguised as a working job, so assert the provider rather than assume
# it. (TCP is fine for the PMI bootstrap; it is not fine for the data plane.)
if [ -n "${CCX:-}" ] && have srun && [ -n "${SLURM_JOB_ID:-}" ] && [ "${BASE_OK:-0}" = 1 ]; then
  # Run 7's version was useless twice over: its caged arms lacked the apinfo fix, so they
  # failed for the already-known reason and printed nothing; and the regex guessed at an
  # output format ("provider ofi_rxd" is a provider LIST, not a selection). Fix the cage,
  # then DUMP the verbose lines rather than guessing what shape they take.
  export MPICH_OFI_VERBOSE=1 MPICH_VERSION_DISPLAY=1
  CXI_ARGS="${CXI_ARGS:-$(cxi_binds)}"
  prov() { # $1 label, $2 = cxi bind args ("" = none)
    local lbl="$1" cxi="$2" body rc
    body='s="$CRAYDIR/$SLURM_JOB_ID.$SLURM_STEP_ID"; exec bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --tmpfs /dev/shm '"$cxi"' --bind "$SHARED" "$SHARED" --bind-try "$s" "$s" -- "$SHARED/mpi_hello"'
    out="$(${TMO[@]+"${TMO[@]}"} srun -N2 -n2 --ntasks-per-node=1 sh -c "$body" 2>&1)"; rc=$?
    printf '%s\n' "$out" | grep -iE 'provider|cxi|tcp|ofi' | head -6 \
      | while IFS= read -r l; do note "$lbl: $l"; done
    if   [ "$rc" != 0 ]; then fnd C11 "$lbl" "run FAILED rc=$rc — provider question unanswered"
    elif ! ranks_ok "$out" 2; then fnd C11 "$lbl" "exit 0 but NOT a real 2-rank job — provider question unanswered"
    elif printf '%s' "$out" | grep -qi 'cxi'; then fnd C11 "$lbl" "OK — real 2-rank job, and it names CXI"
    else fnd C11 "$lbl" "real 2-rank job but NO mention of cxi — see the '$lbl:' lines for a tcp fallback"
    fi
  }
  prov with_cxi "$CXI_ARGS"
  prov no_cxi   ""
  note "read as: if 'no_cxi' RUNS FINE, the tcp fallback is real and silent -> the rank"
  note "         cage needs a positive CXI assertion, not merely a device bind."
else
  fnd C11 provider "SKIP — needs a working uncaged MPI baseline in a SLURM allocation"
fi

# ============================================================================
head2 "C12 — does a caged MPI job use AF_UNIX at all, and to reach what?"
# CAGE-PROFILES.md: the single-node profile should carry the login cage's AF_UNIX
# restriction unless the workload genuinely needs unix sockets. Rather than implement the
# filter and then discover what breaks, OBSERVE the known-good caged 2-rank run: every
# AF_UNIX socket() and the sun_path it connects to. Zero hits ⇒ the profile can block
# AF_UNIX for free. Hits ⇒ we get the destination list, and each one is judged on whether
# it is escape surface (MUNGE) or not (nsswitch).
if [ -n "${CCX:-}" ] && have srun && [ -n "${SLURM_JOB_ID:-}" ] && [ "${BASE_OK:-0}" = 1 ]; then
  if have strace; then
    body='s="$CRAYDIR/$SLURM_JOB_ID.$SLURM_STEP_ID"; mkdir -p "/dev/shm/husk-$SLURM_JOB_ID" 2>/dev/null
      exec bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
           --bind "/dev/shm/husk-$SLURM_JOB_ID" /dev/shm '"$CXI_ARGS"' --unshare-net \
           --bind "$SHARED" "$SHARED" --bind-try "$s" "$s" -- \
           strace -f -e trace=socket,connect "$SHARED/mpi_hello"'
    out="$(${TMO[@]+"${TMO[@]}"} srun -N1 -n2 sh -c "$body" 2>&1)"
    au="$(printf '%s\n' "$out" | grep -c 'AF_UNIX' || true)"
    fnd C12 af_unix_calls "$au socket()/connect() call(s) mentioning AF_UNIX in a caged 2-rank run"
    printf '%s\n' "$out" | grep -oE 'sun_path="[^"]*"' | sort -u \
      | while IFS= read -r l; do note "af_unix dest: $l"; done
    if [ "$au" = 0 ]; then
      fnd C12 verdict "NONE — the single-node profile can block AF_UNIX at no functional cost"
    else
      fnd C12 verdict "USED — judge each 'af_unix dest' above: escape surface (munge) or not (nsswitch/sssd)"
    fi
    # Did the run still form a real communicator under strace? If not, the list above is
    # from a broken run and proves nothing.
    ranks_ok "$out" 2 && fnd C12 traced_run "OK — the traced run was a real 2-rank job" \
                      || fnd C12 traced_run "NOT a real 2-rank job — treat the dest list as unreliable"
  else
    fnd C12 af_unix "SKIP — strace not on PATH"
  fi
else
  fnd C12 af_unix "SKIP — needs a working uncaged MPI baseline in a SLURM allocation"
fi

# ============================================================================
head2 "C7 — can the step-broker keep several srun steps in flight?"
# Chapter 1 mediates every srun through ONE step-broker. If concurrent steps serialize,
# the broker must queue them (and a long-running step would block every other request) —
# that is a design constraint on the step-broker's concurrency, so measure it.
if have srun && [ -n "${SLURM_JOB_ID:-}" ]; then
  fnd C7 srun_version "$(srun --version 2>&1 | head -1)"
  for mode in overlap default; do
    case "$mode" in overlap) opt=(--overlap);; *) opt=();; esac
    t0=$SECONDS
    srun ${opt[@]+"${opt[@]}"} -n1 sleep 5 >/dev/null 2>&1 &  p1=$!
    srun ${opt[@]+"${opt[@]}"} -n1 sleep 5 >/dev/null 2>&1 &  p2=$!
    wait "$p1" "$p2"
    el=$(( SECONDS - t0 ))
    if [ "$el" -lt 8 ]; then
      fnd C7 "steps_$mode" "CONCURRENT (${el}s for 2x 5s steps)"
    else
      fnd C7 "steps_$mode" "SERIALIZED (${el}s for 2x 5s steps) — step-broker must queue"
    fi
  done
else
  fnd C7 concurrent_steps "SKIP — not in a SLURM allocation"
fi

# ============================================================================
# C13 — WHICH PMI TRANSPORT IS ACTUALLY IN USE?
#
# This is the question multi-node containment turns on, and we have been answering a
# DIFFERENT one. We recorded "cray_shasta PMI is TCP" from seeing PMI_CONTROL_PORT and
# SLURM_STEP_RESV_PORTS in the environment. But Slurm exports a pile of PMI variables that
# any given plugin may ignore — their PRESENCE is not evidence that they are the transport.
#
# It matters because the three possible answers need three different amounts of work:
#
#   TCP port        the rank must reach an IP inside its netns. Needs a relay, an address
#                   rewrite, and the hope that PMI treats the address as a connect target
#                   rather than as identity. The expensive answer.
#   inherited fd    PMI_FD exists precisely so a launcher can hand a bootstrapped
#                   connection to the process it spawns. husk already passes fds through
#                   bwrap (--userns 9 --pidns 8), so this is nearly free.
#   unix socket     PMIX_SERVER_URI names a FILESYSTEM path, and a filesystem path crosses
#                   a network namespace natively. husk already bind-mounts exactly this
#                   shape for the egress socket. Nothing to solve — the netns was never
#                   the obstacle.
#
# So: dump what a rank actually sees, and look at what the rank actually has OPEN. The
# environment says what was offered; the fd table and the socket list say what was taken.
# Run 2026-08-06 (job 5021103) proved the FIRST version of this arm useless, twice over, and
# both mistakes are worth stating because they are the ones this probe keeps making:
#
#   * it ran `-n1`. A singleton never wires PMI up at all (MPICH goes singleton-init), so it
#     observed a process that had no reason to touch the transport. PMI_SIZE=1 in the output
#     says so plainly.
#   * it dumped `ss` NODE-WIDE. What came back was chronyd, systemd, dbus, sssd and the
#     node's Lustre mounts on port 988 — none of it the rank's. The Process column was empty
#     because ss could not attribute any of it.
#
# The fix for both: run MULTI-RANK ACROSS TWO NODES (the only geometry that fails), and scope
# the socket list to the rank's OWN fds by resolving socket:[inode] against /proc/net/*.
# That is process-scoped by construction and needs no ss attribution.
head2 "C13 — PMI transport: what is offered vs what is actually used"
# TMO is set inside the compile block above, which does not run without a compiler. Without
# this, C13's sruns would be the only UNBOUNDED ones in the probe — and an srun that cannot
# wire up does not fail, it stalls (C10 measured exactly that: HANG killed at the 90s wall).
[ "${#TMO[@]}" -gt 0 ] 2>/dev/null || { TMO=(); have timeout && TMO=(timeout -k 5 60); }
if [ -n "${SLURM_JOB_ID:-}" ] && [ "${SLURM_NNODES:-1}" -ge 2 ]; then
  say "-- PMI/PMIX environment, as rank 0 of a REAL 2-node step sees it --"
  ${TMO[@]+"${TMO[@]}"} srun -N2 -n2 --overlap sh -c '
      [ "${PMI_RANK:-${SLURM_PROCID:-0}}" = 0 ] || exit 0
      env | grep -E "^(PMI|PMIX|SLURM_STEP_RESV_PORTS|SLURM_MPI)" | sort' 2>/dev/null \
    | sed 's/^/   /'
  say ""
  say "-- the sockets THIS RANK holds, resolved from its own fd table --"
  # For each socket:[inode] in our fd table, find that inode in /proc/net/{unix,tcp,tcp6}.
  # A unix hit means the rendezvous is a filesystem path and a netns cannot block it; a tcp
  # hit means it is an address, and then the peer column says who it is talking to.
  ${TMO[@]+"${TMO[@]}"} srun -N2 -n2 --overlap sh -c '
      [ "${PMI_RANK:-${SLURM_PROCID:-0}}" = 0 ] || exit 0
      for fd in /proc/self/fd/*; do
        t=$(readlink "$fd" 2>/dev/null) || continue
        case "$t" in
          socket:\[*\])
            ino=${t#socket:[}; ino=${ino%]}
            if hit=$(grep -w "$ino" /proc/net/unix 2>/dev/null); then
              echo "  fd ${fd##*/}  UNIX   $hit"
            elif hit=$(grep -w "$ino" /proc/net/tcp /proc/net/tcp6 2>/dev/null); then
              echo "  fd ${fd##*/}  TCP    $hit"
            else
              echo "  fd ${fd##*/}  socket inode $ino (not in /proc/net/{unix,tcp,tcp6})"
            fi ;;
          *) echo "  fd ${fd##*/}  $t" ;;
        esac
      done' 2>/dev/null | sed 's/^/   /'
  say ""
  # The verdict is read from the ENV, but only as a hint — the fd table above is the evidence.
  _c13env=$(${TMO[@]+"${TMO[@]}"} srun -N2 -n2 --overlap sh -c \
      '[ "${PMI_RANK:-${SLURM_PROCID:-0}}" = 0 ] && env' 2>/dev/null)
  case "$_c13env" in
    *PMIX_SERVER_URI=*) fnd C13 pmi_transport "PMIX_SERVER_URI is set — a FILESYSTEM rendezvous, which crosses a netns natively. Bind it like the egress socket." ;;
    *PMI_FD=*)          fnd C13 pmi_transport "PMI_FD is set — an INHERITED FD, which survives unshare-net for free." ;;
    *PMI_CONTROL_PORT=*) fnd C13 pmi_transport "PMI_CONTROL_PORT only. Read the fd table above before concluding TCP — the variable being SET is not proof it is used, and run 5021103 showed a rank holding exactly ONE socket." ;;
    *)                  fnd C13 pmi_transport "no PMI_* rendezvous variable found — read the dumps above" ;;
  esac
elif [ -n "${SLURM_JOB_ID:-}" ]; then
  fnd C13 pmi_transport "SKIP — needs -N2. Intra-node PMI wires up through the filesystem (C10: netns_shm and netns_jobdir both OK), so a 1-node run cannot see the transport that fails."
else
  fnd C13 pmi_transport "SKIP — not in a SLURM allocation"
fi

# ============================================================================
# C14 — DAYS OR WEEKS? The peer of the PMI connection decides it.
#
# `_pmi_set_af_in_use: Unable to obtain IP address` does NOT mean the rank has no address.
# Loopback works in there — the egress relay binds 127.0.0.1:3128 inside exactly this
# namespace and `steps.egress` passes on both clusters. It means PMI REJECTED loopback and
# found nothing else, because it wants an address it can ADVERTISE, not one to connect from.
#
# So the cost of multi-node containment turns on who the rank actually talks to:
#
#   peer on the SAME node   ranks only reach their own node's stepd, and the control planes
#                           carry the inter-node traffic themselves. A bind-mounted socket
#                           or a per-node relay is then enough. DAYS.
#   peer on ANOTHER node    ranks connect directly across nodes, so a caged rank needs a
#                           genuinely routable address: veth, bridge, routes. That is real
#                           container networking, which husk has deliberately never needed.
#                           WEEKS.
#
# Measured UNCAGED on purpose: the question is what a WORKING bootstrap does. A failing one
# tells us nothing about the topology it would have used.
head2 "C14 — days or weeks: who is the PMI peer, and will PMI take an address we give it?"
[ "${#TMO[@]}" -gt 0 ] 2>/dev/null || { TMO=(); have timeout && TMO=(timeout -k 5 60); }
if [ -n "${CCX:-}" ] && [ -n "${SLURM_JOB_ID:-}" ] && [ "${SLURM_NNODES:-1}" -ge 2 ]; then
  # The allocation's node addresses, so "same node" is decided by data rather than by eye.
  ${TMO[@]+"${TMO[@]}"} srun -N2 -n2 --overlap sh -c 'echo "$(hostname) $(hostname -i)"' \
    2>/dev/null | sort -u > "$WORK/nodeips"
  say "-- allocation node addresses --"; sed 's/^/   /' "$WORK/nodeips"

  c14="$(HUSK_PROBE_DUMP_SOCKETS=1 ${TMO[@]+"${TMO[@]}"} \
         srun -N2 -n2 "$SHARED/mpi_hello" 2>&1)"
  say ""
  say "-- sockets held by each rank after MPI_Init (uncaged 2-node) --"
  printf '%s\n' "$c14" | grep '^SOCK' | sed 's/^/   /'
  if ! printf '%s\n' "$c14" | grep -q '^SOCK'; then
    fnd C14 pmi_peer "NO SOCKETS reported — either the run failed ($(one_line "$c14" | cut -c1-140)) or this MPI holds no PMI socket past MPI_Init"
  else
    # Classify every tcp peer: is its IP one of THIS rank's own node, or another node's?
    local_hits=0; remote_hits=0; unix_hits=0
    while read -r host peer proto; do
      case "$proto" in
        unix) unix_hits=$((unix_hits+1)); continue ;;
      esac
      ownip="$(awk -v h="$host" '$1==h {print $2}' "$WORK/nodeips" | head -1)"
      case "$peer" in
        "${ownip%%:*}":*|127.0.0.1:*) local_hits=$((local_hits+1)) ;;
        0.0.0.0:*|"") ;;
        *) remote_hits=$((remote_hits+1)) ;;
      esac
    done <<EOF
$(printf '%s\n' "$c14" | sed -n 's/^SOCK .*host=\([^ ]*\).*peer=\([^ ]*\).*proto=\([^ ]*\).*/\1 \2 \3/p'
  printf '%s\n' "$c14" | sed -n 's/^SOCK .*host=\([^ ]*\) .*proto=\([^ ]*\) local=[^ ]* peer=\([^ ]*\).*/\1 \3 \2/p')
EOF
    if [ "$unix_hits" -gt 0 ]; then
      fnd C14 pmi_peer "UNIX socket(s) held — the rendezvous is a filesystem path; a netns never blocked it. HOURS."
    elif [ "$remote_hits" -gt 0 ]; then
      fnd C14 pmi_peer "REMOTE peer(s) ($remote_hits local=$local_hits) — ranks talk ACROSS nodes, so a caged rank needs a routable address. WEEKS."
    elif [ "$local_hits" -gt 0 ]; then
      fnd C14 pmi_peer "LOCAL peers only ($local_hits) — ranks reach their own node's stepd; the control planes carry the rest. A per-node relay or bound socket suffices. DAYS."
    else
      fnd C14 pmi_peer "sockets found but no peer classified — read the SOCK lines above"
    fi
  fi

  # THE CHEAP SHOT. If PMI will accept an address we hand it, the netns needs a dummy
  # address rather than a route, and this becomes hours instead of days. Cray MPICH reads
  # MPICH_INTERFACE_HOSTNAME; if that is enough to get past _pmi_set_af_in_use inside a
  # netns, the whole routing question is moot.
  say ""
  out="$(${TMO[@]+"${TMO[@]}"} srun -N2 -n2 \
         bwrap "${BWRAP_BASE[@]}" ${CXIB[@]+"${CXIB[@]}"} --unshare-net \
               --bind "$SHARED" "$SHARED" -- \
         env MPICH_INTERFACE_HOSTNAME=127.0.0.1 "$SHARED/mpi_hello" 2>&1)"
  case "$out" in
    *"allreduce=1"*) fnd C14 pmi_addr_hint "OK — MPICH_INTERFACE_HOSTNAME got a CAGED 2-node run past the address lookup. HOURS, not days: $(one_line "$out")" ;;
    *_pmi_set_af_in_use*) fnd C14 pmi_addr_hint "no — still 'Unable to obtain IP address' with the hint set; PMI does not take an address it is given here" ;;
    *) fnd C14 pmi_addr_hint "inconclusive [$(why "$out")]: $(one_line "$out" | cut -c1-200)" ;;
  esac
else
  fnd C14 pmi_peer "SKIP — needs a compiler and -N2 (the failing geometry is inter-node only)"
fi

# ============================================================================
head2 "summary — how to read the caged MPI results, and the one thing this can't do"
say "Re-run with -N2 (two nodes) to force the INTER-NODE fabric for C1-def; a single"
say "node may satisfy 2 ranks over shared memory and hide the netns×CXI question."
say ""
say "If a CAGED 2-rank run FAILS, that is itself a DESIGN FINDING, not a probe bug —"
say "note which, they shape the Chapter-2 rank-cage:"
say "  * PMI/PMIx rendezvous — the stepd bootstrap socket may live under /tmp or /var;"
say "    our --tmpfs /tmp hides it, so ranks can't wire up. → the rank-cage must BIND the"
say "    real PMI socket path (find it: look for PMI_*/PMIX_* paths in the C2 env dump)."
say "  * Intra-node shm — per-task bwrap gives each rank its OWN --tmpfs /dev/shm, so"
say "    same-node ranks can't share shm segments. → a same-node rank-cage must SHARE one"
say "    /dev/shm (bind the real one, or one tmpfs across the node's ranks)."
say ""
say "NOT covered here (needs a libfabric test program, not shell): C2 escape — whether"
say "an in-cage process can use an UN-ALLOCATED VNI or reach slurmctld / another job"
say "over the fabric. That is the security of the whole 'checked hole' (AV8 over the"
say "fabric). Scoped as the next follow-up once the facts above are in."
