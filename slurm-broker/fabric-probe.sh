#!/usr/bin/env bash
# fabric-probe.sh — Slingshot/CXI fabric DISCOVERY for the husk srun/MPI phase.
#
# WHAT THIS IS: a fact-gatherer, run by YOU (the trusted operator) on a COMPUTE node,
# to answer the hardware gates in SRUN-MPI-DESIGN.md (C1–C6). It is NOT a containment
# pass/fail suite (that's selftest.sh) — the srun/MPI containment policy doesn't exist
# yet; these are the facts that will inform it. Output is a report; read it back into
# the design doc's "verify-on-hardware" section.
#
# HOW TO RUN — inside your OWN allocation (you have the rights; this bypasses husk):
#     salloc -N1 -n2 -p <partition> [-A <acct>]      # -N2 for a true inter-node fabric test
#     <activate your uenv>                            # so fi_info / cc / MPI are on PATH
#     slurm-broker/fabric-probe.sh
#   or:  sbatch -N1 -n2 -p <partition> slurm-broker/fabric-probe.sh
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
trap 'rm -rf "$WORK"' EXIT

# bwrap profile mirroring the compute cage (root ro + fresh /dev,/proc,/tmp). Callers
# append device binds / --unshare-net as needed. --dev gives a bare devtmpfs, so CXI
# nodes must be re-bound explicitly (that's the whole point of the C1/C4 questions).
BWRAP_BASE=(--ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --tmpfs /dev/shm)
cxi_binds() { local d; for d in /dev/cxi*; do [ -e "$d" ] && printf -- '--dev-bind-try %s %s ' "$d" "$d"; done; }

# ============================================================================
head2 "context"
say "host    : $(hostname)   arch=$(uname -m)   kernel=$(uname -r)"
say "date    : $(date -u +%FT%TZ)"
say "uenv    : ${UENV_VIEW:-<none>}  (label ${UENV_LABEL:-<none>})"
say "in slurm: JOB_ID=${SLURM_JOB_ID:-<none>}  NODES=${SLURM_JOB_NUM_NODES:-?}  NTASKS=${SLURM_NTASKS:-?}"
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
  && fnd C2 vni_env "VNI/Slingshot env present (see above) — record which var carries the VNI list" \
  || fnd C2 vni_env "no VNI/Slingshot env visible (run INSIDE an allocation; -n>=1)"

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
CCX=""; for c in cc mpicc; do have "$c" && { CCX="$c"; break; }; done
if [ -z "$CCX" ]; then
  fnd C5 mpi_build "SKIP — no cc/mpicc on PATH (activate a uenv with an MPI toolchain)"
else
  cat > "$WORK/mpi_hello.c" <<'C'
#include <mpi.h>
#include <stdio.h>
int main(int argc, char** argv){
  int rank=0,size=1; MPI_Init(&argc,&argv);
  MPI_Comm_rank(MPI_COMM_WORLD,&rank); MPI_Comm_size(MPI_COMM_WORLD,&size);
  int sum=0; MPI_Allreduce(&rank,&sum,1,MPI_INT,MPI_SUM,MPI_COMM_WORLD);
  printf("MPI rank %d/%d allreduce=%d\n", rank, size, sum);
  MPI_Finalize(); return 0;
}
C
  if "$CCX" -o "$WORK/mpi_hello" "$WORK/mpi_hello.c" 2>"$WORK/cc.log"; then
    fnd C5 mpi_build "OK ($CCX)"
    # C5 — singleton init, NO launcher (Stage 0 viability):
    if out="$("$WORK/mpi_hello" 2>&1)"; then fnd C5 singleton_init "OK ($out) — Stage 0: ICON-1-rank may run with NO srun in the current cage"
    else fnd C5 singleton_init "FAIL — $out (singleton init unsupported; Stage 1/srun needed)"; fi
    # C6 — does 1 rank need /dev/cxi? run srun -n1 under a cage WITHOUT the device:
    if have srun && [ -n "${SLURM_JOB_ID:-}" ]; then
      if out="$(srun -n1 bwrap "${BWRAP_BASE[@]}" --unshare-net --bind "$WORK" "$WORK" -- "$WORK/mpi_hello" 2>&1)"; then
        fnd C6 rank1_no_cxi "OK ($out) — 1 rank runs WITHOUT /dev/cxi → Stage-1 cage can stay --unshare-net"
      else
        fnd C6 rank1_no_cxi "needs more ($out) — 1-rank MPI_Init touches the NIC; bind /dev/cxi for Stage 1"
      fi
      # C1-def — 2 ranks, definitive: uncaged vs the two cage shapes.
      read -r -a CXIB <<<"$(cxi_binds)"
      run2() { srun -n2 "$@" 2>&1 | tr '\n' ' '; }
      fnd C1 mpi2_uncaged "$(run2 "$WORK/mpi_hello")"
      fnd C1 mpi2_unshare_net_cxi "$(run2 bwrap "${BWRAP_BASE[@]}" "${CXIB[@]}" --unshare-net --bind "$WORK" "$WORK" -- "$WORK/mpi_hello")"
      fnd C1 mpi2_no_unshare_cxi "$(run2 bwrap "${BWRAP_BASE[@]}" "${CXIB[@]}" --bind "$WORK" "$WORK" -- "$WORK/mpi_hello")"
    else
      fnd C6 rank1 "SKIP — not in a SLURM allocation"
    fi
  else
    fnd C5 mpi_build "FAIL to compile — $(tail -1 "$WORK/cc.log" 2>/dev/null)"
  fi
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
