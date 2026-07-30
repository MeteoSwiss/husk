#!/usr/bin/env bash
# cuda-probe.sh — which layer breaks CUDA?  (discovery, not pass/fail)
#
# ICON's ranks died at `cuInit -> 304 CUDA_ERROR_OPERATING_SYSTEM` inside the rank cage
# (Balfrin 2026-07-30). Several layers could cause that and guessing between them has a
# poor record, so this runs the same tiny cuInit program through each layer separately
# and reports which one it stops working in.
#
# HOW TO RUN — ON A COMPUTE NODE, in your own allocation, OUTSIDE husk:
#     salloc -N1 -n1 -p <partition> [-A <acct>] --gres=gpu:1
#     <activate the ICON uenv, so a CUDA toolchain is on PATH>
#     srun -n1 slurm-broker/cuda-probe.sh        # <- note the srun
#
# `salloc` on Alps HOLDS the nodes but leaves your shell on the LOGIN node, which has no
# GPU. Running the probe straight from that shell reports CUDA_ERROR_NO_DEVICE for
# everything and looks like husk broke CUDA. Use `srun` (or `srun --pty bash` first, or
# sbatch) so it actually executes where the GPUs are.
#
# SAFE: compiles one throwaway binary in a tempdir and calls cuInit. Touches nothing else.
set -uo pipefail

say()  { printf '%s\n' "$*"; }
head2(){ printf '\n== %s ==\n' "$*"; }
fnd()  { printf 'FINDING %-22s %s\n' "$1" "${*:2}"; }
have() { command -v "$1" >/dev/null 2>&1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/husk-cuda-probe.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# A GPU must be present or every arm below reports the same meaningless failure
# (cuInit -> 100 CUDA_ERROR_NO_DEVICE) and the report looks like husk broke something.
# Balfrin 2026-07-30: run on a login node by accident, and it happily produced five
# lines of noise. Refuse instead.
if ! ls /dev/nvidia[0-9]* >/dev/null 2>&1; then
  printf '%s\n' \
    "cuda-probe: no /dev/nvidia* on $(hostname) — this shell is not on a GPU node." \
    "  Every check would fail with CUDA_ERROR_NO_DEVICE and tell you nothing about husk." \
    "" \
    "  NOTE: holding an allocation is not the same as running on it. \`salloc\` on Alps" \
    "  leaves your shell on the LOGIN node; the compute nodes are reserved but idle." \
    "  From inside your existing allocation, either of these works:" \
    "    srun -n1 $0" \
    "    srun --pty bash    # then re-run this" \
    "  or submit it: sbatch -n1 --gres=gpu:1 -p <partition> $0" >&2
  exit 2
fi

head2 "context"
say "host : $(hostname)   arch=$(uname -m)"
say "uenv : ${UENV_VIEW:-<none>}"
for t in nvidia-smi nvcc cc bwrap seccomp-wrapper; do
  have "$t" && say "  present: $t ($(command -v "$t"))" || say "  MISSING: $t"
done

# ── the smallest thing that reproduces the failure ────────────────────────────
cat > "$WORK/cuinit.c" <<'C'
#include <stdio.h>
/* Declared by hand so this builds without the CUDA headers being on the include path. */
typedef int CUresult;
extern CUresult cuInit(unsigned int);
extern CUresult cuDeviceGetCount(int *);
int main(void) {
    CUresult r = cuInit(0);
    if (r != 0) { printf("cuInit FAILED rc=%d\n", r); return 1; }
    int n = -1;
    r = cuDeviceGetCount(&n);
    printf("cuInit OK, cuDeviceGetCount rc=%d devices=%d\n", r, n);
    return 0;
}
C

BIN="$WORK/cuinit"
built=""
for cc in nvcc cc gcc; do
  have "$cc" || continue
  if "$cc" -o "$BIN" "$WORK/cuinit.c" -lcuda >"$WORK/cc.log" 2>&1; then built="$cc"; break; fi
done
if [ -z "$built" ]; then
  fnd build "FAILED — could not link against libcuda ($(tail -1 "$WORK/cc.log" 2>/dev/null))"
  say "Load the ICON uenv first; libcuda must be linkable."
  exit 1
fi
fnd build "OK ($built)"

# The cage masks /tmp, so the test binary built there is invisible inside it —
# `bwrap: execvp …/cuinit: No such file or directory`, which looks like a CUDA problem
# and is not. Re-expose just this directory, after the tmpfs so it wins.
BINDW="--bind $WORK $WORK"

run() { # label, command...
  local label="$1"; shift
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if [ "$rc" = 0 ]; then fnd "$label" "OK — $(printf '%s' "$out" | tr '\n' ' ')"
  else fnd "$label" "rc=$rc — $(printf '%s' "$out" | tr '\n' ' ' | head -c 140)"; fi
}

# ── layer by layer, one variable at a time ────────────────────────────────────
head2 "0. sanity: the test binary must be visible INSIDE a cage"
vis=$(bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp $BINDW \
      -- sh -c "[ -x '$BIN' ] && echo yes || echo NO" 2>&1)
fnd binary_in_cage "$vis  (NO means the arms below test nothing)"

head2 "1. no husk at all (the control — if this fails, nothing below means anything)"
run uncaged "$BIN"

head2 "2. seccomp only, no bwrap — isolates the syscall filter from the mount cage"
if have seccomp-wrapper; then
  run seccomp_login       seccomp-wrapper --profile=login "$BIN"
  run seccomp_single_node seccomp-wrapper --profile=single-node "$BIN"
  say "  If login passes and single-node fails, the AF_UNIX block is the cause."
else
  fnd seccomp "SKIP — seccomp-wrapper not on PATH"
fi

# The two cage shapes, built the way husk builds them. Kept literal rather than imported
# so this probe stays runnable from a checkout without the broker.
GPU_BINDS=""
for d in /dev/nvidiactl /dev/nvidia-uvm /dev/nvidia-uvm-tools /dev/nvidia-caps /dev/gdrdrv \
         /dev/nvidia0 /dev/nvidia1 /dev/nvidia2 /dev/nvidia3; do
  [ -e "$d" ] && GPU_BINDS="$GPU_BINDS --dev-bind-try $d $d"
done
CXI_BINDS=""
for d in /dev/cxi[0-9]*; do [ -e "$d" ] && CXI_BINDS="$CXI_BINDS --dev-bind-try $d $d"; done

head2 "3. the JOB cage shape (private /dev/shm, no fabric)"
run job_cage bwrap --ro-bind / / --dev /dev $GPU_BINDS --proc /proc \
    --tmpfs /tmp $BINDW --tmpfs /dev/shm --unshare-net -- "$BIN"

head2 "4. the RANK cage shape (shared per-job /dev/shm, fabric bound)"
_d="/dev/shm/husk-cudaprobe-$$"
mkdir -m 700 "$_d" 2>/dev/null || true
run rank_cage bwrap --ro-bind / / --dev /dev $GPU_BINDS $CXI_BINDS --proc /proc \
    --tmpfs /tmp $BINDW --bind "$_d" /dev/shm --unshare-net -- "$BIN"
rmdir "$_d" 2>/dev/null || true

head2 "5. both layers together, as a real rank runs"
if have seccomp-wrapper; then
  _d="/dev/shm/husk-cudaprobe2-$$"
  mkdir -m 700 "$_d" 2>/dev/null || true
  run full_rank seccomp-wrapper --profile=single-node bwrap --ro-bind / / --dev /dev \
      $GPU_BINDS $CXI_BINDS --proc /proc --tmpfs /tmp $BINDW --bind "$_d" /dev/shm \
      --unshare-net -- "$BIN"
  rmdir "$_d" 2>/dev/null || true
fi

head2 "6. does CUDA need anything the cage hides?"
# Candidates that a container commonly has to carve back in for CUDA.
for p in /proc/driver/nvidia /sys/module/nvidia /sys/class/drm /dev/nvidia-caps \
         /var/run/nvidia-persistenced; do
  if [ -e "$p" ]; then
    inside=$(bwrap --ro-bind / / --dev /dev $GPU_BINDS --proc /proc --tmpfs /tmp \
             $BINDW -- sh -c "[ -e '$p' ] && echo yes || echo NO" 2>/dev/null)
    fnd "path_$(printf '%s' "$p" | tr '/' '_')" "host=yes cage=${inside:-?}"
  fi
done

head2 "reading this"
say "The first arm that fails names the layer:"
say "  1 fails            -> not husk; the node or the toolchain."
say "  2 single-node only -> the AF_UNIX block (profile flag), not the mount cage."
say "  3 fails            -> the base cage hides something CUDA needs (see arm 6);"
say "                        note this shape is ALSO what ordinary brokered jobs use."
say "  4 but not 3        -> something specific to the rank cage: the shared /dev/shm"
say "                        bind or the fabric devices."
say "  5 only             -> the two layers interact."
say ""
say "CUDA_VISIBLE_DEVICES is set PER TASK by SLURM's GRES plugin. husk's step env"
say "forwarding carries the job script's variables into the rank, so if it overrides that"
say "one, every rank would see the wrong device. Worth checking separately:"
say "  srun -n2 sh -c 'echo \$SLURM_PROCID: \$CUDA_VISIBLE_DEVICES'"
