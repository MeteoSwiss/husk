#!/bin/bash
# hello-gpu.sh — single-node multi-GPU bring-up for the husk SLURM broker.
#
# Proves the compute-side sandbox exposes the GPUs and their NVLink interconnect,
# so a single-process multi-GPU job can run and communicate over NVLink INSIDE the
# cage. Submit it the way the agent would:  sbatch --partition=<site> hello-gpu.sh
#
# The broker forces --partition/--chdir/--output/--error and prepends the
# re-sandbox guard; this body runs inside that cage. If the --dev-bind-try
# /dev/nvidia* carve-outs are missing, nvidia-smi sees nothing here.
#
# NOTE: this is single-PROCESS multi-GPU (NVLink, netns/seccomp-independent) — the
# release-1 target. Multi-RANK launch (srun/mpirun + PMIx/NCCL socket bootstrap)
# hits the AF_UNIX/loopback wall and is a later phase.
#
# No #SBATCH --partition here: the broker forces the site partition (it is
# site-specific), so pinning one would break a direct submit on e.g. Santis.
#SBATCH --nodes=1
#SBATCH --gpus-per-node=4        # adjust to your site if needed (e.g. --gres=gpu:4)
#SBATCH --time=00:05:00
#SBATCH --job-name=husk-gpu
set -u

echo "host : $(hostname)"

echo "--- GPU visibility (device carve-outs must reach INTO the cage) ---"
if ! command -v nvidia-smi >/dev/null 2>&1; then
  echo "gpu  : nvidia-smi NOT FOUND — driver/tools not visible in the sandbox"
  exit 1
fi
ngpu="$(nvidia-smi -L | grep -c '^GPU')"
echo "gpu  : nvidia-smi sees ${ngpu} GPU(s)"
nvidia-smi -L | sed 's/^/       /'
if [ "${ngpu}" -lt 1 ]; then
  echo "gpu  : no GPUs visible — check the --dev-bind-try /dev/nvidia* carve-outs"
  exit 1
fi

echo "--- NVLink status (direct driver query — the reliable check) ---"
# NOTE: prefer `nvidia-smi nvlink -s` over `topo -m`: topo -m reports GPU<->NIC
# affinity and tends to render EMPTY under --unshare-net (no NICs in the netns),
# while nvlink -s reads link state straight from the driver we've bound.
nvlink="$(nvidia-smi nvlink -s 2>&1 || true)"
printf '%s\n' "$nvlink" | sed 's/^/       /'
if printf '%s\n' "$nvlink" | grep -qiE 'GB/s|Active'; then
  echo "nvlink: active NVLink(s) reported [expect]"
else
  echo "nvlink: no active NVLink reported — see output above; a real P2P test is definitive"
fi
echo "--- topo matrix (may be empty under --unshare-net; error shown, not hidden) ---"
nvidia-smi topo -m 2>&1 | sed 's/^/       /'

echo "--- real P2P collective, if a test tool is installed ---"
if command -v all_reduce_perf >/dev/null 2>&1; then
  all_reduce_perf -b 8 -e 128M -f 2 -g "${ngpu}"      # nccl-tests, one process, NVLink
elif command -v p2pBandwidthLatencyTest >/dev/null 2>&1; then
  p2pBandwidthLatencyTest
else
  echo "       (no nccl-tests / cuda-samples on PATH — detection only; for a real"
  echo "        all-reduce, build nccl-tests and run: all_reduce_perf -g ${ngpu})"
fi

echo "--- containment (this is still a caged job) ---"
if timeout 5 bash -c ': < /dev/tcp/1.1.1.1/443' 2>/dev/null; then
  echo "net  : EXTERNAL REACHABLE — NOT sandboxed!"
else
  echo "net  : external blocked [expect]"
fi
n=$(ls -A /users 2>/dev/null | wc -l)
if ls "$HOME/.ssh" >/dev/null 2>&1; then
  echo "fs   : \$HOME/.ssh READABLE — NOT sandboxed!"
elif [ "$n" -gt 2 ]; then
  echo "fs   : /users shows $n entries — homes visible, NOT sandboxed"
else
  echo "fs   : homes hidden (/users has $n entries) [expect]"
fi

echo "done."
