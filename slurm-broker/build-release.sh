#!/usr/bin/env bash
# build-release.sh — compile the SLURM broker binaries for THIS machine's arch.
#
# Produces arch-suffixed binaries that make-release.sh bundles and the installer
# installs, mirroring seccomp-wrapper/seccomp-wrapper-<arch>:
#
#   slurm-broker/husk-slurm-broker-<arch>
#   slurm-broker/husk-slurm-wrapper-<arch>
#
# Release flow (prebuilt-per-arch, like seccomp-wrapper): run this on EACH arch
# (Santis aarch64, Balfrin x86_64), scp the foreign-arch binaries onto the
# release machine, then run make-release.sh there. Releases ship these compiled
# binaries — the cluster never builds from source and vendor/ is never shipped.
#
# Builds offline from slurm-broker/vendor/ if present (a dev machine that ran
# `cargo vendor ../vendor > broker/.cargo/config.toml`); otherwise builds online
# from the committed Cargo.lock (cargo fetches crates once — needs network).
#
# Usage:  ./build-release.sh
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '1d; /^#/!q; s/^#//; s/^ //; p' "$0"
  exit 0
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BROKER="${HERE}/broker"
ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64|aarch64) ;;
  *) echo "error: unsupported arch '${ARCH}' (expected x86_64 or aarch64)" >&2; exit 1 ;;
esac

OFFLINE=()
if [[ -d "${HERE}/vendor" && -f "${BROKER}/.cargo/config.toml" ]]; then
  OFFLINE=(--offline)
  echo "==> vendored crates present — building offline"
else
  echo "==> no vendor/ — building online (cargo fetches crates per Cargo.lock)"
fi

echo "==> cargo build --release --locked ${OFFLINE[*]} (${ARCH})"
( cd "${BROKER}" && cargo build --release --locked "${OFFLINE[@]}" )

for bin in husk-slurm-broker husk-slurm-wrapper; do
  src="${BROKER}/target/release/${bin}"
  if [[ ! -x "${src}" ]]; then
    echo "error: ${src} was not produced by the build" >&2
    exit 1
  fi
  install -m 0755 "${src}" "${HERE}/${bin}-${ARCH}"
  echo "  [ok]   ${bin}-${ARCH}"
done

echo "==> done. scp the foreign-arch binaries to the release machine, then make-release.sh"
