#!/usr/bin/env bash
# make-release.sh — package a release tarball
#
# Run this from the repo root on a tagged commit after building
# seccomp-wrapper on BOTH architectures with claude-safe/build_and_test.sh:
#
#   On Balfrin (x86_64):
#     cd claude-safe && ./build_and_test.sh
#
#   On Santis (aarch64):
#     cd claude-safe && ./build_and_test.sh
#     scp claude-safe/seccomp-wrapper-aarch64 balfrin:<path-to-repo>/claude-safe/
#
# Both arch-tagged binaries (seccomp-wrapper-x86_64, seccomp-wrapper-aarch64)
# must be present in claude-safe/ before running this script.
#
# Output: claude-safe-<version>.tar.gz and claude-safe-<version>.SHA256SUMS

set -euo pipefail

# --help prints this script's header comment block (single source of truth).
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '1d; /^#/!q; s/^#//; s/^ //; p' "$0"
  exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_X86_64="${REPO_ROOT}/claude-safe/seccomp-wrapper-x86_64"
BINARY_AARCH64="${REPO_ROOT}/claude-safe/seccomp-wrapper-aarch64"
CURRENT_ARCH="$(uname -m)"

# ── version ───────────────────────────────────────────────────────────────────

VERSION="${1:-}"
if [[ -z "${VERSION}" ]]; then
    VERSION="$(git -C "${REPO_ROOT}" describe --tags --exact-match 2>/dev/null)" || {
        echo "error: not on an exact git tag and no version argument given."
        echo "       Tag the commit first (e.g. git tag v0.1) or pass the"
        echo "       version explicitly: ./make-release.sh v0.1"
        exit 1
    }
fi

if [[ ! "${VERSION}" =~ ^v[0-9]+\.[0-9]+([.][0-9]+)?(-[A-Za-z0-9._-]+)?$ ]]; then
    echo "error: version '${VERSION}' does not match expected format v<major>.<minor>[.<patch>][-<suffix>]"
    echo "       examples: v0.1  v1.2  v0.1.3  v0.1-bugfix3"
    exit 1
fi

ARCHIVE="${REPO_ROOT}/claude-safe-${VERSION}.tar.gz"
PREFIX="claude-safe-${VERSION}"
STAGING="$(mktemp -d)"
trap 'rm -rf "${STAGING}"' EXIT

# ── preflight ─────────────────────────────────────────────────────────────────

# Verify the entire claude-safe/ tree is clean so tarball source matches binaries.
if ! git -C "${REPO_ROOT}" diff --quiet HEAD -- claude-safe/; then
    echo "error: claude-safe/ has uncommitted changes."
    echo "       The binaries may not match the source shipped in the tarball."
    echo "       Commit the changes or rebuild with build_and_test.sh first."
    exit 1
fi

if [[ ! -x "${BINARY_X86_64}" ]]; then
    echo "error: claude-safe/seccomp-wrapper-x86_64 not found."
    echo "       Build it on Balfrin: cd claude-safe && ./build_and_test.sh"
    exit 1
fi

if [[ ! -x "${BINARY_AARCH64}" ]]; then
    echo "error: claude-safe/seccomp-wrapper-aarch64 not found."
    echo "       Build it on Santis: cd claude-safe && ./build_and_test.sh"
    exit 1
fi

# Sanity-check only the binary for the current arch — the other was validated
# by build_and_test.sh on its native machine.
CURRENT_BINARY="${REPO_ROOT}/claude-safe/seccomp-wrapper-${CURRENT_ARCH}"
if [[ ! -x "${CURRENT_BINARY}" ]]; then
    echo "error: no binary for current arch (${CURRENT_ARCH}) — cannot sanity check"
    exit 1
fi

echo "==> Sanity check (${CURRENT_ARCH})"
if ! "${CURRENT_BINARY}" echo ok > /dev/null 2>&1; then
    echo "error: seccomp-wrapper-${CURRENT_ARCH} failed to exec 'echo ok' —"
    echo "       binary may be corrupt or built for a different kernel."
    exit 1
fi
echo "  [ok]   seccomp-wrapper-${CURRENT_ARCH} functional on this kernel"

# ── assemble ──────────────────────────────────────────────────────────────────

echo "==> Assembling ${PREFIX}"

# Export tracked files from git into staging area.
git -C "${REPO_ROOT}" archive --prefix="${PREFIX}/" HEAD \
    | tar xf - -C "${STAGING}"

# Add compiled binaries (not tracked by git).
cp "${BINARY_X86_64}"  "${STAGING}/${PREFIX}/claude-safe/seccomp-wrapper-x86_64"
cp "${BINARY_AARCH64}" "${STAGING}/${PREFIX}/claude-safe/seccomp-wrapper-aarch64"

echo "  [ok]   source + x86_64 binary + aarch64 binary"

# ── pack ──────────────────────────────────────────────────────────────────────
#
# Reproducible tarball: two runs from identical inputs must produce an identical
# SHA256. --sort=name fixes file ordering, --owner/group/mtime strip host
# identity, and gzip -n omits the filename+timestamp from the gzip header.
# tar -z does not pass -n through to gzip, so we pipe explicitly.
# Note: --sort=name is GNU tar only; make-release.sh is Balfrin (Linux) only.

echo "==> Creating ${ARCHIVE}"
tar --sort=name \
    --owner=0 --group=0 --numeric-owner \
    --mtime='@0' \
    -cf - -C "${STAGING}" "${PREFIX}" | gzip -n > "${ARCHIVE}"
echo "  [ok]   $(du -sh "${ARCHIVE}" | cut -f1)  ${ARCHIVE}"

# ── checksums ─────────────────────────────────────────────────────────────────

CHECKSUMS="${REPO_ROOT}/claude-safe-${VERSION}.SHA256SUMS"
(cd "${REPO_ROOT}" && sha256sum "claude-safe-${VERSION}.tar.gz") > "${CHECKSUMS}"
echo "  [ok]   ${CHECKSUMS}"
