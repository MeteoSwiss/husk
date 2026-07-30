#!/usr/bin/env bash
# build_and_test.sh — build seccomp-wrapper and verify it with the smoke test
#
# Downloads gperf and libseccomp from source, builds them into a temporary
# .build/ directory, compiles seccomp-wrapper, runs the smoke test, then
# removes all build artifacts. The seccomp-wrapper binary is only written to
# this directory if the smoke test passes.
#
# gperf is required by libseccomp's build system and is typically absent on
# HPC login nodes.
#
# Offline / outage fallback: pre-place gperf.tar.gz and libseccomp.tar.gz in
# seccomp-wrapper/.deps/ and the build uses them instead of the network. gperf is fetched
# via ftpmirror.gnu.org (a live-mirror redirector) with ftp.gnu.org as fallback.
#
# Intended for release builds on the target HPC system. For development with
# a system-wide or ~/.local libseccomp, use `make` directly.
#
# Requirements: gcc, wget, make, tar (standard on HPC login nodes)

set -euo pipefail

# --help prints this script's header comment block (single source of truth).
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '1d; /^#/!q; s/^#//; s/^ //; p' "$0"
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/.build"
PREFIX="${BUILD_DIR}/prefix"
# Optional offline cache: drop pre-downloaded tarballs here (named exactly
# gperf.tar.gz / libseccomp.tar.gz) and the build uses them instead of the
# network. Survives the cleanup trap (only .build/ is removed).
DEPS_DIR="${SCRIPT_DIR}/.deps"

GPERF_VERSION="3.1"
# ftpmirror.gnu.org redirects to a live GNU mirror (resilient to ftp.gnu.org
# outages); ftp.gnu.org is kept as an explicit fallback. The checksum below makes
# any mirror safe — wrong bytes abort the build.
GPERF_URL="https://ftpmirror.gnu.org/gperf/gperf-${GPERF_VERSION}.tar.gz"
GPERF_URL_FALLBACK="https://ftp.gnu.org/gnu/gperf/gperf-${GPERF_VERSION}.tar.gz"
# To obtain: wget "$GPERF_URL" && sha256sum gperf-${GPERF_VERSION}.tar.gz
GPERF_SHA256="588546b945bba4b70b6a3a616e80b4ab466e3f33024a352fc2198112cdbb3ae2"

LIBSECCOMP_VERSION="2.5.5"
LIBSECCOMP_URL="https://github.com/seccomp/libseccomp/releases/download/v${LIBSECCOMP_VERSION}/libseccomp-${LIBSECCOMP_VERSION}.tar.gz"
# To obtain: wget "$LIBSECCOMP_URL" && sha256sum libseccomp-${LIBSECCOMP_VERSION}.tar.gz
LIBSECCOMP_SHA256="248a2c8a4d9b9858aa6baf52712c34afefcf9c9e94b76dce02c1c9aa25fb3375"

# ── helpers ───────────────────────────────────────────────────────────────────

log() { echo ""; echo "==> $*"; }
ok()  { printf '  [ok]   %s\n' "$*"; }

verify_checksum() {
    local file="$1" expected="$2" label="$3"
    if [[ -n "${expected}" ]]; then
        echo "${expected}  ${file}" | sha256sum -c - \
            || { echo "  [error] checksum mismatch for ${label} — aborting"; exit 1; }
        ok "checksum verified"
    fi
}

# fetch DEST URL [URL...] — populate DEST from the first working source. Uses a
# pre-staged copy in DEPS_DIR (same basename) first, so a seeded tree builds
# fully offline. If every source fails, prints WHY and how to recover instead of
# letting `set -e` abort into a bare cleanup with no message.
fetch() {
    local dest="$1"; shift
    local name staged url
    name="$(basename "${dest}")"
    staged="${DEPS_DIR}/${name}"

    if [[ -f "${staged}" ]]; then
        cp "${staged}" "${dest}"
        ok "using pre-staged ${name} (${DEPS_DIR}/)"
        return 0
    fi

    for url in "$@"; do
        echo "  fetching ${url}"
        if wget --no-verbose --tries=3 --timeout=30 -O "${dest}" "${url}"; then
            return 0
        fi
        echo "  [warn] failed from ${url}"
        rm -f "${dest}"
    done

    {
        echo "  [error] could not obtain ${name} — every source failed:"
        printf '            %s\n' "$@"
        echo "          Likely the host(s) are down or this machine has no outbound"
        echo "          network (set https_proxy, or check connectivity / DNS)."
        echo "          OFFLINE FIX: download ${name} on a networked machine, then:"
        echo "            mkdir -p ${DEPS_DIR} && cp <downloaded> ${staged}"
        echo "          and re-run — the build uses that copy and skips the network."
    } >&2
    exit 1
}

cleanup() {
    log "Cleaning up build artifacts"
    rm -rf "${BUILD_DIR}"
    rm -f "${SCRIPT_DIR}/test/smoke" \
          "${SCRIPT_DIR}/test/test_ptrace" \
          "${SCRIPT_DIR}/test/test_personality_query" \
          "${SCRIPT_DIR}/test/test_personality_switch" \
          "${SCRIPT_DIR}/test/test_af_unix"
    ok "removed ${BUILD_DIR} and test binaries"
}

trap cleanup EXIT

# ── download ──────────────────────────────────────────────────────────────────

log "Preparing build directory"
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}" "${DEPS_DIR}"

log "Obtaining gperf ${GPERF_VERSION}"
fetch "${BUILD_DIR}/gperf.tar.gz" "${GPERF_URL}" "${GPERF_URL_FALLBACK}"
verify_checksum "${BUILD_DIR}/gperf.tar.gz" "${GPERF_SHA256}" "gperf"

log "Obtaining libseccomp ${LIBSECCOMP_VERSION}"
fetch "${BUILD_DIR}/libseccomp.tar.gz" "${LIBSECCOMP_URL}"
verify_checksum "${BUILD_DIR}/libseccomp.tar.gz" "${LIBSECCOMP_SHA256}" "libseccomp"

# ── build gperf ───────────────────────────────────────────────────────────────

log "Building gperf ${GPERF_VERSION}"
tar xzf "${BUILD_DIR}/gperf.tar.gz" -C "${BUILD_DIR}"
(
    cd "${BUILD_DIR}/gperf-${GPERF_VERSION}"
    ./configure --prefix="${PREFIX}" --quiet
    make -j4 --silent
    make install --silent
)
ok "gperf → ${PREFIX}/bin/gperf"

# ── build libseccomp (static only, no shared library) ────────────────────────
#
# Prepend ${PREFIX}/bin to PATH so libseccomp's build system finds our gperf.

log "Building libseccomp ${LIBSECCOMP_VERSION}"
tar xzf "${BUILD_DIR}/libseccomp.tar.gz" -C "${BUILD_DIR}"
(
    export PATH="${PREFIX}/bin:${PATH}"
    cd "${BUILD_DIR}/libseccomp-${LIBSECCOMP_VERSION}"
    ./configure --prefix="${PREFIX}" --enable-static --disable-shared --quiet
    make -j4 --silent
    make install --silent
)
ok "libseccomp → ${PREFIX}"

# ── compile seccomp-wrapper ───────────────────────────────────────────────────
#
# Build into .build/ first — it is only copied to the final location after the
# smoke test passes, so a test failure leaves no binary behind.
# Link against the local .a archive directly to guarantee we use the freshly
# built static library, not any system or ~/.local copy.

log "Compiling seccomp-wrapper"
gcc -static -O2 -Wall -Wextra -Wpedantic -std=c11 \
    -I"${PREFIX}/include" \
    -o "${BUILD_DIR}/seccomp-wrapper" \
    "${SCRIPT_DIR}/src/seccomp_wrapper.c" \
    "${PREFIX}/lib/libseccomp.a"
ok "seccomp-wrapper (staging in ${BUILD_DIR})"

# ── compile smoke test binaries ───────────────────────────────────────────────
#
# Test binaries do not need libseccomp — delegate to the Makefile so flags
# stay in one place. They are removed by the cleanup trap regardless of outcome.

# Remove any pre-existing test binaries FIRST. `make` treats a binary newer than its
# source as up to date, so a stale one is silently reused — and one built on a different
# machine fails at runtime with `GLIBC_x.yz not found`, which reads as a broken wrapper
# and is not. (Balfrin 2026-07-31: a compiled test binary had been committed by accident,
# so make never rebuilt it, the smoke test failed, and the wrapper was NOT INSTALLED —
# leaving the cluster running the previous build while we debugged the wrong thing.)
# A release build must not depend on what happens to be lying in the tree.
log "Removing any stale test binaries"
make -C "${SCRIPT_DIR}" clean >/dev/null 2>&1 || true
ok "test binaries will be rebuilt from source"

# Delegate to the Makefile: it owns the list of probe binaries and how smoke is
# invoked. WRAPPER points at the freshly STAGED binary rather than a source-tree
# build, which is the only thing this script needs to vary.
log "Running smoke test against the staged binary"
if make -C "${SCRIPT_DIR}" check-tests WRAPPER="${BUILD_DIR}/seccomp-wrapper"; then
    ok "all tests passed"
else
    echo "  [error] smoke test failed — binary not installed"
    exit 1
fi

# ── bwrap compatibility gate ──────────────────────────────────────────────────
#
# The smoke test checks our deny-list behaves, but NOT that bwrap can still set
# up its sandbox UNDER the wrapper. bwrap needs a few syscalls during
# user-namespace setup (notably capset); if the deny-list ever blocks one,
# every sandboxed command dies with SIGSYS — which is exactly how the aarch64
# (Santis) breakage slipped through. This gate catches it per-arch at build
# time, so a wrapper that breaks bwrap is never installed.

log "Verifying bwrap runs under the wrapper"
if command -v bwrap >/dev/null 2>&1; then
    if "${BUILD_DIR}/seccomp-wrapper" bwrap --dev-bind / / true; then
        ok "bwrap sets up its namespace under the wrapper"
    else
        rc=$?
        echo "  [error] bwrap FAILED under the wrapper (exit ${rc})"
        [[ ${rc} -eq 159 ]] && echo "          159 = SIGSYS: the deny-list is blocking a syscall bwrap needs."
        echo "          Find it (run bwrap WITHOUT the wrapper) and exclude it in"
        echo "          src/seccomp_wrapper.c, e.g.:"
        echo "            strace -f -e trace=capset,setuid,setgid,setresuid,setresgid,setreuid,setregid,setfsuid,setfsgid \\"
        echo "              bwrap --dev-bind / / true"
        echo "          Binary NOT installed."
        exit 1
    fi
else
    echo "  [warn] bwrap not found on PATH — cannot verify sandbox setup here."
    echo "         Verify on the target system before relying on this build."
fi

# ── install binary ────────────────────────────────────────────────────────────

log "Installing seccomp-wrapper"
cp "${BUILD_DIR}/seccomp-wrapper" "${SCRIPT_DIR}/seccomp-wrapper"
ok "seccomp-wrapper → ${SCRIPT_DIR}/seccomp-wrapper"

# Also write an arch-tagged copy for multi-arch release packaging.
ARCH="$(uname -m)"
cp "${SCRIPT_DIR}/seccomp-wrapper" "${SCRIPT_DIR}/seccomp-wrapper-${ARCH}"
ok "seccomp-wrapper-${ARCH} → ${SCRIPT_DIR}/seccomp-wrapper-${ARCH}"

# trap EXIT fires here — cleanup() removes .build/ and test binaries
