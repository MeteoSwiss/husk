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
# Intended for release builds on the target HPC system. For development with
# a system-wide or ~/.local libseccomp, use `make` directly.
#
# Requirements: gcc, wget, make, tar (standard on HPC login nodes)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/.build"
PREFIX="${BUILD_DIR}/prefix"

GPERF_VERSION="3.1"
GPERF_URL="https://ftp.gnu.org/gnu/gperf/gperf-${GPERF_VERSION}.tar.gz"
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

cleanup() {
    log "Cleaning up build artifacts"
    rm -rf "${BUILD_DIR}"
    rm -f "${SCRIPT_DIR}/test/smoke" \
          "${SCRIPT_DIR}/test/test_ptrace" \
          "${SCRIPT_DIR}/test/test_personality_query" \
          "${SCRIPT_DIR}/test/test_personality_switch"
    ok "removed ${BUILD_DIR} and test binaries"
}

trap cleanup EXIT

# ── download ──────────────────────────────────────────────────────────────────

log "Preparing build directory"
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

log "Downloading gperf ${GPERF_VERSION}"
wget -q --tries=3 --timeout=30 -O "${BUILD_DIR}/gperf.tar.gz" "${GPERF_URL}"
verify_checksum "${BUILD_DIR}/gperf.tar.gz" "${GPERF_SHA256}" "gperf"
ok "gperf-${GPERF_VERSION}.tar.gz"

log "Downloading libseccomp ${LIBSECCOMP_VERSION}"
wget -q --tries=3 --timeout=30 -O "${BUILD_DIR}/libseccomp.tar.gz" "${LIBSECCOMP_URL}"
verify_checksum "${BUILD_DIR}/libseccomp.tar.gz" "${LIBSECCOMP_SHA256}" "libseccomp"
ok "libseccomp-${LIBSECCOMP_VERSION}.tar.gz"

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

log "Compiling smoke test binaries"
make -C "${SCRIPT_DIR}" test/smoke test/test_ptrace test/test_personality_query test/test_personality_switch
ok "test/smoke, test/test_ptrace, test/test_personality_query, test/test_personality_switch"

# ── run smoke test ────────────────────────────────────────────────────────────

log "Running smoke test"
if "${SCRIPT_DIR}/test/smoke" \
       "${BUILD_DIR}/seccomp-wrapper" \
       "${SCRIPT_DIR}/test/test_ptrace" \
       "${SCRIPT_DIR}/test/test_personality_query" \
       "${SCRIPT_DIR}/test/test_personality_switch"; then
    ok "all tests passed"
else
    echo "  [error] smoke test failed — binary not installed"
    exit 1
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
