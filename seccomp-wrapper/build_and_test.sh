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
    # Delegate to the Makefile, which owns the list of probe binaries — this script
    # used to keep its own copy, and a copy that drifts is exactly what blocked a
    # Balfrin install once already. clean-tests deliberately spares the staged
    # wrapper binary this script leaves in SCRIPT_DIR.
    make -C "${SCRIPT_DIR}" clean-tests >/dev/null 2>&1 || true
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
#
# The previous run's STAGED wrapper goes too, and that is B6-7 rather than tidiness. This
# line used to be `make clean`, which removes `seccomp-wrapper` and SPARES
# `seccomp-wrapper-$(uname -m)` — the only file install-husk.sh reads. A build that got
# this far and then failed a gate therefore left the tree holding the PREVIOUS build's
# arch-tagged binary, and the installer answered `skip seccomp-wrapper already up to date
# — nothing to do`. Failed build → install → "success", with the cluster still running the
# old wrapper: the identical failure this script's own closing message warns about, only
# manufactured by the script instead of by forgetting to run the installer.
#
# This is the right moment for it. The fresh binary already exists in .build/, so nothing
# is lost if a gate below fails, and from here on the invariant is: the arch-tagged binary
# in this tree is the one THIS run produced, or there is none.
#
# The Makefile owns both lists (clean-tests, clean-staged) so this script keeps no copy.
log "Removing stale test binaries and the previous staged wrapper"
make -C "${SCRIPT_DIR}" clean-tests >/dev/null 2>&1 || true
make -C "${SCRIPT_DIR}" clean-staged >/dev/null
# P7: do not take the command's word for it — check the effect. If a stale binary survives
# (read-only file, wrong ARCH, someone editing the Makefile) the whole point is lost, and
# the way that failure shows up is an installer reporting success months later.
ARCH="$(uname -m)"
for stale in "${SCRIPT_DIR}/seccomp-wrapper" "${SCRIPT_DIR}/seccomp-wrapper-${ARCH}"; do
    if [[ -e "${stale}" ]]; then
        echo "  [error] could not remove the previous build's ${stale}."
        echo "          Leaving it would let install-husk.sh deploy it as if it were new"
        echo "          (its hash check would say 'already up to date'). Remove it by hand"
        echo "          and re-run. Aborting."
        exit 1
    fi
done
ok "test binaries will be rebuilt from source; no stale wrapper left for ${ARCH}"

# Delegate to the Makefile: it owns the list of probe binaries and how smoke is
# invoked. WRAPPER points at the freshly STAGED binary rather than a source-tree
# build, which is the only thing this script needs to vary.
log "Running smoke test against the staged binary"
SMOKE_LOG="${BUILD_DIR}/smoke.out"
smoke_rc=0
make -C "${SCRIPT_DIR}" check-tests WRAPPER="${BUILD_DIR}/seccomp-wrapper" \
    2>&1 | tee "${SMOKE_LOG}" || smoke_rc=$?

if [[ ${smoke_rc} -ne 0 ]]; then
    echo "  [error] smoke test failed — binary not installed"
    exit 1
fi

# ── the SKIP gate (B6-4) ──────────────────────────────────────────────────────
#
# `make`'s exit status is smoke.c's `return failed ? 1 : 0`. A SKIP exits 0, so until now a
# run that reported `0 failed, 2 skipped` printed "all tests passed" and staged the binary.
# smoke.c has emitted a machine-greppable summary line since it was written, with a comment
# saying it exists BECAUSE this script cannot see the per-test lines — and nothing here ever
# read it. CLUSTER-TEST-PLAN.md:136 already requires `summary: 0 failed, 0 skipped`, so the
# requirement was written down twice and enforced by a human reading scrollback (`P7`, `P8`).
#
# WHAT A SKIP MEANS HERE, decided rather than inherited: **a skip fails this gate.**
#
# The tempting alternative is "a skip on a legitimately-absent feature is fine, a skip
# because the probe could not run is not" — and it is not available to us, because the
# probes cannot tell those apart. Test 11 skips on ENOSYS from io_uring_setup and prints
# "kernel has no io_uring"; B6-5 measured that exact line on a 6.8 kernel where io_uring
# works fine, the ENOSYS having come from an ENCLOSING filter. Run this script inside a husk
# session, or from a brokered job, and the vendored apply-seccomp filter produces `0 failed,
# 2 skipped` — the graceful-errno contract and the core-dump bound, the two most recently
# argued controls in the file, never executed, and the operator told the tests passed. A
# gate cannot accept a class of outcome its instrument cannot identify (`P11`).
#
# So the release build requires zero skips, and an operator who has a real reason to accept
# one must NAME it: HUSK_ALLOW_SKIPPED_TESTS="11 13". That keeps the authorisation specific
# (never blanket), puts it in the release log where it can be reviewed, and makes a NEW
# skip — a probe added later, or an old one that started skipping — fail even on a machine
# where an old skip was already accepted.
summary_line="$(grep -E '^summary: [0-9]+ failed, [0-9]+ skipped$' "${SMOKE_LOG}" | tail -1 || true)"
if [[ -z "${summary_line}" ]]; then
    echo "  [error] the smoke suite exited 0 but printed no 'summary: N failed, M skipped'"
    echo "          line. This gate reads that line to see SKIPs, which the exit status"
    echo "          cannot show — so with the line missing it can see nothing, and a build"
    echo "          it cannot inspect is not a build it can pass. Either the suite died"
    echo "          early or smoke.c stopped emitting the line; check ${SMOKE_LOG}."
    exit 1
fi
smoke_failed="$(sed -E 's/^summary: ([0-9]+) failed.*/\1/' <<<"${summary_line}")"
smoke_skipped="$(sed -E 's/.* ([0-9]+) skipped$/\1/' <<<"${summary_line}")"

# The per-test SKIP lines and the summary count are two statements of one fact; make one
# assert the other (`P8`), or a miscount hides a skip from the list below.
mapfile -t skipped_ids < <(sed -nE 's/^test ([0-9]+):.*SKIP.*/\1/p' "${SMOKE_LOG}")
if [[ ${smoke_skipped} -ne ${#skipped_ids[@]} ]]; then
    echo "  [error] the suite says ${smoke_skipped} skipped but printed ${#skipped_ids[@]}"
    echo "          per-test SKIP lines. The summary line and the test lines disagree, so"
    echo "          neither can be trusted to say which control ran. See ${SMOKE_LOG}."
    exit 1
fi

# Belt and braces: `make` should already have caught this, but if the two ever disagree the
# summary line is the one that names the number.
if [[ ${smoke_failed} -ne 0 ]]; then
    echo "  [error] ${summary_line} — binary not installed"
    exit 1
fi

# `set -u` is on, so the default must come first: an unset override is the normal case.
allowed_skips="${HUSK_ALLOW_SKIPPED_TESTS:-}"
allowed_skips=" ${allowed_skips//,/ } "
unauthorised=()
for id in "${skipped_ids[@]}"; do
    [[ "${allowed_skips}" == *" ${id} "* ]] || unauthorised+=("${id}")
done

if (( ${#unauthorised[@]} > 0 )); then
    echo "  [error] ${summary_line} — binary NOT installed."
    echo "          A skip is not a pass: the control that test covers did not run here, and"
    echo "          the probe cannot tell 'this kernel lacks the feature' from 'something"
    echo "          already blocks it' (B6-5). Unauthorised skips: ${unauthorised[*]}"
    grep -E '^test [0-9]+:.*SKIP' "${SMOKE_LOG}" | sed 's/^/            /'
    echo "          Most common cause: this script is running INSIDE a sandbox (a husk"
    echo "          session, or a brokered job). Build on a bare login node."
    echo "          If a skip is genuinely correct for this machine, authorise it BY NUMBER"
    echo "          and re-run, so the acceptance is on the record:"
    echo "            HUSK_ALLOW_SKIPPED_TESTS=\"${unauthorised[*]}\" $0"
    exit 1
fi

if (( ${#skipped_ids[@]} > 0 )); then
    ok "all tests passed (${summary_line}; skips ${skipped_ids[*]} authorised via HUSK_ALLOW_SKIPPED_TESTS)"
else
    ok "all tests passed (${summary_line})"
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
elif [[ "${HUSK_ALLOW_NO_BWRAP:-}" == "1" ]]; then
    # Decide, THEN speak. The first version printed the whole [error] block — ending in
    # "Binary NOT installed." and an instruction to set the variable the operator had
    # already set — and only then tested it, so an authorised build logged a refusal and
    # then installed the binary (`RB-5`). The SKIP gate above gets this right, so the file
    # disagreed with itself and the new half was the wrong one. A transcript whose text
    # contradicts its exit status is no longer evidence about the build — and the reader
    # acts on the text, which is `P11`. (Cited `P13` until `RB2-5`; `P13` is husk narrating
    # to the confined agent, and a build script has no confined party.)
    echo "  [warn] bwrap not found on PATH, and HUSK_ALLOW_NO_BWRAP=1 — continuing"
    echo "         UNVERIFIED. The one check that catches a deny-list entry bwrap needs"
    echo "         (SIGSYS on every sandboxed command, which is how the aarch64 breakage"
    echo "         shipped) has NOT run. Do not release this build without running"
    echo "         build_and_test.sh on a host that has bwrap."
else
    # Same shape as B6-4 and the same answer. This gate exists BECAUSE the aarch64 capset
    # breakage slipped through; degrading it to a warning means a build on a host without
    # bwrap is packaged by make-release.sh with the one check that would have caught that
    # class never run, and "verify on the target system" is an instruction to a human in
    # scrollback, which is what `P7` says is already a failure. Refuse, and make the
    # exception explicit and recorded.
    echo "  [error] bwrap not found on PATH — cannot verify that the sandbox still comes up"
    echo "          under this wrapper. That check is not optional: it is the one that"
    echo "          catches a deny-list entry bwrap needs (SIGSYS on every sandboxed"
    echo "          command), which is exactly how the aarch64 breakage shipped."
    echo "          Build on the target system, or — if you know this binary will never be"
    echo "          released from here — record the exception explicitly:"
    echo "            HUSK_ALLOW_NO_BWRAP=1 $0"
    echo "          Binary NOT installed."
    exit 1
fi

# ── install binary ────────────────────────────────────────────────────────────

log "Staging seccomp-wrapper into the source tree (NOT deployed yet)"
cp "${BUILD_DIR}/seccomp-wrapper" "${SCRIPT_DIR}/seccomp-wrapper"
ok "seccomp-wrapper → ${SCRIPT_DIR}/seccomp-wrapper"

# Also write an arch-tagged copy for multi-arch release packaging. ARCH was computed above,
# where the previous build's copy of this same name was removed.
cp "${SCRIPT_DIR}/seccomp-wrapper" "${SCRIPT_DIR}/seccomp-wrapper-${ARCH}"
ok "seccomp-wrapper-${ARCH} → ${SCRIPT_DIR}/seccomp-wrapper-${ARCH}"

printf '\n'
printf '%s\n' \
  "NOT YET DEPLOYED. This only refreshed the binaries in the source tree." \
  "To put them where husk actually runs from:" \
  "    ./install-husk.sh" \
  "which copies the wrapper to ~/.local/bin and checks it understands --profile." \
  "Skipping that step leaves the cluster running the PREVIOUS build, which is" \
  "indistinguishable from a code change having no effect (Balfrin, 2026-07-30)."

# trap EXIT fires here — cleanup() removes .build/ and test binaries
