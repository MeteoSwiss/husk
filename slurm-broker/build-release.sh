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
# Build ORDER does not matter, and neither does which tags a build machine has
# fetched: every broker binary records the COMMIT it was built from, and that is
# what make-release.sh matches (`RB-3`). What must match is the commit — build
# both arches from the same one, and commit before building, because a binary
# built from a dirty tree is stamped `-dirty` and the release gate refuses it.
#
# ACCEPTED RESIDUAL, stated so it is not rediscovered as a finding (`RB2-7`, `P12`):
# a dirty build CAN claim a clean commit. `git update-index --assume-unchanged <file>`
# (and --skip-worktree, which some editors and sync tools set) makes git's index lie
# about that file, and every gate in this chain asks the same index — the stamp's
# --dirty marker, make-release.sh's dirty check, its require_committed, and its
# untracked-source check. All four then pass, and `git archive` ships the COMMITTED
# source: a tarball whose own source cannot rebuild its own binaries, with [ok] on
# every preflight line. This is not a regression and it is not an agent-reachable
# path — it needs a shell on the release machine, which is the operator's, and the
# operator is who the gate is protecting from their own memory. It is in scope for
# the person who runs a release and out of scope for husk's threat model, so it is
# recorded here rather than defended against. `git update-index --no-assume-unchanged`
# on everything under slurm-broker/ is the one-line answer if it is ever suspected.
#
# Builds offline from slurm-broker/vendor/ if present (a dev machine that ran
# `cargo vendor ../vendor > broker/.cargo/config.toml`); otherwise builds online
# from the committed Cargo.lock (cargo fetches crates once — needs network).
#
# Usage:  ./build-release.sh              build (tests first), then stage the binaries
#         ./build-release.sh --test-only  run the crate's tests and stop
#
# --test-only exists so make-release.sh can run the Rust gate without a second copy of
# the offline/online decision below (`P8`). ~8s.
#
# No uenv, no modules, no network beyond cargo's crate fetch: this must run on a bare
# login node before anything else is loaded.
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '1d; /^#/!q; s/^#//; s/^ //; p' "$0"
  exit 0
fi

TEST_ONLY=0
[[ "${1:-}" == "--test-only" ]] && TEST_ONLY=1

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

# ── clear the staged binaries, BEFORE the gate ────────────────────────────────
#
# The rule is "a failed gate must leave no binary to install". Until `RB-1` this script
# only ASSERTED it, three lines below, and measured: break a crate test, run this script,
# get exit 101 — and both stale broker binaries were still sitting here, installable.
#
# install-husk.sh reads FOUR things out of a checkout, and a build that fails must leave
# none of them stale. The commit that added `make clean-staged` called the first of them
# "the only file install-husk.sh reads"; it is not, and the two it missed are the worse
# half:
#
#   install-husk.sh:320  seccomp-wrapper/seccomp-wrapper-<arch>   covered — `make
#                        clean-staged`, called and then VERIFIED by build_and_test.sh
#   install-husk.sh:557  slurm-broker/husk-slurm-broker-<arch>    covered HERE (was: nothing)
#   install-husk.sh:558  slurm-broker/husk-slurm-wrapper-<arch>   covered HERE (was: nothing)
#   install-husk.sh:690  skill/SKILL.md                           tracked, and the crate
#                        test `the_shipped_skill_matches_the_generated_option_contract`
#                        — run by the gate below — goes red if it drifts from the registry
#
# Why the broker pair is worse than the case `B6-7` described: the C wrapper at least gets
# a sha256 comparison at install-husk.sh:332, so a stale one is deployed under "already up
# to date". The broker pair gets `[[ -x ]]`, an unconditional `install`, and
# `ok "SLURM brokering → husk (… installed …)"`. Failed build → install → success, while
# the cluster runs the previous broker: the Balfrin 2026-08-05 failure the build stamp was
# invented to make visible, reached through the deploy path instead of the session path.
#
# The trade this makes, stated CORRECTLY this time. A build that fails now leaves this
# machine with no broker binary at all, where before it kept the previous one. That is
# still the intended direction — a stale binary installed under an [ok] is the failure this
# whole gate exists to prevent — but the first version of this comment justified it with a
# sentence that was false in both halves, and it is worth recording why, because the false
# sentence is what let the consequence go unhandled for a release (`RB2-2`, measured):
#
#   "no binary fails loudly at the next install ... the same trade build_and_test.sh makes"
#
#   install-husk.sh, seccomp-wrapper missing  ->  [error] ... ; exit 1     LOUD
#   install-husk.sh, broker pair missing      ->  skip "SLURM brokering not installed"
#                                             ->  the install CONTINUES and exits 0
#
# So it was NOT the same trade, and "no binary" did NOT fail loudly. The reachable sequence
# is the operator's ordinary upgrade: build-release.sh fails, ./install-husk.sh --uninstall,
# ./install-husk.sh — and the second one reports success while leaving a husk that cannot
# start, because the launcher it writes refuses to run without husk-slurm-wrapper. Without
# the uninstall it is worse: the PREVIOUS broker and wrapper stay in ~/.local/bin, husk
# keeps using them, and the transcript says "not installed".
#
# That half is fixed where it lives, in install-husk.sh, which now refuses to report a
# successful install it cannot back (`P7`: a control that declines to apply must say so to
# someone who can act). This comment no longer claims a property of a file it does not own.
#
# NOT on --test-only: that path builds nothing, and make-release.sh calls it from a
# preflight that is about to check the very binaries this would delete.
#
# `P7`: check the effect, do not take `rm`'s word for it. A survivor (read-only file, a
# directory under the name) means the invariant is gone, and the way that failure shows up
# is an installer reporting success months later.
if [[ ${TEST_ONLY} -eq 0 ]]; then
  for staged in "${HERE}/husk-slurm-broker-${ARCH}" "${HERE}/husk-slurm-wrapper-${ARCH}"; do
    rm -f "${staged}" 2>/dev/null || true
    if [[ -e "${staged}" ]]; then
      echo "error: could not remove the previous build's ${staged}." >&2
      echo "       Leaving it would let install-husk.sh deploy it as if this build had" >&2
      echo "       produced it: that script tests only [[ -x ]] and then installs, with" >&2
      echo "       no hash check and no stamp check. Remove it by hand and re-run." >&2
      exit 1
    fi
  done
  echo "==> cleared previously staged husk-slurm-{broker,wrapper}-${ARCH}"
fi

# ── the Rust gate ─────────────────────────────────────────────────────────────
#
# This script used to compile release binaries without ever running the crate's tests,
# and make-release.sh had no Rust gate either — so the whole broker, the newer and larger
# half of the release, could be built, bundled, checksummed and shipped with a red suite
# and nothing anywhere would have said so (`B8-5`, `P7`). It costs about eight seconds.
#
# AFTER the clearing above and BEFORE the build, deliberately: that ordering is what makes
# "a failed gate leaves no binary to install" true rather than asserted. It is the same
# rule seccomp-wrapper/build_and_test.sh states at its staging step, and the same rule
# B6-7 broke by leaving a stale one behind.
echo "==> cargo test --release --locked ${OFFLINE[*]} (${ARCH})"
( cd "${BROKER}" && cargo test --release --locked "${OFFLINE[@]}" )
echo "  [ok]   crate tests pass"

if [[ ${TEST_ONLY} -eq 1 ]]; then
  echo "==> --test-only: not building, not staging"
  exit 0
fi

# Force the build script to re-run, so this binary is stamped with the tree it is being
# built from RIGHT NOW. Cargo re-runs build.rs when a package file changes, which is the
# correct trigger for "did the code change" — and a release is the one moment where the
# other question also matters: `git commit` and `git tag` change a tree's identity without
# changing a single byte of source, so a release built minutes after tagging would
# otherwise reuse the previous build's stamp and ship binaries reading `<tag>-dirty`.
# `B8-4` names this as its second consequence: build-release.sh runs in a `target/` that
# on a developer machine is warm. One touch, one relink, no ambiguity.
touch "${BROKER}/build.rs"

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
