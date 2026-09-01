#!/usr/bin/env bash
# install-husk.sh — Set up the Claude Code agent sandbox on CSCS supercomputers.
#
# CSCS supercomputers provide bubblewrap (bwrap) system-wide. This script installs the
# remaining dependencies and configures ~/.claude/settings.json so the sandbox
# is active for all projects under this user account.
#
# What this installs (all into ~/.local):
#   socat            — bridges the sandboxed process to the host-side HTTP and
#                      SOCKS5 proxies; bwrap removes the network namespace so all
#                      outbound traffic must route through socat; built from source
#                      if not already present system-wide
#   apply-seccomp    — Anthropic's seccomp helper extracted from the
#                      @anthropic-ai/sandbox-runtime npm tarball; static binary,
#                      no runtime deps; blocks AF_UNIX sockets and io_uring
#   seccomp-wrapper  — syscall deny-list wrapper; pre-built static binary
#                      from this repo's seccomp-wrapper/ directory
#   husk             — launcher script: runs  seccomp-wrapper claude [args...],
#                      and on a SLURM machine also routes job submission through the
#                      fail-closed broker automatically (spawned only when sbatch is
#                      detected; no broker and no trace on a laptop)
#
# What this configures:
#   ~/.claude/skills/husk/SKILL.md — tells the agent it is inside husk
#   ~/.claude/settings.json — enables sandbox, points to apply-seccomp,
#                             restricts filesystem reads to the current project,
#                             and hard-blocks the agent from editing settings files
#
# Prerequisites:
#   - The `claude` CLI installed and signed in. husk wraps an existing
#     Claude Code install; this script does NOT install or update Claude.
#   - bubblewrap (bwrap) available system-wide (present on CSCS).
#
# Usage:
#   ./install-husk.sh              install / update
#   ./install-husk.sh --uninstall  remove everything this installed and
#                                         revert ~/.claude/settings.json
#
# After running, add to ~/.bashrc or ~/.bash_profile if not already present:
#   export PATH="$HOME/.local/bin:$PATH"
#
# Then start Claude Code with:
#   husk

set -euo pipefail

# ── Confirm before modifying ~/.claude/settings.json ─────────────────────────

SCRIPT_DIR_EARLY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Optional flag: --slurm-partition NAME[,NAME...] ─────────────────────────────
# The partitions a brokered agent job may request. Recorded for husk to export as
# HUSK_SLURM_PARTITION. Site-specific: not every site has a preemptible partition, so
# the built-in default is only a default. Prefer a preemptible one where it exists —
# that is what makes the resource envelope structural (THREAT-MODEL.md).
# A COMMA-SEPARATED LIST is accepted, because a cluster is not homogeneous: a GPU
# partition and a CPU-only postprocessing partition are different partitions, and one
# workflow legitimately needs both:  --slurm-partition gpu-part,pp-part
# The job picks one of them; husk refuses anything else and names the whole set.
# Extracted first so the positional --help/--uninstall checks below still see $1.
SLURM_PARTITION_ARG=""
SLURM_ACCOUNT_ARG=""
_args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --slurm-partition)   SLURM_PARTITION_ARG="${2:-}"; shift 2 2>/dev/null || shift ;;
    --slurm-partition=*) SLURM_PARTITION_ARG="${1#*=}"; shift ;;
    # SEED-ONLY, both of them. They write ~/.husk/config.json on a FIRST install and the
    # legacy fallback files; after that the config file is authoritative and these flags are
    # reported as not-applied rather than silently ignored. Kept rather than removed so a
    # scripted first install still works in one command.
    --slurm-account)     SLURM_ACCOUNT_ARG="${2:-}"; shift 2 2>/dev/null || shift ;;
    --slurm-account=*)   SLURM_ACCOUNT_ARG="${1#*=}"; shift ;;
    *)                   _args+=("$1"); shift ;;
  esac
done
set -- "${_args[@]:+${_args[@]}}"

# ── The two seed values, resolved ONCE, here, where every later reader can see them ───────
#
# `B7-5`. They used to be resolved INSIDE the `if broker-binaries-exist` branch 500 lines
# below, while the config seeder that consumes them sits outside it. So on a machine where
# `build-release.sh` had not been run — the state `README.md` sends a development clone
# into — `./install-husk.sh --slurm-account acctA --slurm-partition partA` wrote
#
#     {"accounts": [], "partitions": []}
#
# announced it as `[ok]`, never mentioned either flag, and exited. The never-clobber rule on
# that file (correct on its own terms) then made the empty version permanent: the next
# install says "config exists, left untouched". On Santis an empty `accounts` means the
# site's cli_filter rejects every submission. Twenty lines above the seeder is a comment
# reading A FLAG THAT DOES NOTHING MUST NOT DO IT QUIETLY.
#
# A function rather than two bare assignments so `install-husk.test.sh` can drive the seeder
# through the REAL resolution. A test that sets `SLURM_ACCOUNT` itself is the false friend:
# it passes against the bug, because the bug is that nothing set it here.
husk_slurm_seed() {
  SLURM_PARTITION="${SLURM_PARTITION_ARG:-${HUSK_SLURM_PARTITION:-}}"
  SLURM_ACCOUNT="${SLURM_ACCOUNT_ARG:-${HUSK_SLURM_ACCOUNT:-}}"
}
husk_slurm_seed

# ── --help ────────────────────────────────────────────────────────────────────
# Prints this script's header comment block (the single source of truth for what
# it does), so help text never duplicates or drifts from the header.
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '1d; /^#/!q; s/^#//; s/^ //; p' "$0"
  exit 0
fi

# ── Uninstall mode (./install-husk.sh --uninstall) ────────────────────
if [[ "${1:-}" == "--uninstall" ]]; then
  PREFIX="${HOME}/.local"
  CLAUDE_SETTINGS="${HOME}/.claude/settings.json"
  MANIFEST="$PREFIX/lib/husk/uninstall-manifest.json"

  echo ""
  echo "This will remove husk from your home directory:"
  echo "  - delete  $PREFIX/bin/{husk,seccomp-wrapper,seccomp-wrapper.sha256}"
  echo "            $PREFIX/bin/{husk-slurm-wrapper,husk-slurm-broker} (if installed)"
  echo "            $PREFIX/bin/husk-slurm (legacy, if left by an older install)"
  echo "            $PREFIX/lib/husk/{apply-seccomp,sbatch-stub.py,srun-stub.py,slurm-partition,slurm-account}"
  # ASK THE LIST, do not restate it. Three literals here is the same drift the Python side
  # stopped doing in this cycle — MANAGED_KEYS lives in one file and this banner is read by
  # an operator deciding whether to press Enter (`P8`).
  MANAGED_BLOCKS="$(python3 "$SCRIPT_DIR_EARLY/scripts/merge-claude-settings.py" \
                      --managed-keys 2>/dev/null || true)"
  [[ -n "$MANAGED_BLOCKS" ]] || MANAGED_BLOCKS="(list unavailable — python3 could not read the merge script)"
  echo "  - revert the settings blocks husk manages in $CLAUDE_SETTINGS to their"
  echo "    pre-install state, all other settings kept. Those blocks are:"
  echo "      $MANAGED_BLOCKS"
  echo "  - any $CLAUDE_SETTINGS.husk-replaced.*.json is LEFT in place — those are"
  echo "    YOUR values, saved before husk overwrote a managed key; delete them yourself"
  echo "  - socat at $PREFIX/bin/socat is LEFT in place (a shared dependency);"
  echo "    remove it yourself if nothing else uses it"
  echo "  - session logs in $HOME/.husk/log are LEFT in place — they are the record"
  echo "    of what husk brokered, so an uninstall does not erase them"
  echo ""
  echo "Press Enter to continue or Ctrl+C to cancel."
  read -r

  if [[ -f "$CLAUDE_SETTINGS" ]]; then
    bak="$CLAUDE_SETTINGS.bak.$(date +%s)"
    cp "$CLAUDE_SETTINGS" "$bak"
    printf '  [ok]   backed up current settings to %s\n' "$bak"
    python3 "$SCRIPT_DIR_EARLY/scripts/merge-claude-settings.py" --uninstall \
      "$CLAUDE_SETTINGS" "$MANIFEST"
  else
    printf '  [skip] %s does not exist\n' "$CLAUDE_SETTINGS"
  fi

  # Read the manifest (above) before deleting it here.
  for f in "$PREFIX/bin/husk" \
           "$PREFIX/bin/husk-slurm" \
           "$PREFIX/bin/husk-slurm-wrapper" \
           "$PREFIX/bin/husk-slurm-broker" \
           "$PREFIX/bin/seccomp-wrapper" \
           "$PREFIX/bin/seccomp-wrapper.sha256" \
           "$PREFIX/lib/husk/apply-seccomp" \
           "$PREFIX/lib/husk/sbatch-stub.py" \
           "$PREFIX/lib/husk/srun-stub.py" \
           "$PREFIX/lib/husk/slurm-partition" \
           "$PREFIX/lib/husk/slurm-account" \
           "${HOME}/.claude/skills/husk/SKILL.md" \
           "$MANIFEST"; do
    if [[ -e "$f" ]]; then rm -f "$f"; printf '  [ok]   removed %s\n' "$f"; fi
  done
  rmdir "$PREFIX/lib/husk" 2>/dev/null \
    && printf '  [ok]   removed %s\n' "$PREFIX/lib/husk" || true
  rmdir "${HOME}/.claude/skills/husk" 2>/dev/null \
    && printf '  [ok]   removed %s\n' "${HOME}/.claude/skills/husk" || true

  echo ""
  echo "husk removed. Your ~/.bashrc PATH line (if you added one) and socat"
  echo "were left untouched."
  exit 0
fi
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo "This script will merge settings into ~/.claude/settings.json."
echo "Existing settings outside these blocks are preserved."
echo ""
echo "What will be added:"
echo "  1. Sandbox isolation — restricts Claude to the current project directory;"
echo "     blocks all home directories (/users/); enables seccomp syscall filters."
echo "  2. Permission rules — lets SLURM read-only commands (sinfo, squeue, sacct)"
echo "     run without a prompt; blocks credential files, nc, socat, and Claude's"
echo "     own settings files from being read or modified by the agent."
echo ""
echo "Full settings (user-config/settings.json):"
echo "────────────────────────────────────────────────────────"
cat "$SCRIPT_DIR_EARLY/user-config/settings.json"
echo "────────────────────────────────────────────────────────"
echo ""
echo "Note: Claude Code records every session to"
echo "  ~/.claude/projects/<project>/<session-id>.jsonl"
echo "Every prompt, tool call, and response is captured. Over months these"
echo "become a detailed record of how you write and what you work on."
echo "Delete sessions you do not want to keep."
echo ""
echo "Press Enter to continue or Ctrl+C to cancel."
read -r

# ─────────────────────────────────────────────────────────────────────────────

for _cmd in wget python3 tar sha256sum sha512sum; do
  command -v "$_cmd" >/dev/null 2>&1 \
    || { echo "error: '$_cmd' is required but not found on PATH"; exit 1; }
done
unset _cmd

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${HOME}/.local"
MANIFEST="$PREFIX/lib/husk/uninstall-manifest.json"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

case "$(uname -m)" in
  x86_64)  HOST_ARCH="x86_64" ;;
  aarch64) HOST_ARCH="aarch64" ;;
  *)
    echo "error: unsupported architecture $(uname -m)"
    echo "       Supported: x86_64 (Balfrin), aarch64 (Santis)"
    exit 1
    ;;
esac

SOCAT_VERSION="1.7.4.4"
SANDBOX_RUNTIME_VERSION="0.0.49"

# socat's official distribution is HTTP-only — the author provides no HTTPS mirror.
# Integrity is guaranteed by SOCAT_SHA256: a MITM attack delivers a tarball that
# fails the checksum and aborts the install.
SOCAT_URL="http://www.dest-unreach.org/socat/download/socat-${SOCAT_VERSION}.tar.gz"
SANDBOX_RUNTIME_URL="https://registry.npmjs.org/@anthropic-ai/sandbox-runtime/-/sandbox-runtime-${SANDBOX_RUNTIME_VERSION}.tgz"

# SHA-256 of socat-${SOCAT_VERSION}.tar.gz (verified on Balfrin 2026-05-13)
# To update: wget "$SOCAT_URL" && sha256sum socat-${SOCAT_VERSION}.tar.gz
SOCAT_SHA256="0f8f4b9d5c60b8c53d17b60d79ababc4a0f51b3bb6d2bd3ae8a6a4b9d68f195e"

# SHA-512 of sandbox-runtime-${SANDBOX_RUNTIME_VERSION}.tgz (from npm registry integrity field)
# To update: curl -s https://registry.npmjs.org/@anthropic-ai/sandbox-runtime/<version> \
#   | python3 -c "import json,sys,base64,binascii; d=json.load(sys.stdin); \
#     b64=d['dist']['integrity'].replace('sha512-',''); \
#     print(binascii.hexlify(base64.b64decode(b64+'==')).decode())"
SANDBOX_RUNTIME_SHA512="b7c1a073403b522cf13063e4fc03441fc9f09c2ab335620aa6474a8310d551a28d3109cccf3591e9a12baea21d534dff64fe5137afce2ff92314ec3f568c7729"

# ── Helpers ───────────────────────────────────────────────────────────────────

log()  { echo ""; echo "==> $*"; }
ok()   { printf '  [ok]   %s\n' "$*"; }
skip() { printf '  [skip] %s\n' "$*"; }
warn() { printf '  [warn] %s\n' "$*"; }

# Returns 0 if $1 binary exists in standard system paths (not ~/.local)
system_has_bin() {
  local name="$1"
  local dir
  for dir in /usr/bin /usr/local/bin /bin /usr/sbin; do
    [[ -x "$dir/$name" ]] && return 0
  done
  return 1
}

# Is the binary about to be installed the one this checkout describes? (`RB2-3`)
#
# The producer side (build-release.sh) now clears its staged binaries before its gate, so a
# FAILED build leaves nothing installable. That covers one entry point of three. The two it
# cannot reach are both ordinary and both were measured:
#
#   build at commit A, `git pull` to B, ./install-husk.sh
#       -> [[ -x ]] is true, the commit-A binary is installed, and this script prints
#          ok "SLURM brokering -> husk (... installed ...)". No failed build anywhere.
#   build at A, `git pull` to B, ./make-release.sh
#       -> make-release.sh is RIGHT and refuses ("was not built from the commit this
#          release ships") — and leaves the stale binary staged and installable.
#
# The reason a hash check was declined for this file still stands: B6-7's harm was the
# reassuring "already up to date", and a hash here would reword a stale install rather than
# prevent one. But the control that is available now is not a hash, it is the STAMP the
# broker already carries, and a stamp answers a different question — not "is this the same
# file as last time" but "is this the commit this checkout is at". It prevents rather than
# rewords, it fails closed, and it self-disables outside a checkout so a release-tarball
# install never sees it.
#
# Self-disabling is on `.git` in THIS directory, deliberately, and not on `git rev-parse`
# succeeding: unpack a release tarball under a home directory that is itself a git repo — a
# dotfiles repo — and git happily answers with that repo's HEAD, which no husk binary can
# ever match. That would be a refusal with no converging remedy, i.e. this fix becoming the
# next finding (`P15`: check the name resolves to the object you meant). build.rs guards
# its half the same way and in the same pass.
require_staged_broker_matches_checkout() {
  local bin="$1" head stamped
  [[ -e "$SCRIPT_DIR/.git" ]] || return 0           # tarball install: not a question we can ask
  head="$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null || true)"
  if [[ -z "$head" ]]; then
    # A checkout we cannot read is not a checkout that agrees (`P7`): say the check did not
    # run rather than let silence read as a pass.
    warn "this is a git checkout but 'git rev-parse HEAD' failed here, so the staged broker's"
    warn "  build stamp was NOT checked against it. Installing anyway."
    return 0
  fi
  stamped="$(LC_ALL=C grep -aoE 'husk-build-stamp\{[0-9]+\|[^|]*\|' "$bin" | head -1 || true)"
  stamped="${stamped#*|}"; stamped="${stamped%|}"
  if [[ "$stamped" == "$head" ]]; then
    return 0
  fi
  if [[ "$stamped" == "${head}-dirty" ]]; then
    warn "the staged broker was built from this commit with UNCOMMITTED changes in the tree."
    warn "  Installing it: this is the ordinary edit-build-install loop. Its session banner"
    warn "  will say -dirty, and make-release.sh will refuse it."
    return 0
  fi
  echo "  [error] the staged broker binary is not this checkout."
  echo "          this checkout is at: ${head}"
  echo "          that binary is from: ${stamped:-<no husk build stamp at all>}"
  echo "          Installing it would deploy code the source beside it cannot rebuild, and"
  echo "          nothing later would say so: a broker is spawned once per session and"
  echo "          keeps running, so the next session would answer for a commit you are not"
  echo "          looking at. Rebuild for this commit and re-run:"
  echo "            (cd slurm-broker && ./build-release.sh) && ./install-husk.sh"
  exit 1
}

# Run it BEFORE anything is installed. A refusal here must leave the machine exactly as it
# was found, not with a new seccomp-wrapper, a new launcher and a merged settings.json
# beside a broker this script just refused (`P6` — the safe state is the one you cannot
# forget to restore).
if [[ -x "$SCRIPT_DIR/slurm-broker/husk-slurm-broker-${HOST_ARCH}" ]]; then
  require_staged_broker_matches_checkout \
    "$SCRIPT_DIR/slurm-broker/husk-slurm-broker-${HOST_ARCH}"
fi

# ── bwrap (runtime prerequisite) ──────────────────────────────────────────────
#
# bwrap (bubblewrap) is what actually creates the filesystem/network namespace at
# runtime — husk cannot sandbox without it. It is provided system-wide on
# CSCS. Warn rather than fail, so the install still completes on nodes where it
# is provisioned separately (e.g. via a module), but make the gap explicit.

if ! command -v bwrap >/dev/null 2>&1; then
  warn "bwrap (bubblewrap) not found on PATH — husk cannot sandbox without it."
  warn "It is provided system-wide on CSCS; install or load it before running husk."
fi

# ── socat ─────────────────────────────────────────────────────────────────────

log "socat ${SOCAT_VERSION}"
if system_has_bin socat; then
  skip "socat found system-wide — nothing to do"
elif [[ -x "$PREFIX/bin/socat" ]]; then
  skip "socat already at $PREFIX/bin/socat — nothing to do"
else
  # Build in a subshell to avoid changing the script's working directory.
  for _cmd in gcc make; do
    command -v "$_cmd" >/dev/null 2>&1 \
      || { echo "error: '$_cmd' is required to build socat but not found on PATH"; exit 1; }
  done
  unset _cmd
  (
    cd "$WORK_DIR"
    wget -q --tries=3 --timeout=30 -O "socat-${SOCAT_VERSION}.tar.gz" "$SOCAT_URL"
    echo "${SOCAT_SHA256}  socat-${SOCAT_VERSION}.tar.gz" | sha256sum -c - \
      || { echo "  [error] socat tarball checksum mismatch — aborting"; exit 1; }
    tar xzf "socat-${SOCAT_VERSION}.tar.gz"
    cd "socat-${SOCAT_VERSION}"
    ./configure --prefix="$PREFIX" --quiet
    make -j4 --silent
    make install --silent
  )
  ok "socat → $PREFIX/bin/socat"
fi

# ── apply-seccomp (from @anthropic-ai/sandbox-runtime) ───────────────────────
#
# Static binary with the BPF filter baked in — no runtime deps. Blocks
# AF_UNIX socket creation and io_uring, and wraps each agent subprocess in a
# nested user+PID+mount namespace for additional process isolation.

log "apply-seccomp ${SANDBOX_RUNTIME_VERSION}"

APPLY_SECCOMP_DEST=""

case "$(uname -m)" in
  x86_64)  ARCH="x64" ;;
  aarch64) ARCH="arm64" ;;
  *)
    warn "Unsupported architecture $(uname -m) — skipping apply-seccomp"
    ARCH=""
    ;;
esac

if [[ -n "$ARCH" ]]; then
  APPLY_SECCOMP_DEST="$PREFIX/lib/husk/apply-seccomp"
  if [[ -x "$APPLY_SECCOMP_DEST" ]]; then
    skip "apply-seccomp already at $APPLY_SECCOMP_DEST — nothing to do"
  else
    mkdir -p "$PREFIX/lib/husk"
    wget -q --tries=3 --timeout=30 -O "$WORK_DIR/sandbox-runtime.tgz" "$SANDBOX_RUNTIME_URL"
    echo "${SANDBOX_RUNTIME_SHA512}  $WORK_DIR/sandbox-runtime.tgz" | sha512sum -c - \
      || { echo "  [error] sandbox-runtime tarball checksum mismatch — aborting"; exit 1; }
    tar -xzOf "$WORK_DIR/sandbox-runtime.tgz" \
      "package/vendor/seccomp/${ARCH}/apply-seccomp" \
      > "$WORK_DIR/apply-seccomp"
    install -m 0755 "$WORK_DIR/apply-seccomp" "$APPLY_SECCOMP_DEST"
    ok "apply-seccomp → $APPLY_SECCOMP_DEST"
  fi
fi

# ── seccomp-wrapper + husk launcher ────────────────────────────────────
#
# seccomp-wrapper installs a broad syscall deny-list (ptrace, kexec_load, bpf,
# pivot_root, etc.) before exec'ing its argument. It stacks on top of
# apply-seccomp's filter — the kernel applies both, most-restrictive wins.
#
# husk is a thin launcher that calls: seccomp-wrapper claude [args...]
# Users run husk instead of claude.

log "seccomp-wrapper"

SECCOMP_WRAPPER_SRC="$SCRIPT_DIR/seccomp-wrapper/seccomp-wrapper-${HOST_ARCH}"
SECCOMP_WRAPPER_DEST="$PREFIX/bin/seccomp-wrapper"
SECCOMP_WRAPPER_HASH_FILE="$PREFIX/bin/seccomp-wrapper.sha256"
CLAUDE_SAFE_DEST="$PREFIX/bin/husk"

if [[ ! -x "$SECCOMP_WRAPPER_SRC" ]]; then
  echo "  [error] seccomp-wrapper/seccomp-wrapper-${HOST_ARCH} not found or not executable"
  echo "          Build it on this machine: cd husk && ./build_and_test.sh"
  echo "          See seccomp-wrapper/README.md for details."
  exit 1
fi

src_hash="$(sha256sum "$SECCOMP_WRAPPER_SRC" | cut -d' ' -f1)"
installed_hash=""
[[ -f "$SECCOMP_WRAPPER_HASH_FILE" ]] && installed_hash="$(cat "$SECCOMP_WRAPPER_HASH_FILE")"

if [[ "$installed_hash" == "$src_hash" ]]; then
  skip "seccomp-wrapper already up to date — nothing to do"
else
  mkdir -p "$PREFIX/bin"
  install -m 0755 "$SECCOMP_WRAPPER_SRC" "$SECCOMP_WRAPPER_DEST"
  echo "$src_hash" > "$SECCOMP_WRAPPER_HASH_FILE"
  ok "seccomp-wrapper → $SECCOMP_WRAPPER_DEST"
fi

# CAPABILITY CHECK, not a version string. The broker's job guard emits
# `seccomp-wrapper --profile=single-node ...`, and a wrapper that predates that flag
# treats it as the COMMAND NAME: every brokered job then dies with
# `exec '--profile=single-node' failed` on stderr, while stdout stays empty. That is a
# silent deployment skew — the Rust side rebuilt, the C side not — and it cost two
# bring-up runs on Balfrin (2026-07-30) before anyone read the .err file. Catch it here,
# at the one moment both halves are being deployed, and ASK for the rebuild rather than
# leaving it to be discovered on a compute node.
#
# `G-1`: THIS IS ALSO THE ONLY OPERATOR-FACING APPEARANCE OF THE WRAPPER'S NEW FATAL
# STARTUP ASSERT, AND IT USED TO MISDIAGNOSE IT AND THEN NAME A REMEDY THAT CANNOT WORK.
# `d73072c` made seccomp-wrapper refuse to start when a deny-list name resolves to nothing,
# and its message names the unresolvable syscall. The probe was
# `"$DEST" --profile=login /bin/true >/dev/null 2>&1`, so that message went to /dev/null and
# the operator was told the wrapper "does not understand --profile" — of a wrapper that
# understands it perfectly — and then told to run `make`, which runs no tests and which
# writes `seccomp-wrapper`, while THIS SCRIPT only ever reads `seccomp-wrapper-<arch>`, a
# name only build_and_test.sh writes. The loop was closed twice over: a wrong diagnosis, and
# a remedy that rebuilds a binary this script does not look at (`P11` — an unattributed
# denial invites confident wrong remediation).
#
# Two probes, because the two failures are different questions and the answer must not be
# guessed from message text: can it START AT ALL (which is where the assert fires, before any
# flag is looked at), and does it KNOW THIS FLAG. Both were one probe before, so one answer
# had to serve for both.
#
# $1 wrapper path   $2 the rebuild command to print
husk_seccomp_capability_check() {
  local wrapper="$1" rebuild="$2" out="" rc=0 line

  rc=0; out="$("$wrapper" /bin/true 2>&1 >/dev/null)" || rc=$?
  if (( rc != 0 )); then
    printf '  [error] the installed seccomp-wrapper refuses to START on this machine.\n'
    printf '          Asked to run /bin/true with no flags at all, it exited %s.' "$rc"
    if [[ -n "$out" ]]; then
      printf ' Its own words:\n'
      while IFS= read -r line; do printf '          | %s\n' "$line"; done <<<"$out"
      printf '          That message is the diagnosis and husk cannot improve on it — a\n'
      printf '          deny-list name the wrapper cannot resolve is named there by name.\n'
    else
      printf ' It said nothing at all,\n'
      printf '          which is itself the finding: a wrapper that fails silently is the\n'
      printf '          shape husk exists to refuse.\n'
    fi
    printf '          Fix what it names, then REBUILD AND RE-TEST:\n'
    printf '            %s\n' "$rebuild"
    printf '          `make` alone is not enough and this installer used to say it was: it\n'
    printf '          runs no tests, and it writes seccomp-wrapper, while this script only\n'
    printf '          ever reads seccomp-wrapper-$(uname -m) — which build_and_test.sh\n'
    printf '          writes and make does not. `seccomp-wrapper --self-test` reports the\n'
    printf '          same finding on its own if this binary is new enough to have it.\n'
    return 1
  fi

  rc=0; out="$("$wrapper" --profile=login /bin/true 2>&1 >/dev/null)" || rc=$?
  if (( rc != 0 )); then
    printf '  [error] the installed seccomp-wrapper does not understand --profile.\n'
    printf '          It starts and cages correctly — only the flag is unknown, so this is\n'
    printf '          a deployment skew: the Rust side was rebuilt and the C side was not.\n'
    printf '          The broker job guard passes --profile=single-node, so every brokered\n'
    printf '          job would fail to launch with:\n'
    printf "            seccomp_wrapper: exec '--profile=single-node' failed\n"
    if [[ -n "$out" ]]; then
      printf '          What it said here:\n'
      while IFS= read -r line; do printf '          | %s\n' "$line"; done <<<"$out"
    fi
    printf '          Rebuild and re-test, then re-run this installer:\n'
    printf '            %s\n' "$rebuild"
    return 1
  fi
  return 0
}

if [[ -x "$SECCOMP_WRAPPER_DEST" ]]; then
  husk_seccomp_capability_check "$SECCOMP_WRAPPER_DEST" \
    "(cd \"$SCRIPT_DIR/seccomp-wrapper\" && ./build_and_test.sh) && \"$0\" $*" || exit 1
  ok "seccomp-wrapper understands --profile (cage profiles available)"
fi

# Always write the launcher — two lines, overwriting is harmless, and ensures
# it stays in sync if the content ever changes.
mkdir -p "$PREFIX/bin"
cat > "$CLAUDE_SAFE_DEST" <<'LAUNCHER'
#!/usr/bin/env bash
# husk — sandboxed launcher for the Claude Code agent.
#
# Runs `seccomp-wrapper claude` inside the husk sandbox. On a machine with SLURM it
# ALSO routes job submission through the fail-closed broker — automatically. The
# broker is spawned ONLY when sbatch is detected (by the wrapper); on a laptop there
# is no broker, no spool, and no trace. There is deliberately no flag to disable the
# cage. (A single command drives both cases; the retired `husk-slurm` is gone.)
set -euo pipefail

if ! command -v claude >/dev/null 2>&1; then
  echo "husk: the 'claude' CLI was not found on PATH." >&2
  echo "husk wraps an existing Claude Code install; install and sign in" >&2
  echo "first, then re-run. See https://code.claude.com/docs" >&2
  exit 127
fi

self="$(readlink -f "$0")"
here="$(cd "$(dirname "$self")" && pwd)"     # the bin dir husk is installed in

# Locate the SLURM-brokering pieces (installed together, or absent on unsupported
# arches). The wrapper itself decides at runtime whether to broker (SLURM present)
# or just exec the agent (no SLURM), so we always route through it when it exists.
wrapper=""; broker=""; stub=""
if [ -x "$here/husk-slurm-wrapper" ]; then wrapper="$here/husk-slurm-wrapper"; fi
if [ -x "$here/husk-slurm-broker" ];  then broker="$here/husk-slurm-broker";  fi
for p in "$here/../lib/husk/sbatch-stub.py" "$here/sbatch-stub.py"; do
  if [ -r "$p" ]; then stub="$p"; break; fi
done

# Site partition (operator-recorded at install; agent-UNWRITABLE, which is the property
# that matters — see the note at the partition write, `H-1`: ~/.local is carved back out
# of denyRead by allowRead, so the cage can READ this and cannot change it). An explicit
# HUSK_SLURM_PARTITION env var wins; otherwise use the recorded value. The broker
# forces this partition onto every job.
# The project account(s), where the site requires one (Santis rejects every submission
# without it). Same trusted path as the partition: recorded at install, under ~/.local,
# not writable from the cage.
#
# A comma-separated LIST, and the broker resolves a job's request against it — the same
# bound-the-set-and-let-the-job-pick shape as --slurm-partition. One value keeps the old
# behaviour exactly. It is a list because a person with hours on two projects has to be
# able to say which one a job bills, and re-running this installer is not an answer per
# job. What the set preserves is the property that matters: the caged side never supplies
# the account, it only selects one husk already trusts.
if [ -z "${HUSK_SLURM_ACCOUNT:-}" ]; then
  for cfg in "$here/../lib/husk/slurm-account" "$here/slurm-account"; do
    if [ -r "$cfg" ]; then
      acct="$(head -n1 "$cfg" | tr -d '[:space:]')"
      if [ -n "$acct" ]; then export HUSK_SLURM_ACCOUNT="$acct"; fi
      break
    fi
  done
fi
if [ -z "${HUSK_SLURM_PARTITION:-}" ]; then
  for cfg in "$here/../lib/husk/slurm-partition" "$here/slurm-partition"; do
    if [ -r "$cfg" ]; then
      part="$(head -n1 "$cfg" | tr -d '[:space:]')"
      if [ -n "$part" ]; then export HUSK_SLURM_PARTITION="$part"; fi
      break
    fi
  done
fi

# ── The agent gets Bash and nothing else ──────────────────────────────────────
# Anthropic's sandbox runtime wraps each Bash COMMAND — `wrapWithSandbox(command)`
# builds a bwrap argv and spawns it — so the boundary is in the path of Bash and
# NOTHING ELSE. With a write config that argv is `--ro-bind / /` with only the
# project bound back writable, and every denyRead path masked by an empty
# `--tmpfs`. That is a real, mandatory, kernel-enforced cage.
#
# Read/Write/Edit/Glob/Grep do not go through it. They execute inside the agent
# process, on the host, BESIDE the sandbox: no mount table applies to them. Their
# only leash is Claude Code's permission list — advisory, path-pattern based, and
# answerable "yes" by a human. That is why a Write can land a file in a directory
# the cage otherwise makes unreachable, while the same write from Bash is EROFS.
# Two doors, one lock.
#
# Everything those tools do, Bash does — through the door that IS locked. So husk
# hands the agent an ALLOWLIST (`--tools`), not a deny-list: a tool added upstream
# is excluded until someone decides otherwise, because a denylist is a bug list.
# The agent reads with `cat`, searches with `grep`, and writes with a shell
# redirect — all inside the cage.
#
# **The admission rule, which is what this list actually encodes:** a tool may be on
# it when EVERY effect it can have routes through a cage husk controls. husk has two
# — bwrap mounts, and the netns/egress proxy. One rule, both axes, and it is why
# `WebFetch`/`WebSearch` are excluded for exactly the same reason as `Write`: they
# act host-side, beside the cage. `network.allowedDomains` never sees them, just as
# the mount table never sees a `Write`.
#
# This list is also the first real AgentProfile (see ROADMAP, cross-cutting): at 6a
# husk wraps the CLI itself, and what it needs to know about Claude Code is exactly
# what is measured here — the admissible tool set, where the agent keeps its state,
# and which effects escape the cage today.
#
# Measured 2026-08-10 (laptop, headless probes, FILESYSTEM as the oracle — never the
# agent's self-report, which recited a full tool list while holding none):
#   - `--tools` PROPAGATES to subagents. A project-local `.claude/agents/*.md`
#     declaring `Bash, Write, Read, Edit` — a file the caged agent can author — still
#     yielded Bash only, and no file landed. `Agent` is not a delegation bypass.
#   - `isolation: "worktree"` writes to `<project>/.claude/worktrees/`: inside the
#     writable root, not host-side.
#   - `isolation: "remote"` is gated OFF here and degrades to a local worktree —
#     same hostname, kernel and $HOME. It fails SILENTLY toward local, so that is a
#     dated assumption to re-check, NOT a control. If the gate ever opens, context
#     leaves the machine with no signal.
#   - An unmatched name is dropped, not fail-open (`--tools TypoBash` -> no Write).
#   - `run_in_background` is a Bash PARAMETER, so omitting `BashOutput`/`KillShell`
#     loses nothing.
# All of it is upstream Claude Code behaviour that no test in this repo can pin.
# Re-check on a Claude Code upgrade, and once on each cluster's installed version.
#
# `AskUserQuestion` renders a choice to the HUMAN and returns their answer: no filesystem, no
# network, no execution, and the operator is the trusted party in husk's model anyway. It is
# here because an agent hit its absence with two real decisions to hand over and had to fall
# back to prose. NOTE it cannot be verified headlessly — it is an interactive-only tool, so
# `--tools default` never lists it and no `-p` probe can see it. Verify in a live session.
#
# `TaskGet` and `TaskStop` are pure in-session bookkeeping by their schemas — a read-only
# lookup, and a stop. `TaskStop` has a positive argument beyond symmetry: an agent that has
# spawned background work on a SHARED login node should be able to stop its own runaway, and
# without it the only remedy is a human with `kill`.
#
# `TaskOutput` is deliberately NOT here: it is marked DEPRECATED, and the path it duplicates
# already works — background output lands in a file and `cat` reads it, measured.
#
# `ListAgents` is deliberately NOT here, and the reason arrived late. It reads harmless — an
# enumeration with both parameters disabled in this build — but its own description says it
# lists cloud sessions and Remote Control sessions ON OTHER MACHINES. That makes it the
# DISCOVERY half of the family whose ACTION half (`SendMessage`, `RemoteTrigger`) is already
# excluded, and enumerate-then-act is one capability, not two.
#
# `Skill` earns its place by removing a defect rather than adding a feature: husk
# GENERATES and installs its own skill and the job banner points at it, but under
# `--tools Bash` no skill is listed at all. Measured: the pointer led nowhere.
#
# Still blunt where it counts, and it costs real ergonomics (every file touch is a
# sandboxed command, slow on Lustre). Revisit the rest when the login side gets its
# own outer cage — that is the fix that makes host-side tools safe again, and it
# retires this whole list.
HUSK_TOOLS="Bash,Skill,Agent,AskUserQuestion,TaskCreate,TaskUpdate,TaskList,TaskGet,TaskStop"

# husk's flags go FIRST so an explicit user flag still wins: the human launching
# husk is the trusted party here, the agent inside it is not.
set -- --tools "$HUSK_TOOLS" "$@"

# EVERY startup goes through the Rust wrapper. It is where the fail-closed chain lives
# — the witness types that make an unverified state unrepresentable (P6) — and it already
# handles the no-SLURM case itself (`Plan::Plain`: one line, no namespaces, no spool).
# Routing any launch around it would put a boundary decision back in shell, where it is
# enforced by discipline instead of by construction.
if [ -z "$wrapper" ]; then
  echo "husk: refusing to launch — the husk-slurm-wrapper binary is missing." >&2
  echo "" >&2
  echo "  expected at: $here/husk-slurm-wrapper" >&2
  echo "" >&2
  echo "The wrapper is the layer that verifies husk's sandbox settings have not been" >&2
  echo "overridden, and that job submission is brokered. husk will not start the agent" >&2
  echo "without it, because it cannot tell what boundary the agent would get." >&2
  echo "Build it for this architecture and re-install:" >&2
  echo "    (cd slurm-broker && ./build-release.sh) && ./install-husk.sh" >&2
  exit 1
fi

# Hand off to the fail-closed wrapper. Agent is `seccomp-wrapper claude` (NOT husk,
# so there is no launcher recursion). The wrapper brokers iff it detects SLURM; with
# SLURM present and no --broker it refuses, which is the right answer — an unbrokered
# agent on a SLURM machine is exactly what the broker exists to prevent.
args=("$wrapper")
if [ -n "$stub" ]; then args+=(--stub "$stub"); fi
if [ -n "$broker" ]; then args+=(--broker "$broker"); fi
exec "${args[@]}" -- seccomp-wrapper claude "$@"
LAUNCHER
chmod +x "$CLAUDE_SAFE_DEST"
ok "husk launcher → $CLAUDE_SAFE_DEST"


# ── SLURM brokering (optional) ────────────────────────────────────────────────
#
# Out-of-sandbox broker + fail-closed outer wrapper + in-sandbox sbatch stub. The
# `husk` launcher (installed above) auto-detects SLURM and drives these; there is no
# separate launcher. The binaries are prebuilt per-arch like seccomp-wrapper; build
# them first with:
#   (cd slurm-broker && ./build-release.sh)
#
# NOT OPTIONAL, whatever the heading said until `RB2-2`. The launcher written above
# refuses to start without husk-slurm-wrapper ("husk: refusing to launch"), because that
# binary is where the fail-closed chain lives — so "the broker binaries are absent" is not
# a feature switched off, it is an installation that cannot run the agent. The old text
# said "this is skipped and plain husk still works", and both halves were false: nothing
# still works, and it was announced as [skip], the same word this script uses for
# "already up to date". Two measured consequences, both from one failed build-release.sh
# followed by an install:
#
#   with --uninstall first : nothing is installed, this script exits 0 reporting success,
#                            and the operator discovers it at first launch instead
#   without --uninstall    : the PREVIOUS broker and wrapper are still in PREFIX/bin, are
#                            NOT replaced, and husk goes on brokering with them — while
#                            this transcript says "not installed" and the summary at the
#                            end says the launcher has no brokering. The stale-deploy
#                            shape of B6-7, reached through the path B6-7 did not cover.
log "SLURM brokering"

SLURM_BROKER_SRC="$SCRIPT_DIR/slurm-broker/husk-slurm-broker-${HOST_ARCH}"
SLURM_WRAPPER_SRC="$SCRIPT_DIR/slurm-broker/husk-slurm-wrapper-${HOST_ARCH}"
HUSK_SLURM_INSTALLED=0

if [[ -x "$SLURM_BROKER_SRC" && -x "$SLURM_WRAPPER_SRC" ]]; then
  # Only the broker carries a stamp; the wrapper beside it has none (measured: zero
  # markers). build-release.sh produces and stages the pair from one cargo build, so this
  # answers for both — said plainly rather than implied (`P12`).
  # Provenance was settled in the preflight, before anything was installed.
  mkdir -p "$PREFIX/bin" "$PREFIX/lib/husk"
  install -m 0755 "$SLURM_BROKER_SRC"  "$PREFIX/bin/husk-slurm-broker"
  install -m 0755 "$SLURM_WRAPPER_SRC" "$PREFIX/bin/husk-slurm-wrapper"
  install -m 0755 "$SCRIPT_DIR/slurm-broker/sbatch-stub.py" \
                  "$PREFIX/lib/husk/sbatch-stub.py"
  # The srun stub is bound over srun INSIDE a brokered job by the job guard, which
  # derives this path from the broker's own location (<prefix>/bin -> <prefix>/lib/husk).
  # Both must be deployed together: the guard checks it exists before binding, so a
  # missing stub costs srun brokering, not the cage.
  install -m 0755 "$SCRIPT_DIR/slurm-broker/srun-stub.py" \
                  "$PREFIX/lib/husk/srun-stub.py"
  # husk-slurm is retired — `husk` now brokers SLURM itself. Remove any stale copy
  # left by an older install so users don't keep invoking the dead launcher.
  rm -f "$PREFIX/bin/husk-slurm"
  ok "SLURM brokering → husk (broker + wrapper + stub installed; husk auto-brokers)"

  # Record the site partition (if given) so husk exports it as
  # HUSK_SLURM_PARTITION. Trusted because it is written OUT of the cage by this installer
  # and read by the broker, NOT because the agent cannot see it: the shipped
  # `allowRead: ["./", "~/.local"]` carves ~/.local back out of `denyRead: ["/users"]`, so
  # everything under this prefix — this file, and the uninstall manifest beside it — is
  # READABLE from inside the sandbox and only unwritable (`H-1`). The comment here said
  # "agent-inaccessible" until 2026-09-01 and it was never true on CSCS.
  # Absent → the broker uses its built-in default (preemptible).
  # $SLURM_PARTITION was resolved by husk_slurm_seed at the top of this script, NOT here:
  # the config seeder below reads the same value from outside this branch (`B7-5`).
  if [[ -n "$SLURM_PARTITION" ]]; then
    printf '%s\n' "$SLURM_PARTITION" > "$PREFIX/lib/husk/slurm-partition"
    ok "SLURM partitions → '$SLURM_PARTITION' (recorded in $PREFIX/lib/husk/slurm-partition; a job may request any one of them)"
  else
    rm -f "$PREFIX/lib/husk/slurm-partition"
    # ASK THE BROKER, do not assert on the flag. The flag being empty says nothing about
    # what the broker will USE: ~/.husk/config.json is the durable source and outranks a
    # missing flag. Measured on Balfrin 2026-09-01 — a config naming short,pp-short got
    # "broker default 'preemptible'" and a remedy the operator had already applied. Same
    # shape as `RAB3-B1`: a variable meaning "did THIS RUN set it" printed as "what is in
    # effect". The broker is installed by this point, so its own answer is available.
    _hp="$("$PREFIX/bin/husk-slurm-broker" --print-config 2>/dev/null \
             | sed -n 's/^partitions=//p' | head -1)"
    if [[ -n "$_hp" ]]; then
      ok "SLURM partitions → '$_hp' (from ~/.husk/config.json — no install flag needed; asked the broker, not the flag)"
    else
      skip "SLURM partition not set anywhere — broker default 'preemptible' (set with --slurm-partition NAME[,NAME...], or in ~/.husk/config.json; Santis has no preemptible, use debug or shared)"
    fi
    unset _hp
  fi
  # The project account. Some sites refuse every submission without one: Santis's
  # cli_filter answers "you must specify a project account (-A <account>)". The broker
  # FORCES this value, so recording it here is also what stops an agent billing another
  # project. Resolved at the top by husk_slurm_seed, for the reason given there.
  if [[ -n "$SLURM_ACCOUNT" ]]; then
    printf '%s\n' "$SLURM_ACCOUNT" > "$PREFIX/lib/husk/slurm-account"
    ok "SLURM account(s) → '$SLURM_ACCOUNT' (recorded in $PREFIX/lib/husk/slurm-account)"
    ok "  editable later without reinstalling: ${HOME}/.husk/config.json"
    case "$SLURM_ACCOUNT" in
      *,*) ok "  a job picks one with --account=<name>; the first is billed if it names none" ;;
    esac
  else
    rm -f "$PREFIX/lib/husk/slurm-account"
    # Same shape as the partition branch above — ask the broker, not the flag.
    _ha="$("$PREFIX/bin/husk-slurm-broker" --print-config 2>/dev/null \
             | sed -n 's/^accounts=//p' | head -1)"
    if [[ -n "$_ha" ]]; then
      ok "SLURM account(s) → '$_ha' (from ~/.husk/config.json — no install flag needed)"
    else
      skip "SLURM account not set anywhere — fine where the site does not require one (Balfrin). Santis DOES: set one with --slurm-account NAME or in ~/.husk/config.json, or no job will submit"
    fi
    unset _ha
  fi
  HUSK_SLURM_INSTALLED=1
else
  # NOT skip(). See the section header: without husk-slurm-wrapper the launcher refuses to
  # start, so this branch is a broken install, and [skip] is the word this script uses for
  # "already fine". `P7` — a control that does not apply must say so to someone who can
  # act — and `P11`: name the consequence, not just the absence.
  echo "  [error] the SLURM broker binaries for ${HOST_ARCH} are not built:"
  echo "            $SLURM_BROKER_SRC"
  echo "            $SLURM_WRAPPER_SRC"
  echo "          Build them and re-run this installer:"
  echo "            (cd slurm-broker && ./build-release.sh) && $0"
  if [[ -e "$PREFIX/bin/husk-slurm-wrapper" || -e "$PREFIX/bin/husk-slurm-broker" ]]; then
    echo "          A PREVIOUS install left these in place, and this run did NOT replace"
    echo "          them, so husk will keep launching and keep brokering with the older"
    echo "          binaries — which is the state the build stamp exists to make visible:"
    echo "            $PREFIX/bin/husk-slurm-broker"
    echo "            $PREFIX/bin/husk-slurm-wrapper"
  else
    echo "          Nothing is installed for brokering, and husk will refuse to launch:"
    echo "          the wrapper is the layer that verifies the sandbox settings and that"
    echo "          submission is brokered, so the launcher will not start the agent"
    echo "          without it."
  fi
fi

# ── ~/.claude/settings.json ───────────────────────────────────────────────────
#
# Written to the user-global config so it applies to all projects without
# per-repo setup. Existing keys outside the managed blocks are preserved.
# Note: re-running the installer overwrites the managed blocks —
# any manual edits inside them will be lost.
# If apply-seccomp was not installed (unsupported arch), the seccomp.applyPath
# key is omitted rather than pointing to a non-existent binary.

# ── husk's own operator config ────────────────────────────────────────────────
# The install flags seed it; after that the FILE is authoritative and the operator edits it
# without reinstalling. That is the whole point: accounts and partitions change far more often
# than the installation does, and "re-run the installer to bill a different project" is not an
# answer per job.
#
# Never clobber an existing file. An operator who edited it has said something husk does not
# get to overwrite on the next upgrade — and silently reverting a policy file is precisely the
# failure this project keeps paying for.
# Both halves are FUNCTIONS so `install-husk.test.sh` can drive them with no install, no
# $HOME and no cluster — which is the only reason `B7-5` is now pinned at the level it
# happened rather than one level above it (`P9`).
#
# husk_config_in_effect prints what the FILE says, by reading the file. Not the variables
# that were meant to go into it: four lines of this script's closing transcript were found
# this round asserting a layer from a variable that meant something adjacent, and a seeder
# reporting its own input would be that shape again, one file over (`P15`).
husk_config_in_effect() {   # <path>
  python3 - "$1" <<'PYCFG' || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"     (unreadable: {e}) — husk will REFUSE to start until this is fixed")
    raise SystemExit(0)
for k in ("accounts", "partitions", "uenvs"):
    v = d.get(k) or []
    print(f"     {k:<11} {', '.join(v) if v else '(none)'}")
PYCFG
}

# husk_write_config seeds the file from $SLURM_ACCOUNT / $SLURM_PARTITION — the values
# husk_slurm_seed resolved at the top of this script, which is why it is a function there.
husk_write_config() {   # <path>
  mkdir -p "$(dirname "$1")"
  # Emitted by json.dumps, not by printf. The hand-rolled version could not escape its own
  # input: `--slurm-account 'a"b'` wrote {"accounts": ["a"b"]}, which husk refuses to start
  # on — the same class as `B7-5` (a flag that does not do what it says) one value over, and
  # found by the read-back below rather than by reading this function. The splitting rule is
  # unchanged: comma-separated, all whitespace removed inside each name, empties dropped.
  SLURM_ACCOUNT="${SLURM_ACCOUNT:-}" SLURM_PARTITION="${SLURM_PARTITION:-}" \
  python3 - "$1" <<'PYSEED'
import json, os, sys
def names(v):
    return [w for w in ("".join(p.split()) for p in v.split(",")) if w]
cfg = {"accounts":   names(os.environ.get("SLURM_ACCOUNT", "")),
       "partitions": names(os.environ.get("SLURM_PARTITION", ""))}
with open(sys.argv[1], "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PYSEED
  chmod 0600 "$1"
}

log "husk config"
HUSK_CFG="${HOME}/.husk/config.json"
if [[ -f "$HUSK_CFG" ]]; then
  ok "config exists, left untouched → $HUSK_CFG"
  # A FLAG THAT DOES NOTHING MUST NOT DO IT QUIETLY.
  #
  # The config file wins over the install-time files, deliberately. So once it exists,
  # `--slurm-account X` writes the fallback nobody reads and changes no policy — the flag
  # appears to work and does not. That is the exact failure class husk keeps finding in other
  # people's code, and it would be ours. Not clobbering is right; not saying so is not.
  if [[ -n "${SLURM_ACCOUNT_ARG:-}${SLURM_PARTITION_ARG:-}" ]]; then
    warn "…but you passed --slurm-account/--slurm-partition, and the config file OVERRIDES them."
    warn "   In effect now, from $HUSK_CFG:"
    husk_config_in_effect "$HUSK_CFG"
    warn "   Edit that file to change policy; the flags only seed it on a first install."
  fi
else
  husk_write_config "$HUSK_CFG"
  ok "config → $HUSK_CFG (edit this, no reinstall needed)"
  # Read back from the file, because this line is the ONLY place a --slurm-account passed on
  # a machine with no broker binaries is now reported at all: the [ok] in the brokering
  # section above does not run in that case.
  ok "   what it now says:"
  husk_config_in_effect "$HUSK_CFG"
fi

# ── the husk skill ────────────────────────────────────────────────────────────
# Shipped and installed, not "documentation the user might find".
#
# husk is the layer an agent can SEE, so it is blamed for everything it does not explain
# (`P13`). The single cheapest correction is telling the agent it is inside husk: the one
# report this project got that named a mechanism instead of guessing came from an agent that
# had been told. A skill does that for every user, automatically.
#
# Installed rather than copied by hand for a second reason: it carries an option contract
# GENERATED from the broker's registry, so the skill and the binary must move together. A
# skill vendored into some other repo drifts, and a confidently wrong skill is worse than
# none.
log "husk skill"
SKILL_SRC="$SCRIPT_DIR/skill/SKILL.md"
SKILL_DEST_DIR="${HOME}/.claude/skills/husk"
if [[ -f "$SKILL_SRC" ]]; then
  mkdir -p "$SKILL_DEST_DIR"
  install -m 0644 "$SKILL_SRC" "$SKILL_DEST_DIR/SKILL.md"
  ok "agent skill → $SKILL_DEST_DIR/SKILL.md"
else
  warn "skill/SKILL.md not found — agents will not be told they are inside husk"
fi

log "~/.claude/settings.json"

CLAUDE_SETTINGS="${HOME}/.claude/settings.json"
mkdir -p "${HOME}/.claude"

python3 "$SCRIPT_DIR/scripts/merge-claude-settings.py" \
  "$CLAUDE_SETTINGS" "$APPLY_SECCOMP_DEST" "$SCRIPT_DIR/user-config/settings.json" \
  "$MANIFEST"

# ── Done ──────────────────────────────────────────────────────────────────────

# EVERY LINE IN THIS BLOCK ANSWERS "WHAT IS ON THIS MACHINE", ASKED WHEN IT IS PRINTED.
#
# `RAB3-B1`, and it is a CLASS, not a sentence. This block used to answer a different
# question — "what did THIS RUN do" — while the operator reads it as "what is installed".
# The two differ exactly in the case that matters, a failed `build-release.sh` over a
# previous install: `HUSK_SLURM_INSTALLED` is 0 because this run installed nothing, and the
# summary said `husk-slurm-wrapper is missing` TWELVE LINES BELOW an [error] block that
# correctly named the path where it still sits and warned that husk would keep brokering
# with the older binaries. The operator concludes husk is dead and never looks for the stale
# deploy — a false attribution is worse than none (`P11`), and this is the same commit whose
# whole subject was that the transcript must not lie.
#
# The other three lines had the same shape and were simply not reachable through the
# scenario that was driven: `bwrap` was asserted as an active layer 500 lines after the
# script warned it was absent from PATH, and `seccomp-wrapper` was asserted even when the
# hash file matches while the binary itself is gone (which also silently skips the
# `--profile` capability check just above — `P7`). None of these lines denies anything; they
# are only allowed to say what a stat says (`P15`: check that the name resolves to the object
# you meant).

# A function so it can be EXTRACTED AND DRIVEN without running the installer:
# `install-husk.test.sh` sed's this body out by name and feeds it the four machine states.
# Inline, the only way to test it was a full install against a throwaway $HOME, which is
# why the case below shipped wrong.
husk_layer_summary() {
  if [[ "${HUSK_SLURM_INSTALLED:-0}" == 1 ]]; then
    echo "Sandbox ready. Active layers:"
  else
    # `RAB3-B2`: this run is about to exit 1. A transcript whose text contradicts its exit
    # status is no longer evidence — the principle `RB2-5` proposed, whose fifth instance
    # was created by the commit that counted the first four.
    echo "Install INCOMPLETE — see the [error] at the end. Layers present on this machine:"
  fi
  if command -v bwrap >/dev/null 2>&1; then
    echo "  bwrap             — filesystem namespace (system-provided)"
  else
    echo "  bwrap             — NOT ON PATH: husk cannot sandbox without it (warned above)"
  fi
  if [[ -x "${APPLY_SECCOMP_DEST:-}" ]]; then
    echo "  apply-seccomp     — AF_UNIX + io_uring BPF filter (Anthropic)"
  fi
  if [[ -x "${SECCOMP_WRAPPER_DEST:-}" ]]; then
    echo "  seccomp-wrapper   — broad syscall deny-list"
  else
    echo "  seccomp-wrapper   — MISSING at ${SECCOMP_WRAPPER_DEST:-<unset>}: husk cannot launch"
  fi
  if [[ "${HUSK_SLURM_INSTALLED:-0}" == 1 ]]; then
    echo "  husk              — launcher: seccomp-wrapper claude, + SLURM job brokering"
    echo "                      (auto-detected; broker spawned only when sbatch is present)"
  elif [[ -x "${PREFIX:-}/bin/husk-slurm-wrapper" ]]; then
    echo "  husk              — STILL RUNNING A PREVIOUS INSTALL'S wrapper and broker; this"
    echo "                      run installed neither, so husk keeps brokering with the"
    echo "                      older binaries. See the [error] above."
  else
    echo "  husk              — INSTALLED BUT NOT RUNNABLE: husk-slurm-wrapper is missing"
  fi
}

echo ""
husk_layer_summary
echo ""
echo "If you have not already done so, add this to ~/.bashrc or ~/.bash_profile:"
echo '  export PATH="$HOME/.local/bin:$PATH"'
echo ""
if command -v claude >/dev/null 2>&1; then
  echo "Then start Claude Code with:"
  echo "  husk"
else
  echo "One prerequisite is still missing: the 'claude' CLI is not on your PATH."
  echo "husk wraps an existing Claude Code install — it does not install"
  echo "Claude for you. Install and sign in first (see https://code.claude.com/docs),"
  echo "then start it with:  husk"
fi
echo ""
echo "To remove everything this installed later:  ./install-husk.sh --uninstall"

# Everything this script COULD do is done, and the transcript above is complete — the exit
# status is the last thing that has to agree with it. Deferred to here rather than exiting
# at the branch itself so a failed broker build does not also leave settings.json half
# merged: the install is complete except for the part that cannot be completed, and it says
# so with a status a script can read (`RB2-2`).
if [[ "${HUSK_SLURM_INSTALLED:-0}" != 1 ]]; then
  echo ""
  echo "  [error] This install is INCOMPLETE: the SLURM broker binaries for ${HOST_ARCH}"
  echo "          were not built, so this run installed no broker and no wrapper. What"
  echo "          that leaves on this machine is stated in the SLURM brokering section"
  echo "          above — it differs depending on whether an earlier install is still"
  echo "          deployed, and the two are not the same problem. Build them and run"
  echo "          this installer again:"
  echo "            (cd slurm-broker && ./build-release.sh) && $0"
  exit 1
fi
