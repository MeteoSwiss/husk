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

# ── Optional flag: --slurm-partition NAME ───────────────────────────────────────
# The single partition the SLURM broker forces onto every agent job. Recorded for
# husk to export as HUSK_SLURM_PARTITION. Site-specific: Balfrin uses the
# built-in default `preemptible`; Santis has no such partition (use `debug` or `shared`).
# Extracted first so the positional --help/--uninstall checks below still see $1.
SLURM_PARTITION_ARG=""
_args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --slurm-partition)   SLURM_PARTITION_ARG="${2:-}"; shift 2 2>/dev/null || shift ;;
    --slurm-partition=*) SLURM_PARTITION_ARG="${1#*=}"; shift ;;
    *)                   _args+=("$1"); shift ;;
  esac
done
set -- "${_args[@]:+${_args[@]}}"

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
  echo "            $PREFIX/lib/husk/{apply-seccomp,sbatch-stub.py,srun-stub.py,slurm-partition}"
  echo "  - revert the enableAllProjectMcpServers / sandbox / permissions blocks in"
  echo "    $CLAUDE_SETTINGS to their pre-install state (all other settings kept)"
  echo "  - socat at $PREFIX/bin/socat is LEFT in place (a shared dependency);"
  echo "    remove it yourself if nothing else uses it"
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
           "$MANIFEST"; do
    if [[ -e "$f" ]]; then rm -f "$f"; printf '  [ok]   removed %s\n' "$f"; fi
  done
  rmdir "$PREFIX/lib/husk" 2>/dev/null \
    && printf '  [ok]   removed %s\n' "$PREFIX/lib/husk" || true

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
if [[ -x "$SECCOMP_WRAPPER_DEST" ]]; then
  if "$SECCOMP_WRAPPER_DEST" --profile=login /bin/true >/dev/null 2>&1; then
    ok "seccomp-wrapper understands --profile (cage profiles available)"
  else
    echo "  [error] the installed seccomp-wrapper does not understand --profile."
    echo "          The broker's job guard passes --profile=single-node, so every"
    echo "          brokered job would fail to launch with:"
    echo "            seccomp_wrapper: exec '--profile=single-node' failed"
    echo "          Rebuild the C wrapper and re-run this installer:"
    echo "            make -C \"$SCRIPT_DIR/seccomp-wrapper\" && \"$0\" \"\$@\""
    exit 1
  fi
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

# Site partition (operator-recorded at install; agent-inaccessible). An explicit
# HUSK_SLURM_PARTITION env var wins; otherwise use the recorded value. The broker
# forces this partition onto every job.
if [ -z "${HUSK_SLURM_PARTITION:-}" ]; then
  for cfg in "$here/../lib/husk/slurm-partition" "$here/slurm-partition"; do
    if [ -r "$cfg" ]; then
      part="$(head -n1 "$cfg" | tr -d '[:space:]')"
      if [ -n "$part" ]; then export HUSK_SLURM_PARTITION="$part"; fi
      break
    fi
  done
fi

# No broker layer installed (e.g. unsupported arch) → run the plain cage.
if [ -z "$wrapper" ] || [ -z "$broker" ]; then
  exec seccomp-wrapper claude "$@"
fi

# Hand off to the fail-closed wrapper. Agent is `seccomp-wrapper claude` (NOT husk,
# so there is no launcher recursion). The wrapper brokers iff it detects SLURM.
args=("$wrapper")
if [ -n "$stub" ]; then args+=(--stub "$stub"); fi
args+=(--broker "$broker")
exec "${args[@]}" -- seccomp-wrapper claude "$@"
LAUNCHER
chmod +x "$CLAUDE_SAFE_DEST"
ok "husk launcher → $CLAUDE_SAFE_DEST"

# ── SLURM brokering (optional) ────────────────────────────────────────────────
#
# Out-of-sandbox broker + fail-closed outer wrapper + in-sandbox sbatch stub. The
# `husk` launcher (installed above) auto-detects SLURM and drives these; there is no
# separate launcher. OPTIONAL: if the prebuilt broker binaries for this arch are
# absent this is skipped and plain husk still works. The binaries are prebuilt
# per-arch like seccomp-wrapper; build them first with:
#   (cd slurm-broker && ./build-release.sh)
log "SLURM brokering (optional)"

SLURM_BROKER_SRC="$SCRIPT_DIR/slurm-broker/husk-slurm-broker-${HOST_ARCH}"
SLURM_WRAPPER_SRC="$SCRIPT_DIR/slurm-broker/husk-slurm-wrapper-${HOST_ARCH}"
HUSK_SLURM_INSTALLED=0
if [[ -x "$SLURM_BROKER_SRC" && -x "$SLURM_WRAPPER_SRC" ]]; then
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
  # HUSK_SLURM_PARTITION. Trusted: under ~/.local, agent-inaccessible from the
  # sandbox. Absent → the broker uses its built-in default (preemptible).
  SLURM_PARTITION="${SLURM_PARTITION_ARG:-${HUSK_SLURM_PARTITION:-}}"
  if [[ -n "$SLURM_PARTITION" ]]; then
    printf '%s\n' "$SLURM_PARTITION" > "$PREFIX/lib/husk/slurm-partition"
    ok "SLURM partition → '$SLURM_PARTITION' (recorded in $PREFIX/lib/husk/slurm-partition)"
  else
    rm -f "$PREFIX/lib/husk/slurm-partition"
    skip "SLURM partition not set — broker default 'preemptible' (set with --slurm-partition NAME; Santis has no preemptible, use debug or shared)"
  fi
  HUSK_SLURM_INSTALLED=1
else
  skip "SLURM brokering not installed — broker binaries not built for ${HOST_ARCH}"
  echo "         enable with: (cd slurm-broker && ./build-release.sh)"
fi

# ── ~/.claude/settings.json ───────────────────────────────────────────────────
#
# Written to the user-global config so it applies to all projects without
# per-repo setup. Existing keys outside the managed blocks are preserved.
# Note: re-running the installer overwrites the managed blocks —
# any manual edits inside them will be lost.
# If apply-seccomp was not installed (unsupported arch), the seccomp.applyPath
# key is omitted rather than pointing to a non-existent binary.

log "~/.claude/settings.json"

CLAUDE_SETTINGS="${HOME}/.claude/settings.json"
mkdir -p "${HOME}/.claude"

python3 "$SCRIPT_DIR/scripts/merge-claude-settings.py" \
  "$CLAUDE_SETTINGS" "$APPLY_SECCOMP_DEST" "$SCRIPT_DIR/user-config/settings.json" \
  "$MANIFEST"

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "Sandbox ready. Active layers:"
echo "  bwrap             — filesystem namespace (system-provided)"
[[ -x "$APPLY_SECCOMP_DEST" ]] && \
echo "  apply-seccomp     — AF_UNIX + io_uring BPF filter (Anthropic)"
echo "  seccomp-wrapper   — broad syscall deny-list"
if [[ "${HUSK_SLURM_INSTALLED:-0}" == 1 ]]; then
  echo "  husk              — launcher: seccomp-wrapper claude, + SLURM job brokering"
  echo "                      (auto-detected; broker spawned only when sbatch is present)"
else
  echo "  husk              — launcher: seccomp-wrapper claude"
fi
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
