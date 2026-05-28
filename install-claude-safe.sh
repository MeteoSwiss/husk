#!/usr/bin/env bash
# install-claude-safe.sh — Set up the Claude Code agent sandbox on CSCS supercomputers.
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
#                      from this repo's claude-safe/ directory
#   claude-safe      — launcher script: runs  seccomp-wrapper claude [args...]
#
# What this configures:
#   ~/.claude/settings.json — enables sandbox, points to apply-seccomp,
#                             restricts filesystem reads to the current project,
#                             and hard-blocks the agent from editing settings files
#
# Usage:
#   ./install-claude-safe.sh
#
# After running, add to ~/.bashrc or ~/.bash_profile if not already present:
#   export PATH="$HOME/.local/bin:$PATH"
#
# Then start Claude Code with:
#   claude-safe

set -euo pipefail

# ── Confirm before modifying ~/.claude/settings.json ─────────────────────────

SCRIPT_DIR_EARLY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "This script will merge settings into ~/.claude/settings.json."
echo "Existing settings outside these blocks are preserved."
echo ""
echo "What will be added:"
echo "  1. Sandbox isolation — restricts Claude to the current project directory;"
echo "     blocks all home directories (/users/); enables seccomp syscall filters."
echo "  2. Permission rules — pre-approves SLURM read-only commands (sinfo, squeue,"
echo "     sacct, ...); blocks credential files, nc, socat, and Claude's own"
echo "     settings files from being read or modified by the agent."
echo ""
echo "Full settings (user-config/settings.json):"
echo "────────────────────────────────────────────────────────"
cat "$SCRIPT_DIR_EARLY/user-config/settings.json"
echo "────────────────────────────────────────────────────────"
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
  APPLY_SECCOMP_DEST="$PREFIX/lib/claude-sandbox/apply-seccomp"
  if [[ -x "$APPLY_SECCOMP_DEST" ]]; then
    skip "apply-seccomp already at $APPLY_SECCOMP_DEST — nothing to do"
  else
    mkdir -p "$PREFIX/lib/claude-sandbox"
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

# ── seccomp-wrapper + claude-safe launcher ────────────────────────────────────
#
# seccomp-wrapper installs a broad syscall deny-list (ptrace, kexec_load, bpf,
# pivot_root, etc.) before exec'ing its argument. It stacks on top of
# apply-seccomp's filter — the kernel applies both, most-restrictive wins.
#
# claude-safe is a thin launcher that calls: seccomp-wrapper claude [args...]
# Users run claude-safe instead of claude.

log "seccomp-wrapper"

SECCOMP_WRAPPER_SRC="$SCRIPT_DIR/claude-safe/seccomp-wrapper-${HOST_ARCH}"
SECCOMP_WRAPPER_DEST="$PREFIX/bin/seccomp-wrapper"
SECCOMP_WRAPPER_HASH_FILE="$PREFIX/bin/seccomp-wrapper.sha256"
CLAUDE_SAFE_DEST="$PREFIX/bin/claude-safe"

if [[ ! -x "$SECCOMP_WRAPPER_SRC" ]]; then
  echo "  [error] claude-safe/seccomp-wrapper-${HOST_ARCH} not found or not executable"
  echo "          Build it on this machine: cd claude-safe && ./build_and_test.sh"
  echo "          See claude-safe/README.md for details."
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

# Always write the launcher — two lines, overwriting is harmless, and ensures
# it stays in sync if the content ever changes.
mkdir -p "$PREFIX/bin"
cat > "$CLAUDE_SAFE_DEST" <<'LAUNCHER'
#!/usr/bin/env bash
exec seccomp-wrapper claude "$@"
LAUNCHER
chmod +x "$CLAUDE_SAFE_DEST"
ok "claude-safe launcher → $CLAUDE_SAFE_DEST"

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
  "$CLAUDE_SETTINGS" "$APPLY_SECCOMP_DEST" "$SCRIPT_DIR/user-config/settings.json"

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "Sandbox ready. Active layers:"
echo "  bwrap             — filesystem namespace (system-provided)"
[[ -x "$APPLY_SECCOMP_DEST" ]] && \
echo "  apply-seccomp     — AF_UNIX + io_uring BPF filter (Anthropic)"
echo "  seccomp-wrapper   — broad syscall deny-list"
echo "  claude-safe       — launcher: seccomp-wrapper claude"
echo ""
echo "If you have not already done so, add this to ~/.bashrc or ~/.bash_profile:"
echo '  export PATH="$HOME/.local/bin:$PATH"'
echo ""
echo "Then start Claude Code with:"
echo '  claude-safe'
