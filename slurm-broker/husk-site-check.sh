#!/bin/sh
# husk-site-check — can husk run here, and what would it need?
#
# Run this BEFORE porting husk to a new machine. It answers the one question that is
# fatal and binary (are unprivileged user namespaces available?) in about five seconds,
# and then enumerates the facts a site profile has to carry.
#
# Deliberately dependency-free POSIX sh: it must run on a machine where husk is NOT
# installed, which is the entire point. Nothing here writes outside $TMPDIR, nothing
# needs root, nothing submits a job.
#
# Exit status:  0 = GO      husk's boundary can be built here
#               1 = GAPS    it can be built, but features are missing (see the report)
#               2 = NO-GO   the boundary cannot be built; do not invest in a port
#
# Usage:  ./husk-site-check.sh          human report
#         ./husk-site-check.sh --profile  emit the draft site profile only

set -u

PROFILE_ONLY=0
[ "${1:-}" = "--profile" ] && PROFILE_ONLY=1

FATAL=0
GAPS=0
# Draft site-profile fields, accumulated as we go.
P_ARCH=""; P_KERNEL=""; P_USERNS=""; P_NEST=""; P_BWRAP=""; P_SECCOMP=""
P_GPU="none"; P_FABRIC="none"; P_MODULES="none"; P_SCHED="none"; P_MUNGE="none"
P_TMP=""; P_SOCAT="no"; P_PATHVARS=""

say()  { [ "$PROFILE_ONLY" = 1 ] || printf '%s\n' "$*"; }
ok()   { [ "$PROFILE_ONLY" = 1 ] || printf '  \033[32mok\033[0m    %s\n' "$*"; }
gap()  { GAPS=1;  [ "$PROFILE_ONLY" = 1 ] || printf '  \033[33mGAP\033[0m   %s\n' "$*"; }
bad()  { FATAL=1; [ "$PROFILE_ONLY" = 1 ] || printf '  \033[31mNO-GO\033[0m %s\n' "$*"; }
info() { [ "$PROFILE_ONLY" = 1 ] || printf '        %s\n' "$*"; }

say "husk site check — $(hostname 2>/dev/null || echo '?') — $(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
say ""

# ─────────────────────────────────────────────────────────────────────────────
# 1. THE FATAL ONE. Everything husk does rests on an unprivileged user namespace.
#    Several HPC sites disable them outright; on such a machine husk has no cage,
#    no broker and no story, and no amount of configuration changes that.
#    Tested EMPIRICALLY rather than by reading sysctls, because the sysctl names
#    differ by distro and what matters is whether the syscall succeeds.
# ─────────────────────────────────────────────────────────────────────────────
say "user namespaces (fatal if unavailable)"
P_ARCH=$(uname -m 2>/dev/null); P_KERNEL=$(uname -r 2>/dev/null)
info "arch=$P_ARCH kernel=$P_KERNEL"

USERNS_OK=0
if command -v unshare >/dev/null 2>&1 && unshare -Ur true 2>/dev/null; then
    USERNS_OK=1
elif command -v bwrap >/dev/null 2>&1 && bwrap --unshare-user --ro-bind / / true 2>/dev/null; then
    USERNS_OK=1
fi

if [ "$USERNS_OK" = 1 ]; then
    ok "unprivileged user namespaces work"; P_USERNS="yes"
else
    bad "unprivileged user namespaces are NOT available — husk cannot build a cage here"
    P_USERNS="no"
    # Report the likely reason, since the remedy is a site-admin conversation.
    for s in /proc/sys/kernel/unprivileged_userns_clone /proc/sys/user/max_user_namespaces; do
        [ -r "$s" ] && info "$s = $(cat "$s" 2>/dev/null)"
    done
    info "this is a site policy decision, not something husk can work around"
fi

# NESTING. husk's roadmap step 6a puts husk's own cage AROUND an agent runtime that
# creates its own — so the depth that matters is two, not one. A site where nesting
# is capped at one would support husk today and break 6a, which is worth knowing
# before the design depends on it.
# `--proc /proc` in BOTH cages is not optional and not cosmetic: the inner bwrap writes
# /proc/self/uid_map, so an outer cage without a writable /proc fails with "setting up uid
# map: Read-only file system" — which looks exactly like "nesting is forbidden here" and is
# not. The first version of this check made that mistake and reported a false GAP on a
# machine where nesting works fine (P9: the test proved the harness, not the property).
# husk's real cage always mounts /proc, so testing without it was unrepresentative.
if [ "$USERNS_OK" = 1 ] && command -v bwrap >/dev/null 2>&1; then
    if bwrap --unshare-user --ro-bind / / --proc /proc -- \
         bwrap --unshare-user --ro-bind / / --proc /proc true 2>/dev/null; then
        ok "user namespaces NEST (required by roadmap 6a's outer cage)"; P_NEST="yes"
    else
        gap "user namespaces do NOT nest — husk works today, 6a's outer cage would not"
        P_NEST="no"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# 2. The tools husk's boundary is made of.
# ─────────────────────────────────────────────────────────────────────────────
say ""
say "sandbox tooling"
if command -v bwrap >/dev/null 2>&1; then
    P_BWRAP=$(bwrap --version 2>/dev/null | awk '{print $NF}')
    ok "bwrap $P_BWRAP"
else
    bad "bwrap not found — husk installs its own, but the site must permit it to run"
    P_BWRAP="missing"
fi

# seccomp: husk ships its own filter binary, so the question is whether the KERNEL
# honours a filter installed by an unprivileged process with NO_NEW_PRIVS.
if [ -r /proc/sys/kernel/seccomp/actions_avail ]; then
    ok "seccomp available"; P_SECCOMP="yes"
else
    gap "cannot confirm seccomp (no /proc/sys/kernel/seccomp) — husk's syscall layer may not apply"
    P_SECCOMP="unknown"
fi

if command -v socat >/dev/null 2>&1; then
    ok "socat present (egress relay)"; P_SOCAT="yes"
else
    gap "socat not found — jobs would get no network even with an allowlist configured"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 3. AF_UNIX path budget. sun_path is 108 bytes, fixed by the kernel. husk puts the
#    egress socket under a node-local tmp dir for exactly this reason, and a site
#    with an unusually deep $TMPDIR would silently lose egress.
# ─────────────────────────────────────────────────────────────────────────────
say ""
say "socket path budget"
P_TMP="${TMPDIR:-/tmp}"
SAMPLE="$P_TMP/husk-$(id -u 2>/dev/null || echo 00000)-99999999-XXXXXX/net.sock"
if [ "${#SAMPLE}" -lt 100 ]; then
    ok "$P_TMP gives a ${#SAMPLE}-byte socket path (limit 107)"
else
    gap "$P_TMP yields a ${#SAMPLE}-byte socket path — too close to the 107-byte AF_UNIX limit"
fi
[ -w "$P_TMP" ] && ok "$P_TMP is writable" || bad "$P_TMP is not writable"

# ─────────────────────────────────────────────────────────────────────────────
# 4. Device families. These are the parts husk currently HARD-CODES for NVIDIA +
#    Slingshot; a site with different hardware needs the device list to become data.
# ─────────────────────────────────────────────────────────────────────────────
say ""
say "device families (husk currently hard-codes NVIDIA + Slingshot)"
# /dev/kfd is the AMD COMPUTE device (ROCm). /dev/dri alone is not an AMD signal — it
# exists on anything with integrated graphics, which made the first version of this check
# report "amd" on a laptop with Intel graphics.
GPUS=""
[ -e /dev/nvidiactl ] && GPUS="$GPUS nvidia"
[ -e /dev/kfd ]       && GPUS="$GPUS amd"
if [ -z "$GPUS" ] && [ -d /dev/dri ]; then GPUS="$GPUS render-only"; fi
if [ -n "$GPUS" ]; then
    P_GPU=$(echo "$GPUS" | sed 's/^ //')
    ok "GPU: $P_GPU"
    case "$P_GPU" in *amd*) gap "AMD GPUs need the device list generalised (currently NVIDIA-only)";; esac
else
    info "no GPU devices on THIS node (may still exist on compute nodes)"
fi

FAB=""
ls /dev/cxi* >/dev/null 2>&1        && FAB="$FAB slingshot"
[ -d /dev/infiniband ]              && FAB="$FAB infiniband"
if [ -n "$FAB" ]; then
    P_FABRIC=$(echo "$FAB" | sed 's/^ //')
    ok "fabric: $P_FABRIC"
    case "$P_FABRIC" in *infiniband*) gap "InfiniBand needs the fabric device list generalised (currently /dev/cxi* only)";; esac
else
    info "no fabric devices on THIS node (login nodes often have none)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 5. Scheduler + environment. Not fatal — husk degrades to a plain cage without a
#    scheduler — but every one of these is a site-profile field.
# ─────────────────────────────────────────────────────────────────────────────
say ""
say "scheduler and environment"
if command -v sbatch >/dev/null 2>&1; then
    P_SCHED=$(sbatch --version 2>/dev/null | head -1)
    ok "$P_SCHED"
else
    gap "no sbatch — husk runs as a plain cage with no brokering"
fi
for m in /run/munge/munge.socket.2 /var/run/munge/munge.socket.2; do
    [ -S "$m" ] && { P_MUNGE="$m"; ok "MUNGE socket: $m"; break; }
done
[ "$P_MUNGE" = none ] && info "no MUNGE socket here (normal on a non-SLURM machine)"

[ -n "${UENV_VIEW:-}${UENV_MOUNT_LIST:-}" ] && P_MODULES="uenv"
[ -n "${LMOD_CMD:-}${_ModuleTable001_:-}" ] && P_MODULES="${P_MODULES:+$P_MODULES,}lmod"
[ -n "${MODULE_VERSION:-}" ] && P_MODULES="${P_MODULES:+$P_MODULES,}tcl-modules"
P_MODULES="${P_MODULES#none,}"
[ "$P_MODULES" = "none" ] && info "no module system detected in this shell" || ok "modules: $P_MODULES"

# Site path variables. husk forwards an ALLOWLIST into jobs, and these names are
# site-specific — CSCS uses SCRATCH/PROJECT/STORE, other centres do not.
for v in SCRATCH PROJECT STORE WORK HOME_DIR PROJAPPL FLASH; do
    eval "val=\${$v:-}"
    [ -n "$val" ] && P_PATHVARS="${P_PATHVARS:+$P_PATHVARS,}$v"
done
[ -n "$P_PATHVARS" ] && ok "site path vars: $P_PATHVARS" || info "no recognised site path vars"

# ─────────────────────────────────────────────────────────────────────────────
# Verdict + draft profile
# ─────────────────────────────────────────────────────────────────────────────
if [ "$PROFILE_ONLY" = 0 ]; then
    say ""
    if [ "$FATAL" = 1 ]; then
        say "VERDICT: NO-GO — the boundary cannot be built here. Do not invest in a port."
    elif [ "$GAPS" = 1 ]; then
        say "VERDICT: GO WITH GAPS — husk's boundary works; the GAP lines are the porting work."
    else
        say "VERDICT: GO — no blockers found."
    fi
    say ""
    say "draft site profile (also available with --profile):"
    say ""
fi

cat <<EOF
[site]
host          = $(hostname 2>/dev/null || echo unknown)
arch          = $P_ARCH
kernel        = $P_KERNEL
userns        = $P_USERNS
userns_nested = $P_NEST
bwrap         = $P_BWRAP
seccomp       = $P_SECCOMP
socat         = $P_SOCAT
tmp           = $P_TMP
gpu           = $P_GPU
fabric        = $P_FABRIC
scheduler     = $P_SCHED
munge_socket  = $P_MUNGE
modules       = $P_MODULES
path_vars     = ${P_PATHVARS:-none}
EOF

[ "$FATAL" = 1 ] && exit 2
[ "$GAPS" = 1 ] && exit 1
exit 0
