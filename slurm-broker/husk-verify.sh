#!/bin/sh
# husk-verify — does the cage that is supposed to be around me ACTUALLY hold?
#
# Run this INSIDE a live husk session (login cage or compute job). It does not read
# the config and trust it; it exercises the boundary and reports what it OBSERVES.
# That distinction is the whole point, and it is the lesson this release was built on:
#
#     A boundary is what it DOES, not what you configured it to do. When husk does
#     not own the enforcer (the Anthropic harness owns the login cage), the config is
#     only a REQUEST; the boundary is the observed EFFECT. So test the boundary that
#     exists, never trust the one you asked for.
#
# THREE corollaries are baked into every check below, because all three bit us:
#   * `test -r` is a FALSE FRIEND for masking — access() returns readable on /dev/null,
#     so a masked credential passes `test -r`. We check the inode is a char device
#     (1:3 = /dev/null) instead, and we NEVER read a credential's bytes.
#   * a config-shape assertion is a false friend for enforcement — it proves husk ASKED,
#     not that the harness OBEYED. So nothing here parses settings.json to decide pass/fail.
#     (Intent — "is egress meant to work?" — is the one thing we take from config, and even
#     that is expressed as the presence of an allowed host to probe, then tested by effect.)
#   * A WRITE PROBE THAT DOES NOT READ `errno` IS A FALSE FRIEND FOR CONFINEMENT — added
#     2026-09-01, and this file named the first two and stopped one short of it. Four probes
#     here were `if ( exec 3>>"$f" ) 2>/dev/null; then fail; else pass; fi`, and POSIX `sh`
#     discards the reason: `open(O_WRONLY|O_APPEND)` fails with EROFS on a read-only bind and
#     with EACCES on a mode bit, and both took the `pass` branch. MEASURED: two `chmod 0444`
#     and one `--bind /dev/null` over an otherwise completely uncaged fake home produced
#     twelve PASS lines and `VERDICT: SECURE — every observed boundary held`, exit 0.
#     Under SAME-UID confinement the mode bit belongs to the AUDITED PARTY, so it is not
#     evidence; the rule is that a verifier the audited party can rewrite is not trustworthy —
#     negative is `is_devnull` or an EROFS read from errno — and this is where it lands.
#     EACCES is now reported as its own verdict (WARN, "refuses writes by MODE"), never PASS.
#
# AND A FOURTH THING THIS TOOL CANNOT DO, stated because a verdict is only as good as its
# stated scope: five of the twelve PASS lines in that fake-home run came from ABSENCE
# (§4a's "absent from the cage — contract holds"). `P7` says a security verdict drawn from a
# missing thing is a control that failed silently reported as a control that held — and it
# has cost this project two wrong readings already. Absence still satisfies §4a's contract
# (a write into a tmpfs never reaches the host file), so it is not a BREACH; but it is not
# the same evidence as an EROFS, so it now prints as ABSENT, is counted, and is named in the
# summary line. Read a verdict together with that count.
#
# Exit status:  0 = SECURE       every boundary check held
#               1 = BREACH        a boundary check FAILED — a real leak, do not ship
#               2 = INCONCLUSIVE  not in a cage, or no tool to run a check (never a pass)
#
# Usage:  ./husk-verify.sh
#           --allow HOST:PORT   the one host egress SHOULD reach (default: the shipped
#                               login allowlist, opendatadocs.meteoswiss.ch:443)
#           --block HOST:PORT   a host egress MUST refuse       (default: github.com:443)
#           --no-egress         egress is intentionally closed (empty allowlist); then a
#                               dead relay is fine and only the block check must hold
#
# Deliberately dependency-light POSIX sh. It must run on a bare login node and inside a
# stripped compute cage. GNU coreutils `stat -c` is assumed (as in husk-site-check.sh);
# CSCS is GNU. Nothing here writes any file: the only write is a zero-byte append that
# never modifies its target and only exists to learn whether the open is refused.

set -u

# C locale, deliberately, for TWO checks that read English out of libc/coreutils:
#   * the errno classifier below matches "Read-only file system" / "Permission denied";
#     `strerror` is locale-dependent in principle.
#   * `is_devnull` matches `stat -c '%F'` == "character special file", which coreutils
#     TRANSLATES. On a login node with a non-English locale that comparison silently fails
#     and the crown-jewel check degrades to "unexpected, inspect by hand" — so this line
#     hardens a check that predates it.
LC_ALL=C
export LC_ALL

ALLOW_HOST="opendatadocs.meteoswiss.ch:443"
BLOCK_HOST="github.com:443"
EXPECT_EGRESS=1

while [ $# -gt 0 ]; do
    case "$1" in
        --allow) ALLOW_HOST="${2:?}"; shift 2 ;;
        --block) BLOCK_HOST="${2:?}"; shift 2 ;;
        --no-egress) EXPECT_EGRESS=0; shift ;;
        -h|--help) sed -n '2,56p' "$0"; exit 0 ;;
        *) printf 'husk-verify: unknown argument %s\n' "$1" >&2; exit 2 ;;
    esac
done

BREACH=0        # a boundary check FAILED — a leak
INCONCLUSIVE=0  # a check could not be run
WARN=0          # an accepted residual worth surfacing (does not fail the verdict)
NPASS=0         # positive evidence: a boundary was exercised and held
NABSENT=0       # the contract holds because the thing is not here — NOT the same evidence
NSKIP=0
NFAIL=0

pass()   { NPASS=$((NPASS+1));     printf '  \033[32mPASS\033[0m   %s\n' "$*"; }
fail()   { BREACH=1; NFAIL=$((NFAIL+1)); printf '  \033[31mBREACH\033[0m %s\n' "$*"; }
warn()   { WARN=$((WARN+1));       printf '  \033[33;1mWARN\033[0m   %s\n' "$*"; }
skip()   { INCONCLUSIVE=1; NSKIP=$((NSKIP+1)); printf '  \033[33m????\033[0m   %s\n' "$*"; }
info()   {                         printf '         %s\n' "$*"; }
sect()   { printf '\n%s\n' "$*"; }
# ABSENT is not PASS. The contract may be satisfied — a path that does not exist cannot be
# written — but "the control held" and "there was nothing here to hold" are different
# sentences, and only one of them is evidence about a boundary (`P7`).
absent() { NABSENT=$((NABSENT+1)); printf '  \033[36mABSENT\033[0m %s\n' "$*"; }

# ─────────────────────────────────────────────────────────────────────────────
# write_disposition PATH — what does the KERNEL say about an append to this path?
#
# Echoes exactly one of:
#   WRITABLE  the open succeeded (zero bytes written; nothing modified)
#   EROFS     "Read-only file system" — a read-only bind. THE ONLY TRUSTWORTHY NEGATIVE
#             here, because it is a property of the mount and the agent does not own it.
#   EACCES    "Permission denied" — a mode bit. Under same-uid confinement that belongs to
#             the audited party: it can be set by the agent to fake this check, and it can
#             also be set by an operator for unrelated reasons. INCONCLUSIVE, never a pass.
#             NOTE it also masks a real ro-bind: the kernel checks the mode first, so a file
#             that is BOTH 0444 and ro-bound reports EACCES. "Not proof" is the claim, not
#             "no bind exists".
#   OTHER:msg anything else — say what it was rather than guessing.
#
# Zero bytes are written on every path: `exec 3>>` only opens.
# ─────────────────────────────────────────────────────────────────────────────
write_disposition() {
    _wd=$( ( exec 3>>"$1" ) 2>&1 ) && { echo WRITABLE; return; }
    case "$_wd" in
        *"Read-only file system"*)   echo EROFS ;;
        *"Permission denied"*)       echo EACCES ;;
        *"Operation not permitted"*) echo EPERM ;;
        "")                          echo "OTHER:refused with no message" ;;
        *)                           echo "OTHER:${_wd##*: }" ;;
    esac
}

# create_disposition DIR — the same question for a directory: can a NEW name be created in
# it? Same vocabulary. `set -C` so an existing name is never truncated.
create_disposition() {
    _cd_p="$1/husk-verify-writeprobe.$$"
    _cd=$( ( set -C; : > "$_cd_p" ) 2>&1 ) && { rm -f "$_cd_p" 2>/dev/null; echo WRITABLE; return; }
    case "$_cd" in
        *"Read-only file system"*)   echo EROFS ;;
        *"Permission denied"*)       echo EACCES ;;
        *"Operation not permitted"*) echo EPERM ;;
        "")                          echo "OTHER:refused with no message" ;;
        *)                           echo "OTHER:${_cd##*: }" ;;
    esac
}

# NAME THE CAGE. husk has two, they have different mount tables, and this tool has only ever
# been run in one of them. Inside a brokered job the compute cage tmpfs's `/users` and
# `/work/project/.claude`, so `~/.claude/projects` — which §3 treats as a carve-out that MUST
# be readable — does not exist by design, and running this script there would report
# `VERDICT: BREACH` at a cage that is working exactly as specified (`B7-3b`). The markers are
# husk's own: `HUSK_JOB_LOG` is exported by the generated job guard, alongside SLURM's job id.
#
# THE CAGE NAME IS A LABEL FOR THE READER, NOT A SECURITY DECISION, and it is taken from the
# environment — which is inside the cage, so `P2` says do not let it decide anything. It does
# not: every branch it selects turns an ABSENCE into a differently-worded absence, and none of
# them turns an observed leak into a pass. `is_devnull`, the home-mask reads and the egress
# probes are identical in both cages.
CAGE=login
CAGE_WHY="no SLURM job context in the environment"
if [ -n "${SLURM_JOB_ID:-}" ] && [ -n "${HUSK_JOB_LOG:-}" ]; then
    CAGE=compute
    CAGE_WHY="SLURM_JOB_ID=$SLURM_JOB_ID and HUSK_JOB_LOG set by husk's job guard"
fi

printf 'husk-verify — %s — %s\n' \
    "$(hostname 2>/dev/null || echo '?')" \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
printf 'cage        : %s (%s)\n' "$CAGE" "$CAGE_WHY"

# ─────────────────────────────────────────────────────────────────────────────
# is_devnull PATH — true iff PATH is the char device 1:3 (a husk /dev/null mask).
# This is the enforcement test for masking. `stat -c '%F %t %T'` on a GNU system
# yields "character special file 1 3" for /dev/null; %t/%T are the device major/
# minor in hex. A regular file here means the mask is NOT in force. We never open
# the file for reading, so a live credential never reaches this script or its logs.
# ─────────────────────────────────────────────────────────────────────────────
is_devnull() {
    _s=$(stat -c '%F|%t|%T' "$1" 2>/dev/null) || return 1
    [ "$_s" = "character special file|1|3" ]
}

# readable_regular PATH — true iff PATH is a regular file we can actually open and
# read a byte from. Not `test -r`: we perform the read, because that is the effect
# that matters. Used to prove the DENY side (a leak) and the ALLOW side (projects).
readable_regular() {
    [ -f "$1" ] || return 1
    dd if="$1" bs=1 count=1 >/dev/null 2>&1
}

# ─────────────────────────────────────────────────────────────────────────────
# 0. Are we even in a cage? If nothing is masked and no proxy is injected, this is a
#    bare shell — every "boundary" would trivially appear open, which is INCONCLUSIVE,
#    never a BREACH. We must not cry leak at a machine that was never asked to contain.
# ─────────────────────────────────────────────────────────────────────────────
sect "cage present?"
CAGED=0
_proxy="${HTTPS_PROXY:-${https_proxy:-}}"
case "$_proxy" in
    *localhost:*|*127.0.0.1:*)
        CAGED=1
        # Redact any embedded userinfo before printing. This tool's output is meant
        # to be pasted into transcripts, and a proxy URL is scheme://user:pass@host —
        # the auth travels with it. Same rule as the token below: a verifier must not
        # leak a credential in its own report (POSIX param-expansion, no sed needed).
        case "$_proxy" in
            *://*@*) info "egress proxy injected: ${_proxy%%://*}://<redacted>@${_proxy#*@}" ;;
            *)       info "egress proxy injected: $_proxy" ;;
        esac
        ;;
esac
CRED="$HOME/.claude/.credentials.json"
is_devnull "$CRED" && CAGED=1
# A masked home shows only the bound-back carve-outs, not the real dotfiles.
[ -e "$HOME/.ssh" ] || [ -e "$HOME/.bashrc" ] || CAGED=1

if [ "$CAGED" = 1 ]; then
    pass "a husk cage is in force around this shell"
else
    skip "no cage detected (no proxy, token not masked, home intact) — run me INSIDE a husk session"
    info "refusing to report on a boundary that was never built here"
    echo; echo "VERDICT: INCONCLUSIVE — not in a cage."
    exit 2
fi

# ─────────────────────────────────────────────────────────────────────────────
# 1. The crown jewel. The OAuth token must be masked to /dev/null, and we prove it
#    by the inode, not by test -r (which passes on /dev/null — the false friend that
#    once made this very check report "TOKEN READABLE" on a masked file).
# ─────────────────────────────────────────────────────────────────────────────
sect "credential masking (by inode, never by reading the bytes)"
if [ ! -e "$CRED" ]; then
    skip "token absent at $CRED — cannot confirm masking (expected present+masked on CSCS)"
elif is_devnull "$CRED"; then
    pass "OAuth token is /dev/null (masked)"
elif readable_regular "$CRED"; then
    fail "OAuth token is a READABLE regular file — the credential leaks into the cage"
else
    skip "token is neither /dev/null nor a readable regular file — unexpected, inspect by hand"
fi

for f in history.jsonl sessions session-env shell-snapshots .cc-writes plugins tasks daemon; do
    p="$HOME/.claude/$f"
    [ -e "$p" ] || continue
    if is_devnull "$p"; then
        pass "~/.claude/$f is masked (/dev/null)"
    elif [ -d "$p" ] && [ -z "$(ls -A "$p" 2>/dev/null)" ]; then
        pass "~/.claude/$f is masked (empty tmpfs)"
    elif [ -d "$p" ]; then
        # A DIRECTORY with contents. This branch exists because the one below it could
        # never fire for a directory — `readable_regular` starts with `[ -f ]`, and all but
        # one name on this list IS a directory, so the failure path was dead for six of
        # seven. A populated, fully readable ~/.claude/daemon produced "(ok)" and a SECURE
        # exit: the finding that motivated masking it, reported as fine (P9).
        fail "~/.claude/$f is a READABLE directory ($(ls -A "$p" 2>/dev/null | wc -l) entries) — the mask did not take"
    elif readable_regular "$p"; then
        fail "~/.claude/$f is readable — session/history material leaks"
    else
        info "~/.claude/$f present but not a readable regular file (ok)"
    fi
done

# The credential itself, by name. The loop above judges the DIRECTORY; this asserts the
# thing the directory was masked FOR. `control.key` is 16 random bytes (hex) written 0600 —
# the bearer secret for the local `cc-daemon-<uid>` control socket, which lives in a /tmp
# that K7 records as shared and host-visible from the login cage. Never read its bytes.
_ck="$HOME/.claude/daemon/control.key"
if [ ! -e "$_ck" ]; then
    info "no daemon control key present (nothing to mask yet — not evidence of masking)"
elif is_devnull "$_ck"; then
    pass "daemon control.key is /dev/null (masked)"
elif readable_regular "$_ck"; then
    fail "daemon control.key is READABLE — the bearer secret for the cc-daemon control socket"
else
    pass "daemon control.key is present but not readable"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 2. The home mask. denyRead /users turns the home into a tmpfs that shows only the
#    bound-back carve-outs (~/.claude, ~/.local). If any of the real sensitive dotfiles
#    can actually be READ, the mask is not holding. We read a byte to be sure — presence
#    of a name in a tmpfs listing would not, on its own, mean the bytes are there.
# ─────────────────────────────────────────────────────────────────────────────
sect "home directory mask (actual reads under \$HOME)"
LEAKED=""
# `.husk/config.json` is here deliberately and is not a credential: it is the OPERATOR's
# policy, and beside it lives `~/.husk/log/job-<id>.log` — the trusted record, which now
# carries the proxy's `allowed:`/`refused:` lines. The audited party reading the audit
# trail is a P2 concern even read-only. MEASURED 2026-08-25 on Balfrin: the file exists on
# the host and is ABSENT inside the cage, so the home mask covers it. This pins that — a
# `denyWrite` entry on the same path was suspected (wrongly) of re-binding it into view,
# and a future edit could make that true.
for s in .ssh/id_rsa .ssh/id_ed25519 .netrc .aws/credentials .config/gh/hosts.yml \
         .gitconfig .bash_history .pgpass .husk/config.json; do
    p="$HOME/$s"
    if readable_regular "$p"; then LEAKED="$LEAKED $s"; fi
done
if [ -n "$LEAKED" ]; then
    fail "readable sensitive files under a home that should be masked:$LEAKED"
else
    pass "no sensitive home dotfile is readable (home mask holds)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 3. The ALLOW side of the filesystem. projects is deliberately left readable (husk
#    memories live with the code, but the agent must still read its own project state).
#    Prove it is a real, listable directory — not masked to an empty tmpfs by mistake.
# ─────────────────────────────────────────────────────────────────────────────
sect "readable carve-outs"
PROJ="$HOME/.claude/projects"
if [ -d "$PROJ" ] && [ -n "$(ls -A "$PROJ" 2>/dev/null)" ]; then
    pass "~/.claude/projects is readable and non-empty"
elif [ -d "$PROJ" ]; then
    skip "~/.claude/projects is a directory but empty — expected the live session's project"
elif [ "$CAGE" = compute ]; then
    # THE ONE SECTION THAT WOULD FLIP TO A HARD BREACH IN A CAGE THAT IS WORKING. The compute
    # cage puts a tmpfs over `/users` and over `/work/project/.claude`, so this carve-out is
    # removed on purpose; a job has no session state to read. Calling that a leak would send
    # an operator hunting a breach that is the specification (`B7-3b`).
    absent "~/.claude/projects is not here — the compute cage tmpfs's the home by design, so there is no session-state carve-out inside a brokered job"
else
    fail "~/.claude/projects is not a readable directory — the agent lost its own state"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 3b. Secret scan of the ~/.local carve-out. To make the login egress relay work we
#    re-expose ~/.local (allowRead), and XDG co-mingles credentials with code under it,
#    so no clean directory rule masks the secrets without also masking the tools the
#    agent needs. A credential-location survey (2026-08-25) found that with the rest of
#    $HOME masked, exactly THREE credential stores fall under ~/.local — everything else
#    (aws/gcloud/docker/npm/cargo/ssh/kube…) lives in ~/.config, ~/.cache or a $HOME
#    dotfolder and is already masked. We check those three by name (finite, verified)
#    AND run a content-signature sweep as the heterogeneity net for whatever a future
#    tool drops elsewhere under ~/.local. Detective, not preventive: strict egress is
#    the real backstop (a read secret can't leave) and the clean fix is the v0.6a
#    constructed home. A hit is a WARN, not a BREACH — the carve-out is an accepted
#    residual, but a plaintext credential readable in the cage is worth seeing.
#    Filenames only, never the bytes.
# ─────────────────────────────────────────────────────────────────────────────
sect "carve-out secret scan (~/.local)"
if [ -d "$HOME/.local" ]; then
    _found=0
    # (1) The three stores the survey confirmed land under ~/.local/share.
    if [ -n "$(ls -A "$HOME/.local/share/uv/credentials" 2>/dev/null)" ]; then
        warn "uv credential store present: ~/.local/share/uv/credentials/ (plaintext tokens)"; _found=1
    fi
    if [ -e "$HOME/.local/share/python_keyring/keyring_pass.cfg" ]; then
        warn "keyring file-backend present: ~/.local/share/python_keyring/ (pip/poetry/uv secrets on headless nodes)"; _found=1
    fi
    if [ -n "$(ls -A "$HOME/.local/share/keyrings" 2>/dev/null)" ]; then
        info "libsecret keyring present: ~/.local/share/keyrings/ (encrypted at rest — lower risk, but readable)"
    fi
    # (2) Content-signature sweep — matches the secret VALUE (a long token / a PRIVATE
    #     KEY header), never a keyword, so stdlib token.py/secrets.py and certifi's
    #     public cacert.pem don't trip it. `-size -1048576c` (BYTES, not `-1M` — that
    #     rounds up per-file and would match only EMPTY files) skips the ~1GB version
    #     binaries; grep -I skips binary files (incl. the encrypted keyrings above).
    _sig='-----BEGIN [A-Z ]*PRIVATE KEY-----|sk-ant-[A-Za-z0-9_-]{24,}|sk-proj-[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{12,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}'
    # `-e` is REQUIRED: the pattern starts with `-----BEGIN`, and without -e grep eats
    # those dashes as options and the whole sweep silently matches nothing.
    _hits=$(find "$HOME/.local" -type f -size -1048576c 2>/dev/null \
            | xargs -r -d '\n' grep -lIE -e "$_sig" 2>/dev/null)
    if [ -n "$_hits" ]; then
        warn "plaintext credential signature(s) readable under the ~/.local carve-out:"
        printf '%s\n' "$_hits" | sed 's/^/           - /'
        _found=1
    fi
    if [ "$_found" = 1 ]; then
        info "egress is the backstop (a read secret can't leave); mask these or accept the residual"
    else
        pass "no credential store or plaintext secret signature under the ~/.local carve-out"
    fi
else
    info "~/.local not present in the cage — nothing to scan"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 4. settings.json must be unwritable — the confined side must not edit its own cage.
#    Tested by an ACTUAL open-for-append that writes ZERO bytes: opening O_WRONLY on a
#    read-only bind fails with EROFS before any byte is written, so this is both a real
#    enforcement test and non-destructive. `test -w` would be the config-shape shortcut.
# ─────────────────────────────────────────────────────────────────────────────
sect "self-edit protection (real open-for-append, zero bytes written)"
_selfedit=0
for cfg in "$HOME/.claude/settings.json" ".claude/settings.json"; do
    [ -e "$cfg" ] || continue
    _selfedit=$((_selfedit+1))
    _wdv="$(write_disposition "$cfg")"
    case "$_wdv" in
        WRITABLE) fail "$cfg is WRITABLE from inside the cage — the agent can edit its own boundary" ;;
        EROFS)    pass "$cfg refuses writes: EROFS, a read-only bind (the mount, not a mode bit)" ;;
        EACCES)   warn "$cfg refuses writes by MODE (EACCES), which under same-uid confinement the agent owns — INCONCLUSIVE, not a boundary. A read-only bind would say EROFS." ;;
        EPERM)    warn "$cfg refuses writes with EPERM — not a read-only bind; inspect by hand" ;;
        OTHER:*)  skip "$cfg refused an append for an unexpected reason: ${_wdv#OTHER:}" ;;
    esac
done
if [ "$_selfedit" = 0 ]; then
    # NOT SILENCE. Both files being absent used to print nothing at all — a whole section
    # with no line in the report, which reads as "nothing to say" and means "nothing was
    # checked" (`P7`).
    if [ "$CAGE" = compute ]; then
        absent "neither settings.json exists in this cage — the compute cage masks the home, so self-edit protection is a LOGIN-cage question and was not asked here"
    else
        skip "neither ~/.claude/settings.json nor ./.claude/settings.json exists — self-edit protection was NOT tested"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# 4a. THE CONTRACT: every file the broker reads POLICY from must be one the agent
#    cannot change. Not "must appear in denyWrite" — that is a mechanism, and asserting
#    a mechanism is how a shape test becomes a false friend (P9). Three different
#    mechanisms satisfy this contract and any one of them is enough:
#       * the path is MASKED OUT OF EXISTENCE by denyRead (a write lands in the tmpfs
#         and is discarded — it never reaches the host file);
#       * `allowWrite: []` leaves it outside the writable set (EROFS);
#       * an explicit denyWrite re-binds it read-only.
#    So the check is the CONTRACT: absent-or-unwritable. It matters because the broker
#    reads its egress allowlist from settings.json and its account/partition policy from
#    ~/.husk/config.json — a writable one lets the agent grant itself network, or a
#    partition it was never given (P2/F17).
# ─────────────────────────────────────────────────────────────────────────────
sect "policy inputs the broker reads (contract: absent OR unwritable)"
for _pol in "$HOME/.husk/config.json" "$HOME/.claude/settings.json" ".claude/settings.json"; do
    if [ ! -e "$_pol" ]; then
        absent "$_pol is absent from the cage (masked out of existence — the contract holds, but nothing here was exercised)"
        continue
    fi
    _wdv="$(write_disposition "$_pol")"
    case "$_wdv" in
        WRITABLE) fail "$_pol is WRITABLE — the agent can edit the policy the broker obeys" ;;
        EROFS)    pass "$_pol refuses writes: EROFS, a read-only bind" ;;
        EACCES)   warn "$_pol refuses writes by MODE (EACCES) — the agent owns that bit, so this is not evidence the broker's policy input is protected" ;;
        EPERM)    warn "$_pol refuses writes with EPERM — not a read-only bind; inspect by hand" ;;
        OTHER:*)  skip "$_pol refused an append for an unexpected reason: ${_wdv#OTHER:}" ;;
    esac
done

# ─────────────────────────────────────────────────────────────────────────────
# 4b. Confiner integrity. settings.json is the cage's CONFIG; these binaries are the
#    cage's CODE. They live in ~/.local/bin — INSIDE the ~/.local carve-out we open for
#    the egress relay — so the agent can read them, and if it could also WRITE one it
#    would rewrite its own confiner: the next `husk` launch executes attacker bytes as
#    the operator, outside every cage. That is F17 ("the agent must not author its
#    cage") one level down from the config.
#    `allowWrite: []` should already make these read-only, and a synergizer pass argued
#    exactly that — but an inferred boundary is not a boundary (the whole point of this
#    tool), so we attempt the write. Same non-destructive zero-byte append as above.
# ─────────────────────────────────────────────────────────────────────────────
sect "confiner integrity (can the agent rewrite the code that cages it?)"
_checked=0
for _bin in husk seccomp-wrapper husk-slurm-broker husk-slurm-wrapper socat; do
    _p="$HOME/.local/bin/$_bin"
    [ -e "$_p" ] || continue
    _checked=$((_checked+1))
    _wdv="$(write_disposition "$_p")"
    case "$_wdv" in
        WRITABLE) fail "~/.local/bin/$_bin is WRITABLE — the agent can rewrite its own confiner" ;;
        EROFS)    pass "~/.local/bin/$_bin refuses writes: EROFS, a read-only bind" ;;
        EACCES)   warn "~/.local/bin/$_bin refuses writes by MODE (EACCES) only — a mode bit the agent owns is not what stops it rewriting its own confiner" ;;
        EPERM)    warn "~/.local/bin/$_bin refuses writes with EPERM — not a read-only bind; inspect by hand" ;;
        OTHER:*)
            # ETXTBSY is not an unknown answer, it is the WRONG QUESTION. A binary that is
            # currently executing — the broker serving this session, the socat relay behind
            # the egress proxy — cannot be opened for write at all, and the kernel says so
            # BEFORE consulting the mount. So the file cannot answer; the directory holding it
            # can, and it is not executing. `allowWrite: []` makes the whole filesystem
            # read-only outside the workdir, so ~/.local/bin is covered by one bind rather
            # than five per-file ones (settings.rs:4436) — probing the directory is direct
            # evidence about the same mount, not an inference from a sibling.
            #
            # Measured on Balfrin 2026-09-01: this arm returned INCONCLUSIVE for
            # husk-slurm-broker and socat, both running, while three siblings in the same
            # directory reported EROFS. Two honest "cannot tell" answers where the evidence
            # was one probe away (`P11`).
            case "${_wdv#OTHER:}" in
                *"Text file busy"*|*ETXTBSY*)
                    _dirv="$(create_disposition "$HOME/.local/bin")"
                    case "$_dirv" in
                        EROFS)
                            pass "~/.local/bin/$_bin is running (ETXTBSY), so it cannot be probed directly — but a NEW name in ~/.local/bin is refused with EROFS, and one read-only bind covers the directory" ;;
                        WRITABLE)
                            fail "~/.local/bin/$_bin is running (ETXTBSY) and its DIRECTORY is writable — the agent cannot rewrite the running binary but can replace it for the next launch" ;;
                        *)
                            skip "~/.local/bin/$_bin is running (ETXTBSY) and ~/.local/bin answered '${_dirv}' — neither the file nor its directory could be established" ;;
                    esac
                    unset _dirv ;;
                *) skip "~/.local/bin/$_bin refused an append for an unexpected reason: ${_wdv#OTHER:}" ;;
            esac ;;
    esac
done
if [ "$_checked" = 0 ]; then
    if [ "$CAGE" = compute ]; then
        absent "no husk binaries under ~/.local/bin — the compute cage tmpfs's ~/.local, so confiner integrity is a LOGIN-cage question and was not asked here"
    else
        skip "no husk binaries found under ~/.local/bin — cannot verify confiner integrity"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# 4b2. THE VERIFIER'S OWN BYTES. §4b lists `husk seccomp-wrapper husk-slurm-broker
#    husk-slurm-wrapper socat` — and not this file, which is the instrument whose verdict IS
#    release criterion 2. The runbook runs it out of the operator's checkout
#    (`!~/husk/slurm-broker/husk-verify.sh`), and if a husk session is launched in or above
#    that checkout the script is inside the writable project root: the agent can then rewrite
#    the tool that judges it. `F17` aimed at the auditor rather than the confiner, and `P2`'s
#    "the audited party must not author the audit trail" one level up.
#
#    WARN, never BREACH. Whether the checkout is writable is an operator's launch choice, not
#    a husk defect, and turning a legitimate working configuration into a red verdict would
#    make this tool refuse to certify the setup it is normally run in. What was missing was
#    the DATUM, which nobody had ever captured. Now every run carries it.
# ─────────────────────────────────────────────────────────────────────────────
sect "the verifier's own integrity (can the audited party rewrite its auditor?)"
_self="$0"
case "$_self" in /*) : ;; *) _self="$(pwd)/$_self" ;; esac
if [ ! -f "$_self" ]; then
    skip "cannot locate this script's own file (\$0=$0) — self-integrity not checked"
else
    _wdv="$(write_disposition "$_self")"
    case "$_wdv" in
        WRITABLE) warn "THIS SCRIPT IS WRITABLE from inside the cage: $_self — the confined side can rewrite the instrument whose VERDICT is a release criterion. Not a cage defect; a property of where husk was launched. Treat this run's verdict as trusted only if you also trust the bytes." ;;
        EROFS)    pass "this script is read-only in this cage (EROFS): the verdict's own bytes are outside the writable set" ;;
        EACCES)   warn "this script refuses writes by MODE (EACCES) only — a bit the agent owns; the verifier's integrity rests on nothing structural" ;;
        EPERM)    warn "this script refuses writes with EPERM — not a read-only bind; inspect by hand" ;;
        OTHER:*)  skip "could not classify a write to this script: ${_wdv#OTHER:}" ;;
    esac
fi

# ─────────────────────────────────────────────────────────────────────────────
# 4c. The runtime's OWN default write paths, which husk never asked for. The vendored
#    `getDefaultWritePaths()` is unioned in unconditionally:
#
#        allowOnly: [...getDefaultWritePaths(), ...userAllowWrite]
#
#    so `allowWrite: []` means "no ADDITIONAL write paths", NOT "nothing is writable".
#    Two of the defaults land inside trees husk treats as sensitive — `~/.claude/debug`
#    and `~/.npm/_logs` are under the masked home, and `/tmp/claude` is on a /tmp that
#    A9 measured as shared and host-visible on CSCS.
#
#    READ exposure of ~/.claude is NOT the point here and is already handled: the CLI
#    binds ~/.claude back over the home mask, which is exactly why the shipped config masks
#    its children by name. This section is about WRITE, a separate axis with a separate
#    control — and `allowWrite: []` does not cover it, because the defaults are unioned in
#    regardless.
#
#    Whether a given default actually ends up writable depends on mount ordering (tmpfs
#    over the home, write paths re-bound, the CLI's ~/.claude bind, then the child masks),
#    which is not worth predicting — that is what this probe is for.
#
#    Latent, not theoretical: the hole needs the directory to exist, which for
#    ~/.claude/debug means the first time anyone runs with debug logging. The remedy if it
#    fires is one denyWrite entry — denyWrite takes precedence over allowWrite — and it
#    fits the rule rather than breaking it, since the path IS inside the writable set.
# ─────────────────────────────────────────────────────────────────────────────
sect "runtime default write paths (husk did not ask for these)"
_dflt=0
for _d in "$HOME/.claude/debug" "$HOME/.npm/_logs" "/tmp/claude"; do
    [ -e "$_d" ] || continue
    _dflt=1
    # The FOURTH errno-blind probe. The finding that named the class listed three and this
    # one was missed, because it spells the write differently (`set -C; : >` rather than
    # `exec 3>>`) — so the sweep that would have caught it grepped for the wrong string
    # (`D1`, attack 1). Same blindness, and it emitted `pass`, not `warn`.
    _cdv="$(create_disposition "$_d")"
    case "$_cdv" in
        WRITABLE) warn "$_d is WRITABLE — a runtime default, inside a tree husk masks"
                  info "denyWrite takes precedence over allowWrite, so one entry closes it" ;;
        EROFS)    pass "$_d exists but refuses writes: EROFS, a read-only bind" ;;
        EACCES)   warn "$_d exists and refuses writes by MODE (EACCES) only — not a bind, and the mode is the agent's to change" ;;
        EPERM)    warn "$_d exists and refuses writes with EPERM — not a read-only bind; inspect by hand" ;;
        OTHER:*)  skip "$_d refused a create for an unexpected reason: ${_cdv#OTHER:}" ;;
    esac
done
# `pass` here was a verdict from absence about paths husk never asked for: it says the hole
# is not open YET (the hole needs the directory to exist), which is worth printing and is
# not a boundary that held.
[ "$_dflt" = 0 ] && absent "none of the runtime's default write paths exist in this cage — the hole is latent, not closed"

# ─────────────────────────────────────────────────────────────────────────────
# 5. Egress. The proxy blocks at CONNECT: a refused host yields curl exit 56 with a
#    403 tunnel failure (proxy UP, host not on the allowlist); an unreachable proxy
#    yields exit 7/28 (relay DOWN). That difference is the whole reason relay-down is a
#    HARD FAIL whenever an allowlist exists — a dead relay silently turns "reach exactly
#    these hosts" into "reach nothing", and a silent downgrade is the failure mode husk
#    is meant to make impossible. An OPEN result to the BLOCK host is the loud breach.
# ─────────────────────────────────────────────────────────────────────────────
sect "egress boundary"

# probe_host HOST:PORT  ->  echoes OPEN | BLOCKED | DOWN | NOTOOL
probe_host() {
    _hp="$1"; _h="${_hp%:*}"; _p="${_hp##*:}"
    if command -v curl >/dev/null 2>&1; then
        _err=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 12 \
                    "https://$_h:$_p/" 2>&1); _rc=$?
        if [ "$_rc" = 0 ]; then echo OPEN; return; fi
        case "$_err" in
            *403*|*tunnel*|*Tunnel*) echo BLOCKED; return ;;
        esac
        echo DOWN; return   # exit 7/28/35: proxy unreachable, timeout, or TLS to a dead relay
    elif command -v python3 >/dev/null 2>&1; then
        python3 - "$_h" "$_p" <<'PY'
import os, sys, urllib.request, urllib.error
host, port = sys.argv[1], sys.argv[2]
proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
op = urllib.request.ProxyHandler({"https": proxy} if proxy else {})
try:
    urllib.request.build_opener(op).open(f"https://{host}:{port}/", timeout=12)
    print("OPEN")
except urllib.error.HTTPError:
    print("OPEN")               # HTTP response from the ORIGIN → the tunnel opened
except Exception as e:
    print("BLOCKED" if "403" in str(e) else "DOWN")
PY
    else
        echo NOTOOL
    fi
}

if [ "$EXPECT_EGRESS" = 1 ]; then
    A=$(probe_host "$ALLOW_HOST")
    case "$A" in
        OPEN)    pass "allowlisted host reachable: $ALLOW_HOST" ;;
        BLOCKED) fail "allowlisted host is BLOCKED: $ALLOW_HOST — egress is broken/misconfigured" ;;
        DOWN)    fail "RELAY DOWN: allowlisted host $ALLOW_HOST unreachable while an allowlist exists"
                 info "a dead relay silently downgrades 'reach exactly these' to 'reach nothing' — hard fail" ;;
        NOTOOL)  skip "no curl or python3 to probe egress" ;;
    esac
else
    info "egress intentionally closed (--no-egress); relay-down is acceptable"
fi

B=$(probe_host "$BLOCK_HOST")
case "$B" in
    BLOCKED) pass "non-allowlisted host refused: $BLOCK_HOST" ;;
    OPEN)    fail "non-allowlisted host REACHED: $BLOCK_HOST — egress is NOT strict (leak)" ;;
    DOWN)    if [ "$EXPECT_EGRESS" = 1 ]; then
                 skip "block host $BLOCK_HOST unreachable (relay may be down; see egress result above)"
             else
                 pass "no egress at all (block host unreachable, egress intentionally closed)"
             fi ;;
    NOTOOL)  skip "no curl or python3 to probe egress" ;;
esac

# ─────────────────────────────────────────────────────────────────────────────
# Verdict
# ─────────────────────────────────────────────────────────────────────────────
echo
# ONE MACHINE-GREPPABLE LINE, the shape `smoke.c` has had since it was written and that
# `build_and_test.sh` finally started reading this round (`B6-4`). Until now the only token a
# transcript could be graded on was `VERDICT:`, and a verdict says nothing about how much of
# it came from absence. Read the two together.
printf 'husk-verify summary: cage=%s pass=%d breach=%d inconclusive=%d warn=%d from-absence=%d\n' \
    "$CAGE" "$NPASS" "$NFAIL" "$NSKIP" "$WARN" "$NABSENT"
echo
if [ "$BREACH" = 1 ]; then
    echo "VERDICT: BREACH — a boundary that should hold does not. Do not ship this cage."
    exit 1
elif [ "$INCONCLUSIVE" = 1 ]; then
    echo "VERDICT: INCONCLUSIVE — some checks could not run; treat as not-yet-verified."
    exit 2
elif [ "$WARN" -gt 0 ]; then
    echo "VERDICT: SECURE (with $WARN advisory) — every ENFORCED boundary held; see WARN above (carve-out exposure, backstopped by strict egress)."
    exit 0
else
    echo "VERDICT: SECURE — every observed boundary held."
    exit 0
fi
