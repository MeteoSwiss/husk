#!/usr/bin/env bash
# verify-uenv-passthrough.sh — how should the broker submit a job from within a
# started uenv session? Answer it on hardware instead of guessing.
#
# uenv v10.0 disables sbatch/salloc from inside a `uenv start` session by default
# ("Calling sbatch/salloc from inside a uenv session is disabled by default") and
# adds --uenv-passthrough={use,ignore,disable} to control it. We got bitten forcing
# a mount-qualified --view (UENV_VIEW=/user-environment:icon:default is NOT a valid
# --view arg). This probe submits the SAME tiny job several ways and reports, for
# each, whether it (a) SUBMITTED, (b) MOUNTED the uenv, and (c) ACTIVATED the view
# (PATH points into the mount) — so we can pick the broker's approach with evidence.
#
# Variants:
#   passthrough        --uenv-passthrough=use                       (default export=ALL)
#   passthrough_allow  --uenv-passthrough=use  + locked --export    (the broker's posture)
#   explicit_noview    --uenv=<label>          + locked --export    (current committed fix)
#   explicit_view      --uenv=<label> --view=<fixed> + locked --export  (explicit + corrected view)
#
# A variant that fails AT SUBMIT (e.g. unknown --uenv-passthrough on uenv <10.0, or
# "invalid view description") is reported with its sbatch error — that is a result,
# not a crash.
#
# Run from a NORMAL shell INSIDE a uenv session (after `uenv start …`), NOT inside
# husk. No sandbox/broker involved — pure platform probe.
#
# Config via env: PARTITION (default preemptible), ACCOUNT (optional),
#                 TIMELIMIT (default 00:02:00), LABEL (default $UENV_LABEL/$UENV_MOUNT_LIST).
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '1d; /^#/!q; s/^#//; s/^ //; p' "$0"; exit 0
fi

die() { echo "error: $*" >&2; exit 1; }
command -v sbatch >/dev/null 2>&1 || die "sbatch not on PATH (load SLURM first)."
[[ -n "${UENV_MOUNT_LIST:-}" ]] || die "not in a uenv session (UENV_MOUNT_LIST unset). Run 'uenv start …' first."

PARTITION="${PARTITION:-preemptible}"
ACCOUNT="${ACCOUNT:-}"
TIMELIMIT="${TIMELIMIT:-00:02:00}"
# --uenv argument: prefer a label; UENV_MOUNT_LIST (file:mount-point pairs) is itself
# a valid --uenv argument and always present, so fall back to it.
LABEL="${LABEL:-${UENV_LABEL:-${UENV_MOUNT_LIST:-}}}"
[[ -n "$LABEL" ]] || die "could not determine a --uenv argument. Set LABEL=… and re-run."

# Correct the --view value: UENV_VIEW is mount-qualified on uenv v10 (e.g.
# /user-environment:icon:default); --view wants uenvname:viewname. Drop a leading
# /mount-point field if present.
VIEW_RAW="${UENV_VIEW:-}"
VIEW_FIXED="$VIEW_RAW"
case "$VIEW_FIXED" in
  /*) VIEW_FIXED="${VIEW_FIXED#*:}" ;;   # "/user-environment:icon:default" -> "icon:default"
esac

# The broker's locked export allowlist (mirror of session.rs::EXPORT_ALLOWLIST).
ALLOWLIST="UENV_MOUNT_LIST,UENV_VIEW,UENV_REPO,UENV_LABEL,SLURM_UENV,SLURM_UENV_VIEW,SLURM_UENV_REPO"

echo "uenv (--uenv arg)  : $LABEL"
echo "UENV_VIEW (raw)    : ${VIEW_RAW:-<unset>}"
echo "--view (corrected) : ${VIEW_FIXED:-<unset>}"
echo "Partition          : $PARTITION${ACCOUNT:+   Account: $ACCOUNT}"
echo

# ── detection: what would the broker key its submission strategy on? ─────────────
# Purely informational + time-bounded: `uenv` may be a shell function and `sbatch
# --help` can be slow, so never let detection block the actual probe. (The passthrough
# variant below is the authoritative capability check anyway — it just tries it.)
echo "== detection (informs the broker's submit strategy) =="
uenv_ver="$(timeout 8 uenv --version 2>&1 | head -1 || true)"
echo "  uenv --version            : ${uenv_ver:-<unavailable / not a command here>}"
if timeout 8 sbatch --help 2>/dev/null | grep -qi 'uenv-passthrough'; then
  echo "  sbatch --uenv-passthrough : SUPPORTED (uenv v10+ path is available)"
else
  echo "  sbatch --uenv-passthrough : not detected here (see the passthrough variant below)"
fi
echo

WORK="$PWD/.uenv-passthrough-probe.$$"      # MUST be on the shared FS (compute node writes --output here)
mkdir -p "$WORK"
trap 'rm -f "$WORK"/probe.sh' EXIT           # keep outputs for inspection; drop the probe body
PROBE="$WORK/probe.sh"
cat > "$PROBE" <<'EOF'
#!/bin/bash
echo "host=$(hostname)"
echo "UENV_MOUNT_LIST=${UENV_MOUNT_LIST:-<unset>}"
echo "UENV_VIEW=${UENV_VIEW:-<unset>}"
if grep -qi squashfs /proc/mounts || [ -d /user-environment ]; then
  echo "MOUNT=yes"
else
  echo "MOUNT=no"
fi
# View activation: an active view prepends its bin dirs (under the mount) to PATH.
if printf '%s' "$PATH" | tr ':' '\n' | grep -q '^/user-environment'; then
  echo "VIEW_ACTIVE=yes"
else
  echo "VIEW_ACTIVE=no"
fi
echo "uenv_path_entries=$(printf '%s' "$PATH" | tr ':' '\n' | grep -c '^/user-environment')"
echo "PATH=$PATH"
EOF
chmod +x "$PROBE"

declare -A JID DESC ERRTXT
ORDER=(passthrough passthrough_allow explicit_noview explicit_view explicit_noview_all explicit_view_all)

run_variant() { # tag desc extra-args...
  local tag="$1" desc="$2"; shift 2
  DESC[$tag]="$desc"
  local e="$WORK/submit.$tag.err" j
  if j=$(sbatch --parsable \
        --partition="$PARTITION" ${ACCOUNT:+--account="$ACCOUNT"} \
        --time="$TIMELIMIT" --nodes=1 --ntasks=1 \
        --job-name="uenvpt-$tag" \
        --output="$WORK/out.$tag.%j" \
        "$@" "$PROBE" 2>"$e"); then
    JID[$tag]="$j"
    echo "  submitted $tag -> job $j"
  else
    JID[$tag]=""
    ERRTXT[$tag]="$(tr '\n' ' ' < "$e" | sed 's/  */ /g')"
    echo "  SUBMIT FAILED $tag: ${ERRTXT[$tag]}"
  fi
}

echo "==> Submitting probe variants..."
run_variant passthrough       "--uenv-passthrough=use (export=ALL default)" \
              --uenv-passthrough=use
run_variant passthrough_allow "--uenv-passthrough=use + locked --export" \
              --uenv-passthrough=use --export="$ALLOWLIST"
run_variant explicit_noview   "--uenv=<label> + locked --export (committed fix)" \
              --uenv="$LABEL" --export="$ALLOWLIST"
if [[ -n "$VIEW_FIXED" ]]; then
  run_variant explicit_view   "--uenv=<label> --view=$VIEW_FIXED + locked --export" \
              --uenv="$LABEL" --view="$VIEW_FIXED" --export="$ALLOWLIST"
else
  DESC[explicit_view]="(skipped: no UENV_VIEW to correct)"; JID[explicit_view]=""
fi
# The chosen posture: export=ALL (inherit the trusted session). Does the EXPLICIT
# path activate the view under export=ALL — with and without --view — so we know
# whether a uniform (branch-free) broker path works on both machines?
run_variant explicit_noview_all "--uenv=<label> + --export=ALL (no --view)" \
              --uenv="$LABEL" --export=ALL
if [[ -n "$VIEW_FIXED" ]]; then
  run_variant explicit_view_all "--uenv=<label> --view=$VIEW_FIXED + --export=ALL" \
              --uenv="$LABEL" --view="$VIEW_FIXED" --export=ALL
else
  DESC[explicit_view_all]="(skipped: no UENV_VIEW to correct)"; JID[explicit_view_all]=""
fi
echo

echo "==> Waiting for submitted jobs to finish..."
ids="$(printf '%s,' "${JID[@]}" | sed 's/,,*/,/g; s/^,//; s/,$//')"
if [[ -n "$ids" ]]; then
  for _ in $(seq 1 120); do
    left=$(squeue -h -j "$ids" 2>/dev/null | wc -l || echo 0)
    [[ "$left" -eq 0 ]] && break
    sleep 5
  done
fi
echo

for tag in "${ORDER[@]}"; do
  echo "######## $tag — ${DESC[$tag]:-} ########"
  if [[ -z "${JID[$tag]:-}" ]]; then
    echo "  SUBMIT FAILED: ${ERRTXT[$tag]:-<not submitted>}"
  else
    f=$(ls "$WORK"/out.$tag.* 2>/dev/null | head -1 || true)
    if [[ -n "$f" && -f "$f" ]]; then sed 's/^/  /' "$f"; else
      echo "  (no output yet — job ${JID[$tag]} may still be queued; check $WORK/out.$tag.* later)"
    fi
  fi
  echo
done

cat <<EOF
── how to read it → broker decision ─────────────────────────────────────────────
Look at MOUNT and VIEW_ACTIVE for each variant that SUBMITTED:

  passthrough SUBMIT FAILED with "invalid option / --uenv-passthrough"
      -> uenv on this system is < v10.0; the flag doesn't exist. Use the explicit
         path: broker forces --uenv=<label> (+ --view=<corrected> if a view is needed).

  passthrough  MOUNT=yes VIEW_ACTIVE=yes,  AND
  passthrough_allow same
      -> CLEANEST: broker forces --uenv-passthrough=use; it composes with the locked
         --export. Drop the hand-rolled --uenv/--view entirely.

  passthrough works but passthrough_allow does NOT (mount/view lost)
      -> the locked --export clobbers passthrough; broker must widen --export (or not
         lock it when passing through). Note which vars differ.

  explicit_noview VIEW_ACTIVE=no  but  explicit_view VIEW_ACTIVE=yes
      -> the committed "drop --view" fix MOUNTS but does NOT activate the view. Broker
         must pass a corrected --view=$VIEW_FIXED (not the raw UENV_VIEW).

  explicit_noview VIEW_ACTIVE=yes
      -> env-carried UENV_VIEW activates the view; the committed fix is sufficient.

  --- with the chosen posture (export=ALL) ---
  explicit_view_all / explicit_noview_all  MOUNT=yes VIEW_ACTIVE=yes on BOTH machines
      -> the broker can use ONE uniform, branch-free path: --uenv=<label>
         [--view=<normalized>] --export=ALL. No version detection needed. (Compare
         explicit_view_all vs explicit_noview_all: if both activate, --view is only a
         marker and can be dropped; if only _view does, keep the normalized --view.)
  explicit_*_all VIEW_ACTIVE=yes on Balfrin but NOT on Santis (only passthrough works there)
      -> the broker MUST branch on capability (see the detection block above):
         passthrough supported -> --uenv-passthrough=use --export=ALL;
         else                  -> --uenv=<label> --view=<normalized> --export=ALL.

Clean up when done:  rm -rf "$WORK"
EOF
