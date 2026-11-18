# husk-prefix.sh — where husk is installed. SOURCED, never run. POSIX sh.
#
# The single statement of the install record (`P8`), for every script that runs OUTSIDE the
# cage and needs to find what install-husk.sh put down: the installer itself, selftest.sh,
# slurmd-differential.sh, directive-parity-probe.sh.
#
# The record is ~/.husk/install-prefix — one line, the absolute prefix — written by the
# installer BEFORE it installs anything into that prefix, so even a half-finished install
# names where it went (`P6`: the resource gets its owner first). ~/.husk is written out of the
# cage and masked inside it, so the agent can neither read the record nor rewrite it. That is
# the property that lets a script believe it (`P2`), and it is why the prefix is NOT taken from
# an environment variable: whoever sets the environment would choose which directory gets
# checked (`P15`).
#
# husk-verify.sh does NOT use this. It runs inside the cage, where ~/.husk is masked, and
# reads the prefix from `sandbox.seccomp.applyPath` instead.
#
# No record means an install made before the record existed, and every one of those is at
# ~/.local — so the fallback is a fact about history, not a guess.

husk_prefix_record() { printf '%s\n' "${HOME}/.husk/install-prefix"; }

# Sets `husk_prefix` and `husk_prefix_from` (say the second whenever you use the first).
#   return 0 — from the record, or the default because there is no record
#   return 2 — a record EXISTS but does not hold an absolute path. The default is still set so
#              a diagnostic can carry on and say so; the installer refuses instead, because it
#              cannot tell where the install it would be upgrading or removing actually is.
husk_find_prefix() {
  _hp_rec="$(husk_prefix_record)"
  husk_prefix=""
  husk_prefix_from=""
  _hp_rc=0
  if [ -e "$_hp_rec" ]; then
    husk_prefix="$(head -n1 "$_hp_rec" 2>/dev/null || true)"
    case "$husk_prefix" in
      /*) husk_prefix_from="$_hp_rec" ;;
      *)  husk_prefix=""
          husk_prefix_from="the default, because $_hp_rec exists but does not hold an absolute path"
          _hp_rc=2 ;;
    esac
  fi
  if [ -z "$husk_prefix" ]; then
    husk_prefix="${HOME}/.local"
    [ -n "$husk_prefix_from" ] || husk_prefix_from="the default (no $_hp_rec: an install from before the record)"
  fi
  unset _hp_rec
  return "$_hp_rc"
}
