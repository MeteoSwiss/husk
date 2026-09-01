#!/usr/bin/env bash
# Does the settings merge tell the operator what it replaced — and, on the way out, stop
# calling the operator's own edits "keys we added"?
#
# WHY THIS FILE EXISTS
# --------------------
# `C3-3` / `B7-6` / `C1-3`, three passes reaching the same defect independently.
# `MANAGED_KEYS` has three entries. The announcement block iterated the sub-keys of ONE of
# them. `permissions` and `enableAllProjectMcpServers` were replaced wholesale with no
# output at all, and the manifest is written once, so from the second install on the
# operator's value was neither reported nor recoverable. Measured then:
#
#     operator adds  permissions.deny += ["Bash(curl:*)", "Bash(ssh:*)"]  and re-installs
#     --- the ENTIRE output of the run ---
#     [ok]   sandbox settings written to …/settings.json
#     Bash(curl:*) present: False
#
# and `--uninstall` finished the job by reporting `removed keys we added` for a block whose
# content husk did not write. The comment above the loop said the class was *"a managed
# SUB-KEY the operator had different values for"*. It is one level up — a managed KEY — and
# there are three of them.
#
# This file drives the REAL script (never a copy — a copy drifts and then tests itself,
# `P8`) through the operator's actual sequence: install, hand-edit, re-install, uninstall.
#
# FALSE FRIENDS, NAMED
# --------------------
#   * An assertion that the note block is non-empty. The shipped bug PRINTED FOUR NOTES on
#     the run that deleted `permissions.additionalDirectories` — all four about `sandbox`
#     defaults that had been absent, i.e. about nothing being lost. Every assertion here
#     names the KEY it expects, and `§3` asserts that a run which loses nothing is SILENT.
#   * Reading the resulting settings.json. It was always correct: husk's blocks really are
#     installed. The defect is entirely in what the operator is told and what survives, so
#     the oracle is the TRANSCRIPT and the saved-value file, not the merge result.
#   * Grepping for the operator's string anywhere in the output. `permissions.deny` is 75
#     entries and both sides get truncated at 160 characters, so two dumps of it are
#     byte-identical for the first 160 characters and prove nothing. `§2` asserts the
#     "gone from yours" line, which is the answer to the question actually being asked.
#
# Needs no cluster, no $HOME, no install. Writes only under mktemp -d.
set -u
MERGE="${MERGE:-$(dirname "$0")/merge-claude-settings.py}"
SHIPPED="${SHIPPED:-$(dirname "$0")/../user-config/settings.json}"
pass=0; fail=0

for f in "$MERGE" "$SHIPPED"; do
  [[ -f "$f" ]] || { echo "FAIL: $f not found — nothing was tested"; exit 1; }
done

check_has()   { if grep -qF -- "$3" <<<"$2"; then pass=$((pass+1)); printf '  ok    %s\n' "$1"
                else fail=$((fail+1)); printf '  FAIL  %s\n        wanted: %s\n        got:\n%s\n' "$1" "$3" "$2"; fi; }
check_lacks() { if grep -qF -- "$3" <<<"$2"; then fail=$((fail+1)); printf '  FAIL  %s\n        must NOT say: %s\n        got:\n%s\n' "$1" "$3" "$2"
                else pass=$((pass+1)); printf '  ok    %s\n' "$1"; fi; }
check_eq()    { if [[ "$3" == "$2" ]]; then pass=$((pass+1)); printf '  ok    %-58s %s\n' "$1" "$3"
                else fail=$((fail+1)); printf '  FAIL  %-58s got %s want %s\n' "$1" "$3" "$2"; fi; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# One scenario = one throwaway machine: a settings file, a manifest directory, and a stub
# apply-seccomp so the computed sandbox.seccomp.applyPath is a property of the scenario.
n=0
new_machine() {   # <settings-json-literal>
  n=$((n+1)); D="$TMP/m$n"; mkdir -p "$D/claude" "$D/lib/husk"
  : > "$D/apply-seccomp"
  S="$D/claude/settings.json"; M="$D/lib/husk/uninstall-manifest.json"
  printf '%s\n' "$1" > "$S"
}
install_run()   { python3 "$MERGE" "$S" "$D/apply-seccomp" "${1:-$SHIPPED}" "$M" 2>&1; }
uninstall_run() { python3 "$MERGE" --uninstall "$S" "$M" 2>&1; }
saved_files()   { ls "$D/claude" | grep -c 'husk-replaced' || true; }
# The path the run PRINTED, not the newest file in the directory: the operator recovers
# their value by reading that line, so the line is what has to be right.
saved_from()    { grep -oE '[^ ]*husk-replaced[^ ]*\.json' <<<"$1" | tail -1; }
jq_py()         { python3 -c "$2" "$1"; }

OPERATOR='{
  "model": "opus",
  "enableAllProjectMcpServers": true,
  "permissions": { "allow": ["Bash(make:*)"], "additionalDirectories": ["/capstor/scratch/mine"] }
}'

echo "-- 1. first install: all three managed keys are reported, not one of them --"
new_machine "$OPERATOR"
t="$(install_run)"
check_has   "permissions.allow is named"            "$t" "permissions.allow replaced"
check_has   "additionalDirectories is named (R3: a writable bind)" \
                                                    "$t" "permissions.additionalDirectories replaced"
check_has   "enableAllProjectMcpServers is named"   "$t" "enableAllProjectMcpServers replaced"
check_has   "and the settings are still installed"  "$t" "sandbox settings written to"
check_eq    "the operator's values were saved" 1 "$(saved_files)"
check_eq    "…beside the settings file, not under ~/.local where the cage can read it" \
            "yes" "$([[ "$(saved_from "$t")" == "$D/claude/"* ]] && echo yes || echo no)"
check_eq    "…and the saved copy really holds the operator's allow entry" "Bash(make:*)" \
            "$(jq_py "$(saved_from "$t")" 'import json,sys;print(json.load(open(sys.argv[1]))["permissions"]["allow"][0])')"
check_eq    "the model key outside the managed set is untouched" "opus" \
            "$(jq_py "$S" 'import json,sys;print(json.load(open(sys.argv[1]))["model"])')"

echo "-- 2. THE BUG: hand-harden permissions.deny, then re-install --"
python3 - "$S" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
s["permissions"]["deny"] += ["Bash(curl:*)", "Bash(ssh:*)"]
json.dump(s, open(sys.argv[1], "w"), indent=2)
PY
t="$(install_run)"
check_has   "the key is named"                      "$t" "permissions.deny replaced"
check_has   "and WHAT LEFT is named — the whole point" \
                                                    "$t" 'gone from yours: ["Bash(curl:*)", "Bash(ssh:*)"]'
check_lacks "not reported as husk's own version bump" "$t" "husk updated its own"
check_eq    "a second saved copy, and the first is not overwritten" 2 "$(saved_files)"
check_eq    "…holding the hardening that was removed" "True" \
            "$(jq_py "$(saved_from "$t")" 'import json,sys;print("Bash(curl:*)" in json.load(open(sys.argv[1]))["permissions"]["deny"])')"

echo "-- 3. the noise floor: a re-install that loses nothing says nothing --"
t="$(install_run)"
check_lacks "no [note] at all"                      "$t" "[note]"
check_has   "just the [ok]"                         "$t" "sandbox settings written to"
check_eq    "and no third saved file"             2 "$(saved_files)"

echo "-- 4. husk's OWN default changing is one line, not a wall of diff --"
# The operator has not touched anything since the install above; husk ships a new default.
NEXT="$TMP/shipped-next.json"
python3 - "$SHIPPED" "$NEXT" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["sandbox"]["network"]["allowedDomains"].append("newdefault.example:443")
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
t="$(install_run "$NEXT")"
check_has   "attributed to husk"                    "$t" "husk updated its own \`sandbox\` block"
check_lacks "…and not dumped as if the operator had lost something" "$t" "gone from yours"
check_eq    "nothing saved: nothing of the operator's was at risk" 2 "$(saved_files)"

echo "-- 5. --uninstall must not sign its name to the operator's content --"
new_machine "$OPERATOR"
install_run >/dev/null
python3 - "$S" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
s["permissions"]["deny"] += ["Bash(curl:*)"]
json.dump(s, open(sys.argv[1], "w"), indent=2)
PY
t="$(uninstall_run)"
check_lacks "the shipped claim of authorship is gone"        "$t" "removed keys we added"
check_has   "the operator's edit is attributed to them"      "$t" "changed after husk installed them"
check_has   "…by name"                                       "$t" "permissions"
check_has   "…and saved, since the revert is still a revert" "$t" "saved"
check_eq    "the saved copy holds their edit" "True" \
            "$(jq_py "$(saved_from "$t")" 'import json,sys;print("Bash(curl:*)" in json.load(open(sys.argv[1]))["permissions"]["deny"])')"
check_eq    "…and the revert happened: their pre-install allow entry is back" "Bash(make:*)" \
            "$(jq_py "$S" 'import json,sys;print(json.load(open(sys.argv[1]))["permissions"]["allow"][0])')"

echo "-- 6. an untouched install: husk may say it removed its own blocks --"
new_machine '{"model": "opus"}'
install_run >/dev/null
t="$(uninstall_run)"
check_has   "authorship claimed where it is true"   "$t" "removed the blocks husk wrote"
check_lacks "no warning about anything"             "$t" "[warn]"
check_eq    "nothing saved"                       0 "$(saved_files)"
check_eq    "and the key is gone"                 "absent" \
            "$(jq_py "$S" 'import json,sys;print("sandbox" in json.load(open(sys.argv[1])) and "present" or "absent")')"

echo "-- 7. a manifest from a husk that predates the record: revert, but do not claim it --"
new_machine "$OPERATOR"
install_run >/dev/null
python3 - "$M" <<'PY'
import json, sys        # strip every record of what husk wrote, as the first husk had none
m = json.load(open(sys.argv[1]))
for k in ("installed", "installed_sha256", "installed_at"): m.pop(k, None)
json.dump(m, open(sys.argv[1], "w"), indent=2)
PY
t="$(uninstall_run)"
check_has   "says it cannot tell"                   "$t" "no record of having written these"
check_lacks "…so it does not claim them"            "$t" "removed the blocks husk wrote"
check_has   "…reverts anyway (no regression for anyone mid-upgrade)" "$t" "reverted"
check_eq    "…having saved what it found" 2 "$(saved_files)"

echo "-- 8. C1-3 direction A: a key shipped but not managed refuses, before writing --"
new_machine "$OPERATOR"
BAD="$TMP/shipped-extra.json"
python3 - "$SHIPPED" "$BAD" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["statusLine"] = {"type": "command", "command": "x"}
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
before="$(cat "$S")"
t="$(install_run "$BAD")"; rc=$?
check_eq    "exits non-zero"                      1 "$rc"
check_has   "names the key"                         "$t" "'statusLine' is shipped but not managed"
check_lacks "and nothing was installed"             "$t" "sandbox settings written"
check_eq    "the settings file is byte-identical"   "same" \
            "$([[ "$before" == "$(cat "$S")" ]] && echo same || echo CHANGED)"
check_eq    "no manifest was created"               "absent" \
            "$([[ -e "$M" ]] && echo present || echo absent)"

echo "-- 9. C1-3 direction B: a managed key that is not shipped refuses, before deleting --"
new_machine "$OPERATOR"
BAD2="$TMP/shipped-missing.json"
python3 - "$SHIPPED" "$BAD2" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d.pop("permissions")
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
# `rc` alone is a false friend HERE and only here: the shipped code also exited 1, with a
# KeyError traceback, which is a crash and not a refusal. The message arm is the real one.
t="$(install_run "$BAD2")"; rc=$?
check_eq    "exits non-zero"                      1 "$rc"
check_has   "and says what it would have destroyed" "$t" "'permissions' is managed but not shipped"
check_eq    "the operator's permissions survive"    "Bash(make:*)" \
            "$(jq_py "$S" 'import json,sys;print(json.load(open(sys.argv[1]))["permissions"]["allow"][0])')"

echo "-- 10. the write-once manifest stays write-once --"
new_machine "$OPERATOR"
install_run >/dev/null
c1="$(jq_py "$M" 'import json,sys;m=json.load(open(sys.argv[1]));print(m["created"], sorted(m["preinstall"]), m["preinstall"]["enableAllProjectMcpServers"])')"
i1="$(jq_py "$M" 'import json,sys;print("installed_sha256" in json.load(open(sys.argv[1])))')"
install_run >/dev/null; install_run >/dev/null
c2="$(jq_py "$M" 'import json,sys;m=json.load(open(sys.argv[1]));print(m["created"], sorted(m["preinstall"]), m["preinstall"]["enableAllProjectMcpServers"])')"
check_eq    "preinstall and created never move"   "$c1" "$c2"
check_eq    "the pre-install value is the OPERATOR's, not husk's" "True" \
            "$(jq_py "$M" 'import json,sys;print(json.load(open(sys.argv[1]))["preinstall"]["enableAllProjectMcpServers"])')"
check_eq    "…and what husk wrote is on record"   "True" "$i1"

echo "-- 11. H-1: the manifest must not be a copy of husk's ACTIVE POLICY --"
# THE BUG, measured on a fresh machine: 140 bytes disclosing nothing at 20ca07d, 3923 bytes at
# HEAD holding all 75 `permissions.deny` entries, `denyRead` and the network allowlist. The
# manifest lives under ~/.local, which the shipped `allowRead` carves back out of `denyRead`,
# so THE CAGED AGENT CAN READ IT. Two thirds of that content was already reachable — the
# seccomp list from `strings` on the wrapper, the sandbox block from the agent's own system
# reminder — but the tool denylist was not, and `P5` says a denylist is a bug list.
#
# THE FALSE FRIEND: asserting the manifest is "small". A size is a proxy for the property and
# goes green the moment someone stores something else large; and the manifest legitimately
# grows with `preinstall` on a machine that had settings. This asserts the property — no
# shipped policy value appears in the file — on the case where `preinstall` is empty and every
# byte in the file is husk's own.
new_machine '{"model": "opus"}'
install_run >/dev/null
leaked="$(python3 - "$M" "$SHIPPED" <<'PY'
import json, sys
text = open(sys.argv[1]).read()
shipped = json.load(open(sys.argv[2]))
bad = [e for e in shipped["permissions"]["deny"] if e in text]
bad += [d for d in shipped["sandbox"]["filesystem"]["denyRead"] if d in text]
bad += [d for d in shipped["sandbox"]["network"]["allowedDomains"] if d in text]
print(len(bad), bad[:3])
PY
)"
check_eq    "no shipped policy value appears in the manifest" "0 []" "$leaked"
check_eq    "…and what husk wrote is still on record, as digests" "True" \
            "$(jq_py "$M" 'import json,sys
m=json.load(open(sys.argv[1]))["installed_sha256"]
print(sorted(m)==sorted(["enableAllProjectMcpServers","sandbox","permissions"])
      and all(len(v)==64 and all(c in "0123456789abcdef" for c in v) for v in m.values()))')"
# The discrimination the digest has to preserve is §4 above (husk's own default changing is one
# line, not a diff) and §5 (an operator edit is attributed to them). Both ran before this.
check_eq    "the manifest is back to the order of magnitude it disclosed nothing at" "small" \
            "$([[ "$(stat -c %s "$M")" -lt 800 ]] && echo small || echo "$(stat -c %s "$M") bytes")"

echo "-- 12. H-2: a release that ADDS a managed key can still be uninstalled --"
# Reproduced end to end, through the FIXED code, on the upgrade path: `managed_keys` is written
# inside the write-once block and never updated, while the record of what husk wrote is
# rewritten every install. So --uninstall said "removed the blocks husk wrote", named the old
# three, and left husk's `statusLine` in the operator's settings for good.
#
# This is the one place the suite runs a MODIFIED copy of the script, because the scenario IS a
# future release. The modification is one line, generated by sed from the real file, so it
# cannot drift into a reimplementation.
V6="$TMP/merge-v6.py"
sed 's/^MANAGED_KEYS = .*/MANAGED_KEYS = ["enableAllProjectMcpServers", "sandbox", "permissions", "statusLine"]/' \
    "$MERGE" > "$V6"
grep -q '"statusLine"' "$V6" || { echo "FAIL: could not build the v0.6 script"; fail=$((fail+1)); }
SHIPPED6="$TMP/shipped-v6.json"
python3 - "$SHIPPED" "$SHIPPED6" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["statusLine"] = {"type": "command", "command": "husk-status"}
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
new_machine '{"model": "opus", "statusLine": {"type": "command", "command": "MY-OWN-STATUSLINE"}}'
install_run >/dev/null                                   # v0.5: three managed keys
t="$(python3 "$V6" "$S" "$D/apply-seccomp" "$SHIPPED6" "$M" 2>&1)"   # v0.6 upgrade
check_has   "the new key's arrival is announced"    "$t" "statusLine.command replaced"
t="$(python3 "$V6" --uninstall "$S" "$M" 2>&1)"
check_has   "…and uninstall names it among the blocks husk wrote" "$t" "statusLine"
check_eq    "…and it is GONE, not left behind for good" "absent" \
            "$(jq_py "$S" 'import json,sys;print("statusLine" in json.load(open(sys.argv[1])) and "present" or "absent")')"

echo "-- 13. H-3: a difference the OPERATOR cannot have made is not a replacement --"
# `sandbox.seccomp.applyPath` is computed by the installer for this machine. change_notes
# suppresses it; the write set did not, so this produced a saved backup file and the header
# "husk did not write what it just replaced under: sandbox" with no change lines under it at
# all. Reached by the residual the author flagged — delete the manifest, re-install — plus any
# apply-seccomp path change.
new_machine '{"model": "opus"}'
install_run >/dev/null
rm -f "$M"
: > "$D/apply-seccomp-moved"
t="$(python3 "$MERGE" "$S" "$D/apply-seccomp-moved" "$SHIPPED" "$M" 2>&1)"
check_lacks "no [note] about a replacement nobody made"  "$t" "husk did not write what it just replaced"
check_lacks "…and no empty note block either"            "$t" "[note]"
check_eq    "…and no backup file of husk's own path"   0 "$(saved_files)"
check_eq    "…while the new path really is installed"  "$D/apply-seccomp-moved" \
            "$(jq_py "$S" 'import json,sys;print(json.load(open(sys.argv[1]))["sandbox"]["seccomp"]["applyPath"])')"

echo "-- 14. H-4: a read-only ~/.claude is an [error], not a Python traceback --"
if [[ "$(id -u)" == "0" ]]; then
  echo "  skip  running as root: chmod cannot make a directory read-only here"
else
  new_machine "$OPERATOR"
  install_run >/dev/null
  python3 - "$S" <<'PY'
import json, sys
s = json.load(open(sys.argv[1])); s["permissions"]["deny"] += ["Bash(curl:*)"]
json.dump(s, open(sys.argv[1], "w"), indent=2)
PY
  chmod 500 "$D/claude"
  t="$(install_run)"; rc=$?
  chmod 700 "$D/claude"
  check_eq    "still fails closed"                      1 "$rc"
  check_lacks "no traceback"                            "$t" "Traceback (most recent call last)"
  check_has   "an attributed error"                     "$t" "[error] husk could not write"
  check_has   "…naming the path it could not write"     "$t" "$D/claude/settings.json.husk-replaced"
  check_has   "…and what to do about it"                "$t" "run this again"
fi

echo "-- 15. H-5: the answer line survives more entries than the old limit allowed --"
# `_short`'s 160 characters were shared between the two-dump form and the list-difference form,
# so the line added BECAUSE 160 characters of two 75-entry lists answers nothing truncated at
# about ten entries and answered nothing itself.
new_machine "$OPERATOR"
install_run >/dev/null
python3 - "$S" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
s["permissions"]["deny"] += ["Bash(husk-probe-%02d:*)" % i for i in range(12)]
json.dump(s, open(sys.argv[1], "w"), indent=2)
PY
t="$(install_run)"
check_has   "the FIRST hand-added entry is named"   "$t" "Bash(husk-probe-00:*)"
check_has   "…and so is the twelfth"                "$t" "Bash(husk-probe-11:*)"
check_lacks "the shipped side is still bounded"     "$t" "new from husk:   [\"EnterPlanMode\", \"ExitPlanMode\", \"EndConversation\", \"Artifact\", \"Read\""

echo "-- 16. a manifest written by the husk that stored VALUES: read it, then scrub it --"
# The upgrade path for H-1. The old manifest is still usable — husk must not lose the ability
# to tell its own default from the operator's edit across one release — and the next install
# takes the disclosed copy OFF DISK rather than leaving it beside the digests.
new_machine '{"model": "opus"}'
install_run >/dev/null
python3 - "$M" "$S" <<'PY'
import json, sys                       # rebuild the 128d057 manifest shape from the settings
m = json.load(open(sys.argv[1])); s = json.load(open(sys.argv[2]))
m.pop("installed_sha256", None)
m["installed"] = {k: s[k] for k in ("enableAllProjectMcpServers", "sandbox", "permissions")}
json.dump(m, open(sys.argv[1], "w"), indent=2)
PY
NEXT2="$TMP/shipped-next2.json"
python3 - "$SHIPPED" "$NEXT2" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["sandbox"]["network"]["allowedDomains"].append("legacy.example:443")
json.dump(d, open(sys.argv[2], "w"), indent=2)
PY
t="$(install_run "$NEXT2")"
check_has   "the legacy record still attributes husk's own block to husk" \
                                                    "$t" "husk updated its own \`sandbox\` block"
check_eq    "…and the verbatim copy is gone from the manifest" "absent" \
            "$(jq_py "$M" 'import json,sys;print("installed" in json.load(open(sys.argv[1])) and "present" or "absent")')"
check_eq    "…replaced by digests"                  "present" \
            "$(jq_py "$M" 'import json,sys;print("installed_sha256" in json.load(open(sys.argv[1])) and "present" or "absent")')"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
