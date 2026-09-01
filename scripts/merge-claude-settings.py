#!/usr/bin/env python3
# merge-claude-settings.py — merge user-config/settings.json into ~/.claude/settings.json,
# and reverse that merge on uninstall.
#
# Usage:
#   install:    merge-claude-settings.py <settings_path> <apply_seccomp_path> <user_config_path> <manifest_path>
#   uninstall:  merge-claude-settings.py --uninstall <settings_path> <manifest_path>
#
# THE MANAGED KEYS ARE THE SHIPPED FILE'S TOP-LEVEL KEYS — all of them, and nothing else.
# Install OVERWRITES each of them wholesale. To make that reversible without disturbing a
# user's other settings, the FIRST install records each managed key's pre-install value (or
# its absence) in the manifest, and EVERY install records what husk itself wrote. Uninstall
# restores the pre-install values (or deletes the key if it was absent before us), leaves
# every other key alone — and where the value it found is NOT the one husk wrote, it saves
# that value beside the settings file and says whose it is, rather than reporting it as a
# key husk added.
#
# Nothing here merges, and nothing here refuses. husk's blocks are a security policy, not a
# preference, so a stale operator entry surviving into a new version is the thing an upgrade
# exists to end — and refusing to install until a diff is resolved would turn husk's own
# release cadence into a lock on the operator's machine. What husk owes is neither silence
# nor a merge algorithm (`P14`): it is naming what changed, and leaving the old value
# somewhere the operator can get it back from.
#
# Notes:
#   - Backs up settings_path to <path>.bak.<timestamp> if it contains invalid JSON.
#   - Writes atomically via a temp file + os.replace().
#   - The manifest's `preinstall` block is never overwritten once written, so re-installs do
#     not capture our own managed blocks as the "pre-install" state. `installed_sha256` IS
#     rewritten on every install: it records a DIGEST of what husk wrote, so husk's own previous
#     default can never be mistaken for the operator's, and it is the only thing that lets
#     uninstall tell the two apart.
#   - Nothing in the manifest may be a copy of husk's ACTIVE POLICY. The manifest lives under
#     ~/.local, which the shipped `allowRead` carves back out of `denyRead`, so the caged agent
#     can read it (`H-1`). See `key_digest`.

import hashlib, json, sys, os, time

# The declaration. `install()` refuses to run unless the shipped user-config/settings.json
# has EXACTLY these top-level keys, in both directions — they fail differently and both were
# measured (`C1-3`):
#
#   a shipped key not listed here : installed with an [ok] and never recorded in the
#                                   manifest, so --uninstall leaves husk's value in place
#                                   for good. (Measured with `statusLine`: not installed
#                                   at all, because the write set was three literals.)
#   a listed key not shipped      : the operator's value is DELETED and nothing replaces it.
#
# One set stated in two files is the drift `P8` is about, and the assert is what makes one
# answer for the other — at install time, on the operator's machine, not only in the test.
MANAGED_KEYS = ["enableAllProjectMcpServers", "sandbox", "permissions"]

# Where husk records what it wrote, and the key an older husk used for the same job.
#
# The name changed with the shape, deliberately. An old script reading a new manifest finds no
# `installed`, so it says "husk has no record of having written these" and saves a copy before
# reverting — true, and the safe direction. Had the digests kept the old name, that same old
# script would have compared a settings value against a hex string, found them different, and
# reported "changed after husk installed them, so what the file held was YOURS" — a confident
# false statement about the operator's own file. An honest "cannot tell" beats a wrong "yours".
INSTALLED_DIGESTS = "installed_sha256"
INSTALLED_VALUES_LEGACY = "installed"

# Paths the INSTALLER computes for this machine, as dotted labels. A difference there is
# never something the operator chose, so reporting it is noise that trains people to skip the
# block — which is how the one thing they needed to read gets skipped too.
# `sandbox.seccomp` holds the path apply-seccomp landed at on this machine. Named here rather
# than special-cased inside the report loop, so the next computed value has one place to go
# and the loop stays generic.
COMPUTED_PATHS = ("sandbox.seccomp",)

# Distinct from a JSON `null`, which is a value an operator can have written on purpose.
_ABSENT = object()

# How much of a value one note line may spend. `permissions.deny` is 75 entries, so a raw dump
# of both sides is the transcript rather than a note.
SHORT_LIMIT = 160

# …except on the `gone from yours` line, which is the ANSWER the note exists to give (`H-5`).
# The two limits were one, so with ten hand-added deny entries the line truncated mid-entry —
# the line added because 160 characters of two 75-entry lists "answers nothing", answering
# nothing. It is still bounded, because it is bounded by the operator's list and not by husk's:
# an operator with a 500-entry deny list would otherwise get 500 entries here. When the bound
# does bite, the count is printed, so the line never silently under-reports.
GONE_LIMIT = 1200


def key_digest(value):
    """A fingerprint of one managed key's value, and the whole of `H-1`.

    THE MANIFEST IS AGENT-READABLE. `denyRead: ["/users"]` hides every CSCS home, `allowRead`
    carves `~/.local` back out, and the manifest sits at
    `~/.local/lib/husk/uninstall-manifest.json`. The previous version of this script recorded
    `installed` as a VERBATIM COPY of the three managed keys husk had just written, so on a
    fresh machine the manifest went from 140 bytes disclosing nothing to 3.9 KB holding husk's
    complete active policy: all 75 `permissions.deny` entries, `denyRead`, and the network
    allowlist. The seccomp deny list was already extractable from the wrapper binary and the
    sandbox block is handed to the agent by its own harness, but the TOOL DENYLIST was not
    readable from inside the cage before and became readable in one file. `P5` — a denylist is
    a bug list, and that handed over the enumeration without a single probe.

    The fix is that the code never needed the values. Both readers ask one question — "is what
    is in the settings file byte-for-byte what husk wrote here last time?" — and a digest
    answers it exactly. Same discrimination, nothing disclosed, and the manifest shrinks back
    to a few hundred bytes.

    Canonical form, so the digest is a function of the VALUE and not of Python's dict order:
    sorted keys, no whitespace. List order is preserved, because a reordered deny list is a
    different list and `==` said so too.

    One deliberate difference from `==`: `1` and `1.0`, and `True` and `1`, are equal in Python
    and hash differently here. That makes the comparison STRICTER, which is the safe direction —
    husk saves a backup and names the key rather than silently claiming authorship.

    AND WHAT A DIGEST IS NOT. It confirms a guess; it does not resist one. `permissions` and
    `sandbox` are whole policy blocks, so their preimage space is not searchable — but
    `enableAllProjectMcpServers` is a BOOLEAN, and two candidates is not a search. That entry
    is one bit, and it is disclosed. It is also the one managed key that is not a policy list.
    On a machine where husk's own checkout sits inside the agent's working directory the whole
    shipped file is readable anyway; what the manifest changed is that the policy was on EVERY
    installed machine, checkout or not.

    WHAT THIS DOES NOT CLOSE, said plainly (`P12`): `preinstall` still holds the operator's own
    pre-install values verbatim, and it must, because `--uninstall` restores them. That half is
    the pre-existing exposure `128d057` named; it discloses the operator's settings from before
    husk existed on the machine, never husk's active policy, and on a fresh install it is `{}`.
    Moving the manifest somewhere `allowRead` does not carve out is the fix for that half and
    it is not this change.
    """
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def installed_digests(manifest):
    """{key: digest} for what husk last wrote, from either manifest shape, or None.

    The legacy shape is a manifest written by `128d057`, which stored the values. It is read
    (so an upgrade does not lose the discrimination) and then dropped on the next install, so
    upgrading husk DELETES the disclosed copy from disk rather than leaving it beside a digest.
    """
    if not isinstance(manifest, dict):
        return None
    digests = manifest.get(INSTALLED_DIGESTS)
    if isinstance(digests, dict):
        return digests
    legacy = manifest.get(INSTALLED_VALUES_LEGACY)
    if isinstance(legacy, dict):
        return {k: key_digest(v) for k, v in legacy.items()}
    return None


def write_json_atomic(path, obj):
    """Write via a temp file + `os.replace`, and do not leave the temp file behind.

    The `.tmp` is an acquired resource and `P6` wants a release on EVERY path, including the
    ENOSPC one — which is exactly the moment a stray `uninstall-manifest.json.tmp` beside the
    real manifest is most confusing, and it is not on any cleanup list. The failure itself is
    still raised: this removes the litter, not the refusal.
    """
    tmp = path + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(obj, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_json(path, default=None):
    if not os.path.exists(path):
        return default
    with open(path) as f:
        return json.load(f)


def save_beside(settings_path, tag, payload):
    """Write `payload` beside the settings file under a timestamped name; return the path.

    BESIDE THE SETTINGS FILE, and deliberately NOT next to the manifest under ~/.local. Two
    reasons, and the second is the one that decided it:

      * it is the directory install-husk.sh already writes settings.json.bak.<ts> into on
        uninstall, so this adds no new location and no new class of leftover; and
      * on CSCS, $HOME is under /users, which the shipped sandbox lists in `denyRead`, while
        `allowRead` carves ~/.local back out. So a copy of the operator's config written next
        to the manifest is one the caged agent CAN read, and one in ~/.claude is not. (The
        carve-out is why the manifest itself is already agent-readable; that is not this
        change's to fix, but it is this change's to not make worse.) A file this code adds is
        a target like any other, and its path is a control (`P15`).

    Never overwrites. This is the only remaining copy of data that is about to stop existing
    anywhere else, so a same-second second run must not be the thing that destroys it.
    """
    base = "%s.husk-%s.%d" % (settings_path, tag, int(time.time()))
    path, n = base + ".json", 1
    while os.path.exists(path):
        path = "%s.%d.json" % (base, n)
        n += 1
    write_json_atomic(path, payload)
    return path


def _short(v, limit=SHORT_LIMIT):
    t = "<absent>" if v is _ABSENT else json.dumps(v, sort_keys=True)
    return t if len(t) <= limit else t[:limit - 3] + "..."


def change_notes(label, old, new):
    """The [note] block for one managed key: a list of lines, or [] if nothing changed.

    Descends while both sides are dicts, so `permissions.deny` is named as
    `permissions.deny` and not as "permissions", and a bool like
    `enableAllProjectMcpServers` is named as itself. The class is A MANAGED KEY THE OPERATOR
    HAD DIFFERENT VALUES FOR; `sandbox` was only ever the first instance of it, and
    reporting sub-keys of that one key while replacing the other two in silence is what
    `C3-3` / `B7-6` / `C1-3` each found independently.

    Two lists are reported as WHAT LEFT, not as two truncated dumps. `permissions.deny` is
    75 entries and the two entries an operator added are at the end of it: printing 160
    characters of each list shows two identical prefixes and answers nothing. The question
    being asked here is "what did I lose", so that is the line, and it is first.
    """
    if label in COMPUTED_PATHS or old == new:
        return []
    if isinstance(old, dict) and isinstance(new, dict):
        out = []
        for k in sorted(set(old) | set(new)):
            out.extend(change_notes("%s.%s" % (label, k),
                                    old.get(k, _ABSENT), new.get(k, _ABSENT)))
        return out
    out = ["  [note] %s replaced" % label]
    if isinstance(old, list) and isinstance(new, list):
        # `gone from yours` gets its own, larger budget, and says how many there were when even
        # that bites (`H-5`). `new from husk` keeps the small one: the installer cats the whole
        # shipped file before asking for confirmation, so that half is never the unanswered
        # question. The two limits used to be one, which truncated the answer at about ten
        # entries — inside the line that exists because a truncated dump answers nothing.
        gone = [x for x in old if x not in new]
        out.append("         gone from yours: %s" % _short(gone, GONE_LIMIT))
        if len(json.dumps(gone, sort_keys=True)) > GONE_LIMIT:
            out.append("         …%d entries in all; every one of them is in the file named "
                       "below" % len(gone))
        out.append("         new from husk:   %s" % _short([x for x in new if x not in old]))
    else:
        out.append("         yours: %s" % _short(old))
        out.append("         husk:  %s" % _short(new))
    return out


def require_shipped_matches_managed(user_config, user_config_path):
    """Fail closed if the shipped policy file and MANAGED_KEYS have drifted (`C1-3`, `P8`).

    Only husk's own source can trip this — the shipped file and this script travel together
    in one checkout or one tarball — and it fails BEFORE anything is written, so the machine
    is left as it was found (`P6`). The alternative is worse in both directions: a shipped
    security key silently not installed, or an operator key deleted with nothing put back.
    """
    shipped = list(user_config)
    missing = [k for k in MANAGED_KEYS if k not in shipped]
    extra = [k for k in shipped if k not in MANAGED_KEYS]
    if not missing and not extra:
        return
    print("  [error] husk's managed-key list and its shipped settings file disagree.")
    print("          MANAGED_KEYS (scripts/merge-claude-settings.py): %s" % ", ".join(MANAGED_KEYS))
    print("          top-level keys in %s: %s" % (user_config_path, ", ".join(shipped)))
    for k in extra:
        print("          '%s' is shipped but not managed: it would be installed and then never" % k)
        print("            recorded, so --uninstall could not take it back out.")
    for k in missing:
        print("          '%s' is managed but not shipped: installing would DELETE whatever the" % k)
        print("            operator has under that key and put nothing in its place.")
    print("          Nothing was written. Make the two lists agree and re-run.")
    sys.exit(1)


def uninstall(settings_path, manifest_path):
    manifest = None
    try:
        manifest = load_json(manifest_path)
    except (ValueError, OSError) as e:
        print("  [warn] %s cannot be read (%s)" % (manifest_path, e))
    if not isinstance(manifest, dict):
        print("  [warn] no usable manifest at %s — cannot safely revert %s; leaving it "
              "untouched. Remove the %s blocks by hand if you want them gone."
              % (manifest_path, settings_path, " / ".join(MANAGED_KEYS)))
        return
    try:
        settings = load_json(settings_path, {})
    except json.JSONDecodeError:
        bak = settings_path + ".bak." + str(int(time.time()))
        print("  [warn] %s is not valid JSON — backing up to %s and reverting from an empty "
              "config" % (settings_path, bak))
        os.rename(settings_path, bak)
        settings = {}

    preinstall = manifest.get("preinstall", {})
    installed = installed_digests(manifest)

    # THE KEYS TO REVERT ARE THE UNION OF WHAT THE MANIFEST SAYS husk MANAGES AND WHAT husk
    # RECORDED WRITING (`H-2`).
    #
    # `managed_keys` is written inside the write-once block and never updated, while `installed`
    # is rewritten on every install. So a release that ADDS a managed key installed it, recorded
    # writing it, and left `managed_keys` stale — and `--uninstall` then printed "removed the
    # blocks husk wrote", named the old three, and left husk's fourth in the operator's settings
    # for good. Reproduced end to end with `statusLine`, through the fixed code, on the upgrade
    # path. `P8`: the fix made list #1 assert list #2 and created list #3.
    #
    # NOT `| set(MANAGED_KEYS)`, deliberately. This script's own list is what husk manages TODAY;
    # uninstalling must revert what husk actually WROTE on this machine. A newer script run over
    # an older install would otherwise delete a key husk never touched — the same class of harm,
    # pointed the other way.
    recorded = manifest.get("managed_keys")
    managed = sorted(set(recorded if isinstance(recorded, list) else MANAGED_KEYS)
                     | set(installed or {}))

    # Three dispositions, one per key, and the third is the one that did not exist: a value
    # husk can PROVE it wrote, a value it can prove it did NOT, and a value it cannot say
    # either way about. Reporting all three as "removed keys we added" is husk taking credit
    # for the operator's own hardening on the way out (`C3-3`, `P12`).
    restored, deleted, changed, unverified = [], [], [], []
    at_risk = {}
    for key in managed:
        if key in settings:
            if isinstance(installed, dict) and key in installed:
                if key_digest(settings[key]) != installed[key]:
                    changed.append(key)
                    at_risk[key] = settings[key]
            else:
                unverified.append(key)
                at_risk[key] = settings[key]
        if key in preinstall:
            settings[key] = preinstall[key]
            restored.append(key)
        elif key in settings:
            del settings[key]
            deleted.append(key)

    saved = save_beside(settings_path, "replaced", at_risk) if at_risk else None
    write_json_atomic(settings_path, settings)

    ours = [k for k in deleted if k not in changed and k not in unverified]
    if restored:
        print("  [ok]   restored pre-install values: %s" % ", ".join(restored))
    if ours:
        print("  [ok]   removed the blocks husk wrote: %s" % ", ".join(ours))
    if changed:
        print("  [warn] changed after husk installed them, so what the file held was YOURS —")
        print("         not keys husk can report itself as having added: %s" % ", ".join(changed))
    if unverified:
        print("  [warn] husk has no record of having written these, so it cannot tell whether")
        print("         the value it found is yours: %s" % ", ".join(unverified))
    if saved:
        print("  [warn] reverted them anyway — that is what --uninstall means, and half a husk")
        print("         config left behind would be its own kind of lie. What they held, saved")
        print("         before the revert:")
        print("           %s" % saved)
    print("  [ok]   %s reverted" % settings_path)


def install(settings_path, apply_seccomp, user_config_path, manifest_path):
    with open(user_config_path) as f:
        user_config = json.load(f)
    require_shipped_matches_managed(user_config, user_config_path)

    incoming = dict(user_config)
    sandbox = dict(user_config["sandbox"])
    if apply_seccomp and os.path.exists(apply_seccomp):
        sandbox["seccomp"] = {"applyPath": apply_seccomp}
    incoming["sandbox"] = sandbox

    existing = {}
    if os.path.exists(settings_path):
        with open(settings_path) as f:
            try:
                existing = json.load(f)
            except json.JSONDecodeError:
                bak = settings_path + ".bak." + str(int(time.time()))
                print("  [warn] %s is not valid JSON — backing up to %s and overwriting"
                      % (settings_path, bak))
                os.rename(settings_path, bak)

    # What husk wrote here last time, if it is on record. This is the whole of the fix's
    # discrimination: without it "your value" and "husk's own previous default" are the same
    # bytes to this script, and the only safe reading of that is to shout about both.
    prior, manifest_unreadable = None, False
    if os.path.exists(manifest_path):
        try:
            prior = load_json(manifest_path)
        except (ValueError, OSError) as e:
            prior = None
            manifest_unreadable = True
            print("  [warn] %s exists but cannot be read (%s)." % (manifest_path, e))
        if not manifest_unreadable and not isinstance(prior, dict):
            prior = None
            manifest_unreadable = True
            print("  [warn] %s exists but is not a JSON object." % manifest_path)
        if manifest_unreadable:
            print("         Leaving it untouched — rewriting it would record husk's own install")
            print("         as your pre-install state — so --uninstall cannot revert this")
            print("         settings file until that file is fixed or deleted. Everything husk")
            print("         replaces below is still saved beside the settings file.")
    last_written = installed_digests(prior)

    # SAY WHICH MANAGED KEYS ARE BEING REPLACED, AND WHOSE VALUES THEY WERE.
    #
    # The installer already cats user-config/settings.json before asking for confirmation, so
    # the incoming content is never a secret. But sixty lines of JSON does not tell you that
    # YOUR network policy differs from it — and on Santis (2026-08-30) an operator loosening
    # (strictAllowlist removed so an agent could reach arbitrary hosts) was replaced by the
    # shipped default and nobody noticed until a divergence NOTE failed to appear and two
    # hypotheses had to be eliminated. The same thing then happened to `permissions`, which
    # this block did not cover: a hand-added `permissions.deny` entry — the durable half of
    # the tool control — and a `permissions.additionalDirectories` carve-out that is a
    # writable bind, both deleted under four notes about `sandbox` defaults.
    #
    # Three dispositions, and only the last two are the operator's business:
    #   unchanged / absent  — nothing of anyone's is being replaced. Silent.
    #   husk's own          — byte-identical to what husk wrote here last install, so the
    #                         difference is husk's version changing. One line, no dump.
    #   yours, or unknown   — named, diffed, and SAVED. This is the case that cost the time.
    replaced, notes = {}, []
    for key in MANAGED_KEYS:
        old = existing.get(key, _ABSENT)
        new = incoming[key]
        if old is _ABSENT or old == new:
            continue
        if isinstance(last_written, dict) and last_written.get(key) == key_digest(old):
            print("  [note] husk updated its own `%s` block — it was byte-identical to what "
                  "husk\n         installed last time, so nothing of yours was replaced." % key)
            continue
        # A DIFFERENCE THE OPERATOR CANNOT HAVE MADE IS NOT A REPLACEMENT (`H-3`).
        # `change_notes` already suppresses `COMPUTED_PATHS` — values the INSTALLER derives for
        # this machine, like where apply-seccomp landed. The `replaced` dict did not, so a
        # difference confined to `sandbox.seccomp.applyPath` produced a saved backup file and
        # the header "[note] husk did not write what it just replaced under: sandbox" with NO
        # change lines under it at all. That header is the one line in this transcript that must
        # mean something, and `COMPUTED_PATHS`'s own docstring names the harm: noise that trains
        # people to skip the block is how the one thing they needed to read gets skipped too.
        key_notes = change_notes(key, old, new)
        if not key_notes:
            continue
        replaced[key] = old
        notes.extend(key_notes)
    for line in notes:
        print(line)
    if replaced:
        saved = save_beside(settings_path, "replaced", replaced)
        print("  [note] husk did not write what it just replaced under: %s"
              % ", ".join(sorted(replaced)))
        print("         Saved, in full, before the overwrite:")
        print("           %s" % saved)
        print("         These are managed keys — husk owns them and rewrites them on every")
        print("         install. Durable per-site policy belongs in ~/.husk/config.json.")

    # First install only: record each managed key's pre-install value (or absence) so
    # uninstall can reverse exactly what we changed. Never overwrite that block, or it would
    # capture our own install as the "before" state.
    #
    # `installed` is the other half and IS rewritten every time: it is husk's own output, so
    # recording it cannot lose anything, and it is what lets the next uninstall tell the
    # operator's edits from husk's leftovers. Written BEFORE the settings file on purpose —
    # a crash between the two leaves a manifest describing an install that did not happen,
    # which uninstall handles as "changed since", whereas the other order leaves husk's
    # values installed with no manifest and the next install would snapshot them as yours.
    if not manifest_unreadable:
        os.makedirs(os.path.dirname(manifest_path) or ".", exist_ok=True)
        if prior is None:
            prior = {
                "managed_keys": MANAGED_KEYS,
                "preinstall": {k: existing[k] for k in MANAGED_KEYS if k in existing},
                "created": int(time.time()),
            }
            print("  [ok]   uninstall manifest written to %s" % manifest_path)
        # `managed_keys` grows with every release that adds one, so the manifest describes what
        # husk has EVER installed here and an uninstall run from any checkout can reverse it
        # (`H-2`). It never shrinks: a downgrade must not orphan a key the newer husk wrote.
        prior["managed_keys"] = sorted(
            set(prior.get("managed_keys") if isinstance(prior.get("managed_keys"), list) else [])
            | set(MANAGED_KEYS)
        )
        # DIGESTS, NOT VALUES (`H-1`) — see `key_digest`. And the verbatim copy an older husk
        # wrote is REMOVED here rather than left beside them, so upgrading takes the disclosed
        # policy off disk instead of adding to it.
        prior[INSTALLED_DIGESTS] = {k: key_digest(incoming[k]) for k in MANAGED_KEYS}
        prior.pop(INSTALLED_VALUES_LEGACY, None)
        prior["installed_at"] = int(time.time())
        write_json_atomic(manifest_path, prior)

    for key in MANAGED_KEYS:
        existing[key] = incoming[key]
    write_json_atomic(settings_path, existing)
    print("  [ok]   sandbox settings written to %s" % settings_path)


def _refuse_on_write_error(e):
    """One attributed refusal for the whole script, instead of a Python traceback (`H-4`).

    A read-only or quota-full `$HOME` made `save_beside` raise `PermissionError` and the
    operator got a stack trace, where every other failure in this file prints `[error]` and says
    what to do (`P11`, `P13`). The exit status is unchanged — it was 1 before and is 1 now — so
    this adds words to an existing refusal and no new refusal.

    It does NOT claim "nothing was written": that is true for the measured case and not for
    every case, and this handler cannot tell which one it is in. What it can say truthfully is
    that the install did not finish and that re-running is safe, which is the actionable half.
    """
    where = getattr(e, "filename", None) or "a file it needed to write"
    print("  [error] husk could not write %s (%s)." % (where, e.strerror or e))
    print("          The install did not complete. Fix that path — a read-only or full $HOME")
    print("          is the usual cause — and run this again; it is idempotent, so re-running")
    print("          after the fix finishes the job and changes nothing twice.")
    sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--managed-keys":
        # For install-husk.sh's uninstall banner, so the operator reads THIS list rather than
        # three literals kept in step by hand (`P8`). Read-only, writes nothing, exits 0.
        print(" / ".join(MANAGED_KEYS))
        sys.exit(0)
    if len(sys.argv) >= 2 and sys.argv[1] in ("-h", "--help"):
        # Print this file's header comment block (single source of truth).
        with open(__file__) as _f:
            for _line in _f.read().splitlines()[1:]:   # skip the shebang
                if not _line.startswith("#"):
                    break
                print(_line[2:] if _line.startswith("# ") else _line[1:])
        sys.exit(0)
    try:
        if len(sys.argv) >= 2 and sys.argv[1] == "--uninstall":
            uninstall(sys.argv[2], sys.argv[3])
        else:
            install(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    except OSError as e:
        _refuse_on_write_error(e)
