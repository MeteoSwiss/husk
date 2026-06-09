#!/usr/bin/env python3
# merge-claude-settings.py — merge user-config/settings.json into ~/.claude/settings.json,
# and reverse that merge on uninstall.
#
# Usage:
#   install:    merge-claude-settings.py <settings_path> <apply_seccomp_path> <user_config_path> <manifest_path>
#   uninstall:  merge-claude-settings.py --uninstall <settings_path> <manifest_path>
#
# The three managed keys (enableAllProjectMcpServers, sandbox, permissions) are
# OVERWRITTEN wholesale on install. To make that reversible without disturbing a
# user's other settings, the FIRST install records each managed key's pre-install
# value (or its absence) in the manifest. Uninstall restores those exact values
# (or deletes the key if it was absent before us), leaving every other key alone.
#
# Notes:
#   - Backs up settings_path to <path>.bak.<timestamp> if it contains invalid JSON.
#   - Writes atomically via a temp file + os.replace().
#   - The manifest is never overwritten once written, so re-installs do not capture
#     our own managed blocks as the "pre-install" state.

import json, sys, os, time

MANAGED_KEYS = ["enableAllProjectMcpServers", "sandbox", "permissions"]


def write_json_atomic(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def load_json(path, default=None):
    if not os.path.exists(path):
        return default
    with open(path) as f:
        return json.load(f)


def uninstall(settings_path, manifest_path):
    manifest = load_json(manifest_path)
    if manifest is None:
        print(f"  [warn] no manifest at {manifest_path} — cannot safely revert "
              f"{settings_path}; leaving it untouched. Remove the "
              f"enableAllProjectMcpServers / sandbox / permissions blocks by hand "
              f"if you want them gone.")
        return
    try:
        settings = load_json(settings_path, {})
    except json.JSONDecodeError:
        bak = settings_path + ".bak." + str(int(time.time()))
        print(f"  [warn] {settings_path} is not valid JSON — backing up to {bak} "
              f"and reverting from an empty config")
        os.rename(settings_path, bak)
        settings = {}
    preinstall = manifest.get("preinstall", {})
    restored, deleted = [], []
    for key in manifest.get("managed_keys", MANAGED_KEYS):
        if key in preinstall:
            settings[key] = preinstall[key]
            restored.append(key)
        elif key in settings:
            del settings[key]
            deleted.append(key)
    write_json_atomic(settings_path, settings)
    if restored:
        print(f"  [ok]   restored pre-install values: {', '.join(restored)}")
    if deleted:
        print(f"  [ok]   removed keys we added: {', '.join(deleted)}")
    print(f"  [ok]   {settings_path} reverted")


def install(settings_path, apply_seccomp, user_config_path, manifest_path):
    with open(user_config_path) as f:
        user_config = json.load(f)

    sandbox = user_config["sandbox"]
    if apply_seccomp and os.path.exists(apply_seccomp):
        sandbox["seccomp"] = {"applyPath": apply_seccomp}

    existing = {}
    if os.path.exists(settings_path):
        with open(settings_path) as f:
            try:
                existing = json.load(f)
            except json.JSONDecodeError:
                bak = settings_path + ".bak." + str(int(time.time()))
                print(f"  [warn] {settings_path} is not valid JSON — backing up to {bak} and overwriting")
                os.rename(settings_path, bak)

    # First install only: record each managed key's pre-install value (or absence)
    # so uninstall can reverse exactly what we changed. Never overwrite an existing
    # manifest, or it would capture our own install as the "before" state.
    if not os.path.exists(manifest_path):
        preinstall = {k: existing[k] for k in MANAGED_KEYS if k in existing}
        os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
        write_json_atomic(manifest_path, {
            "managed_keys": MANAGED_KEYS,
            "preinstall": preinstall,
            "created": int(time.time()),
        })
        print(f"  [ok]   uninstall manifest written to {manifest_path}")

    existing["enableAllProjectMcpServers"] = user_config["enableAllProjectMcpServers"]
    existing["sandbox"] = sandbox
    existing["permissions"] = user_config["permissions"]
    write_json_atomic(settings_path, existing)
    print(f"  [ok]   sandbox settings written to {settings_path}")


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] in ("-h", "--help"):
        # Print this file's header comment block (single source of truth).
        with open(__file__) as _f:
            for _line in _f.read().splitlines()[1:]:   # skip the shebang
                if not _line.startswith("#"):
                    break
                print(_line[2:] if _line.startswith("# ") else _line[1:])
        sys.exit(0)
    if len(sys.argv) >= 2 and sys.argv[1] == "--uninstall":
        uninstall(sys.argv[2], sys.argv[3])
    else:
        install(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
