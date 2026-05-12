#!/usr/bin/env python3
# merge-claude-settings.py — merge user-config/settings.json into ~/.claude/settings.json
#
# Usage:
#   merge-claude-settings.py <settings_path> <apply_seccomp_path> <user_config_path>
#
# Arguments:
#   settings_path      path to ~/.claude/settings.json (created if absent)
#   apply_seccomp_path path to apply-seccomp binary; empty string if not installed
#   user_config_path   path to user-config/settings.json (source of truth)
#
# Behaviour:
#   - Reads user_config_path and writes enableAllProjectMcpServers, sandbox,
#     and permissions blocks into settings_path, preserving all other keys.
#   - Injects sandbox.seccomp.applyPath if apply_seccomp_path is non-empty and exists.
#   - Backs up settings_path to <path>.bak.<timestamp> if it contains invalid JSON.
#   - Writes atomically via a temp file + os.replace().

import json, sys, os, time

settings_path    = sys.argv[1]
apply_seccomp    = sys.argv[2]
user_config_path = sys.argv[3]

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

existing["enableAllProjectMcpServers"] = user_config["enableAllProjectMcpServers"]
existing["sandbox"] = sandbox
existing["permissions"] = user_config["permissions"]

tmp_path = settings_path + ".tmp"
with open(tmp_path, "w") as f:
    json.dump(existing, f, indent=2)
    f.write("\n")
os.replace(tmp_path, settings_path)

print(f"  [ok]   sandbox settings written to {settings_path}")
