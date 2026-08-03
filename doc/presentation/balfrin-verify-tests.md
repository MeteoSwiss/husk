# Balfrin verification tests — the 3 open config questions

Copy-paste ready. Grades from exit codes / file diffs, not from any agent's prose.
Run on Balfrin/Santis where claude-safe is installed.

Grounding (from the repo, already true):
- `user-config/settings.json` ships `sandbox.filesystem.denyRead: ["/users"]`,
  `allowRead: ["./"]` — the broad `/users` deny is real.
- `sandbox-runtime/README.md`: **"`allowRead` takes precedence over `denyRead`"**
  (read = deny-then-re-allow; write is the opposite). Test 2 confirms on hardware.
- `user-config/settings.json` `permissions.deny` already blocks
  `Write/Edit(.claude/settings.json)` and `…local.json`. Test 1 checks whether the
  CLI sandbox toggle bypasses that (internal mutation, not a Write tool call).

## 0. Locate the standalone sandbox CLI (`srt`)

```bash
SRT="$(command -v srt || true)"
if [ -z "$SRT" ]; then
  # fall back to the copy claude-safe installed, else npx
  SRT="$(find "$HOME" /opt -maxdepth 6 -name cli.js -path '*sandbox-runtime/dist*' 2>/dev/null | head -1)"
  [ -n "$SRT" ] && SRT="node $SRT" || SRT="npx --yes @anthropic-ai/sandbox-runtime"
fi
echo "using: $SRT"
$SRT "echo srt-works"      # sanity check
```

---

## Test 1 — Does the CLI "sandbox off" persist, and to which file?

**Question:** disabling the sandbox once from the CLI — does it write to the
*shared* `.claude/settings.json` or to `.claude/settings.local.json`, and does it
slip past claude-safe's `Write/Edit` deny on those files?

### Setup — known starting state + snapshot

```bash
mkdir -p ~/sbtest1 && cd ~/sbtest1
mkdir -p .claude
printf '{ "sandbox": { "enabled": true } }\n' > .claude/settings.json
rm -f .claude/settings.local.json
# snapshot every candidate file
for f in "$HOME/.claude/settings.json" .claude/settings.json .claude/settings.local.json; do
  [ -f "$f" ] && cp -a "$f" "$f.before"
done
{ for f in "$HOME/.claude/settings.json" .claude/settings.json .claude/settings.local.json; do
    [ -f "$f" ] && sha256sum "$f"; done; } > BEFORE.sha
cat BEFORE.sha
```

### Action (manual, in a claude-safe session from `~/sbtest1`)

1. Launch claude-safe in `~/sbtest1`.
2. Do the exact gesture you've seen turn the sandbox off (declining a sandbox
   prompt / the `/config` toggle / accepting "run unsandboxed and remember").
3. Exit.

### Grade — which file changed, and the exact key

```bash
cd ~/sbtest1
{ for f in "$HOME/.claude/settings.json" .claude/settings.json .claude/settings.local.json; do
    [ -f "$f" ] && sha256sum "$f"; done; } > AFTER.sha
echo "== changed files =="; diff BEFORE.sha AFTER.sha
for f in "$HOME/.claude/settings.json" .claude/settings.json .claude/settings.local.json; do
  [ -f "$f.before" ] && { echo "== diff $f =="; diff "$f.before" "$f"; }
  [ -f "$f" ] && [ ! -f "$f.before" ] && { echo "== NEW $f =="; cat "$f"; }
done
```

**Read-off:**
- The file in the `diff` is the answer to "which file."
- The added line is the exact key (expect `"enabled": false` under `sandbox`,
  or an `allowUnsandboxedCommands` / per-command allow flip).
- **If it wrote to `.claude/settings.json` despite the `Write/Edit` deny → the
  toggle bypasses the permission guard.** That's the slide-25 footgun, confirmed,
  and an argument for an install-time `chmod 0444` / git-hook tripwire on that file.

---

## Test 2 — Does a specific `allowRead` override a broad `denyRead`?

**Question:** with `/users` denied, does re-allowing `…/miniconda3` actually let
Bash read inside it — while everything else under `/users` stays blocked?
**Agent not needed** — drive the sandbox directly with `srt`.

### Setup — canaries + two settings files

```bash
mkdir -p ~/sbtest2/proj && cd ~/sbtest2/proj
mkdir -p ~/sbtest2/fake-conda ~/sbtest2/secret-other
echo HOLE_CANARY   > ~/sbtest2/fake-conda/canary.txt
echo SECRET_CANARY > ~/sbtest2/secret-other/canary.txt

# A: broad deny, no hole
cat > ~/sbtest2/A.json <<EOF
{ "filesystem": { "denyRead": ["/users"], "allowRead": ["."] } }
EOF
# B: broad deny + re-allow just the fake-conda path
cat > ~/sbtest2/B.json <<EOF
{ "filesystem": { "denyRead": ["/users"], "allowRead": [".", "$HOME/sbtest2/fake-conda"] } }
EOF
```

### Run + grade (from `~/sbtest2/proj`)

```bash
cd ~/sbtest2/proj
chk() { echo "--- $1 ---"; $SRT --settings "$2" "cat $3" && echo "[READABLE]" || echo "[BLOCKED]"; }

chk "A: fake-conda (no hole) -> expect BLOCKED" ~/sbtest2/A.json "$HOME/sbtest2/fake-conda/canary.txt"
chk "B: fake-conda (hole)    -> expect READABLE" ~/sbtest2/B.json "$HOME/sbtest2/fake-conda/canary.txt"
chk "B: secret-other         -> expect BLOCKED"  ~/sbtest2/B.json "$HOME/sbtest2/secret-other/canary.txt"
```

**Pass =** BLOCKED / READABLE / BLOCKED. That proves: broad deny holds, a specific
`allowRead` punches exactly one hole, and the deny still covers everything else —
i.e. the `~/miniconda3` recipe in `project-config/README.md` is sound on hardware.

---

## Test 3 — Does the Read tool respect `sandbox.filesystem`, or only `permissions`?

**Question:** the "two doors" claim. Bash reads go through `sandbox.filesystem`.
Does the **Read tool** also honor it, or only the `permissions` layer? This one
*needs* Claude (only it can issue a Read-tool call).

### Setup — a file blocked by the sandbox but NOT by any `Read(...)` deny

```bash
mkdir -p ~/sbtest3/proj && cd ~/sbtest3/proj
mkdir -p ~/sbtest3/outside
echo TWO_DOORS_CANARY > ~/sbtest3/outside/plain.txt   # not *.env/*.pem/etc → no permissions deny matches
```

Use a project `.claude/settings.json` that denies `/users` for the sandbox but adds
**no** `Read()` deny for this file:

```bash
mkdir -p ~/sbtest3/proj/.claude
cat > ~/sbtest3/proj/.claude/settings.json <<'EOF'
{ "sandbox": { "enabled": true, "filesystem": { "denyRead": ["/users"], "allowRead": ["./"] } } }
EOF
```

Note: if claude-safe's **user** `~/.claude/settings.json` adds `Read(...)` denies
that happen to match this plain `.txt`, pick a path/name none of them match (the
shipped denies only hit `*.env`/`*.pem`/`*.key`/`credentials`, so `plain.txt` is
clear).

### Action (in a claude-safe session from `~/sbtest3/proj`)

Ask Claude, verbatim, to do BOTH and report raw results:

> Run `cat ~/sbtest3/outside/plain.txt` with the Bash tool, then separately open
> `~/sbtest3/outside/plain.txt` with the Read tool. Tell me the exact result of
> each (content or the error string), no interpretation.

### Read-off (the matrix)

| Bash (`cat`) | Read tool | Conclusion |
|---|---|---|
| BLOCKED | BLOCKED | Read tool **also** respects `sandbox.filesystem` — one door covers both |
| BLOCKED | reads `TWO_DOORS_CANARY` | **Two genuinely separate doors** — Read tool ignores the sandbox, governed only by `permissions`. Confirms slide 22: you must deny on **both** layers |

The second row is the one the `.env` leak predicts. If you get it, the slide-22
framing is verified and the practical rule stands: **mirror every `sandbox`
filesystem deny with a `permissions` `Read(...)` deny** (and vice-versa).

---

## What each result feeds back into the talk

- **T1** → slide 25 (footgun): names the file + proves/disproves the deny guard.
- **T2** → slides 23/24: confirms deny-broad + allow-narrow works on hardware.
- **T3** → slide 22: confirms "two doors" (or simplifies it to one).
