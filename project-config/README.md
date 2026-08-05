# Project configuration template

Copy `settings.json` from this directory into your project's `.claude/` folder:

```bash
mkdir -p .claude
cp /path/to/agentskills-internal/project-config/settings.json .claude/settings.json
```

Commit `.claude/settings.json` so the restrictions apply to everyone working on the project. Claude Code automatically gitignores `.claude/settings.local.json`, which is the right place for per-user overrides.

This file covers only the workflow decisions that vary per project. Machine-wide rules (credential files, nc/socat, SLURM allow list, settings.json protection, `enableAllProjectMcpServers`) are set globally by `install-husk.sh` and apply automatically.

## What each entry does

**`permissions.deny`**

> **Note on enforcement:** These rules match on the command string Claude Code
> submits to the Bash tool — `Bash(ssh *)` blocks `ssh user@host` but not
> `/usr/bin/ssh user@host` or an indirect invocation via Python. They prevent
> accidental direct use; they are not an airtight barrier. The real egress
> boundary is the bwrap network namespace — until that is wired up, `curl`,
> `wget`, `ssh`, and friends are denied here as a compensating control.
> See `doc/constraints.md` for the full rationale.

| Entry | What it blocks | Why |
|---|---|---|
| `Bash(ssh *)` | SSH connections | Prevents the agent from reaching other cluster nodes or exfiltrating data |
| `Bash(scp *)` | Secure copy | Same as SSH |
| `Bash(rsync *)` | Remote sync | Same as SSH |
| `Bash(curl *)` | Outbound HTTP/HTTPS | Limits data exfiltration and access to cluster services reachable from login nodes |
| `Bash(wget *)` | Outbound HTTP/HTTPS | Same as curl |
| `mcp__*` | All MCP tool calls | Prevents a compromised or malicious MCP server from being used as a pivot point |

> **Note on MCP:** `enableAllProjectMcpServers: false` (set globally by the install script) prevents project-local `.mcp.json` files from auto-loading MCP servers, but user-level MCP servers configured in `~/.claude/` are unaffected. If you use user-level MCP servers, review them independently.

## Relaxing restrictions

Some entries may be too aggressive for your workflow:

- **`curl`/`wget`**: if your project fetches data from a fixed set of known endpoints, remove these from `deny` and add a `network.allowedDomains` allowlist to your `.claude/settings.json` instead — the proxy enforces it for all outbound traffic, not just explicit curl/wget calls, making it a stronger control. If your project does general coding work where Claude reads documentation from unpredictable sites, keep the deny rules and accept that Claude cannot browse the web.
- **`ssh`**: if you regularly ask Claude to run commands on compute nodes, remove this from `deny` so it prompts for confirmation rather than hard-blocking.
- **`mcp__*`**: if you use specific MCP servers you trust, remove this entry.

## Giving Claude access to your Python environment

The global sandbox blocks the entire home directory from Claude's view, with
only the current project directory visible. If your conda environment or Python
installation lives inside your home directory (e.g. `~/miniconda3/`), Claude's
Bash commands won't find it — home directories are blocked by the sandbox.

Check where your Python lives:

```bash
which python3
echo $CONDA_PREFIX
```

If the path starts with `/users/` (or your site's home directory prefix), add
it to `allowRead` in your project's `.claude/settings.json`:

```json
{
  "sandbox": {
    "filesystem": {
      "allowRead": ["./", "/users/yourusername/miniconda3/"]
    }
  }
}
```

Adjust the path to match your actual installation. If your Python is on
`/scratch/` or loaded via a module, no change is needed — paths outside the
home directories are already visible inside the sandbox.
