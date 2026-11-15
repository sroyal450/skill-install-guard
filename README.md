# skill-install-guard

A Claude Code guardrail: no skill, MCP server or plugin gets installed unless it
was scanned with [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector)
and a human approved it.

## Pieces

| File | Goes to | Job |
|---|---|---|
| `hooks/skill-install-guard.py` | `~/.claude/hooks/` | PreToolUse hook. Denies `npx skills add`, `claude plugin install`, `claude mcp add`, and writes into `~/.claude/skills` / `~/.claude/plugins`. For `safe-install-skill`, runs a SkillSpector scan and shows the user a permission prompt with the score; HIGH / CRITICAL / DO NOT INSTALL is denied outright. |
| `bin/safe-install-skill` | `/usr/local/bin/` | The one allowed install route. Copies the skill to a private temp dir, scans that exact copy, refuses symlinks / bad names / existing targets / risky scores, installs, verifies sha256 of every file. |
| `settings-snippet.json` | merge into `~/.claude/settings.json` | Registers the hook and adds a `permissions.deny` list as a second lock. |

## Usage

```bash
safe-install-skill /path/to/quarantined/skill-folder skill-name
```

Run it alone as the whole command, otherwise the guard denies it (so the approval
prompt cannot be skipped).

## Requirements

- `skillspector` at `/usr/local/bin/skillspector`. The absolute path is deliberate,
  so a fake scanner earlier in `PATH` cannot fake a result.
- Python 3.

## Limits

- Text-pattern matching on shell commands is a guardrail against accidental or
  instructed installs, not a sandbox: wildcards, variables or encoded commands can
  get around it. The `permissions.deny` list and the policy text are extra layers.
- Unexpected errors in the hook allow the command (so a bug cannot break every
  command). A failed scan always blocks the install.
- Installs done through the claude.ai web UI never pass through the hook.

## Tests

```bash
python3 -I tests/test_guard.py [safe_skill_dir] [risky_skill_dir]
```

Feeds sample tool calls to the hook and checks each allow / deny / ask decision.
The two optional folders enable the cases that need a real SkillSpector scan.
