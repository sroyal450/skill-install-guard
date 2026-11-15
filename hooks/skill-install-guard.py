#!/usr/bin/env python3
"""PreToolUse guard: block skill/MCP/plugin installs that skip SkillSpector.

- Direct install commands (claude plugin/mcp add, npx skills add, writes into
  ~/.claude/skills or ~/.claude/plugins) -> deny.
- `safe-install-skill <src_dir> <name>` (one plain command) -> scan with
  SkillSpector now; HIGH/CRITICAL/DO NOT INSTALL -> deny, otherwise ask the
  user with the score in the prompt.
- Write/Edit into skills/plugins dirs -> deny. Edits to this guard's own
  files -> ask.
- Any unexpected error -> allow (never break normal work); stderr notes it.
"""
import json
import os
import re
import shlex
import subprocess
import sys

HOME = os.path.expanduser("~")
# Absolute path: a fake "skillspector" earlier in PATH must not be able to fake a scan.
SKILLSPECTOR = "/usr/local/bin/skillspector"
GUARD_FILES = (
    os.path.join(HOME, ".claude", "hooks", "skill-install-guard.py"),
    "/usr/local/bin/safe-install-skill",
    os.path.join(HOME, ".claude", "settings.json"),
    "/home/user/.claude/settings.json",
)
PROTECTED_DIR_RE = re.compile(r"\.claude/(skills|plugins)(/|\b)")
INSTALL_CMD_RES = [
    re.compile(r"\bclaude\s+(plugins?|mcp)\s+(install|add|add-json|add-from-claude-desktop|marketplace\s+add)\b"),
    re.compile(r"\b(npx|bunx|pnpx|pnpm\s+dlx|yarn\s+dlx)\s+(-y\s+|--yes\s+)?skills(@\S+)?\s+(add|install|update)\b"),
    re.compile(r"(^|[\s;&|(])skills\s+(add|install)\b"),
]
WRITE_VERB_RE = re.compile(
    # verbs must be whole words: not part of a hyphenated/dotted name like safe-install-skill
    r"(?<![\w.-])(cp|mv|ln|rsync|install|curl|wget|tee|unzip|tar|git\s+clone|mkdir|touch|dd|sed\s+-i"
    r"|python3?|node|perl|bash|sh)(?![\w.-])"
    # or a redirect whose target is a protected dir (2>&1 and >/dev/null don't count)
    r"|>>?\s*['\"]?\S*\.claude/(skills|plugins)"
)
SHELL_META_RE = re.compile(r"[;&|`$<>(){}\n]")
READ_ONLY_CMDS = {"cat", "less", "head", "tail", "grep", "ls", "stat", "sha256sum", "wc", "diff", "file"}


def out(decision, reason):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
    }}))
    sys.exit(0)


def scan(src):
    proc = subprocess.run(
        [SKILLSPECTOR, "scan", src, "--no-llm", "--format", "json"],
        capture_output=True, text=True, timeout=100,
    )
    data = json.loads(proc.stdout)
    ra = data.get("risk_assessment") or {}
    return data, ra


def check_safe_install(cmd):
    if SHELL_META_RE.search(cmd):
        out("deny", "safe-install-skill must be run as one plain command "
                    "(no ; & | $ ` < > or subshells).")
    parts = shlex.split(cmd)
    if len(parts) != 3:
        out("deny", "Usage: safe-install-skill <quarantine_dir> <skill-name>")
    src = os.path.realpath(parts[1])
    try:
        data, ra = scan(src)
    except Exception as exc:  # scan failure must not become an approval
        out("deny", f"SkillSpector scan failed, install blocked: {exc}")
    sev = str(ra.get("severity", "UNKNOWN")).upper()
    rec = str(ra.get("recommendation", "UNKNOWN")).upper().replace("_", " ")
    score = ra.get("score", "?")
    n = len(data.get("issues") or [])
    summary = f"SkillSpector: score {score}/100, severity {sev}, recommendation {rec}, {n} issue(s)."
    if (not data.get("execution_successful", False) or sev in ("HIGH", "CRITICAL")
            or "DO NOT" in rec or rec in ("UNSAFE", "BLOCK")):
        out("deny", summary + " Refused by install policy (HIGH/CRITICAL/DO NOT INSTALL or scan incomplete).")
    out("ask", summary + f" Install skill '{parts[2]}' from {src}? Approve only if you agreed in chat.")


def check_bash(cmd):
    stripped = cmd.strip()
    if re.match(r"^(/usr/local/bin/)?safe-install-skill(\s|$)", stripped):
        check_safe_install(re.sub(r"^/usr/local/bin/", "", stripped))
    if "safe-install-skill" in cmd:
        # Only plain read-only looks at the tool are allowed; any other mention
        # (after cd/&&, via bash -c, env, etc.) would skip the approval prompt.
        first = stripped.split()[0] if stripped else ""
        if first not in READ_ONLY_CMDS or SHELL_META_RE.search(cmd):
            out("deny", "Run safe-install-skill alone as the entire command, so the approval prompt is shown.")
    for rx in INSTALL_CMD_RES:
        if rx.search(cmd):
            out("deny", "Direct skill/MCP/plugin install blocked. Quarantine it, scan with "
                        "SkillSpector, get user approval, then use: safe-install-skill <dir> <name>.")
    if PROTECTED_DIR_RE.search(cmd) and WRITE_VERB_RE.search(cmd):
        out("deny", "Writing into ~/.claude/skills or ~/.claude/plugins is blocked. "
                    "Use: safe-install-skill <quarantine_dir> <name>.")
    if any(g in cmd for g in GUARD_FILES) and WRITE_VERB_RE.search(cmd):
        out("ask", "This command may change the skill-install guard itself. Allow?")


def check_file(path):
    real = os.path.realpath(path)
    if PROTECTED_DIR_RE.search(real):
        out("deny", "Writing into ~/.claude/skills or ~/.claude/plugins is blocked. "
                    "Use: safe-install-skill <quarantine_dir> <name>.")
    if real in GUARD_FILES:
        out("ask", "This edit changes the skill-install guard itself. Allow?")


def main():
    try:
        payload = json.load(sys.stdin)
        tool = payload.get("tool_name", "")
        ti = payload.get("tool_input") or {}
        if tool == "Bash":
            check_bash(ti.get("command", ""))
        elif tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            check_file(ti.get("file_path") or ti.get("notebook_path") or "")
    except SystemExit:
        raise
    except Exception as exc:
        print(f"skill-install-guard error (allowing): {exc}", file=sys.stderr)
    sys.exit(0)


if __name__ == "__main__":
    main()
