#!/usr/bin/env python3
"""PreToolUse guard: block skill/MCP/plugin installs that skip SkillSpector.

- Direct install commands (claude plugin/mcp add, npx skills add) -> deny.
- Commands whose WRITE DESTINATION is ~/.claude/skills or ~/.claude/plugins
  (cp/mv/ln target, redirect target, curl -o, unzip -d, tee, mkdir, ...) -> deny.
  Reading from those folders or running a script stored there is allowed.
- `safe-install-skill <src_dir> <name>` as the whole command -> scan with
  SkillSpector now; HIGH/CRITICAL/DO NOT INSTALL -> deny, otherwise ask the
  user with the score in the prompt. Executing it any other way -> deny.
- Write/Edit into skills/plugins dirs -> deny. Changes to this guard's own
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
INSTALLER = "safe-install-skill"
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
# Redirect straight into a protected dir (belt and braces next to token parsing).
REDIRECT_RE = re.compile(r">>?\s*['\"]?\S*\.claude/(skills|plugins)")
SHELL_META_RE = re.compile(r"[;&|`$<>(){}\n]")

SEPARATORS = {";", "&&", "||", "|", "&", "|&", "(", ")", ";;"}
REDIRECTS = {">", ">>", ">|", "&>", "&>>"}
# Destination is the LAST non-option argument (or the value of -t).
DEST_LAST = {"cp", "mv", "ln", "rsync", "install", "scp"}
# Every non-option argument is a write target.
DEST_ANY = {"tee", "touch", "mkdir", "truncate"}
# Only the value of these options is a write target.
DEST_OPTS = {
    "curl": {"-o", "--output", "--output-dir"},
    "wget": {"-O", "-P", "--output-document", "--directory-prefix"},
    "unzip": {"-d"},
    "tar": {"-C", "--directory"},
    "cp": {"-t", "--target-directory"},
    "mv": {"-t", "--target-directory"},
    "install": {"-t", "--target-directory"},
}
GIT_WRITE_SUBCMDS = {"pull", "merge", "checkout", "switch", "reset", "restore", "rebase", "apply", "am",
                     "clone", "init", "cherry-pick", "stash", "submodule"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
INTERPRETERS = SHELLS | {"python", "python3", "node", "perl", "ruby", "deno", "bun"}
WRAPPERS = {"sudo", "env", "nohup", "time", "timeout", "nice", "xargs", "exec", "eval",
            "command", "stdbuf", "setsid", "ionice", "watch"}


def out(decision, reason):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
    }}))
    sys.exit(0)


def deny_write():
    out("deny", "Writing into ~/.claude/skills or ~/.claude/plugins is blocked. "
                "Use: safe-install-skill <quarantine_dir> <name>.")


def deny_not_alone():
    out("deny", "Run safe-install-skill alone as the entire command, so the approval prompt is shown.")


def is_protected(text):
    return bool(PROTECTED_DIR_RE.search(text))


def is_guard_file(text):
    return any(g in text for g in GUARD_FILES)


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


def tokenize(cmd):
    """Shell-ish tokens with operators (; && | > ...) as separate tokens."""
    text = cmd.replace("\n", " ; ").replace("`", " ; ").replace("$(", " ( ")
    try:
        lex = shlex.shlex(text, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        return list(lex)
    except ValueError:  # unbalanced quotes etc: crude but safe fallback
        return re.sub(r"(\|\||&&|>>|[;|&()<>])", r" \1 ", text).split()


def split_segments(tokens):
    """-> list of (command_tokens, redirect_targets) per simple command."""
    segments, cur, redirs = [], [], []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in SEPARATORS:
            segments.append((cur, redirs))
            cur, redirs = [], []
        elif tok in REDIRECTS:
            if i + 1 < len(tokens):
                redirs.append(tokens[i + 1])
                i += 1
        else:
            cur.append(tok)
        i += 1
    segments.append((cur, redirs))
    return [s for s in segments if s[0] or s[1]]


def strip_prefix(tokens):
    """Drop VAR=value assignments and wrapper commands (sudo, env, xargs, ...)."""
    toks = list(tokens)
    while toks:
        head = os.path.basename(toks[0])
        if re.match(r"^\w+=", toks[0]):
            toks = toks[1:]
        elif head in WRAPPERS:
            toks = toks[1:]
            while toks and (toks[0].startswith("-") or re.match(r"^\w+=", toks[0])
                            or re.fullmatch(r"[\d.]+[smhd]?", toks[0])):
                toks = toks[1:]
        else:
            break
    return toks


def write_targets(cmdw, args):
    """Paths this simple command writes to (best effort)."""
    targets = []
    opts = DEST_OPTS.get(cmdw, set())
    for i, a in enumerate(args):
        if a in opts and i + 1 < len(args):
            targets.append(args[i + 1])
        for o in opts:
            if a.startswith(o + "="):
                targets.append(a.split("=", 1)[1])
            elif len(o) == 2 and a.startswith(o) and len(a) > 2 and not a.startswith("--"):
                targets.append(a[2:])
    nonopt = [a for a in args if not a.startswith("-")]
    if cmdw in DEST_LAST and nonopt:
        targets.append(nonopt[-1])
    if cmdw in DEST_ANY:
        targets.extend(nonopt)
    if cmdw == "dd":
        targets.extend(a[3:] for a in args if a.startswith("of="))
    if cmdw == "git" and "clone" in args and nonopt:
        targets.append(nonopt[-1])
    if cmdw in ("sed", "perl") and any(re.match(r"^-[a-zA-Z]*i", a) or a.startswith("--in-place") for a in args):
        targets.extend(nonopt)
    return targets


def check_segment(tokens, redirs, state, depth):
    # A protected path stored in a variable (D=~/.claude/skills; cp x $D/) hides the target.
    for tok in tokens:
        m = re.match(r"^\w+=(.*)", tok)
        if m and is_protected(m.group(1)):
            state["var_protected"] = True
    for target in redirs:
        if is_protected(target) or state["in_protected"] or (state["var_protected"] and "$" in target):
            deny_write()
        if is_guard_file(target):
            state["ask_guard"] = True
    toks = strip_prefix(tokens)
    if toks and toks[0] in ("export", "declare", "local", "readonly"):
        return
    if not toks:
        return
    cmdw, args = os.path.basename(toks[0]), toks[1:]

    if cmdw == INSTALLER:
        deny_not_alone()  # the whole-command case was handled before parsing
    if cmdw in INTERPRETERS and any(os.path.basename(a) == INSTALLER for a in args):
        deny_not_alone()
    if cmdw == "find":
        for flag in ("-exec", "-execdir", "-ok"):
            if flag in args:
                check_segment(args[args.index(flag) + 1:], [], state, depth)

    if cmdw in ("cd", "pushd") and args:
        state["in_protected"] = is_protected(args[-1]) or (state["var_protected"] and "$" in args[-1])
        return

    if cmdw == "git" and any(a in GIT_WRITE_SUBCMDS for a in args):
        git_dir = [args[i + 1] for i, a in enumerate(args[:-1]) if a == "-C"]
        if state["in_protected"] or any(is_protected(d) for d in git_dir):
            deny_write()  # changes the code of an installed plugin/skill without a scan

    targets = write_targets(cmdw, args)
    if targets and state["var_protected"] and any("$" in t for t in targets):
        deny_write()  # target built from a variable that holds a protected path
    if targets and state["in_protected"] and any(not os.path.isabs(os.path.expanduser(t)) for t in targets):
        deny_write()  # relative write after cd into a protected dir
    for target in targets:
        if is_protected(target):
            deny_write()
        if is_guard_file(target):
            state["ask_guard"] = True

    if cmdw in INTERPRETERS:
        for i, a in enumerate(args):
            if a in ("-c", "-e", "--eval", "-p", "--print") and i + 1 < len(args):
                inline = args[i + 1]
                if INSTALLER in inline:
                    deny_not_alone()
                if is_protected(inline):
                    deny_write()  # inline code touching a protected dir: cannot tell read from write
                if is_guard_file(inline):
                    state["ask_guard"] = True
                if cmdw in SHELLS and depth < 3:
                    check_tokens(tokenize(inline), state, depth + 1)


def check_tokens(tokens, state, depth=0):
    for seg_tokens, redirs in split_segments(tokens):
        check_segment(seg_tokens, redirs, state, depth)


def check_bash(cmd):
    stripped = cmd.strip()
    if re.match(r"^(/usr/local/bin/)?safe-install-skill(\s|$)", stripped):
        check_safe_install(re.sub(r"^/usr/local/bin/", "", stripped))
    for rx in INSTALL_CMD_RES:
        if rx.search(cmd):
            out("deny", "Direct skill/MCP/plugin install blocked. Quarantine it, scan with "
                        "SkillSpector, get user approval, then use: safe-install-skill <dir> <name>.")
    if REDIRECT_RE.search(cmd):
        deny_write()
    state = {"in_protected": False, "var_protected": False, "ask_guard": False}
    check_tokens(tokenize(cmd), state)
    if state["ask_guard"]:
        out("ask", "This command may change the skill-install guard itself. Allow?")


def check_file(path):
    real = os.path.realpath(path)
    if is_protected(real):
        deny_write()
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
