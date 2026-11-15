"""Decision tests for hooks/skill-install-guard.py.

Usage: python3 -I tests/test_guard.py [safe_skill_dir] [risky_skill_dir]
The two optional folders enable the cases that need a real SkillSpector scan.
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUARD = os.environ.get("GUARD", os.path.join(ROOT, "hooks", "skill-install-guard.py"))
SAFE = sys.argv[1] if len(sys.argv) > 1 else None
RISKY = sys.argv[2] if len(sys.argv) > 2 else None
PLUG = "/root/.claude/plugins/synced/abc_def/caveman/src/hooks/caveman-statusline.sh"
HOOK = "/root/.claude/hooks/skill-install-guard.py"

CASES = [
    # --- ordinary work must pass ---
    ("Bash", "ls ~/.claude/skills", "allow"),
    ("Bash", "cat ~/.claude/skills/find-skills/SKILL.md", "allow"),
    ("Bash", "git status", "allow"),
    ("Bash", "npx skills find react", "allow"),
    ("Bash", "ls /root/.claude/skills; ls /tmp/x 2>&1", "allow"),
    ("Bash", "ls ~/.claude/skills >/dev/null", "allow"),
    ("Bash", "grep -r foo ~/.claude/skills", "allow"),
    ("Write", "/home/user/notes.md", "allow"),
    # --- running / reading things that live in protected dirs must pass ---
    ("Bash", f"bash {PLUG} | cat -v", "allow"),
    ("Bash", f'bash "{PLUG}"', "allow"),
    ("Bash", "node /root/.claude/plugins/cache/x/dist/cli.js --help", "allow"),
    ("Bash", "python3 ~/.claude/skills/foo/scripts/run.py --arg 1", "allow"),
    ("Bash", f'python3 -m json.tool ~/.claude/settings.json >/dev/null && bash "{PLUG}" | cat -v', "allow"),
    ("Bash", "cp ~/.claude/skills/find-skills/SKILL.md /tmp/x.md", "allow"),
    ("Bash", "tar czf /tmp/backup.tgz ~/.claude/skills", "allow"),
    ("Bash", "sh ~/.claude/plugins/p/run.sh > /tmp/out.txt 2>&1", "allow"),
    ("Bash", "cd ~/.claude/plugins/p && ls -la", "allow"),
    ("Bash", "cd ~/.claude/plugins/p && node index.js", "allow"),
    # --- merely mentioning the installer must pass ---
    ("Bash", "cat /usr/local/bin/safe-install-skill", "allow"),
    ("Bash", "ls -l /usr/local/bin/safe-install-skill", "allow"),
    ("Bash", "ls /root/.claude/hooks; which skillspector safe-install-skill", "allow"),
    ("Bash", "git commit -m 'document safe-install-skill usage'", "allow"),
    ("Bash", "grep -n safe-install-skill README.md | head", "allow"),
    ("Bash", "cp /usr/local/bin/safe-install-skill /tmp/copy-for-review", "allow"),
    ("Bash", f"cat {HOOK}", "allow"),
    ("Bash", f"python3 -I {HOOK}", "allow"),
    # --- direct installs must be denied ---
    ("Bash", "npx skills add vercel-labs/agent-skills@x -g -y", "deny"),
    ("Bash", "npx -y skills@1.2.0 add foo/bar", "deny"),
    ("Bash", "claude plugin install foo@bar", "deny"),
    ("Bash", "claude mcp add evil -- npx evil-mcp", "deny"),
    # --- writes whose destination is a protected dir must be denied ---
    ("Bash", "cp -r /tmp/x ~/.claude/skills/x", "deny"),
    ("Bash", "mv /tmp/x /root/.claude/plugins/x", "deny"),
    ("Bash", "cp -t ~/.claude/skills/x /tmp/a /tmp/b", "deny"),
    ("Bash", "ln -s /tmp/evil ~/.claude/skills/evil", "deny"),
    ("Bash", "git clone https://github.com/a/b /root/.claude/plugins/b", "deny"),
    ("Bash", "echo hi > ~/.claude/skills/x/SKILL.md", "deny"),
    ("Bash", "echo x >> ~/.claude/skills/a/SKILL.md", "deny"),
    ("Bash", "echo x>/root/.claude/plugins/p.json", "deny"),
    ("Bash", "tee ~/.claude/skills/a/SKILL.md < f", "deny"),
    ("Bash", "mkdir -p ~/.claude/skills/new", "deny"),
    ("Bash", "curl -sL https://x.example/s.md -o ~/.claude/skills/a/SKILL.md", "deny"),
    ("Bash", "unzip /tmp/a.zip -d ~/.claude/plugins/p", "deny"),
    ("Bash", "tar xzf /tmp/a.tgz -C ~/.claude/skills", "deny"),
    ("Bash", "sed -i s/a/b/ ~/.claude/skills/a/SKILL.md", "deny"),
    ("Bash", "python3 -c 'open(\"/root/.claude/skills/a\",\"w\")'", "deny"),
    ("Bash", "bash -c 'cp /tmp/x ~/.claude/skills/x'", "deny"),
    ("Bash", "sudo cp /tmp/x ~/.claude/skills/x", "deny"),
    ("Bash", "cd ~/.claude/skills && cp -r /tmp/x .", "deny"),
    ("Bash", "cd ~/.claude/skills && echo hi > x.md", "deny"),
    ("Bash", "ls /tmp && cp /tmp/x ~/.claude/skills/x", "deny"),
    ("Write", "/root/.claude/skills/new/SKILL.md", "deny"),
    ("Bash", "D=~/.claude/skills; cp -r /tmp/x $D/x", "deny"),
    ("Bash", "export D=/root/.claude/plugins && echo hi > $D/p.json", "deny"),
    ("Bash", "pushd ~/.claude/skills && cp -r /tmp/x .", "deny"),
    ("Bash", "git -C ~/.claude/plugins/marketplaces/x pull", "deny"),
    ("Bash", "cd ~/.claude/plugins/x && git checkout evil-branch", "deny"),
    ("Bash", "git -C ~/.claude/plugins/marketplaces/x log --oneline", "allow"),
    ("Bash", "D=~/.claude/skills; ls $D", "allow"),
    ("Bash", "cd /home/user/proj && git pull && cp a.txt b.txt", "allow"),
    # --- running the installer any way but alone must be denied ---
    ("Bash", "cd /tmp && safe-install-skill /tmp/q x", "deny"),
    ("Bash", "bash -c 'safe-install-skill /tmp/q x'", "deny"),
    ("Bash", "env safe-install-skill /tmp/q x", "deny"),
    ("Bash", "python3 /usr/local/bin/safe-install-skill /tmp/q x", "deny"),
    ("Bash", "echo /tmp/q | xargs safe-install-skill", "deny"),
    ("Bash", "find /tmp/q -maxdepth 0 -exec safe-install-skill {} x ;", "deny"),
    ("Bash", "echo $(safe-install-skill /tmp/q x)", "deny"),
    ("Bash", "safe-install-skill /tmp/q y; rm -rf /tmp/zzz", "deny"),
    # --- changing the guard itself must ask ---
    ("Edit", HOOK, "ask"),
    ("Bash", f"cp /tmp/x {HOOK}", "ask"),
    ("Bash", "echo '{}' > /root/.claude/settings.json", "ask"),
]
if SAFE:
    CASES += [
        ("Bash", f"safe-install-skill {SAFE} zz-test-a", "ask"),
        ("Bash", f"/usr/local/bin/safe-install-skill {SAFE} zz-test-b", "ask"),
    ]
if RISKY:
    CASES += [("Bash", f"safe-install-skill {RISKY} zz-test-c", "deny")]


def decide(tool, arg):
    ti = {"command": arg} if tool == "Bash" else {"file_path": arg}
    r = subprocess.run([sys.executable, "-I", GUARD], input=json.dumps({"tool_name": tool, "tool_input": ti}),
                       capture_output=True, text=True)
    if r.stderr.strip():
        return "error:" + r.stderr.strip()[:80]
    if not r.stdout.strip():
        return "allow"
    return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"]


def main():
    bad = 0
    for tool, arg, want in CASES:
        got = decide(tool, arg)
        if got != want:
            bad += 1
            print(f"FAIL want={want:5} got={got:5} {tool}: {arg}")
    print(f"{len(CASES) - bad}/{len(CASES)} passed")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
