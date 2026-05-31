#!/usr/bin/env python3
"""
phase_gate.py — PreToolUse hook
Blocks attack tools and attack agents until RECON-COMPLETE.md exists.
Blocks parallel agent spawns.
"""
import json, sys, os, time

def get_target():
    f = '/home/hunter/new_agent/state/.active-target'
    if not os.path.exists(f): return None
    return open(f).read().strip()

def recon_complete(target):
    if not target: return True
    return os.path.exists(
        f'/home/hunter/new_agent/targets/{target}/recon/RECON-COMPLETE.md'
    )

def deny(reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason
        }
    }))
    sys.exit(0)

def allow():
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow"
        }
    }))
    sys.exit(0)

try:
    data   = json.load(sys.stdin)
    tool   = data.get('tool_name', '')
    inp    = data.get('tool_input', {})
    target = get_target()

    if tool == 'Bash':
        cmd = inp.get('command', '')
        ATTACK_TOOLS = ['sqlmap', 'dalfox', 'nuclei', 'attack-', 'attack_']
        if any(t in cmd for t in ATTACK_TOOLS):
            if not recon_complete(target):
                deny(
                    f"ATTACK BLOCKED: recon not complete. "
                    f"Write ~/new_agent/targets/{target}/recon/RECON-COMPLETE.md first."
                )
        INLINE = [
            'python3 -c', 'python -c',
            'requests.get', 'requests.post', 'requests.put',
            'requests.patch', 'requests.delete',
            'urllib.request',
        ]
        if any(p in cmd for p in INLINE):
            deny(
                "INLINE HTTP BLOCKED. Use safe_http.py:\n"
                "python3 ~/new_agent/.claude/lib/safe_http.py GET <url> --headers '{...}'\n"
                "Or: bash ~/new_agent/.claude/tools/<tool>.sh"
            )

    if tool == 'Agent':
        prompt = inp.get('prompt', '')
        ATTACK_AGENTS = [
            'attack-idor', 'attack-ssrf', 'attack-auth',
            'attack-rce', 'attack-sqli', 'attack-xss',
            'attack-privesc', 'attack-graphql', 'attack-llm', 'attack-logic',
        ]
        if any(a in prompt.lower() for a in ATTACK_AGENTS):
            if not recon_complete(target):
                deny(
                    f"ATTACK AGENT BLOCKED: recon not complete. "
                    f"Write ~/new_agent/targets/{target}/recon/RECON-COMPLETE.md first."
                )
        lock = '/tmp/new_agent_agent_running.lock'
        if os.path.exists(lock):
            age = time.time() - os.path.getmtime(lock)
            if age < 1800:
                deny("PARALLEL AGENT BLOCKED: another agent is running. Wait for it to finish.")
            else:
                os.remove(lock)
        open(lock, 'w').write(str(time.time()))

    allow()

except Exception:
    allow()
