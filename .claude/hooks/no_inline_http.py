#!/usr/bin/env python3
"""
no_inline_http.py — PreToolUse hook
Forces use of safe_http.py instead of inline Python HTTP calls.
"""
import json, sys, re

PATTERNS = [
    r'python3?\s+-c\s+["\'].*import\s+requests',
    r'python3?\s+-c\s+["\'].*urllib',
    r'python3?\s+-c\s+["\'].*http\.client',
    r'requests\.(get|post|put|patch|delete|head|options)\s*\(',
    r'urllib\.request\.',
    r'http\.client\.',
]

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
    data = json.load(sys.stdin)
    if data.get('tool_name') == 'Bash':
        cmd = data.get('tool_input', {}).get('command', '')
        for p in PATTERNS:
            if re.search(p, cmd, re.IGNORECASE | re.DOTALL):
                deny(
                    "INLINE HTTP BLOCKED.\n"
                    "Use: python3 ~/new_agent/.claude/lib/safe_http.py GET <url> --headers '{...}'\n"
                    "Or:  bash ~/new_agent/.claude/tools/<tool>.sh"
                )
    allow()
except Exception:
    allow()
