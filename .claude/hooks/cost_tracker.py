#!/usr/bin/env python3
"""
cost_tracker.py — PostToolUse hook
Tracks bash call counts per session.
"""
import json, sys, os, time

try:
    f = '/tmp/new_agent_tool_count.json'
    data = json.load(open(f)) if os.path.exists(f) else {"count": 0, "session_start": time.time()}
    data["count"] += 1
    json.dump(data, open(f, 'w'))
    print(json.dumps({"decision": "approve"}))
except:
    print(json.dumps({"decision": "approve"}))
