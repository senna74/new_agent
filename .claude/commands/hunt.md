---
name: hunt
description: Full autonomous bug bounty hunt on a target.
---

TARGET="$1"
if [ -z "$TARGET" ]; then
  echo "ERROR: usage: /hunt <target>"
  exit 1
fi

mkdir -p \
  ~/new_agent/targets/$TARGET/{recon/identity,recon/endpoints,recon/js,recon/secrets,findings,reports,leads,notes} \
  ~/new_agent/results/$TARGET \
  ~/new_agent/memory \
  ~/new_agent/state

echo "$TARGET" > ~/new_agent/state/.active-target
touch ~/new_agent/state/queue.jsonl
touch ~/new_agent/targets/$TARGET/findings/MASTER-SUMMARY.md

test -f ~/new_agent/targets/$TARGET/scope.md \
  || { echo "ERROR: create ~/new_agent/targets/$TARGET/scope.md first"; exit 1; }

test -f ~/new_agent/targets/$TARGET/recon/tokens.json \
  || { echo "ERROR: create ~/new_agent/targets/$TARGET/recon/tokens.json first"; exit 1; }

Read ~/new_agent/.claude/ORCHESTRATOR.md
