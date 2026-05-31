# TRIAGE + VALIDATION

## PRINCIPLE
Adversarial. Assume every finding is a false positive until proven otherwise.
Run immediately on every finding. Never batch.

## 7-QUESTION GATE
First NO = KILL immediately.

Q1. Real HTTP request with real server response captured?
Q2. Impact on HackerOne accepted-impact list per scope.md?
Q3. Host in scope per scope.md?
Q4. Exploitable right now without additional preconditions?
Q5. Reproducible 3 times consistently?
Q6. Concrete impact — data accessed, action taken, account affected?
Q7. Not in memory/false-positives.md?

## CONFIDENCE SCORING
Start at 0.0 — add only from real evidence:
  +0.30  HTTP request + response captured and saved to disk
  +0.20  Differential auth test confirmed (role A vs role B)
  +0.20  Response diff proves data exposure or unauthorized action
  +0.15  PoC executed — impact demonstrated
  +0.15  Reproduced 3 times independently

## ROUTING
  ≥ 0.85  → PASS
             Write targets/<TARGET>/findings/<id>.md
             Append {"event":"finding_passed","id":"<id>"} to queue.jsonl

  0.40-0.84 → CHAIN
              Write targets/<TARGET>/leads/<id>.md
              Append {"event":"chain_candidate","id":"<id>"} to queue.jsonl

  < 0.40  → KILL
             Write pattern to memory/false-positives.md
             Never test this pattern again on this target
