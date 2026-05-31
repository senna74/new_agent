# CONTEXT MANAGEMENT

## LIMITS
Orchestrator: < 80k tokens
Sub-agents:   < 60k tokens

## RULES
- Never print full API responses — 150 chars max
- After each wave: discard raw data, keep one-line summaries
- Sub-agents get fresh context windows — keep them lean
- Load skills on-demand only

## CHECKPOINT
If orchestrator > 70k tokens:
  Write state/session-state.json
  Summarize completed work
  Continue from summary — never restart from zero

## SUB-AGENT ECONOMY
Each sub-agent dies after its task.
Results live on disk in queue.jsonl and results/.
Orchestrator reads disk only — never sub-agent memory.
