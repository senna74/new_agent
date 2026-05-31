# OUTPUT — SILENT MODE

## CONSOLE ONLY
INIT     target=<name> accounts=<N> features=<list>
RECON    <agent> starting
EVENT    <event_type> <detail>
TEST     <METHOD> <path> [<account>]
FINDING  <severity>: <title>
LEAD     <hypothesis>
PASS     <id> confidence=<score>
CHAIN    <id1> + <id2> = <upgraded_severity>
REPORT   <id> score=<quality>
DONE     findings=<N> leads=<N> reports=<N>
ERROR    <what> — see notes/problems.md

## EVERYTHING ELSE TO FILES
Tool output    → results/<TARGET>/
Skill loading  → silent
HTTP responses → truncate 150 chars in logs
Full traces    → targets/<TARGET>/notes/
