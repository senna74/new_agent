# REPORT FORMAT + QUALITY GATE

## STRUCTURE
Title:    [VulnType] - [Impact] in [Component]
Severity: CVSS 4.0 score + full vector string
Summary:  2-3 sentences — what, where, impact
Steps:    Numbered exact HTTP requests — anyone must reproduce
Impact:   Concrete — data accessed, action taken, who affected
PoC:      Working curl command or minimal Python script
Evidence: Response diffs, screenshots if needed

## QUALITY GATE (≥ 7 required)
  +2  Reproduction steps with exact HTTP requests
  +2  Concrete impact with captured evidence
  +2  Working PoC included and tested
  +1  CVSS 4.0 correct with full vector
  +1  Not duplicate (brain.sqlite + hacktivity checked)
  +1  In scope per scope.md
  +1  No false positive indicators

Score < 7 → fix → re-score → never submit below 7.
Write targets/<TARGET>/reports/<id>.md
Update targets/<TARGET>/findings/MASTER-SUMMARY.md
Write winning technique to memory/<target>-wins.md
