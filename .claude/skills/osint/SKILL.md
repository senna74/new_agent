---
name: osint
description: "Use this skill when scope includes OSINT, when target has a public GitHub organization, when you need to enumerate company repos for secret leaks, when investigating git history for removed credentials, when mapping employee footprint (LinkedIn, Twitter, GitHub), or when assessing the org's external code exposure. Covers repo enumeration, secret scanning, git history analysis, employee footprint, code exposure discovery. Only invoke this skill if there is real impact potential. Skip theoretical findings."
---

# OSINT

Passive and semi-passive intelligence gathering focused on code repositories, developer footprints, and exposed secrets across public platforms.

## Phases

### 1. Organization Discovery
- Enumerate GitHub/GitLab/Bitbucket orgs for target company name variants
- Find employee personal accounts linked to the target org
- Identify archived, forked, and deleted repositories

### 2. Repository Analysis
- Map all repos: tech stack, languages, CI/CD, dependencies
- Identify internal hostnames, IPs, endpoints, environment names
- Check for `.env`, config files, secrets in current code

### 3. Secret & Credential Scanning
- Scan current code with `gitleaks` / `trufflehog`
- Scan full git history (secrets removed in commits are still accessible)
- Search with targeted dorks (see `reference/repository-recon.md`)

### 4. Code Intelligence
- Extract API endpoints, auth patterns, internal service names
- Review Dockerfiles, CI configs, IaC for infra details
- Check dependency files for version-specific CVE candidates

## Output

```
data/reconnaissance/repositories.json   # Repo inventory + findings
reports/reconnaissance_report.md        # OSINT section appended
raw/osint/                              # Raw tool outputs
```

## Tools

`trufflehog`, `gitleaks`, `gitrob`, GitHub/GitLab search, `gh` CLI, `git log`

## Rules

1. Passive discovery first (search APIs, public pages) before any cloning
2. Scan git history — deleted secrets are still in commit objects
3. Check employee personal accounts, not just org accounts
4. Document every discovered credential/secret immediately as a finding
5. All output saved to `{OUTPUT_DIR}/` per CLAUDE.md directory structure

## Reference

- `reference/repository-recon.md` - Dorks, tool commands, secret patterns, workflow

## Fallback Chain
1. Try the techniques in this skill first
2. If they fail or don't apply, use your own creativity
3. Never stop because a technique didn't work
4. Always find another angle
