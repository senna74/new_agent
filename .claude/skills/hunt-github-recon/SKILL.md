# GitHub Recon Skill

## Objective
Find secrets, exposed credentials, internal endpoints, and sensitive data
in GitHub repositories belonging to the target organization.

## Workflow

### 1. Org Discovery
Search for the target org and all related repos:
  gh org list
  gh repo list {org} --limit 100

### 2. Code Search — Secrets
Search for common secret patterns:
  gh search code "org:{org} password"
  gh search code "org:{org} api_key"
  gh search code "org:{org} secret_key"
  gh search code "org:{org} access_token"
  gh search code "org:{org} private_key"
  gh search code "org:{org} BEGIN RSA"
  gh search code "org:{org} AKIA"
  gh search code "org:{org} database_url"
  gh search code "org:{org} db_password"
  gh search code "org:{org} smtp_password"

### 3. Code Search — Internal Endpoints
  gh search code "org:{org} api.internal"
  gh search code "org:{org} staging."
  gh search code "org:{org} dev."
  gh search code "org:{org} localhost"
  gh search code "org:{org} 127.0.0.1"
  gh search code "org:{org} .corp"
  gh search code "org:{org} .internal"

### 4. Code Search — Auth Configs
  gh search code "org:{org} Authorization: Bearer"
  gh search code "org:{org} X-API-Key"
  gh search code "org:{org} token ="
  gh search code "org:{org} SECRET ="

### 5. Commit History Scan
For each interesting repo:
  git clone --depth 50 https://github.com/{org}/{repo}
  trufflehog git file://{repo}/ --json > secrets.json
  gitleaks detect --source {repo}/ --report-path leaks.json

### 6. Exposed Files
  gh search code "org:{org} filename:.env"
  gh search code "org:{org} filename:config.yml password"
  gh search code "org:{org} filename:database.yml"
  gh search code "org:{org} filename:settings.py SECRET"
  gh search code "org:{org} filename:wp-config.php"
  gh search code "org:{org} filename:.npmrc _authToken"
  gh search code "org:{org} filename:docker-compose.yml password"

### 7. Issues and PRs
  gh search issues "org:{org} password" --state open
  gh search issues "org:{org} token" --state open
  gh search prs "org:{org} secret" --state merged

## False Positives to Ignore
- Test fixture keys (example values in documentation)
- Rotated keys confirmed invalid
- Hashed/encrypted values
- Placeholder strings like "YOUR_API_KEY_HERE"

## Output
Save all findings to:
  ~/new_agent/targets/{TARGET}/recon/github-recon.json

Format:
  {
    "repo": "...",
    "finding_type": "secret|endpoint|config",
    "file": "...",
    "line": N,
    "value": "REDACTED — confirm validity before reporting",
    "confidence": 0.0-1.0
  }

## Rules
- NEVER report a secret without confirming it is currently valid
- NEVER report example/test/fixture values
- Validate every secret before including in findings
- Rate limit: max 30 searches per minute
