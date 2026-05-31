# SKILL LOADING DISCIPLINE

## CRITICAL
Skill("name") does NOT load anything — display text only.
ALWAYS use explicit Read:
  Read ~/new_agent/.claude/skills/hunt-jwt/SKILL.md

## ALWAYS LOAD
Read ~/new_agent/.claude/skills/hunt-critical/SKILL.md
Read ~/new_agent/.claude/skills/critical-attack-matrix/SKILL.md

## DYNAMIC (from scope.md features)
has_jwt: true          → hunt-jwt + hunt-auth-bypass
has_oauth: true        → hunt-oauth + hunt-mfa-bypass
has_saml: true         → hunt-saml
has_graphql: true      → hunt-graphql
has_file_upload: true  → hunt-file-upload + hunt-rce
has_webhooks: true     → hunt-ssrf + hunt-metadata-ssrf
has_multi_tenant: true → hunt-bac-privesc + hunt-idor + hunt-ato
has_api_keys: true     → hunt-api-misconfig
has_websockets: true   → hunt-websocket
has_swagger: true      → hunt-api-misconfig
has_payments: true     → hunt-business-logic
has_llm: true          → hunt-llm-ai + hunt-llm-advanced
has_nosql: true        → hunt-nosql
has_s3: true           → hunt-s3-misconfig
has_cloud: true        → hunt-cloud-misconfig

## DISCIPLINE
Orchestrator: max 2 skills loaded at once
Sub-agents: max 1 skill — only what you need for your task
