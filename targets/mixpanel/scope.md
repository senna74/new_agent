target_name: mixpanel
severity_floor: medium
scan_mode: deep

urls:
  dashboard: https://mixpanel.com
  api: https://mixpanel.com/api

in_scope:
  - mixpanel.com
  - "*.mixpanel.com"

out_of_scope:
  - help.mixpanel.com
  - status.mixpanel.com
  - blog.mixpanel.com

forbidden:
  - brute_force
  - dos
  - social_engineering
  - destroy_data
  - access_other_users_data

accounts:
  ADMIN:
    role: admin
    note: Full admin access
    auth_type: session_cookie
  MEMBER:
    role: member
    note: Regular member access
    auth_type: session_cookie
  IDOR:
    role: idor
    note: Separate account for cross-account testing
    auth_type: session_cookie

auth_type: session_cookie
program: HackerOne Private
cvss_version: v4

features:
  has_jwt: false
  has_oauth: true
  has_webhooks: true
  has_graphql: false
  has_websockets: false
  has_multi_tenant: true
  has_roles: true
  has_api_keys: true
  has_file_upload: true
  has_swagger: false
  has_payments: false
  has_llm: false

attack_surface:
  high_priority:
    - Cross-account IDOR via organization/project IDs
    - API key exposure and misuse
    - Webhook SSRF
    - Role escalation within organization
    - Cross-organization data access
    - File upload abuse
  medium_priority:
    - OAuth flow manipulation
    - Mass assignment in user/project creation
    - IDOR in report/dashboard IDs

rules:
  - Submit one vulnerability per report unless chaining
  - Do not access modify or exfiltrate real data
  - Use wearehackerone.com email aliases only
  - Private program — never discuss outside
  - Feature gate bypass is out of scope

docs:
  read_all_before_hunt: true
  note: Agent MUST read all docs links below before starting recon to understand the application
  links:
    - https://docs.mixpanel.com/docs/what-is-mixpanel
    - https://docs.mixpanel.com/docs/orgs-and-projects/organizations
    - https://docs.mixpanel.com/docs/orgs-and-projects/managing-projects
    - https://docs.mixpanel.com/docs/orgs-and-projects/roles-and-permissions
    - https://docs.mixpanel.com/docs/access-security/login-methods
    - https://docs.mixpanel.com/docs/access-security/two-factor-authentication
    - https://docs.mixpanel.com/docs/access-security/single-sign-on
    - https://docs.mixpanel.com/docs/access-security/audit-log
    - https://docs.mixpanel.com/docs/cohort-sync/webhooks
    - https://docs.mixpanel.com/docs/data-pipelines
    - https://docs.mixpanel.com/docs/export-methods
    - https://docs.mixpanel.com/docs/privacy/protecting-user-data
    - https://docs.mixpanel.com/docs/privacy/end-user-data-management
    - https://docs.mixpanel.com/docs/data-governance/lexicon
    - https://docs.mixpanel.com/docs/data-governance/data-views-and-classification
    - https://docs.mixpanel.com/docs/boards/sharing-and-permission
    - https://docs.mixpanel.com/docs/boards/public-boards
    - https://docs.mixpanel.com/docs/features/embeds
    - https://docs.mixpanel.com/docs/features/alerts
    - https://docs.mixpanel.com/docs/mixpanel-agent
    - https://docs.mixpanel.com/docs/agentic-automations
    - https://docs.mixpanel.com/docs/mcp
    - https://developer.mixpanel.com/reference
