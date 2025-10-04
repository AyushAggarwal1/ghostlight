Jira Scanner (Cloud)
====================

Scan Jira issues (summary, description, and recent comments) for sensitive data.

What you need
-------------
- Atlassian Cloud site (e.g., `your-domain.atlassian.net`)
- Your account email and a Jira API token
  - Create: `https://id.atlassian.com/manage-profile/security/api-tokens`

Build the target URL
--------------------
Format:
```
jira://BASE_URL:EMAIL:API_TOKEN:PROJECT_KEY[?jql=URL_ENCODED_JQL]
```
Examples:
```bash
ghostlight scan --scanner jira --target "jira://https://your-domain.atlassian.net:you@example.com:ATLTOKEN:ENG" --format json --output jira.json

# Custom JQL (last 7 days)
ghostlight scan --scanner jira --target "jira://https://your-domain.atlassian.net:you@example.com:ATLTOKEN:ENG?jql=project%3DENG%20AND%20updated%20%3E%3D%20-7d"
```

Tips
----
- You can also set an env var and omit the `?jql=` in the URL:
  ```bash
  export GHOSTLIGHT_JIRA_JQL='project=${PROJECT} AND updated >= -30d ORDER BY updated DESC'
  ```

