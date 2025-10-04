Confluence Scanner (Cloud)
==========================

Scan Confluence pages (and first-page comments) for sensitive data.

What you need
-------------
- Atlassian Cloud site (e.g., `your-domain.atlassian.net`)
- Your account email and an API token
  - Create: `https://id.atlassian.com/manage-profile/security/api-tokens`
- Space key (e.g., `ENG`) or personal space `~accountId`

Build the target URL
--------------------
Format:
```
confluence://BASE_URL[:/wiki]:EMAIL:API_TOKEN:SPACE_KEY[?cql=URL_ENCODED_CQL]
```
Examples:
```bash
ghostlight scan --scanner confluence --target "confluence://https://your-domain.atlassian.net/wiki:you@example.com:ATLTOKEN:ENG" --format json --output confluence.json

# Custom CQL (pages or blog posts updated in last 30 days)
ghostlight scan --scanner confluence --target "confluence://https://your-domain.atlassian.net/wiki:you@example.com:ATLTOKEN:ENG?cql=space%3D%22ENG%22%20AND%20type%20in%20(page%2Cblogpost)%20AND%20lastmodified%20%3E%3D%20-30d"
```

Tips
----
- You can set an env var for default CQL:
  ```bash
  export GHOSTLIGHT_CONFLUENCE_CQL='space="${SPACE}" AND type=page ORDER BY lastmodified DESC'
  ```

