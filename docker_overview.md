## Ghostlight – Data Security Scanner (Docker Image)

Detect sensitive data (PII/PHI/PCI/Secrets) across filesystems, Git, cloud storage, SaaS (Slack/Jira/Confluence), databases, and VMs. Streams findings to JSON/Markdown with exact evidence snippets and language‑aware detection.

### Highlights
- **Broad sources**: FS, Git, S3, GCS, Azure Blob, Slack, Jira, Confluence, RDS/EC2/VM, Postgres/MySQL/Mongo/Redis/Firebase.
- **Streaming outputs**: JSON/Markdown written incrementally as findings are produced.
- **Exact evidence**: Line‑accurate snippets with correct line numbers.
- **Language‑aware**: Auto‑detects language; i18n phone/ID validation reduces false positives.
- **Secret validation**: Format/checksum checks (AWS, Slack, Stripe, GitHub, Azure AD, Twilio, etc.).
- **Optional metrics**: Prometheus counters/histogram via a built‑in /metrics endpoint.

### Visit GitHub
- Repository: [AyushAggarwal1/ghostlight](https://github.com/AyushAggarwal1/ghostlight)

### Quickstart
```bash
docker pull ayush1136/ghostlight:latest
docker run --rm ayush1136/ghostlight:latest --help
```

### Common usage
- Filesystem scan, write JSON to host:
```bash
mkdir -p ./scan_result
docker run --rm \
  -v $(pwd)/scan_result:/out \
  ayush1136/ghostlight:latest \
  scan --scanner fs --target /app \
  --format json --output /out/fs.json
```

- Slack scan (bot token and channel):
```bash
docker run --rm \
  -v $(pwd)/scan_result:/out \
  ayush1136/ghostlight:latest \
  scan --scanner slack --target 'xoxb-XXXX:C0123456789' \
  --format json --output /out/slack.json
```

- Git scan (public repo):
```bash
docker run --rm \
  -v $(pwd)/scan_result:/out \
  ayush1136/ghostlight:latest \
  scan --scanner git --target https://github.com/user/repo.git \
  --format json --output /out/git.json
```

### Environment variables
- Provider credentials are read from typical envs when needed (e.g., AWS creds for S3/RDS; Atlassian API token for Jira/Confluence; Slack bot token).


### Exit codes
- 0 on success, non‑zero on failures (e.g., connectivity/auth errors).

### Tags and platforms
- Tags: `latest` (rolling), versioned tags as released.
- Platforms: linux/amd64 (multi‑arch available if published).

### Notes
- Mount a host directory using `-v` to persist output (e.g., `/out`).
- For private Git, provide tokens/SSH; for cloud/DB scans, ensure network access and credentials.
- Logs avoid leaking sensitive values; tune verbosity with CLI flags.

For full usage and connectors matrix, see the project `README.md`.
