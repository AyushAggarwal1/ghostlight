## Understanding Ghostlight’s JSON Output

This page explains, what you get when you run Ghostlight with JSON output and how to read it.

### 1) How do I get JSON?

```bash
ghostlight scan --scanner fs --target /path/to/dir --format json --output results.json
```

- The scan writes a file called `results.json`.
- It contains a list of “findings” (each finding is one place where we saw something sensitive).

### 2) What is a “finding”?

Think of a finding as “one item Ghostlight wants to show you,” like a file, a cloud object, a database table, or a message that appears to contain sensitive data.

In the JSON, a finding looks like this (shortened):

```json
{
  "id": "fs:README.md",
  "location": "/repo/README.md:18",
  "classifications": ["GDPR:PII.Email"],
  "evidence": [{ "snippet": "Contact: you@example.com" }],
  "severity": "high",
  "detections": [
    {
      "bucket": "GDPR",
      "pattern_name": "PII.Email",
      "matches": ["you@example.com"]
    }
  ]
}
```

### 3) The 5 fields most people care about

- location: Where we found it. Often includes a line number, like `/path/file.txt:42`.
- classifications: The type(s) of sensitive data (e.g., PII email, secrets, credit card).
- evidence.snippet: A short preview from around the match.
- detections[].matches: The exact text we matched (this is the most precise value).
- severity: Our simple sense of urgency: low, medium, high, or critical.

### 4) Where is the exact matched text?

- Look under `detections[].matches`.
- Example: `"matches": ["AKIA...."]` for an AWS key, or an email like `"you@example.com"`.

Tip: `top_exact_matches` at the finding level gives a quick list of up to 20 unique matches for fast triage.

### 5) What do “buckets” mean?

They’re just groups of data types:
- GDPR: Personal info (emails, phone numbers, SSNs, etc.)
- HIPAA: Health-related identifiers/content
- PCI: Payment card numbers
- SECRETS: Keys/tokens/password-like values
- IP: Technical items like JWTs or private keys

### 6) What do risk_score and risk_level mean?

- risk_score: A number from 0 to 100. Higher = more concerning.
- risk_level: Turns that number into words: low, medium, high, critical.

How we think about risk:
- Sensitivity (what was found) + Exposure (how risky the location is) = Overall risk.

### 7) What else might I see?

- resource/profile/file_path: Labels to help you group where things came from (e.g., which bucket, which repo, which DB).
- metadata: Extra details depending on the source (for example, for S3 we include public/encryption info; for Jira/Confluence we include links and titles).

### 8) Safety note

The JSON may contain sensitive strings (like tokens or emails) in `detections[].matches` and in `evidence.snippet`.
- Treat the file as confidential.
- Store it securely and avoid sharing it widely.

### 9) Quick checklist when reading results

- Is the location somewhere risky (public bucket, public repo, production logs)?
- Do the matches look real (not example values)?
- Is the severity/risk_level high or critical?
- Do I need to rotate a key, remove data, or restrict access?

### 10) Common questions

- Why do I sometimes see a lot of matches? Some files (like docs or config samples) contain many examples. Use `severity`, `risk_level`, and `pattern_match_counts` to sort what to fix first.
- Why is the snippet short? It’s designed to be a safe preview. For full context, open the file at the `location` line number.
- Can I turn off/limit exact matches? You can post-process the JSON, or we can add a CLI flag to redact by default if you need that.



