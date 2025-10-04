Git Scanner (Local and Remote)
==============================

Scan local repositories or remote (public/private) repos for secrets and sensitive data.

What you need
-------------
- For public repos: nothing. Just pass the HTTPS URL.
- For private repos: authenticate using ONE of the following:
  1) GitHub Personal Access Token (recommended)
  2) Bitbucket App Password
  3) SSH key (added to your Git provider)

Option 1: GitHub token
----------------------
1. Create a token: `https://github.com/settings/tokens`
   - Scope: `repo`
2. Export it:
```bash
export GITHUB_TOKEN=ghp_your_token_here
```
3. Scan a private repo:
```bash
ghostlight scan --scanner git --target https://github.com/your-org/private-repo.git --format json --output git.json
```

Option 2: GitLab token
----------------------
1. Create token with `read_repository` scope (Settings > Access Tokens).
2. Export it:
```bash
export GITLAB_TOKEN=your_token_here
```
3. Scan:
```bash
ghostlight scan --scanner git --target https://gitlab.com/your-group/your-repo.git
```

Option 3: Bitbucket App Password
--------------------------------
1. Create App Password (Repositories: Read).
2. Export credentials:
```bash
export BITBUCKET_USERNAME=your_username
export BITBUCKET_TOKEN=your_app_password
```
3. Scan:
```bash
ghostlight scan --scanner git --target https://bitbucket.org/workspace/repo.git
```

Option 4: SSH key (all providers)
---------------------------------
1. Generate a key if needed:
```bash
ssh-keygen -t ed25519 -C "you@example.com"
```
2. Add the public key to your Git provider.
3. Scan with SSH URL:
```bash
ghostlight scan --scanner git --target git@github.com:your-org/private-repo.git
```

Local repository
----------------
```bash
ghostlight scan --scanner git --target /path/to/local/repo --format md --output report.md
```


