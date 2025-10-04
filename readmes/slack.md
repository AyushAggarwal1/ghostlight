Slack Setup Guide
=================

This guide walks you through creating a Slack app, assigning the right permissions, installing it, and testing connectivity with ghostlight.

1) Create a Slack App
---------------------
1. Go to `https://api.slack.com/apps` → Create New App → From scratch.
2. Name your app (e.g., Ghostlight) and select your workspace.

2) Add Bot User and Scopes
---------------------------
1. In your app, go to: Features → App Home → Scroll to "App Display Name" to ensure a Bot User is enabled.
2. Go to: Features → OAuth & Permissions → Scopes → Bot Token Scopes.
3. Add the following read-only scopes (minimum for reading messages across channel types):
   - channels:read
   - channels:history
   - groups:read
   - groups:history
   - im:read
   - im:history
   - mpim:read
   - mpim:history
   - users:read 

Notes:
- If you want to restrict to only public channels, you can omit the private/DM scopes, but ghostlight will only read what the token is allowed to read.
- You do NOT need chat:write for scanning.

3) Install the App to Workspace
-------------------------------
1. Go to: OAuth & Permissions → Install App (or Reinstall if you changed scopes).
2. Copy the Bot User OAuth Token (starts with `xoxb-`). Treat this as a secret.

4) Invite the App to Channels
-----------------------------
For each channel you want to scan:
- In Slack, open the channel and run `/invite @YourAppName`.

5) Get the Channel ID
---------------------
Recommended to pass a channel ID to limit scope:
- In Slack channel: Channel details → About → Copy Channel ID (e.g., `C0123456789`).
- Or from the channel URL: `https://yourworkspace.slack.com/archives/C0123456789`.

6) Test Connectivity
--------------------
Ghostlight provides a preflight test.

Token only (auth check):
```bash
export SLACK_BOT_TOKEN='xoxb-...'
ghostlight test --scanner slack --target "$SLACK_BOT_TOKEN"
```

Token + channel (auth + channel access check):
```bash
ghostlight test --scanner slack --target "$SLACK_BOT_TOKEN:C0123456789"
```

Expected output includes lines like:
- `Slack token valid (team=..., bot_user=...)`
- `Slack channel access OK (channel=...)`

7) Run a Scan
-------------
Scan a specific channel:
```bash
ghostlight scan --scanner slack --target "$SLACK_BOT_TOKEN:C0123456789" --format json --output slack.json
```

Scan the first ~50 channels visible to the bot (broader):
```bash
ghostlight scan --scanner slack --target "$SLACK_BOT_TOKEN"
```

8) Generate a Known Test Finding (Optional)
-------------------------------------------
To verify detections, post a test secret in the target channel, then rerun the scan:


9) Troubleshooting
------------------
- `invalid_auth`: Token is wrong or from another workspace. Use the Bot token (`xoxb-...`).
- `channel_not_found`: Wrong channel ID, or the bot is not invited to that channel.
- `not_in_channel`: Invite the app (`/invite @YourAppName`).
- `missing_scope`: Add the scopes listed above and reinstall the app.
- User name shows as `unknown`:
  - Ensure `users:read` scope is added and the app reinstalled.
  - Some bot/webhook messages don’t include a real user; ghostlight falls back to `bot_profile.name` where possible.
- Deprecation warnings from cryptography: harmless; to suppress on CLI:
  ```bash
  PYTHONWARNINGS="ignore::CryptographyDeprecationWarning" ghostlight scan --scanner slack --target "$SLACK_BOT_TOKEN:C0123456789"
  ```

10) Security Best Practices
---------------------------
- Treat `xoxb-...` tokens as secrets. Do not commit to version control.
- Use a dedicated Slack app with read-only scopes.
- Limit the app to only the channels you need (invite on demand).
- Rotate/revoke tokens when no longer needed.

Reference
---------
- Slack App Management: `https://api.slack.com/apps`
- Conversations API: `https://api.slack.com/methods/conversations.history`
- Scopes reference: `https://api.slack.com/scopes`


