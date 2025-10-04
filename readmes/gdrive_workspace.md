Google Drive Workspace Scanner Setup
===================================

Requirements
------------
- `google-api-python-client`, `google-auth`
- Service account with domain-wide delegation
- Scopes: `admin.directory.user.readonly`, `drive.readonly`

Quick steps
-----------
1. Create a service account and enable domain-wide delegation.
2. In Admin Console, grant the scopes above to the service account client ID.
3. Download the delegated service account JSON.

```bash
ghostlight scan --scanner gdrive_workspace --target /path/to/delegated_service_account.json
```

Notes
-----
- The scan lists files owned by users in the domain and samples readable content.
- Ensure the service account has the necessary domain-wide permissions.

Detailed setup (domain-wide delegation)
--------------------------------------
1. Create service account: Google Cloud Console → IAM & Admin → Service Accounts → Create.
2. Edit the service account → Show Domain-wide Delegation → Enable.
3. Copy the service account’s “Client ID”.
4. In Google Admin Console (admin.google.com) → Security → Access and data control → API Controls → Domain-wide Delegation → Manage Domain Wide Delegation → Add new.
5. Paste the Client ID, and add scopes (comma-separated):
   - `https://www.googleapis.com/auth/admin.directory.user.readonly`
   - `https://www.googleapis.com/auth/drive.readonly`
6. Save. Download a JSON key for the service account and use it with the scanner.


