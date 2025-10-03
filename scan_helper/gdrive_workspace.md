Google Drive Workspace Scanner Setup
===================================

Requirements
------------
- `google-api-python-client`, `google-auth`
- Service account with domain-wide delegation
- Scopes: `admin.directory.user.readonly`, `drive.readonly`

Scan examples
-------------
```bash
ghostlight scan --scanner gdrive_workspace --target /path/to/delegated_service_account.json
```


