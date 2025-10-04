Google Drive Scanner Setup
==========================

Requirements
------------
- `google-api-python-client`, `google-auth`
- Service account JSON (recommended) or ADC

Create a service account (recommended)
-------------------------------------
1. In Google Cloud Console: IAM & Admin → Service Accounts → Create Service Account.
2. Name it (e.g., ghostlight-gdrive) and create.
3. Grant minimal roles (for Drive, access is controlled by sharing rather than roles):
   - You must SHARE the Drive files/folders you want to scan with the service account’s email.
   - Optional: If using a Shared Drive, add the service account as a reader to that drive.
4. Create a key → JSON, and download it.
5. Enable the Drive API (APIs & Services → Library → Google Drive API → Enable).

Quick steps
-----------
```bash
ghostlight scan --scanner gdrive --target /path/to/service_account.json
ghostlight scan --scanner gdrive --target default
```

Notes
-----
- If using a service account, grant Drive read access to the content you want to scan.
- `default` uses application default credentials; make sure `gcloud auth application-default login` is configured.


