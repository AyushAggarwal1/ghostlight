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

Step-by-step (beginner)
-----------------------
1. Create a Google Cloud project
   - In Google Cloud Console, click the project selector → New Project → Create.
   - Note your Project ID.
2. Enable the Google Drive API
   - Go to APIs & Services → Library → search "Google Drive API" → Enable.
3. Create a Service Account
   - IAM & Admin → Service Accounts → Create Service Account.
   - Name it (e.g., `ghostlight-gdrive`).
   - Keys → Add key → Create new key → JSON → Download and save the JSON file path.
4. Share Drive content with the Service Account
   - Copy the service account email (ends with `iam.gserviceaccount.com`).
   - In Google Drive:
     - For My Drive items: Right-click file/folder → Share → add the service account as Viewer.
     - For Shared Drives: Manage members → add the service account as Viewer.
5. Run Ghostlight using the Service Account JSON
```bash
ghostlight scan --scanner gdrive --target /path/to/service_account.json
```
6. Alternative: Use Application Default Credentials (ADC)
   - Authenticate with gcloud, then run Ghostlight:
```bash
gcloud auth application-default login
ghostlight scan --scanner gdrive --target default
```
7. Common fixes
   - 403/permission errors: ensure the service account has Viewer access to the exact files/folders (or is a member of the Shared Drive).
   - API not enabled: re-check the Drive API is enabled in the same project as the service account.
   - Quotas: default Drive API quotas usually suffice; request increases in the Console if needed.
   - Secret hygiene: keep the JSON key safe and rotate if exposed.

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


