Google Cloud Storage Scanner Setup
=================================

Requirements
------------
- `google-cloud-storage` installed
- GCP credentials (ADC or service account): `export GOOGLE_APPLICATION_CREDENTIALS=/path/key.json`

Create a service account
------------------------
1. Google Cloud Console → IAM & Admin → Service Accounts → Create.
2. Grant at least read access to the target bucket(s). Minimal role examples:
   - Project level: `Storage Object Viewer` (roles/storage.objectViewer)
   - Or bucket-level permission: add service account as a Reader.
3. Create key → JSON, download it.
4. Enable the “Cloud Storage” API if not already enabled.

Quick steps
-----------
```bash
# Test bucket exists with your creds
ghostlight test --scanner gcs --target my-gcs-bucket

# Scan bucket or prefix
ghostlight scan --scanner gcs --target my-gcs-bucket
ghostlight scan --scanner gcs --target my-gcs-bucket/prefix --format json --output gcs.json
```


