Google Cloud Storage Scanner Setup
=================================

Requirements
------------
- `google-cloud-storage` installed
- GCP credentials (ADC or service account): `export GOOGLE_APPLICATION_CREDENTIALS=/path/key.json`

Connectivity test
-----------------
```bash
ghostlight test --scanner gcs --target my-gcs-bucket
```

Scan examples
-------------
```bash
ghostlight scan --scanner gcs --target my-gcs-bucket
ghostlight scan --scanner gcs --target my-gcs-bucket/prefix
```


