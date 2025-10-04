Google Drive Scanner Setup
==========================

Requirements
------------
- `google-api-python-client`, `google-auth`
- Service account JSON (recommended) or ADC

Connectivity test
-----------------
```bash
ghostlight test --scanner gcs --target my-bucket   # Drive has no test; use scan directly
```

Scan examples
-------------
```bash
ghostlight scan --scanner gdrive --target /path/to/service_account.json
ghostlight scan --scanner gdrive --target default
```


