Firebase Firestore Scanner Setup
================================

Target format
-------------
`firestore:project_id:collection1,collection2`

Create a service account
------------------------
1. Google Cloud Console → IAM & Admin → Service Accounts → Create.
2. Grant it permission to read Firestore data (e.g., at the project level):
   - `Cloud Datastore Viewer` (roles/datastore.viewer) or a custom read-only role.
3. Create key → JSON, download it.
4. Enable the Firestore API.

Quick steps
-----------
```bash
ghostlight scan --scanner firebase --target "firestore:my-gcp-project:users,events"
```

Notes
-----
- Ensure `firebase-admin` is installed and your environment is authorized to access the project.
- Provide one or more collection names after the project id.


