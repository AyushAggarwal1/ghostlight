MongoDB Scanner Setup
=====================

Target format
-------------
`mongodb://user:pass@host:27017/db:collection1,collection2`

Quick steps
-----------
```bash
ghostlight scan --scanner mongo --target "mongodb://user:pass@mongo:27017/app:users,events"
```

Notes
-----
- Provide one or more collection names after the colon.
- Ensure your user has read access to the collections.


