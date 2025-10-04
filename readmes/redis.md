Redis Scanner Setup
===================

Target format
-------------
`redis://host:6379/db`

Quick steps
-----------
```bash
ghostlight scan --scanner redis --target "redis://redis:6379/0"
```

Notes
-----
- The scanner samples values from keys to look for sensitive data.
- Use a read-only user when possible.


