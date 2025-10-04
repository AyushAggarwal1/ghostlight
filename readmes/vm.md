VM Scanner Setup
================

Requirements
------------
- SSH access to target VM (password or key)
- `paramiko` installed

Examples
--------
```bash
ghostlight scan --scanner vm --target "user@host:/etc,/var/log" --format table
```

Target format
-------------
`user@hostname:/path1,/path2`


