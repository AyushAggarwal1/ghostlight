VM Scanner Setup
================

Requirements
------------
- SSH access to target VM (password or key)
- `paramiko` installed

Quick steps
-----------
```bash
ghostlight scan --scanner vm --target "user@host:/etc,/var/log" --format table
```

Target format
-------------
`user@hostname:/path1,/path2`

Notes
-----
- For convenience, add your public key to the VM to avoid password prompts.
- You can list multiple files and directories, separated by commas.

