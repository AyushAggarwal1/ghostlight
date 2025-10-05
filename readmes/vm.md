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

Authentication
--------------
The VM scanner supports both SSH key and password authentication:

1. **SSH Key Authentication (Recommended)**
   - Add your public key to the VM: `ssh-copy-id user@hostname`
   - No password prompt required

2. **Password Authentication**
   - The scanner will automatically prompt for password if SSH key auth fails
   - Enter password when prompted: `Enter password for user@hostname:`

Notes
-----
- The scanner tries SSH key authentication first, then falls back to password
- You can list multiple files and directories, separated by commas.

