Filesystem Scanner Setup
========================

Scan a file or directory. Skips common binaries.

Examples
--------
```bash
ghostlight scan --scanner fs --target /path/to/dir --format table
ghostlight scan --scanner fs --target ./file.txt --format json --output fs.json
```

Options
-------
- --max-file-mb: size cutoff (default 20)
- --sample-bytes: bytes per file (default 2048)


