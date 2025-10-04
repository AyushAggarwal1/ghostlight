EC2 Scanner (no SSH keys needed)
================================

Scan files on running EC2 instances via AWS Systems Manager (SSM).

What you need
-------------
- AWS credentials configured (`aws configure` or env vars)
- The EC2 instance must have:
  - SSM Agent installed (Amazon Linux 2/Ubuntu images usually have it)
  - IAM role with `AmazonSSMManagedInstanceCore`

Quick scan
---------
```bash
ghostlight scan --scanner ec2 --target i-0123456789abcdef0 --format json --output ec2.json
```

Scan specific paths
-------------------
```bash
ghostlight scan --scanner ec2 --target "i-0123456789abcdef0:/etc,/var/log,/home" --format table
```

Notes
-----
- We read a small sample from each text file to keep scans fast.
- If the instance is not SSM-managed or not online, we’ll show a clear error.


