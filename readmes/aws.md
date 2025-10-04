AWS Aggregate Scanner Setup
===========================

Scans RDS, S3, and EC2.

Requirements
------------
- AWS credentials

Examples
--------
```bash
ghostlight scan --scanner aws --target all --format json --output aws.json
ghostlight scan --scanner aws --target rds,s3
```

See also: `AWS_COMPREHENSIVE_SCANNING.md`


