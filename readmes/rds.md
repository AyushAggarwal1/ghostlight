RDS Scanner (PostgreSQL, MySQL, MariaDB)
=======================================

Scan AWS RDS databases for sensitive data.

What you need
-------------
- AWS credentials set up (any one):
  - `aws configure` (creates credentials file), or
  - Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`
- Database user and password exported as env vars:
  - `export RDS_USERNAME=admin`
  - `export RDS_PASSWORD=your_password`

Find your instance id and engine
--------------------------------
In AWS Console > RDS, note the DB Instance Identifier and Engine (e.g., `postgres`, `mysql`).

Quick scan (auto-discover tables)
---------------------------------
```bash
ghostlight scan --scanner rds --target "rds://mydb-instance/postgres:mydb:" --format json --output rds.json
```

Scan specific tables
--------------------
```bash
ghostlight scan --scanner rds --target "rds://mydb-instance/mysql:appdb:users,orders" --show-sql --list-tables
```

Tips
----
- If your RDS is private (no public endpoint), run Ghostlight from an EC2 in the same VPC.
- Use `--sample-rows` to increase sample depth per table.

