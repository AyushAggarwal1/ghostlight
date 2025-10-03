ghostlight
============

Data Security Posture Management tool that scans cloud storage, VMs, databases, and git repositories to detect sensitive data and classify findings against GDPR, HIPAA, PCI, and secrets exposure.

Quick Commands
--------------

| Icons | Tool | Command |
|---|---|---|
| <img src="assets/icons/fs.svg" width="28" /> | Filesystem | `ghostlight scan --scanner fs --target /path/to/dir` |
| <img src="assets/icons/git.svg" width="28" /> | Git | `ghostlight scan --scanner git --target https://github.com/user/repo.git` |
| <img src="assets/icons/s3.svg" width="28" /> | Amazon S3 | `ghostlight scan --scanner s3 --target my-bucket/prefix` |
| <img src="assets/icons/gcs.svg" width="28" /> | Google Cloud Storage | `ghostlight scan --scanner gcs --target my-bucket` |
| <img src="assets/icons/azure.svg" width="28" /> | Azure Blob | `ghostlight scan --scanner azure --target "conn/container/prefix"` |
| <img src="assets/icons/gdrive.svg" width="28" /> | Google Drive | `ghostlight scan --scanner gdrive --target default` |
| <img src="assets/icons/gdrive_workspace.svg" width="28" /> | GDrive Workspace | `ghostlight scan --scanner gdrive_workspace --target /path/to/delegated.json` |
| <img src="assets/icons/slack.svg" width="28" /> | Slack | `ghostlight scan --scanner slack --target "xoxb-...:C12345"` |
| <img src="assets/icons/vm.svg" width="28" /> | VM over SSH | `ghostlight scan --scanner vm --target "user@host:/etc,/var/log"` |
| <img src="assets/icons/rds.svg" width="28" /> | AWS RDS | `ghostlight scan --scanner rds --target "rds://my-instance-id"` |
| <img src="assets/icons/postgres.svg" width="28" /> | PostgreSQL | `ghostlight scan --scanner postgres --target "postgresql://user:pass@host:5432/db?sslmode=require"` |
| <img src="assets/icons/mysql.svg" width="28" /> | MySQL | `ghostlight scan --scanner mysql --target "mysql://user:pass@host:3306/db"` |

## Features

### Sensitive Data Detection
- **PII**: Email, Phone, SSN, Aadhaar, PAN, Passport, Driver License, IBAN, IP addresses, Coordinates
- **PHI**: Medical Record Numbers, NPI, Medicare ID, Medical Records
- **PCI**: Credit Card Numbers
- **Secrets**: AWS keys, Google API keys, GitHub tokens, Slack tokens, JWT, PEM keys, database connection strings, API keys, passwords
- **Intellectual Property**: Private keys, JWT tokens, API paths

### Classification & Risk Scoring
- Multi-framework compliance classification (GDPR, HIPAA, PCI-DSS)
- Sensitivity scoring based on pattern weights
- Exposure risk assessment (encryption, public access, versioning)
- Combined risk scoring with actionable factors
- **🤖 AI-Powered False Positive Reduction** (NEW!)
  - Uses LLMs (Ollama/OpenAI/Anthropic) to filter false positives
  - Context-aware analysis of detections
  - 93%+ reduction in false positives
  - See [AI_FILTERING.md](AI_FILTERING.md) for details

### Multi-Format Support
- Text files: `.txt`, `.md`, `.csv`, `.log`, `.json`, `.yaml`, `.xml`, `.html`
- Code files: `.js`, `.py`, `.java`, `.cpp`, `.go`, `.rs`, `.sh`, `.sql`
- Documents: `.pdf`, `.docx`, `.xlsx`, `.csv`
- Binary detection and automatic skipping

### Cloud Configuration Checks
- S3 bucket public access analysis
- Encryption status (SSE, KMS)
- Versioning and logging configuration
- ACL and policy evaluation

Quickstart
----------

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m ghostlight --help
python -m pip install -e .
ghostlight --help
```

Usage
-----

```bash
source .venv/bin/activate

# Filesystem (single file or directory)
ghostlight scan --scanner fs --target ./myfile.txt --format table
ghostlight scan --scanner fs --target /path/to/dir --format json --output results.json

# Git repository (local)
ghostlight scan --scanner git --target /path/to/repo --format md --output report.md

# Git repository (public remote)
ghostlight scan --scanner git --target https://github.com/user/repo.git --format json

# Git repository (private - GitHub)
export GITHUB_TOKEN=ghp_YOUR_TOKEN_HERE
ghostlight scan --scanner git --target https://github.com/user/private-repo.git

# Git repository (private - SSH)
ghostlight scan --scanner git --target git@github.com:user/private-repo.git

# Virtual Machine (remote via SSH - supports recursive directory scanning)
ghostlight scan --scanner vm --target "user@hostname:/path/to/scan" --format table
ghostlight scan --scanner vm --target "root@192.168.1.100:/" --format json

# S3 (requires AWS credentials in environment or ~/.aws/credentials)
ghostlight scan --scanner s3 --target my-bucket/prefix --format json --output s3.json

# Azure Blob (connection string|container/prefix)
ghostlight scan --scanner azure --target "<conn>|container/prefix"

# RDS (AWS RDS instances)
export AWS_PROFILE=myprofile  # or set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY
export RDS_USERNAME=admin
export RDS_PASSWORD=yourpassword
ghostlight scan --scanner rds --target "rds://mydb-instance"               # auto-detect engine/db, auto tables
ghostlight scan --scanner rds --target "rds://mydb-instance/postgres:mydb:" # explicit engine/db, auto tables
ghostlight scan --scanner rds --target "rds://mydb-instance/mysql:appdb:users,orders" --list-tables --show-sql

# Postgres (direct connection via DSN URL)
ghostlight scan --scanner postgres --target "postgresql://user:pass@host:5432/db?sslmode=require"
ghostlight scan --scanner postgres --target "postgresql://user:pass@host:5432/db?sslmode=require" --list-tables --show-sql

# AWS Comprehensive (auto-discovers ALL AWS resources: RDS + S3 + EC2)
export AWS_ACCESS_KEY_ID=AKIAXXXXXXXX
export AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxx
export RDS_USERNAME=admin
export RDS_PASSWORD=dbpassword
ghostlight scan --scanner aws --target all --format json --output aws-full-scan.json

# AWS Specific resources
ghostlight scan --scanner aws --target rds,s3 --format table
ghostlight scan --scanner aws --target ec2 --format md

# EC2 (individual instance via SSM)
ghostlight scan --scanner ec2 --target i-1234567890abcdef0 --format table
```

Supported Scanners
------------------

Core
- <img src="assets/icons/fs.svg" width="20" /> Filesystem (`fs`): `ghostlight scan --scanner fs --target /path/to/dir`
- <img src="assets/icons/git.svg" width="20" /> Git (`git`): `ghostlight scan --scanner git --target https://github.com/user/repo.git`

Cloud Storage
- <img src="assets/icons/s3.svg" width="20" /> Amazon S3 (`s3`): `ghostlight scan --scanner s3 --target my-bucket/prefix`
- <img src="assets/icons/gcs.svg" width="20" /> Google Cloud Storage (`gcs`): `ghostlight scan --scanner gcs --target my-bucket`
- <img src="assets/icons/azure.svg" width="20" /> Azure Blob (`azure`): `ghostlight scan --scanner azure --target "<conn>|container/prefix"`

SaaS
- <img src="assets/icons/gdrive.svg" width="20" /> Google Drive (`gdrive`): `ghostlight scan --scanner gdrive --target default`
- <img src="assets/icons/gdrive_workspace.svg" width="20" /> GDrive Workspace (`gdrive_workspace`): `ghostlight scan --scanner gdrive_workspace --target /path/to/delegated.json`
- <img src="assets/icons/slack.svg" width="20" /> Slack (`slack`): `ghostlight scan --scanner slack --target "xoxb-...:C12345"`

Compute
- <img src="assets/icons/vm.svg" width="20" /> VM over SSH (`vm`): `ghostlight scan --scanner vm --target "user@host:/etc,/var/log"`

Databases
- <img src="assets/icons/rds.svg" width="20" /> AWS RDS (`rds`): `ghostlight scan --scanner rds --target "rds://my-instance-id"`
- <img src="assets/icons/postgres.svg" width="20" /> PostgreSQL (`postgres`): `ghostlight scan --scanner postgres --target "postgresql://user:pass@host:5432/db?sslmode=require"`
- <img src="assets/icons/mysql.svg" width="20" /> MySQL (`mysql`): `ghostlight scan --scanner mysql --target "mysql://user:pass@host:3306/db"`

Tips
- Use `--list-tables` (DB scans) to print discovered tables.
- Use `--show-sql` to log executed SQL.
- Increase `--sample-bytes` for deeper content sampling.

### AWS Comprehensive Scanning

The AWS scanner automatically discovers and scans **ALL** your AWS resources using AWS credentials.

#### Supported Resources
- **RDS**: PostgreSQL, MySQL, MariaDB instances
- **S3**: All buckets and objects
- **EC2**: Running instances via SSM Session Manager (no SSH keys needed!)

#### Prerequisites
```bash
# Install boto3
pip install boto3

# Configure AWS credentials
aws configure
# OR
export AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX
export AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
export AWS_DEFAULT_REGION=us-east-1

# For RDS scanning
export RDS_USERNAME=admin
export RDS_PASSWORD=your_db_password

# For EC2 scanning (SSM must be configured on instances)
# No additional credentials needed - uses AWS credentials
```

#### Usage Examples

**Scan everything:**
```bash
ghostlight scan --scanner aws --target all --format json --output aws-scan.json
```

**Scan specific resource types:**
```bash
# Only RDS databases
ghostlight scan --scanner aws --target rds --format table

# Only S3 buckets
ghostlight scan --scanner aws --target s3 --format json

# Only EC2 instances
ghostlight scan --scanner aws --target ec2 --format md

# RDS and S3 (skip EC2)
ghostlight scan --scanner aws --target rds,s3 --format json
```

#### What Gets Discovered & Scanned

**RDS:**
- Auto-discovers all RDS instances in the region
- Scans tables for PII, PHI, PCI, Secrets
- Includes RDS configuration risk assessment

**S3:**
- Auto-discovers all S3 buckets in the account
- Scans all objects in each bucket
- Checks bucket security configuration (public access, encryption)

**EC2:**
- Auto-discovers all running EC2 instances
- Scans via SSM Session Manager (no SSH keys required!)
- Scans `/var/log`, `/etc`, `/home`, `/opt` by default
- Detects secrets in configuration files and logs

#### IAM Permissions Required

Your AWS user/role needs these permissions:
- `sts:GetCallerIdentity`
- `rds:DescribeDBInstances`
- `s3:ListAllMyBuckets`, `s3:ListBucket`, `s3:GetObject`
- `ec2:DescribeInstances`
- `ssm:DescribeInstanceInformation`, `ssm:SendCommand`, `ssm:GetCommandInvocation`

See `AWS_COMPREHENSIVE_SCANNING.md` for complete IAM policy.

#### Multi-Region Scanning
```bash
for region in us-east-1 us-west-2 eu-west-1; do
  export AWS_DEFAULT_REGION=$region
  ghostlight scan --scanner aws --target all \
    --format json --output "aws-scan-${region}.json"
done
```

**📖 For detailed AWS scanning guide, see:** `AWS_COMPREHENSIVE_SCANNING.md`

### Authentication for Private Repositories

#### GitHub
```bash
# Create Personal Access Token at: https://github.com/settings/tokens
# Scopes needed: repo (full access)
export GITHUB_TOKEN=ghp_YOUR_TOKEN_HERE
ghostlight scan --scanner git --target https://github.com/user/private-repo.git
```

#### GitLab
```bash
# Create token at: Settings > Access Tokens (read_repository scope)
export GITLAB_TOKEN=YOUR_TOKEN_HERE
ghostlight scan --scanner git --target https://gitlab.com/user/private-repo.git
```

#### Bitbucket
```bash
# Create App Password at: Settings > App passwords (Repositories: Read)
export BITBUCKET_USERNAME=your_username
export BITBUCKET_TOKEN=your_app_password
ghostlight scan --scanner git --target https://bitbucket.org/user/private-repo.git
```

#### SSH Authentication (All providers)
```bash
# Configure SSH key once
ssh-keygen -t ed25519 -C "your_email@example.com"
# Add public key to GitHub/GitLab/Bitbucket settings
# Then use SSH URLs
ghostlight scan --scanner git --target git@github.com:user/private-repo.git
```

### Scanning Virtual Machines (Remote via SSH)

The VM scanner connects to remote Virtual Machines via SSH and scans files/directories for sensitive data. It supports both single files and recursive directory scanning.

#### Prerequisites
1. **SSH Access** - You need SSH access to the target VM:
```bash
# Test SSH connection first
ssh user@hostname
```

2. **SSH Key Setup** (recommended):
```bash
# Generate SSH key if you don't have one
ssh-keygen -t ed25519 -C "your_email@example.com"

# Copy public key to VM
ssh-copy-id user@hostname
```

3. **Python Dependencies**:
```bash
pip install paramiko
```

#### Usage Examples

**Scan from root directory (requires appropriate permissions):**
```bash
# Recursively scan from root
ghostlight scan --scanner vm \
  --target "root@192.168.1.100:/" \
  --format json --output vm-root-scan.json
```

**Scan specific directories:**
```bash
# Scan /etc and /var/log directories
ghostlight scan --scanner vm \
  --target "ubuntu@myvm.example.com:/etc,/var/log" \
  --format table

# Scan home directory
ghostlight scan --scanner vm \
  --target "user@hostname:/home/user" \
  --format md --output vm-report.md
```

**Scan specific files:**
```bash
# Scan individual configuration files
ghostlight scan --scanner vm \
  --target "admin@prod-server:/etc/config.json,/var/app/secrets.yaml" \
  --format json
```

**Scan application directories:**
```bash
# Scan web application directory
ghostlight scan --scanner vm \
  --target "deploy@webserver:/var/www/html" \
  --format table

# Scan multiple application folders
ghostlight scan --scanner vm \
  --target "app@server:/opt/app1,/opt/app2,/home/app/logs" \
  --format json --output app-scan.json
```

#### Target Format
```
user@hostname:/path1,/path2,/path3

Where:
  user     = SSH username
  hostname = VM hostname or IP address
  paths    = Comma-separated file or directory paths (directories are scanned recursively)
```

#### What Gets Scanned
- **Recursive Directory Traversal**: Automatically discovers all files in specified directories
- **Smart Filtering**: Skips binary files (.jpg, .png, .zip, .exe, etc.)
- **Size Limits**: Respects `--max-file-mb` setting (default: 20 MB)
- **Hidden Files**: Automatically skips hidden files and directories (starting with .)
- **Common Ignores**: Skips `node_modules`, `__pycache__`, `.git`, `venv`, `.venv`, `.cache`
- **Detects**: PII, PHI, PCI, secrets in all scanned text files
- **Risk Scoring**: Includes sensitivity scoring and risk assessment

#### Security & Performance Notes
- **Read-Only**: Only performs read operations via SFTP
- **Sampling**: Reads up to `--sample-bytes` per file (default: 2048 bytes)
- **Encryption**: Uses SSH/SFTP protocol (encrypted by default)
- **Permissions**: Respects file system permissions (files you can't read are skipped)
- **Performance**: Large directories may take time; consider scanning specific subdirectories

#### SSH Authentication Options

**1. Password-based (interactive):**
```bash
# Will prompt for password
ghostlight scan --scanner vm --target "user@hostname:/path"
```

**2. SSH key-based (recommended):**
```bash
# No password prompt if key is in default location (~/.ssh/id_rsa or ~/.ssh/id_ed25519)
ghostlight scan --scanner vm --target "user@hostname:/path"
```

**3. SSH config file:**
```bash
# Add to ~/.ssh/config
Host myvm
    HostName 192.168.1.100
    User admin
    IdentityFile ~/.ssh/vm_key

# Then use the alias
ghostlight scan --scanner vm --target "admin@myvm:/var/app"
```

#### Common Scenarios

**Development Server Audit:**
```bash
ghostlight scan --scanner vm \
  --target "developer@dev-server:/home/developer,/var/www,/opt/projects" \
  --format md --output dev-audit.md
```

**Production Server Security Scan:**
```bash
ghostlight scan --scanner vm \
  --target "admin@prod-01:/var/log,/etc,/opt/applications" \
  --format json --output prod-security-scan.json
```

**Configuration Files Audit:**
```bash
ghostlight scan --scanner vm \
  --target "ops@server:/etc/nginx,/etc/mysql,/etc/redis,/etc/app" \
  --format table
```

### Scanning AWS RDS Databases

The RDS scanner connects to AWS RDS instances (PostgreSQL, MySQL, MariaDB) and scans tables for sensitive data.

#### Prerequisites
1. **AWS Credentials** - Configure AWS CLI or set environment variables:
```bash
aws configure
# Or manually:
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-east-1
```

2. **IAM Permissions** - Your AWS user/role needs:
   - `rds:DescribeDBInstances`

3. **Database Credentials**:
```bash
export RDS_USERNAME=admin
export RDS_PASSWORD=your_db_password
```

4. **Network Access** - Ensure:
   - RDS security group allows inbound from your IP
   - Or run from EC2/Lambda in same VPC

#### Usage Examples

**Scan specific tables:**
```bash
export RDS_USERNAME=admin
export RDS_PASSWORD=mypassword
ghostlight scan --scanner rds \
  --target "rds://my-postgres-instance/postgres:mydb:users,orders,payments" \
  --format json --output rds-scan.json
```

**Auto-discover and scan all tables:**
```bash
# Omit table list to scan all tables (up to 50)
ghostlight scan --scanner rds \
  --target "rds://my-mysql-prod/mysql:appdb:" \
  --format table
```

**Target Format:**
```
rds://INSTANCE_ID/ENGINE:DATABASE:TABLE1,TABLE2,TABLE3

Where:
  INSTANCE_ID = RDS instance identifier (from AWS console)
  ENGINE      = postgres, mysql, or mariadb
  DATABASE    = Database name to scan
  TABLES      = Comma-separated table names (optional, auto-discovers if empty)
```

**Examples:**
```bash
# PostgreSQL RDS
rds://prod-postgres/postgres:analytics:user_events,transactions

# MySQL RDS
rds://app-mysql/mysql:production:customers,orders

# Auto-discover tables
rds://dev-db/postgres:testdb:
```

#### What Gets Scanned
- Samples up to 100 rows per table
- Detects PII, PHI, PCI, secrets in table data
- Reports row counts, column names
- Includes RDS instance metadata
- Risk scoring based on data sensitivity + RDS config

#### Security Notes
- Uses read-only queries (`SELECT`)
- Credentials are never logged or stored
- Samples limited data (configurable via `--sample-bytes`)
- Supports SSL/TLS connections (default for RDS)

Connector Configuration and Scan Guide
--------------------------------------

This section shows how to configure and run scans for every connector supported by ghostlight.

Prerequisites
-------------
- Install dependencies:
```bash
pip install -r requirements.txt
```
- Optional connectors require extra deps (already listed in `requirements.txt`):
  - GCS: `google-cloud-storage`
  - Google Drive/Workspace: `google-api-python-client`, `google-auth`
  - Slack: `slack-sdk`
  - CouchDB: `couchdb`


Filesystem (fs)
---------------
Scan a file or directory. Skips binaries by default.
```bash
ghostlight scan --scanner fs --target /path/to/dir --format table
ghostlight scan --scanner fs --target ./file.txt --format json --output fs.json
```

Text (inline)
-------------
Scan a raw string or pasted text.
```bash
ghostlight scan --scanner text --target "my api key is sk_live_..." --format table
```

Git (local or remote)
---------------------
Authenticate via env if needed: `GITHUB_TOKEN`, `GITLAB_TOKEN`, or SSH keys.
```bash
ghostlight scan --scanner git --target /path/to/repo
ghostlight scan --scanner git --target https://github.com/user/repo.git
ghostlight scan --scanner git --target git@github.com:user/private-repo.git
```

Amazon S3 (s3)
--------------
Requires AWS creds: `aws configure` or `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`.
```bash
ghostlight scan --scanner s3 --target my-bucket
ghostlight scan --scanner s3 --target my-bucket/prefix --format json --output s3.json
```

Google Cloud Storage (gcs)
--------------------------
Requires Application Default Credentials or service account. Set `GOOGLE_APPLICATION_CREDENTIALS=/path/key.json`.
```bash
ghostlight scan --scanner gcs --target my-gcs-bucket
ghostlight scan --scanner gcs --target my-gcs-bucket/path/prefix
```

Google Drive (gdrive)
---------------------
Use a service account JSON (recommended) or default credentials.
```bash
ghostlight scan --scanner gdrive --target /path/to/service_account.json
# or rely on default creds
ghostlight scan --scanner gdrive --target default
```

Google Drive Workspace (gdrive_workspace)
-----------------------------------------
Requires domain-wide delegation service account with Drive and Admin Directory readonly scopes.
```bash
ghostlight scan --scanner gdrive_workspace --target /path/to/delegated_service_account.json
```

Slack (slack)
-------------
Provide a bot token and optional channel id: `xoxb-...:C12345`. If no channel is provided, first 50 channels are scanned.
```bash
ghostlight scan --scanner slack --target "xoxb-XXXXX:C0123456789"
ghostlight scan --scanner slack --target "xoxb-XXXXX"
```

Azure Blob Storage (azure)
--------------------------
Target format: `"<connection-string>|container/prefix"`.
```bash
ghostlight scan --scanner azure --target "DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...;EndpointSuffix=core.windows.net|container/prefix"
```

Virtual Machines over SSH (vm)
------------------------------
Scan files on remote hosts via SSH. See `VM_SCANNING_EXAMPLES.md` for more.
```bash
ghostlight scan --scanner vm --target "user@host:/etc,/var/log" --format table
```

AWS Aggregated (aws)
--------------------
Auto-discovers RDS, S3, and EC2. See `AWS_COMPREHENSIVE_SCANNING.md`.
```bash
ghostlight scan --scanner aws --target all --format json --output aws.json
ghostlight scan --scanner aws --target rds,s3
```

PostgreSQL (postgres)
---------------------
Target format: `postgres://user:pass@host:port/db:schema.table1,schema.table2`
```bash
ghostlight scan --scanner postgres --target "postgres://user:pass@db:5432/app:public.users,public.orders"
```

MySQL (mysql)
-------------
Target format: `mysql://user:pass@host:port/db` (now supports direct DSN)
```bash
ghostlight scan --scanner mysql --target "mysql://user:pass@db:3306/app"
ghostlight scan --scanner mysql --target "mysql://user:pass@db:3306/app" --list-tables --show-sql
```

MongoDB (mongo)
---------------
Target format: `mongodb://user:pass@host:port/db:collection1,collection2`
```bash
ghostlight scan --scanner mongo --target "mongodb://user:pass@mongo:27017/app:users,events"
```

Redis (redis)
-------------
Target is a standard Redis URL.
```bash
ghostlight scan --scanner redis --target "redis://redis:6379/0"
```

Firebase Firestore (firebase)
-----------------------------
Target format: `firestore:project_id:collection1,collection2`. Requires `firebase-admin` and access to the project.
```bash
ghostlight scan --scanner firebase --target "firestore:my-gcp-project:users,events"
```

CouchDB (couchdb)
-----------------
Target format: `http[s]://user:pass@host:port:db1,db2`
```bash
ghostlight scan --scanner couchdb --target "http://admin:pass@couchdb:5984:users,orders"
```

Notes on False Positives
------------------------
- Ghostlight applies context-aware filters to reduce false positives (phone, SSN, coordinates, AWS keys).
- Tune `--sample-bytes` for performance vs. coverage.
- Use JSON/Markdown outputs for post-processing and triage.


