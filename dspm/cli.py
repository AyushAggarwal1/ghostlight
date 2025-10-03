import json
import os
from typing import Optional, List

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .core.models import ScanConfig
from .reporters.json_reporter import to_json as reporter_json
from .reporters.markdown_reporter import to_markdown as reporter_md


console = Console()


@click.group(help="ghostlight scanning CLI")
@click.version_option(__version__, prog_name="ghostlight")
def main():
    pass


@main.command("scan", help="Run a scan")
@click.option("--scanner", type=click.Choice(["fs","git","s3","gcs","gdrive","gdrive_workspace","slack","azure","vm","rds","ec2","aws","postgres","mysql","mongo","redis","firebase","couchdb","text"]) , default="fs")
@click.option("--target", type=str, default=".", help="Target identifier for scanner")
@click.option("--format", "fmt", type=click.Choice(["table","json","md"]), default="table")
@click.option("--output", type=click.Path(dir_okay=False), default=None, help="Optional output file")
@click.option("--max-file-mb", type=int, default=20)
@click.option("--sample-bytes", type=int, default=2048)
def scan_cmd(scanner: str, target: str, fmt: str, output: Optional[str], max_file_mb: int, sample_bytes: int):
    config = ScanConfig(max_file_mb=max_file_mb, sample_bytes=sample_bytes)
    
    # Preflight connectivity checks per scanner
    def preflight_check(name: str, tgt: str) -> bool:
        try:
            if name == "slack":
                from slack_sdk import WebClient  # type: ignore
                token, channel = (tgt.split(":", 1) + [None])[:2]
                client = WebClient(token=token)
                res = client.auth_test()
                if not res.get("ok"):
                    console.print("[red]Slack token invalid (auth_test failed).[/red]")
                    return False
                team = res.get("team")
                user_id = res.get("user_id")
                console.print(f"[green]Slack token valid[/green] (team={team}, bot_user={user_id})")
                if channel:
                    info = client.conversations_info(channel=channel)
                    if not info.get("ok"):
                        console.print(f"[red]Slack channel not accessible:[/red] {channel}")
                        return False
                    console.print(f"[green]Slack channel access OK[/green] (channel={channel})")
                return True
            if name in {"aws", "s3", "rds", "ec2"}:
                import boto3  # type: ignore
                sts = boto3.client("sts")
                ident = sts.get_caller_identity()
                console.print(f"[green]AWS credentials OK[/green] (account={ident.get('Account')})")
                if name == "s3":
                    s3 = boto3.client("s3")
                    bucket = tgt.split("/", 1)[0]
                    s3.head_bucket(Bucket=bucket)
                    console.print(f"[green]S3 bucket access OK[/green] (bucket={bucket})")
                return True
            if name == "gcs":
                from google.cloud import storage  # type: ignore
                client = storage.Client()
                bucket = tgt.split("/", 1)[0]
                if not client.bucket(bucket).exists():
                    console.print(f"[red]GCS bucket not found:[/red] {bucket}")
                    return False
                console.print(f"[green]GCS bucket access OK[/green] (bucket={bucket})")
                return True
            if name == "azure":
                from azure.storage.blob import BlobServiceClient  # type: ignore
                if "|" in tgt:
                    conn, rest = tgt.split("|", 1)
                else:
                    conn, rest = tgt, ""
                bsc = BlobServiceClient.from_connection_string(conn)
                # If container provided, ensure it exists
                if rest:
                    container = (rest.split("/", 1)[0] or "").strip()
                    if container:
                        _ = bsc.get_container_client(container).get_container_properties()
                        console.print(f"[green]Azure container access OK[/green] (container={container})")
                else:
                    console.print("[green]Azure connection string OK[/green]")
                return True
            if name == "postgres":
                import psycopg2  # type: ignore
                dsn = tgt.split(":", 1)[0]
                conn = psycopg2.connect(dsn)
                conn.close()
                console.print("[green]PostgreSQL connection OK[/green]")
                return True
            if name == "mysql":
                import pymysql  # type: ignore
                dsn = tgt.split(":", 1)[0]
                # Minimal parse (host/user/pass may be in DSN; let scanner do full). Here just sanity import.
                console.print("[yellow]MySQL DSN provided; connection will be validated during scan[/yellow]")
                return True
            if name == "mongo":
                import pymongo  # type: ignore
                dsn = tgt.split(":", 1)[0]
                client = pymongo.MongoClient(dsn, serverSelectionTimeoutMS=3000)
                client.admin.command("ping")
                client.close()
                console.print("[green]MongoDB connection OK[/green]")
                return True
            if name == "redis":
                import redis as redis_lib  # type: ignore
                r = redis_lib.from_url(tgt)
                r.ping()
                console.print("[green]Redis connection OK[/green]")
                return True
            if name == "firebase":
                import firebase_admin  # type: ignore
                from firebase_admin import firestore  # type: ignore
                parts = tgt.split(":", 2)
                if len(parts) >= 3:
                    project = parts[1]
                    if not firebase_admin._apps:
                        firebase_admin.initialize_app()
                    _ = firestore.client(project=project)
                    console.print(f"[green]Firestore client OK[/green] (project={project})")
                return True
            if name == "couchdb":
                import couchdb  # type: ignore
                dsn = tgt.split(":", 1)[0]
                server = couchdb.Server(dsn)
                _ = server.version()
                console.print("[green]CouchDB connection OK[/green]")
                return True
            if name == "gdrive":
                from googleapiclient.discovery import build  # type: ignore
                from google.oauth2 import service_account  # type: ignore
                if tgt and tgt != "default":
                    creds = service_account.Credentials.from_service_account_file(tgt, scopes=["https://www.googleapis.com/auth/drive.readonly"])  # type: ignore
                else:
                    creds = None  # type: ignore
                _ = build("drive", "v3", credentials=creds)
                console.print("[green]Google Drive credentials OK[/green]")
                return True
            if name == "gdrive_workspace":
                from googleapiclient.discovery import build  # type: ignore
                from google.oauth2 import service_account  # type: ignore
                creds = service_account.Credentials.from_service_account_file(tgt, scopes=["https://www.googleapis.com/auth/admin.directory.user.readonly","https://www.googleapis.com/auth/drive.readonly"])  # type: ignore
                _ = build("admin", "directory_v1", credentials=creds)
                _ = build("drive", "v3", credentials=creds)
                console.print("[green]Google Workspace credentials OK[/green]")
                return True
            if name == "fs":
                # path existence check for dir/file targets
                if not os.path.exists(tgt):
                    console.print(f"[yellow]Path not found:[/yellow] {tgt}. Proceeding may yield 0 files.")
                else:
                    console.print(f"[green]Filesystem path OK[/green] ({tgt})")
                return True
            # Default: no preflight
            return True
        except Exception as e:
            console.print(f"[red]Preflight check failed for {name}:[/red] {e}")
            return False

    if not preflight_check(scanner, target):
        return

    # Lazy-load scanners to avoid importing heavy deps on --help
    def get_scanner(name: str):
        if name == "fs":
            from .scanners.fs_scanner import FileSystemScanner
            return FileSystemScanner()
        if name == "git":
            from .scanners.git_scanner import GitScanner
            return GitScanner()
        if name == "s3":
            from .scanners.s3_scanner import S3Scanner
            return S3Scanner()
        if name == "gcs":
            from .scanners.gcs_scanner import GCSScanner
            return GCSScanner()
        if name == "gdrive":
            from .scanners.gdrive_scanner import GDriveScanner
            return GDriveScanner()
        if name == "gdrive_workspace":
            from .scanners.gdrive_workspace_scanner import GDriveWorkspaceScanner
            return GDriveWorkspaceScanner()
        if name == "slack":
            from .scanners.slack_scanner import SlackScanner
            return SlackScanner()
        if name == "azure":
            from .scanners.azure_blob_scanner import AzureBlobScanner
            return AzureBlobScanner()
        if name == "vm":
            from .scanners.vm_scanner import VMScanner
            return VMScanner()
        if name == "rds":
            from .scanners.rds_scanner import RDSScanner
            return RDSScanner()
        if name == "ec2":
            from .scanners.ec2_scanner import EC2Scanner
            return EC2Scanner()
        if name == "aws":
            from .scanners.aws_scanner import AWSScanner
            return AWSScanner()
        if name == "postgres":
            from .scanners.databases import PostgresScanner
            return PostgresScanner()
        if name == "mysql":
            from .scanners.databases import MySQLScanner
            return MySQLScanner()
        if name == "mongo":
            from .scanners.databases import MongoScanner
            return MongoScanner()
        if name == "redis":
            from .scanners.databases import RedisScanner
            return RedisScanner()
        if name == "firebase":
            from .scanners.databases import FirebaseScanner
            return FirebaseScanner()
        if name == "couchdb":
            from .scanners.couchdb_scanner import CouchDBScanner
            return CouchDBScanner()
        if name == "text":
            from .scanners.text_scanner import TextScanner
            return TextScanner()
        raise click.ClickException(f"Unknown scanner: {name}")

    impl = get_scanner(scanner)
    try:
        findings = impl.scan_list(target, config)
    except Exception as e:
        findings = []
        console.print(f"[red]Scan error:[/red] {e}")

    if fmt == "json":
        content = reporter_json(findings)
    elif fmt == "md":
        content = reporter_md(findings)
    else:
        table = Table(title="Ghostlight Findings", show_lines=True)
        table.add_column("Finding", style="cyan", width=30)
        table.add_column("Resource", style="magenta", width=20)
        table.add_column("Location", style="yellow", width=20)
        table.add_column("DB Engine", style="blue", width=15)
        table.add_column("Severity", style="red", width=10)
        table.add_column("Classifications", style="green", width=30)
        
        for f in findings:
            # Extract metadata
            db_engine = f.metadata.get("db_engine", "N/A") if f.metadata else "N/A"
            table_name = f.metadata.get("table_name", f.file_path or "N/A") if f.metadata else (f.file_path or "N/A")
            finding_name = f.profile or f.severity_description or "Sensitive data detected"
            
            # Format classifications (max 3)
            classifications_list = f.classifications[:3]
            classifications_str = "\n".join(classifications_list)
            if len(f.classifications) > 3:
                classifications_str += f"\n+{len(f.classifications)-3} more..."
            
            table.add_row(
                finding_name,
                f.resource,
                f.location,
                db_engine,
                f.severity.upper(),
                classifications_str
            )
        
        console.print(table)
        console.print(f"\n[bold]Total Findings:[/bold] {len(findings)}")
        content = None

    if output and content is not None:
        with open(output, "w", encoding="utf-8") as f:
            f.write(content)
        console.print(f"Saved results to {output}")


@main.command("test", help="Test connectivity to a scanner/source (e.g., Slack token and channel access)")
@click.option("--scanner", type=click.Choice(["slack", "s3", "gcs"]), required=True)
@click.option("--target", type=str, required=True, help="Target identifier (e.g., slack: xoxb-...[:CHANNEL_ID])")
def test_cmd(scanner: str, target: str):
    """Lightweight connectivity checks.

    slack: target = xoxb-token[:CHANNEL_ID]
    s3:    target = bucket or bucket/prefix (checks AWS creds & list access)
    gcs:   target = bucket or bucket/prefix (checks GCP creds & list access)
    """
    if scanner == "slack":
        try:
            from slack_sdk import WebClient  # type: ignore
        except Exception:
            console.print("[red]slack-sdk not installed. Run: pip install slack-sdk[/red]")
            return
        token, channel = (target.split(":", 1) + [None])[:2]
        client = WebClient(token=token)
        # Auth test
        try:
            res = client.auth_test()
            if not res.get("ok"):
                console.print("[red]Slack auth_test failed.[/red]")
                return
            team = res.get("team")
            user_id = res.get("user_id")
            console.print(f"[green]Token valid[/green] (team={team}, bot_user={user_id})")
        except Exception as e:
            console.print(f"[red]Slack token invalid or not authorized:[/red] {e}")
            return
        # Optional channel access check
        if channel:
            try:
                info = client.conversations_info(channel=channel)
                if not info.get("ok"):
                    console.print(f"[yellow]Channel access check failed for {channel}[/yellow]")
                    return
                console.print(f"[green]Channel access OK[/green] (channel={channel})")
            except Exception as e:
                console.print(f"[yellow]Token valid, but channel access failed:[/yellow] {e}")
                return
        console.print("[bold green]Slack connectivity OK[/bold green]")
        return

    if scanner == "s3":
        try:
            import boto3  # type: ignore
        except Exception:
            console.print("[red]boto3 not installed. Run: pip install boto3[/red]")
            return
        s3 = boto3.client("s3")
        try:
            # Validate credentials
            sts = boto3.client("sts")
            ident = sts.get_caller_identity()
            console.print(f"[green]AWS creds OK[/green] (account={ident.get('Account')})")
        except Exception as e:
            console.print(f"[red]AWS credential check failed:[/red] {e}")
            return
        bucket = target.split("/", 1)[0]
        try:
            s3.head_bucket(Bucket=bucket)
            console.print(f"[green]S3 access OK[/green] bucket={bucket}")
            console.print("[bold green]S3 connectivity OK[/bold green]")
        except Exception as e:
            console.print(f"[yellow]AWS creds OK but S3 access failed for bucket {bucket}:[/yellow] {e}")
        return

    if scanner == "gcs":
        try:
            from google.cloud import storage  # type: ignore
        except Exception:
            console.print("[red]google-cloud-storage not installed. Run: pip install google-cloud-storage[/red]")
            return
        client = storage.Client()
        bucket_name = target.split("/", 1)[0]
        try:
            bucket = client.bucket(bucket_name)
            exists = bucket.exists()
            if exists:
                console.print(f"[green]GCS access OK[/green] bucket={bucket_name}")
                console.print("[bold green]GCS connectivity OK[/bold green]")
            else:
                console.print(f"[yellow]GCS credential OK but bucket not found:[/yellow] {bucket_name}")
        except Exception as e:
            console.print(f"[red]GCS connectivity failed:[/red] {e}")
        return

