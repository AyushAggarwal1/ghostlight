# from .git_scanner import GitScanner
# from .fs_scanner import FileSystemScanner
# from .s3_scanner import S3Scanner
# from .azure_blob_scanner import AzureBlobScanner
# from .vm_scanner import VMScanner
# from .rds_scanner import RDSScanner
# from .ec2_scanner import EC2Scanner
# from .aws_scanner import AWSScanner
# from .databases import PostgresScanner, MySQLScanner, MongoScanner, RedisScanner, FirebaseScanner
# from .gcs_scanner import GCSScanner
# from .slack_scanner import SlackScanner
# from .gdrive_scanner import GDriveScanner
# from .gdrive_workspace_scanner import GDriveWorkspaceScanner
# from .text_scanner import TextScanner
# from .couchdb_scanner import CouchDBScanner
# from .jira_scanner import JiraScanner
# from .confluence_scanner import ConfluenceScanner

__all__ = [
    # Names exported for type checkers; scanners are imported lazily by cli.get_scanner
    "GitScanner",
    "FileSystemScanner",
    "S3Scanner",
    "AzureBlobScanner",
    "VMScanner",
    "RDSScanner",
    "EC2Scanner",
    "AWSScanner",
    "PostgresScanner",
    "MySQLScanner",
    "MongoScanner",
    "RedisScanner",
    "FirebaseScanner",
    "GCSScanner",
    "SlackScanner",
    "GDriveScanner",
    "GDriveWorkspaceScanner",
    "TextScanner",
    "CouchDBScanner",
    "JiraScanner",
    "ConfluenceScanner",
]

# Lazy attribute access to preserve `from ghostlight.scanners import XScanner` API
# without importing heavy dependencies until needed.
import importlib as _importlib  # noqa: E402

_NAME_TO_MODULE = {
    "GitScanner": "git_scanner",
    "FileSystemScanner": "fs_scanner",
    "S3Scanner": "s3_scanner",
    "AzureBlobScanner": "azure_blob_scanner",
    "VMScanner": "vm_scanner",
    "RDSScanner": "rds_scanner",
    "EC2Scanner": "ec2_scanner",
    "AWSScanner": "aws_scanner",
    "PostgresScanner": "databases",
    "MySQLScanner": "databases",
    "MongoScanner": "databases",
    "RedisScanner": "databases",
    "FirebaseScanner": "databases",
    "GCSScanner": "gcs_scanner",
    "SlackScanner": "slack_scanner",
    "GDriveScanner": "gdrive_scanner",
    "GDriveWorkspaceScanner": "gdrive_workspace_scanner",
    "TextScanner": "text_scanner",
    "CouchDBScanner": "couchdb_scanner",
    "JiraScanner": "jira_scanner",
    "ConfluenceScanner": "confluence_scanner",
}


def __getattr__(name):  # type: ignore
    module_name = _NAME_TO_MODULE.get(name)
    if module_name is None:
        raise AttributeError(name)
    mod = _importlib.import_module(f".{module_name}", __name__)
    return getattr(mod, name)


