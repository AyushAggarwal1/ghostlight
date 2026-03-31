from dataclasses import dataclass, field
from typing import Dict, List, Optional
import os
import yaml
import json


@dataclass
class Evidence:
    snippet: str
    context: Optional[str] = None


@dataclass
class Finding:
    id: str
    resource: str
    location: str
    classifications: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    severity: str = "low"
    metadata: Dict[str, str] = field(default_factory=dict)
    # Extended fields
    data_source: Optional[str] = None  # e.g., s3, azure, git, filesystem, postgres
    profile: Optional[str] = None      # e.g., account/profile/context
    bucket_name: Optional[str] = None  # s3 bucket or storage container
    file_path: Optional[str] = None    # object key / file path / repo path
    severity_description: Optional[str] = None
    detections: List["Detection"] = field(default_factory=list)
    # Risk fields
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    risk_factors: List[str] = field(default_factory=list)


@dataclass
class ScanConfig:
    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    max_file_mb: int = 20
    sample_bytes: int = 65536
    # DB scanning verbosity
    list_tables: bool = False
    show_sql: bool = False
    # FP reduction
    strict: bool = False           # Drop single, low-confidence detections
    min_entropy: float = 3.5       # Entropy threshold for secrets
    # Deep scanning
    deep: bool = True
    sample_rows: int = 1000
    # Custom recognizers
    use_custom_recognizers: bool = True  # Enable custom recognizer validation


@dataclass
class Detection:
    bucket: str  # GDPR, HIPAA, PCI, SECRETS
    pattern_name: str
    matches: List[str] = field(default_factory=list)
    sample_text: Optional[str] = None


# Scanning functions for each data source

def scan_firebase(profile: str, config_path: Optional[str] = None, config_json: Optional[str] = None) -> List[Finding]:
    connections = get_connection(config_path, config_json)
    # Implement Firebase scanning logic using connections
    return []


def scan_fs(profile: str, config_path: Optional[str] = None, config_json: Optional[str] = None) -> List[Finding]:
    connections = get_connection(config_path, config_json)
    # Implement filesystem scanning logic using connections
    return []


def scan_gcs(profile: str, config_path: Optional[str] = None, config_json: Optional[str] = None) -> List[Finding]:
    connections = get_connection(config_path, config_json)
    # Implement GCS scanning logic using connections
    return []


def scan_text(profile: str, config_path: Optional[str] = None, config_json: Optional[str] = None) -> List[Finding]:
    connections = get_connection(config_path, config_json)
    # Implement text scanning logic using connections
    return []


def scan_mysql(profile: str, config_path: Optional[str] = None, config_json: Optional[str] = None) -> List[Finding]:
    connections = get_connection(config_path, config_json)
    # Implement MySQL scanning logic using connections
    return []


def scan_mongodb(profile: str, config_path: Optional[str] = None, config_json: Optional[str] = None) -> List[Finding]:
    connections = get_connection(config_path, config_json)
    # Implement MongoDB scanning logic using connections
    return []


def scan_couchdb(profile: str, config_path: Optional[str] = None, config_json: Optional[str] = None) -> List[Finding]:
    connections = get_connection(config_path, config_json)
    # Implement CouchDB scanning logic using connections
    return []


def scan_slack(profile: str, config_path: Optional[str] = None, config_json: Optional[str] = None) -> List[Finding]:
    connections = get_connection(config_path, config_json)
    # Implement Slack scanning logic using connections
    return []


def scan_postgresql(profile: str, config_path: Optional[str] = None, config_json: Optional[str] = None) -> List[Finding]:
    connections = get_connection(config_path, config_json)
    # Implement PostgreSQL scanning logic using connections
    return []


def scan_redis(profile: str, config_path: Optional[str] = None, config_json: Optional[str] = None) -> List[Finding]:
    connections = get_connection(config_path, config_json)
    # Implement Redis scanning logic using connections
    return []


def scan_s3(profile: str, config_path: Optional[str] = None, config_json: Optional[str] = None) -> List[Finding]:
    connections = get_connection(config_path, config_json)
    # Implement S3 scanning logic using connections
    return []


def scan_gdrive(profile: str, config_path: Optional[str] = None, config_json: Optional[str] = None) -> List[Finding]:
    connections = get_connection(config_path, config_json)
    # Implement Google Drive scanning logic using connections
    return []


def scan_gdrive_workspace(profile: str, config_path: Optional[str] = None, config_json: Optional[str] = None) -> List[Finding]:
    connections = get_connection(config_path, config_json)
    # Implement Google Drive Workspace scanning logic using connections
    return []


def get_connection(config_path: Optional[str] = None, config_json: Optional[str] = None) -> Dict:
    """
    Retrieve connection details from a YAML file or JSON input.
    """
    if config_path:
        if os.path.exists(config_path):
            with open(config_path, 'r') as file:
                connections = yaml.safe_load(file)
                return connections
        else:
            raise FileNotFoundError(f"Connection file not found: {config_path}")
    elif config_json:
        try:
            connections = json.loads(config_json)
            return connections
        except json.JSONDecodeError as e:
            raise ValueError(f"Error parsing JSON: {e}")
    else:
        raise ValueError("Please provide a connection file path or connection details in JSON format.")


