"""
AWS EC2 Scanner using SSM Session Manager
Scans EC2 instances without requiring SSH keys
"""
from __future__ import annotations

import os
import json
import time
from typing import Iterable, List, Tuple

try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None

from ghostlight.classify.engine import classify_text, classify_text_detailed, score_severity
from ghostlight.risk.scoring import compute_sensitivity_score, compute_exposure_factor, compute_risk
from ghostlight.core.models import Evidence, Finding, ScanConfig, Detection
from ghostlight.utils.logging import get_logger
from ghostlight.utils.snippets import earliest_line_and_snippet
from .base import Scanner

logger = get_logger(__name__)

TEXT_EXTS = {".txt", ".md", ".csv", ".log", ".json", ".yaml", ".yml", ".xml", ".html", 
             ".js", ".py", ".java", ".cpp", ".c", ".h", ".go", ".rs", ".sh", ".sql", ".conf", ".config"}
SKIP_DIRS = {'node_modules', '__pycache__', '.git', 'venv', '.venv', '.cache', 'cache'}


class EC2Scanner(Scanner):
    """
    Scan EC2 instances using AWS Systems Manager (SSM) Session Manager.
    No SSH keys required - uses AWS credentials.
    
    Target formats:
      - instance-id (scans default paths)
      - instance-id:/path1,/path2 (scans specific paths)
    
    Prerequisites:
      - SSM agent installed on EC2 instance (pre-installed on Amazon Linux 2, Ubuntu 16.04+)
      - IAM permissions: ssm:SendCommand, ssm:GetCommandInvocation
      - EC2 instance has IAM role with AmazonSSMManagedInstanceCore policy
    """
    
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        if boto3 is None:
            logger.error("boto3 not available. Install with: pip install boto3")
            return []
        
        # Parse target: instance-id or instance-id:/path1,/path2
        if ":" in target:
            instance_id, paths_str = target.split(":", 1)
            paths = [p.strip() for p in paths_str.split(",") if p.strip()]
        else:
            instance_id = target
            # Default paths to scan
            paths = ["/var/log", "/etc", "/home", "/opt"]
        
        logger.info(f"EC2 Scanner: Instance {instance_id}")
        
        # Verify instance exists and is running
        ec2_client = boto3.client("ec2")
        ssm_client = boto3.client("ssm")
        
        try:
            response = ec2_client.describe_instances(InstanceIds=[instance_id])
            if not response["Reservations"]:
                logger.error(f"Instance {instance_id} not found")
                return []
            
            instance = response["Reservations"][0]["Instances"][0]
            state = instance["State"]["Name"]
            
            if state != "running":
                logger.error(f"Instance {instance_id} is not running (state: {state})")
                return []
            
            logger.info(f"Instance state: {state}")
            
        except Exception as e:
            logger.error(f"Failed to describe instance: {e}")
            return []
        
        # Check if instance is managed by SSM
        try:
            response = ssm_client.describe_instance_information(
                Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
            )
            
            if not response["InstanceInformationList"]:
                logger.error(f"Instance {instance_id} is not managed by SSM")
                logger.error("Ensure SSM agent is installed and instance has AmazonSSMManagedInstanceCore IAM role")
                return []
            
            ping_status = response["InstanceInformationList"][0]["PingStatus"]
            logger.info(f"SSM Status: {ping_status}")
            
            if ping_status != "Online":
                logger.error(f"Instance is not online in SSM (status: {ping_status})")
                return []
                
        except Exception as e:
            logger.error(f"Failed to check SSM status: {e}")
            return []
        
        # Scan each path
        for path in paths:
            logger.info(f"Scanning path: {path}")
            yield from self._scan_path(ssm_client, instance_id, path, config)
    
    def _scan_path(
        self,
        ssm_client,
        instance_id: str,
        path: str,
        config: ScanConfig
    ) -> Iterable[Finding]:
        """Scan a specific path on EC2 instance using SSM"""
        
        # Find all text files in the path
        find_command = f"""
find {path} -type f \\
  \\( -name "*.txt" -o -name "*.log" -o -name "*.json" -o -name "*.yaml" \\
  -o -name "*.yml" -o -name "*.conf" -o -name "*.config" -o -name "*.sh" \\
  -o -name "*.py" -o -name "*.js" -o -name "*.java" -o -name "*.sql" \\) \\
  ! -path "*/.*" ! -path "*/node_modules/*" ! -path "*/__pycache__/*" \\
  2>/dev/null | head -100
"""
        
        try:
            # Execute find command
            response = ssm_client.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [find_command]},
                TimeoutSeconds=30
            )
            
            command_id = response["Command"]["CommandId"]
            
            # Wait for command to complete
            time.sleep(2)
            
            # Get command output
            output = ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )
            
            if output["Status"] != "Success":
                logger.warning(f"Find command failed: {output.get('StatusDetails')}")
                return
            
            file_list = output["StandardOutputContent"].strip().split("\n")
            file_list = [f for f in file_list if f]
            
            logger.info(f"Found {len(file_list)} file(s) in {path}")
            
            # Scan each file
            for file_path in file_list[:50]:  # Limit to 50 files per path
                try:
                    yield from self._scan_file(ssm_client, instance_id, file_path, config)
                except Exception as e:
                    logger.debug(f"Failed to scan {file_path}: {e}")
                    
        except Exception as e:
            logger.error(f"Failed to scan path {path}: {e}")
    
    def _scan_file(
        self,
        ssm_client,
        instance_id: str,
        file_path: str,
        config: ScanConfig
    ) -> Iterable[Finding]:
        """Scan a specific file on EC2 instance"""
        
        # Read first N bytes of file
        read_command = f"head -c {config.sample_bytes} {file_path}"
        
        try:
            response = ssm_client.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [read_command]},
                TimeoutSeconds=10
            )
            
            command_id = response["Command"]["CommandId"]
            time.sleep(1)
            
            output = ssm_client.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id
            )
            
            if output["Status"] != "Success":
                return
            
            text = output["StandardOutputContent"]
            
            if not text or len(text) < 10:
                return
            
        except Exception as e:
            logger.debug(f"Failed to read {file_path}: {e}")
            return
        
        # Classify text
        labels = classify_text(text)
        detailed = classify_text_detailed(text)
        
        classifications = [
            f"GDPR:{l}" for l in labels.get("GDPR", [])
        ] + [
            f"HIPAA:{l}" for l in labels.get("HIPAA", [])
        ] + [
            f"PCI:{l}" for l in labels.get("PCI", [])
        ] + [
            f"SECRETS:{l}" for l in labels.get("SECRETS", [])
        ] + [
            f"IP:{l}" for l in labels.get("IP", [])
        ]
        
        detections = [
            Detection(bucket=b, pattern_name=name, matches=matches, sample_text=text[:200])
            for (b, name, matches) in detailed
        ]
        
        if not classifications:
            return
        
        sev, desc = score_severity(len(detections), sum(len(d.matches) for d in detections))
        sens, sens_factors = compute_sensitivity_score(detections)
        expo, expo_factors = compute_exposure_factor("ec2", {"instance_id": instance_id})
        risk, risk_level = compute_risk(sens, expo)
        
        earliest_line, snippet_line = earliest_line_and_snippet(text, detailed)
        logger.info(f"Found {len(detections)} detection(s) in {file_path}")
        
        yield Finding(
            id=f"ec2:{instance_id}{file_path}",
            resource=instance_id,
            location=f"ec2://{instance_id}{file_path}:{earliest_line or 1}",
            classifications=classifications,
            evidence=[Evidence(snippet=snippet_line)],
            severity=sev,
            data_source="ec2",
            profile=instance_id,
            bucket_name=None,
            file_path=file_path,
            severity_description=desc,
            detections=detections,
            risk_score=risk,
            risk_level=risk_level,
            risk_factors=sens_factors + expo_factors,
        )

