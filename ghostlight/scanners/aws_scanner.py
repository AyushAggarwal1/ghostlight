"""
AWS Comprehensive Scanner
Auto-discovers and scans all AWS resources: RDS, EC2, S3
"""
from __future__ import annotations

import os
from typing import Iterable, List, Dict, Any

try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None

from ghostlight.core.models import Finding, ScanConfig
from ghostlight.utils.logging import get_logger
from .base import Scanner
from .rds_scanner import RDSScanner
from .s3_scanner import S3Scanner
from .ec2_scanner import EC2Scanner

logger = get_logger(__name__)


class AWSScanner(Scanner):
    """
    Comprehensive AWS scanner that auto-discovers and scans:
    - RDS instances (PostgreSQL, MySQL, MariaDB)
    - S3 buckets
    - EC2 instances
    
    Usage:
        ghostlight scan --scanner aws --target all
        ghostlight scan --scanner aws --target rds,s3
        ghostlight scan --scanner aws --target ec2
    
    Environment Variables:
        AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION
        or use AWS_PROFILE
        
        RDS_USERNAME, RDS_PASSWORD (for RDS scanning)
        EC2_SSH_KEY_PATH (optional, for EC2 scanning)
        EC2_SSH_USER (default: ec2-user)
    """
    
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        if boto3 is None:
            logger.error("boto3 not available. Install with: pip install boto3")
            return []
        
        # Parse target to determine what to scan
        # target can be: "all", "rds", "s3", "ec2", "rds,s3", "s3,ec2", etc.
        target = target.lower().strip()
        
        if target == "all" or target == "":
            scan_types = ["rds", "s3", "ec2"]
        else:
            scan_types = [t.strip() for t in target.split(",")]
        
        logger.info(f"AWS Scanner: Will scan {', '.join(scan_types)}")
        logger.info("⏳ Validating AWS credentials...")
        
        # Validate AWS credentials with timeout
        try:
            import botocore.config
            boto_config = botocore.config.Config(
                connect_timeout=10,
                read_timeout=10,
                retries={'max_attempts': 2}
            )
            sts = boto3.client("sts", config=boto_config)
            identity = sts.get_caller_identity()
            logger.info(f"✅ AWS Account: {identity['Account']}")
            logger.info(f"✅ AWS User/Role: {identity['Arn']}")
        except Exception as e:
            logger.error(f"❌ Failed to validate AWS credentials: {e}")
            logger.error("⚠️  Set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION")
            logger.error("⚠️  Or use: aws configure")
            return []
        
        # Scan each resource type
        for scan_type in scan_types:
            if scan_type == "rds":
                yield from self._scan_all_rds(config)
            elif scan_type == "s3":
                yield from self._scan_all_s3(config)
            elif scan_type == "ec2":
                yield from self._scan_all_ec2(config)
            else:
                logger.warning(f"Unknown scan type: {scan_type}")
    
    def _scan_all_rds(self, config: ScanConfig) -> Iterable[Finding]:
        """Discover and scan all RDS instances"""
        logger.info("=" * 60)
        logger.info("🔍 DISCOVERING RDS INSTANCES...")
        logger.info("=" * 60)
        
        try:
            rds_client = boto3.client("rds")
            response = rds_client.describe_db_instances()
            instances = response["DBInstances"]
            
            logger.info(f"✅ Found {len(instances)} RDS instance(s)")
            
            if not instances:
                logger.info("ℹ️  No RDS instances found")
                return
            
            # Check for database credentials
            username = os.environ.get("RDS_USERNAME") or os.environ.get("DB_USERNAME")
            password = os.environ.get("RDS_PASSWORD") or os.environ.get("DB_PASSWORD")
            
            if not username or not password:
                logger.warning("⚠️  RDS credentials not found. Set RDS_USERNAME and RDS_PASSWORD")
                logger.warning("⏭️  Skipping RDS scanning...")
                return
            
            rds_scanner = RDSScanner()
            
            for idx, instance in enumerate(instances, 1):
                instance_id = instance["DBInstanceIdentifier"]
                engine = instance["Engine"]
                db_name = instance.get("DBName", "postgres" if "postgres" in engine else "mysql")
                status = instance["DBInstanceStatus"]
                publicly_accessible = instance.get("PubliclyAccessible", False)
                
                logger.info(f"\n📊 [{idx}/{len(instances)}] RDS Instance: {instance_id}")
                logger.info(f"    Engine: {engine} | Status: {status} | Database: {db_name}")
                logger.info(f"    Public Access: {'Yes' if publicly_accessible else 'No (Private VPC)'}")
                
                if status != "available":
                    logger.warning(f"    ⏭️  Skipping (not available)")
                    continue
                
                if not publicly_accessible:
                    logger.warning(f"    ⏭️  Skipping (private RDS - not reachable from this machine)")
                    logger.warning(f"    💡 To scan private RDS: Run scanner from EC2 in same VPC")
                    logger.warning(f"    💡 Or use: ghostlight scan --scanner aws --target s3,ec2")
                    continue
                
                logger.info(f"    ⏳ Connecting and scanning...")
                
                # Auto-discover tables by using empty table list
                # Note: Must use / after instance_id for proper URL parsing
                target = f"rds://{instance_id}/{engine}:{db_name}:"
                
                try:
                    findings_count = 0
                    for finding in rds_scanner.scan(target, config):
                        findings_count += 1
                        yield finding
                    logger.info(f"    ✅ Completed: {findings_count} finding(s)")
                except Exception as e:
                    logger.error(f"    ❌ Failed to scan: {e}")
                    
        except Exception as e:
            logger.error(f"❌ Failed to list RDS instances: {e}")
    
    def _scan_all_s3(self, config: ScanConfig) -> Iterable[Finding]:
        """Discover and scan all S3 buckets"""
        logger.info("=" * 60)
        logger.info("🔍 DISCOVERING S3 BUCKETS...")
        logger.info("=" * 60)
        
        try:
            s3_client = boto3.client("s3")
            response = s3_client.list_buckets()
            buckets = response["Buckets"]
            
            logger.info(f"✅ Found {len(buckets)} S3 bucket(s)")
            
            if not buckets:
                logger.info("ℹ️  No S3 buckets found")
                return
            
            s3_scanner = S3Scanner()
            
            for idx, bucket in enumerate(buckets, 1):
                bucket_name = bucket["Name"]
                logger.info(f"\n📦 [{idx}/{len(buckets)}] S3 Bucket: {bucket_name}")
                logger.info(f"    ⏳ Scanning objects...")
                
                try:
                    findings_count = 0
                    for finding in s3_scanner.scan(bucket_name, config):
                        findings_count += 1
                        yield finding
                    logger.info(f"    ✅ Completed: {findings_count} finding(s)")
                except Exception as e:
                    logger.error(f"    ❌ Failed to scan: {e}")
                    
        except Exception as e:
            logger.error(f"❌ Failed to list S3 buckets: {e}")
    
    def _scan_all_ec2(self, config: ScanConfig) -> Iterable[Finding]:
        """Discover and scan all EC2 instances"""
        logger.info("=" * 60)
        logger.info("🔍 DISCOVERING EC2 INSTANCES...")
        logger.info("=" * 60)
        
        try:
            ec2_client = boto3.client("ec2")
            response = ec2_client.describe_instances(
                Filters=[
                    {"Name": "instance-state-name", "Values": ["running"]}
                ]
            )
            
            instances = []
            for reservation in response["Reservations"]:
                instances.extend(reservation["Instances"])
            
            logger.info(f"✅ Found {len(instances)} running EC2 instance(s)")
            
            if not instances:
                logger.info("ℹ️  No running EC2 instances found")
                return
            
            ec2_scanner = EC2Scanner()
            
            for idx, instance in enumerate(instances, 1):
                instance_id = instance["InstanceId"]
                instance_type = instance["InstanceType"]
                
                # Get instance name from tags
                name = "N/A"
                for tag in instance.get("Tags", []):
                    if tag["Key"] == "Name":
                        name = tag["Value"]
                        break
                
                logger.info(f"\n💻 [{idx}/{len(instances)}] EC2 Instance: {instance_id}")
                logger.info(f"    Name: {name} | Type: {instance_type}")
                logger.info(f"    ⏳ Scanning filesystem...")
                
                try:
                    findings_count = 0
                    for finding in ec2_scanner.scan(instance_id, config):
                        findings_count += 1
                        yield finding
                    logger.info(f"    ✅ Completed: {findings_count} finding(s)")
                except Exception as e:
                    logger.error(f"    ❌ Failed to scan: {e}")
                    
        except Exception as e:
            logger.error(f"❌ Failed to list EC2 instances: {e}")

