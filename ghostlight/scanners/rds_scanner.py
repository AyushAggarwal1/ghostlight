"""
AWS RDS Scanner for Ghostlight
Supports PostgreSQL, MySQL, MariaDB RDS instances

Target format: rds://instance-id/engine:database:table1,table2
Example: rds://my-db/postgres:mydb:users,orders
         rds://my-db/mysql:mydb: (empty tables = auto-discover)
"""
from __future__ import annotations

import os
from typing import Iterable, Optional, Dict
from urllib.parse import urlparse

try:
    # Prefer psycopg3 if available
    import psycopg as psycopg2  # type: ignore
except Exception:  # pragma: no cover
    try:
        import psycopg2  # type: ignore
    except Exception:  # pragma: no cover
        psycopg2 = None

try:
    import pymysql  # type: ignore
except Exception:  # pragma: no cover
    pymysql = None

try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None

from ghostlight.classify.engine import classify_text, classify_text_detailed, score_severity
from ghostlight.classify.filters import apply_context_filters, is_system_table
from ghostlight.classify.ai_filter import ai_classify_detection, get_ai_summary, install_ollama_instructions
from ghostlight.risk.scoring import compute_sensitivity_score, compute_exposure_factor, compute_risk
from ghostlight.core.models import Evidence, Finding, ScanConfig, Detection
from ghostlight.utils.logging import get_logger
from ghostlight.utils.retry import retry_on_exception
from .base import Scanner

logger = get_logger(__name__)


class RDSScanner(Scanner):
    """
    Scanner for AWS RDS databases
    
    Target format:
        rds://instance-identifier/engine:database:table1,table2,table3
    
    Examples:
        rds://mydb-instance/postgres:mydb:users,orders,payments
        rds://mysql-prod/mysql:appdb:customers,transactions
    
    Authentication:
        - Uses AWS credentials from environment or ~/.aws/credentials
        - Requires IAM permissions: rds:DescribeDBInstances
        - Database credentials from environment variables:
          * RDS_USERNAME or DB_USERNAME
          * RDS_PASSWORD or DB_PASSWORD
    """
    
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        if boto3 is None:
            logger.error("boto3 not available. Install: pip install boto3")
            return []
        
        # Parse target: rds://<identifier_or_endpoint>/<engine>:<database>:<table1,table2>
        # Relaxed format: engine/database/tables are optional; we auto-discover when omitted.
        try:
            parsed = urlparse(target)
            # Prefer hostname (excludes optional trailing colon/port). Fallback to netloc trimmed.
            identifier_or_endpoint = parsed.hostname or parsed.netloc.split(":")[0].rstrip(":")
            path_body = parsed.path.lstrip("/")
            path_parts = path_body.split(":") if path_body else []
            
            engine = path_parts[0] if len(path_parts) >= 1 and path_parts[0] else ""
            database = path_parts[1] if len(path_parts) >= 2 and path_parts[1] else ""
            tables: list[str] = []
            if len(path_parts) >= 3 and path_parts[2]:
                tables = [t.strip() for t in path_parts[2].split(",") if t.strip()]
        except Exception as e:
            logger.error(f"Failed to parse RDS target: {e}")
            return []
        
        # Get RDS instance details
        # Resolve instance by identifier or endpoint
        endpoint, port, instance_info = self._get_rds_endpoint_with_details(identifier_or_endpoint)
        if not endpoint:
            logger.error(f"Could not find RDS instance for: {identifier_or_endpoint}")
            return []
        
        # Store instance info for findings metadata
        db_engine_version = instance_info.get("engine_version", "unknown")
        db_engine_type = instance_info.get("engine", engine or "unknown")
        instance_id = instance_info.get("instance_id", identifier_or_endpoint)
        
        # Fill missing engine/database from instance details
        if not engine:
            engine = db_engine_type
        if not database:
            database = (
                instance_info.get("db_name")
                or os.environ.get("RDS_DATABASE")
                or os.environ.get("DB_NAME")
                or ("postgres" if (engine or "").lower().startswith("postgres") else "mysql")
            )
        
        logger.info(f"Found RDS endpoint: {endpoint}:{port}")
        
        # Get database credentials
        username = os.environ.get("RDS_USERNAME") or os.environ.get("DB_USERNAME")
        password = os.environ.get("RDS_PASSWORD") or os.environ.get("DB_PASSWORD")
        
        if not username or not password:
            logger.error("Database credentials not found. Set RDS_USERNAME and RDS_PASSWORD env vars")
            return []
        
        # Connect based on engine type
        if engine.lower() in ["postgres", "postgresql"]:
            yield from self._scan_postgres(endpoint, port, database, username, password, tables, config, instance_id, db_engine_type, db_engine_version)
        elif engine.lower() in ["mysql", "mariadb"]:
            yield from self._scan_mysql(endpoint, port, database, username, password, tables, config, instance_id, db_engine_type, db_engine_version)
        else:
            logger.error(f"Unsupported RDS engine: {engine}")
    
    @retry_on_exception(max_retries=2)
    def _get_rds_endpoint(self, instance_id: str) -> tuple[Optional[str], Optional[int]]:
        """Get RDS instance endpoint from AWS API (backward compatibility)"""
        endpoint, port, _ = self._get_rds_endpoint_with_details(instance_id)
        return endpoint, port
    
    @retry_on_exception(max_retries=2)
    def _get_rds_endpoint_with_details(self, identifier_or_endpoint: str) -> tuple[Optional[str], Optional[int], Dict[str, str]]:
        """Get RDS instance endpoint and details from AWS API by identifier or endpoint hostname"""
        try:
            rds = boto3.client("rds")
            instance = None
            # First try direct describe by identifier
            try:
                resp = rds.describe_db_instances(DBInstanceIdentifier=identifier_or_endpoint)
                if resp.get("DBInstances"):
                    instance = resp["DBInstances"][0]
            except Exception:
                instance = None
            # Fallback: search by endpoint address
            if instance is None:
                paginator = rds.get_paginator("describe_db_instances")
                for page in paginator.paginate():
                    for inst in page.get("DBInstances", []):
                        ep = (inst.get("Endpoint") or {}).get("Address")
                        if ep and ep == identifier_or_endpoint:
                            instance = inst
                            break
                    if instance is not None:
                        break
            if instance is None:
                return None, None, {}
            endpoint = instance["Endpoint"]["Address"]
            port = instance["Endpoint"]["Port"]
            # Extract instance details
            instance_info = {
                "instance_id": instance.get("DBInstanceIdentifier", identifier_or_endpoint),
                "engine": instance.get("Engine", "unknown"),
                "engine_version": instance.get("EngineVersion", "unknown"),
                "db_name": instance.get("DBName"),
                "storage_gb": str(instance.get("AllocatedStorage", "0")),
                "encrypted": str(instance.get("StorageEncrypted", False)),
                "multi_az": str(instance.get("MultiAZ", False)),
                "publicly_accessible": str(instance.get("PubliclyAccessible", False)),
                "instance_class": instance.get("DBInstanceClass", "unknown"),
            }
            # Log instance details
            logger.info(f"RDS Instance: {instance_info['instance_id']} ({instance_info['engine']} {instance_info['engine_version']})")
            logger.info(f"Storage: {instance_info['storage_gb']}GB, Encrypted: {instance_info['encrypted']}")
            logger.info(f"Multi-AZ: {instance_info['multi_az']}, Public: {instance_info['publicly_accessible']}")
            return endpoint, port, instance_info
        except Exception as e:
            logger.error(f"Failed to describe RDS instance: {e}")
            return None, None, {}
    
    def _scan_postgres(
        self,
        host: str,
        port: int,
        database: str,
        username: str,
        password: str,
        tables: list[str],
        config: ScanConfig,
        instance_id: str,
        db_engine: str = "postgres",
        db_version: str = "unknown"
    ) -> Iterable[Finding]:
        """Scan PostgreSQL RDS database"""
        if psycopg2 is None:
            logger.error("psycopg2 not available. Install: pip install psycopg2-binary")
            return []
        
        try:
            conn = psycopg2.connect(
                host=host,
                port=port,
                database=database,
                user=username,
                password=password,
                connect_timeout=10
            )
            logger.info(f"Connected to PostgreSQL RDS: {host}:{port}/{database}")
        except Exception as e:
            logger.error(f"Failed to connect to PostgreSQL: {e}")
            return []
        
        cur = conn.cursor()
        
        # Auto-discover tables if not specified
        if not tables:
            try:
                sql = (
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = 'public' AND table_type = 'BASE TABLE' LIMIT 50"
                )
                if config.show_sql:
                    logger.info(f"SQL: {sql}")
                cur.execute(sql)
                tables = [row[0] for row in cur.fetchall()]
                logger.info(f"Auto-discovered {len(tables)} tables")
                if config.list_tables and tables:
                    logger.info("Tables: " + ", ".join(tables))
            except Exception as e:
                logger.warning(f"Failed to auto-discover tables: {e}")
                tables = []
        
        scanned_tables = 0
        for table in tables:
            try:
                # Get row count
                sql_count = f'SELECT COUNT(*) FROM "{table}"'
                if config.show_sql:
                    logger.info(f"SQL: {sql_count}")
                cur.execute(sql_count)
                row_count = cur.fetchone()[0]
                
                # Sample rows
                sql_sample = f'SELECT * FROM "{table}" LIMIT {config.sample_rows}'
                if config.show_sql:
                    logger.info(f"SQL: {sql_sample}")
                cur.execute(sql_sample)
                rows = cur.fetchall()
                
                # Get column names
                sql_cols = (
                    "SELECT column_name FROM information_schema.columns WHERE table_name = %s"
                )
                if config.show_sql:
                    logger.info(f"SQL: {sql_cols} [params: {table}]")
                cur.execute(sql_cols, (table,))
                columns = [row[0] for row in cur.fetchall()]
                
                scanned_tables += 1
                logger.info(f"Scanned table {table}: {row_count} rows, {len(columns)} columns")
            except Exception as e:
                logger.warning(f"Failed to scan table {table}: {e}")
                continue
            
            # Create sample text from rows
            sample = "\n".join(str(row) for row in rows[:50])[: config.sample_bytes]
            
            labels = classify_text(sample)
            detailed = classify_text_detailed(sample)
            
            # Apply context filters to reduce false positives
            detailed = apply_context_filters(detailed, sample, table, db_engine)
            
            # Skip if all detections were filtered out by rule-based filters
            if not detailed:
                logger.debug(f"All detections filtered out for table {table} (likely false positives)")
                continue
            
            # Apply AI-powered filtering (if enabled and available)
            ai_mode = os.getenv("GHOSTLIGHT_AI_FILTER", "auto")  # "auto", "ollama", "openai", "anthropic", "off"
            
            if ai_mode != "off" and detailed:
                # For each detection, ask AI to verify
                ai_verified_detections = []
                for bucket, pattern_name, matches in detailed:
                    matched_value = str(matches[0]) if matches else ""
                    
                    is_true_positive, reason = ai_classify_detection(
                        pattern_name=pattern_name,
                        matched_value=matched_value,
                        sample_text=sample,
                        table_name=table,
                        db_engine=db_engine,
                        column_names=columns,
                        use_ai=ai_mode
                    )
                    
                    if is_true_positive:
                        ai_verified_detections.append((bucket, pattern_name, matches))
                    else:
                        logger.debug(f"AI filtered out {pattern_name} in table {table}: {reason}")
                
                detailed = ai_verified_detections
            
            # Skip if AI filtered out all detections
            if not detailed:
                logger.debug(f"All detections filtered by AI for table {table}")
                continue
            
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
            
            if not classifications:
                continue
            
            detections = [
                Detection(bucket=b, pattern_name=name, matches=matches, sample_text=sample[:200])
                for (b, name, matches) in detailed
            ]
            
            sev, desc = score_severity(len(detections), sum(len(d.matches) for d in detections))
            sens, sens_factors = compute_sensitivity_score(detections)
            
            # RDS exposure metadata
            metadata = {
                "instance_id": instance_id,
                "engine": db_engine,
                "database": database,
                "table": table,
                "row_count": str(row_count),
                "columns": ",".join(columns[:10]),
            }
            
            expo, expo_factors = compute_exposure_factor("rds", metadata)
            risk, risk_level = compute_risk(sens, expo)
            
            logger.info(f"Found {len(detections)} detection(s) in table {table}")
            
            yield Finding(
                id=f"rds:{instance_id}/{database}/{table}",
                resource=instance_id,
                location=f"rds://{instance_id}/{database}/{table}",
                classifications=classifications,
                evidence=[Evidence(snippet=sample[:200])],
                severity=sev,
                data_source="rds",
                profile=instance_id,
                bucket_name=database,
                file_path=table,
                severity_description=desc,
                detections=detections,
                risk_score=risk,
                risk_level=risk_level,
                risk_factors=sens_factors + expo_factors,
                metadata=metadata,
            )
        
        cur.close()
        conn.close()
        logger.info(f"PostgreSQL RDS scan complete. Scanned {scanned_tables} tables")
    
    def _scan_mysql(
        self,
        host: str,
        port: int,
        database: str,
        username: str,
        password: str,
        tables: list[str],
        config: ScanConfig,
        instance_id: str,
        db_engine: str = "mysql",
        db_version: str = "unknown"
    ) -> Iterable[Finding]:
        """Scan MySQL/MariaDB RDS database"""
        if pymysql is None:
            logger.error("pymysql not available. Install: pip install pymysql")
            return []
        
        try:
            conn = pymysql.connect(
                host=host,
                port=port,
                database=database,
                user=username,
                password=password,
                connect_timeout=10
            )
            logger.info(f"Connected to MySQL RDS: {host}:{port}/{database}")
        except Exception as e:
            logger.error(f"Failed to connect to MySQL: {e}")
            return []
        
        cur = conn.cursor()
        
        # Auto-discover tables if not specified
        if not tables:
            try:
                sql = "SHOW TABLES"
                if config.show_sql:
                    logger.info(f"SQL: {sql}")
                cur.execute(sql)
                tables = [row[0] for row in cur.fetchall()]
                logger.info(f"Auto-discovered {len(tables)} tables")
                if config.list_tables and tables:
                    logger.info("Tables: " + ", ".join([str(t) for t in tables]))
            except Exception as e:
                logger.warning(f"Failed to auto-discover tables: {e}")
                tables = []
        
        scanned_tables = 0
        for table in tables:
            try:
                # Get row count
                sql_count = f"SELECT COUNT(*) FROM `{table}`"
                if config.show_sql:
                    logger.info(f"SQL: {sql_count}")
                cur.execute(sql_count)
                row_count = cur.fetchone()[0]
                
                # Sample rows
                sql_sample = f"SELECT * FROM `{table}` LIMIT {config.sample_rows}"
                if config.show_sql:
                    logger.info(f"SQL: {sql_sample}")
                cur.execute(sql_sample)
                rows = cur.fetchall()
                
                # Get column info
                sql_desc = f"DESCRIBE `{table}`"
                if config.show_sql:
                    logger.info(f"SQL: {sql_desc}")
                cur.execute(sql_desc)
                columns = [row[0] for row in cur.fetchall()]
                
                scanned_tables += 1
                logger.info(f"Scanned table {table}: {row_count} rows, {len(columns)} columns")
            except Exception as e:
                logger.warning(f"Failed to scan table {table}: {e}")
                continue
            
            sample = "\n".join(str(row) for row in rows[:50])[: config.sample_bytes]
            
            labels = classify_text(sample)
            detailed = classify_text_detailed(sample)
            
            # Apply context filters to reduce false positives
            detailed = apply_context_filters(detailed, sample, table, db_engine)
            
            # Skip if all detections were filtered out by rule-based filters
            if not detailed:
                logger.debug(f"All detections filtered out for table {table} (likely false positives)")
                continue
            
            # Apply AI-powered filtering (if enabled and available)
            ai_mode = os.getenv("GHOSTLIGHT_AI_FILTER", "auto")  # "auto", "ollama", "openai", "anthropic", "off"
            
            if ai_mode != "off" and detailed:
                # For each detection, ask AI to verify
                ai_verified_detections = []
                for bucket, pattern_name, matches in detailed:
                    matched_value = str(matches[0]) if matches else ""
                    
                    is_true_positive, reason = ai_classify_detection(
                        pattern_name=pattern_name,
                        matched_value=matched_value,
                        sample_text=sample,
                        table_name=table,
                        db_engine=db_engine,
                        column_names=columns,
                        use_ai=ai_mode
                    )
                    
                    if is_true_positive:
                        ai_verified_detections.append((bucket, pattern_name, matches))
                    else:
                        logger.debug(f"AI filtered out {pattern_name} in table {table}: {reason}")
                
                detailed = ai_verified_detections
            
            # Skip if AI filtered out all detections
            if not detailed:
                logger.debug(f"All detections filtered by AI for table {table}")
                continue
            
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
            
            if not classifications:
                continue
            
            detections = [
                Detection(bucket=b, pattern_name=name, matches=matches, sample_text=sample[:200])
                for (b, name, matches) in detailed
            ]
            
            sev, desc = score_severity(len(detections), sum(len(d.matches) for d in detections))
            sens, sens_factors = compute_sensitivity_score(detections)
            
            # Create descriptive finding name
            finding_name = f"Sensitive data in table '{table}'"
            if detections:
                pattern_types = list(set([d.pattern_name for d in detections]))
                finding_name = f"{', '.join(pattern_types[:2])} in '{table}'"
            
            metadata = {
                "instance_id": instance_id,
                "db_engine": f"{db_engine} {db_version}",
                "database": database,
                "table_name": table,
                "row_count": str(row_count),
                "column_count": str(len(columns)),
                "columns": ",".join(columns[:5]),
            }
            
            expo, expo_factors = compute_exposure_factor("rds", metadata)
            risk, risk_level = compute_risk(sens, expo)
            
            logger.info(f"Found {len(detections)} detection(s) in table {table}")
            
            yield Finding(
                id=f"rds:{instance_id}/{database}/{table}",
                resource=f"{instance_id} ({db_engine})",
                location=f"{database}.{table}",
                classifications=classifications,
                evidence=[Evidence(snippet=sample[:200])],
                severity=sev,
                data_source="rds",
                profile=finding_name,
                bucket_name=database,
                file_path=table,
                severity_description=desc,
                detections=detections,
                risk_score=risk,
                risk_level=risk_level,
                risk_factors=sens_factors + expo_factors,
                metadata=metadata,
            )
        
        cur.close()
        conn.close()
        logger.info(f"MySQL RDS scan complete. Scanned {scanned_tables} tables")


