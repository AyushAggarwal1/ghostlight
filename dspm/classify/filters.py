"""
Context-aware filters to reduce false positives
"""
import re
from typing import List, Tuple


# MySQL system tables that commonly contain metadata, not real PII
MYSQL_SYSTEM_TABLES = {
    # Core authentication and privilege tables
    'user', 'db', 'func', 'plugin', 'servers',
    'proxies_priv', 'procs_priv', 'tables_priv', 'columns_priv',
    'role_edges', 'password_history', 'global_grants', 'default_roles',
    # Time zone tables
    'time_zone', 'time_zone_name', 'time_zone_transition', 'time_zone_transition_type',
    'time_zone_leap_second',
    # InnoDB statistics
    'innodb_index_stats', 'innodb_table_stats',
    # Help system
    'help_topic', 'help_category', 'help_keyword', 'help_relation',
    # RDS-specific tables
    'rds_configuration', 'rds_heartbeat2', 'rds_history', 'rds_replication_status',
    'rds_global_status_history', 'rds_global_status_history_old', 'rds_sysinfo',
    'rds_reserved_users',
    # Cost and performance tables
    'server_cost', 'engine_cost',
    # Replication tables
    'slave_master_info', 'slave_relay_log_info', 'slave_worker_info',
    'replication_asynchronous_connection_failover',
    'replication_asynchronous_connection_failover_managed',
    'replication_group_configuration_version', 'replication_group_member_actions',
    # Logging tables
    'general_log', 'slow_log',
    # GTID tables
    'gtid_executed', 'component',
}

# PostgreSQL system tables
POSTGRES_SYSTEM_TABLES = {
    'pg_class', 'pg_attribute', 'pg_proc', 'pg_type', 'pg_database',
    'pg_namespace', 'pg_tablespace', 'pg_authid', 'pg_stat_activity',
}


def is_system_table(table_name: str, engine: str = "mysql") -> bool:
    """Check if a table is a system/metadata table"""
    table_lower = table_name.lower()
    
    if engine.lower() in ["mysql", "mariadb"]:
        return table_lower in MYSQL_SYSTEM_TABLES
    elif engine.lower() in ["postgres", "postgresql"]:
        return table_lower in POSTGRES_SYSTEM_TABLES or table_lower.startswith('pg_')
    
    return False


def is_datetime_pattern(text: str) -> bool:
    """
    Check if text contains datetime patterns that might be misidentified
    
    Examples that should return True:
    - "datetime.datetime(2025, 9, 18, 8, 48, 10)"
    - "(2025, 9, 18)"
    - "2025-09-18 08:48:10"
    """
    # Python datetime objects
    if 'datetime.datetime(' in text or 'datetime(' in text:
        return True
    
    # ISO date formats
    if re.search(r'\d{4}-\d{2}-\d{2}', text):
        return True
    
    # Tuples that look like dates
    if re.search(r'\(\d{4},\s*\d{1,2},\s*\d{1,2}', text):
        return True
    
    return False


def is_unix_timestamp(value: str) -> bool:
    """
    Check if a value is likely a Unix timestamp
    
    Unix timestamps are typically 10 digits (seconds) or 13 digits (milliseconds)
    Range: 1000000000 (2001) to 2147483647 (2038) for 10-digit
    """
    if not value.isdigit():
        return False
    
    num = int(value)
    
    # 10-digit Unix timestamp (seconds since epoch)
    if 1000000000 <= num <= 2147483647:
        return True
    
    # 13-digit Unix timestamp (milliseconds since epoch)  
    if 1000000000000 <= num <= 9999999999999:
        return True
    
    return False


def filter_coordinate_matches(matches: List[str], context: str) -> List[str]:
    """
    Filter out coordinate matches that are likely datetime tuples
    
    Real coordinates: "37.7749, -122.4194"
    False positives: "(2025, 9)" from datetime, "(25, 9)" from tuple
    """
    filtered = []
    
    for match in matches:
        # Skip if it's part of a datetime string
        if is_datetime_pattern(context):
            continue
        
        # Parse the coordinate
        parts = match.replace(' ', '').split(',')
        if len(parts) != 2:
            continue
        
        try:
            lat = float(parts[0])
            lon = float(parts[1])
            
            # Real coordinates should have reasonable ranges
            # Skip obvious date/time components
            if abs(lat) > 90 or abs(lon) > 180:
                continue
            
            # Skip if both values are small integers (likely tuple indices)
            if abs(lat) < 100 and abs(lon) < 100 and lat == int(lat) and lon == int(lon):
                # But allow if they have decimal points (real coords)
                if '.' not in parts[0] and '.' not in parts[1]:
                    continue
            
            filtered.append(match)
        except (ValueError, IndexError):
            continue
    
    return filtered


def filter_phone_matches(matches: List[str], context: str) -> List[str]:
    """
    Filter out phone number matches that are likely timestamps or IDs
    """
    filtered = []
    
    for match in matches:
        # Remove common phone formatting
        digits = re.sub(r'[^\d]', '', match)
        
        # Skip if it's a Unix timestamp
        if is_unix_timestamp(digits):
            continue
        
        # Skip if it's part of a datetime
        if is_datetime_pattern(context):
            continue
        
        # Real phone numbers usually have formatting or country codes
        # If it's just a bare 10+ digit number, it's suspicious
        if len(digits) >= 10 and match == digits:
            # Check if it looks like an ID (no formatting)
            continue
        
        filtered.append(match)
    
    return filtered


def filter_ssn_matches(matches: List[str], context: str) -> List[str]:
    """
    Filter out SSN matches that are likely timestamps or system values
    """
    filtered = []
    
    for match in matches:
        digits = re.sub(r'[^\d]', '', match)
        
        # Skip Unix timestamps
        if is_unix_timestamp(digits):
            continue
        
        # Skip datetime contexts
        if is_datetime_pattern(context):
            continue
        
        # SSNs should be exactly 9 digits
        if len(digits) != 9:
            continue
        
        filtered.append(match)
    
    return filtered


def filter_npi_matches(matches: List[str], context: str) -> List[str]:
    """
    Filter out NPI matches that are timestamps
    
    NPI (National Provider Identifier) is always exactly 10 digits
    But many Unix timestamps are also 10 digits
    """
    filtered = []
    
    for match in matches:
        # Skip if it's a Unix timestamp
        if is_unix_timestamp(match):
            continue
        
        # Skip datetime contexts
        if is_datetime_pattern(context):
            continue
        
        # Real NPIs usually start with 1 or 2
        if match[0] not in ['1', '2']:
            continue
        
        filtered.append(match)
    
    return filtered


def validate_aws_secret_key(match: str, context: str) -> bool:
    """
    Validate if an AWS secret key match is likely real
    
    Real AWS secret keys:
    - Exactly 40 characters
    - Base64-like (A-Za-z0-9/+=)
    - Usually near AWS_SECRET or similar keywords
    """
    # Check length
    if len(match) != 40:
        return False
    
    # Check if it's in a relevant context
    context_lower = context.lower()
    aws_keywords = [
        'aws', 'secret', 'access', 'key', 'credential',
        'auth', 'token', 'password', 'authentication'
    ]
    
    # If any AWS-related keyword is nearby, it's more likely real
    has_aws_context = any(keyword in context_lower for keyword in aws_keywords)
    
    # If it's just a hash in a MySQL user table or password field, might be legit
    if 'password' in context_lower or 'authentication_string' in context_lower:
        return True
    
    return has_aws_context


def apply_context_filters(
    detections: List[Tuple[str, str, List[str]]],
    text: str,
    table_name: str = None,
    db_engine: str = "mysql"
) -> List[Tuple[str, str, List[str]]]:
    """
    Apply context-aware filters to reduce false positives
    
    Args:
        detections: List of (bucket, pattern_name, matches)
        text: The scanned text content
        table_name: Name of the database table (if applicable)
        db_engine: Database engine type
    
    Returns:
        Filtered list of detections
    """
    # Skip system tables entirely
    if table_name and is_system_table(table_name, db_engine):
        # Only keep SECRETS findings from system tables, filter out PII
        return [
            (bucket, name, matches)
            for bucket, name, matches in detections
            if bucket == "SECRETS" and not name.startswith("Secrets.AWS.SecretAccessKey")
        ]
    
    filtered_detections = []
    
    for bucket, pattern_name, matches in detections:
        # Apply pattern-specific filters
        if pattern_name == "PII.Coordinates":
            filtered_matches = filter_coordinate_matches(matches, text)
        elif pattern_name == "PII.Phone":
            filtered_matches = filter_phone_matches(matches, text)
        elif pattern_name == "PII.SSN":
            filtered_matches = filter_ssn_matches(matches, text)
        elif pattern_name == "PHI.NPI":
            filtered_matches = filter_npi_matches(matches, text)
        elif pattern_name == "Secrets.AWS.SecretAccessKey":
            # Validate each match
            filtered_matches = [m for m in matches if validate_aws_secret_key(m, text)]
        else:
            # Keep other patterns as-is
            filtered_matches = matches
        
        # Only include if we still have matches
        if filtered_matches:
            filtered_detections.append((bucket, pattern_name, filtered_matches))
    
    return filtered_detections

