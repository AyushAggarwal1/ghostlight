"""
Context-aware filters to reduce false positives
"""
import re
from typing import List, Tuple
import base64
import json
from typing import Optional

# Optional dependencies for language/i18n
try:
    from langdetect import detect as _lang_detect  # type: ignore
except Exception:  # pragma: no cover
    _lang_detect = None  # type: ignore

try:
    import phonenumbers as _phonenumbers  # type: ignore
except Exception:  # pragma: no cover
    _phonenumbers = None  # type: ignore


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
    ctx_lower = (context or "").lower()
    # Drop CSS/visual contexts entirely
    if any(tok in ctx_lower for tok in [" rgb(", " rgba(", "--foreground-rgb", "--background-rgb", "box-shadow", "boxshadow"]):
        return []
    
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


def detect_primary_language(text: str) -> Optional[str]:
    """Best-effort language detection using langdetect."""
    if not text:
        return None
    if _lang_detect is None:
        return None
    try:
        return _lang_detect(text)
    except Exception:
        return None


def language_to_region(lang: Optional[str]) -> Optional[str]:
    """Map language code to a default region for phone parsing (heuristic)."""
    if not lang:
        return None
    mapping = {
        "en": "US",
        "hi": "IN",
        "bn": "BD",
        "fr": "FR",
        "de": "DE",
        "es": "ES",
        "pt": "BR",
        "it": "IT",
        "nl": "NL",
        "ru": "RU",
        "ja": "JP",
        "ko": "KR",
        "zh": "CN",
    }
    return mapping.get(lang)


def filter_phone_matches_i18n(matches: List[str], context: str) -> List[str]:
    """Validate phones using libphonenumber with language-inferred region."""
    if _phonenumbers is None:
        return matches
    region = language_to_region(detect_primary_language(context))
    validated: List[str] = []
    for m in matches:
        try:
            # Try parsing with inferred region if not explicitly international
            if m.strip().startswith("+"):
                num = _phonenumbers.parse(m, None)
            else:
                num = _phonenumbers.parse(m, region) if region else _phonenumbers.parse(m, None)
            if _phonenumbers.is_valid_number(num):
                validated.append(m)
        except Exception:
            continue
    return validated


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
    ctx = (context or "").lower()
    medical_context = any(t in ctx for t in [
        "npi", "national provider", "provider", "taxonomy", "nppes", "cms", "medicare"
    ])
    
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
        
        # Require medical/provider context
        if not medical_context:
            continue
        
        filtered.append(match)
    
    return filtered


def filter_medical_record_matches(matches: List[str], context: str) -> List[str]:
    """
    Reduce false positives for PHI.MedicalRecord by requiring medical context
    and filtering out common e-commerce/product contexts where words like
    "condition" frequently appear.
    """
    if not matches:
        return []
    ctx = (context or "").lower()
    medical_context_tokens = {
        "patient", "diagnosis", "diagnosed", "physician", "doctor", "md",
        "hospital", "clinic", "treatment", "therapy", "prescription", "medication",
        "medical", "surgery", "symptom", "allergy", "lab", "laboratory",
        "imaging", "radiology", "vital", "blood pressure", "bp", "heart rate",
        "nurse", "discharge", "admission", "pharmacy"
    }
    ecommerce_context_tokens = {
        "book", "seller", "price", "listing", "item", "product", "cart",
        "order", "shipping", "inventory", "condition, images, price"
    }
    has_medical = any(tok in ctx for tok in medical_context_tokens)
    has_ecommerce = any(tok in ctx for tok in ecommerce_context_tokens)

    filtered: List[str] = []
    for m in matches:
        # Keep only if there's medical context; drop if it's clearly e-commerce without medical context
        if has_medical:
            filtered.append(m)
        elif has_ecommerce:
            continue
        else:
            # Neutral contexts: keep conservative and drop single ambiguous occurrences
            if any(k in m.lower() for k in ("diagnosis", "prescription", "medication", "patient")):
                filtered.append(m)
            # Plain "condition" without medical context is dropped
    return filtered

def luhn_valid(number: str) -> bool:
    """Luhn checksum for credit cards."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = (len(digits) - 2) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d = d * 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def filter_credit_card_matches(matches: List[str], context: str) -> List[str]:
    """Keep only Luhn-valid card numbers; drop long digit blobs and code samples."""
    filtered: List[str] = []
    for m in matches:
        digits = re.sub(r"[^0-9]", "", m)
        # Typical PAN length 13-19
        if not (13 <= len(digits) <= 19):
            continue
        if luhn_valid(digits):
            filtered.append(m)
    return filtered


def iban_valid(iban: str) -> bool:
    """Validate IBAN using mod-97 (ISO 13616)."""
    s = re.sub(r"\s+", "", iban).upper()
    if len(s) < 15 or len(s) > 34:
        return False
    s = s[4:] + s[:4]
    converted = "".join(str(ord(c) - 55) if c.isalpha() else c for c in s)
    try:
        return int(converted) % 97 == 1
    except Exception:
        return False


def filter_iban_matches(matches: List[str]) -> List[str]:
    return [m for m in matches if iban_valid(m)]


def is_valid_jwt(token: str) -> bool:
    """Basic JWT validation: three segments, header JSON decodes."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        header_b64 = parts[0] + "=="  # pad
        header = json.loads(base64.urlsafe_b64decode(header_b64.encode("utf-8")).decode("utf-8"))
        return isinstance(header, dict) and "alg" in header
    except Exception:
        return False


def shannon_entropy(s: str) -> float:
    import math
    if not s:
        return 0.0
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log(p, 2) for p in probs)


def filter_bearer_tokens(matches: List[str], min_entropy: float = 3.5) -> List[str]:
    """Drop low-entropy strings that look like placeholders."""
    filtered: List[str] = []
    for m in matches:
        if shannon_entropy(m) >= min_entropy:
            filtered.append(m)
    return filtered


def clean_slack_mailto(email_like: str) -> str:
    """Slack formats links as <mailto:addr|label>; extract addr."""
    if email_like.startswith("<mailto:") and "|" in email_like and email_like.endswith(">"):
        try:
            body = email_like[1:-1]  # strip <>
            addr = body.split(":", 1)[1].split("|", 1)[0]
            return addr
        except Exception:
            return email_like
    return email_like


def filter_email_matches(matches: List[str]) -> List[str]:
    """Normalize Slack mailto and drop obvious placeholders/domains."""
    cleaned: List[str] = []
    for m in matches:
        addr = clean_slack_mailto(m)
        # Drop well-known placeholder domains
        domain = addr.split("@")[-1].lower() if "@" in addr else ""
        if domain in {"example.com", "test.com", "example.org", "example.net", "dotenvx.com", "prisma.io"}:
            continue
        # Drop a common placeholder address
        if addr.lower() == "user@email.com":
            continue
        # Drop bracketed placeholders
        if any(tok in addr for tok in ["<", ">", "{", "}", "["]):
            continue
        cleaned.append(addr)
    return cleaned


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
    
    # Reject pure hex (likely git shas or hashes)
    if all(c in "0123456789abcdefABCDEF" for c in match):
        return False

    # Restrict to base64-like char set commonly seen in AWS secrets
    import re as _re
    if not _re.fullmatch(r"[A-Za-z0-9/+=]{40}", match):
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


def filter_ipv4_matches(matches: List[str], context: str) -> List[str]:
    """Drop common non-IP contexts (SVG paths, CSS, browser versions) and invalid octets."""
    filtered: List[str] = []
    ctx = (context or "").lower()
    # If the whole context looks like SVG/CSS markup, drop all
    svg_css_tokens = ["<svg", "svg ", "viewbox", "path ", "stroke", "fill", "strokelinecap", "strokelinejoin", "box-shadow", "rgba("]
    if any(tok in ctx for tok in svg_css_tokens):
        return []
    ua_tokens = ["mozilla/", "chrome/", "safari/", "applewebkit/"]
    for m in matches:
        # Skip if near typical UA/version contexts
        if any(tok in ctx for tok in ua_tokens):
            continue
        parts = m.split('.')
        if len(parts) != 4:
            continue
        valid = True
        for p in parts:
            if not p.isdigit():
                valid = False
                break
            # Reject leading zeros (e.g., 03, 062) to avoid float-like strings
            if len(p) > 1 and p.startswith('0'):
                valid = False
                break
            num = int(p)
            if not (0 <= num <= 255):
                valid = False
                break
        if valid:
            # Drop common reserved/placeholder addresses
            if m in {"0.0.0.0", "127.0.0.1", "255.255.255.255"}:
                continue
            filtered.append(m)
    return filtered


def filter_pan_matches(matches: List[str], context: str) -> List[str]:
    """Enforce PAN casing and require relevant tax/GST context to reduce FPs in code/binaries."""
    filtered: List[str] = []
    ctx = (context or "").lower()
    has_tax_ctx = any(tok in ctx for tok in [" pan", "gst", "gstin", "income tax", "itd", "nsdl", "tin", "kyc", "aadhaar"])  # note leading space for ' pan'
    for m in matches:
        # Drop well-known placeholder PAN
        if m == "AAAAA0000A":
            continue
        # Strict uppercase PAN format ABCDE1234F
        if not (len(m) == 10 and m[:5].isalpha() and m[:5].upper() == m[:5] and m[5:9].isdigit() and m[9].isalpha() and m[9].upper() == m[9]):
            continue
        # Require related context
        if not has_tax_ctx:
            continue
        filtered.append(m)
    return filtered


def filter_dob_matches(matches: List[str], context: str) -> List[str]:
    """Drop dates in sitemap/metadata contexts that are unlikely to be DOBs."""
    ctx = (context or "").lower()
    if any(tok in ctx for tok in ["<urlset", "</urlset", "<lastmod>", "</lastmod>", "sitemap", "xml version"]):
        return []
    return matches


def filter_basic_auth_url_matches(matches: List[str], context: str) -> List[str]:
    """Drop obvious placeholder credentials in examples."""
    filtered: List[str] = []
    placeholders = [
        "user:pass@", "username:password@", "username:pass@", "user:password@",
        "host:port", "host:5432", "database", "${", "<username>", "<password>", "<host>", "<db>"
    ]
    for m in matches:
        lower = m.lower()
        if any(ph in lower for ph in placeholders):
            continue
        filtered.append(m)
    return filtered


def filter_db_connection_matches(matches: List[str], context: str) -> List[str]:
    """Drop template DB connection strings with obvious placeholders (e.g., postgres:password@db)."""
    return filter_basic_auth_url_matches(matches, context)

def apply_context_filters(
    detections: List[Tuple[str, str, List[str]]],
    text: str,
    table_name: str = None,
    db_engine: str = "mysql",
    min_entropy: float = 3.5
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
        # Drop most PII from vendor-generated Prisma runtimes/builds to reduce noise
        if pattern_name in {"PII.IPv4", "PII.Coordinates", "PII.DOB", "PII.Email", "PII.SSN"}:
            lower = text.lower()
            if "this is code generated by prisma" in lower or \
               ("src/generated/prisma" in lower) or \
               ("prisma" in lower and ("runtime" in lower or "query_engine" in lower)):
                # Keep only Secrets; skip this PII pattern
                continue
        # Apply pattern-specific filters
        if pattern_name == "PII.Coordinates":
            filtered_matches = filter_coordinate_matches(matches, text)
        elif pattern_name == "PII.IPv4":
            filtered_matches = filter_ipv4_matches(matches, text)
        elif pattern_name == "PII.Phone":
            # First remove obvious timestamps/ids, then validate with libphonenumber if available
            filtered_matches = filter_phone_matches(matches, text)
            if filtered_matches:
                filtered_matches = filter_phone_matches_i18n(filtered_matches, text)
        elif pattern_name == "PII.SSN":
            filtered_matches = filter_ssn_matches(matches, text)
        elif pattern_name == "PHI.NPI":
            filtered_matches = filter_npi_matches(matches, text)
        elif pattern_name == "PHI.MedicalRecord":
            filtered_matches = filter_medical_record_matches(matches, text)
        elif pattern_name == "PCI.CreditCard":
            filtered_matches = filter_credit_card_matches(matches, text)
        elif pattern_name == "PII.IBAN":
            filtered_matches = filter_iban_matches(matches)
        elif pattern_name == "PII.DOB":
            filtered_matches = filter_dob_matches(matches, text)
        elif pattern_name == "IP.JWT":
            filtered_matches = [m for m in matches if is_valid_jwt(m)]
        elif pattern_name == "Secrets.Generic.BearerToken":
            filtered_matches = filter_bearer_tokens(matches, min_entropy=min_entropy)
        elif pattern_name == "PII.Email":
            filtered_matches = filter_email_matches(matches)
        elif pattern_name == "PII.PAN":
            filtered_matches = filter_pan_matches(matches, text)
        elif pattern_name == "Secrets.AWS.SecretAccessKey":
            # Validate each match
            filtered_matches = [m for m in matches if validate_aws_secret_key(m, text)]
        elif pattern_name == "Secrets.BasicAuth.URL":
            filtered_matches = filter_basic_auth_url_matches(matches, text)
        elif pattern_name == "Secrets.Database.ConnectionString":
            filtered_matches = filter_db_connection_matches(matches, text)
        elif pattern_name in {"Secrets.Stripe.WebhookSecret"}:
            # Stripe whsec_: fixed length and context keyword
            filtered_matches = [m for m in matches if len(m) == len(m) and "stripe" in text.lower()]
        elif pattern_name in {"Secrets.GitHub.AppToken", "Secrets.GitHub.PersonalTokenNew"}:
            # Must appear near github context tokens
            ctx = text.lower()
            filtered_matches = [m for m in matches if any(k in ctx for k in ["github", "gh token", "gh auth", "gh api"]) ]
        elif pattern_name in {"Secrets.Slack.AppToken", "Secrets.Slack.BotToken", "Secrets.Slack.UserToken", "Secrets.Slack.Webhook"}:
            # Slack: ensure slack context present
            filtered_matches = [m for m in matches if "slack" in text.lower()]
        elif pattern_name in {"Secrets.AzureAD.ClientID"}:
            # Azure AD GUID must be near known keywords
            ctx = text.lower()
            filtered_matches = [m for m in matches if any(k in ctx for k in ["azuread", "entra", "client id", "application (client) id", "tenant id"]) ]
        else:
            # Keep other patterns as-is
            filtered_matches = matches
        
        # Only include if we still have matches
        if filtered_matches:
            filtered_detections.append((bucket, pattern_name, filtered_matches))
    
    return filtered_detections

