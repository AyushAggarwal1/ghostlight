import os
import re
from pathlib import Path
from urllib.parse import urlparse


def validate_path(path: str) -> bool:
    """Check if path exists and is accessible"""
    try:
        p = Path(path)
        return p.exists() and os.access(p, os.R_OK)
    except Exception:
        return False


def validate_url(url: str) -> bool:
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def sanitize_bucket_name(name: str) -> str:
    """Sanitize bucket/container name"""
    # Remove invalid chars and limit length
    sanitized = re.sub(r"[^a-z0-9-]", "-", name.lower())
    return sanitized[:63]


def is_binary_file(path: str, sample_size: int = 8192) -> bool:
    """Detect if file is binary"""
    try:
        with open(path, "rb") as f:
            chunk = f.read(sample_size)
        # Check for null bytes
        if b"\x00" in chunk:
            return True
        # Check text ratio
        text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
        non_text = sum(1 for byte in chunk if byte not in text_chars)
        return non_text / len(chunk) > 0.3 if chunk else False
    except Exception:
        return True

