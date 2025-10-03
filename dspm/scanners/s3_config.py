from __future__ import annotations

from typing import Dict

try:
    import boto3  # type: ignore
    from botocore.exceptions import ClientError  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None
    ClientError = Exception  # type: ignore

from dspm.utils.logging import get_logger
from dspm.utils.retry import retry_on_exception

logger = get_logger(__name__)


@retry_on_exception(max_retries=2, exceptions=(ClientError,))
def check_bucket_public_access(bucket: str) -> Dict[str, str]:
    """Check if S3 bucket has public access"""
    if boto3 is None:
        return {}
    
    s3 = boto3.client("s3")
    result = {
        "bucket_public": "false",
        "bucket_encryption": "",
        "bucket_versioning": "false",
        "bucket_logging": "false",
        "public_acl": "false",
    }
    
    try:
        # Check public access block
        pub_block = s3.get_public_access_block(Bucket=bucket)
        config = pub_block.get("PublicAccessBlockConfiguration", {})
        if not all([
            config.get("BlockPublicAcls"),
            config.get("BlockPublicPolicy"),
            config.get("IgnorePublicAcls"),
            config.get("RestrictPublicBuckets"),
        ]):
            result["bucket_public"] = "true"
    except ClientError:
        # No block configuration means potentially public
        result["bucket_public"] = "true"
    
    try:
        # Check bucket ACL
        acl = s3.get_bucket_acl(Bucket=bucket)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                result["public_acl"] = "true"
                result["bucket_public"] = "true"
    except ClientError as e:
        logger.warning(f"Failed to get bucket ACL for {bucket}: {e}")
    
    try:
        # Check encryption
        enc = s3.get_bucket_encryption(Bucket=bucket)
        rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if rules:
            algo = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")
            result["bucket_encryption"] = algo or ""
    except ClientError:
        pass
    
    try:
        # Check versioning
        ver = s3.get_bucket_versioning(Bucket=bucket)
        if ver.get("Status") == "Enabled":
            result["bucket_versioning"] = "true"
    except ClientError:
        pass
    
    try:
        # Check logging
        log = s3.get_bucket_logging(Bucket=bucket)
        if log.get("LoggingEnabled"):
            result["bucket_logging"] = "true"
    except ClientError:
        pass
    
    return result

