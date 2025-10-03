from __future__ import annotations

from typing import Iterable

try:
    import boto3  # type: ignore
except Exception:  # pragma: no cover
    boto3 = None
try:
    from botocore.exceptions import ClientError, NoCredentialsError  # type: ignore
except Exception:  # pragma: no cover
    ClientError = Exception  # type: ignore
    NoCredentialsError = Exception  # type: ignore

from ghostlight.classify.engine import classify_text, classify_text_detailed, score_severity
from ghostlight.classify.filters import apply_context_filters
from ghostlight.risk.scoring import compute_sensitivity_score, compute_exposure_factor, compute_risk
from ghostlight.core.models import Evidence, Finding, ScanConfig, Detection
from ghostlight.utils.logging import get_logger
from ghostlight.utils.retry import retry_on_exception
from .s3_config import check_bucket_public_access
from .base import Scanner

logger = get_logger(__name__)


class S3Scanner(Scanner):
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        if boto3 is None:
            logger.error("boto3 not available")
            return []
        # target can be bucket or bucket/prefix
        if "/" in target:
            bucket, prefix = target.split("/", 1)
        else:
            bucket, prefix = target, ""
        
        # Check bucket configuration
        bucket_config = check_bucket_public_access(bucket)
        logger.info(f"Bucket config: public={bucket_config.get('bucket_public')}, encryption={bucket_config.get('bucket_encryption')}")
        
        s3 = boto3.client("s3")
        paginator = s3.get_paginator("list_objects_v2")
        scanned_count = 0
        try:
            for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    try:
                        head = s3.head_object(Bucket=bucket, Key=key)
                        size = head.get("ContentLength", 0)
                        if size > config.max_file_mb * 1024 * 1024:
                            continue
                        rng = f"bytes=0-{config.sample_bytes-1}"
                        body = s3.get_object(Bucket=bucket, Key=key, Range=rng)["Body"].read()
                        text = body.decode("utf-8", errors="ignore")
                    except Exception:
                        continue
                    labels = classify_text(text)
                    detailed = classify_text_detailed(text)
                    filtered = apply_context_filters(detailed, text)
                    classifications = [f"{b}:{n}" for (b, n, _m) in filtered]
                    detections = [
                        Detection(bucket=b, pattern_name=name, matches=matches, sample_text=text[:200])
                        for (b, name, matches) in filtered
                    ]
                    if not classifications:
                        continue
                    # Build metadata for the finding
                    content_type = head.get("ContentType")
                    etag = head.get("ETag")
                    storage_class = obj.get("StorageClass") or head.get("StorageClass")
                    last_modified = obj.get("LastModified")
                    if hasattr(last_modified, "isoformat"):
                        last_modified = last_modified.isoformat()
                    sse = head.get("ServerSideEncryption")
                    kms_key = head.get("SSEKMSKeyId")
                    user_meta = head.get("Metadata") or {}
                    meta = {
                        "size_bytes": str(size),
                        "etag": str(etag) if etag is not None else "",
                        "content_type": str(content_type) if content_type is not None else "",
                        "storage_class": str(storage_class) if storage_class is not None else "",
                        "last_modified": str(last_modified) if last_modified is not None else "",
                        "sse": str(sse) if sse is not None else "",
                        "kms_key_id": str(kms_key) if kms_key is not None else "",
                    }
                    # Add bucket-level config
                    meta.update(bucket_config)
                    for k, v in user_meta.items():
                        meta[f"user_meta_{k}"] = str(v)
                    
                    scanned_count += 1

                    sev, desc = score_severity(len(detections), sum(len(d.matches) for d in detections))
                    sens, sens_factors = compute_sensitivity_score(detections)
                    expo, expo_factors = compute_exposure_factor("s3", meta)
                    risk, risk_level = compute_risk(sens, expo)
                    
                    logger.info(f"Found {len(detections)} detection(s) in s3://{bucket}/{key}")
                    
                    yield Finding(
                        id=f"s3:{bucket}/{key}",
                        resource=bucket,
                        location=f"s3://{bucket}/{key}",
                        classifications=classifications,
                        evidence=[Evidence(snippet=text[:200])],
                        severity=sev,
                        metadata=meta,
                        data_source="s3",
                        profile=bucket,
                        bucket_name=bucket,
                        file_path=key,
                        severity_description=desc,
                        detections=detections,
                        risk_score=risk,
                        risk_level=risk_level,
                        risk_factors=sens_factors + expo_factors,
                    )
        except (ClientError, NoCredentialsError) as e:  # AccessDenied or missing creds
            logger.error(f"S3 scan error for {bucket}: {e}")
            yield Finding(
                id=f"s3:{bucket}/{prefix}:error",
                resource=bucket,
                location=f"s3://{bucket}/{prefix}",
                classifications=[],
                evidence=[Evidence(snippet=str(e))],
                severity="error",
                metadata={"error": str(e)},
            )
        except Exception as e:
            logger.error(f"Unexpected error scanning S3 {bucket}: {e}")
            return []
        
        logger.info(f"S3 scan complete. Scanned {scanned_count} objects in {bucket}/{prefix}")


