from __future__ import annotations

from typing import Iterable

try:
    from google.cloud import storage  # type: ignore
except Exception:  # pragma: no cover
    storage = None

from dspm.classify.engine import classify_text_detailed, score_severity
from dspm.classify.filters import apply_context_filters
from dspm.core.models import Evidence, Finding, ScanConfig, Detection
from dspm.risk.scoring import compute_sensitivity_score, compute_exposure_factor, compute_risk
from dspm.utils.logging import get_logger
from .base import Scanner

logger = get_logger(__name__)


class GCSScanner(Scanner):
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        # target: bucket or bucket/prefix
        if storage is None:
            logger.error("google-cloud-storage not available")
            return []

        if "/" in target:
            bucket_name, prefix = target.split("/", 1)
        else:
            bucket_name, prefix = target, ""

        client = storage.Client()
        bucket = client.bucket(bucket_name)
        scanned = 0

        for blob in client.list_blobs(bucket_name, prefix=prefix):
            if blob.size and blob.size > config.max_file_mb * 1024 * 1024:
                continue
            try:
                data = blob.download_as_bytes(start=0, end=config.sample_bytes - 1)
                text = data.decode("utf-8", errors="ignore")
            except Exception:
                continue

            detailed = classify_text_detailed(text)
            filtered = apply_context_filters(detailed, text)
            if not filtered:
                continue

            detections = [
                Detection(bucket=b, pattern_name=name, matches=matches, sample_text=text[:200])
                for (b, name, matches) in filtered
            ]
            sev, desc = score_severity(len(detections), sum(len(d.matches) for d in detections))
            sens, sens_factors = compute_sensitivity_score(detections)
            expo, expo_factors = compute_exposure_factor("gcs", {})
            risk, risk_level = compute_risk(sens, expo)

            scanned += 1
            yield Finding(
                id=f"gcs:{bucket_name}/{blob.name}",
                resource=bucket_name,
                location=f"gs://{bucket_name}/{blob.name}",
                classifications=[f"{b}:{n}" for (b, n, _m) in filtered],
                evidence=[Evidence(snippet=text[:200])],
                severity=sev,
                data_source="gcs",
                profile=bucket_name,
                bucket_name=bucket_name,
                file_path=blob.name,
                severity_description=desc,
                detections=detections,
                risk_score=risk,
                risk_level=risk_level,
                risk_factors=sens_factors + expo_factors,
            )

        logger.info(f"GCS scan complete. Scanned {scanned} objects in {bucket_name}/{prefix}")


