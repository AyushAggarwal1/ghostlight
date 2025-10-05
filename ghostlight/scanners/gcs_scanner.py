from __future__ import annotations

from typing import Iterable

try:
    from google.cloud import storage  # type: ignore
except Exception:  # pragma: no cover
    storage = None

from ghostlight.classify.engine import classify_text_detailed, score_severity
from ghostlight.classify.filters import apply_context_filters
from ghostlight.classify.ai_filter import ai_classify_detection
from ghostlight.core.models import Evidence, Finding, ScanConfig, Detection
from ghostlight.utils.snippets import earliest_line_and_snippet
from ghostlight.risk.scoring import compute_sensitivity_score, compute_exposure_factor, compute_risk
from ghostlight.utils.logging import get_logger
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
            filtered = apply_context_filters(detailed, text, min_entropy=config.min_entropy)
            # Optionally apply AI verification
            import os as _os
            ai_mode = _os.getenv("GHOSTLIGHT_AI_FILTER", "auto")
            if ai_mode != "off" and detailed:
                try:
                    logger.info(
                        f"AI filter enabled (mode={ai_mode}) for gcs object {bucket_name}/{blob.name} with {len(filtered)} detections pre-AI"
                    )
                except Exception:
                    logger.debug("AI filter start log failed (gcs)")
                ai_verified = []
                for bucket, pattern_name, matches in filtered:
                    matched_value = str(matches[0]) if matches else ""
                    is_tp, _reason = ai_classify_detection(
                        pattern_name=pattern_name,
                        matched_value=matched_value,
                        sample_text=text,
                        table_name=f"{bucket_name}/{blob.name}",
                        db_engine="gcs",
                        column_names=None,
                        use_ai=ai_mode
                    )
                    if is_tp:
                        ai_verified.append((bucket, pattern_name, matches))
                filtered = ai_verified
            if not filtered:
                continue

            detections = [
                Detection(bucket=b, pattern_name=name, matches=matches, sample_text=text[:200])
                for (b, name, matches) in filtered
            ]
            # Strict mode guard
            if config.strict and not (len(detections) >= 2 or sum(len(d.matches) for d in detections) >= 2):
                continue
            sev, desc = score_severity(len(detections), sum(len(d.matches) for d in detections))
            sens, sens_factors = compute_sensitivity_score(detections)
            expo, expo_factors = compute_exposure_factor("gcs", {})
            risk, risk_level = compute_risk(sens, expo)

            scanned += 1
            earliest_line, snippet_line = earliest_line_and_snippet(text, filtered)

            yield Finding(
                id=f"gcs:{bucket_name}/{blob.name}",
                resource=bucket_name,
                location=f"gs://{bucket_name}/{blob.name}:{earliest_line or 1}",
                classifications=[f"{b}:{n}" for (b, n, _m) in filtered],
                evidence=[Evidence(snippet=snippet_line)],
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


