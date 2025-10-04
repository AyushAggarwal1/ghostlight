from __future__ import annotations

from typing import Iterable

try:
    from azure.storage.blob import BlobServiceClient  # type: ignore
except Exception:  # pragma: no cover
    BlobServiceClient = None

from ghostlight.classify.engine import classify_text_detailed, score_severity
from ghostlight.classify.filters import apply_context_filters
from ghostlight.core.models import Evidence, Finding, ScanConfig, Detection
from ghostlight.risk.scoring import compute_sensitivity_score, compute_exposure_factor, compute_risk
from ghostlight.utils.snippets import earliest_line_and_snippet
from .base import Scanner


class AzureBlobScanner(Scanner):
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        # target: connection_string:container[/prefix]
        if BlobServiceClient is None:
            return []
        try:
            connection_string, rest = target.split("|", 1)
            if "/" in rest:
                container, prefix = rest.split("/", 1)
            else:
                container, prefix = rest, ""
        except ValueError:
            return []

        client = BlobServiceClient.from_connection_string(connection_string)
        container_client = client.get_container_client(container)
        scanned = 0
        for blob in container_client.list_blobs(name_starts_with=prefix):
            if blob.size and blob.size > config.max_file_mb * 1024 * 1024:
                continue
            try:
                stream = container_client.download_blob(blob.name, offset=0, length=config.sample_bytes)
                data = stream.readall()
                text = data.decode("utf-8", errors="ignore")
            except Exception:
                continue
            detailed = classify_text_detailed(text)
            filtered = apply_context_filters(detailed, text, min_entropy=config.min_entropy)
            if not filtered:
                continue
            earliest_line, snippet_line = earliest_line_and_snippet(text, filtered)

            detections = [
                Detection(bucket=b, pattern_name=name, matches=matches, sample_text=text[:200])
                for (b, name, matches) in filtered
            ]
            # Strict mode guard
            if config.strict and not (len(detections) >= 2 or sum(len(d.matches) for d in detections) >= 2):
                continue

            sev, desc = score_severity(len(detections), sum(len(d.matches) for d in detections))
            sens, sens_factors = compute_sensitivity_score(detections)
            expo, expo_factors = compute_exposure_factor("azure", {})
            risk, risk_level = compute_risk(sens, expo)

            scanned += 1
            yield Finding(
                id=f"azure:{container}/{blob.name}",
                resource=container,
                location=f"azure://{container}/{blob.name}:{earliest_line or 1}",
                classifications=[f"{b}:{n}" for (b, n, _m) in filtered],
                evidence=[Evidence(snippet=snippet_line)],
                severity=sev,
                data_source="azure",
                profile=container,
                bucket_name=container,
                file_path=blob.name,
                severity_description=desc,
                detections=detections,
                risk_score=risk,
                risk_level=risk_level,
                risk_factors=sens_factors + expo_factors,
            )


