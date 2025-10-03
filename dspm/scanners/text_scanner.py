from __future__ import annotations

from typing import Iterable

from dspm.classify.engine import classify_text_detailed, score_severity
from dspm.core.models import Evidence, Finding, ScanConfig, Detection
from dspm.risk.scoring import compute_sensitivity_score, compute_exposure_factor, compute_risk
from dspm.classify.filters import apply_context_filters
from .base import Scanner


class TextScanner(Scanner):
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        # target is raw text
        text = target[: config.sample_bytes]
        detailed = classify_text_detailed(text)
        filtered = apply_context_filters(detailed, text)
        if not filtered:
            return []
        detections = [
            Detection(bucket=b, pattern_name=name, matches=matches, sample_text=text[:200])
            for (b, name, matches) in filtered
        ]
        sev, desc = score_severity(len(detections), sum(len(d.matches) for d in detections))
        sens, sens_factors = compute_sensitivity_score(detections)
        expo, expo_factors = compute_exposure_factor("text", {})
        risk, risk_level = compute_risk(sens, expo)
        yield Finding(
            id="text:input",
            resource="text",
            location="stdin",
            classifications=[f"{b}:{n}" for (b, n, _m) in filtered],
            evidence=[Evidence(snippet=text[:200])],
            severity=sev,
            data_source="text",
            profile="inline",
            file_path=None,
            severity_description=desc,
            detections=detections,
            risk_score=risk,
            risk_level=risk_level,
            risk_factors=sens_factors + expo_factors,
        )


