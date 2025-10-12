from __future__ import annotations

from typing import Iterable

from ghostlight.classify.engine import classify_text_detailed, score_severity
from ghostlight.core.models import Evidence, Finding, ScanConfig, Detection
from ghostlight.utils.snippets import earliest_line_and_snippet
from ghostlight.risk.scoring import compute_sensitivity_score, compute_exposure_factor, compute_risk
from ghostlight.classify.filters import apply_context_filters
from .base import Scanner


class TextScanner(Scanner):
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        # target is raw text
        text = target[: config.sample_bytes]
        detailed = classify_text_detailed(text, use_custom_recognizers=config.use_custom_recognizers)
        filtered = apply_context_filters(detailed, text, use_custom_recognizers=config.use_custom_recognizers)
        if not filtered:
            return []
        detections = [
            Detection(bucket=b, pattern_name=name, matches=matches, sample_text=text[:200])
            for (b, name, matches) in filtered
        ]
        earliest_line, snippet_line = earliest_line_and_snippet(text, filtered)
        sev, desc = score_severity(len(detections), sum(len(d.matches) for d in detections))
        sens, sens_factors = compute_sensitivity_score(detections)
        expo, expo_factors = compute_exposure_factor("text", {})
        risk, risk_level = compute_risk(sens, expo)
        yield Finding(
            id="text:input",
            resource="text",
            location=f"stdin:{earliest_line or 1}",
            classifications=[f"{b}:{n}" for (b, n, _m) in filtered],
            evidence=[Evidence(snippet=snippet_line)],
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


