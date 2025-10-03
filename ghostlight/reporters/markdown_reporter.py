from typing import List

from ghostlight.core.models import Finding


def to_markdown(findings: List[Finding]) -> str:
    lines = [
        "# Ghostlight Findings",
        "",
        "| ID | Source | Profile | Path | Severity | Risk | Classes | Detections |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for f in findings:
        classes = ", ".join(f.classifications)
        dets = "; ".join(f"{d.bucket}:{d.pattern_name} x{len(d.matches)}" for d in f.detections)
        risk = f"{f.risk_level or ''} ({f.risk_score if f.risk_score is not None else ''})"
        lines.append(f"| {f.id} | {f.data_source or ''} | {f.profile or ''} | {f.file_path or f.location} | {f.severity} | {risk} | {classes} | {dets} |")
    if len(findings) == 0:
        lines.append("| (none) | - | - | - | - | - | - | - |")
    return "\n".join(lines)


