import json
from typing import List, Dict, Any

from ghostlight.core.models import Finding


def _compute_counts(f: Finding) -> Dict[str, Any]:
    num_detections = len(f.detections or [])
    num_matches = 0
    bucket_match_counts: Dict[str, int] = {}
    pattern_match_counts: Dict[str, int] = {}
    top_exact_matches: List[str] = []
    seen: set[str] = set()

    for d in f.detections or []:
        count = len(d.matches or [])
        num_matches += count
        bucket_match_counts[d.bucket] = bucket_match_counts.get(d.bucket, 0) + count
        pattern_match_counts[d.pattern_name] = pattern_match_counts.get(d.pattern_name, 0) + count
        for m in d.matches or []:
            if m not in seen and len(top_exact_matches) < 20:
                top_exact_matches.append(m)
                seen.add(m)

    return {
        "num_detections": num_detections,
        "num_matches": num_matches,
        "bucket_match_counts": bucket_match_counts,
        "pattern_match_counts": pattern_match_counts,
        "top_exact_matches": top_exact_matches,
    }


def serialize_finding(f: Finding) -> Dict[str, Any]:
    counts = _compute_counts(f)
    metadata = f.metadata or {}

    # Derive a human-friendly title if available
    title = (
        metadata.get("page_title")
        or metadata.get("table_name")
        or metadata.get("object_key")
        or (f.file_path or "")
    )

    # Prefer any known timestamp fields present in metadata
    last_updated = (
        metadata.get("last_updated")
        or metadata.get("updated_at")
        or metadata.get("modified")
    )

    data: Dict[str, Any] = {
        "id": f.id,
        "resource": f.resource,
        "title": title,
        "location": f.location,
        "classifications": f.classifications,
        "evidence": [e.__dict__ for e in (f.evidence or [])],
        "severity": f.severity,
        "metadata": metadata,
        "data_source": f.data_source,
        "profile": f.profile,
        "bucket": f.bucket_name,
        "file_path": f.file_path,
        "severity_description": f.severity_description,
        "risk_score": f.risk_score,
        "risk_level": f.risk_level,
        "risk_factors": f.risk_factors or [],
        "detections": [
            {
                "bucket": d.bucket,
                "pattern_name": d.pattern_name,
                "matches": d.matches,
                "sample_text": d.sample_text,
            }
            for d in (f.detections or [])
        ],
        # Computed convenience fields
        "num_detections": counts["num_detections"],
        "num_matches": counts["num_matches"],
        "bucket_match_counts": counts["bucket_match_counts"],
        "pattern_match_counts": counts["pattern_match_counts"],
        "top_exact_matches": counts["top_exact_matches"],
        "last_updated": last_updated,
    }
    return data


def to_json(findings: List[Finding]) -> str:
    return json.dumps([serialize_finding(f) for f in findings], indent=2)


