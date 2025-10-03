import json
from typing import List

from dspm.core.models import Finding


def to_json(findings: List[Finding]) -> str:
    def serialize(f: Finding):
        return {
            "id": f.id,
            "resource": f.resource,
            "location": f.location,
            "classifications": f.classifications,
            "evidence": [e.__dict__ for e in f.evidence],
            "severity": f.severity,
            "metadata": f.metadata,
            "data_source": f.data_source,
            "profile": f.profile,
            "bucket": f.bucket_name,
            "file_path": f.file_path,
            "severity_description": f.severity_description,
            "risk_score": f.risk_score,
            "risk_level": f.risk_level,
            "risk_factors": f.risk_factors,
            "detections": [
                {
                    "bucket": d.bucket,
                    "pattern_name": d.pattern_name,
                    "matches": d.matches,
                    "sample_text": d.sample_text,
                }
                for d in f.detections
            ],
        }

    return json.dumps([serialize(f) for f in findings], indent=2)


