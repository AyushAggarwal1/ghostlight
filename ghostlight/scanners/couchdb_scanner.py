from __future__ import annotations

from typing import Iterable

try:
    import couchdb  # type: ignore
except Exception:  # pragma: no cover
    couchdb = None

from ghostlight.classify.engine import classify_text_detailed, score_severity
from ghostlight.classify.filters import apply_context_filters
from ghostlight.core.models import Evidence, Finding, ScanConfig, Detection
from ghostlight.utils.snippets import earliest_line_and_snippet
from ghostlight.risk.scoring import compute_sensitivity_score, compute_exposure_factor, compute_risk
from ghostlight.utils.logging import get_logger
from .base import Scanner

logger = get_logger(__name__)


class CouchDBScanner(Scanner):
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        # target: http[s]://user:pass@host:port:db1,db2
        if couchdb is None:
            logger.error("couchdb library not available")
            return []
        try:
            dsn, dbs = target.split(":", 1)
            db_list = [d for d in dbs.split(",") if d]
            server = couchdb.Server(dsn)
        except Exception:
            return []
        for dbname in db_list:
            try:
                db = server[dbname]
                rows = []
                for i, (_id, doc) in enumerate(db.items()):
                    rows.append(str(doc))
                    if i >= 50:
                        break
            except Exception:
                continue
            sample = "\n".join(rows)[: config.sample_bytes]
            detailed = classify_text_detailed(sample)
            filtered = apply_context_filters(detailed, sample, table_name=dbname, db_engine="couchdb")
            if not filtered:
                continue
            earliest_line, snippet_line = earliest_line_and_snippet(sample, filtered)
            detections = [
                Detection(bucket=b, pattern_name=name, matches=matches, sample_text=sample[:200])
                for (b, name, matches) in filtered
            ]
            sev, desc = score_severity(len(detections), sum(len(d.matches) for d in detections))
            sens, sens_factors = compute_sensitivity_score(detections)
            expo, expo_factors = compute_exposure_factor("couchdb", {})
            risk, risk_level = compute_risk(sens, expo)
            yield Finding(
                id=f"couchdb:{dbname}",
                resource=dsn,
                location=f"{dsn}/{dbname}:{earliest_line or 1}",
                classifications=[f"{b}:{n}" for (b, n, _m) in filtered],
                evidence=[Evidence(snippet=snippet_line)],
                severity=sev,
                data_source="couchdb",
                profile=dbname,
                file_path=None,
                severity_description=desc,
                detections=detections,
                risk_score=risk,
                risk_level=risk_level,
                risk_factors=sens_factors + expo_factors,
            )


