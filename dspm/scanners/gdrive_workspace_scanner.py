from __future__ import annotations

from typing import Iterable

try:
    from googleapiclient.discovery import build  # type: ignore
    from google.oauth2 import service_account  # type: ignore
except Exception:  # pragma: no cover
    build = None
    service_account = None

from dspm.classify.engine import classify_text_detailed, score_severity
from dspm.classify.filters import apply_context_filters
from dspm.core.models import Evidence, Finding, ScanConfig, Detection
from dspm.risk.scoring import compute_sensitivity_score, compute_exposure_factor, compute_risk
from dspm.utils.logging import get_logger
from .base import Scanner

logger = get_logger(__name__)


class GDriveWorkspaceScanner(Scanner):
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        # target: service account JSON path with domain-wide delegation
        if build is None or service_account is None:
            logger.error("googleapiclient/google.oauth2 not available")
            return []

        try:
            creds = service_account.Credentials.from_service_account_file(target, scopes=["https://www.googleapis.com/auth/admin.directory.user.readonly","https://www.googleapis.com/auth/drive.readonly"])  # type: ignore
            service = build("admin", "directory_v1", credentials=creds)
            drive_service = build("drive", "v3", credentials=creds)
        except Exception as e:
            logger.error(f"Failed to init Workspace clients: {e}")
            return []

        scanned = 0
        req = service.users().list(customer='my_customer', maxResults=50, orderBy='email')
        while req is not None:
            resp = req.execute()
            for user in resp.get('users', []):
                user_email = user.get('primaryEmail')
                try:
                    files_resp = drive_service.files().list(q=f"'{user_email}' in owners and mimeType != 'application/vnd.google-apps.folder'", spaces='drive', fields="files(id,name,mimeType,size)").execute()
                except Exception:
                    continue
                for f in files_resp.get('files', []):
                    size = int(f.get('size') or 0)
                    if size > config.max_file_mb * 1024 * 1024:
                        continue
                    # For brevity, skip download; in production, sample contents as in GDriveScanner
                    name = f.get('name', '')
                    detailed = classify_text_detailed(name)
                    filtered = apply_context_filters(detailed, name)
                    if not filtered:
                        continue
                    detections = [
                        Detection(bucket=b, pattern_name=p, matches=m, sample_text=name[:200])
                        for (b, p, m) in filtered
                    ]
                    sev, desc = score_severity(len(detections), sum(len(d.matches) for d in detections))
                    sens, sens_factors = compute_sensitivity_score(detections)
                    expo, expo_factors = compute_exposure_factor("gdrive_workspace", {})
                    risk, risk_level = compute_risk(sens, expo)
                    scanned += 1
                    yield Finding(
                        id=f"gws:{user_email}:{f['id']}",
                        resource="workspace",
                        location=f"gws://{user_email}/{name}",
                        classifications=[f"{b}:{n}" for (b, n, _m) in filtered],
                        evidence=[Evidence(snippet=name[:200])],
                        severity=sev,
                        data_source="gdrive_workspace",
                        profile=user_email,
                        file_path=name,
                        severity_description=desc,
                        detections=detections,
                        risk_score=risk,
                        risk_level=risk_level,
                        risk_factors=sens_factors + expo_factors,
                    )
            req = service.users().list_next(previous_request=req, previous_response=resp)

        logger.info(f"GWS scan complete. Scanned {scanned} user files metadata")


