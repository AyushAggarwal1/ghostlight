from __future__ import annotations

from typing import Iterable

try:
    from googleapiclient.discovery import build  # type: ignore
    from googleapiclient.errors import HttpError  # type: ignore
    from google.oauth2 import service_account  # type: ignore
except Exception:  # pragma: no cover
    build = None
    HttpError = Exception
    service_account = None

from dspm.classify.engine import classify_text_detailed, score_severity
from dspm.classify.filters import apply_context_filters
from dspm.core.models import Evidence, Finding, ScanConfig, Detection
from dspm.risk.scoring import compute_sensitivity_score, compute_exposure_factor, compute_risk
from dspm.utils.text_extract import extract_text_from_file
from dspm.utils.logging import get_logger
from .base import Scanner

logger = get_logger(__name__)


class GDriveScanner(Scanner):
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        # target: path to service account JSON or 'default'
        if build is None or service_account is None:
            logger.error("googleapiclient/google.oauth2 not available")
            return []

        try:
            if target and target != "default":
                creds = service_account.Credentials.from_service_account_file(target, scopes=["https://www.googleapis.com/auth/drive.readonly"])
            else:
                # Relies on environment default credentials
                creds = None  # type: ignore
            service = build("drive", "v3", credentials=creds)
        except Exception as e:
            logger.error(f"Failed to create Drive client: {e}")
            return []

        page_token = None
        scanned = 0
        while True:
            try:
                response = service.files().list(q="mimeType != 'application/vnd.google-apps.folder'",
                                                spaces="drive",
                                                fields="nextPageToken, files(id, name, mimeType, size)",
                                                pageToken=page_token).execute()
            except HttpError as e:
                logger.error(f"Drive list error: {e}")
                break

            for f in response.get('files', []):
                size = int(f.get('size') or 0)
                if size > config.max_file_mb * 1024 * 1024:
                    continue
                # Download small sample using export for Google Docs or media for others
                try:
                    if f['mimeType'].startswith('application/vnd.google-apps'):
                        # Export as plain text
                        data = service.files().export(fileId=f['id'], mimeType='text/plain').execute()
                        text = (data or b"").decode('utf-8', errors='ignore')
                    else:
                        req = service.files().get_media(fileId=f['id'])
                        data = req.execute()
                        # Extract text from binary if needed
                        text = extract_text_from_file(None, config.sample_bytes, content_bytes=data)  # type: ignore
                    text = text[: config.sample_bytes]
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
                expo, expo_factors = compute_exposure_factor("gdrive", {})
                risk, risk_level = compute_risk(sens, expo)

                scanned += 1
                yield Finding(
                    id=f"gdrive:{f['id']}",
                    resource="gdrive",
                    location=f"gdrive://{f['name']}",
                    classifications=[f"{b}:{n}" for (b, n, _m) in filtered],
                    evidence=[Evidence(snippet=text[:200])],
                    severity=sev,
                    data_source="gdrive",
                    profile="drive",
                    file_path=f["name"],
                    severity_description=desc,
                    detections=detections,
                    risk_score=risk,
                    risk_level=risk_level,
                    risk_factors=sens_factors + expo_factors,
                )

            page_token = response.get('nextPageToken', None)
            if page_token is None:
                break

        logger.info(f"Google Drive scan complete. Scanned {scanned} files")


