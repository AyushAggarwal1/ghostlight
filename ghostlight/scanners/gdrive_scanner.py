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

from ghostlight.classify.engine import classify_text_detailed, score_severity
from ghostlight.classify.filters import apply_context_filters
from ghostlight.classify.ai_filter import ai_classify_detection
from ghostlight.core.models import Evidence, Finding, ScanConfig, Detection
from ghostlight.risk.scoring import compute_sensitivity_score, compute_exposure_factor, compute_risk
from ghostlight.utils.snippets import earliest_line_and_snippet
from ghostlight.utils.text_extract import extract_text_from_file
from ghostlight.utils.logging import get_logger
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
        # Simple cache to avoid repeated folder lookups
        folder_meta_cache = {}

        def _get_folder_meta(fid: str):
            if fid in folder_meta_cache:
                return folder_meta_cache[fid]
            try:
                meta = service.files().get(fileId=fid, fields="id, name, parents", supportsAllDrives=True).execute()
                folder_meta_cache[fid] = meta
                return meta
            except Exception:
                return None

        def _build_full_path(file_name: str, parents: list | None) -> str:
            # Reconstruct path by walking first parent chain up to root
            segments = [file_name]
            current_parents = list(parents or [])
            visited = set()
            while current_parents:
                pid = current_parents[0]
                if pid in visited:
                    break
                visited.add(pid)
                meta = _get_folder_meta(pid)
                if not meta:
                    break
                segments.append(meta.get("name") or "")
                current_parents = meta.get("parents") or []
            # segments collected child→root; reverse for root→child
            segments = [s for s in segments if s]
            return "/".join(reversed(segments)) if segments else file_name
        scanned = 0
        while True:
            try:
                response = service.files().list(q="mimeType != 'application/vnd.google-apps.folder'",
                                                spaces="drive",
                                                fields="nextPageToken, files(id, name, mimeType, size, parents)",
                                                includeItemsFromAllDrives=True,
                                                supportsAllDrives=True,
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
                        # Extract text from binary if needed (write to temp file to reuse extractor)
                        import tempfile
                        import os as _os
                        with tempfile.NamedTemporaryFile(delete=False) as tmp:
                            tmp.write(data)
                            tmp_path = tmp.name
                        try:
                            text = extract_text_from_file(tmp_path, config.sample_bytes) or ""
                        finally:
                            try:
                                _os.unlink(tmp_path)
                            except Exception:
                                pass
                    text = text[: config.sample_bytes]
                except Exception:
                    continue

                detailed = classify_text_detailed(text)
                filtered = apply_context_filters(detailed, text)
                # Optionally apply AI verification
                import os as _os
                ai_mode = _os.getenv("GHOSTLIGHT_AI_FILTER", "auto")
                if ai_mode != "off" and detailed:
                    try:
                        logger.info(
                            f"AI filter enabled (mode={ai_mode}) for gdrive file {f.get('name','')} with {len(filtered)} detections pre-AI"
                        )
                    except Exception:
                        logger.debug("AI filter start log failed (gdrive)")
                    ai_verified = []
                    full_path = _build_full_path(f['name'], f.get('parents'))
                    for bucket, pattern_name, matches in filtered:
                        matched_value = str(matches[0]) if matches else ""
                        is_tp, _reason = ai_classify_detection(
                            pattern_name=pattern_name,
                            matched_value=matched_value,
                            sample_text=text,
                            table_name=full_path,
                            db_engine="gdrive",
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
                sev, desc = score_severity(len(detections), sum(len(d.matches) for d in detections))
                sens, sens_factors = compute_sensitivity_score(detections)
                expo, expo_factors = compute_exposure_factor("gdrive", {})
                risk, risk_level = compute_risk(sens, expo)

                scanned += 1
                earliest_line, snippet_line = earliest_line_and_snippet(text, filtered)
                full_path = _build_full_path(f['name'], f.get('parents'))
                yield Finding(
                    id=f"gdrive:{f['id']}",
                    resource="gdrive",
                    location=f"gdrive://{full_path} ({f['id']}):{earliest_line or 1}",
                    classifications=[f"{b}:{n}" for (b, n, _m) in filtered],
                    evidence=[Evidence(snippet=snippet_line)],
                    severity=sev,
                    data_source="gdrive",
                    profile="drive",
                    file_path=full_path,
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


