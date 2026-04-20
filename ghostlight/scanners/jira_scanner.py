from __future__ import annotations

from typing import Iterable, List, Dict, Optional
import os
import json
from urllib.parse import unquote

try:
	import requests  # type: ignore
except Exception:  # pragma: no cover
	requests = None

from ghostlight.classify.engine import classify_text_detailed, score_severity
from ghostlight.classify.ai_filter import ai_classify_detection
from ghostlight.classify.filters import apply_context_filters, detect_primary_language
from ghostlight.core.models import Evidence, Finding, ScanConfig, Detection
from ghostlight.risk.scoring import compute_sensitivity_score, compute_exposure_factor, compute_risk
from ghostlight.utils.logging import get_logger
from ghostlight.utils.text_extract import extract_text_from_file
from .base import Scanner

logger = get_logger(__name__)


class JiraScanner(Scanner):
	"""Scan Jira projects for sensitive data in issue descriptions and comments.

	Target format:
		jira://https://your-domain.atlassian.net:EMAIL:API_TOKEN:PROJECT_KEY[?jql=URL_ENCODED_JQL]
	You can also set env var GHOSTLIGHT_JIRA_JQL to override the JQL; '${PROJECT}' will be replaced with the project key.
	"""
	# Connection test: verifies auth and project access before scanning
	def _test_connection(self, session: "requests.Session", base: str, project: str) -> bool:
		try:
			r1 = session.get(f"{base}/rest/api/3/myself", timeout=10)
			if r1.status_code in (401, 403):
				logger.error("Jira connection test failed (/myself): unauthorized. Check email/API token permissions.")
				return False
			r1.raise_for_status()
			me: Dict = {}
			try:
				me = r1.json()
			except Exception:
				pass
		except Exception as e:
			status = getattr(getattr(e, "response", None), "status_code", None)
			body = ""
			try:
				body = e.response.text  # type: ignore[attr-defined]
			except Exception:
				pass
			logger.error(f"Jira connection test failed (/myself): status={status} error={e} body={body[:300]}")
			return False

		try:
			r2 = session.get(f"{base}/rest/api/3/project/{project}", timeout=10)
			if r2.status_code in (401, 403):
				logger.error(f"Jira connection test failed (/project/{project}): unauthorized. Check project access permissions.")
				return False
			r2.raise_for_status()
			proj: Dict = {}
			try:
				proj = r2.json()
			except Exception:
				pass
		except Exception as e:
			status = getattr(getattr(e, "response", None), "status_code", None)
			body = ""
			try:
				body = e.response.text  # type: ignore[attr-defined]
			except Exception:
				pass
			logger.error(f"Jira connection test failed (/project/{project}): status={status} error={e} body={body[:300]}")
			return False

		user_label = me.get("displayName") or me.get("emailAddress") or me.get("accountId") or "unknown"
		proj_name = proj.get("name") or project
		proj_key = proj.get("key") or project
		logger.info(f"Jira connection successful: user={user_label}, project={proj_name} ({proj_key}), base={base}")
		return True

	def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
		if requests is None:
			logger.error("requests not available. Run: pip install requests")
			return []
		try:
			# Support base URL with scheme-containing ':' by splitting from the right
			_, rest = target.split("jira://", 1)
			base_part, email, token, project = rest.rsplit(":", 3)
			base = base_part.strip()
			if not base.lower().startswith(("http://", "https://")):
				base = "https://" + base
		except Exception:
			logger.error("Invalid Jira target. Expected: jira://BASE_URL:EMAIL:API_TOKEN:PROJECT[?jql=...]")
			return []

		# Extract optional inline JQL
		custom_jql = None
		if "?jql=" in project:
			proj, q = project.split("?jql=", 1)
			project = proj
			custom_jql = unquote(q)

		# Env overrides
		if custom_jql is None:
			custom_jql = os.getenv("GHOSTLIGHT_JIRA_JQL") or os.getenv("JIRA_JQL")

		# Default bounded JQL (avoid unbounded errors)
		if custom_jql:
			jql = custom_jql.replace("${PROJECT}", project)
		else:
			jql = f"project={project} AND updated >= -30d ORDER BY updated DESC"

		logger.info(f"Starting Jira scan: project={project}, sample_bytes={config.sample_bytes}, jql=<{jql}>")

		session = requests.Session()
		session.auth = (email, token)
		session.headers.update({"Accept": "application/json"})

		# Test connection before scanning
		if not self._test_connection(session, base, project):
			logger.error("Aborting Jira scan due to failed connection test.")
			return []

		next_token: Optional[str] = None
		scanned = 0
		while True:
			issues: List[Dict] = []
			# Preferred modern API: POST /rest/api/3/search/jql
			try:
				payload: Dict[str, object] = {
					"jql": jql,
					"maxResults": 50,
					"fields": ["summary", "description", "issuetype", "status", "priority", "reporter", "assignee", "labels", "created", "updated"],
				}
				if next_token:
					payload["nextPageToken"] = next_token
				resp = session.post(
					f"{base}/rest/api/3/search/jql",
					json=payload,
					timeout=20,
				)
				resp.raise_for_status()
				payload = resp.json()
				issues = payload.get("issues", []) or []
				# Pagination
				is_last = bool(payload.get("isLast", True))
				next_token = payload.get("nextPageToken") if not is_last else None
				logger.info(f"Jira: fetched {len(issues)} issue(s) (is_last={is_last})")
			except requests.exceptions.HTTPError as http_err:
				status = getattr(http_err.response, "status_code", None)
				# Only fallback on 404 (older servers). Do NOT fallback on 410 (deprecated) or 400.
				if status == 404:
					try:
						legacy_payload: Dict[str, object] = {
							"jql": jql,
							"startAt": 0 if next_token is None else 50,  # simple single-page fallback
							"maxResults": 50,
							"fields": ["summary", "description", "issuetype", "status", "priority", "reporter", "assignee", "labels", "created", "updated"],
						}
						resp = session.post(
							f"{base}/rest/api/3/search",
							json=legacy_payload,
							timeout=20,
						)
						resp.raise_for_status()
						data = resp.json()
						issues = data.get("issues", [])
						next_token = None
					except Exception as e2:
						logger.error(f"Jira search failed: {e2}")
						break
				else:
					logger.error(f"Jira search failed: {http_err}")
					break
			except Exception as e:
				logger.error(f"Jira search failed: {e}")
				break

			if not issues:
				break

			for issue in issues:
				key = issue.get("key") or ""
				fields = issue.get("fields", {})
				summary = fields.get("summary") or ""
				desc = (fields.get("description") or "")
				# Aggregate text: summary + description + comments + attachment texts (OCR/PDF/etc.)
				text_parts: List[str] = [summary or "", str(desc) or ""]
				logger.info(f"Scanning Jira issue: {key} | {summary[:60]}")
				# Fetch comments
				try:
					c_resp = session.get(f"{base}/rest/api/3/issue/{key}/comment", timeout=15)
					if c_resp.ok:
						comments = (c_resp.json().get("comments") or [])
						for c in comments[:20]:
							body = c.get("body")
							if isinstance(body, dict) and "content" in body:
								# JIRA ADF: pick plain text pieces
								try:
									bt = []
									for blk in body.get("content", []):
										for it in blk.get("content", []):
											if it.get("text"):
												bt.append(it.get("text"))
									if bt:
										text_parts.append("\n".join(bt))
								except Exception:
									pass
							elif isinstance(body, str):
								text_parts.append(body)
						logger.info(f"Jira: added {min(len(comments),20)} comment(s) from {key}")
						logger.info(f"Jira: added {min(len(comments),20)} comment(s) from {key}")
				except Exception:
					pass

				# Fetch attachments (metadata only), do not download binaries; include filenames and OCR if small and public URL
				try:
					fields_attachments = fields.get("attachment") or []
					att_names = []
					for att in fields_attachments[:5]:
						name = str(att.get("filename") or "")
						att_names.append(name)
					# Add attachment filenames to context
					if att_names:
						text_parts.append("\n".join(att_names))
						logger.info(f"Jira: issue {key} has {len(fields_attachments)} attachment(s); added top {len(att_names)} name(s)")
				except Exception:
					pass

				text = ("\n".join(p for p in text_parts if p)).strip()[: config.sample_bytes]
				if not text.strip():
					continue

				detailed = classify_text_detailed(text)
                filtered = apply_context_filters(detailed, text, min_entropy=config.min_entropy)
                # Optionally apply AI verification
                ai_mode = os.getenv("GHOSTLIGHT_AI_FILTER", "auto")
                if ai_mode != "off" and detailed:
                    try:
                        logger.info(
                            f"AI filter enabled (mode={ai_mode}) for jira issue {key} with {len(filtered)} detections pre-AI"
                        )
                    except Exception:
                        pass
                    ai_verified = []
                    for bucket, pattern_name, matches in filtered:
                        matched_value = str(matches[0]) if matches else ""
                        is_tp, _reason = ai_classify_detection(
                            pattern_name=pattern_name,
                            matched_value=matched_value,
                            sample_text=text,
                            table_name=key,
                            db_engine="jira",
                            column_names=None,
                            use_ai=ai_mode
                        )
                        if is_tp:
                            ai_verified.append((bucket, pattern_name, matches))
                    filtered = ai_verified
                if not filtered:
                    continue

				exact_matches = sorted({m for (_b, _n, ms) in filtered for m in ms})
				issue_type = ((fields.get("issuetype") or {}).get("name") if isinstance(fields.get("issuetype"), dict) else str(fields.get("issuetype") or "")) or ""
				status_name = ((fields.get("status") or {}).get("name") if isinstance(fields.get("status"), dict) else str(fields.get("status") or "")) or ""
				priority_name = ((fields.get("priority") or {}).get("name") if isinstance(fields.get("priority"), dict) else str(fields.get("priority") or "")) or ""
				reporter = ((fields.get("reporter") or {}).get("displayName") if isinstance(fields.get("reporter"), dict) else str(fields.get("reporter") or "")) or ""
				assignee = ((fields.get("assignee") or {}).get("displayName") if isinstance(fields.get("assignee"), dict) else str(fields.get("assignee") or "")) or ""
				labels = fields.get("labels") or []
				created = str(fields.get("created") or "")
				updated = str(fields.get("updated") or "")
				issue_url = f"{base}/browse/{key}"
				metadata: Dict[str, str] = {
					"base_url": base,
					"project_key": project,
					"issue_key": key,
					"issue_type": str(issue_type),
					"status": str(status_name),
					"priority": str(priority_name),
					"reporter": str(reporter),
					"assignee": str(assignee),
					"labels": ",".join(labels) if isinstance(labels, list) else str(labels),
					"created": created,
					"updated": updated,
					"summary": summary[:150],
					"jql_used": jql,
					"sample_bytes": str(config.sample_bytes),
					"text_length": str(len(text)),
					"exact_matches_count": str(len(exact_matches)),
					"exact_matches": json.dumps(exact_matches[:50]),
				}

				# Language metadata
				lang = detect_primary_language(text)
				if lang:
					metadata["language"] = lang

				detections = [
					Detection(bucket=b, pattern_name=name, matches=matches, sample_text=text[:200])
					for (b, name, matches) in filtered
				]
				# Strict mode
				if config.strict and not (len(detections) >= 2 or sum(len(d.matches) for d in detections) >= 2):
					continue

				sev, desc_sev = score_severity(len(detections), sum(len(d.matches) for d in detections))
				sens, sens_factors = compute_sensitivity_score(detections)
				expo, expo_factors = compute_exposure_factor("jira", {"project": project})
				risk, risk_level = compute_risk(sens, expo)

				yield Finding(
					id=f"jira:{project}:{key}",
					resource=project,
					location=issue_url,
					classifications=[f"{b}:{n}" for (b, n, _m) in filtered],
					evidence=[Evidence(snippet=text[:200], context=json.dumps({"matches": exact_matches[:50]}))],
					severity=sev,
					data_source="jira",
					profile=project,
					severity_description=desc_sev,
					detections=detections,
					risk_score=risk,
					risk_level=risk_level,
					risk_factors=sens_factors + expo_factors,
					metadata=metadata,
				)

			scanned += len(issues)
			if not next_token:
				break

		logger.info(f"Jira scan complete. Scanned {scanned} issues in {project}")
		return []
