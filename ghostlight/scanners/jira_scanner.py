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
from ghostlight.classify.filters import apply_context_filters
from ghostlight.core.models import Evidence, Finding, ScanConfig, Detection
from ghostlight.risk.scoring import compute_sensitivity_score, compute_exposure_factor, compute_risk
from ghostlight.utils.logging import get_logger
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
				text = (summary + "\n" + str(desc))[: config.sample_bytes]
				if not text.strip():
					continue

				detailed = classify_text_detailed(text)
				filtered = apply_context_filters(detailed, text, min_entropy=config.min_entropy)
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
