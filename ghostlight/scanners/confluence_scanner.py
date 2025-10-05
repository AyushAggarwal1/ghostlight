from __future__ import annotations

from typing import Iterable, List, Dict, Optional
import os
import re
import html as html_mod
import time
from urllib.parse import unquote

try:
	import requests  # type: ignore
except Exception:  # pragma: no cover
	requests = None

from ghostlight.classify.engine import classify_text_detailed, score_severity
from ghostlight.classify.filters import apply_context_filters, detect_primary_language
from ghostlight.classify.ai_filter import ai_classify_detection
from ghostlight.core.models import Evidence, Finding, ScanConfig, Detection
from ghostlight.risk.scoring import compute_sensitivity_score, compute_exposure_factor, compute_risk
from ghostlight.utils.logging import get_logger
from ghostlight.utils.text_extract import extract_text_from_file
from .base import Scanner

logger = get_logger(__name__)


def _strip_html(html: str) -> str:
	try:
		text = re.sub(r"<script[\s\S]*?</script>|<style[\s\S]*?</style>", " ", html, flags=re.IGNORECASE)
		text = re.sub(r"<[^>]+>", " ", text)
		text = html_mod.unescape(text)
		text = re.sub(r"\s+", " ", text).strip()
		return text
	except Exception:
		return html


class ConfluenceScanner(Scanner):
	"""Scan Confluence spaces/pages for sensitive data.

	Target format:
		confluence://https://your-domain.atlassian.net[:/wiki]:EMAIL:API_TOKEN:SPACE_KEY[?cql=URL_ENCODED_CQL]
	Default CQL bounds results to avoid unbounded queries.
	"""

	def _ensure_api_base(self, base: str) -> str:
		base = base.rstrip("/")
		if base.endswith("/wiki"):
			return base
		return base + "/wiki"

	def _test_connection(self, session: "requests.Session", api_base: str, space: str) -> bool:
		# Verify auth
		try:
			r1 = session.get(f"{api_base}/rest/api/user/current", timeout=10)
			if r1.status_code in (401, 403):
				logger.error("Confluence connection failed (/user/current): unauthorized. Check email/API token permissions.")
				return False
			r1.raise_for_status()
		except Exception as e:
			status = getattr(getattr(e, "response", None), "status_code", None)
			body = ""
			try:
				body = e.response.text  # type: ignore[attr-defined]
			except Exception:
				pass
			logger.error(f"Confluence connection failed (/user/current): status={status} error={e} body={body[:300]}")
			return False
		# Verify space
		try:
			r2 = session.get(f"{api_base}/rest/api/space/{space}", timeout=10)
			if r2.status_code in (401, 403):
				logger.error(f"Confluence connection failed (/space/{space}): unauthorized. Check space access.")
				return False
			r2.raise_for_status()
		except Exception as e:
			status = getattr(getattr(e, "response", None), "status_code", None)
			body = ""
			try:
				body = e.response.text  # type: ignore[attr-defined]
			except Exception:
				pass
			logger.error(f"Confluence connection failed (/space/{space}): status={status} error={e} body={body[:300]}")
			return False
		logger.info(f"Confluence connection successful: space={space}, base={api_base}")
		return True

	def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
		if requests is None:
			logger.error("requests not available. Run: pip install requests")
			return []
		try:
			_, rest = target.split("confluence://", 1)
			base_part, email, token, space_and_q = rest.rsplit(":", 3)
			base = base_part.strip()
			if not base.lower().startswith(("http://", "https://")):
				base = "https://" + base
			space = space_and_q
		except Exception:
			logger.error("Invalid Confluence target. Expected: confluence://BASE_URL:EMAIL:API_TOKEN:SPACE_KEY[?cql=...]")
			return []

		# Inline CQL support
		custom_cql = None
		if "?cql=" in space:
			sp, q = space.split("?cql=", 1)
			space = sp
			custom_cql = unquote(q)

		if custom_cql is None:
			custom_cql = os.getenv("GHOSTLIGHT_CONFLUENCE_CQL") or os.getenv("CONFLUENCE_CQL")

		# Default bounded CQL (quote space key to support personal spaces like ~accountId)
		if custom_cql:
			cql = custom_cql.replace("${SPACE}", space)
		else:
			safe_space = space.replace('"', '\\"')
			cql = f"space = \"{safe_space}\" AND type=page ORDER BY lastmodified DESC"

		session = requests.Session()
		session.auth = (email, token)
		session.headers.update({"Accept": "application/json"})

		api_base = self._ensure_api_base(base)
		if not self._test_connection(session, api_base, space):
			logger.error("Aborting Confluence scan due to failed connection test.")
			return []

		logger.info(f"Starting Confluence scan: space={space}, limit=50, sample_bytes={config.sample_bytes}")
		start = 0
		limit = 50
		scanned = 0
		backoff = 2.0
		seen_ids: set[str] = set()
		next_rel: Optional[str] = None
		prev_next_rel: Optional[str] = None
		while True:
			results: List[Dict] = []
			# Prefer content search API
			try:
				if next_rel:
					url = next_rel if next_rel.startswith("http") else (api_base.rstrip("/") + next_rel)
					resp = session.get(url, timeout=20)
				else:
					resp = session.get(
						f"{api_base}/rest/api/content/search",
						params={"cql": cql, "limit": limit, "start": start},
						timeout=20,
					)
				# Handle explicit rate limit
				if resp.status_code == 429:
					retry_after = float(resp.headers.get("Retry-After", backoff))
					logger.warning(f"Confluence rate limited (429). Backing off {retry_after:.1f}s...")
					time.sleep(retry_after)
					backoff = min(backoff * 1.5, 30.0)
					continue
				resp.raise_for_status()
				backoff = 2.0
				data = resp.json()
				results = data.get("results", []) or []
				if not isinstance(results, list):
					results = []
				# Use cursor-based pagination when available
				links = data.get("_links") or {}
				next_rel = links.get("next") if isinstance(links, dict) else None
				next_page = bool(next_rel) or (len(results) == limit)
			except requests.exceptions.HTTPError as http_err:
				status = getattr(http_err.response, "status_code", None)
				# Fallback to legacy search
				try:
					resp = session.get(
						f"{api_base}/rest/api/search",
						params={"cql": cql, "limit": limit, "start": start},
						timeout=20,
					)
					if resp.status_code == 429:
						retry_after = float(resp.headers.get("Retry-After", backoff))
						logger.warning(f"Confluence rate limited (429 legacy). Backing off {retry_after:.1f}s...")
						time.sleep(retry_after)
						backoff = min(backoff * 1.5, 30.0)
						continue
					resp.raise_for_status()
					backoff = 2.0
					data = resp.json()
					results = data.get("results", []) or []
					if not isinstance(results, list):
						results = []
					# Legacy pagination heuristic (no links.next)
					next_rel = None
					next_page = len(results) == limit
				except Exception as e2:
					logger.error(f"Confluence search failed: {e2} | CQL=<{cql}>")
					break
			except Exception as e:
				logger.error(f"Confluence search failed: {e} | CQL=<{cql}>")
				break

			if not results:
				logger.info(f"Confluence search: no results at start={start}. Ending.")
				break

			logger.info(f"Confluence search: fetched {len(results)} results at start={start}. Total scanned so far={scanned + len(results)}")
			batch_ids = []
			for item in results:
				# content search returns content objects directly; legacy search returns {content:{id, title}, url}
				content = item.get("content", item)
				page_id = str(content.get("id") or "").strip()
				title = str(content.get("title") or "").strip()
				if not page_id:
					continue
				batch_ids.append(page_id)
				# Log document name being scanned
				logger.info(f"Scanning Confluence page: {title or page_id} (id={page_id})")
				# Fetch page detail with body.storage and comments/attachments metadata
				try:
					detail = session.get(
						f"{api_base}/rest/api/content/{page_id}",
						params={"expand": "body.storage,version,space,history.lastUpdated,metadata.labels"},
						timeout=20,
					)
					detail.raise_for_status()
					doc = detail.json()
				except Exception as e:
					logger.error(f"Confluence page fetch failed (id={page_id}): {e}")
					continue

				storage_html = (((doc.get("body") or {}).get("storage") or {}).get("value") or "")
				text_parts: List[str] = []
				text_full = _strip_html(storage_html)
				if text_full:
					text_parts.append(text_full)
				# Comments (1st page)
				try:
					c_resp = session.get(
						f"{api_base}/rest/api/content/{page_id}/child/comment",
						params={"expand": "body.storage"},
						timeout=20,
					)
					if c_resp.ok:
						cdata = c_resp.json()
						for c in (cdata.get("results") or [])[:50]:
							c_html = (((c.get("body") or {}).get("storage") or {}).get("value") or "")
							c_text = _strip_html(c_html)
							if c_text:
								text_parts.append(c_text)
				except Exception:
					pass
				# Attachments (names into context; content OCR not downloaded here)
				try:
					a_resp = session.get(
						f"{api_base}/rest/api/content/{page_id}/child/attachment",
						params={"limit": 50},
						timeout=20,
					)
					if a_resp.ok:
						adata = a_resp.json()
						att_names = [str(a.get("title") or "") for a in (adata.get("results") or [])[:50]]
						if att_names:
							text_parts.append("\n".join(att_names))
				except Exception:
					pass

				text = ("\n".join(text_parts)).strip()[: config.sample_bytes]
				if not text.strip():
					continue

                detailed = classify_text_detailed(text)
                filtered = apply_context_filters(detailed, text, min_entropy=config.min_entropy)
                # Optionally apply AI verification
                ai_mode = os.getenv("GHOSTLIGHT_AI_FILTER", "auto")
                if ai_mode != "off" and detailed:
                    try:
                        logger.info(
                            f"AI filter enabled (mode={ai_mode}) for confluence page {title or page_id} with {len(filtered)} detections pre-AI"
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
                            table_name=f"{space_key}:{title or page_id}",
                            db_engine="confluence",
                            column_names=None,
                            use_ai=ai_mode
                        )
                        if is_tp:
                            ai_verified.append((bucket, pattern_name, matches))
                    filtered = ai_verified
				if not filtered:
					continue

				exact_matches = sorted({m for (_b, _n, ms) in filtered for m in ms})
				version_num = str(((doc.get("version") or {}).get("number") or ""))
				updated = str(((doc.get("history") or {}).get("lastUpdated") or {}).get("when") or "")
				updated_by = str((((doc.get("history") or {}).get("lastUpdated") or {}).get("by") or {}).get("displayName") or "")
				space_key = ((doc.get("space") or {}).get("key") or space)
				links = doc.get("_links") or {}
				webui = links.get("webui") or ""
				base_href = links.get("base") or api_base
				page_url = (base_href.rstrip("/") + webui) if webui else f"{api_base}/spaces/{space_key}/pages/{page_id}"

				metadata: Dict[str, str] = {
					"base_url": base,
					"api_base": api_base,
					"space_key": str(space_key),
					"page_id": page_id,
					"page_title": title[:200],
					"version": version_num,
					"last_updated": updated,
					"last_updated_by": updated_by,
					"sample_bytes": str(config.sample_bytes),
					"text_length": str(len(text)),
					"exact_matches_count": str(len(exact_matches)),
				}
				lang = detect_primary_language(text)
				if lang:
					metadata["language"] = lang

				detections = [
					Detection(bucket=b, pattern_name=name, matches=matches, sample_text=text[:200])
					for (b, name, matches) in filtered
				]
				if config.strict and not (len(detections) >= 2 or sum(len(d.matches) for d in detections) >= 2):
					continue

				sev, desc_sev = score_severity(len(detections), sum(len(d.matches) for d in detections))
				sens, sens_factors = compute_sensitivity_score(detections)
				expo, expo_factors = compute_exposure_factor("confluence", {"space": space_key})
				risk, risk_level = compute_risk(sens, expo)

				yield Finding(
					id=f"confluence:{space_key}:{page_id}",
					resource=str(space_key),
					location=page_url,
					classifications=[f"{b}:{n}" for (b, n, _m) in filtered],
					evidence=[Evidence(snippet=text[:200], context=os.linesep.join(exact_matches[:20]))],
					severity=sev,
					data_source="confluence",
					profile=str(space_key),
					severity_description=desc_sev,
					detections=detections,
					risk_score=risk,
					risk_level=risk_level,
					risk_factors=sens_factors + expo_factors,
					metadata=metadata,
				)

			# Loop progress and termination checks
			new_in_batch = sum(1 for pid in batch_ids if pid not in seen_ids)
			seen_ids.update(batch_ids)
			scanned += len(results)
			if new_in_batch == 0:
				logger.warning("Confluence search: no new pages in this batch; stopping to prevent loop.")
				break
			if not next_page:
				logger.info(f"Confluence search: reached last page at start={start}. Total scanned={scanned}")
				break
			# Advance pagination cursor or offset
			if next_rel:
				if prev_next_rel == next_rel:
					logger.warning("Confluence search: repeating next cursor detected; stopping to prevent loop.")
					break
				prev_next_rel = next_rel
			else:
				start += limit

		logger.info(f"Confluence scan complete. Scanned {scanned} items in space {space}")
		return []
