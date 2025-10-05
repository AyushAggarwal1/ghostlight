from __future__ import annotations

from typing import Iterable, Dict

try:
    from slack_sdk import WebClient  # type: ignore
except Exception:  # pragma: no cover
    WebClient = None

from ghostlight.classify.engine import classify_text_detailed, score_severity
from ghostlight.classify.filters import apply_context_filters
from ghostlight.classify.ai_filter import ai_classify_detection
from ghostlight.core.models import Evidence, Finding, ScanConfig, Detection
from ghostlight.utils.snippets import earliest_line_and_snippet
from ghostlight.risk.scoring import compute_sensitivity_score, compute_exposure_factor, compute_risk
from ghostlight.utils.logging import get_logger
from .base import Scanner

logger = get_logger(__name__)


class SlackScanner(Scanner):
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        # target: slack_bot_token[:channel_id]
        if WebClient is None:
            logger.error("slack_sdk not available")
            return []
        try:
            token, channel = (target.split(":", 1) + [None])[:2]
            client = WebClient(token=token)
            channels = [channel] if channel else [c['id'] for c in client.conversations_list(limit=50)['channels']]
        except Exception:
            return []

        user_cache: Dict[str, str] = {}

        for ch in channels:
            # Fetch channel name
            channel_name = ch
            try:
                info = client.conversations_info(channel=ch)
                if info.get('ok'):
                    channel_name = info['channel'].get('name') or ch
            except Exception:
                pass

            try:
                resp = client.conversations_history(channel=ch, limit=200)
            except Exception:
                continue

            for msg in resp.get('messages', []):
                text = (msg.get('text') or '')[: config.sample_bytes]
                if not text:
                    continue

                detailed = classify_text_detailed(text)
                filtered = apply_context_filters(detailed, text)
                # Optionally apply AI verification
                import os as _os
                ai_mode = _os.getenv("GHOSTLIGHT_AI_FILTER", "auto")
                if ai_mode != "off" and detailed:
                    try:
                        logger.info(
                            f"AI filter enabled (mode={ai_mode}) for slack message {channel_name}/{ts} with {len(filtered)} detections pre-AI"
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
                            table_name=f"{channel_name}:{ts}",
                            db_engine="slack",
                            column_names=None,
                            use_ai=ai_mode
                        )
                        if is_tp:
                            ai_verified.append((bucket, pattern_name, matches))
                    filtered = ai_verified
                if not filtered:
                    continue

                # Resolve user information
                user_id = msg.get('user') or ''
                # Prefer explicit username present on the message (legacy/webhook)
                user_name = msg.get('username') or ''
                # If bot message without 'user', fall back to bot_profile name
                if not user_name and not user_id:
                    bot_profile = msg.get('bot_profile') or {}
                    user_name = bot_profile.get('name') or bot_profile.get('real_name') or ''
                # If we have a user_id, enrich via users.info for reliable display/real name
                if user_id and not user_name:
                    if user_id in user_cache:
                        user_name = user_cache[user_id]
                    else:
                        try:
                            u = client.users_info(user=user_id)
                            if u.get('ok'):
                                uu = u.get('user', {})
                                prof = uu.get('profile', {})
                                # Try a rich set of fields in order of preference
                                for cand in [
                                    prof.get('display_name_normalized'),
                                    prof.get('display_name'),
                                    prof.get('real_name_normalized'),
                                    prof.get('real_name'),
                                    uu.get('real_name'),
                                    uu.get('name'),
                                ]:
                                    if cand:
                                        user_name = cand
                                        break
                                user_cache[user_id] = user_name or ''
                        except Exception:
                            pass
                if not user_name:
                    user_name = 'unknown'

                ts = msg.get('ts') or ''
                permalink = ''
                try:
                    pl = client.chat_getPermalink(channel=ch, message_ts=ts)
                    if pl.get('ok'):
                        permalink = pl.get('permalink') or ''
                except Exception:
                    pass

                # Build detections and scores
                detections = [
                    Detection(bucket=b, pattern_name=name, matches=matches, sample_text=text[:200])
                    for (b, name, matches) in filtered
                ]
                sev, desc = score_severity(len(detections), sum(len(d.matches) for d in detections))
                sens, sens_factors = compute_sensitivity_score(detections)
                expo_meta = {
                    "channel_id": ch,
                    "channel_name": channel_name,
                    "user_id": user_id,
                    "user_name": user_name,
                    "ts": ts,
                    "permalink": permalink,
                }
                expo, expo_factors = compute_exposure_factor("slack", expo_meta)
                risk, risk_level = compute_risk(sens, expo)

                earliest_line, snippet_line = earliest_line_and_snippet(text, filtered)
                yield Finding(
                    id=f"slack:{ch}:{ts}",
                    resource=channel_name,
                    location=(permalink or f"slack://{ch}/{ts}:{earliest_line or 1}"),
                    classifications=[f"{b}:{n}" for (b, n, _m) in filtered],
                    evidence=[Evidence(snippet=snippet_line)],
                    severity=sev,
                    metadata=expo_meta,
                    data_source="slack",
                    profile=channel_name,
                    file_path=None,
                    severity_description=desc,
                    detections=detections,
                    risk_score=risk,
                    risk_level=risk_level,
                    risk_factors=sens_factors + expo_factors,
                )


