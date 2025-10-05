from __future__ import annotations

import os
from typing import Iterable
import tempfile
import shutil
import re

from git import Repo, InvalidGitRepositoryError, NoSuchPathError

from ghostlight.classify.engine import classify_text_detailed, score_severity
from ghostlight.classify.filters import apply_context_filters
from ghostlight.risk.scoring import compute_sensitivity_score, compute_exposure_factor, compute_risk
from ghostlight.core.models import Evidence, Finding, ScanConfig, Detection
from ghostlight.utils.snippets import earliest_line_and_snippet
from ghostlight.utils.logging import get_logger
from .git_auth import build_authenticated_url, get_git_credentials, get_auth_help_message
from .base import Scanner

logger = get_logger(__name__)


class GitScanner(Scanner):
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        is_remote = bool(re.match(r"^(?:https?://|git@).+|.+\.git$", target))
        tmp_dir = None
        try:
            if is_remote:
                logger.info(f"Cloning remote repository: {target}")
                tmp_dir = tempfile.mkdtemp(prefix="ghostlight-git-")
                
                # Get credentials from environment
                creds = get_git_credentials()
                
                # Build authenticated URL if credentials available
                if target.startswith("https://") and creds.get("token"):
                    authenticated_url = build_authenticated_url(
                        target,
                        token=creds["token"],
                        username=creds.get("username")
                    )
                    logger.info("Using token authentication")
                elif target.startswith("git@"):
                    authenticated_url = target
                    logger.info("Using SSH key authentication")
                else:
                    authenticated_url = target
                    logger.info("Attempting clone without explicit credentials (will use git config)")
                
                # Clone with depth=1 for faster scanning
                repo = Repo.clone_from(authenticated_url, tmp_dir, depth=1)
                root = repo.working_tree_dir or tmp_dir
            else:
                logger.info(f"Scanning local repository: {target}")
                repo = Repo(target)
                root = repo.working_tree_dir or target
        except (InvalidGitRepositoryError, NoSuchPathError, Exception) as e:
            logger.error(f"Failed to access git repository {target}: {e}")
            error_str = str(e).lower()
            if any(keyword in error_str for keyword in ["authentication", "credentials", "permission denied", "could not read", "403", "401"]):
                logger.error("\n" + get_auth_help_message(target))
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            return []
        
        # Use the original target as the display resource for remote scans, otherwise use the local root
        display_resource = target if is_remote else root

        scanned_count = 0
        for blob in repo.head.commit.tree.traverse():
            if blob.type != "blob":
                continue
            path = os.path.join(root, blob.path)
            try:
                data = blob.data_stream.read(config.sample_bytes)
                text = data.decode("utf-8", errors="ignore")
            except Exception:
                continue

            detailed = classify_text_detailed(text)
            # Apply context-aware filters (entropy, structure) and build classes/detections from filtered
            filtered = apply_context_filters(detailed, text, min_entropy=config.min_entropy)
            classifications = [f"{b}:{n}" for (b, n, _m) in filtered]
            if not classifications:
                continue

            detections = [
                Detection(bucket=b, pattern_name=name, matches=matches, sample_text=text[:200])
                for (b, name, matches) in filtered
            ]
            # Strict mode guard
            if config.strict and not (len(detections) >= 2 or sum(len(d.matches) for d in detections) >= 2):
                continue
            sev, desc = score_severity(len(detections), sum(len(d.matches) for d in detections))
            sens, sens_factors = compute_sensitivity_score(detections)
            expo, expo_factors = compute_exposure_factor("git", {})
            risk, risk_level = compute_risk(sens, expo)
            
            scanned_count += 1
            logger.info(f"Found {len(detections)} detection(s) in {blob.path}")
            
            earliest_line, snippet_line = earliest_line_and_snippet(text, filtered)

            # Build location that avoids leaking temporary clone paths for remote repositories
            if is_remote:
                location_path = f"{target.rstrip('/')}/{blob.path}"
            else:
                location_path = path
            yield Finding(
                id=f"git:{blob.hexsha[:8]}/{blob.path}",
                resource=display_resource,
                location=f"{location_path}:{earliest_line or 1}",
                classifications=classifications,
                evidence=[Evidence(snippet=snippet_line)],
                severity=sev,
                data_source="git",
                profile=display_resource,
                file_path=blob.path,
                severity_description=desc,
                detections=detections,
                risk_score=risk,
                risk_level=risk_level,
                risk_factors=sens_factors + expo_factors,
            )
        
        logger.info(f"Git scan complete. Scanned {scanned_count} files in {target}")
        if tmp_dir:
            logger.info(f"Cleaning up temporary clone: {tmp_dir}")
            shutil.rmtree(tmp_dir, ignore_errors=True)


