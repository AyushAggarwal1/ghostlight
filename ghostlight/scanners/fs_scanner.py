from __future__ import annotations

import os
from typing import Iterable

from ghostlight.classify.engine import classify_text, classify_text_detailed, score_severity
from ghostlight.classify.filters import apply_context_filters
from ghostlight.classify.ai_filter import ai_classify_detection
from ghostlight.risk.scoring import compute_sensitivity_score, compute_exposure_factor, compute_risk
from ghostlight.core.models import Evidence, Finding, ScanConfig, Detection
from ghostlight.utils.text_extract import extract_text_from_file
from ghostlight.utils.snippets import earliest_line_and_snippet
from ghostlight.utils.validation import is_binary_file
from ghostlight.utils.logging import get_logger
from .base import Scanner

logger = get_logger(__name__)

TEXT_EXTS = {".txt", ".md", ".csv", ".log", ".json", ".yaml", ".yml", ".xml", ".html", 
             ".js", ".py", ".java", ".cpp", ".c", ".h", ".go", ".rs", ".sh", ".sql"}
DOC_EXTS = {".pdf", ".docx", ".doc", ".xlsx", ".xls"}
SKIP_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico", ".mp4", ".avi", 
             ".mov", ".mp3", ".wav", ".zip", ".tar", ".gz", ".7z", ".rar", ".exe", ".dll"}


class FileSystemScanner(Scanner):
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        target_path = os.path.abspath(target)
        scanned_count = 0
        
        # Handle single file vs directory
        if os.path.isfile(target_path):
            files_to_scan = [(os.path.dirname(target_path), os.path.basename(target_path))]
            root = os.path.dirname(target_path)
        else:
            root = target_path
            files_to_scan = []
            for dirpath, dirnames, filenames in os.walk(root):
                # Skip hidden and common ignore directories
                dirnames[:] = [d for d in dirnames if not d.startswith('.') and d not in {'node_modules', '__pycache__', '.git', 'venv', '.venv'}]
                for name in filenames:
                    if not name.startswith('.'):
                        files_to_scan.append((dirpath, name))
        
        for dirpath, name in files_to_scan:
            
            path = os.path.join(dirpath, name)
            _, ext = os.path.splitext(name)
            ext_lower = ext.lower()
            
            # Skip known binary/media files
            if ext_lower in SKIP_EXTS:
                continue
            
            # Check file size
            try:
                size = os.path.getsize(path)
                if size > config.max_file_mb * 1024 * 1024:
                    logger.debug(f"Skipping large file: {path}")
                    continue
                if size == 0:
                    continue
            except Exception as e:
                logger.warning(f"Cannot access {path}: {e}")
                continue
            
            # Extract text based on file type
            try:
                if ext_lower in TEXT_EXTS:
                    with open(path, "rb") as fh:
                        data = fh.read(config.sample_bytes)
                    text = data.decode("utf-8", errors="ignore")
                elif ext_lower in DOC_EXTS:
                    text = extract_text_from_file(path, config.sample_bytes)
                else:
                    # Binary check for unknown extensions
                    if is_binary_file(path):
                        continue
                    with open(path, "rb") as fh:
                        data = fh.read(config.sample_bytes)
                    text = data.decode("utf-8", errors="ignore")
            except Exception as e:
                logger.debug(f"Failed to read {path}: {e}")
                continue
            
            scanned_count += 1

            labels = classify_text(text)
            detailed = classify_text_detailed(text)
            # Apply context-aware FP reduction (entropy-aware)
            filtered = apply_context_filters(detailed, text, min_entropy=config.min_entropy)
            # Optionally apply AI verification
            ai_mode = os.getenv("GHOSTLIGHT_AI_FILTER", "auto")
            if ai_mode != "off" and detailed:
                try:
                    logger.info(
                        f"AI filter enabled (mode={ai_mode}) for file {os.path.relpath(path, root) if root != path else name} with {len(filtered)} detections pre-AI"
                    )
                except Exception:
                    logger.debug("AI filter start log failed (fs)")
                ai_verified = []
                for bucket, pattern_name, matches in filtered:
                    matched_value = str(matches[0]) if matches else ""
                    is_tp, _reason = ai_classify_detection(
                        pattern_name=pattern_name,
                        matched_value=matched_value,
                        sample_text=text,
                        table_name=os.path.relpath(path, root) if root != path else name,
                        db_engine="filesystem",
                        column_names=None,
                        use_ai=ai_mode
                    )
                    if is_tp:
                        ai_verified.append((bucket, pattern_name, matches))
                filtered = ai_verified

            # Build classifications and detections from filtered results
            classifications = [f"{b}:{n}" for (b, n, _m) in filtered]
            detections = []
            for (b, name, matches) in filtered:
                detections.append(Detection(bucket=b, pattern_name=name, matches=matches, sample_text=text[:200]))
            # Compute exact earliest line and use that line as snippet
            earliest_line, snippet_line = earliest_line_and_snippet(text, filtered)
            # Strict mode: require >=2 detections or >=2 total matches
            if config.strict and not (len(detections) >= 2 or sum(len(d.matches) for d in detections) >= 2):
                continue
            if not classifications:
                continue

            sev, desc = score_severity(len(detections), sum(len(d.matches) for d in detections))
            sens, sens_factors = compute_sensitivity_score(detections)
            expo, expo_factors = compute_exposure_factor("filesystem", {})
            risk, risk_level = compute_risk(sens, expo)
            
            logger.info(f"Found {len(detections)} detection(s) in {os.path.relpath(path, root) if root != path else name}")
            
            yield Finding(
                id=f"fs:{os.path.relpath(path, root) if root != path else name}",
                resource=root,
                location=(f"{path}:{earliest_line}" if classifications else path),
                classifications=classifications,
                evidence=[Evidence(snippet=snippet_line)],
                severity=sev,
                data_source="filesystem",
                profile=root,
                bucket_name=None,
                file_path=os.path.relpath(path, root) if root != path else name,
                severity_description=desc,
                detections=detections,
                risk_score=risk,
                risk_level=risk_level,
                risk_factors=sens_factors + expo_factors,
            )
        
        logger.info(f"Filesystem scan complete. Scanned {scanned_count} files in {target_path}")


