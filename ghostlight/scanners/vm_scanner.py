from __future__ import annotations

import os
import stat
from typing import Iterable, List, Tuple

try:
    import paramiko  # type: ignore
except Exception:  # pragma: no cover
    paramiko = None

from ghostlight.classify.engine import classify_text, classify_text_detailed, score_severity
from ghostlight.risk.scoring import compute_sensitivity_score, compute_exposure_factor, compute_risk
from ghostlight.core.models import Evidence, Finding, ScanConfig, Detection
from ghostlight.utils.logging import get_logger
from .base import Scanner

logger = get_logger(__name__)

TEXT_EXTS = {".txt", ".md", ".csv", ".log", ".json", ".yaml", ".yml", ".xml", ".html", 
             ".js", ".py", ".java", ".cpp", ".c", ".h", ".go", ".rs", ".sh", ".sql"}
SKIP_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico", ".mp4", ".avi", 
             ".mov", ".mp3", ".wav", ".zip", ".tar", ".gz", ".7z", ".rar", ".exe", ".dll", ".so", ".o"}
SKIP_DIRS = {'node_modules', '__pycache__', '.git', 'venv', '.venv', '.cache', 'cache'}


class VMScanner(Scanner):
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        """
        Scan remote VM via SSH with support for recursive directory scanning.
        
        Target formats:
          - user@host:/path/to/file              (single file)
          - user@host:/path/to/file1,/file2      (multiple files)
          - user@host:/path/to/directory         (recursive directory scan)
          - user@host:/dir1,/dir2                (multiple directories)
        """
        if paramiko is None:
            logger.error("paramiko not available. Install with: pip install paramiko")
            return []
        
        try:
            auth, paths = target.split(":", 1)
            user, host = auth.split("@", 1)
            path_list = [p.strip() for p in paths.split(",") if p.strip()]
        except ValueError:
            logger.error(f"Invalid target format: {target}. Expected: user@host:/path1,/path2")
            return []

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            logger.info(f"Connecting to {host} as {user}...")
            ssh.connect(hostname=host, username=user, timeout=10)
        except Exception as e:
            logger.error(f"Failed to connect to {host}: {e}")
            return []

        sftp = ssh.open_sftp()
        scanned_count = 0
        
        try:
            # Collect all files to scan
            files_to_scan: List[Tuple[str, str]] = []
            
            for path in path_list:
                try:
                    attrs = sftp.stat(path)
                    if stat.S_ISDIR(attrs.st_mode):
                        # Recursive directory traversal
                        logger.info(f"Recursively scanning directory: {path}")
                        files_to_scan.extend(self._walk_remote_dir(sftp, path))
                    else:
                        # Single file
                        dirname = os.path.dirname(path) or "/"
                        basename = os.path.basename(path)
                        files_to_scan.append((dirname, basename))
                except Exception as e:
                    logger.warning(f"Cannot access {path}: {e}")
                    continue
            
            logger.info(f"Found {len(files_to_scan)} file(s) to scan")
            
            # Scan each file
            for dirpath, filename in files_to_scan:
                full_path = os.path.join(dirpath, filename)
                
                # Skip hidden files
                if filename.startswith('.'):
                    continue
                
                _, ext = os.path.splitext(filename)
                ext_lower = ext.lower()
                
                # Skip known binary/media files
                if ext_lower in SKIP_EXTS:
                    logger.debug(f"Skipping binary file: {full_path}")
                    continue
                
                try:
                    # Check file size
                    attrs = sftp.stat(full_path)
                    size = attrs.st_size
                    
                    if size > config.max_file_mb * 1024 * 1024:
                        logger.debug(f"Skipping large file: {full_path}")
                        continue
                    if size == 0:
                        continue
                    
                    # Read file content
                    with sftp.open(full_path, "r") as fh:
                        data = fh.read(config.sample_bytes)
                    
                    text = data.decode("utf-8", errors="ignore")
                    
                    # Check if file appears to be binary
                    if self._is_binary_text(text):
                        logger.debug(f"Skipping binary content: {full_path}")
                        continue
                    
                except Exception as e:
                    logger.debug(f"Failed to read {full_path}: {e}")
                    continue
                
                scanned_count += 1
                
                # Classify text
                labels = classify_text(text)
                detailed = classify_text_detailed(text)
                
                classifications = [
                    f"GDPR:{l}" for l in labels.get("GDPR", [])
                ] + [
                    f"HIPAA:{l}" for l in labels.get("HIPAA", [])
                ] + [
                    f"PCI:{l}" for l in labels.get("PCI", [])
                ] + [
                    f"SECRETS:{l}" for l in labels.get("SECRETS", [])
                ] + [
                    f"IP:{l}" for l in labels.get("IP", [])
                ]
                
                detections = [
                    Detection(bucket=b, pattern_name=name, matches=matches, sample_text=text[:200])
                    for (b, name, matches) in detailed
                ]
                
                if not classifications:
                    continue
                
                sev, desc = score_severity(len(detections), sum(len(d.matches) for d in detections))
                sens, sens_factors = compute_sensitivity_score(detections)
                expo, expo_factors = compute_exposure_factor("vm", {"host": host})
                risk, risk_level = compute_risk(sens, expo)
                
                logger.info(f"Found {len(detections)} detection(s) in {full_path}")
                
                yield Finding(
                    id=f"vm:{host}{full_path}",
                    resource=host,
                    location=f"ssh://{user}@{host}{full_path}",
                    classifications=classifications,
                    evidence=[Evidence(snippet=text[:200])],
                    severity=sev,
                    data_source="vm",
                    profile=f"{user}@{host}",
                    bucket_name=None,
                    file_path=full_path,
                    severity_description=desc,
                    detections=detections,
                    risk_score=risk,
                    risk_level=risk_level,
                    risk_factors=sens_factors + expo_factors,
                )
            
            logger.info(f"VM scan complete. Scanned {scanned_count} files on {host}")
            
        finally:
            sftp.close()
            ssh.close()
    
    def _walk_remote_dir(self, sftp, path: str) -> List[Tuple[str, str]]:
        """Recursively walk a remote directory via SFTP, similar to os.walk."""
        files = []
        
        try:
            entries = sftp.listdir_attr(path)
        except Exception as e:
            logger.warning(f"Cannot list directory {path}: {e}")
            return files
        
        for entry in entries:
            name = entry.filename
            full_path = os.path.join(path, name)
            
            # Skip hidden files and directories
            if name.startswith('.'):
                continue
            
            # Skip common ignore directories
            if name in SKIP_DIRS:
                continue
            
            try:
                if stat.S_ISDIR(entry.st_mode):
                    # Recursively scan subdirectory
                    files.extend(self._walk_remote_dir(sftp, full_path))
                elif stat.S_ISREG(entry.st_mode):
                    # Add file
                    files.append((path, name))
            except Exception as e:
                logger.debug(f"Error processing {full_path}: {e}")
                continue
        
        return files
    
    def _is_binary_text(self, text: str) -> bool:
        """Check if decoded text appears to be binary content."""
        if not text:
            return True
        # If more than 30% of characters are non-printable, consider it binary
        non_printable = sum(1 for c in text[:1000] if ord(c) < 32 and c not in '\n\r\t')
        return non_printable > len(text[:1000]) * 0.3


