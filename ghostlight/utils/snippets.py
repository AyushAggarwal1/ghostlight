from __future__ import annotations

from typing import List, Tuple, Optional


def _find_line_index(lines: List[str], needle: str) -> Optional[int]:
    """Return 0-based line index containing needle, else None."""
    if not needle:
        return None
    for idx, line in enumerate(lines):
        if needle in line:
            return idx
    return None


def earliest_line_and_snippet(text: str, filtered: List[Tuple[str, str, List[str]]]) -> Tuple[int, str]:
    """Compute earliest 1-based line number across matches and exact line snippet.

    If no match lines are found, returns (1, first line or first 200 chars).
    """
    if not text:
        return 1, ""
    lines = text.splitlines() or [text]
    earliest_idx: Optional[int] = None
    for _bucket, _name, matches in filtered:
        for m in matches:
            idx = _find_line_index(lines, m)
            if idx is not None:
                if earliest_idx is None or idx < earliest_idx:
                    earliest_idx = idx
    if earliest_idx is None:
        # Fallback: return first non-empty line or first 200 chars
        for i, l in enumerate(lines):
            if l.strip():
                return i + 1, l[:200]
        return 1, (text[:200])
    # Exact line content, trimmed to reasonable length
    line_text = lines[earliest_idx]
    return earliest_idx + 1, line_text[:500]


