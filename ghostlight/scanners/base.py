from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable, List

from ghostlight.core.models import Finding, ScanConfig


class Scanner(ABC):
    @abstractmethod
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        raise NotImplementedError

    def scan_list(self, target: str, config: ScanConfig) -> List[Finding]:
        return list(self.scan(target, config))


