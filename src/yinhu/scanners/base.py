"""Base scanner interface."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    SAFE = "safe"
    WARNING = "warning"
    DANGER = "danger"


@dataclass
class ScanResult:
    name: str
    detail: str
    severity: Severity
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanReport:
    scanner_name: str
    elapsed_ms: float
    results: list[ScanResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def safe_count(self) -> int:
        return sum(1 for r in self.results if r.severity == Severity.SAFE)

    @property
    def warning_count(self) -> int:
        return sum(1 for r in self.results if r.severity == Severity.WARNING)

    @property
    def danger_count(self) -> int:
        return sum(1 for r in self.results if r.severity == Severity.DANGER)


class BaseScanner(ABC):
    name: str = "Unknown"
    description: str = ""

    def run(self) -> ScanReport:
        start = time.perf_counter()
        results = self.scan()
        elapsed = (time.perf_counter() - start) * 1000
        return ScanReport(scanner_name=self.name, elapsed_ms=elapsed, results=results)

    @abstractmethod
    def scan(self) -> list[ScanResult]:
        ...
