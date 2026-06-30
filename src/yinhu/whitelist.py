"""Persistent whitelist — paths or names treated as SAFE after matching."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable

from .scanners.base import ScanResult, Severity


def _store_path() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    p = Path(base) / "yinhu"
    p.mkdir(parents=True, exist_ok=True)
    return p / "whitelist.json"


def _key_for(item: ScanResult) -> str:
    path = item.properties.get("path") or item.properties.get("ResolvedPath")
    if path:
        return str(path).strip().lower()
    return f"name::{item.name}".lower()


class Whitelist:
    def __init__(self) -> None:
        self._path = _store_path()
        self._entries: set[str] = set()
        self._load()

    def _load(self) -> None:
        try:
            if self._path.exists():
                data = json.loads(self._path.read_text(encoding="utf-8"))
                self._entries = {str(x).strip().lower() for x in data if x}
        except Exception:
            self._entries = set()

    def _save(self) -> None:
        try:
            self._path.write_text(
                json.dumps(sorted(self._entries), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

    def all(self) -> list[str]:
        return sorted(self._entries)

    def contains(self, item: ScanResult) -> bool:
        return _key_for(item) in self._entries

    def add(self, item: ScanResult) -> None:
        self._entries.add(_key_for(item))
        self._save()

    def remove(self, item: ScanResult) -> None:
        self._entries.discard(_key_for(item))
        self._save()

    def apply(self, items: Iterable[ScanResult]) -> list[ScanResult]:
        out: list[ScanResult] = []
        for item in items:
            if self.contains(item) and item.severity != Severity.SAFE:
                item.severity = Severity.SAFE
                if "[白名单]" not in item.detail:
                    item.detail = f"{item.detail}  [白名单]"
            out.append(item)
        return out
