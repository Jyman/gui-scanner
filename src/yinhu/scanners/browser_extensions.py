"""Enumerate installed Chromium-based and Firefox browser extensions."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .base import BaseScanner, ScanResult, Severity


LOCAL_APP = Path(os.environ.get("LOCALAPPDATA", ""))
ROAMING = Path(os.environ.get("APPDATA", ""))


CHROMIUM_PATHS = [
    LOCAL_APP / "Google" / "Chrome" / "User Data",
    LOCAL_APP / "Microsoft" / "Edge" / "User Data",
    LOCAL_APP / "BraveSoftware" / "Brave-Browser" / "User Data",
    LOCAL_APP / "Chromium" / "User Data",
]

FIREFOX_PROFILES = ROAMING / "Mozilla" / "Firefox" / "Profiles"


class BrowserExtensionScanner(BaseScanner):
    name = "浏览器扩展"
    description = "枚举 Chrome / Edge / Brave / Firefox 已安装扩展"

    def scan(self) -> list[ScanResult]:
        results: list[ScanResult] = []
        results.extend(self._chromium())
        results.extend(self._firefox())

        if not results:
            results.append(ScanResult(
                name="未发现扩展",
                detail="未找到任何浏览器扩展（或浏览器未安装）",
                severity=Severity.SAFE,
                properties={"source": "Browser"},
            ))
        return results

    def _chromium(self) -> list[ScanResult]:
        out: list[ScanResult] = []
        for root in CHROMIUM_PATHS:
            if not root.exists():
                continue
            browser = root.parent.name
            for profile_dir in root.iterdir():
                if not profile_dir.is_dir():
                    continue
                ext_root = profile_dir / "Extensions"
                if not ext_root.exists():
                    continue
                for ext_id in ext_root.iterdir():
                    if not ext_id.is_dir():
                        continue
                    versions = [v for v in ext_id.iterdir() if v.is_dir()]
                    if not versions:
                        continue
                    latest = sorted(versions, key=lambda p: p.name)[-1]
                    manifest = latest / "manifest.json"
                    name = ext_id.name
                    sev = Severity.SAFE
                    perms: list[str] = []
                    if manifest.exists():
                        try:
                            data = json.loads(manifest.read_text(encoding="utf-8", errors="ignore"))
                            name = data.get("name", name)
                            if isinstance(name, str) and name.startswith("__MSG_"):
                                name = ext_id.name
                            perms = data.get("permissions", []) or []
                            host_perms = data.get("host_permissions", []) or []
                            if any(p in perms for p in (
                                "<all_urls>", "tabs", "webRequest", "webRequestBlocking",
                                "cookies", "history", "debugger",
                            )):
                                sev = Severity.WARNING
                            if "<all_urls>" in host_perms or "*://*/*" in host_perms:
                                sev = Severity.WARNING
                        except Exception:
                            pass
                    out.append(ScanResult(
                        name=str(name),
                        detail=f"{browser} / {profile_dir.name}  · {ext_id.name}",
                        severity=sev,
                        properties={
                            "source": "Browser",
                            "path": str(latest),
                            "browser": browser,
                            "ext_id": ext_id.name,
                            "permissions": ",".join(perms[:8]),
                        },
                    ))
        return out

    def _firefox(self) -> list[ScanResult]:
        out: list[ScanResult] = []
        if not FIREFOX_PROFILES.exists():
            return out
        for profile in FIREFOX_PROFILES.iterdir():
            ext_json = profile / "extensions.json"
            if not ext_json.exists():
                continue
            try:
                data = json.loads(ext_json.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                continue
            for addon in data.get("addons", []):
                if addon.get("type") != "extension":
                    continue
                name = addon.get("defaultLocale", {}).get("name") or addon.get("id", "?")
                path = addon.get("path", "")
                out.append(ScanResult(
                    name=name,
                    detail=f"Firefox / {profile.name}  · {addon.get('id', '')}",
                    severity=Severity.SAFE,
                    properties={
                        "source": "Browser", "path": path,
                        "browser": "Firefox", "ext_id": addon.get("id", ""),
                    },
                ))
        return out
