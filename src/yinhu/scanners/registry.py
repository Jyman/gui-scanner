"""Registry startup entry scanner."""

from __future__ import annotations

import os
import re
import stat
import winreg

from .base import BaseScanner, ScanResult, Severity

_REG_PATHS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (WOW64)"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce (WOW64)"),
]


def _resolve_path(raw: str) -> str | None:
    val = raw.strip()
    if m := re.match(r'^"([^"]+)"', val):
        return m.group(1)
    if val.startswith("@"):
        return None
    expanded = os.path.expandvars(val)
    if m := re.match(r'^"([^"]+)"', expanded):
        return m.group(1)
    if m := re.match(r'^[a-zA-Z]:\\[^\s]+\.[a-zA-Z]{1,4}', expanded):
        candidate = m.group(0)
        if os.path.exists(candidate):
            return candidate
    return None


class RegistryScanner(BaseScanner):
    name = "注册表启动项"
    description = "扫描 Run/RunOnce 注册表项，标记 Hidden/System 属性的目标文件"

    def scan(self) -> list[ScanResult]:
        results: list[ScanResult] = []

        for hive, subkey, label in _REG_PATHS:
            try:
                key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
            except OSError:
                continue

            try:
                i = 0
                while True:
                    try:
                        vname, vdata, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    i += 1

                    raw_str = str(vdata) if not isinstance(vdata, bytes) else "[REG_BINARY]"
                    target = _resolve_path(raw_str)

                    is_hidden = False
                    is_system = False
                    if target and os.path.exists(target):
                        try:
                            attrs = os.stat(target).st_file_attributes  # type: ignore[attr-defined]
                            is_hidden = bool(attrs & stat.FILE_ATTRIBUTE_HIDDEN)
                            is_system = bool(attrs & stat.FILE_ATTRIBUTE_SYSTEM)
                        except OSError:
                            pass

                    flags = []
                    if is_hidden:
                        flags.append("H")
                    if is_system:
                        flags.append("S")

                    severity = Severity.DANGER if flags else Severity.SAFE
                    results.append(ScanResult(
                        name=vname or "(default)",
                        detail=f"[{label}] {raw_str}",
                        severity=severity,
                        properties={
                            "source": label,
                            "raw_value": raw_str,
                            "resolved_path": target or "(unresolved)",
                            "flags": "/".join(flags),
                        },
                    ))
            finally:
                winreg.CloseKey(key)

        results.sort(key=lambda r: (r.severity != Severity.DANGER, r.name.lower()))
        return results
