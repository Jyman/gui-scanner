"""DLL injection heuristics: DLLs loaded from non-system paths into common targets."""

from __future__ import annotations

import os
import psutil

from .base import BaseScanner, ScanResult, Severity


TARGET_PROCESSES = {
    "explorer.exe", "winlogon.exe", "lsass.exe", "services.exe",
    "svchost.exe", "csrss.exe", "smss.exe", "spoolsv.exe",
    "chrome.exe", "msedge.exe", "firefox.exe",
}

TRUSTED_DIRS = (
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\winsxs",
    r"c:\windows\servicing",
    r"c:\program files",
    r"c:\program files (x86)",
)


def _is_trusted_dir(path: str) -> bool:
    p = path.lower()
    return any(p.startswith(d) for d in TRUSTED_DIRS)


class DLLInjectionScanner(BaseScanner):
    name = "DLL 注入检测"
    description = "检测系统/浏览器关键进程中加载的非系统目录 DLL"

    def scan(self) -> list[ScanResult]:
        results: list[ScanResult] = []
        seen: set[tuple[int, str]] = set()

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pname = (proc.info["name"] or "").lower()
                if pname not in TARGET_PROCESSES:
                    continue
                try:
                    maps = proc.memory_maps()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

                for m in maps:
                    path = (m.path or "").strip()
                    if not path.lower().endswith(".dll"):
                        continue
                    if _is_trusted_dir(path):
                        continue
                    key = (proc.info["pid"], path.lower())
                    if key in seen:
                        continue
                    seen.add(key)

                    results.append(ScanResult(
                        name=os.path.basename(path),
                        detail=f"{pname} (pid {proc.info['pid']}) ← {path}",
                        severity=Severity.DANGER,
                        properties={
                            "source": "DLL",
                            "path": path,
                            "pid": proc.info["pid"],
                            "process": pname,
                        },
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not results:
            results.append(ScanResult(
                name="无异常 DLL",
                detail="系统关键进程未发现非信任目录 DLL 加载",
                severity=Severity.SAFE,
                properties={"source": "DLL"},
            ))
        return results
