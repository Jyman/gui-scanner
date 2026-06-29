"""Hidden/System attribute process scanner."""

from __future__ import annotations

import os
import stat

import psutil

from .base import BaseScanner, ScanResult, Severity


class ProcessScanner(BaseScanner):
    name = "隐藏进程扫描"
    description = "检测运行进程中带有 Hidden/System 文件属性的可执行文件"

    def scan(self) -> list[ScanResult]:
        results: list[ScanResult] = []
        seen_paths: set[str] = set()

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                exe = proc.info["exe"]
                if not exe or exe in seen_paths:
                    continue
                seen_paths.add(exe)

                attrs = os.stat(exe).st_file_attributes  # type: ignore[attr-defined]
                is_hidden = bool(attrs & stat.FILE_ATTRIBUTE_HIDDEN)
                is_system = bool(attrs & stat.FILE_ATTRIBUTE_SYSTEM)

                if is_hidden or is_system:
                    flags = []
                    if is_hidden:
                        flags.append("H")
                    if is_system:
                        flags.append("S")

                    results.append(ScanResult(
                        name=proc.info["name"] or "unknown",
                        detail=exe,
                        severity=Severity.DANGER,
                        properties={
                            "pid": proc.info["pid"],
                            "flags": "/".join(flags),
                            "path": exe,
                        },
                    ))
                else:
                    results.append(ScanResult(
                        name=proc.info["name"] or "unknown",
                        detail=exe,
                        severity=Severity.SAFE,
                        properties={
                            "pid": proc.info["pid"],
                            "flags": "",
                            "path": exe,
                        },
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue

        results.sort(key=lambda r: (r.severity != Severity.DANGER, r.name.lower()))
        return results
