"""Scheduled task scanner — detects non-Microsoft hidden tasks."""

from __future__ import annotations

import subprocess

from .base import BaseScanner, ScanResult, Severity


def _run_cmd(args: list[str], timeout: int = 30) -> str:
    try:
        raw = subprocess.check_output(args, stderr=subprocess.DEVNULL, timeout=timeout)
        for enc in ("utf-8", "gbk", "cp936", "latin-1"):
            try:
                return raw.decode(enc)
            except (UnicodeDecodeError, LookupError):
                continue
        return raw.decode("utf-8", errors="replace")
    except (subprocess.SubprocessError, OSError):
        return ""


class TaskScanner(BaseScanner):
    name = "计划任务扫描"
    description = "检测非 Microsoft 的隐藏计划任务"

    def scan(self) -> list[ScanResult]:
        results: list[ScanResult] = []

        output = _run_cmd(["powershell", "-NoProfile", "-Command",
            "Get-ScheduledTask | ForEach-Object {"
            " $name = if($_.TaskName){$_.TaskName}else{''};"
            " $path = if($_.TaskPath){$_.TaskPath}else{''};"
            " $state = if($_.State){$_.State}else{''};"
            " $exe = if($_.Actions.Execute){$_.Actions.Execute -join ';'}else{''};"
            " \"$name|$path|$state|$exe\" }"])

        if not output.strip():
            return results

        for line in output.strip().splitlines():
            parts = line.split("|", 3)
            if len(parts) < 4:
                continue
            name, path, state, exe = parts
            if not name.strip():
                continue
            is_ms = (path or "").strip("\\").startswith("Microsoft")
            severity = Severity.SAFE if is_ms else Severity.WARNING
            results.append(ScanResult(
                name=name.strip(),
                detail=f"{path} → {exe}",
                severity=severity,
                properties={
                    "task_path": path,
                    "state": state,
                    "action": exe,
                    "is_microsoft": is_ms,
                },
            ))

        results.sort(key=lambda r: (r.severity == Severity.SAFE, r.name.lower()))
        return results
