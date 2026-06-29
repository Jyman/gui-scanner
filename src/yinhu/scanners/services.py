"""Service anomaly scanner — flags unsigned or non-standard-path services."""

from __future__ import annotations

import os
import re
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

_STANDARD_PREFIXES = [
    os.environ.get("SystemRoot", r"C:\Windows"),
    os.environ.get("ProgramFiles", r"C:\Program Files"),
    os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    os.environ.get("ProgramW6432", r"C:\Program Files"),
]


def _is_standard_path(path: str) -> bool:
    path_lower = path.lower()
    for prefix in _STANDARD_PREFIXES:
        if prefix and path_lower.startswith(prefix.lower()):
            return True
    return False


def _extract_exe_path(image_path: str) -> str | None:
    val = image_path.strip()
    if m := re.match(r'^"([^"]+)"', val):
        return m.group(1)
    if m := re.match(r'^[a-zA-Z]:\\[^\s]+\.[a-zA-Z]{1,4}', val):
        return m.group(0)
    expanded = os.path.expandvars(val)
    if m := re.match(r'^[a-zA-Z]:\\[^\s]+\.[a-zA-Z]{1,4}', expanded):
        return m.group(0)
    return None


class ServiceScanner(BaseScanner):
    name = "服务异常检测"
    description = "检测非标准路径或无数字签名的可执行服务文件"

    def scan(self) -> list[ScanResult]:
        results: list[ScanResult] = []

        output = _run_cmd(
            ["powershell", "-NoProfile", "-Command",
             "Get-WmiObject Win32_Service | ForEach-Object {"
             " $n = if($_.Name){$_.Name}else{''};"
             " $d = if($_.DisplayName){$_.DisplayName}else{''};"
             " $s = if($_.State){$_.State}else{''};"
             " $p = if($_.PathName){$_.PathName}else{''};"
             " $m = if($_.StartMode){$_.StartMode}else{''};"
             " \"$n|$d|$s|$p|$m\" }"],
            timeout=60,
        )

        if not output.strip():
            return results

        for line in output.strip().splitlines():
            parts = line.split("|", 4)
            if len(parts) < 5:
                continue
            svc_name, display_name, state, image_path, start_mode = parts

            if not image_path.strip() or image_path.strip() == "None":
                continue

            exe_path = _extract_exe_path(image_path)
            is_standard = _is_standard_path(exe_path) if exe_path else True
            exe_exists = exe_path is not None and os.path.exists(exe_path)

            if not exe_path or not exe_exists:
                severity = Severity.WARNING
            elif not is_standard:
                severity = Severity.WARNING
            else:
                severity = Severity.SAFE

            results.append(ScanResult(
                name=display_name or svc_name,
                detail=image_path,
                severity=severity,
                properties={
                    "service_name": svc_name,
                    "state": state,
                    "start_mode": start_mode,
                    "exe_path": exe_path or "(unresolved)",
                    "is_standard_path": is_standard,
                    "exe_exists": exe_exists,
                },
            ))

        results.sort(key=lambda r: (r.severity == Severity.SAFE, r.name.lower()))
        return results
