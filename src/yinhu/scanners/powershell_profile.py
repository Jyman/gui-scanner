"""PowerShell profile / module persistence checks."""

from __future__ import annotations

import os
import re
from pathlib import Path

from .base import BaseScanner, ScanResult, Severity


def _profile_paths() -> list[Path]:
    paths: list[Path] = []
    docs = Path(os.environ.get("USERPROFILE", "")) / "Documents"
    for shell in ("WindowsPowerShell", "PowerShell"):
        paths.append(docs / shell / "Microsoft.PowerShell_profile.ps1")
        paths.append(docs / shell / "profile.ps1")
    sysroot = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    paths.append(sysroot / "System32" / "WindowsPowerShell" / "v1.0" / "profile.ps1")
    paths.append(sysroot / "System32" / "WindowsPowerShell" / "v1.0" / "Microsoft.PowerShell_profile.ps1")
    return paths


SUSPICIOUS_PATTERNS = [
    (r"\bIEX\b|\bInvoke-Expression\b", "动态执行字符串"),
    (r"\bDownloadString\b|\bInvoke-WebRequest\b|\bcurl\b|\bwget\b", "网络下载"),
    (r"-enc(odedcommand)?\b", "Base64 编码命令"),
    (r"\bAdd-MpPreference\b.*ExclusionPath", "添加 Defender 排除路径"),
    (r"\bSet-MpPreference\b.*Disable", "禁用 Defender"),
    (r"\bStart-Process\b.*-WindowStyle\s+Hidden", "隐藏窗口启动进程"),
    (r"\bSchTasks\b|\bRegister-ScheduledTask\b", "创建计划任务"),
    (r"\bNew-Item\b.*HKLM.*Run\b|\bSet-ItemProperty\b.*Run\b", "注册表自启动"),
    (r"FromBase64String", "Base64 解码"),
]


class PowerShellProfileScanner(BaseScanner):
    name = "PowerShell 持久化"
    description = "检查 PowerShell profile 中的可疑命令模式"

    def scan(self) -> list[ScanResult]:
        results: list[ScanResult] = []
        any_exists = False

        for path in _profile_paths():
            if not path.exists():
                continue
            any_exists = True
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                results.append(ScanResult(
                    name=path.name,
                    detail=f"读取失败: {e}",
                    severity=Severity.WARNING,
                    properties={"source": "PSProfile", "path": str(path)},
                ))
                continue

            hits: list[str] = []
            for pattern, label in SUSPICIOUS_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    hits.append(label)

            if hits:
                results.append(ScanResult(
                    name=path.name,
                    detail=f"{path}  · 命中: {' / '.join(hits)}",
                    severity=Severity.DANGER,
                    properties={"source": "PSProfile", "path": str(path),
                                "patterns": ";".join(hits)},
                ))
            else:
                size = len(text.strip())
                results.append(ScanResult(
                    name=path.name,
                    detail=f"{path}  · {size} 字节，未命中可疑模式",
                    severity=Severity.SAFE,
                    properties={"source": "PSProfile", "path": str(path)},
                ))

        if not any_exists:
            results.append(ScanResult(
                name="无 PowerShell profile",
                detail="系统中未发现任何 PowerShell profile 文件",
                severity=Severity.SAFE,
                properties={"source": "PSProfile"},
            ))
        return results
