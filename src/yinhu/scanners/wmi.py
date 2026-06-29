"""WMI event subscription persistence scanner."""

from __future__ import annotations

import subprocess

from .base import BaseScanner, ScanResult, Severity


def _run_cmd(args: list[str], timeout: int = 15) -> str:
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


class WMIScanner(BaseScanner):
    name = "WMI 持久化"
    description = "检测 WMI 事件订阅 (EventFilter / EventConsumer / Binding)"

    def scan(self) -> list[ScanResult]:
        results: list[ScanResult] = []

        queries = [
            ("EventFilter", "Get-WmiObject -Namespace root/subscription -Class __EventFilter | "
             "ForEach-Object { $_.Name + '|' + $_.Query }"),
            ("EventConsumer", "Get-WmiObject -Namespace root/subscription -Class __EventConsumer | "
             "ForEach-Object { $_.Name + '|' + $_.GetType().Name + '|' + "
             "$(if($_.CommandLineTemplate){$_.CommandLineTemplate}elseif($_.ScriptText){$_.ScriptText.Substring(0,[Math]::Min(200,$_.ScriptText.Length))}else{'(n/a)'}) }"),
            ("FilterToConsumerBinding", "Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding | "
             "ForEach-Object { $_.Filter + '|' + $_.Consumer }"),
        ]

        for category, ps_cmd in queries:
            output = _run_cmd(["powershell", "-NoProfile", "-Command", ps_cmd])

            for line in output.strip().splitlines():
                if not line.strip():
                    continue
                parts = line.split("|", 2)
                name = parts[0] if parts else "(unknown)"
                detail = parts[1] if len(parts) > 1 else ""
                extra = parts[2] if len(parts) > 2 else ""

                is_system = any(k in name.lower() for k in ["bvtfilter", "scm event", "wmi perfmon"])
                severity = Severity.SAFE if is_system else Severity.DANGER

                results.append(ScanResult(
                    name=f"[{category}] {name}",
                    detail=f"{detail} {extra}".strip(),
                    severity=severity,
                    properties={
                        "category": category,
                        "wmi_name": name,
                    },
                ))

        if not results:
            results.append(ScanResult(
                name="(无 WMI 事件订阅)",
                detail="未发现任何 WMI 持久化项",
                severity=Severity.SAFE,
                properties={},
            ))

        results.sort(key=lambda r: (r.severity == Severity.SAFE, r.name.lower()))
        return results
