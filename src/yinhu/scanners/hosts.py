"""Suspicious entries in the Windows hosts file."""

from __future__ import annotations

import ipaddress
import os
import re

from .base import BaseScanner, ScanResult, Severity


HOSTS_PATH = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"),
    "System32", "drivers", "etc", "hosts",
)

SUSPICIOUS_KEYWORDS = (
    "microsoft.com", "windowsupdate.com", "kaspersky", "360", "qq.com",
    "tencent", "alipay", "taobao", "google.com", "facebook.com",
    "github.com", "antivirus", "norton", "mcafee", "bitdefender",
)


class HostsScanner(BaseScanner):
    name = "Hosts 文件检查"
    description = "检测 hosts 文件中可疑的重定向条目"

    def scan(self) -> list[ScanResult]:
        results: list[ScanResult] = []
        if not os.path.exists(HOSTS_PATH):
            return results

        try:
            text = open(HOSTS_PATH, "r", encoding="utf-8", errors="ignore").read()
        except Exception as e:
            results.append(ScanResult(
                name="hosts 文件",
                detail=f"读取失败: {e}",
                severity=Severity.WARNING,
                properties={"source": "Hosts", "path": HOSTS_PATH},
            ))
            return results

        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = re.split(r"\s+", line, maxsplit=1)
            if len(parts) < 2:
                continue
            ip, host_part = parts[0], parts[1]
            host = host_part.split("#", 1)[0].strip()
            if not host:
                continue
            sev = self._classify(ip, host)
            results.append(ScanResult(
                name=host,
                detail=f"line {lineno}: {ip} → {host}",
                severity=sev,
                properties={"source": "Hosts", "path": HOSTS_PATH,
                            "ip": ip, "host": host, "line": lineno},
            ))

        return results

    @staticmethod
    def _classify(ip: str, host: str) -> Severity:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return Severity.WARNING

        loopback = addr.is_loopback
        host_l = host.lower()
        is_sensitive = any(k in host_l for k in SUSPICIOUS_KEYWORDS)

        if is_sensitive and loopback:
            return Severity.DANGER
        if is_sensitive:
            return Severity.DANGER
        if loopback:
            return Severity.SAFE
        return Severity.WARNING
