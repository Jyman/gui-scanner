"""Suspicious outbound network connections."""

from __future__ import annotations

import ipaddress

import psutil

from .base import BaseScanner, ScanResult, Severity


SUSPICIOUS_PROCESSES = {
    "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe",
}

HIGH_RISK_PORTS = {4444, 5555, 6666, 7777, 8888, 31337, 1337, 1080}


class NetworkScanner(BaseScanner):
    name = "网络连接检查"
    description = "检测异常的网络外连：可疑进程、高危端口、外部 ESTABLISHED 连接"

    def scan(self) -> list[ScanResult]:
        results: list[ScanResult] = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, RuntimeError):
            return [ScanResult(
                name="权限不足",
                detail="读取网络连接需要管理员权限",
                severity=Severity.WARNING,
                properties={"source": "Network"},
            )]

        for c in conns:
            if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
                continue

            try:
                addr = ipaddress.ip_address(c.raddr.ip)
            except ValueError:
                continue
            if addr.is_loopback or addr.is_link_local:
                continue
            is_private = addr.is_private

            pname = "unknown"
            exe = ""
            if c.pid:
                try:
                    p = psutil.Process(c.pid)
                    pname = (p.name() or "").lower()
                    exe = p.exe() or ""
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            sev = Severity.SAFE
            reasons: list[str] = []
            if pname in SUSPICIOUS_PROCESSES:
                sev = Severity.DANGER
                reasons.append(f"可疑进程 {pname}")
            if c.raddr.port in HIGH_RISK_PORTS:
                sev = Severity.DANGER
                reasons.append(f"高危端口 {c.raddr.port}")
            if sev == Severity.SAFE and not is_private:
                sev = Severity.SAFE

            detail = f"{c.raddr.ip}:{c.raddr.port}  ←  {pname} (pid {c.pid})"
            if reasons:
                detail += "  · " + " / ".join(reasons)

            results.append(ScanResult(
                name=f"{c.raddr.ip}:{c.raddr.port}",
                detail=detail,
                severity=sev,
                properties={
                    "source": "Network", "pid": c.pid, "path": exe,
                    "raddr": f"{c.raddr.ip}:{c.raddr.port}",
                    "process": pname,
                },
            ))

        results.sort(key=lambda r: (r.severity != Severity.DANGER, r.name))
        return results
