import customtkinter as ctk
import threading
from datetime import datetime

from .theme import COLORS, apply_theme
from .scan_panel import ScanPanel
from ..scanners.base import ScanResult, Severity
from ..scanners.process import ProcessScanner
from ..scanners.registry import RegistryScanner
from ..scanners.tasks import TaskScanner
from ..scanners.services import ServiceScanner
from ..scanners.wmi import WMIScanner
from ..report.html_export import export_html_report


class MainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        apply_theme()
        self.title("隐虎 - 系统安全扫描器")
        self.geometry("1100x700")
        self.minsize(900, 600)
        self.configure(fg_color=COLORS["bg"])

        self.scanners = [
            ProcessScanner(),
            RegistryScanner(),
            TaskScanner(),
            ServiceScanner(),
            WMIScanner(),
        ]
        self.results = {}
        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main_area()

    def _build_sidebar(self):
        sidebar = ctk.CTkFrame(self, width=200, fg_color=COLORS["sidebar"], corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsw")
        sidebar.grid_propagate(False)

        title = ctk.CTkLabel(
            sidebar, text="隐 虎", font=ctk.CTkFont(size=22, weight="bold"),
            text_color=COLORS["accent"]
        )
        title.pack(pady=(24, 4))

        subtitle = ctk.CTkLabel(
            sidebar, text="系统安全扫描器", font=ctk.CTkFont(size=12),
            text_color=COLORS["text_dim"]
        )
        subtitle.pack(pady=(0, 24))

        self.nav_buttons = []
        icons = ["🔍", "📋", "⏱", "⚙", "🔗"]
        for i, scanner in enumerate(self.scanners):
            btn = ctk.CTkButton(
                sidebar, text=f" {icons[i]}  {scanner.name}",
                font=ctk.CTkFont(size=13),
                fg_color="transparent", hover_color=COLORS["card"],
                text_color=COLORS["text"], anchor="w", height=38,
                command=lambda idx=i: self._on_nav_click(idx)
            )
            btn.pack(fill="x", padx=8, pady=2)
            self.nav_buttons.append(btn)

        spacer = ctk.CTkFrame(sidebar, fg_color="transparent")
        spacer.pack(fill="both", expand=True)

        self.scan_all_btn = ctk.CTkButton(
            sidebar, text="全 部 扫 描", font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=COLORS["accent"], hover_color="#5d8ae6",
            text_color="#1a1b26", height=40, corner_radius=8,
            command=self._scan_all
        )
        self.scan_all_btn.pack(fill="x", padx=12, pady=(0, 8))

        self.export_btn = ctk.CTkButton(
            sidebar, text="导出报告", font=ctk.CTkFont(size=13),
            fg_color=COLORS["card"], hover_color="#2f3549",
            text_color=COLORS["text"], height=34, corner_radius=8,
            command=self._export_report
        )
        self.export_btn.pack(fill="x", padx=12, pady=(0, 16))

    def _build_main_area(self):
        self.main_frame = ctk.CTkFrame(self, fg_color=COLORS["bg"], corner_radius=0)
        self.main_frame.grid(row=0, column=1, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        self._build_stats_bar()

        self.scan_panel = ScanPanel(self.main_frame)
        self.scan_panel.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 8))

        self._build_status_bar()

    def _build_stats_bar(self):
        stats_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent", height=80)
        stats_frame.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 8))
        stats_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.stat_cards = {}
        card_defs = [
            ("total", "扫描项目", "0", COLORS["text"]),
            ("safe", "安全", "0", COLORS["safe"]),
            ("warn", "可疑", "0", COLORS["warn"]),
            ("danger", "危险", "0", COLORS["danger"]),
        ]
        for col, (key, label, val, color) in enumerate(card_defs):
            card = ctk.CTkFrame(stats_frame, fg_color=COLORS["card"], corner_radius=10, height=70)
            card.grid(row=0, column=col, sticky="ew", padx=4)
            card.grid_propagate(False)

            num_label = ctk.CTkLabel(
                card, text=val, font=ctk.CTkFont(size=24, weight="bold"),
                text_color=color
            )
            num_label.pack(pady=(12, 0))

            desc_label = ctk.CTkLabel(
                card, text=label, font=ctk.CTkFont(size=11),
                text_color=COLORS["text_dim"]
            )
            desc_label.pack()

            self.stat_cards[key] = num_label

    def _build_status_bar(self):
        status_frame = ctk.CTkFrame(self.main_frame, fg_color=COLORS["card"], height=30, corner_radius=0)
        status_frame.grid(row=2, column=0, sticky="ew")
        status_frame.grid_propagate(False)

        self.status_label = ctk.CTkLabel(
            status_frame, text="就绪", font=ctk.CTkFont(size=11),
            text_color=COLORS["text_dim"]
        )
        self.status_label.pack(side="left", padx=12, pady=4)

        self.time_label = ctk.CTkLabel(
            status_frame, text="", font=ctk.CTkFont(size=11),
            text_color=COLORS["text_dim"]
        )
        self.time_label.pack(side="right", padx=12, pady=4)

    def _on_nav_click(self, idx):
        scanner = self.scanners[idx]
        self._run_scanner(scanner)

    def _scan_all(self):
        self.scan_all_btn.configure(state="disabled", text="扫描中...")
        self.status_label.configure(text="正在执行全部扫描...")
        self.results.clear()

        def do_scan():
            start = datetime.now()
            all_items = []
            for scanner in self.scanners:
                items = scanner.scan()
                self.results[scanner.name] = items
                all_items.extend(items)
            elapsed = (datetime.now() - start).total_seconds()
            self.after(0, lambda: self._on_scan_complete(all_items, elapsed))

        threading.Thread(target=do_scan, daemon=True).start()

    def _run_scanner(self, scanner):
        self.status_label.configure(text=f"正在扫描: {scanner.name}...")

        def do_scan():
            start = datetime.now()
            items = scanner.scan()
            self.results[scanner.name] = items
            elapsed = (datetime.now() - start).total_seconds()
            self.after(0, lambda: self._on_scan_complete(items, elapsed))

        threading.Thread(target=do_scan, daemon=True).start()

    def _on_scan_complete(self, items: list[ScanResult], elapsed):
        self.scan_all_btn.configure(state="normal", text="全 部 扫 描")

        total = len(items)
        danger = sum(1 for i in items if i.severity == Severity.DANGER)
        warn = sum(1 for i in items if i.severity == Severity.WARNING)
        safe = total - danger - warn

        self.stat_cards["total"].configure(text=str(total))
        self.stat_cards["safe"].configure(text=str(safe))
        self.stat_cards["warn"].configure(text=str(warn))
        self.stat_cards["danger"].configure(text=str(danger))

        self.status_label.configure(text=f"扫描完成 — 共 {total} 项")
        self.time_label.configure(text=f"耗时 {elapsed:.2f}s")

        self.scan_panel.display(items)

    def _export_report(self):
        if not self.results:
            self.status_label.configure(text="请先执行扫描")
            return
        path = export_html_report(self.results)
        self.status_label.configure(text=f"报告已导出: {path}")
