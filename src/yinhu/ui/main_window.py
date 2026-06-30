import customtkinter as ctk
import threading
import os
import subprocess
import urllib.parse
import webbrowser
from datetime import datetime

from .context_menu import ContextMenu

from .theme import COLORS, apply_theme
from .scan_panel import ScanPanel
from ..scanners.base import ScanResult, Severity
from ..scanners.process import ProcessScanner
from ..scanners.registry import RegistryScanner
from ..scanners.tasks import TaskScanner
from ..scanners.services import ServiceScanner
from ..scanners.wmi import WMIScanner
from ..scanners.hosts import HostsScanner
from ..scanners.network import NetworkScanner
from ..scanners.dll_injection import DLLInjectionScanner
from ..scanners.browser_extensions import BrowserExtensionScanner
from ..scanners.powershell_profile import PowerShellProfileScanner
from ..report.html_export import export_html_report
from ..whitelist import Whitelist


APP_TITLE = "系统危险排查"


class MainWindow(ctk.CTk):
    def __init__(self, is_admin: bool = True, on_elevate=None):
        super().__init__()
        apply_theme()
        self.title(APP_TITLE)
        self.geometry("1100x700")
        self.minsize(900, 600)
        self.configure(fg_color=COLORS["bg"])
        self._set_window_icon()

        self._is_admin = is_admin
        self._on_elevate = on_elevate
        self.whitelist = Whitelist()
        self._active_nav: int | None = None

        self.scanners = [
            ProcessScanner(),
            RegistryScanner(),
            TaskScanner(),
            ServiceScanner(),
            WMIScanner(),
            DLLInjectionScanner(),
            NetworkScanner(),
            HostsScanner(),
            BrowserExtensionScanner(),
            PowerShellProfileScanner(),
        ]
        self.results: dict[str, list[ScanResult]] = {}
        self._current_items: list[ScanResult] = []
        self._active_filter: str | None = None

        self._build_ui()

    def _set_window_icon(self):
        import sys, os
        if getattr(sys, "frozen", False):
            base = sys._MEIPASS
        else:
            base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
        ico = os.path.join(base, "assets", "yinhu.ico")
        if os.path.exists(ico):
            try:
                self.iconbitmap(ico)
            except Exception:
                pass

    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main_area()

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=210, fg_color=COLORS["sidebar"], corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsw")
        self.sidebar.grid_propagate(False)

        self.title_label = ctk.CTkLabel(
            self.sidebar, text="系统危险排查",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=COLORS["accent"]
        )
        self.title_label.pack(pady=(24, 4))

        self.subtitle_label = ctk.CTkLabel(
            self.sidebar, text="System Threat Inspector",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["text_dim"]
        )
        self.subtitle_label.pack(pady=(0, 20))

        self.nav_buttons = []
        icons = ["🔍", "📋", "⏱", "⚙", "🔗", "🧬", "🌐", "📡", "🧩", "💠"]
        for i, scanner in enumerate(self.scanners):
            btn = ctk.CTkButton(
                self.sidebar, text=f"  {icons[i]}   {scanner.name}",
                font=ctk.CTkFont(size=13),
                fg_color="transparent", hover_color=COLORS["hover"],
                text_color=COLORS["text"], anchor="w", height=36,
                corner_radius=8,
                command=lambda idx=i: self._on_nav_click(idx)
            )
            btn.pack(fill="x", padx=10, pady=2)
            self.nav_buttons.append(btn)

        spacer = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        spacer.pack(fill="both", expand=True)

        self.scan_all_btn = ctk.CTkButton(
            self.sidebar, text="全 部 扫 描",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=COLORS["accent"], hover_color=COLORS["accent_hover"],
            text_color=COLORS["btn_text"], height=40, corner_radius=8,
            command=self._scan_all
        )
        self.scan_all_btn.pack(fill="x", padx=12, pady=(0, 8))

        self.export_btn = ctk.CTkButton(
            self.sidebar, text="导出报告", font=ctk.CTkFont(size=13),
            fg_color=COLORS["card"], hover_color=COLORS["hover"],
            text_color=COLORS["text"], height=34, corner_radius=8,
            command=self._export_report
        )
        self.export_btn.pack(fill="x", padx=12, pady=(0, 16))

    def _build_main_area(self):
        self.main_frame = ctk.CTkFrame(self, fg_color=COLORS["bg"], corner_radius=0)
        self.main_frame.grid(row=0, column=1, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(2, weight=1)

        self._build_admin_banner()
        self._build_stats_bar()

        self.scan_panel = ScanPanel(self.main_frame, on_row_right_click=self._show_row_menu)
        self.scan_panel.grid(row=2, column=0, sticky="nsew", padx=16, pady=(0, 8))

        self._build_status_bar()

    def _build_admin_banner(self):
        if self._is_admin:
            return
        banner = ctk.CTkFrame(self.main_frame, fg_color=COLORS["warn"],
                              corner_radius=8, height=46)
        banner.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 0))
        banner.grid_propagate(False)
        banner.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            banner,
            text="⚠  当前为受限模式：未以管理员身份运行，部分扫描结果可能不完整",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#ffffff",
        ).grid(row=0, column=0, sticky="w", padx=14, pady=10)

        ctk.CTkButton(
            banner, text="重启提权", width=88, height=28,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#ffffff", hover_color="#f1f3fa",
            text_color=COLORS["warn"], corner_radius=6,
            command=self._do_elevate,
        ).grid(row=0, column=1, sticky="e", padx=12, pady=8)

    def _do_elevate(self):
        if self._on_elevate:
            self._on_elevate()

    def _build_stats_bar(self):
        self.stats_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent", height=82)
        top_pad = 8 if not self._is_admin else 16
        self.stats_frame.grid(row=1, column=0, sticky="ew", padx=16, pady=(top_pad, 8))
        self.stats_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.stat_cards: dict[str, dict] = {}
        card_defs = [
            ("total", None,      "总数", COLORS["text"]),
            ("safe", "safe",     "安全", COLORS["safe"]),
            ("warn", "warning",  "可疑", COLORS["warn"]),
            ("danger", "danger", "危险", COLORS["danger"]),
        ]
        for col, (key, filter_level, label, color) in enumerate(card_defs):
            card = ctk.CTkFrame(self.stats_frame, fg_color=COLORS["card"],
                                corner_radius=12, height=76,
                                border_width=1, border_color=COLORS["border"])
            card.grid(row=0, column=col, sticky="ew", padx=4)
            card.grid_propagate(False)

            num_label = ctk.CTkLabel(
                card, text="0", font=ctk.CTkFont(size=24, weight="bold"),
                text_color=color
            )
            num_label.pack(pady=(10, 0))

            desc_label = ctk.CTkLabel(
                card, text=label, font=ctk.CTkFont(size=11),
                text_color=COLORS["text_dim"]
            )
            desc_label.pack()

            self.stat_cards[key] = {
                "card": card, "num": num_label, "desc": desc_label,
                "color": color, "filter": filter_level,
            }

            for widget in (card, num_label, desc_label):
                widget.bind("<Button-1>", lambda _e, k=key: self._on_card_click(k))
                widget.bind("<Enter>", lambda _e, c=card: self._card_hover(c, True))
                widget.bind("<Leave>", lambda _e, c=card: self._card_hover(c, False))
                widget.configure(cursor="hand2")

    def _build_status_bar(self):
        self.status_frame = ctk.CTkFrame(self.main_frame, fg_color=COLORS["card"],
                                         height=30, corner_radius=0)
        self.status_frame.grid(row=3, column=0, sticky="ew")
        self.status_frame.grid_propagate(False)

        self.status_label = ctk.CTkLabel(
            self.status_frame, text="就绪", font=ctk.CTkFont(size=11),
            text_color=COLORS["text_dim"]
        )
        self.status_label.pack(side="left", padx=12, pady=4)

        self.time_label = ctk.CTkLabel(
            self.status_frame, text="", font=ctk.CTkFont(size=11),
            text_color=COLORS["text_dim"]
        )
        self.time_label.pack(side="right", padx=12, pady=4)

    def _card_hover(self, card_widget, entered: bool) -> None:
        active = any(
            ref["card"] is card_widget and self._active_filter == ref["filter"]
            and ref["filter"] is not None
            for ref in self.stat_cards.values()
        )
        if entered and not active:
            card_widget.configure(fg_color=COLORS["card_alt"])
        elif not entered and not active:
            card_widget.configure(fg_color=COLORS["card"])

    def _refresh_card_border(self, key: str) -> None:
        ref = self.stat_cards[key]
        active = (self._active_filter == ref["filter"]) and ref["filter"] is not None
        if active:
            ref["card"].configure(border_color=ref["color"], fg_color=COLORS["card_alt"])
        else:
            ref["card"].configure(border_color=COLORS["border"], fg_color=COLORS["card"])

    def _on_card_click(self, key: str) -> None:
        ref = self.stat_cards[key]
        target = ref["filter"]
        if target is None:
            self._active_filter = None
        else:
            self._active_filter = None if self._active_filter == target else target

        for k in self.stat_cards:
            self._refresh_card_border(k)
        self.scan_panel.set_filter(self._active_filter)

    def _set_nav_active(self, idx: int | None):
        self._active_nav = idx
        for i, btn in enumerate(self.nav_buttons):
            if i == idx:
                btn.configure(
                    fg_color=COLORS["card_alt"], hover_color=COLORS["card_alt"],
                    text_color=COLORS["accent"],
                    font=ctk.CTkFont(size=13, weight="bold"),
                )
            else:
                btn.configure(
                    fg_color="transparent", hover_color=COLORS["hover"],
                    text_color=COLORS["text"],
                    font=ctk.CTkFont(size=13, weight="normal"),
                )

    def _reset_results(self):
        self.results.clear()
        self._current_items = []
        self._active_filter = None
        for key in self.stat_cards:
            self.stat_cards[key]["num"].configure(text="0")
            self._refresh_card_border(key)
        self.scan_panel.set_filter(None)
        self.scan_panel.display([])
        self.time_label.configure(text="")

    def _on_nav_click(self, idx):
        scanner = self.scanners[idx]
        self._set_nav_active(idx)
        self._reset_results()
        self._run_scanner(scanner)

    def _scan_all(self):
        self.scan_all_btn.configure(state="disabled", text="扫描中...")
        self.status_label.configure(text="正在执行全部扫描...")
        self._set_nav_active(None)
        self._reset_results()

        def do_scan():
            start = datetime.now()
            all_items: list[ScanResult] = []
            for scanner in self.scanners:
                items = self.whitelist.apply(scanner.scan())
                self.results[scanner.name] = items
                all_items.extend(items)
            elapsed = (datetime.now() - start).total_seconds()
            self.after(0, lambda: self._on_scan_complete(all_items, elapsed))

        threading.Thread(target=do_scan, daemon=True).start()

    def _run_scanner(self, scanner):
        self.status_label.configure(text=f"正在扫描: {scanner.name}...")

        def do_scan():
            start = datetime.now()
            items = self.whitelist.apply(scanner.scan())
            self.results[scanner.name] = items
            elapsed = (datetime.now() - start).total_seconds()
            self.after(0, lambda: self._on_scan_complete(items, elapsed))

        threading.Thread(target=do_scan, daemon=True).start()

    def _on_scan_complete(self, items: list[ScanResult], elapsed: float) -> None:
        self.scan_all_btn.configure(state="normal", text="全 部 扫 描")
        self._current_items = items

        total = len(items)
        danger = sum(1 for i in items if i.severity == Severity.DANGER)
        warn = sum(1 for i in items if i.severity == Severity.WARNING)
        safe = total - danger - warn

        self.stat_cards["total"]["num"].configure(text=str(total))
        self.stat_cards["safe"]["num"].configure(text=str(safe))
        self.stat_cards["warn"]["num"].configure(text=str(warn))
        self.stat_cards["danger"]["num"].configure(text=str(danger))

        self.status_label.configure(text=f"扫描完成 — 共 {total} 项")
        self.time_label.configure(text=f"耗时 {elapsed:.2f}s")

        self.scan_panel.display(items)

    def _export_report(self):
        if not self.results:
            self.status_label.configure(text="请先执行扫描")
            return
        path = export_html_report(self.results)
        self.status_label.configure(text=f"报告已导出: {path}")

    def _show_row_menu(self, item, x_root: int, y_root: int):
        path = item.properties.get("path") or item.properties.get("ResolvedPath") or ""
        in_whitelist = self.whitelist.contains(item)

        entries: list = [
            ("复制名称", lambda: self._copy(item.name)),
            ("复制详情", lambda: self._copy(item.detail)),
        ]
        if path:
            entries.append(("复制路径", lambda: self._copy(path)))
            entries.append(None)
            entries.append(("打开所在文件夹", lambda: self._open_in_explorer(path)))
        entries.append(None)
        entries.append(("在 VirusTotal 搜索", lambda: self._vt_search(item)))
        entries.append(None)
        if in_whitelist:
            entries.append(("移出白名单", lambda: self._toggle_whitelist(item, False)))
        else:
            entries.append(("加入白名单（标为安全）", lambda: self._toggle_whitelist(item, True)))

        ContextMenu(self, entries).show(x_root, y_root)

    def _copy(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.status_label.configure(text=f"已复制到剪贴板")

    def _open_in_explorer(self, path: str):
        try:
            if os.path.exists(path):
                subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
            else:
                folder = os.path.dirname(path)
                if folder and os.path.exists(folder):
                    subprocess.Popen(["explorer", os.path.normpath(folder)])
                else:
                    self.status_label.configure(text="路径不存在")
        except Exception as e:
            self.status_label.configure(text=f"打开失败: {e}")

    def _vt_search(self, item):
        query = item.properties.get("path") or item.name
        url = "https://www.virustotal.com/gui/search/" + urllib.parse.quote(query)
        webbrowser.open(url)

    def _toggle_whitelist(self, item, add: bool):
        if add:
            self.whitelist.add(item)
            self.status_label.configure(text="已加入白名单")
        else:
            self.whitelist.remove(item)
            self.status_label.configure(text="已移出白名单")
        # rerun current display through whitelist filter to refresh severity
        for source, items in self.results.items():
            self.results[source] = self.whitelist.apply(items)
        self._refresh_current_view()

    def _refresh_current_view(self):
        all_items: list[ScanResult] = []
        for items in self.results.values():
            all_items.extend(items)
        total = len(all_items)
        danger = sum(1 for i in all_items if i.severity == Severity.DANGER)
        warn = sum(1 for i in all_items if i.severity == Severity.WARNING)
        safe = total - danger - warn
        self.stat_cards["total"]["num"].configure(text=str(total))
        self.stat_cards["safe"]["num"].configure(text=str(safe))
        self.stat_cards["warn"]["num"].configure(text=str(warn))
        self.stat_cards["danger"]["num"].configure(text=str(danger))
        self.scan_panel.display(all_items)
