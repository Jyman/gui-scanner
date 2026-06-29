import customtkinter as ctk
from .theme import COLORS
from ..scanners.base import ScanResult, Severity


class ScanPanel(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master, fg_color=COLORS["card"], corner_radius=10)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 0))

        self.title_label = ctk.CTkLabel(
            header, text="扫描结果", font=ctk.CTkFont(size=15, weight="bold"),
            text_color=COLORS["text"]
        )
        self.title_label.pack(side="left")

        self.count_label = ctk.CTkLabel(
            header, text="", font=ctk.CTkFont(size=12),
            text_color=COLORS["text_dim"]
        )
        self.count_label.pack(side="right")

        self.scroll_frame = ctk.CTkScrollableFrame(
            self, fg_color="transparent", corner_radius=0
        )
        self.scroll_frame.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)
        self.scroll_frame.grid_columnconfigure(0, weight=1)

        self._placeholder()

    def _placeholder(self):
        self._clear()
        label = ctk.CTkLabel(
            self.scroll_frame, text="点击左侧模块或「全部扫描」开始",
            font=ctk.CTkFont(size=13), text_color=COLORS["text_dim"]
        )
        label.pack(pady=80)

    def _clear(self):
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()

    def display(self, items):
        self._clear()
        self.count_label.configure(text=f"共 {len(items)} 项")

        if not items:
            label = ctk.CTkLabel(
                self.scroll_frame, text="未发现异常项目",
                font=ctk.CTkFont(size=13), text_color=COLORS["safe"]
            )
            label.pack(pady=80)
            return

        for i, item in enumerate(items):
            self._add_row(item, i)

    def _add_row(self, item, index):
        level = item.severity.value
        level_colors = {
            "safe": COLORS["safe"],
            "warning": COLORS["warn"],
            "danger": COLORS["danger"],
        }
        accent = level_colors.get(level, COLORS["text"])

        row_bg = COLORS["bg"] if index % 2 == 0 else "#1e2030"
        row = ctk.CTkFrame(self.scroll_frame, fg_color=row_bg, corner_radius=6, height=48)
        row.pack(fill="x", pady=1)
        row.pack_propagate(False)

        indicator = ctk.CTkFrame(row, width=4, fg_color=accent, corner_radius=2)
        indicator.pack(side="left", fill="y", padx=(4, 8), pady=6)

        level_text = {"safe": "安全", "warning": "可疑", "danger": "危险"}.get(level, "?")
        badge = ctk.CTkLabel(
            row, text=level_text, font=ctk.CTkFont(size=10, weight="bold"),
            text_color=accent, width=36
        )
        badge.pack(side="left", padx=(0, 8), pady=8)

        source_label = ctk.CTkLabel(
            row, text=item.properties.get("source", ""),
            font=ctk.CTkFont(size=11), text_color=COLORS["text_dim"], width=80
        )
        source_label.pack(side="left", padx=(0, 8), pady=8)

        name_label = ctk.CTkLabel(
            row, text=item.name,
            font=ctk.CTkFont(size=12, weight="bold"), text_color=COLORS["text"]
        )
        name_label.pack(side="left", padx=(0, 12), pady=8)

        detail_label = ctk.CTkLabel(
            row, text=item.detail,
            font=ctk.CTkFont(size=11), text_color=COLORS["text_dim"]
        )
        detail_label.pack(side="left", fill="x", expand=True, pady=8)
