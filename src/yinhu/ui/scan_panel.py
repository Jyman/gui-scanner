import customtkinter as ctk

from .theme import COLORS
from ..scanners.base import ScanResult, Severity


SEVERITY_LABELS = {"safe": "安全", "warning": "可疑", "danger": "危险"}


class ScanPanel(ctk.CTkFrame):
    def __init__(self, master, on_row_right_click=None):
        super().__init__(master, fg_color=COLORS["card"], corner_radius=10)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._rows: list[tuple[ctk.CTkFrame, str]] = []
        self._all_items: list[ScanResult] = []
        self._filter: str | None = None
        self._on_row_right_click = on_row_right_click

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 0))

        self.title_label = ctk.CTkLabel(
            header, text="扫描结果", font=ctk.CTkFont(size=15, weight="bold"),
            text_color=COLORS["text"]
        )
        self.title_label.pack(side="left")

        self.filter_hint = ctk.CTkLabel(
            header, text="", font=ctk.CTkFont(size=11),
            text_color=COLORS["accent"]
        )
        self.filter_hint.pack(side="left", padx=(12, 0))

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

        self._placeholder_label: ctk.CTkLabel | None = None
        self._empty_label: ctk.CTkLabel | None = None
        self._show_placeholder()

    def _show_placeholder(self) -> None:
        self._clear_messages()
        self._placeholder_label = ctk.CTkLabel(
            self.scroll_frame, text="点击左侧模块或「全部扫描」开始",
            font=ctk.CTkFont(size=13), text_color=COLORS["text_dim"]
        )
        self._placeholder_label.pack(pady=80)
        self.count_label.configure(text="")

    def _clear_messages(self) -> None:
        if self._placeholder_label is not None:
            self._placeholder_label.destroy()
            self._placeholder_label = None
        if self._empty_label is not None:
            self._empty_label.destroy()
            self._empty_label = None

    def _destroy_rows(self) -> None:
        for row, _level in self._rows:
            row.destroy()
        self._rows.clear()

    def display(self, items: list[ScanResult]) -> None:
        self._all_items = list(items)
        self._clear_messages()
        self._destroy_rows()

        if not items:
            self._show_placeholder()
            return

        for i, item in enumerate(items):
            row = self._build_row(item, i)
            self._rows.append((row, item.severity.value))

        self._apply_filter()

    def set_filter(self, level: str | None) -> None:
        if level == self._filter:
            return
        self._filter = level
        if level:
            self.filter_hint.configure(text=f"· 筛选: {SEVERITY_LABELS.get(level, level)}")
        else:
            self.filter_hint.configure(text="")
        if not self._all_items:
            return
        self._apply_filter()

    def _apply_filter(self) -> None:
        self._clear_messages()
        shown = 0
        for row, level in self._rows:
            if self._filter is None or level == self._filter:
                if not row.winfo_ismapped():
                    row.pack(fill="x", pady=1)
                shown += 1
            else:
                if row.winfo_ismapped():
                    row.pack_forget()

        self.count_label.configure(
            text=f"显示 {shown} / {len(self._all_items)} 项"
        )

        if shown == 0:
            self._empty_label = ctk.CTkLabel(
                self.scroll_frame, text="该等级下无项目",
                font=ctk.CTkFont(size=13), text_color=COLORS["text_dim"]
            )
            self._empty_label.pack(pady=80)

    def _build_row(self, item: ScanResult, index: int) -> ctk.CTkFrame:
        level = item.severity.value
        level_colors = {
            "safe": COLORS["safe"],
            "warning": COLORS["warn"],
            "danger": COLORS["danger"],
        }
        accent = level_colors.get(level, COLORS["text"])

        row_bg = COLORS["row_even"] if index % 2 == 0 else COLORS["row_odd"]
        row = ctk.CTkFrame(self.scroll_frame, fg_color=row_bg, corner_radius=8, height=48)
        row.pack(fill="x", pady=2)
        row.pack_propagate(False)

        def _enter(_e=None, r=row):
            r.configure(fg_color=COLORS["hover"])

        def _leave(_e=None, r=row, base=row_bg):
            r.configure(fg_color=base)

        row.bind("<Enter>", _enter)
        row.bind("<Leave>", _leave)

        if self._on_row_right_click is not None:
            cb = self._on_row_right_click
            row.bind("<Button-3>", lambda e, it=item: cb(it, e.x_root, e.y_root))
            row.configure(cursor="hand2")

        indicator = ctk.CTkFrame(row, width=4, fg_color=accent, corner_radius=2)
        indicator.pack(side="left", fill="y", padx=(4, 8), pady=6)

        level_text = SEVERITY_LABELS.get(level, "?")
        ctk.CTkLabel(
            row, text=level_text, font=ctk.CTkFont(size=10, weight="bold"),
            text_color=accent, width=36
        ).pack(side="left", padx=(0, 8), pady=8)

        ctk.CTkLabel(
            row, text=item.properties.get("source", ""),
            font=ctk.CTkFont(size=11), text_color=COLORS["text_dim"], width=80
        ).pack(side="left", padx=(0, 8), pady=8)

        ctk.CTkLabel(
            row, text=item.name,
            font=ctk.CTkFont(size=12, weight="bold"), text_color=COLORS["text"]
        ).pack(side="left", padx=(0, 12), pady=8)

        detail_lbl = ctk.CTkLabel(
            row, text=item.detail,
            font=ctk.CTkFont(size=11), text_color=COLORS["text_dim"]
        )
        detail_lbl.pack(side="left", fill="x", expand=True, pady=8)

        if self._on_row_right_click is not None:
            cb = self._on_row_right_click
            for child in row.winfo_children():
                child.bind("<Button-3>", lambda e, it=item: cb(it, e.x_root, e.y_root))
        for child in row.winfo_children():
            child.bind("<Enter>", _enter)
            child.bind("<Leave>", _leave)

        return row
