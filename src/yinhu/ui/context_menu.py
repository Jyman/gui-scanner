"""Custom themed context menu using CTkToplevel."""

from __future__ import annotations

from typing import Callable

import customtkinter as ctk

from .theme import COLORS


class ContextMenu(ctk.CTkToplevel):
    def __init__(self, master, items: list[tuple[str, Callable | None]]):
        super().__init__(master)
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        try:
            self.attributes("-alpha", 0.0)
        except Exception:
            pass

        self.configure(fg_color=COLORS["panel"])

        self._frame = ctk.CTkFrame(
            self, fg_color=COLORS["panel"],
            border_color=COLORS["border"], border_width=1,
            corner_radius=10,
        )
        self._frame.pack(fill="both", expand=True, padx=0, pady=0)

        for entry in items:
            if entry is None:
                sep = ctk.CTkFrame(self._frame, height=1, fg_color=COLORS["border"])
                sep.pack(fill="x", padx=8, pady=4)
                continue
            label, cb = entry
            self._add_item(label, cb)

        self.bind("<FocusOut>", lambda _e: self.destroy())
        self.bind("<Escape>", lambda _e: self.destroy())

    def _add_item(self, label: str, cb: Callable | None) -> None:
        btn = ctk.CTkButton(
            self._frame, text=label, anchor="w",
            font=ctk.CTkFont(size=12),
            fg_color="transparent",
            hover_color=COLORS["hover"],
            text_color=COLORS["text"],
            corner_radius=6,
            height=30,
            command=lambda c=cb: self._invoke(c),
        )
        btn.pack(fill="x", padx=6, pady=1)

    def _invoke(self, cb: Callable | None) -> None:
        self.destroy()
        if cb is not None:
            try:
                cb()
            except Exception:
                pass

    def show(self, x_root: int, y_root: int) -> None:
        self.update_idletasks()
        w = max(self.winfo_reqwidth(), 200)
        h = self.winfo_reqheight()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = min(x_root, sw - w - 8)
        y = min(y_root, sh - h - 8)
        self.geometry(f"{w}x{h}+{x}+{y}")
        try:
            self.attributes("-alpha", 1.0)
        except Exception:
            pass
        self.lift()
        self.focus_force()
