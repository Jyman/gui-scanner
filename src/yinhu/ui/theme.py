"""Soft paper light theme."""

from __future__ import annotations

import customtkinter as ctk

COLORS = {
    "bg": "#f7f7fb",
    "sidebar": "#eceef5",
    "panel": "#ffffff",
    "card": "#ffffff",
    "card_alt": "#f1f3fa",
    "hover": "#e4e7f1",
    "input": "#ffffff",
    "text": "#2a2e3d",
    "text_dim": "#6b7393",
    "text_muted": "#a3aac4",
    "accent": "#3b6dd6",
    "accent_hover": "#2e5cc0",
    "accent_text": "#ffffff",
    "btn_text": "#ffffff",
    "safe": "#3e9a4e",
    "warn": "#c98a2c",
    "danger": "#d24c63",
    "border": "#e1e4ee",
    "row_even": "#ffffff",
    "row_odd": "#f5f6fb",
}

FONTS = {
    "title": ("Segoe UI", 18, "bold"),
    "heading": ("Segoe UI", 14, "bold"),
    "body": ("Segoe UI", 12),
    "small": ("Segoe UI", 10),
    "mono": ("Cascadia Code", 11),
    "mono_small": ("Cascadia Code", 10),
}


def apply_theme() -> None:
    ctk.set_default_color_theme("blue")
    ctk.set_appearance_mode("light")
