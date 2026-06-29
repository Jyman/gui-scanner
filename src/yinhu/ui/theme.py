"""Tokyo Night inspired dark theme for the scanner UI."""

import customtkinter as ctk

COLORS = {
    "bg": "#1a1b26",
    "sidebar": "#16161e",
    "panel": "#24283b",
    "card": "#292e42",
    "hover": "#33394d",
    "input": "#1f2335",
    "text": "#c0caf5",
    "text_dim": "#565f89",
    "text_muted": "#3b4261",
    "accent": "#7aa2f7",
    "accent_hover": "#89b4fa",
    "safe": "#9ece6a",
    "warn": "#e0af68",
    "danger": "#f7768e",
    "border": "#292e42",
}

FONTS = {
    "title": ("Segoe UI", 18, "bold"),
    "heading": ("Segoe UI", 14, "bold"),
    "body": ("Segoe UI", 12),
    "small": ("Segoe UI", 10),
    "mono": ("Cascadia Code", 11),
    "mono_small": ("Cascadia Code", 10),
}


def apply_theme():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
