#!/usr/bin/env python3

import sys
sys.dont_write_bytecode = True

import customtkinter as ctk

# ============================================================================
# COLORS
# ============================================================================
COLORS = {
    "bg": "#141414",
    "bg_secondary": "#1b1b1c",
    "bg_tertiary": "#2a2a2c",
    "text": "#f2f2f2",
    "text_secondary": "#8a8a8e",
    "accent": "#e5e5e7",
    "border": "#333335",
    "success": "#15803d",
    "success_dark": "#166534",
    "danger": "#dc2626",
    "danger_dark": "#b91c1c",
    "warning": "#b45309",
    "warning_dark": "#92400e",
    "info": "#2563eb",
    "info_dark": "#1d4ed8",
}

# ============================================================================
# SPACING
# ============================================================================
SP_XS = 4
SP_SM = 8
SP_MD = 12
SP_LG = 16
SP_XL = 24
SP_XXL = 32

# ============================================================================
# THEME
# ============================================================================
def setup_theme():
    """Configures the application theme"""
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")
