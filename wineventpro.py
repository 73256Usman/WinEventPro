"""
WinEvent Pro — Main GUI
Windows Event Log Monitor
Light theme, blue accents, left sidebar navigation, dashboard charts
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import ctypes
import sys
from datetime import datetime
from typing import List, Optional, Dict

import re
import subprocess
import webbrowser

from event_reader import EventReader, EventRecord, CHANNELS
from threat_engine import ThreatEngine, ThreatAlert
from database import Database
from report_generator import generate_report
from settings import Settings


# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------

BG            = "#f0f4f8"
WHITE         = "#ffffff"
SIDEBAR_BG    = "#1e3a5f"
SIDEBAR_HOVER = "#2a4f7c"
SIDEBAR_SEL   = "#2563eb"
ACCENT        = "#2563eb"
ACCENT_LIGHT  = "#dbeafe"
ACCENT_DARK   = "#1d4ed8"
BORDER        = "#e2e8f0"
TEXT_DARK     = "#1e293b"
TEXT_MID      = "#475569"
TEXT_LIGHT    = "#94a3b8"
WHITE_TEXT    = "#ffffff"

CRITICAL_CLR  = "#dc2626"
HIGH_CLR      = "#ea580c"
MEDIUM_CLR    = "#d97706"
LOW_CLR       = "#3b82f6"
INFO_CLR      = "#64748b"
SAFE_CLR      = "#3b82f6"
SUCCESS_CLR   = "#16a34a"
ERROR_CLR     = "#dc2626"

# Subtle row-background tint per severity level (very pale, text stays readable)
SEV_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH":     "#fff7ed",
    "MEDIUM":   "#fefce8",
    "LOW":      "#eff6ff",
    "INFO":     "#f8fafc",
    "SAFE":     "#eff6ff",
}

SEVERITY_COLORS = {
    "CRITICAL": CRITICAL_CLR,
    "HIGH":     HIGH_CLR,
    "MEDIUM":   MEDIUM_CLR,
    "LOW":      LOW_CLR,
    "INFO":     INFO_CLR,
    "SAFE":     SAFE_CLR,
}

NAV_ITEMS = [
    ("📊  Dashboard",     "dashboard"),
    ("📡  Live Monitor",  "live"),
    ("⚠   Threat Alerts", "alerts"),
    ("📋  History",       "history"),
    ("⚙   Settings",      "settings"),
]

PAGE_INFO = {
    "dashboard": ("Dashboard",     "Live monitoring session — alerts and severity breakdown"),
    "live":      ("Live Monitor",  "Real-time event stream from Windows Event Log channels"),
    "alerts":    ("Threat Alerts", "Detected threats from historical scans"),
    "history":   ("Scan History",  "Past scan sessions and saved reports"),
    "settings":  ("Settings",      "Configure scan parameters and detection thresholds"),
}

# Maps alert rule names to a (button label, msc tool) pair used in the
# investigation popup so the analyst can jump straight to the relevant
# Windows management console.
_CONTEXT_TOOLS: dict = {
    "Scheduled Task Created":                ("Open Task Scheduler", "taskschd.msc"),
    "Scheduled Task Deleted":                ("Open Task Scheduler", "taskschd.msc"),
    "Scheduled Task Re-enabled":             ("Open Task Scheduler", "taskschd.msc"),
    "New User Account Created":              ("Open User Management", "lusrmgr.msc"),
    "User Added to Security Group":          ("Open User Management", "lusrmgr.msc"),
    "Account Password Reset":                ("Open User Management", "lusrmgr.msc"),
    "Account Disabled":                      ("Open User Management", "lusrmgr.msc"),
    "User Account Permanently Deleted":      ("Open User Management", "lusrmgr.msc"),
    "New Windows Service Installed":         ("Open Services",        "services.msc"),
    "Service Installed from Suspicious Path":("Open Services",        "services.msc"),
    "Windows Service Crashed":               ("Open Services",        "services.msc"),
}


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

class WinEventPro:

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("WinEvent Pro — Windows Event Log Monitor")
        self.root.geometry("1300x820")
        self.root.minsize(1050, 680)
        self.root.configure(bg=SIDEBAR_BG)

        self.reader   = EventReader()
        self.engine   = ThreatEngine()
        self.db       = Database()
        self.settings = Settings()

        self._live_thread:    Optional[threading.Thread] = None
        self._is_live         = False
        self._flash_active    = False
        self._session_id:     Optional[int] = None
        self._current_page    = "dashboard"
        self._nav_buttons:    Dict[str, tk.Frame] = {}
        self._pages:          Dict[str, tk.Frame] = {}
        self._live_item_data: Dict[str, dict] = {}

        # Live monitor state — feeds the dashboard and top-bar cards.
        # Only updated by the live monitor; historical scans never touch these.
        self._live_alerts:      List[ThreatAlert] = []
        self._live_event_count: int = 0
        self._live_safe_count:  int = 0  # events with no alert (tagged SAFE in tree)

        # Scan state — feeds the Threat Alerts tab and PDF export.
        # Updated by both live monitor and historical scan.
        self._scan_alerts:      List[ThreatAlert] = []
        self._scan_event_count: int = 0
        self._scan_info:        dict = {}

        self._apply_styles()
        self._build_layout()
        self._show_page("dashboard")
        self._refresh_history()
        self._refresh_dashboard()

        if self.settings.auto_start_live:
            self.root.after(500, self._start_live)

    # ── Styles ──────────────────────────────────────────────────────────────

    def _apply_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("Treeview",
            background=WHITE, foreground=TEXT_DARK,
            fieldbackground=WHITE, rowheight=28,
            font=("Segoe UI", 9), borderwidth=0)
        style.configure("Treeview.Heading",
            background=ACCENT_LIGHT, foreground=ACCENT,
            font=("Segoe UI", 9, "bold"), relief="flat", padding=6)
        style.map("Treeview",
            background=[("selected", ACCENT)],
            foreground=[("selected", WHITE_TEXT)])
        style.configure("Vertical.TScrollbar",
            background=BORDER, troughcolor=BG,
            arrowcolor=TEXT_LIGHT, borderwidth=0, relief="flat")

    # ── Layout ──────────────────────────────────────────────────────────────

    def _build_layout(self):
        self._sidebar = tk.Frame(self.root, bg=SIDEBAR_BG, width=224)
        self._sidebar.pack(side="left", fill="y")
        self._sidebar.pack_propagate(False)

        main = tk.Frame(self.root, bg=BG)
        main.pack(side="left", fill="both", expand=True)

        self._build_status_bar(main)
        self._build_top_bar(main)

        self._content = tk.Frame(main, bg=BG)
        self._content.pack(fill="both", expand=True)

        self._build_sidebar()
        self._build_dashboard_page()
        self._build_live_page()
        self._build_alerts_page()
        self._build_history_page()
        self._build_settings_page()

    # ── Sidebar ─────────────────────────────────────────────────────────────

    def _build_sidebar(self):
        logo = tk.Frame(self._sidebar, bg=SIDEBAR_BG)
        logo.pack(fill="x", padx=20, pady=(24, 12))

        tk.Label(logo, text="WinEvent Pro",
            font=("Segoe UI", 15, "bold"),
            fg=WHITE_TEXT, bg=SIDEBAR_BG).pack(anchor="w")
        tk.Label(logo, text="Event Log Monitor",
            font=("Segoe UI", 8),
            fg="#60a5fa", bg=SIDEBAR_BG).pack(anchor="w", pady=(2, 0))

        tk.Frame(self._sidebar, bg="#2a4f7c", height=1).pack(
            fill="x", padx=16, pady=(4, 12))

        nav = tk.Frame(self._sidebar, bg=SIDEBAR_BG)
        nav.pack(fill="x")
        for label, key in NAV_ITEMS:
            self._nav_buttons[key] = self._nav_button(nav, label, key)

        tk.Frame(self._sidebar, bg="#2a4f7c", height=1).pack(
            fill="x", padx=16, pady=8, side="bottom")

        bot = tk.Frame(self._sidebar, bg=SIDEBAR_BG)
        bot.pack(side="bottom", fill="x", padx=18, pady=14)

        self._live_dot = tk.Label(bot,
            text="● IDLE",
            font=("Segoe UI", 8, "bold"),
            fg="#64748b", bg=SIDEBAR_BG)
        self._live_dot.pack(anchor="w")

        self._sidebar_status = tk.Label(bot,
            text="Not monitoring",
            font=("Segoe UI", 8),
            fg="#475569", bg=SIDEBAR_BG,
            wraplength=184, justify="left")
        self._sidebar_status.pack(anchor="w", pady=(3, 0))

    def _nav_button(self, parent: tk.Frame, label: str, key: str) -> tk.Frame:
        frame = tk.Frame(parent, bg=SIDEBAR_BG, cursor="hand2")
        frame.pack(fill="x", padx=10, pady=2)

        lbl = tk.Label(frame,
            text=f"   {label}",
            font=("Segoe UI", 9),
            fg="#94a3b8", bg=SIDEBAR_BG,
            anchor="w", pady=10, padx=6)
        lbl.pack(fill="x")
        frame._label = lbl

        def click(k=key): self._show_page(k)
        def enter(e, f=frame, l=lbl):
            if self._current_page != key:
                f.configure(bg=SIDEBAR_HOVER)
                l.configure(bg=SIDEBAR_HOVER)
        def leave(e, f=frame, l=lbl):
            if self._current_page != key:
                f.configure(bg=SIDEBAR_BG)
                l.configure(bg=SIDEBAR_BG)

        for widget in (frame, lbl):
            widget.bind("<Button-1>", lambda e: click())
            widget.bind("<Enter>", enter)
            widget.bind("<Leave>", leave)

        return frame

    def _show_page(self, key: str):
        old = self._nav_buttons.get(self._current_page)
        if old:
            old.configure(bg=SIDEBAR_BG)
            old._label.configure(bg=SIDEBAR_BG, fg="#94a3b8",
                font=("Segoe UI", 9))

        self._current_page = key
        btn = self._nav_buttons.get(key)
        if btn:
            btn.configure(bg=SIDEBAR_SEL)
            btn._label.configure(bg=SIDEBAR_SEL, fg=WHITE_TEXT,
                font=("Segoe UI", 9, "bold"))

        if key in self._pages:
            self._pages[key].tkraise()

        title, subtitle = PAGE_INFO.get(key, (key.title(), ""))
        self._page_title.configure(text=title)
        self._page_subtitle.configure(text=subtitle)

        if key == "dashboard":
            self._refresh_dashboard()

        if key == "settings":
            self.root.bind_all("<MouseWheel>", self._on_settings_scroll)
        else:
            self.root.unbind_all("<MouseWheel>")

    # ── Top bar ─────────────────────────────────────────────────────────────

    def _build_top_bar(self, parent: tk.Frame):
        bar = tk.Frame(parent, bg=WHITE, height=64)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", side="top")

        left = tk.Frame(bar, bg=WHITE)
        left.pack(side="left", padx=20, pady=12)

        self._page_title = tk.Label(left, text="Dashboard",
            font=("Segoe UI", 13, "bold"),
            fg=TEXT_DARK, bg=WHITE)
        self._page_title.pack(anchor="w")

        self._page_subtitle = tk.Label(left,
            text="Live monitoring session — alerts and severity breakdown",
            font=("Segoe UI", 8), fg=TEXT_LIGHT, bg=WHITE)
        self._page_subtitle.pack(anchor="w")

        cards = tk.Frame(bar, bg=WHITE)
        cards.pack(side="right", padx=16, pady=10)

        self._top_info    = self._top_card(cards, "INFO",     "0",    INFO_CLR)
        self._top_low     = self._top_card(cards, "LOW",      "0",    LOW_CLR)
        self._top_med     = self._top_card(cards, "MEDIUM",   "0",    MEDIUM_CLR)
        self._top_high    = self._top_card(cards, "HIGH",     "0",    HIGH_CLR)
        self._top_crit    = self._top_card(cards, "CRITICAL", "0",    CRITICAL_CLR)
        self._card_status = self._top_card(cards, "STATUS",   "IDLE", TEXT_LIGHT)

    def _top_card(self, parent, label: str, value: str, color: str) -> tk.Label:
        frame = tk.Frame(parent, bg=BG,
            highlightthickness=1, highlightbackground=BORDER,
            padx=14, pady=6)
        frame.pack(side="left", padx=4)
        val_lbl = tk.Label(frame, text=value,
            font=("Segoe UI", 15, "bold"),
            fg=color, bg=BG)
        val_lbl.pack()
        tk.Label(frame, text=label,
            font=("Segoe UI", 7),
            fg=TEXT_LIGHT, bg=BG).pack()
        return val_lbl

    # ── Dashboard page ──────────────────────────────────────────────────────

    def _build_dashboard_page(self):
        page = tk.Frame(self._content, bg=BG)
        page.place(x=0, y=0, relwidth=1, relheight=1)
        self._pages["dashboard"] = page

        row1 = tk.Frame(page, bg=BG)
        row1.pack(fill="x", padx=20, pady=(16, 8))

        # Severity spectrum: left = lowest (Info/gray), right = highest (Critical/red)
        stats = [
            ("Info",     "0", INFO_CLR,     "info"),
            ("Low",      "0", LOW_CLR,      "low"),
            ("Medium",   "0", MEDIUM_CLR,   "medium"),
            ("High",     "0", HIGH_CLR,     "high"),
            ("Critical", "0", CRITICAL_CLR, "critical"),
        ]

        self._dash_cards: Dict[str, tk.Label] = {}
        for title, val, color, k in stats:
            card, lbl = self._dash_stat_card(row1, title, val, color)
            card.pack(side="left", fill="x", expand=True, padx=4)
            self._dash_cards[k] = lbl

        row2 = tk.Frame(page, bg=BG)
        row2.pack(fill="both", expand=True, padx=20, pady=8)

        # Left: severity donut
        dc = self._card_panel(row2, "Severity Distribution")
        dc.pack(side="left", fill="both", expand=True, padx=(0, 6))
        self._donut_canvas = tk.Canvas(dc, width=220, height=210,
            bg=WHITE, highlightthickness=0)
        self._donut_canvas.pack(pady=(8, 4))
        self._donut_legend = tk.Frame(dc, bg=WHITE)
        self._donut_legend.pack(pady=(0, 10))

        # Middle: channel bar chart
        bc = self._card_panel(row2, "Alerts by Channel")
        bc.pack(side="left", fill="both", expand=True, padx=6)
        self._channel_canvas = tk.Canvas(bc, width=240, height=210,
            bg=WHITE, highlightthickness=0)
        self._channel_canvas.pack(pady=(8, 10))

        # Right: session alert list — shows the alerts making up the donut
        ac = self._card_panel(row2, "Session Alerts")
        ac.pack(side="left", fill="both", expand=True, padx=(6, 0))

        ac_inner = tk.Frame(ac, bg=WHITE)
        ac_inner.pack(fill="both", expand=True, padx=10, pady=(6, 10))

        dash_cols = ("severity", "rule", "time")
        self._dash_alert_tree = ttk.Treeview(ac_inner, columns=dash_cols,
            show="headings", selectmode="none")
        self._dash_alert_tree.heading("severity", text="Sev")
        self._dash_alert_tree.heading("rule",     text="Rule / Alert")
        self._dash_alert_tree.heading("time",     text="Time")
        self._dash_alert_tree.column("severity", width=65,  minwidth=65)
        self._dash_alert_tree.column("rule",     minwidth=90, stretch=True)
        self._dash_alert_tree.column("time",     width=70,  minwidth=70)

        for sev, color in SEVERITY_COLORS.items():
            self._dash_alert_tree.tag_configure(sev, foreground=color,
                background=SEV_BG.get(sev, WHITE))

        dash_vsb = ttk.Scrollbar(ac_inner, orient="vertical",
            command=self._dash_alert_tree.yview)
        self._dash_alert_tree.configure(yscrollcommand=dash_vsb.set)
        self._dash_alert_tree.pack(side="left", fill="both", expand=True)
        dash_vsb.pack(side="right", fill="y")

        self._draw_donut({}, 0)
        self._draw_channel_chart({})

    def _dash_stat_card(self, parent, title: str, value: str, color: str):
        frame = tk.Frame(parent, bg=WHITE,
            highlightthickness=1, highlightbackground=BORDER)
        bar = tk.Frame(frame, bg=color, width=5)
        bar.pack(side="left", fill="y")
        inner = tk.Frame(frame, bg=WHITE, padx=10, pady=10)
        inner.pack(side="left", fill="both", expand=True)
        val_lbl = tk.Label(inner, text=value,
            font=("Segoe UI", 20, "bold"),
            fg=color, bg=WHITE)
        val_lbl.pack(anchor="w")
        tk.Label(inner, text=title,
            font=("Segoe UI", 9),
            fg=TEXT_MID, bg=WHITE).pack(anchor="w")
        return frame, val_lbl

    def _card_panel(self, parent, title: str) -> tk.Frame:
        outer = tk.Frame(parent, bg=WHITE,
            highlightthickness=1, highlightbackground=BORDER)
        tk.Label(outer, text=title,
            font=("Segoe UI", 10, "bold"),
            fg=TEXT_DARK, bg=WHITE).pack(anchor="w", padx=14, pady=(12, 0))
        tk.Frame(outer, bg=BORDER, height=1).pack(fill="x", padx=14, pady=(4, 0))
        return outer

    # ── Charts ───────────────────────────────────────────────────────────────

    def _draw_donut(self, data: dict, total: int):
        c = self._donut_canvas
        c.delete("all")
        cx, cy, r_out, r_in = 110, 105, 88, 54

        if total == 0:
            c.create_oval(cx-r_out, cy-r_out, cx+r_out, cy+r_out,
                fill=BORDER, outline="")
            c.create_oval(cx-r_in, cy-r_in, cx+r_in, cy+r_in,
                fill=WHITE, outline="")
            c.create_text(cx, cy-8, text="0",
                font=("Segoe UI", 20, "bold"), fill=TEXT_LIGHT)
            c.create_text(cx, cy+14, text="No Alerts",
                font=("Segoe UI", 8), fill=TEXT_LIGHT)
            return

        angle = -90.0
        for sev in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            count = data.get(sev, 0)
            if not count:
                continue
            extent = (count / total) * 360.0
            c.create_arc(
                cx-r_out, cy-r_out, cx+r_out, cy+r_out,
                start=angle, extent=extent,
                fill=SEVERITY_COLORS[sev],
                outline=WHITE, width=2, style="pieslice")
            angle += extent

        c.create_oval(cx-r_in, cy-r_in, cx+r_in, cy+r_in,
            fill=WHITE, outline="")
        c.create_text(cx, cy-10, text=str(total),
            font=("Segoe UI", 18, "bold"), fill=TEXT_DARK)
        c.create_text(cx, cy+12, text="Events",
            font=("Segoe UI", 8), fill=TEXT_LIGHT)

        for w in self._donut_legend.winfo_children():
            w.destroy()
        for sev in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            count = data.get(sev, 0)
            if not count:
                continue
            f = tk.Frame(self._donut_legend, bg=WHITE)
            f.pack(side="left", padx=5)
            tk.Frame(f, bg=SEVERITY_COLORS[sev], width=10, height=10).pack(
                side="left")
            tk.Label(f, text=f" {sev[:4]} {count}",
                font=("Segoe UI", 7), fg=TEXT_MID, bg=WHITE).pack(side="left")

    def _draw_channel_chart(self, data: dict):
        c = self._channel_canvas
        c.delete("all")
        channels  = ["Security", "System", "Application"]
        values    = [data.get(ch, 0) for ch in channels]
        max_val   = max(values) if any(values) else 1
        colors    = [ACCENT, "#06b6d4", "#8b5cf6"]
        pad_left  = 90
        pad_right = 30
        pad_top   = 28
        bar_h     = 30
        gap       = 26
        bar_area  = 240 - pad_left - pad_right

        for i, (ch, val, color) in enumerate(zip(channels, values, colors)):
            y  = pad_top + i * (bar_h + gap)
            bw = max(4, int((val / max_val) * bar_area))
            c.create_text(pad_left - 8, y + bar_h // 2,
                text=ch, font=("Segoe UI", 8), fill=TEXT_MID, anchor="e")
            c.create_rectangle(
                pad_left, y, pad_left + bar_area, y + bar_h,
                fill=ACCENT_LIGHT, outline="")
            c.create_rectangle(
                pad_left, y, pad_left + bw, y + bar_h,
                fill=color, outline="")
            c.create_text(
                pad_left + bw + 5, y + bar_h // 2,
                text=str(val),
                font=("Segoe UI", 8, "bold"),
                fill=TEXT_DARK, anchor="w")

    # ── Live Monitor page ───────────────────────────────────────────────────

    def _build_live_page(self):
        page = tk.Frame(self._content, bg=BG)
        page.place(x=0, y=0, relwidth=1, relheight=1)
        self._pages["live"] = page

        toolbar = tk.Frame(page, bg=WHITE, height=52)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)
        tk.Frame(page, bg=BORDER, height=1).pack(fill="x")

        self._btn_start = tk.Button(toolbar,
            text="▶  Start Monitor",
            font=("Segoe UI", 9, "bold"),
            bg=SUCCESS_CLR, fg=WHITE_TEXT, relief="flat",
            padx=14, pady=6, cursor="hand2",
            command=self._start_live)
        self._btn_start.pack(side="left", padx=12, pady=10)

        self._btn_stop = tk.Button(toolbar,
            text="■  Stop",
            font=("Segoe UI", 9, "bold"),
            bg=BORDER, fg=TEXT_LIGHT, relief="flat",
            padx=14, pady=6, cursor="hand2",
            state="disabled",
            command=self._stop_live)
        self._btn_stop.pack(side="left", padx=4, pady=10)

        tk.Button(toolbar,
            text="🗑  Clear",
            font=("Segoe UI", 9),
            bg=WHITE, fg=TEXT_MID, relief="flat",
            padx=10, pady=6, cursor="hand2",
            command=self._clear_live).pack(side="left", padx=4, pady=10)

        ch_frame = tk.Frame(toolbar, bg=WHITE)
        ch_frame.pack(side="right", padx=14)
        tk.Label(ch_frame, text="Watching:",
            font=("Segoe UI", 8), fg=TEXT_LIGHT, bg=WHITE).pack(side="left")
        for ch in ["Security", "System", "Application"]:
            tk.Label(ch_frame, text=ch,
                font=("Segoe UI", 8, "bold"),
                fg=ACCENT, bg=WHITE, padx=6).pack(side="left")

        # Color legend — left=lowest concern, right=highest
        legend_bar = tk.Frame(page, bg=WHITE,
            highlightthickness=1, highlightbackground=BORDER)
        legend_bar.pack(fill="x", padx=16, pady=(8, 0))
        tk.Label(legend_bar, text="Severity:",
            font=("Segoe UI", 8, "bold"),
            fg=TEXT_MID, bg=WHITE).pack(side="left", padx=(10, 6), pady=6)
        for label, color in [
            ("No Threat / Low", SAFE_CLR),
            ("Info",            INFO_CLR),
            ("Medium",          MEDIUM_CLR),
            ("High",            HIGH_CLR),
            ("Critical",        CRITICAL_CLR),
        ]:
            dot = tk.Frame(legend_bar, bg=color, width=10, height=10)
            dot.pack(side="left", pady=6)
            dot.pack_propagate(False)
            tk.Label(legend_bar, text=label,
                font=("Segoe UI", 8),
                fg=TEXT_MID, bg=WHITE).pack(side="left", padx=(4, 12), pady=6)

        tbl = tk.Frame(page, bg=BG)
        tbl.pack(fill="both", expand=True, padx=16, pady=(8, 6))

        cols     = ("time", "channel", "event_id", "sev",
                    "source", "user", "description")
        widths   = [155, 70, 55, 70, 135, 90, 0]
        headings = ["Time", "Channel", "Event ID", "Sev",
                    "Source", "User", "Description"]

        self._live_tree = ttk.Treeview(tbl, columns=cols,
            displaycolumns=("time", "channel", "event_id",
                            "sev", "user", "description"),
            show="headings", selectmode="browse")
        for col, hd, w in zip(cols, headings, widths):
            self._live_tree.heading(col, text=hd)
            if w:
                self._live_tree.column(col, width=w, minwidth=40)
            else:
                self._live_tree.column(col, minwidth=200, stretch=True)

        vsb = ttk.Scrollbar(tbl, orient="vertical",
            command=self._live_tree.yview)
        hsb = ttk.Scrollbar(tbl, orient="horizontal",
            command=self._live_tree.xview)
        self._live_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self._live_tree.pack(side="left", fill="both", expand=True)

        for sev, color in SEVERITY_COLORS.items():
            self._live_tree.tag_configure(sev, foreground=color,
                background=SEV_BG.get(sev, WHITE))

        # Detail panel — full description for the selected event
        detail = tk.Frame(page, bg=WHITE,
            highlightthickness=1, highlightbackground=BORDER)
        detail.pack(fill="x", padx=16, pady=(0, 12))
        tk.Label(detail, text="Event Detail",
            font=("Segoe UI", 8, "bold"),
            fg=ACCENT, bg=WHITE).pack(anchor="w", padx=10, pady=(6, 0))
        self._live_detail_text = tk.Text(detail,
            font=("Consolas", 8),
            bg=WHITE, fg=TEXT_DARK,
            relief="flat", wrap="word",
            state="disabled", height=4)
        self._live_detail_text.pack(fill="x", padx=10, pady=(2, 8))

        self._live_tree.bind("<<TreeviewSelect>>", self._on_live_select)
        self._live_tree.bind("<Double-1>", self._on_live_double_click)
        self._live_tree.bind("<Button-3>", self._on_live_right_click)

    # ── Threat Alerts page ──────────────────────────────────────────────────

    def _build_alerts_page(self):
        page = tk.Frame(self._content, bg=BG)
        page.place(x=0, y=0, relwidth=1, relheight=1)
        self._pages["alerts"] = page

        toolbar = tk.Frame(page, bg=WHITE, height=52)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)
        tk.Frame(page, bg=BORDER, height=1).pack(fill="x")

        tk.Button(toolbar,
            text="🔍  Run Historical Scan",
            font=("Segoe UI", 9, "bold"),
            bg=ACCENT, fg=WHITE_TEXT, relief="flat",
            padx=14, pady=6, cursor="hand2",
            command=self._run_historical_scan).pack(side="left", padx=12, pady=10)

        tk.Button(toolbar,
            text="📄  Export PDF",
            font=("Segoe UI", 9),
            bg=WHITE, fg=TEXT_MID, relief="flat",
            padx=10, pady=6, cursor="hand2",
            command=self._export_pdf).pack(side="left", padx=4, pady=10)

        tk.Button(toolbar,
            text="🗑  Clear",
            font=("Segoe UI", 9),
            bg=WHITE, fg=TEXT_MID, relief="flat",
            padx=10, pady=6, cursor="hand2",
            command=self._clear_alerts).pack(side="left", padx=4, pady=10)

        hb = tk.Frame(toolbar, bg=WHITE)
        hb.pack(side="right", padx=14)
        tk.Label(hb, text="Hours back:",
            font=("Segoe UI", 8), fg=TEXT_LIGHT, bg=WHITE).pack(side="left")
        self._hours_var = tk.StringVar(value=str(self.settings.hours_back))
        tk.Spinbox(hb, from_=1, to=168, width=5,
            textvariable=self._hours_var,
            font=("Segoe UI", 9),
            bg=BG, fg=TEXT_DARK, relief="flat",
            buttonbackground=BORDER).pack(side="left", padx=6)

        tbl = tk.Frame(page, bg=BG)
        tbl.pack(fill="both", expand=True, padx=16, pady=(12, 6))

        cols     = ("severity", "rule", "event_id", "channel",
                    "time", "computer", "user", "mitre")
        widths   = [80, 0, 58, 75, 155, 130, 100, 72]
        headings = ["Severity", "Rule", "Event ID", "Channel",
                    "Time", "Computer", "User", "MITRE"]

        self._alerts_tree = ttk.Treeview(tbl, columns=cols,
            displaycolumns=("severity", "time", "event_id",
                            "channel", "user", "rule", "mitre"),
            show="headings", selectmode="browse")
        for col, hd, w in zip(cols, headings, widths):
            self._alerts_tree.heading(col, text=hd)
            if w:
                self._alerts_tree.column(col, width=w, minwidth=40)
            else:
                self._alerts_tree.column(col, minwidth=180, stretch=True)

        vsb = ttk.Scrollbar(tbl, orient="vertical",
            command=self._alerts_tree.yview)
        hsb = ttk.Scrollbar(tbl, orient="horizontal",
            command=self._alerts_tree.xview)
        self._alerts_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self._alerts_tree.pack(side="left", fill="both", expand=True)

        for sev, color in SEVERITY_COLORS.items():
            self._alerts_tree.tag_configure(sev, foreground=color,
                background=SEV_BG.get(sev, WHITE))

        detail = tk.Frame(page, bg=WHITE,
            highlightthickness=1, highlightbackground=BORDER)
        detail.pack(fill="x", padx=16, pady=(0, 12))
        tk.Label(detail, text="Alert Detail",
            font=("Segoe UI", 8, "bold"),
            fg=ACCENT, bg=WHITE).pack(anchor="w", padx=10, pady=(6, 0))
        self._detail_text = tk.Text(detail,
            font=("Consolas", 8),
            bg=WHITE, fg=TEXT_DARK,
            relief="flat", wrap="word",
            state="disabled", height=4)
        self._detail_text.pack(fill="x", padx=10, pady=(2, 8))
        self._alerts_tree.bind("<<TreeviewSelect>>", self._on_alert_select)
        self._alerts_tree.bind("<Double-1>", self._on_alert_double_click)
        self._alerts_tree.bind("<Button-3>", self._on_alert_right_click)

    # ── History page ─────────────────────────────────────────────────────────

    def _build_history_page(self):
        page = tk.Frame(self._content, bg=BG)
        page.place(x=0, y=0, relwidth=1, relheight=1)
        self._pages["history"] = page

        toolbar = tk.Frame(page, bg=WHITE, height=52)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)
        tk.Frame(page, bg=BORDER, height=1).pack(fill="x")

        tk.Button(toolbar, text="🔄  Refresh",
            font=("Segoe UI", 9), bg=WHITE, fg=TEXT_MID, relief="flat",
            padx=10, pady=6, cursor="hand2",
            command=self._refresh_history).pack(side="left", padx=12, pady=10)

        tk.Button(toolbar, text="📄  Export PDF",
            font=("Segoe UI", 9), bg=WHITE, fg=TEXT_MID, relief="flat",
            padx=10, pady=6, cursor="hand2",
            command=self._export_history_pdf).pack(side="left", padx=4, pady=10)

        tk.Button(toolbar, text="🗑  Delete Session",
            font=("Segoe UI", 9), bg=WHITE, fg=ERROR_CLR, relief="flat",
            padx=10, pady=6, cursor="hand2",
            command=self._delete_session).pack(side="left", padx=4, pady=10)

        tbl = tk.Frame(page, bg=BG)
        tbl.pack(fill="both", expand=True, padx=16, pady=12)

        cols     = ("id", "type", "channels", "started",
                    "ended", "events", "alerts")
        widths   = [45, 95, 0, 155, 155, 80, 80]
        headings = ["ID", "Type", "Channels", "Started",
                    "Ended", "Events", "Alerts"]

        self._history_tree = ttk.Treeview(tbl, columns=cols,
            show="headings", selectmode="browse")
        for col, hd, w in zip(cols, headings, widths):
            self._history_tree.heading(col, text=hd)
            if w:
                self._history_tree.column(col, width=w, minwidth=40)
            else:
                self._history_tree.column(col, minwidth=180, stretch=True)

        vsb = ttk.Scrollbar(tbl, orient="vertical",
            command=self._history_tree.yview)
        hsb = ttk.Scrollbar(tbl, orient="horizontal",
            command=self._history_tree.xview)
        self._history_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self._history_tree.pack(side="left", fill="both", expand=True)
        self._history_tree.tag_configure("evenrow", background="#f0f4f8")
        self._history_tree.tag_configure("oddrow",  background=WHITE)

    # ── Settings page ────────────────────────────────────────────────────────

    def _build_settings_page(self):
        page = tk.Frame(self._content, bg=BG)
        page.place(x=0, y=0, relwidth=1, relheight=1)
        self._pages["settings"] = page

        canv = tk.Canvas(page, bg=BG, highlightthickness=0)
        self._settings_canvas = canv
        vsb  = ttk.Scrollbar(page, orient="vertical", command=canv.yview)
        canv.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canv.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canv, bg=BG)
        wid   = canv.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>",
            lambda e: canv.configure(scrollregion=canv.bbox("all")))
        canv.bind("<Configure>",
            lambda e: canv.itemconfig(wid, width=e.width))

        def section(text):
            f = tk.Frame(inner, bg=BG)
            f.pack(fill="x", padx=28, pady=(20, 4))
            tk.Label(f, text=text,
                font=("Segoe UI", 10, "bold"),
                fg=ACCENT, bg=BG).pack(side="left")
            tk.Frame(inner, bg=BORDER, height=1).pack(
                fill="x", padx=28, pady=(0, 6))

        def row(label, widget_fn):
            f = tk.Frame(inner, bg=WHITE,
                highlightthickness=1, highlightbackground=BORDER)
            f.pack(fill="x", padx=28, pady=3)
            tk.Label(f, text=label,
                font=("Segoe UI", 9), fg=TEXT_DARK, bg=WHITE,
                width=34, anchor="w", padx=14, pady=10).pack(side="left")
            widget_fn(f)

        def spin(f, var, lo, hi, inc=1):
            tk.Spinbox(f, from_=lo, to=hi, increment=inc, width=8,
                textvariable=var, font=("Segoe UI", 9),
                bg=BG, fg=TEXT_DARK, relief="flat",
                buttonbackground=BORDER).pack(
                    side="left", padx=(0, 14), pady=8)

        section("Scan Settings")
        self._sv_hours = tk.StringVar(value=str(self.settings.hours_back))
        row("Default hours back",
            lambda f: spin(f, self._sv_hours, 1, 168))
        self._sv_max = tk.StringVar(value=str(self.settings.max_events))
        row("Max events per scan",
            lambda f: spin(f, self._sv_max, 100, 10000, 100))

        section("Live Monitor")
        self._sv_poll = tk.StringVar(value=str(self.settings.poll_interval))
        row("Poll interval (seconds)",
            lambda f: spin(f, self._sv_poll, 1, 60))
        self._sv_auto = tk.BooleanVar(value=self.settings.auto_start_live)
        row("Auto-start on launch",
            lambda f: tk.Checkbutton(f, variable=self._sv_auto,
                bg=WHITE, fg=TEXT_DARK, selectcolor=ACCENT_LIGHT,
                activebackground=WHITE, relief="flat").pack(
                    side="left", padx=(0, 14), pady=8))

        section("Display")
        self._sv_time_24h = tk.BooleanVar(value=self.settings.time_format_24h)
        row("Use 24-hour clock",
            lambda f: tk.Checkbutton(f, variable=self._sv_time_24h,
                bg=WHITE, fg=TEXT_DARK, selectcolor=ACCENT_LIGHT,
                activebackground=WHITE, relief="flat").pack(
                    side="left", padx=(0, 14), pady=8))

        section("Brute Force Detection")
        self._sv_bf_thresh = tk.StringVar(
            value=str(self.settings.brute_force_threshold))
        row("Failure threshold (count)",
            lambda f: spin(f, self._sv_bf_thresh, 2, 50))
        self._sv_bf_window = tk.StringVar(
            value=str(self.settings.brute_force_window))
        row("Detection window (seconds)",
            lambda f: spin(f, self._sv_bf_window, 30, 3600, 30))

        section("Report Output")
        self._sv_report_dir = tk.StringVar(
            value=self.settings.report_output_dir)

        def report_row(f):
            tk.Entry(f, textvariable=self._sv_report_dir,
                font=("Segoe UI", 9), bg=BG, fg=TEXT_DARK,
                insertbackground=TEXT_DARK, relief="flat",
                width=36).pack(side="left", padx=(0, 6), pady=8)
            tk.Button(f, text="Browse",
                font=("Segoe UI", 8),
                bg=ACCENT_LIGHT, fg=ACCENT, relief="flat",
                padx=8, cursor="hand2",
                command=self._browse_report_dir).pack(side="left", pady=8)

        row("Save reports to", report_row)

        section("Data Management")
        bf = tk.Frame(inner, bg=BG)
        bf.pack(anchor="w", padx=28, pady=8)
        tk.Button(bf, text="Clear All History",
            font=("Segoe UI", 9), bg=ERROR_CLR, fg=WHITE_TEXT,
            relief="flat", padx=12, pady=6, cursor="hand2",
            command=self._clear_all_history).pack(side="left", padx=(0, 8))
        tk.Button(bf, text="Reset to Defaults",
            font=("Segoe UI", 9), bg=BORDER, fg=TEXT_MID,
            relief="flat", padx=12, pady=6, cursor="hand2",
            command=self._reset_settings).pack(side="left")

        tk.Button(inner, text="  Save Settings  ",
            font=("Segoe UI", 10, "bold"),
            bg=ACCENT, fg=WHITE_TEXT, relief="flat",
            padx=16, pady=8, cursor="hand2",
            command=self._save_settings).pack(
                anchor="w", padx=28, pady=(12, 24))

    # ── Status bar ──────────────────────────────────────────────────────────

    def _build_status_bar(self, parent: tk.Frame):
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", side="bottom")
        bar = tk.Frame(parent, bg=WHITE, height=26)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        self._status_var = tk.StringVar(
            value="Ready  •  Run as Administrator for full Security log access")
        tk.Label(bar, textvariable=self._status_var,
            font=("Segoe UI", 8), fg=TEXT_LIGHT, bg=WHITE).pack(
                side="left", padx=12)

    # =========================================================================
    # Logic
    # =========================================================================

    # ── Live monitor ─────────────────────────────────────────────────────────

    def _start_live(self):
        if self._is_live:
            return

        self._is_live         = True
        self._live_alerts     = []
        self._live_event_count= 0
        self._live_safe_count = 0
        self._scan_alerts     = []
        self._scan_event_count= 0
        self.engine.reset_windows()

        self._session_id = self.db.start_session(
            "live", self.settings.channels)
        self._scan_info = {
            "scan_type":    "live",
            "channels":     ", ".join(self.settings.channels),
            "hours_back":   None,
            "started_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ended_at":     "",
            "total_events": 0,
        }

        self._btn_start.configure(
            state="disabled", bg=BORDER, fg=TEXT_LIGHT)
        self._btn_stop.configure(
            state="normal", bg=ERROR_CLR, fg=WHITE_TEXT)
        self._card_status.configure(text="LIVE", fg=SUCCESS_CLR)
        self._live_dot.configure(text="● LIVE")
        self._start_live_flash()
        self._sidebar_status.configure(text="Monitoring active")
        self._set_status(
            f"Live monitoring active  •  polling every "
            f"{self.settings.poll_interval}s  •  waiting for new events...")

        self._live_thread = self.reader.start_live_monitor(
            channels=self.settings.channels,
            callback=lambda batch: self.root.after(
                0, self._on_live_batch, batch),
            poll_interval=self.settings.poll_interval,
        )

    def _on_live_batch(self, records: List[EventRecord]):
        """
        Called on the main thread once per poll cycle with all new events.
        Processes the entire batch in one pass so tkinter is never flooded
        with thousands of individual calls.
        """
        alert_map: Dict[int, ThreatAlert] = {}
        alerts_found: List[ThreatAlert]   = []

        for record in records:
            self._live_event_count  += 1
            self._scan_event_count  += 1
            alert = self.engine.analyze(record)
            if alert:
                self._live_alerts.append(alert)
                self._scan_alerts.append(alert)
                alerts_found.append(alert)
                alert_map[record.record_id] = alert
                if self._session_id:
                    self.db.save_alert(self._session_id, alert)
            else:
                self._live_safe_count += 1

        for record in records[-50:]:
            self._add_event_to_live_tree(
                record, alert_map.get(record.record_id))

        for alert in alerts_found:
            self._add_alert_to_tree(alert)

        if records:
            self._update_live_cards()
            if self._current_page == "dashboard":
                self._refresh_dashboard()
            self._set_status(
                f"Live  •  {self._live_event_count} events captured  •  "
                f"{len(self._live_alerts)} alerts  •  "
                f"last event: {records[-1].timestamp.strftime('%H:%M:%S')}")

    def _add_event_to_live_tree(
            self, record: EventRecord, alert: Optional[ThreatAlert]):
        tag = alert.severity.upper() if alert else "SAFE"

        # Use the alert's readable description when one exists
        if alert:
            display_desc = alert.description
        else:
            display_desc = record.description or ""
        display_desc = " ".join(display_desc.split())[:80]

        iid = self._live_tree.insert("", 0, values=(
            self._fmt_time(record.timestamp),
            record.channel,
            record.event_id,
            tag,
            (record.source or "")[:30],
            record.user or "",
            display_desc,
        ), tags=(tag,))

        self._live_item_data[iid] = {
            "description": alert.description if alert else (record.description or ""),
            "alert":       alert,
            "timestamp":   record.timestamp,
        }

        children = self._live_tree.get_children()
        if len(children) > 1000:
            removed = children[-1]
            self._live_tree.delete(removed)
            self._live_item_data.pop(removed, None)

    def _add_alert_to_tree(self, alert: ThreatAlert):
        self._alerts_tree.insert("", 0, values=(
            alert.severity,
            alert.rule_name,
            alert.event_id,
            alert.channel,
            self._fmt_time(alert.timestamp),
            alert.computer or "",
            alert.user or "",
            alert.mitre or "",
        ), tags=(alert.severity.upper(),))

    def _stop_live(self):
        if not self._is_live:
            return

        self.reader.stop_live_monitor()
        self._is_live = False

        ended_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._scan_info["ended_at"]     = ended_at
        self._scan_info["total_events"] = self._live_event_count

        if self._session_id:
            self.db.close_session(
                self._session_id,
                self._live_event_count,
                len(self._live_alerts))

        self._btn_start.configure(
            state="normal", bg=SUCCESS_CLR, fg=WHITE_TEXT)
        self._btn_stop.configure(
            state="disabled", bg=BORDER, fg=TEXT_LIGHT)
        self._card_status.configure(text="IDLE", fg=TEXT_LIGHT)
        self._stop_live_flash()
        self._sidebar_status.configure(text="Not monitoring")
        self._set_status(
            f"Live monitor stopped  •  {self._live_event_count} events captured  •  "
            f"{len(self._live_alerts)} alerts detected")

        self._refresh_history()

    def _clear_live(self):
        self._live_tree.delete(*self._live_tree.get_children())
        self._live_item_data.clear()

    def _on_live_select(self, _):
        sel = self._live_tree.selection()
        if not sel:
            return
        iid  = sel[0]
        vals = self._live_tree.item(iid)["values"]
        if not vals:
            return

        time_str, channel, event_id, _, source, user, _ = vals
        data  = self._live_item_data.get(iid, {})
        alert = data.get("alert")
        desc  = data.get("description", "")

        if alert:
            text = (
                f"[{alert.severity}]  {alert.rule_name}"
                + (f"  |  MITRE: {alert.mitre}" if alert.mitre else "") + "\n"
                f"Time: {time_str}  |  Channel: {channel}  "
                f"|  Event ID: {event_id}  |  User: {user}\n\n"
                f"{alert.description}"
            )
        else:
            text = (
                f"[SAFE]  No threat detected\n"
                f"Time: {time_str}  |  Channel: {channel}  "
                f"|  Event ID: {event_id}  |  Source: {source}  |  User: {user}\n\n"
                f"{desc or 'No description available.'}"
            )

        self._live_detail_text.configure(state="normal")
        self._live_detail_text.delete("1.0", "end")
        self._live_detail_text.insert("1.0", text)
        self._live_detail_text.configure(state="disabled")

    # ── Historical scan ──────────────────────────────────────────────────────

    def _run_historical_scan(self):
        if self._is_live:
            messagebox.showwarning("WinEvent Pro",
                "Stop the live monitor before running a historical scan.")
            return

        try:
            hours = int(self._hours_var.get())
        except ValueError:
            hours = self.settings.hours_back

        self._alerts_tree.delete(*self._alerts_tree.get_children())
        self._scan_alerts      = []
        self._scan_event_count = 0
        self.engine.reset_windows()

        session_id = self.db.start_session(
            "historical", self.settings.channels, hours_back=hours)
        self._session_id = session_id
        self._scan_info  = {
            "scan_type":    "historical",
            "channels":     ", ".join(self.settings.channels),
            "hours_back":   hours,
            "started_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ended_at":     "",
            "total_events": 0,
        }

        self._card_status.configure(text="SCANNING", fg=ACCENT)
        self._set_status(
            f"Running historical scan  •  last {hours} hours...")

        def _scan():
            all_records: List[EventRecord] = []
            for ch in self.settings.channels:
                try:
                    records = self.reader.read_channel(
                        ch,
                        hours_back=hours,
                        max_events=self.settings.max_events,
                    )
                    all_records.extend(records)
                except PermissionError as e:
                    self.root.after(0, lambda msg=str(e):
                        messagebox.showwarning("WinEvent Pro", msg))
                except Exception:
                    pass

            alerts = self.engine.analyze_batch(all_records)

            ended_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._scan_info["ended_at"]     = ended_at
            self._scan_info["total_events"] = len(all_records)

            self.db.close_session(session_id, len(all_records), len(alerts))
            self.db.save_alerts(session_id, alerts)
            self.root.after(0, self._on_scan_complete, alerts, len(all_records))

        threading.Thread(target=_scan, daemon=True).start()

    def _on_scan_complete(self, alerts: List[ThreatAlert], event_count: int):
        # Store for export — does NOT touch _live_alerts or dashboard cards
        self._scan_alerts      = alerts
        self._scan_event_count = event_count

        self._alerts_tree.delete(*self._alerts_tree.get_children())
        for alert in alerts:
            self._alerts_tree.insert("", "end", values=(
                alert.severity,
                alert.rule_name,
                alert.event_id,
                alert.channel,
                self._fmt_time(alert.timestamp),
                alert.computer or "",
                alert.user or "",
                alert.mitre or "",
            ), tags=(alert.severity.upper(),))

        self._refresh_history()
        self._card_status.configure(text="DONE", fg=SUCCESS_CLR)
        self._set_status(
            f"Scan complete  •  {event_count} events analysed  •  "
            f"{len(alerts)} threats detected")
        self._show_page("alerts")

    # ── Alerts ───────────────────────────────────────────────────────────────

    def _clear_alerts(self):
        self._alerts_tree.delete(*self._alerts_tree.get_children())
        self._scan_alerts      = []
        self._scan_event_count = 0

    def _on_alert_select(self, _):
        sel = self._alerts_tree.selection()
        if not sel:
            return
        vals = self._alerts_tree.item(sel[0])["values"]
        if not vals:
            return

        severity, rule, event_id, channel, time_str, computer, user, mitre = vals

        desc = ""
        for alert in self._scan_alerts:
            if (alert.rule_name == str(rule)
                    and alert.event_id == int(event_id)
                    and alert.timestamp.strftime(
                        "%Y-%m-%d %H:%M:%S") == str(time_str)):
                desc = alert.description
                break

        text = (
            f"[{severity}]  {rule}  |  Event ID: {event_id}  "
            f"|  Channel: {channel}\n"
            f"Time: {time_str}  |  Computer: {computer}  "
            f"|  User: {user}  |  MITRE: {mitre}\n\n{desc}"
        )
        self._detail_text.configure(state="normal")
        self._detail_text.delete("1.0", "end")
        self._detail_text.insert("1.0", text)
        self._detail_text.configure(state="disabled")

    # ── PDF export ───────────────────────────────────────────────────────────

    def _export_pdf(self):
        if self._scan_event_count == 0 and not self._scan_alerts:
            messagebox.showinfo("WinEvent Pro",
                "No scan data to export.\n\n"
                "Run a historical scan from this tab first, "
                "or stop the live monitor to export a live session.")
            return
        try:
            path = generate_report(
                alerts=self._scan_alerts,
                session_info=self._scan_info,
                output_dir=self.settings.report_output_dir,
            )
            messagebox.showinfo("WinEvent Pro", f"Report saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("WinEvent Pro",
                f"Failed to generate report:\n{e}")

    def _export_history_pdf(self):
        sel = self._history_tree.selection()
        if not sel:
            messagebox.showinfo("WinEvent Pro",
                "Select a session to export.")
            return

        vals       = self._history_tree.item(sel[0])["values"]
        session_id = vals[0]
        rows       = self.db.get_alerts(session_id)

        alerts: List[ThreatAlert] = []
        for row in rows:
            try:
                ts = datetime.fromisoformat(row["timestamp"])
            except Exception:
                ts = datetime.now()
            alerts.append(ThreatAlert(
                severity=row["severity"],
                rule_name=row["rule_name"],
                description=row["description"],
                event_id=row["event_id"],
                channel=row["channel"],
                timestamp=ts,
                computer=row["computer"] or "",
                user=row["user"],
                record_id=row["record_id"] or 0,
                mitre=row["mitre"] or "",
            ))

        sessions   = self.db.get_sessions()
        s          = next(
            (x for x in sessions if x["id"] == session_id), None)
        info = {
            "scan_type":    s["scan_type"]    if s else "historical",
            "channels":     s["channels"]     if s else "",
            "hours_back":   s["hours_back"]   if s else None,
            "started_at":   s["started_at"]   if s else "",
            "ended_at":     s["ended_at"]     if s else "",
            "total_events": s["total_events"] if s else 0,
        }

        try:
            path = generate_report(
                alerts=alerts,
                session_info=info,
                output_dir=self.settings.report_output_dir,
            )
            messagebox.showinfo("WinEvent Pro", f"Report saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("WinEvent Pro",
                f"Failed to generate report:\n{e}")

    # ── History ──────────────────────────────────────────────────────────────

    def _refresh_history(self):
        self._history_tree.delete(*self._history_tree.get_children())
        for i, row in enumerate(self.db.get_sessions()):
            bg = "evenrow" if i % 2 == 0 else "oddrow"
            self._history_tree.insert("", "end", values=(
                row["id"],
                row["scan_type"].title(),
                row["channels"],
                row["started_at"],
                row["ended_at"] or "—",
                row["total_events"],
                row["total_alerts"],
            ), tags=(bg,))

    def _delete_session(self):
        sel = self._history_tree.selection()
        if not sel:
            messagebox.showinfo("WinEvent Pro",
                "Select a session to delete.")
            return
        vals       = self._history_tree.item(sel[0])["values"]
        session_id = vals[0]
        if messagebox.askyesno("WinEvent Pro",
                f"Delete session {session_id} and all its alerts?"):
            self.db.delete_session(session_id)
            self._refresh_history()

    # ── Dashboard ────────────────────────────────────────────────────────────

    def _compute_sev_counts(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0,
                  "LOW": self._live_safe_count, "INFO": 0}
        for alert in self._live_alerts:
            sev = alert.severity.upper()
            if sev == "SAFE":
                counts["LOW"] += 1
            elif sev in counts:
                counts[sev] += 1
        return counts

    def _update_live_cards(self):
        """Update the top-bar metric cards from live monitor state only."""
        counts = self._compute_sev_counts()
        self._top_info.configure(text=str(counts["INFO"]))
        self._top_low.configure(text=str(counts["LOW"]))
        self._top_med.configure(text=str(counts["MEDIUM"]))
        self._top_high.configure(text=str(counts["HIGH"]))
        self._top_crit.configure(text=str(counts["CRITICAL"]))

    def _refresh_dashboard(self):
        """
        Rebuild the dashboard from live monitor state.
        Historical scans never call this — dashboard is live-only.
        """
        sev_counts = self._compute_sev_counts()
        ch_counts  = {"Security": 0, "System": 0, "Application": 0}
        for alert in self._live_alerts:
            if alert.channel in ch_counts:
                ch_counts[alert.channel] += 1

        # Sync top bar and dashboard stat cards — always identical
        self._top_info.configure(text=str(sev_counts["INFO"]))
        self._top_low.configure(text=str(sev_counts["LOW"]))
        self._top_med.configure(text=str(sev_counts["MEDIUM"]))
        self._top_high.configure(text=str(sev_counts["HIGH"]))
        self._top_crit.configure(text=str(sev_counts["CRITICAL"]))
        self._dash_cards["info"].configure(text=str(sev_counts["INFO"]))
        self._dash_cards["low"].configure(text=str(sev_counts["LOW"]))
        self._dash_cards["medium"].configure(text=str(sev_counts["MEDIUM"]))
        self._dash_cards["high"].configure(text=str(sev_counts["HIGH"]))
        self._dash_cards["critical"].configure(text=str(sev_counts["CRITICAL"]))

        total = sum(sev_counts.values())
        self._draw_donut(sev_counts, total)
        self._draw_channel_chart(ch_counts)

        # Session Alerts list — shows the individual alerts making up the donut
        self._dash_alert_tree.delete(*self._dash_alert_tree.get_children())
        if self._live_alerts:
            for alert in self._live_alerts:
                self._dash_alert_tree.insert("", "end", values=(
                    alert.severity,
                    alert.rule_name,
                    alert.timestamp.strftime(
                        "%H:%M:%S" if self.settings.time_format_24h else "%I:%M %p"),
                ), tags=(alert.severity.upper(),))
        else:
            self._dash_alert_tree.insert("", "end", values=(
                "", "Start live monitoring to see alerts here", ""))

    # ── Settings ─────────────────────────────────────────────────────────────

    def _on_settings_scroll(self, event):
        self._settings_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _save_settings(self):
        try:
            self.settings.hours_back            = int(self._sv_hours.get())
            self.settings.max_events            = int(self._sv_max.get())
            self.settings.poll_interval         = float(self._sv_poll.get())
            self.settings.auto_start_live       = self._sv_auto.get()
            self.settings.time_format_24h       = self._sv_time_24h.get()
            self.settings.brute_force_threshold = int(self._sv_bf_thresh.get())
            self.settings.brute_force_window    = int(self._sv_bf_window.get())
            self.settings.report_output_dir     = self._sv_report_dir.get()
            self.settings.save()
            self._reformat_all_times()
            messagebox.showinfo("WinEvent Pro", "Settings saved.")
        except Exception as e:
            messagebox.showerror("WinEvent Pro",
                f"Could not save settings:\n{e}")

    def _reset_settings(self):
        if messagebox.askyesno("WinEvent Pro",
                "Reset all settings to defaults?"):
            self.settings.reset()
            self._sv_hours.set(str(self.settings.hours_back))
            self._sv_max.set(str(self.settings.max_events))
            self._sv_poll.set(str(self.settings.poll_interval))
            self._sv_auto.set(self.settings.auto_start_live)
            self._sv_time_24h.set(self.settings.time_format_24h)
            self._sv_bf_thresh.set(str(self.settings.brute_force_threshold))
            self._sv_bf_window.set(str(self.settings.brute_force_window))
            self._sv_report_dir.set(self.settings.report_output_dir)
            messagebox.showinfo("WinEvent Pro", "Settings reset to defaults.")

    def _clear_all_history(self):
        if messagebox.askyesno("WinEvent Pro",
                "This will permanently delete all scan history and alerts. "
                "Continue?"):
            self.db.clear_all()
            self._refresh_history()
            messagebox.showinfo("WinEvent Pro", "All history cleared.")

    def _browse_report_dir(self):
        d = filedialog.askdirectory()
        if d:
            self._sv_report_dir.set(d)

    def _set_status(self, msg: str):
        self._status_var.set(msg)

    # ── Time format ───────────────────────────────────────────────────────────

    def _fmt_time(self, dt: datetime) -> str:
        if self.settings.time_format_24h:
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        return dt.strftime("%Y-%m-%d %I:%M:%S %p")

    def _reformat_all_times(self):
        """Reformat every timestamp in the live and alerts trees to match the
        current clock setting. Called immediately after saving settings."""
        for iid in self._live_tree.get_children():
            data = self._live_item_data.get(iid, {})
            ts   = data.get("timestamp")
            if ts:
                vals    = list(self._live_tree.item(iid)["values"])
                vals[0] = self._fmt_time(ts)
                self._live_tree.item(iid, values=vals)

        for iid in self._alerts_tree.get_children():
            vals    = list(self._alerts_tree.item(iid)["values"])
            # Find matching alert by rule + event_id + current time string (index 4)
            rule_str = str(vals[1])
            eid_int  = int(vals[2])
            for a in self._scan_alerts:
                if a.rule_name == rule_str and a.event_id == eid_int:
                    vals[4] = self._fmt_time(a.timestamp)
                    self._alerts_tree.item(iid, values=vals)
                    break

        self._refresh_dashboard()

    # ── Live-dot flash ────────────────────────────────────────────────────────

    def _start_live_flash(self):
        self._flash_active = True
        self._do_flash(True)

    def _do_flash(self, state: bool):
        if not self._flash_active:
            return
        self._live_dot.configure(fg="#4ade80" if state else SIDEBAR_BG)
        self.root.after(900, lambda: self._do_flash(not state))

    def _stop_live_flash(self):
        self._flash_active = False
        self._live_dot.configure(text="● IDLE", fg="#64748b")

    # ── Investigation ─────────────────────────────────────────────────────────

    @staticmethod
    def _extract_path(text: str) -> Optional[str]:
        """Return the first Windows absolute path found in text, or None."""
        if not text:
            return None
        m = re.search(r'[A-Za-z]:\\[^\s\'"<>|?*,;\n]+', text)
        return m.group(0).rstrip(".,)") if m else None

    def _get_alert_from_scan(self, rule: str, event_id: int,
                             time_str: str) -> Optional[ThreatAlert]:
        for a in self._scan_alerts:
            if (a.rule_name == rule
                    and a.event_id == event_id
                    and self._fmt_time(a.timestamp) == time_str):
                return a
        return None

    def _on_alert_double_click(self, event):
        iid = self._alerts_tree.identify_row(event.y)
        if not iid:
            return
        self._alerts_tree.selection_set(iid)
        vals = self._alerts_tree.item(iid)["values"]
        if not vals:
            return
        _, rule, event_id, _, time_str, _, _, _ = vals
        alert = self._get_alert_from_scan(str(rule), int(event_id), str(time_str))
        if alert:
            self._open_investigation_window(alert)

    def _on_live_double_click(self, event):
        iid = self._live_tree.identify_row(event.y)
        if not iid:
            return
        self._live_tree.selection_set(iid)
        data  = self._live_item_data.get(iid, {})
        alert = data.get("alert")
        if alert:
            self._open_investigation_window(alert)
        else:
            vals = self._live_tree.item(iid)["values"]
            if vals:
                self._open_safe_event_window(vals, data)

    def _on_alert_right_click(self, event):
        iid = self._alerts_tree.identify_row(event.y)
        if not iid:
            return
        self._alerts_tree.selection_set(iid)
        vals = self._alerts_tree.item(iid)["values"]
        if not vals:
            return
        _, rule, event_id, _, time_str, _, _, _ = vals
        alert = self._get_alert_from_scan(str(rule), int(event_id), str(time_str))

        menu = tk.Menu(self.root, tearoff=0)
        if alert:
            menu.add_command(label="Investigate...",
                             command=lambda: self._open_investigation_window(alert))
            menu.add_separator()
            menu.add_command(label="Copy Details",
                             command=lambda: self._copy_alert_to_clipboard(alert))
            path = self._extract_path(alert.description)
            if path:
                menu.add_command(label=f"Open File Location",
                                 command=lambda p=path: self._open_path_in_explorer(p))
            if alert.mitre:
                menu.add_command(label=f"MITRE ATT&CK  ({alert.mitre})",
                                 command=lambda: self._open_mitre(alert.mitre))
            menu.add_command(label="Open Event Viewer",
                             command=lambda: self._launch_event_viewer(
                                 alert.channel, alert.record_id))
        else:
            menu.add_command(label="(No alert data)")
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _on_live_right_click(self, event):
        iid = self._live_tree.identify_row(event.y)
        if not iid:
            return
        self._live_tree.selection_set(iid)
        data  = self._live_item_data.get(iid, {})
        alert = data.get("alert")
        vals  = self._live_tree.item(iid)["values"]

        menu = tk.Menu(self.root, tearoff=0)
        if alert:
            menu.add_command(label="Investigate...",
                             command=lambda: self._open_investigation_window(alert))
            menu.add_separator()
            menu.add_command(label="Copy Details",
                             command=lambda: self._copy_alert_to_clipboard(alert))
            path = self._extract_path(alert.description)
            if path:
                menu.add_command(label="Open File Location",
                                 command=lambda p=path: self._open_path_in_explorer(p))
            if alert.mitre:
                menu.add_command(label=f"MITRE ATT&CK  ({alert.mitre})",
                                 command=lambda: self._open_mitre(alert.mitre))
            menu.add_command(label="Open Event Viewer",
                             command=lambda: self._launch_event_viewer(
                                 alert.channel, alert.record_id))
        elif vals:
            menu.add_command(label="Copy Event Info",
                             command=lambda: self._copy_event_vals_to_clipboard(
                                 vals, data.get("description", "")))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _open_investigation_window(self, alert: ThreatAlert):
        win = tk.Toplevel(self.root)
        win.title(f"Investigate — {alert.rule_name}")
        win.geometry("680x520")
        win.resizable(True, True)
        win.configure(bg=BG)
        win.grab_set()

        sev_color = SEVERITY_COLORS.get(alert.severity.upper(), TEXT_LIGHT)

        # Severity header strip
        hdr = tk.Frame(win, bg=sev_color, height=44)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text=f"  [{alert.severity}]  {alert.rule_name}",
                 font=("Segoe UI", 11, "bold"),
                 fg=WHITE_TEXT, bg=sev_color, anchor="w").pack(
                     side="left", padx=14, fill="y")

        # Metadata grid
        meta_frame = tk.Frame(win, bg=WHITE,
            highlightthickness=1, highlightbackground=BORDER)
        meta_frame.pack(fill="x", padx=16, pady=(12, 0))

        meta_rows = [
            ("Event ID",   str(alert.event_id)),
            ("Channel",    alert.channel),
            ("Computer",   alert.computer or "—"),
            ("User",       alert.user or "—"),
            ("Time",       self._fmt_time(alert.timestamp)),
            ("Record ID",  str(alert.record_id) if alert.record_id else "—"),
            ("MITRE",      alert.mitre or "—"),
        ]
        for i, (k, v) in enumerate(meta_rows):
            row_bg = BG if i % 2 == 0 else WHITE
            rf = tk.Frame(meta_frame, bg=row_bg)
            rf.pack(fill="x")
            tk.Label(rf, text=k, font=("Segoe UI", 8, "bold"),
                     fg=TEXT_MID, bg=row_bg, width=12, anchor="w",
                     padx=12, pady=5).pack(side="left")
            tk.Label(rf, text=v, font=("Segoe UI", 8),
                     fg=TEXT_DARK, bg=row_bg, anchor="w",
                     padx=4, pady=5).pack(side="left")

        # Description
        desc_frame = tk.Frame(win, bg=WHITE,
            highlightthickness=1, highlightbackground=BORDER)
        desc_frame.pack(fill="both", expand=True, padx=16, pady=8)
        tk.Label(desc_frame, text="Description",
                 font=("Segoe UI", 8, "bold"),
                 fg=ACCENT, bg=WHITE).pack(anchor="w", padx=10, pady=(6, 0))
        desc_text = tk.Text(desc_frame, font=("Segoe UI", 9),
                            bg=WHITE, fg=TEXT_DARK,
                            relief="flat", wrap="word", padx=10, pady=6)
        desc_scroll = ttk.Scrollbar(desc_frame, orient="vertical",
                                    command=desc_text.yview)
        desc_text.configure(yscrollcommand=desc_scroll.set)
        desc_scroll.pack(side="right", fill="y")
        desc_text.pack(fill="both", expand=True)
        desc_text.insert("1.0", alert.description)
        desc_text.configure(state="disabled")

        # Action buttons
        btn_frame = tk.Frame(win, bg=BG)
        btn_frame.pack(fill="x", padx=16, pady=(0, 14))

        def btn(parent, text, cmd, color=ACCENT, fg=WHITE_TEXT):
            return tk.Button(parent, text=text, command=cmd,
                             font=("Segoe UI", 8, "bold"),
                             bg=color, fg=fg, relief="flat",
                             padx=10, pady=5, cursor="hand2")

        btn(btn_frame, "Copy Details",
            lambda: self._copy_alert_to_clipboard(alert),
            BORDER, TEXT_DARK).pack(side="left", padx=(0, 6))

        path = self._extract_path(alert.description)
        if path:
            btn(btn_frame, "Open File Location",
                lambda p=path: self._open_path_in_explorer(p)).pack(
                    side="left", padx=(0, 6))

        btn(btn_frame, "Open Event Viewer",
            lambda: self._launch_event_viewer(
                alert.channel, alert.record_id)).pack(
                    side="left", padx=(0, 6))

        if alert.mitre:
            btn(btn_frame, f"MITRE  {alert.mitre}",
                lambda: self._open_mitre(alert.mitre),
                "#7c3aed").pack(side="left", padx=(0, 6))

        tool = _CONTEXT_TOOLS.get(alert.rule_name)
        if tool:
            label, msc = tool
            btn(btn_frame, label,
                lambda m=msc: subprocess.Popen(
                    ["mmc", m], shell=True),
                "#0891b2").pack(side="left", padx=(0, 6))

        btn(btn_frame, "Close", win.destroy,
            BORDER, TEXT_DARK).pack(side="right")

    def _open_safe_event_window(self, vals, data: dict):
        time_str, channel, event_id, level, source, user, _ = vals
        desc = data.get("description", "") or "No description available."

        win = tk.Toplevel(self.root)
        win.title(f"Event Detail — ID {event_id}")
        win.geometry("620x420")
        win.resizable(True, True)
        win.configure(bg=BG)
        win.grab_set()

        hdr = tk.Frame(win, bg=SAFE_CLR, height=44)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text=f"  [SAFE]  No threat detected  —  Event ID {event_id}",
                 font=("Segoe UI", 11, "bold"),
                 fg=WHITE_TEXT, bg=SAFE_CLR, anchor="w").pack(
                     side="left", padx=14, fill="y")

        meta_frame = tk.Frame(win, bg=WHITE,
            highlightthickness=1, highlightbackground=BORDER)
        meta_frame.pack(fill="x", padx=16, pady=(12, 0))

        meta_rows = [
            ("Time",    str(time_str)),
            ("Channel", str(channel)),
            ("Severity", str(level)),
            ("Source",  str(source)),
            ("User",    str(user) if user else "—"),
        ]
        for i, (k, v) in enumerate(meta_rows):
            row_bg = BG if i % 2 == 0 else WHITE
            rf = tk.Frame(meta_frame, bg=row_bg)
            rf.pack(fill="x")
            tk.Label(rf, text=k, font=("Segoe UI", 8, "bold"),
                     fg=TEXT_MID, bg=row_bg, width=12, anchor="w",
                     padx=12, pady=5).pack(side="left")
            tk.Label(rf, text=v, font=("Segoe UI", 8),
                     fg=TEXT_DARK, bg=row_bg, anchor="w",
                     padx=4, pady=5).pack(side="left")

        desc_frame = tk.Frame(win, bg=WHITE,
            highlightthickness=1, highlightbackground=BORDER)
        desc_frame.pack(fill="both", expand=True, padx=16, pady=8)
        tk.Label(desc_frame, text="Event Description",
                 font=("Segoe UI", 8, "bold"),
                 fg=ACCENT, bg=WHITE).pack(anchor="w", padx=10, pady=(6, 0))
        desc_text = tk.Text(desc_frame, font=("Segoe UI", 9),
                            bg=WHITE, fg=TEXT_DARK,
                            relief="flat", wrap="word", padx=10, pady=6)
        desc_scroll = ttk.Scrollbar(desc_frame, orient="vertical",
                                    command=desc_text.yview)
        desc_text.configure(yscrollcommand=desc_scroll.set)
        desc_scroll.pack(side="right", fill="y")
        desc_text.pack(fill="both", expand=True)
        desc_text.insert("1.0", desc)
        desc_text.configure(state="disabled")

        btn_frame = tk.Frame(win, bg=BG)
        btn_frame.pack(fill="x", padx=16, pady=(0, 14))
        tk.Button(btn_frame, text="Copy Details",
                  command=lambda: self._copy_event_vals_to_clipboard(vals, desc),
                  font=("Segoe UI", 8, "bold"),
                  bg=BORDER, fg=TEXT_DARK, relief="flat",
                  padx=10, pady=5, cursor="hand2").pack(side="left", padx=(0, 6))
        tk.Button(btn_frame, text="Close", command=win.destroy,
                  font=("Segoe UI", 8, "bold"),
                  bg=BORDER, fg=TEXT_DARK, relief="flat",
                  padx=10, pady=5, cursor="hand2").pack(side="right")

    def _copy_alert_to_clipboard(self, alert: ThreatAlert):
        lines = [
            f"WinEvent Pro — Alert",
            f"",
            f"Severity   : {alert.severity}",
            f"Rule       : {alert.rule_name}",
            f"Event ID   : {alert.event_id}",
            f"Channel    : {alert.channel}",
            f"Time       : {self._fmt_time(alert.timestamp)}",
            f"Computer   : {alert.computer or '—'}",
            f"User       : {alert.user or '—'}",
            f"MITRE      : {alert.mitre or '—'}",
            f"Record ID  : {alert.record_id or '—'}",
            f"",
            f"Description:",
            alert.description,
        ]
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(lines))
        self._set_status("Alert details copied to clipboard.")

    def _copy_event_vals_to_clipboard(self, vals, desc: str):
        time_str, channel, event_id, level, source, user, _ = vals
        lines = [
            f"WinEvent Pro — Event",
            f"",
            f"Time       : {time_str}",
            f"Channel    : {channel}",
            f"Event ID   : {event_id}",
            f"Severity   : {level}",
            f"Source     : {source}",
            f"User       : {user or '—'}",
            f"",
            f"Description:",
            desc,
        ]
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(lines))
        self._set_status("Event details copied to clipboard.")

    def _open_path_in_explorer(self, path: str):
        import os
        try:
            if os.path.isfile(path):
                subprocess.Popen(["explorer", "/select,", path])
            elif os.path.isdir(path):
                subprocess.Popen(["explorer", path])
            else:
                parent = os.path.dirname(path)
                if os.path.isdir(parent):
                    subprocess.Popen(["explorer", parent])
                else:
                    messagebox.showinfo("WinEvent Pro",
                        f"Path not found on this system:\n{path}")
        except Exception as e:
            messagebox.showerror("WinEvent Pro",
                f"Could not open Explorer:\n{e}")

    def _launch_event_viewer(self, channel: str, record_id: int):
        messagebox.showinfo(
            "Open in Event Viewer",
            f"Event Viewer will open now.\n\n"
            f"To find this specific event:\n"
            f"  1. Expand Windows Logs in the left panel\n"
            f"  2. Click '{channel}'\n"
            f"  3. Use Find (Ctrl+F) or filter for Record ID: {record_id}",
        )
        try:
            subprocess.Popen(["eventvwr.msc"], shell=True)
        except Exception as e:
            messagebox.showerror("WinEvent Pro",
                f"Could not open Event Viewer:\n{e}")

    def _open_mitre(self, mitre_id: str):
        if not mitre_id:
            return
        parts = mitre_id.split(".")
        if len(parts) == 2:
            url = (f"https://attack.mitre.org/techniques/"
                   f"{parts[0]}/{parts[1].zfill(3)}/")
        else:
            url = f"https://attack.mitre.org/techniques/{parts[0]}/"
        webbrowser.open(url)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Re-launch as Administrator automatically if not already elevated.
    # This triggers the standard Windows UAC prompt once; after that the
    # elevated process runs normally with no further prompting.
    try:
        _is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        _is_admin = False

    if not _is_admin:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas",
            sys.executable,
            " ".join(f'"{a}"' for a in sys.argv),
            None, 1,
        )
        sys.exit(0)

    root = tk.Tk()

    # Set window icon (titlebar + taskbar) when the .ico file is available,
    # whether running from source or as a PyInstaller exe.
    import sys as _sys, os as _os
    _ico = (_os.path.join(_sys._MEIPASS, "WinEventPro.ico")
            if hasattr(_sys, "_MEIPASS")
            else _os.path.join(_os.path.dirname(_os.path.abspath(__file__)),
                               "WinEventPro.ico"))
    if _os.path.exists(_ico):
        root.iconbitmap(_ico)

    app  = WinEventPro(root)
    root.mainloop()
