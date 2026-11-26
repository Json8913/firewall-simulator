#!/usr/bin/env python3
"""Desktop interface for the synthetic firewall rule simulator."""

import tkinter as tk
from tkinter import ttk

from firewall_simulator import RULES, SAMPLE_PACKETS, decide


BG = "#0b1220"
PANEL = "#121d2e"
TEXT = "#edf4ff"
MUTED = "#9bacbf"
ACCENT = "#45d6c5"


class FirewallApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Firewall Simulator")
        self.geometry("980x660")
        self.minsize(760, 520)
        self.configure(bg=BG)
        self._style()
        self._build()
        self.run_sample()

    def _style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", font=("Arial", 10))
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Muted.TLabel", background=BG, foreground=MUTED)
        style.configure("Card.TLabel", background=PANEL, foreground=TEXT)
        style.configure("TButton", padding=(12, 8), background="#24364b",
                        foreground=TEXT, borderwidth=0)
        style.configure("Accent.TButton", background=ACCENT, foreground="#07131b",
                        font=("Arial", 10, "bold"))
        style.configure("Treeview", background="#0f1928", fieldbackground="#0f1928",
                        foreground=TEXT, rowheight=30, borderwidth=0)
        style.configure("Treeview.Heading", background="#1d2c40", foreground=TEXT, padding=7)

    def _build(self):
        shell = ttk.Frame(self, padding=24)
        shell.pack(fill="both", expand=True)
        ttk.Label(shell, text="POLICY LAB  /  SYNTHETIC TRAFFIC", style="Muted.TLabel").pack(anchor="w")
        ttk.Label(shell, text="Firewall Simulator", font=("Arial", 25, "bold")).pack(anchor="w", pady=(6, 4))
        ttk.Label(shell, text="Review rule order and see which rule decides each sample packet.",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 18))
        card = ttk.Frame(shell, style="Card.TFrame", padding=16)
        card.pack(fill="x")
        ttk.Label(card, text="Ordered rule set", style="Card.TLabel",
                  font=("Arial", 12, "bold")).pack(anchor="w", pady=(0, 10))
        rules = ttk.Treeview(card, columns=("action", "source", "protocol", "port", "reason"),
                             show="headings", height=3)
        for col, label, width in (("action", "Action", 90), ("source", "Source network", 170),
                                  ("protocol", "Protocol", 100), ("port", "Port", 80),
                                  ("reason", "Reason", 400)):
            rules.heading(col, text=label)
            rules.column(col, width=width, anchor="w")
        rules.pack(fill="x")
        for i, rule in enumerate(RULES, 1):
            rules.insert("", "end", values=(f"{i}. {rule.action.upper()}", rule.source,
                                            rule.protocol, rule.destination_port or "any", rule.reason))
        ttk.Button(shell, text="Evaluate sample traffic", style="Accent.TButton",
                   command=self.run_sample).pack(anchor="e", pady=(14, 10))
        ttk.Label(shell, text="Decision trace", font=("Arial", 14, "bold")).pack(anchor="w", pady=(0, 8))
        self.results = ttk.Treeview(shell, columns=("source", "protocol", "port", "decision", "rule", "reason"),
                                    show="headings")
        for col, label, width in (("source", "Source", 160), ("protocol", "Protocol", 90),
                                  ("port", "Destination port", 120), ("decision", "Result", 100),
                                  ("rule", "Matched rule", 110), ("reason", "Why", 320)):
            self.results.heading(col, text=label)
            self.results.column(col, width=width, anchor="w")
        self.results.pack(fill="both", expand=True)
        self.results.tag_configure("allow", foreground="#67e8b5")
        self.results.tag_configure("deny", foreground="#ff9a9a")

    def run_sample(self):
        self.results.delete(*self.results.get_children())
        for packet in SAMPLE_PACKETS:
            action, reason, number = decide(packet)
            self.results.insert("", "end",
                values=(packet["source"], packet["protocol"].upper(),
                        packet["destination_port"], action, number, reason),
                tags=(action.lower(),))


if __name__ == "__main__":
    FirewallApp().mainloop()
