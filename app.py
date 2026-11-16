"""NetMon desktop UI. All Tk and SQLite UI work stays on the main thread."""
from __future__ import annotations

import argparse
import ipaddress
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, font as tkfont, messagebox, simpledialog, ttk

from app_paths import VERSION, data_directory, resource_path
import bluetooth_scan
from exporting import write_csv
import network_scan
from oui_lookup import OuiDatabase, guess_device
from storage import Storage

BG = "#f3f6fa"
INK = "#172b41"
MUTED = "#5d6c7f"
TEAL = "#087f70"
NET_COLUMNS = [("label", "Your label", 175), ("ip", "IP address", 125), ("mac", "MAC address", 155),
               ("hostname", "Hostname", 180), ("vendor", "Vendor", 220), ("guess", "Device hint", 175),
               ("interface", "Seen via", 145)]
BT_COLUMNS = [("label", "Your label", 165), ("name", "Advertised name", 210), ("address", "Address", 190),
              ("rssi", "Signal (dBm)", 115), ("vendor", "Vendor hint", 210), ("guess", "Device hint", 180)]


class DeviceTable(ttk.Frame):
    def __init__(self, parent, columns, empty_text, edit, context):
        super().__init__(parent, style="Card.TFrame")
        self.columns = columns
        self.records = []
        self.visible = []
        self.sort_column = None
        self.descending = False
        self.query = tk.StringVar()
        self.count = tk.StringVar(value="0 devices")
        toolbar = ttk.Frame(self, style="Card.TFrame", padding=(14, 8))
        toolbar.grid(row=0, column=0, columnspan=2, sticky="ew")
        ttk.Label(toolbar, text="Search", style="Card.TLabel").pack(side="left", padx=(0, 8))
        search = ttk.Entry(toolbar, textvariable=self.query, width=34)
        search.pack(side="left")
        search.bind("<Escape>", lambda _: self.query.set(""))
        ttk.Button(toolbar, text="Clear", command=lambda: self.query.set("")).pack(side="left", padx=6)
        ttk.Label(toolbar, textvariable=self.count, style="MutedCard.TLabel").pack(side="right")
        self.tree = ttk.Treeview(self, columns=[c[0] for c in columns], show="headings", selectmode="browse", height=6)
        for key, title, width in columns:
            self.tree.heading(key, text=title, command=lambda k=key: self.sort_by(k))
            self.tree.column(key, width=width, minwidth=width, stretch=True, anchor="w")
        self.tree.tag_configure("even", background="#ffffff")
        self.tree.tag_configure("odd", background="#f6f9fc")
        self.tree.tag_configure("alert", background="#fff1d6", foreground="#724500")
        self.tree.grid(row=1, column=0, sticky="nsew")
        vertical = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        horizontal = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        vertical.grid(row=1, column=1, sticky="ns")
        horizontal.grid(row=2, column=0, sticky="ew")
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.empty_text = empty_text
        self.empty = ttk.Label(self.tree, text=empty_text, style="Empty.TLabel", justify="center", anchor="center")
        self.tree.bind("<Double-1>", lambda e: edit() if self.tree.identify_region(e.x, e.y) == "cell" else None)
        self.tree.bind("<Return>", lambda _: edit())
        self.tree.bind("<Button-3>", context)
        self.query.trace_add("write", lambda *_: self.render())
        self.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)
        self.render()

    def selected(self):
        selection = self.tree.selection()
        return next((r for r in self.records if r["_key"] == selection[0]), None) if selection else None

    def sort_by(self, key):
        self.descending = not self.descending if self.sort_column == key else False
        self.sort_column = key
        self.render()

    def render(self, records=None):
        if records is not None:
            self.records = records
        selected = self.tree.selection()
        yview = self.tree.yview()[0]
        query = self.query.get().casefold().strip()
        self.visible = [r for r in self.records if query in " ".join(str(r.get(k, "")) for k, _, _ in self.columns).casefold()]
        if self.sort_column:
            def sort_key(row):
                value = row.get(self.sort_column)
                if self.sort_column == "ip":
                    return int(ipaddress.IPv4Address(value))
                if self.sort_column == "rssi":
                    return value if value is not None else -999
                return str(value or "").casefold()
            self.visible.sort(key=sort_key, reverse=self.descending)
        for key, title, _ in self.columns:
            suffix = (" ▼" if self.descending else " ▲") if key == self.sort_column else ""
            self.tree.heading(key, text=title + suffix)
        self.tree.delete(*self.tree.get_children())
        for i, row in enumerate(self.visible):
            self.tree.insert("", "end", iid=row["_key"], values=[row.get(k) if row.get(k) is not None else "—" for k, _, _ in self.columns],
                             tags=("alert" if row.get("_alert") else "odd" if i % 2 else "even",))
        if selected and self.tree.exists(selected[0]):
            self.tree.selection_set(selected[0])
        self.tree.yview_moveto(yview)
        self.count.set(f"{len(self.visible)} of {len(self.records)} devices" if query else f"{len(self.records)} devices")
        if self.visible:
            self.empty.place_forget()
        else:
            self.empty.configure(text="No devices match your search.\nTry a label, address, name, or vendor." if query else self.empty_text)
            self.empty.place(relx=0.5, rely=0.48, anchor="center")


class App(tk.Tk):
    def __init__(self, data_dir: Path | None = None, auto_start=True):
        super().__init__()
        self.withdraw()
        self.title(f"NetMon {VERSION}")
        width = min(1280, max(900, self.winfo_screenwidth() - 80))
        height = min(800, max(580, self.winfo_screenheight() - 140))
        self.geometry(f"{width}x{height}")
        self.minsize(900, 580)
        self.configure(background=BG)
        self.data_dir = Path(data_dir) if data_dir else data_directory()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.storage = Storage(str(self.data_dir / "monitor.db"))
        cached = self.data_dir / "manuf.txt"
        self.oui = OuiDatabase(str(cached if cached.exists() else resource_path("manuf.txt")))
        self.queue = queue.Queue()
        self.net_stop, self.bt_stop = threading.Event(), threading.Event()
        self.net_busy = self.bt_busy = self.oui_busy = self.closing = False
        self.bt_service = None
        self.auto_id = None
        self.alerts = {}
        self.current_scope = None
        self._build_ui()
        self.refresh_adapters()
        self.refresh_events()
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.bind("<F5>", lambda _: self.start_bluetooth() if self.nb.index("current") == 1 else self.start_network())
        self.bind("<Control-e>", lambda _: self.export_current())
        self.after(80, self.drain)
        if auto_start:
            self.after(350, self.start_network)
        self.deiconify()

    def _build_ui(self):
        families = tkfont.families(self)
        font = "Segoe UI" if "Segoe UI" in families else "DejaVu Sans" if "DejaVu Sans" in families else "TkDefaultFont"
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", font=(font, 10), background=BG, foreground=INK)
        style.configure("TButton", padding=(12, 8), borderwidth=0)
        style.map("TButton", background=[("active", "#dce8ef")])
        style.configure("Accent.TButton", background=TEAL, foreground="white", font=(font, 10, "bold"))
        style.map("Accent.TButton", background=[("disabled", "#8aada8"), ("active", "#096b60")], foreground=[("disabled", "#ffffff")])
        style.configure("Card.TFrame", background="white")
        style.configure("Card.TLabel", background="white")
        style.configure("Muted.TLabel", foreground=MUTED)
        style.configure("MutedCard.TLabel", background="white", foreground=MUTED)
        style.configure("Empty.TLabel", background="white", foreground=MUTED, padding=20)
        style.configure("Metric.TLabel", background="white", font=(font, 24, "bold"))
        style.configure("Horizontal.TProgressbar", thickness=4, borderwidth=0, background=TEAL, troughcolor="#e0e9ef")
        style.configure("Treeview", background="white", fieldbackground="white", rowheight=34, borderwidth=0)
        style.configure("Treeview.Heading", font=(font, 10, "bold"), padding=(10, 10), background="#e7edf4", relief="flat")
        style.map("Treeview", background=[("selected", "#d3ede9")], foreground=[("selected", "#123a36")])
        style.configure("TNotebook", borderwidth=0, tabmargins=(0, 0, 0, 10))
        style.configure("TNotebook.Tab", padding=(22, 10), font=(font, 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", "white")], foreground=[("selected", TEAL)])
        try:
            self.iconphoto(True, tk.PhotoImage(file=str(resource_path("assets/netmon.png"))))
        except tk.TclError:
            pass
        menu = tk.Menu(self)
        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(label="Export current view…", accelerator="Ctrl+E", command=self.export_current)
        file_menu.add_command(label="Open data folder", command=self.open_data)
        file_menu.add_command(label="Refresh vendor database", command=self.update_oui)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.close)
        menu.add_cascade(label="File", menu=file_menu)
        help_menu = tk.Menu(menu, tearoff=False)
        help_menu.add_command(label="About NetMon", command=self.about)
        menu.add_cascade(label="Help", menu=help_menu)
        self.configure(menu=menu)
        header = tk.Frame(self, background="#152d43", padx=24, pady=10)
        header.pack(fill="x")
        tk.Label(header, text="NetMon", background="#152d43", foreground="white", font=(font, 26, "bold")).pack(side="left")
        tk.Label(header, text="LOCAL NETWORK  /  BLUETOOTH", background="#152d43", foreground="#b8cbd9", font=(font, 10)).pack(side="left", padx=20, pady=(9, 0))
        tk.Label(header, text=f"v{VERSION}", background="#152d43", foreground="#b8cbd9").pack(side="right")
        metrics = ttk.Frame(self, padding=(20, 12, 20, 8))
        metrics.pack(fill="x")
        self.net_count, self.bt_count, self.alert_count = tk.StringVar(value="—"), tk.StringVar(value="—"), tk.StringVar(value="0")
        for i, (title, value, caption) in enumerate([
            ("NETWORK DEVICES", self.net_count, "Observed in the latest completed scan"),
            ("BLUETOOTH LE", self.bt_count, "Nearby devices advertising during the scan"),
            ("ADDRESS CHANGES", self.alert_count, "Unacknowledged changes on this network"),
        ]):
            card = ttk.Frame(metrics, style="Card.TFrame", padding=(18, 8))
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            metrics.columnconfigure(i, weight=1, uniform="cards")
            ttk.Label(card, text=title, style="MutedCard.TLabel", font=(font, 9, "bold")).pack(anchor="w")
            ttk.Label(card, textvariable=value, style="Metric.TLabel").pack(anchor="w", pady=3)
            ttk.Label(card, text=caption, style="MutedCard.TLabel", wraplength=285).pack(anchor="w")
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=20)
        net, bt, activity = ttk.Frame(self.nb), ttk.Frame(self.nb), ttk.Frame(self.nb)
        self.nb.add(net, text="Local network")
        self.nb.add(bt, text="Bluetooth LE")
        self.nb.add(activity, text="Activity")
        adapter_bar = ttk.Frame(net)
        adapter_bar.pack(fill="x", pady=(0, 8))
        ttk.Label(adapter_bar, text="Adapter", font=(font, 10, "bold")).pack(side="left", padx=(0, 10))
        self.adapter_var = tk.StringVar()
        self.adapter_box = ttk.Combobox(adapter_bar, textvariable=self.adapter_var, state="readonly", width=72)
        self.adapter_box.pack(side="left", fill="x", expand=True)
        self.adapter_box.bind("<<ComboboxSelected>>", self.adapter_changed)
        self.adapter_refresh = ttk.Button(adapter_bar, text="Refresh adapters", command=self.refresh_adapters)
        self.adapter_refresh.pack(side="left", padx=(8, 0))
        bar = ttk.Frame(net)
        bar.pack(fill="x", pady=(0, 8))
        self.net_button = ttk.Button(bar, text="Scan network", style="Accent.TButton", command=self.start_network)
        self.net_button.pack(side="left")
        self.net_cancel = ttk.Button(bar, text="Stop", state="disabled", command=self.cancel_network)
        self.net_cancel.pack(side="left", padx=6)
        self.auto = tk.BooleanVar(value=self.storage.get_setting("auto", "1") == "1")
        self.auto_check = ttk.Checkbutton(bar, text="Auto scan · 30 sec", variable=self.auto, command=self.schedule)
        self.auto_check.pack(side="left", padx=6)
        ttk.Button(bar, text="Edit label", command=lambda: self.edit_label("net")).pack(side="left", padx=5)
        ttk.Button(bar, text="Export CSV", command=lambda: self.export_table(self.net_table, "network")).pack(side="right")
        self.net_status = tk.StringVar(value="Ready to scan your selected local network.")
        ttk.Label(net, textvariable=self.net_status, style="Muted.TLabel").pack(anchor="w", pady=(0, 6))
        net_track = ttk.Frame(net, height=4)
        net_track.pack(fill="x", pady=(0, 8))
        self.net_progress = ttk.Progressbar(net_track, mode="indeterminate")
        self.net_progress.place(relwidth=1, relheight=1)
        self.net_table = DeviceTable(net, NET_COLUMNS, "Your local network, at a glance.\nChoose an adapter, then select Scan network.", lambda: self.edit_label("net"), lambda e: self.context_menu(e, "net"))
        self.net_table.pack(fill="both", expand=True)
        ttk.Label(net, text="Neighbor-table observations can include cached or sleeping devices. “Seen via” is your PC's adapter, not the device's connection type.", style="Muted.TLabel", wraplength=1120).pack(anchor="w", fill="x", side="bottom", before=self.net_table, pady=(8, 4))
        bar = ttk.Frame(bt)
        bar.pack(fill="x", pady=(0, 10))
        self.bt_button = ttk.Button(bar, text="Scan Bluetooth", style="Accent.TButton", command=self.start_bluetooth)
        self.bt_button.pack(side="left")
        self.bt_cancel = ttk.Button(bar, text="Stop", state="disabled", command=self.cancel_bluetooth)
        self.bt_cancel.pack(side="left", padx=6)
        ttk.Button(bar, text="Edit label", command=lambda: self.edit_label("bt")).pack(side="left", padx=5)
        ttk.Button(bar, text="Export CSV", command=lambda: self.export_table(self.bt_table, "bluetooth")).pack(side="right")
        self.bt_status = tk.StringVar(value="Scan for 6 seconds. Your Bluetooth radio must be switched on.")
        ttk.Label(bt, textvariable=self.bt_status, style="Muted.TLabel").pack(anchor="w", pady=(0, 6))
        bt_track = ttk.Frame(bt, height=4)
        bt_track.pack(fill="x", pady=(0, 8))
        self.bt_progress = ttk.Progressbar(bt_track, mode="indeterminate")
        self.bt_progress.place(relwidth=1, relheight=1)
        self.bt_table = DeviceTable(bt, BT_COLUMNS, "Discover nearby Bluetooth LE devices.\nStart a scan with your Bluetooth radio switched on.", lambda: self.edit_label("bt"), lambda e: self.context_menu(e, "bt"))
        self.bt_table.pack(fill="both", expand=True)
        ttk.Label(bt, text="BLE advertising only; this does not pair with devices. Private Bluetooth addresses may change, and vendor/device hints are estimates.", style="Muted.TLabel", wraplength=1120).pack(anchor="w", fill="x", side="bottom", before=self.bt_table, pady=(8, 4))
        bar = ttk.Frame(activity)
        bar.pack(fill="x", pady=(0, 10))
        ttk.Label(bar, text="Address-change history", font=(font, 12, "bold")).pack(side="left")
        ttk.Button(bar, text="Acknowledge current changes", command=self.ack_all).pack(side="right")
        self.events = ttk.Treeview(activity, columns=("time", "message"), show="headings")
        self.events.heading("time", text="Time")
        self.events.heading("message", text="Observation")
        self.events.column("time", width=175, stretch=False)
        self.events.column("message", width=880)
        scrollbar = ttk.Scrollbar(activity, orient="vertical", command=self.events.yview)
        scrollbar.pack(side="right", fill="y")
        self.events.configure(yscrollcommand=scrollbar.set)
        self.events.pack(fill="both", expand=True)
        ttk.Label(activity, text="An IP address can be reassigned by your router. A changed MAC address alone is not evidence of an intrusion.", style="Muted.TLabel").pack(anchor="w", pady=8)
        self.status = tk.StringVar(value=f"Ready  ·  {self.oui.count:,} vendor prefixes loaded")
        ttk.Label(self, textvariable=self.status, style="Muted.TLabel", padding=(22, 10)).pack(fill="x", side="bottom", before=self.nb)

    def selected_adapter(self):
        index = self.adapter_box.current()
        return self.adapters[index] if 0 <= index < len(self.adapters) else None

    def refresh_adapters(self):
        previous = self.selected_adapter() if hasattr(self, "adapters") else None
        try:
            self.adapters = network_scan.get_adapters()
        except Exception as exc:
            self.adapters = []
            self.status.set(f"Adapter detection failed: {exc}")
        self.adapter_box.configure(values=[a.display for a in self.adapters])
        saved = previous.name if previous else self.storage.get_setting("adapter")
        if self.adapters:
            index = next((i for i, a in enumerate(self.adapters) if a.name == saved), 0)
            self.adapter_box.current(index)
        else:
            self.adapter_var.set("No active IPv4 adapters — connect to Wi-Fi or Ethernet, then refresh")
        self.adapter_changed()

    def adapter_changed(self, _event=None):
        adapter = self.selected_adapter()
        scope = adapter.scope if adapter else None
        if scope != self.current_scope:
            self.current_scope = scope
            self.net_table.render([])
            self.net_count.set("—")
            self.net_status.set("Ready to scan." if adapter else "No active network adapter.")
        self.update_alert_count()
        if adapter:
            self.storage.set_setting("adapter", adapter.name)
        self.net_button.configure(state="normal" if adapter else "disabled")
        self.schedule()

    def schedule(self):
        if self.auto_id:
            self.after_cancel(self.auto_id)
            self.auto_id = None
        self.storage.set_setting("auto", "1" if self.auto.get() else "0")
        if self.auto.get() and not self.net_busy and not self.closing and self.selected_adapter():
            self.auto_id = self.after(30_000, self.start_network)

    def start_network(self):
        adapter = self.selected_adapter()
        if self.net_busy or self.closing or not adapter:
            return
        if self.auto_id:
            self.after_cancel(self.auto_id)
            self.auto_id = None
        self.net_busy = True
        self.net_stop.clear()
        self.net_button.configure(state="disabled")
        self.adapter_box.configure(state="disabled")
        self.adapter_refresh.configure(state="disabled")
        self.net_cancel.configure(state="normal")
        self.net_progress.start(12)
        self.net_status.set(f"Scanning {adapter.scan_cidr} via {adapter.name}…")
        def worker():
            start = time.monotonic()
            try:
                devices = network_scan.scan_network(adapter, self.net_stop)
                self.queue.put(("net", devices, adapter, time.monotonic() - start, None))
            except Exception as exc:
                logging.exception("Network scan failed")
                self.queue.put(("net", [], adapter, 0, str(exc)))
        threading.Thread(target=worker, daemon=True, name="netmon-network").start()

    def cancel_network(self):
        self.net_stop.set()
        self.net_cancel.configure(state="disabled")
        self.net_status.set("Stopping scan…")

    def finish_network(self, devices, adapter, elapsed, error):
        self.net_busy = False
        self.net_progress.stop()
        self.net_button.configure(state="normal")
        self.net_cancel.configure(state="disabled")
        self.adapter_box.configure(state="readonly")
        self.adapter_refresh.configure(state="normal")
        if self.net_stop.is_set():
            self.net_status.set("Scan stopped. Previous results kept.")
        elif error:
            self.net_status.set("Scan failed. Check the status bar for details, then try again.")
            self.status.set(error)
        else:
            rows = []
            for device in devices:
                change = self.storage.update_ip_mac(device.ip, device.mac, adapter.scope)
                alert_key = (adapter.scope, device.ip)
                if change:
                    self.alerts[alert_key] = change
                    self.storage.log_event("mac_change", f"{adapter.name} · {change.ip}: {change.old_mac} → {change.new_mac}" + (f" (was {change.label})" if change.label else ""))
                vendor = self.oui.lookup(device.mac)
                rows.append({**device.to_dict(), "label": self.storage.get_label(device.mac), "vendor": vendor,
                             "guess": guess_device(vendor, device.hostname), "_key": f"{device.ip}|{device.mac}", "_alert": alert_key in self.alerts})
            self.net_table.render(rows)
            self.net_count.set(str(len(rows)))
            self.net_status.set(f"Last scan {time.strftime('%I:%M:%S %p').lstrip('0')}  ·  {len(rows)} observed  ·  {elapsed:.1f} sec  ·  {adapter.scan_cidr}")
            self.status.set("Network scan complete." if rows else "No neighbors observed. Check the selected adapter; sleeping or isolated devices may not appear.")
            self.update_alert_count()
            self.refresh_events()
        self.schedule()

    def start_bluetooth(self):
        if self.bt_busy or self.closing:
            return
        available, message = bluetooth_scan.is_available()
        if not available:
            self.status.set(message)
            return
        if self.bt_service is None:
            self.bt_service = bluetooth_scan.BluetoothService()
        self.bt_busy = True
        self.bt_stop.clear()
        self.bt_button.configure(state="disabled")
        self.bt_cancel.configure(state="normal")
        self.bt_progress.start(12)
        self.bt_status.set("Listening for Bluetooth LE advertisements…")
        def worker():
            try:
                self.queue.put(("bt", self.bt_service.scan(6, self.bt_stop), None))
            except Exception as exc:
                logging.exception("Bluetooth scan failed")
                self.queue.put(("bt", [], str(exc)))
        threading.Thread(target=worker, daemon=True, name="netmon-ble-results").start()

    def cancel_bluetooth(self):
        self.bt_stop.set()
        self.bt_cancel.configure(state="disabled")
        self.bt_status.set("Stopping Bluetooth scan…")

    def finish_bluetooth(self, devices, error):
        self.bt_busy = False
        self.bt_progress.stop()
        self.bt_button.configure(state="normal")
        self.bt_cancel.configure(state="disabled")
        if self.bt_stop.is_set():
            self.bt_status.set("Scan stopped. Previous results kept.")
        elif error:
            self.bt_status.set("Bluetooth unavailable. Switch on the radio and check Windows Bluetooth settings.")
            self.status.set(error)
        else:
            rows = []
            for device in devices:
                vendor = self.oui.lookup(device.address) if device.address_kind == "mac" else "macOS private identifier"
                rows.append({**device.to_dict(), "label": self.storage.get_label(device.address), "vendor": vendor,
                             "guess": guess_device(vendor, advertised_name=device.name), "_key": device.address})
            self.bt_table.render(rows)
            self.bt_count.set(str(len(rows)))
            self.bt_status.set(f"Last scan {time.strftime('%I:%M:%S %p').lstrip('0')}  ·  {len(rows)} Bluetooth LE devices")
            self.status.set("Bluetooth scan complete." if rows else "No BLE advertisements heard. Some paired devices do not advertise while connected.")

    def drain(self):
        if self.closing:
            return
        try:
            while True:
                item = self.queue.get_nowait()
                if item[0] == "net":
                    self.finish_network(*item[1:])
                elif item[0] == "bt":
                    self.finish_bluetooth(*item[1:])
                elif item[0] == "oui":
                    self.oui_busy = False
                    ok, message, database = item[1:]
                    if ok:
                        self.oui = database
                        self.refresh_vendor_rows()
                    self.status.set(message)
        except queue.Empty:
            pass
        finally:
            if not self.closing:
                self.after(80, self.drain)

    def edit_label(self, kind):
        table = self.net_table if kind == "net" else self.bt_table
        row = table.selected()
        if not row:
            self.status.set("Select a device first, or double-click its row to edit the label.")
            return
        address = row["mac" if kind == "net" else "address"]
        label = simpledialog.askstring("Label device", f"Your label for {address}\nLeave blank to remove the label.", initialvalue=self.storage.get_label(address), parent=self)
        if label is None:
            return
        self.storage.set_label(address, label.strip(), kind)
        for current, key in ((self.net_table, "mac"), (self.bt_table, "address")):
            for record in current.records:
                if record.get(key) == address:
                    record["label"] = label.strip()
            current.render()
        self.status.set("Device label saved.")

    def context_menu(self, event, kind):
        table = self.net_table if kind == "net" else self.bt_table
        item = table.tree.identify_row(event.y)
        if not item:
            return
        table.tree.selection_set(item)
        row = table.selected()
        menu = tk.Menu(self, tearoff=False)
        menu.add_command(label="Edit label…", command=lambda: self.edit_label(kind))
        def copy_address():
            self.clipboard_clear()
            self.clipboard_append(row["ip" if kind == "net" else "address"])
        menu.add_command(label="Copy address", command=copy_address)
        if kind == "net" and row.get("_alert"):
            menu.add_command(label="Acknowledge address change", command=lambda: self.ack(row["ip"]))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def ack(self, ip):
        self.alerts.pop((self.current_scope, ip), None)
        for row in self.net_table.records:
            if row["ip"] == ip:
                row["_alert"] = False
        self.net_table.render()
        self.update_alert_count()

    def ack_all(self):
        for scope, ip in list(self.alerts):
            if scope == self.current_scope:
                self.alerts.pop((scope, ip))
        for row in self.net_table.records:
            row["_alert"] = False
        self.net_table.render()
        self.update_alert_count()
        self.status.set("Current address changes acknowledged. History retained in Activity.")

    def update_alert_count(self):
        self.alert_count.set(str(sum(scope == self.current_scope for scope, _ in self.alerts)))

    def refresh_events(self):
        self.events.delete(*self.events.get_children())
        for row in self.storage.recent_events():
            self.events.insert("", "end", values=(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["ts"])), row["message"]))

    def export_table(self, table, name):
        if not table.visible:
            self.status.set("There are no visible devices to export.")
            return
        path = filedialog.asksaveasfilename(parent=self, title="Export visible devices", initialfile=f"netmon-{name}-{time.strftime('%Y%m%d-%H%M%S')}.csv", defaultextension=".csv", filetypes=[("CSV file", "*.csv")])
        if path:
            try:
                write_csv(path, [title for _, title, _ in table.columns], [[row.get(key, "") for key, _, _ in table.columns] for row in table.visible])
                self.status.set(f"Exported {len(table.visible)} devices to {Path(path).name}.")
            except OSError as exc:
                messagebox.showerror("Export failed", str(exc), parent=self)

    def export_current(self):
        selected = self.nb.index("current")
        if selected == 2:
            self.status.set("Choose Local network or Bluetooth LE to export a device list.")
        else:
            self.export_table(self.bt_table if selected == 1 else self.net_table, "bluetooth" if selected == 1 else "network")

    def update_oui(self):
        if self.oui_busy:
            return
        self.oui_busy = True
        self.status.set("Updating vendor database…")
        def worker():
            try:
                database = OuiDatabase(str(self.data_dir / "manuf.txt"))
                ok, message = database.update_from_internet()
                self.queue.put(("oui", ok, message, database))
            except Exception as exc:
                self.queue.put(("oui", False, f"Vendor update failed: {exc}", None))
        threading.Thread(target=worker, daemon=True, name="netmon-vendors").start()

    def refresh_vendor_rows(self):
        for table, key in ((self.net_table, "mac"), (self.bt_table, "address")):
            for row in table.records:
                row["vendor"] = self.oui.lookup(row[key]) if row.get("address_kind") != "uuid" else "macOS private identifier"
                row["guess"] = guess_device(row["vendor"], row.get("hostname", ""), row.get("name", ""))
            table.render()

    def open_data(self):
        try:
            if sys.platform == "win32":
                os.startfile(self.data_dir)
            else:
                subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", str(self.data_dir)])
        except OSError as exc:
            messagebox.showinfo("NetMon data", f"{self.data_dir}\n\n{exc}", parent=self)

    def about(self):
        messagebox.showinfo("About NetMon", f"NetMon {VERSION}\nLocal network & Bluetooth LE monitor\n\nLabels and scan history stay on this computer.\nVendor and device names are best-effort hints.\n\nVendor data: Wireshark manuf database.\nData folder: {self.data_dir}\n\nSource and notices: github.com/TE99SJM/netmon", parent=self)

    def report_callback_exception(self, exc, value, tb):
        logging.error("UI callback failed", exc_info=(exc, value, tb))
        messagebox.showerror("NetMon", f"This action could not finish.\n{value}\n\nDetails are saved in the NetMon data folder.", parent=self)

    def close(self):
        if self.closing:
            return
        self.closing = True
        self.net_stop.set()
        self.bt_stop.set()
        if self.auto_id:
            self.after_cancel(self.auto_id)
        if self.bt_service:
            self.bt_service.close()
        self.storage.close()
        self.destroy()


def main():
    parser = argparse.ArgumentParser(description="NetMon desktop network and Bluetooth monitor")
    parser.add_argument("--smoke-test", type=Path, help="Run offline packaged-app checks and write a JSON report")
    args = parser.parse_args()
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
    if args.smoke_test:
        from smoke_test import run
        return run(args.smoke_test)
    folder = data_directory()
    logging.basicConfig(level=logging.INFO, handlers=[RotatingFileHandler(folder / "netmon.log", maxBytes=1_000_000, backupCount=2, encoding="utf-8")], format="%(asctime)s %(levelname)s %(message)s")
    try:
        App(folder).mainloop()
        return 0
    except Exception:
        logging.exception("Startup failed")
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("NetMon could not start", f"See {folder / 'netmon.log'} for details.", parent=root)
        root.destroy()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
