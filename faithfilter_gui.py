#!/usr/bin/env python3
"""
FaithFilter Control Panel
-------------------------

A native desktop GUI for configuring and running the FaithFilter DNS
service, so no command line or "DOS window" is needed.  It edits every
option in ``config.yaml`` through tabbed forms, edits the blocklist,
whitelist and keyword files, and starts/stops the DNS service as a hidden
background process (no console window ever appears).

On Windows this is built into ``faithfilter-gui.exe`` (a windowed program)
and shipped alongside ``faithfilter.exe`` (the service).  Double-click the
GUI, adjust settings, click *Start service*.

The module is import-safe without Tk installed (the GUI simply refuses to
launch), so the pure helper functions below can be unit-tested headless.
"""

import os
import queue
import subprocess
import sys
import threading
import urllib.request

import yaml

import faithfilter
from faithfilter import DEFAULT_CONFIG, __version__, deep_merge

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    TK_AVAILABLE = True
except Exception:  # pragma: no cover - headless/CI without Tk
    TK_AVAILABLE = False


# ---------------------------------------------------------------------------
# Pure helpers (no Tk required — unit tested headless)
# ---------------------------------------------------------------------------

def gui_dir() -> str:
    """Folder containing this program (next to the .exe when frozen)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def get_by_path(cfg: dict, path: str, default=None):
    """Read a nested value: get_by_path(cfg, 'dns.listen_port')."""
    node = cfg
    for key in path.split("."):
        if not isinstance(node, dict) or key not in node:
            return default
        node = node[key]
    return node


def set_by_path(cfg: dict, path: str, value) -> None:
    """Write a nested value, creating intermediate dicts as needed."""
    keys = path.split(".")
    node = cfg
    for key in keys[:-1]:
        nxt = node.get(key)
        if not isinstance(nxt, dict):
            nxt = {}
            node[key] = nxt
        node = nxt
    node[keys[-1]] = value


def parse_list(text: str) -> list:
    """Multiline / comma text -> list of trimmed non-empty strings."""
    items: list = []
    for chunk in text.replace(",", "\n").splitlines():
        chunk = chunk.strip()
        if chunk:
            items.append(chunk)
    return items


def format_list(value) -> str:
    if isinstance(value, (list, tuple)):
        return "\n".join(str(v) for v in value)
    return "" if value is None else str(value)


def parse_curfews(text: str) -> list:
    """Parse curfew lines into policy dicts.

    Each non-empty line is ``[days] HH:MM-HH:MM`` where days is an optional
    comma list (mon..sun); omitting days means every day.  Example::

        fri,sat 22:00-07:00
        21:30-06:30
    """
    windows: list = []
    for line in text.splitlines():
        line = line.strip().lower()
        if not line:
            continue
        parts = line.split()
        if len(parts) == 1:
            days_part, span = "", parts[0]
        else:
            days_part, span = parts[0], parts[1]
        if "-" not in span:
            continue
        start, end = span.split("-", 1)
        window = {"from": start.strip(), "to": end.strip()}
        days = [d.strip()[:3] for d in days_part.split(",") if d.strip()]
        if days:
            window["days"] = days
        windows.append(window)
    return windows


def format_curfews(windows) -> str:
    lines = []
    for window in windows or []:
        days = ",".join(window.get("days", [])) if window.get("days") else ""
        span = f"{window.get('from', '')}-{window.get('to', '')}"
        lines.append(f"{days} {span}".strip())
    return "\n".join(lines)


def load_config(path: str) -> dict:
    """Return DEFAULT_CONFIG deep-merged with the file (if any)."""
    user: dict = {}
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            user = yaml.safe_load(f) or {}
    return deep_merge(DEFAULT_CONFIG, user)


def save_config(path: str, cfg: dict) -> None:
    """Write the full effective config as YAML (runtime-only keys removed)."""
    clean = {k: v for k, v in cfg.items() if not k.startswith("_")}
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("# FaithFilter settings - written by the Control Panel.\n")
        yaml.safe_dump(clean, f, default_flow_style=False, sort_keys=False,
                       allow_unicode=True)
    os.replace(tmp, path)


def find_service_command(base_dir: str, config_path: str):
    """Argv to launch the DNS service, or None if it can't be located."""
    if getattr(sys, "frozen", False):
        exe = os.path.join(base_dir,
                           "faithfilter.exe" if os.name == "nt" else "faithfilter")
        if os.path.exists(exe):
            return [exe, "--config", config_path]
        return None
    script = os.path.join(base_dir, "faithfilter.py")
    if os.path.exists(script):
        return [sys.executable, script, "--config", config_path]
    return None


def read_text_file(path: str) -> str:
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    return ""


def write_text_file(path: str, text: str) -> None:
    if not path:
        return
    if os.path.dirname(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text if text.endswith("\n") or not text else text + "\n")


# ---------------------------------------------------------------------------
# Background service process (hidden — no console window)
# ---------------------------------------------------------------------------

class ServiceProcess:
    """Runs faithfilter as a hidden child process and streams its log."""

    def __init__(self, base_dir: str, config_path: str):
        self.base_dir = base_dir
        self.config_path = config_path
        self.proc = None
        self.log_queue: "queue.Queue[str]" = queue.Queue()

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def start(self) -> str:
        if self.is_running():
            return "already running"
        cmd = find_service_command(self.base_dir, self.config_path)
        if not cmd:
            raise FileNotFoundError(
                "Could not find the faithfilter service executable next to "
                "this program.")
        creationflags = 0
        if os.name == "nt":
            # CREATE_NO_WINDOW keeps the service from opening a console.
            creationflags = 0x08000000
        self.proc = subprocess.Popen(
            cmd, cwd=self.base_dir, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1,
            creationflags=creationflags)
        threading.Thread(target=self._reader, daemon=True).start()
        return "started"

    def _reader(self) -> None:
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            self.log_queue.put(line.rstrip())
        self.log_queue.put("[service stopped]")

    def stop(self) -> None:
        if not self.is_running():
            return
        try:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        except Exception:
            pass


def relaunch_as_admin() -> bool:
    """Restart this GUI elevated on Windows.  Returns True if launched."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Declarative form schema (drives the tabbed config editor)
# ---------------------------------------------------------------------------
# Each field: (label, config-path, kind, options)
#   kind: "str" | "int" | "bool" | "choice" | "list" | "password"

FORM_TABS = [
    ("Network", [
        ("Listen IP (0.0.0.0 = all interfaces)", "dns.listen_ip", "str", None),
        ("Listen port (53 needs Administrator)", "dns.listen_port", "int", None),
        ("Answer DNS over TCP", "dns.listen_tcp", "bool", None),
        ("Upstream DNS servers (one per line)", "dns.upstream_dns", "list", None),
        ("Upstream timeout (seconds)", "dns.forward_timeout", "int", None),
        ("Block response", "dns.block_response", "choice", ["nxdomain", "zero_ip"]),
        ("Block CNAME-cloaked trackers", "dns.block_cname_cloaking", "bool", None),
        ("Enable DNS cache", "dns.cache.enabled", "bool", None),
        ("Cache size (entries)", "dns.cache.max_entries", "int", None),
        ("Serve stale cache on outage", "dns.cache.serve_stale", "bool", None),
    ]),
    ("Blocking", [
        ("Block DoH/Firefox canary domains", "blocking.block_doh_canary", "bool", None),
        ("Refresh online lists every (hours)", "blocking.refresh_hours", "int", None),
    ]),
    ("Monitoring", [
        ("Scan for built-in adult keywords", "monitoring.adult_keywords_enabled", "bool", None),
        ("Extra keywords to watch (one per line)", "monitoring.extra_keywords", "list", None),
        ("Keyword false-positive exceptions", "monitoring.keyword_exceptions", "list", None),
        ("Block keyword matches (not just report)", "monitoring.block_keyword_matches", "bool", None),
        ("Delete alerts older than (days)", "monitoring.alert_retention_days", "int", None),
    ]),
    ("Safe Search", [
        ("Enforce Google SafeSearch", "safe_search.google", "bool", None),
        ("Enforce Bing strict", "safe_search.bing", "bool", None),
        ("Enforce DuckDuckGo safe", "safe_search.duckduckgo", "bool", None),
        ("YouTube restricted mode", "safe_search.youtube", "choice",
         ["off", "moderate", "strict"]),
    ]),
    ("Email report", [
        ("Enable weekly e-mail report", "email.enabled", "bool", None),
        ("SMTP server", "email.smtp_host", "str", None),
        ("SMTP port", "email.smtp_port", "int", None),
        ("Use STARTTLS", "email.use_tls", "bool", None),
        ("Use SSL", "email.use_ssl", "bool", None),
        ("Username", "email.username", "str", None),
        ("Password (or set the env var below)", "email.password", "password", None),
        ("Password environment variable", "email.password_env", "str", None),
        ("From", "email.from", "str", None),
        ("Send to (one per line)", "email.to", "list", None),
        ("Report day", "email.report_day", "choice",
         ["monday", "tuesday", "wednesday", "thursday", "friday",
          "saturday", "sunday"]),
        ("Report hour (0-23)", "email.report_hour", "int", None),
        ("Report time zone", "email.report_timezone", "choice", ["local", "utc"]),
        ("Send even with no alerts", "email.send_if_empty", "bool", None),
    ]),
    ("Alerts & Block Page", [
        ("Instant e-mail on adult/bypass attempts", "notifications.instant_alerts", "bool", None),
        ("Min minutes between instant alerts", "notifications.instant_min_minutes", "int", None),
        ("E-mail when the service starts", "notifications.notify_on_start", "bool", None),
        ("Warn after N failed list refreshes", "notifications.refresh_failure_threshold", "int", None),
        ("Show a block page for blocked sites", "block_page.enabled", "bool", None),
        ("Block page port", "block_page.port", "int", None),
        ("Block page IP (blank = auto)", "block_page.ip", "str", None),
    ]),
    ("Advanced", [
        ("Enable dashboard / API", "http_api.enable", "bool", None),
        ("Dashboard host (0.0.0.0 = LAN)", "http_api.host", "str", None),
        ("Dashboard port", "http_api.port", "int", None),
        ("Dashboard password (blank = auto)", "http_api.password", "password", None),
        ("API key (for scripts & this panel)", "http_api.api_key", "str", None),
        ("Serve DNS-over-HTTPS at /dns-query", "http_api.doh", "bool", None),
        ("TLS certificate file (HTTPS/DoT)", "http_api.cert_file", "str", None),
        ("TLS key file", "http_api.key_file", "str", None),
        ("Enable DNS-over-TLS listener", "dot.enabled", "bool", None),
        ("DoT port", "dot.port", "int", None),
        ("Keep long-term statistics", "stats.enabled", "bool", None),
        ("Statistics retention (days)", "stats.retention_days", "int", None),
        ("Check for updates", "updates.check", "bool", None),
        ("Follower sync: enable", "sync.enabled", "bool", None),
        ("Follower sync: primary URL", "sync.primary_url", "str", None),
        ("Follower sync: API key", "sync.api_key", "str", None),
        ("Follower sync: interval (minutes)", "sync.interval_minutes", "int", None),
        ("Log level", "logs.log_level", "choice",
         ["DEBUG", "INFO", "WARNING", "ERROR"]),
        ("Rotate logs beyond (MB)", "logs.max_log_mb", "int", None),
        ("Delete rotated query logs after (days)", "logs.retention_days", "int", None),
    ]),
]


# ---------------------------------------------------------------------------
# The GUI (requires Tk)
# ---------------------------------------------------------------------------

if TK_AVAILABLE:

    class ControlPanel(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title(f"FaithFilter Control Panel  v{__version__}")
            self.geometry("860x680")
            self.minsize(760, 560)

            self.base_dir = gui_dir()
            self.config_path = os.path.join(self.base_dir, "config.yaml")
            self.cfg = load_config(self.config_path)
            self.vars: dict = {}
            self.service = ServiceProcess(self.base_dir, self.config_path)

            self._build_toolbar()
            self.notebook = ttk.Notebook(self)
            self.notebook.pack(fill="both", expand=True, padx=8, pady=(0, 8))
            self._build_form_tabs()
            self._build_lists_tab()
            self._build_devices_tab()
            self._build_status_tab()
            self._load_into_widgets()

            self.after(300, self._drain_log)
            self.after(1500, self._poll_status)
            self.protocol("WM_DELETE_WINDOW", self._on_close)

        # -- top toolbar ---------------------------------------------------
        def _build_toolbar(self):
            bar = ttk.Frame(self)
            bar.pack(fill="x", padx=8, pady=8)
            self.status_var = tk.StringVar(value="Service: stopped")
            ttk.Label(bar, textvariable=self.status_var,
                      font=("Segoe UI", 10, "bold")).pack(side="left")
            for text, cmd in [
                ("Start service", self.start_service),
                ("Stop", self.stop_service),
                ("Restart", self.restart_service),
                ("Save settings", self.save_settings),
                ("Open dashboard", self.open_dashboard),
            ]:
                ttk.Button(bar, text=text, command=cmd).pack(side="right", padx=3)

        # -- scalar form tabs ---------------------------------------------
        def _build_form_tabs(self):
            for title, fields in FORM_TABS:
                frame = ttk.Frame(self.notebook)
                self.notebook.add(frame, text=title)
                canvas = tk.Canvas(frame, highlightthickness=0)
                scroll = ttk.Scrollbar(frame, orient="vertical",
                                       command=canvas.yview)
                inner = ttk.Frame(canvas)
                inner.bind("<Configure>", lambda e: canvas.configure(
                    scrollregion=canvas.bbox("all")))
                canvas.create_window((0, 0), window=inner, anchor="nw")
                canvas.configure(yscrollcommand=scroll.set)
                canvas.pack(side="left", fill="both", expand=True)
                scroll.pack(side="right", fill="y")
                for row, (label, path, kind, opts) in enumerate(fields):
                    ttk.Label(inner, text=label, wraplength=360).grid(
                        row=row, column=0, sticky="w", padx=8, pady=4)
                    self._make_widget(inner, row, path, kind, opts)

        def _make_widget(self, parent, row, path, kind, opts):
            if kind == "bool":
                var = tk.BooleanVar()
                ttk.Checkbutton(parent, variable=var).grid(
                    row=row, column=1, sticky="w", padx=8)
            elif kind == "choice":
                var = tk.StringVar()
                ttk.Combobox(parent, textvariable=var, values=opts,
                             state="readonly", width=22).grid(
                    row=row, column=1, sticky="w", padx=8)
            elif kind == "list":
                var = tk.Text(parent, height=4, width=44, wrap="none")
                var.grid(row=row, column=1, sticky="w", padx=8, pady=2)
            elif kind == "password":
                var = tk.StringVar()
                ttk.Entry(parent, textvariable=var, width=44, show="*").grid(
                    row=row, column=1, sticky="w", padx=8)
            else:
                var = tk.StringVar()
                ttk.Entry(parent, textvariable=var, width=44).grid(
                    row=row, column=1, sticky="w", padx=8)
            self.vars[path] = (kind, var)

        # -- blocklist / whitelist / keyword file editors -----------------
        def _build_lists_tab(self):
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text="Lists")
            self.list_editors = {}
            specs = [
                ("My blocked sites (domain, *wildcard* or /regex/)",
                 "blocking.my_blocklist"),
                ("Always-allowed (whitelist)", "blocking.whitelist"),
                ("Monitored keywords", "monitoring.keywords_file"),
            ]
            for col, (label, path) in enumerate(specs):
                sub = ttk.LabelFrame(frame, text=label)
                sub.grid(row=0, column=col, sticky="nsew", padx=5, pady=5)
                frame.columnconfigure(col, weight=1)
                text = tk.Text(sub, width=30, height=26, wrap="none")
                text.pack(fill="both", expand=True)
                self.list_editors[path] = text
            frame.rowconfigure(0, weight=1)

        # -- device names & groups ----------------------------------------
        def _build_devices_tab(self):
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text="Devices")

            names_box = ttk.LabelFrame(
                frame, text="Device names  (one per line:  IP = Name)")
            names_box.pack(fill="both", expand=True, padx=6, pady=6)
            self.names_text = tk.Text(names_box, height=8, wrap="none")
            self.names_text.pack(fill="both", expand=True)

            groups_box = ttk.LabelFrame(
                frame, text="Groups  (advanced — YAML list; see README)")
            groups_box.pack(fill="both", expand=True, padx=6, pady=6)
            self.groups_text = tk.Text(groups_box, height=12, wrap="none")
            self.groups_text.pack(fill="both", expand=True)
            ttk.Label(groups_box, text=(
                "Example:\n- name: kids\n  members: [192.168.1.20]\n"
                "  filtering: full\n  safe_search: true\n"
                "  curfew:\n    - {days: [sun, mon], from: '21:30', to: '06:30'}"
            ), font=("Consolas", 8), foreground="#555").pack(anchor="w")

        # -- status & log --------------------------------------------------
        def _build_status_tab(self):
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text="Status & Log")
            self.stats_var = tk.StringVar(value="Start the service to see stats.")
            ttk.Label(frame, textvariable=self.stats_var, justify="left",
                      font=("Consolas", 9)).pack(anchor="w", padx=8, pady=6)
            self.log_text = tk.Text(frame, height=22, wrap="none",
                                    background="#111", foreground="#0f0",
                                    font=("Consolas", 9))
            self.log_text.pack(fill="both", expand=True, padx=8, pady=6)

        # -- load config -> widgets ---------------------------------------
        def _load_into_widgets(self):
            for path, (kind, var) in self.vars.items():
                value = get_by_path(self.cfg, path)
                if kind == "bool":
                    var.set(bool(value))
                elif kind == "list":
                    var.delete("1.0", "end")
                    var.insert("1.0", format_list(value))
                else:
                    var.set("" if value is None else str(value))
            for path, text in self.list_editors.items():
                filepath = self._resolve(get_by_path(self.cfg, path))
                text.delete("1.0", "end")
                text.insert("1.0", read_text_file(filepath))
            names = get_by_path(self.cfg, "clients.names") or {}
            self.names_text.delete("1.0", "end")
            self.names_text.insert("1.0", "\n".join(
                f"{ip} = {name}" for ip, name in names.items()))
            groups = get_by_path(self.cfg, "clients.groups") or []
            self.groups_text.delete("1.0", "end")
            if groups:
                self.groups_text.insert("1.0", yaml.safe_dump(
                    groups, default_flow_style=False, sort_keys=False))

        def _resolve(self, relpath):
            if not relpath:
                return None
            if os.path.isabs(relpath):
                return relpath
            return os.path.join(self.base_dir, relpath)

        # -- widgets -> config + files ------------------------------------
        def _collect(self) -> bool:
            for path, (kind, var) in self.vars.items():
                if kind == "bool":
                    set_by_path(self.cfg, path, bool(var.get()))
                elif kind == "int":
                    raw = var.get().strip()
                    try:
                        set_by_path(self.cfg, path, int(raw))
                    except ValueError:
                        messagebox.showerror(
                            "Invalid number", f"'{path}' must be a whole "
                            f"number (got '{raw}').")
                        return False
                elif kind == "list":
                    set_by_path(self.cfg, path,
                                parse_list(var.get("1.0", "end")))
                else:
                    set_by_path(self.cfg, path, var.get().strip())
            # Device names
            names = {}
            for line in self.names_text.get("1.0", "end").splitlines():
                if "=" in line:
                    ip, name = line.split("=", 1)
                    if ip.strip():
                        names[ip.strip()] = name.strip()
            set_by_path(self.cfg, "clients.names", names)
            # Groups (YAML)
            groups_raw = self.groups_text.get("1.0", "end").strip()
            if groups_raw:
                try:
                    parsed = yaml.safe_load(groups_raw)
                    if not isinstance(parsed, list):
                        raise ValueError("must be a YAML list")
                    set_by_path(self.cfg, "clients.groups", parsed)
                except Exception as exc:
                    messagebox.showerror("Groups error",
                                         f"Could not parse Groups: {exc}")
                    return False
            else:
                set_by_path(self.cfg, "clients.groups", [])
            return True

        def save_settings(self) -> bool:
            if not self._collect():
                return False
            try:
                save_config(self.config_path, self.cfg)
                for path, text in self.list_editors.items():
                    filepath = self._resolve(get_by_path(self.cfg, path))
                    write_text_file(filepath, text.get("1.0", "end").strip())
            except OSError as exc:
                messagebox.showerror("Save failed", str(exc))
                return False
            self._append_log(f"Saved settings to {self.config_path}")
            return True

        # -- service control ----------------------------------------------
        def start_service(self):
            if not self.save_settings():
                return
            try:
                self.service.start()
            except FileNotFoundError as exc:
                messagebox.showerror("Service not found", str(exc))
                return
            self.after(1800, self._check_started)

        def _check_started(self):
            if self.service.is_running():
                self._append_log("Service is running.")
                return
            port = get_by_path(self.cfg, "dns.listen_port", 53)
            if os.name == "nt" and int(port) < 1024:
                if messagebox.askyesno(
                        "Administrator needed",
                        f"The service could not bind port {port}.\n\nPort "
                        "53 requires Administrator rights. Restart the "
                        "Control Panel as Administrator now?"):
                    if relaunch_as_admin():
                        self.destroy()
            else:
                messagebox.showwarning(
                    "Service stopped",
                    "The service exited right after starting. Check the "
                    "Status & Log tab for the reason (often the port is "
                    "already in use).")

        def stop_service(self):
            self.service.stop()
            self.status_var.set("Service: stopped")

        def restart_service(self):
            self.service.stop()
            self.after(600, self.start_service)

        def open_dashboard(self):
            import webbrowser
            host = get_by_path(self.cfg, "http_api.host", "127.0.0.1")
            if host == "0.0.0.0":
                host = "127.0.0.1"
            port = get_by_path(self.cfg, "http_api.port", 5000)
            webbrowser.open(f"http://{host}:{port}/")

        # -- periodic updates ---------------------------------------------
        def _append_log(self, line: str):
            self.log_text.insert("end", line + "\n")
            self.log_text.see("end")
            # Cap the log widget so it can't grow without bound.
            if int(self.log_text.index("end-1c").split(".")[0]) > 2000:
                self.log_text.delete("1.0", "500.0")

        def _drain_log(self):
            try:
                while True:
                    self._append_log(self.service.log_queue.get_nowait())
            except queue.Empty:
                pass
            self.after(300, self._drain_log)

        def _poll_status(self):
            running = self.service.is_running()
            self.status_var.set(
                "Service: RUNNING" if running else "Service: stopped")
            if running:
                self._refresh_stats()
            self.after(4000, self._poll_status)

        def _refresh_stats(self):
            api_key = get_by_path(self.cfg, "http_api.api_key")
            if not api_key or not get_by_path(self.cfg, "http_api.enable", True):
                self.stats_var.set(
                    "Set an API key (Advanced tab) and save to show live "
                    "stats here.")
                return
            port = get_by_path(self.cfg, "http_api.port", 5000)
            threading.Thread(target=self._fetch_stats, args=(port, api_key),
                             daemon=True).start()

        def _fetch_stats(self, port, api_key):
            try:
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/status",
                    headers={"X-API-Key": api_key})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    import json
                    data = json.load(resp)
                st = data.get("stats", {})
                lists = data.get("lists", {})
                text = (f"Version {data.get('version')}   "
                        f"uptime {data.get('uptime_seconds', 0) // 3600}h\n"
                        f"Queries: {st.get('total_queries', 0)}   "
                        f"Blocked: {st.get('blocked', 0)}   "
                        f"Adult: {st.get('blocked_adult', 0)}   "
                        f"Ads: {st.get('blocked_ads', 0)}   "
                        f"Bypass: {st.get('blocked_bypass', 0)}\n"
                        f"Domains loaded: {lists.get('total_blocked_domains', 0)}"
                        + ("   UPDATE AVAILABLE"
                           if data.get("update_available") else ""))
                self.stats_var.set(text)
            except Exception:
                self.stats_var.set("Service running (stats unavailable yet).")

        def _on_close(self):
            if self.service.is_running():
                if not messagebox.askyesno(
                        "Quit", "The DNS service is running. Stop it and "
                        "quit?\n\n(Choose No to leave it running in the "
                        "background.)"):
                    self.destroy()
                    return
                self.service.stop()
            self.destroy()


def main() -> None:
    if not TK_AVAILABLE:
        sys.stderr.write(
            "The graphical Control Panel needs Tk, which is not available in "
            "this Python.\nOn Linux install it with:  sudo apt install "
            "python3-tk\nThe service itself runs fine without it: "
            "python3 faithfilter.py --config config.yaml\n")
        sys.exit(1)
    ControlPanel().mainloop()


if __name__ == "__main__":
    main()
