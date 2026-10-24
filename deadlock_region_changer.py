"""Deadlock Region Changer.

Matchmaking in Deadlock picks the region by your ping to Valve's relay servers
(Steam Datagram Relay). The program blocks the relays of unwanted regions in
the Windows Firewall, so the game sees only the ones you selected.
"""

import ctypes
import json
import os
import re
import socket
import subprocess
import sys
import threading
import tkinter as tk
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tkinter import messagebox, ttk

__version__ = "1.1.0"

APP_ID = 1422450  # Deadlock
SDR_URL = f"https://api.steampowered.com/ISteamApps/GetSDRConfig/v1/?appid={APP_ID}"
RULE_NAME = "DeadlockRegionChanger"
FROZEN = getattr(sys, "frozen", False)  # running as the PyInstaller exe

# A one-file exe unpacks itself into a temp folder, so data can't live next to the code.
DATA_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "DeadlockRegionChanger"
CACHE_FILE = DATA_DIR / "sdr_cache.json"
STATE_FILE = DATA_DIR / "blocked.json"

GAME_PROCESSES = ("deadlock.exe", "project8.exe")  # project8 is the old name

# Valve lists some cities several times (its own and partner data centers).
# They are merged so a city can't stay reachable through its twin.
CLUSTERS = {
    "fra": ("Frankfurt (Germany)", ["fra", "dfra"]),
    "sto": ("Stockholm (Sweden)", ["sto", "sto2", "dsto"]),
    "lhr": ("London (England)", ["lhr", "dlhr"]),
    "vie": ("Vienna (Austria)", ["vie", "dvie"]),
}
CLUSTER_OF = {m: code for code, (_, members) in CLUSTERS.items() for m in members}

# Groups by continent; unknown POPs fall into "Другое".
REGIONS = {
    "Европа": ["ams", "fra", "fsn", "hel", "lhr", "mad", "par", "sto", "vie", "waw"],
    "Северная Америка": ["atl", "dfw", "eat", "iad", "lax", "ord", "sea"],
    "Южная Америка": ["eze", "gru", "lim", "scl"],
    "Азия": ["hkg", "seo", "sgp", "tyo", "gum", "bom2", "maa2"],
    "Ближний Восток": ["dxb", "dfjr"],
    "Африка": ["jnb"],
    "Океания": ["syd"],
}

# name -> (allowed POPs or None for all, subtitle).
# There are no Russian servers: Valve routes players it geolocates to Russia
# to Frankfurt, Helsinki (no relays at the moment) or Stockholm.
RU_ROUTES = ["fra", "sto", "hel"]
PRESETS = {
    "Россия / СНГ": (RU_ROUTES, "Франкфурт, Стокгольм"),
    "Европа": (REGIONS["Европа"], "Все серверы Европы"),
    "Европа без РФ": ([c for c in REGIONS["Европа"] if c not in RU_ROUTES],
                      "Без Франкфурта и Стокгольма"),
    "Америка": (REGIONS["Северная Америка"], "Все серверы США"),
    "Все серверы": (None, "Без ограничений"),
}

# Palette
BG = "#0e1014"
SURFACE = "#161920"
SURFACE_HOVER = "#1d212a"
SURFACE_2 = "#232733"
BORDER = "#272c37"
TEXT = "#e8e6e3"
MUTED = "#8a909c"
DIM = "#4e5460"
ACCENT = "#d9a441"
ACCENT_HOVER = "#e9b85c"
ON_ACCENT = "#17130b"
GOOD = "#4cc38a"
WARN = "#e0a33a"
BAD = "#e5534b"

FONT = "Segoe UI"
FONT_BOLD = "Segoe UI Semibold"
FONT_MONO = "Consolas"

SCALE = 1.0  # set from the screen DPI once Tk exists


def px(n):
    return int(round(n * SCALE))


# ---------------------------------------------------------------- system --

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    # An elevated process starts in System32, so the script path must be absolute.
    # The exe asks for admin rights in its manifest and normally never gets here.
    script = Path(sys.executable if FROZEN else __file__).resolve()
    args = sys.argv[1:] if FROZEN else [str(script), *sys.argv[1:]]
    params = " ".join(f'"{a}"' for a in args)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params,
                                        str(script.parent), 1)


def powershell(command):
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    return result.returncode == 0, result.stdout.strip()


def firewall_off_profiles():
    """Firewall profiles that are disabled but used by an active network.

    Rules have no effect on a network whose profile is switched off."""
    ok, out = powershell(
        "[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
        "Get-NetConnectionProfile | ForEach-Object { "
        "($_.NetworkCategory -replace 'DomainAuthenticated', 'Domain').ToString() } | "
        "Sort-Object -Unique | ForEach-Object { "
        "if (-not (Get-NetFirewallProfile -Name $_).Enabled) { $_ } }")
    return out.split() if ok else []


def enable_firewall(profiles):
    ok, _ = powershell(f"Set-NetFirewallProfile -Profile {','.join(profiles)} -Enabled True")
    return ok


def netsh(*args):
    result = subprocess.run(
        ["netsh", "advfirewall", "firewall", *args],
        capture_output=True, text=True, encoding="cp866", errors="replace",
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    return result.returncode == 0, result.stdout.strip()


def remove_rules():
    # netsh deletes every rule with this name in one call.
    netsh("delete", "rule", f"name={RULE_NAME}")


def block_ips(ips):
    # Also removes rules of older versions (inbound, protocol any).
    remove_rules()
    # Small chunks keep the remoteip argument within netsh limits. Only outbound
    # TCP and UDP are blocked: ICMP stays open, so blocked servers still answer ping.
    for i in range(0, len(ips), 50):
        chunk = ",".join(ips[i:i + 50])
        for protocol in ("TCP", "UDP"):
            ok, out = netsh("add", "rule", f"name={RULE_NAME}", "dir=out",
                            "action=block", f"protocol={protocol}", "profile=any",
                            f"remoteip={chunk}")
            if not ok:
                raise RuntimeError(out or "netsh завершился с ошибкой")


def game_running():
    result = subprocess.run(
        ["tasklist", "/FO", "CSV", "/NH"],
        capture_output=True, text=True, encoding="cp866", errors="replace",
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    out = result.stdout.lower()
    return any(f'"{name}"' in out for name in GAME_PROCESSES)


def ping_ms(ip, timeout_ms=1000):
    """ICMP echo through iphlpapi: works without admin rights and parsing."""
    iphlpapi = ctypes.windll.iphlpapi
    iphlpapi.IcmpCreateFile.restype = ctypes.c_void_p
    handle = iphlpapi.IcmpCreateFile()
    if not handle:
        return None
    try:
        addr = int.from_bytes(socket.inet_aton(ip), "little")
        data = b"deadlock"
        reply = ctypes.create_string_buffer(64 + len(data))
        n = iphlpapi.IcmpSendEcho(ctypes.c_void_p(handle), ctypes.c_ulong(addr),
                                  data, len(data), None, reply, len(reply),
                                  timeout_ms)
        if n == 0:
            return None
        status = int.from_bytes(reply.raw[4:8], "little")
        rtt = int.from_bytes(reply.raw[8:12], "little")
        return rtt if status == 0 else None
    finally:
        iphlpapi.IcmpCloseHandle(ctypes.c_void_p(handle))


# ------------------------------------------------------------------ data --

def fetch_sdr_config(attempts=3):
    # Requests through a VPN sometimes stall; a retry usually goes through at once.
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(SDR_URL, timeout=10) as resp:
                return json.load(resp)
        except Exception:
            if attempt == attempts - 1:
                raise


def load_pops():
    """Returns ({code: {"desc", "ips", "members"}}, fresh) for POPs with relays.

    fresh is False when Steam was unreachable and the cached list was used."""
    fresh = True
    try:
        raw = fetch_sdr_config()
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(raw), encoding="utf-8")
    except Exception:
        if not CACHE_FILE.exists():
            raise
        raw = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        fresh = False

    pops = {}
    for code, pop in raw["pops"].items():
        ips = [r["ipv4"] for r in pop.get("relays", []) if r.get("ipv4")]
        if not ips:
            continue
        group = CLUSTER_OF.get(code, code)
        if group in pops:
            pops[group]["ips"] += ips
            pops[group]["members"].append(code)
        else:
            desc = CLUSTERS[group][0] if group in CLUSTERS else pop.get("desc", code)
            pops[group] = {"desc": desc, "ips": ips, "members": [code]}
    return pops, fresh


def load_state():
    """Returns (blocked codes, blocked IPs) saved by the last apply."""
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return set(), []
    if isinstance(data, list):  # older versions saved only the codes
        data = {"codes": data, "ips": []}
    codes = {CLUSTER_OF.get(c, c) for c in data.get("codes", [])}
    return codes, data.get("ips", [])


def save_state(codes, ips):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps({"codes": sorted(codes), "ips": sorted(ips)}),
                          encoding="utf-8")


def split_desc(desc):
    """'Amsterdam (Netherlands)' -> ('Amsterdam', 'Netherlands')."""
    m = re.match(r"^(.*?)\s*\((.*)\)$", desc)
    return (m.group(1), m.group(2)) if m else (desc, "")


def ping_color(ms):
    return GOOD if ms < 60 else WARN if ms < 120 else BAD


def ping_level(ms):
    if ms is None:
        return 0
    return 4 if ms < 50 else 3 if ms < 90 else 2 if ms < 150 else 1


# --------------------------------------------------------------- widgets --

def walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from walk(child)


def paint(widget, bg):
    """Recolors a widget tree; widgets marked keep_bg stay as they are."""
    for w in walk(widget):
        if not getattr(w, "keep_bg", False):
            try:
                w.configure(bg=bg)
            except tk.TclError:
                pass


def bind_hover(root, normal, hover):
    def enter(_):
        paint(root, hover)

    def leave(_):
        # Leave also fires when the pointer moves onto a child widget.
        try:
            under = root.winfo_containing(*root.winfo_pointerxy())
        except (KeyError, tk.TclError):
            under = None
        while under is not None:
            if under is root:
                return
            under = under.master
        paint(root, normal)

    for w in walk(root):
        w.bind("<Enter>", enter, add="+")
        w.bind("<Leave>", leave, add="+")


def bind_click(root, command, skip=()):
    for w in walk(root):
        if w not in skip:
            w.bind("<Button-1>", lambda e: command(), add="+")
            w.configure(cursor="hand2")


class FlatButton(tk.Label):
    def __init__(self, master, text, command, bg=SURFACE_2, fg=TEXT,
                 hover_bg=None, font=(FONT_BOLD, 10), padx=16, pady=8):
        super().__init__(master, text=text, bg=bg, fg=fg, font=font,
                         padx=px(padx), pady=px(pady), cursor="hand2")
        self.keep_bg = True
        self.bind("<Button-1>", lambda e: command())
        self.bind("<Enter>", lambda e: self.configure(bg=hover_bg or SURFACE_HOVER))
        self.bind("<Leave>", lambda e: self.configure(bg=bg))


class LinkLabel(tk.Label):
    def __init__(self, master, text, command, bg):
        super().__init__(master, text=text, bg=bg, fg=MUTED,
                         font=(FONT, 9), cursor="hand2")
        self.bind("<Button-1>", lambda e: command())
        self.bind("<Enter>", lambda e: self.configure(fg=ACCENT))
        self.bind("<Leave>", lambda e: self.configure(fg=MUTED))


class Toggle(tk.Canvas):
    def __init__(self, master, variable, bg):
        self.w, self.h = px(38), px(20)
        super().__init__(master, width=self.w, height=self.h, bg=bg,
                         highlightthickness=0, cursor="hand2")
        self.var = variable
        self.var.trace_add("write", lambda *_: self.draw())
        self.bind("<Button-1>", lambda e: self.var.set(not self.var.get()))
        self.draw()

    def draw(self):
        self.delete("all")
        on = self.var.get()
        w, h = self.w - 1, self.h - 1
        track = ACCENT if on else "#3a404c"
        self.create_oval(0, 0, h, h, fill=track, outline=track)
        self.create_oval(w - h, 0, w, h, fill=track, outline=track)
        self.create_rectangle(h / 2, 0, w - h / 2, h, fill=track, outline=track)
        pad = px(3)
        x = w - h + pad if on else pad
        self.create_oval(x, pad, x + h - 2 * pad, h - pad,
                         fill="#ffffff" if on else "#c9ccd2", outline="")


class Signal(tk.Canvas):
    """Four bars like a Wi-Fi indicator."""

    def __init__(self, master, bg):
        self.w, self.h = px(20), px(14)
        super().__init__(master, width=self.w, height=self.h, bg=bg, highlightthickness=0)
        self.set(0, DIM)

    def set(self, level, color):
        self.delete("all")
        bar, gap = px(3), px(2)
        for i in range(4):
            top = self.h - (i + 1) * self.h / 4
            x = i * (bar + gap)
            self.create_rectangle(x, top, x + bar, self.h,
                                  fill=color if i < level else "#2f3440", outline="")


class ScrollFrame(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG)
        self.canvas = tk.Canvas(self, bg=BG, highlightthickness=0, yscrollincrement=px(20))
        bar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview,
                            style="Dark.Vertical.TScrollbar")
        self.inner = tk.Frame(self.canvas, bg=BG)
        window = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>",
                        lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>",
                         lambda e: self.canvas.itemconfigure(window, width=e.width))
        self.canvas.configure(yscrollcommand=bar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        bar.pack(side="right", fill="y", padx=(px(8), 0))
        self.bind_all("<MouseWheel>",
                      lambda e: self.canvas.yview_scroll(int(-e.delta / 40), "units"))


class ServerRow(tk.Frame):
    def __init__(self, master, code, pop, var):
        super().__init__(master, bg=SURFACE, padx=px(14), pady=px(9))
        self.var = var
        city, country = split_desc(pop["desc"])
        if len(pop["members"]) > 1:
            country = f"{country} · {', '.join(pop['members'])}"

        self.badge = tk.Label(self, text=code.upper(), font=(FONT_MONO, 9, "bold"),
                              fg=MUTED, bg=SURFACE_2, width=5, pady=px(3))
        self.badge.keep_bg = True
        self.badge.grid(row=0, column=0, rowspan=2, padx=(0, px(12)))

        self.city = tk.Label(self, text=city, font=(FONT_BOLD, 10), fg=TEXT, bg=SURFACE, anchor="w")
        self.city.grid(row=0, column=1, sticky="w")
        self.country = tk.Label(self, text=country, font=(FONT, 9), fg=MUTED, bg=SURFACE, anchor="w")
        self.country.grid(row=1, column=1, sticky="w")

        self.signal = Signal(self, SURFACE)
        self.signal.grid(row=0, column=2, rowspan=2, padx=(px(8), px(6)))
        self.ping = tk.Label(self, text="…", font=(FONT, 9), fg=DIM, bg=SURFACE, width=7, anchor="e")
        self.ping.grid(row=0, column=3, rowspan=2, padx=(0, px(14)))
        self.toggle = Toggle(self, var, SURFACE)
        self.toggle.grid(row=0, column=4, rowspan=2)
        self.columnconfigure(1, weight=1)

        bind_hover(self, SURFACE, SURFACE_HOVER)
        bind_click(self, lambda: var.set(not var.get()), skip=(self.toggle,))
        self.toggle.configure(cursor="hand2")

    def update_state(self):
        on = self.var.get()
        self.city.configure(fg=TEXT if on else DIM)
        self.country.configure(fg=MUTED if on else DIM)
        self.badge.configure(fg=ACCENT if on else DIM)

    def set_ping(self, ms):
        if ms is None:
            self.ping.configure(text="нет ответа", fg=DIM)
            self.signal.set(0, DIM)
        else:
            self.ping.configure(text=f"{ms} мс", fg=ping_color(ms))
            self.signal.set(ping_level(ms), ping_color(ms))

    def set_unknown(self):
        self.ping.configure(text="?", fg=DIM)
        self.signal.set(0, DIM)


class PresetCard(tk.Frame):
    def __init__(self, master, title, subtitle, command):
        super().__init__(master, bg=SURFACE, padx=px(14), pady=px(8),
                         highlightthickness=1, highlightbackground=BORDER)
        self.title = tk.Label(self, text=title, font=(FONT_BOLD, 10), fg=TEXT, bg=SURFACE, anchor="w")
        self.title.pack(fill="x")
        tk.Label(self, text=subtitle, font=(FONT, 9), fg=MUTED, bg=SURFACE, anchor="w").pack(fill="x")
        bind_hover(self, SURFACE, SURFACE_HOVER)
        bind_click(self, command)

    def set_active(self, active):
        self.configure(highlightbackground=ACCENT if active else BORDER)
        self.title.configure(fg=ACCENT if active else TEXT)


def section_label(master, text):
    tk.Label(master, text=text, font=(FONT_BOLD, 8), fg=MUTED, bg=BG,
             anchor="w").pack(fill="x", pady=(0, px(8)))


# -------------------------------------------------------------------- UI --

class App(tk.Tk):
    def __init__(self, pops, fresh=True):
        super().__init__()
        global SCALE
        SCALE = self.winfo_fpixels("1i") / 96

        self.title(f"Deadlock Region Changer {__version__}")
        self.configure(bg=BG)
        icon = Path(getattr(sys, "_MEIPASS", Path(__file__).parent)) / "icon.ico"
        if icon.exists():
            self.iconbitmap(default=str(icon))
        self.geometry(f"{px(960)}x{px(720)}")
        self.minsize(px(780), px(520))

        self.pops = pops
        self.applied, self.applied_ips = load_state()
        self.applied &= set(pops)
        self.vars = {}
        self.rows = {}
        self.sections = []
        self.pings = {}
        self.batch = False
        self.message_text = "После применения перезапустите Deadlock, чтобы он заново замерил пинг"
        self.message_color = MUTED

        self.setup_style()
        self.build_header()
        self.build_footer()
        self.build_banner()
        self.build_body()

        for code, var in self.vars.items():
            var.trace_add("write", lambda *_: self.on_change())
        self.on_change()
        self.refresh_pings()
        threading.Thread(target=self.check_firewall, daemon=True).start()
        if fresh:
            threading.Thread(target=self.refresh_rules, daemon=True).start()
        self.watch_game()

    def blocked_ips(self, codes):
        return [ip for c in sorted(codes) for ip in self.pops[c]["ips"]]

    def check_firewall(self):
        off = firewall_off_profiles()
        if off:
            self.after(0, self.set_message,
                       f"Брандмауэр Windows выключен ({', '.join(off)}): "
                       "программа предложит включить его при применении", WARN)

    def refresh_rules(self):
        """Valve changes relay IPs from time to time; old rules would stop working."""
        codes = set(self.applied)
        if not codes:
            return
        ips = self.blocked_ips(codes)
        if sorted(ips) == sorted(self.applied_ips):
            return
        try:
            block_ips(ips)
        except RuntimeError:
            self.after(0, self.set_message,
                       "IP-адреса серверов изменились, но обновить правила не удалось", BAD)
            return
        save_state(codes, ips)
        self.applied_ips = ips
        self.after(0, self.set_message,
                   "IP-адреса серверов Valve изменились, правила обновлены", GOOD)

    def watch_game(self):
        def worker():
            running = game_running()
            self.after(0, self.show_game_banner, running)

        threading.Thread(target=worker, daemon=True).start()
        self.after(5000, self.watch_game)

    def show_game_banner(self, running):
        if running and not self.banner.winfo_ismapped():
            self.banner.pack(fill="x", padx=px(24), pady=(0, px(16)), before=self.body)
        elif not running and self.banner.winfo_ismapped():
            self.banner.pack_forget()

    def setup_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        # The "default" theme thumb has no grip lines, unlike clam's.
        style.element_create("Plain.thumb", "from", "default")
        style.layout("Dark.Vertical.TScrollbar", [
            ("Vertical.Scrollbar.trough", {"sticky": "ns", "children": [
                ("Plain.thumb", {"expand": "1", "sticky": "nswe"})]})])
        style.configure("Dark.Vertical.TScrollbar", troughcolor=BG, background=SURFACE_2,
                        bordercolor=BG, lightcolor=SURFACE_2, darkcolor=SURFACE_2,
                        width=px(8), relief="flat", borderwidth=0)
        style.map("Dark.Vertical.TScrollbar", background=[("active", "#353b48")])

    # --- layout

    def build_header(self):
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=px(24), pady=(px(20), px(16)))

        left = tk.Frame(header, bg=BG)
        left.pack(side="left")
        title = tk.Frame(left, bg=BG)
        title.pack(anchor="w")
        tk.Label(title, text="DEADLOCK", font=(FONT_BOLD, 18), fg=ACCENT, bg=BG).pack(side="left")
        tk.Label(title, text=" REGION CHANGER", font=(FONT_BOLD, 18), fg=TEXT, bg=BG).pack(side="left")
        tk.Label(left, text="Оставьте включёнными серверы, на которых хотите играть",
                 font=(FONT, 10), fg=MUTED, bg=BG).pack(anchor="w")

        self.pill = tk.Label(header, font=(FONT_BOLD, 9), padx=px(12), pady=px(6))
        self.pill.pack(side="right")

    def build_banner(self):
        # Shown by show_game_banner while Deadlock is running.
        self.banner = tk.Frame(self, bg="#35191b", highlightthickness=1,
                               highlightbackground=BAD, padx=px(16), pady=px(8))
        tk.Label(self.banner, text="⚠", font=(FONT_BOLD, 16), fg=BAD,
                 bg="#35191b").pack(side="left", padx=(0, px(12)))
        text = tk.Frame(self.banner, bg="#35191b")
        text.pack(side="left", fill="x")
        tk.Label(text, text="Deadlock запущен", font=(FONT_BOLD, 10), fg=TEXT,
                 bg="#35191b", anchor="w").pack(fill="x")
        tk.Label(text, text="Игра замеряет пинг при запуске: изменения вступят в силу "
                            "только после её перезапуска.",
                 font=(FONT, 9), fg="#e9b3ae", bg="#35191b", anchor="w").pack(fill="x")

    def build_body(self):
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=px(24), pady=(0, px(16)))
        self.body = body

        side = tk.Frame(body, bg=BG, width=px(230))
        side.pack(side="left", fill="y", padx=(0, px(20)))
        side.pack_propagate(False)

        section_label(side, "ПРЕСЕТЫ")
        self.preset_cards = {}
        for name, (codes, subtitle) in PRESETS.items():
            card = PresetCard(side, name, subtitle,
                              lambda c=codes: self.select_only(c if c is not None else self.pops))
            card.pack(fill="x", pady=(0, px(8)))
            self.preset_cards[name] = card

        ping_head = tk.Frame(side, bg=BG)
        ping_head.pack(fill="x", pady=(px(8), 0))
        tk.Label(ping_head, text="ПИНГ", font=(FONT_BOLD, 8), fg=MUTED, bg=BG).pack(side="left")
        LinkLabel(ping_head, "↻ обновить", self.refresh_pings, BG).pack(side="right")
        self.best = tk.Label(side, text="Измеряем…", font=(FONT, 9), fg=MUTED, bg=BG,
                             anchor="w", justify="left", wraplength=px(225))
        self.best.pack(fill="x", pady=(px(6), 0))

        scroll = ScrollFrame(body)
        scroll.pack(side="left", fill="both", expand=True)
        self.build_server_list(scroll.inner)

    def build_server_list(self, parent):
        known = {c for codes in REGIONS.values() for c in codes}
        groups = dict(REGIONS)
        groups["Другое"] = [c for c in self.pops if c not in known]

        first = True
        for region, codes in groups.items():
            codes = [c for c in codes if c in self.pops]
            if not codes:
                continue
            head = tk.Frame(parent, bg=BG)
            head.pack(fill="x", pady=(0 if first else px(18), px(8)))
            first = False
            tk.Label(head, text=region, font=(FONT_BOLD, 11), fg=TEXT, bg=BG).pack(side="left")
            counter = tk.Label(head, font=(FONT, 9), fg=MUTED, bg=BG)
            counter.pack(side="left", padx=(px(8), 0), pady=(px(2), 0))
            LinkLabel(head, "выключить все", lambda c=codes: self.set_many(c, False), BG).pack(side="right")
            LinkLabel(head, "включить все", lambda c=codes: self.set_many(c, True), BG).pack(
                side="right", padx=(0, px(12)))
            self.sections.append((codes, counter))

            for code in codes:
                var = tk.BooleanVar(value=code not in self.applied)
                self.vars[code] = var
                row = ServerRow(parent, code, self.pops[code], var)
                row.pack(fill="x", pady=(0, px(4)))
                self.rows[code] = row

    def build_footer(self):
        footer = tk.Frame(self, bg=SURFACE, padx=px(24), pady=px(14))
        footer.pack(side="bottom", fill="x")
        tk.Frame(self, bg=BORDER, height=1).pack(side="bottom", fill="x")

        info = tk.Frame(footer, bg=SURFACE)
        info.pack(side="left")
        self.summary = tk.Label(info, font=(FONT_BOLD, 10), fg=TEXT, bg=SURFACE, anchor="w")
        self.summary.pack(anchor="w")
        self.message = tk.Label(info, font=(FONT, 9), fg=MUTED, bg=SURFACE, anchor="w")
        self.message.pack(anchor="w")

        FlatButton(footer, "Применить", self.apply, bg=ACCENT, fg=ON_ACCENT,
                   hover_bg=ACCENT_HOVER, padx=22).pack(side="right")
        FlatButton(footer, "Сбросить", self.reset).pack(side="right", padx=(0, px(10)))

    # --- state

    def current_blocked(self):
        return {c for c, v in self.vars.items() if not v.get()}

    def on_change(self):
        if self.batch:
            return
        blocked = self.current_blocked()
        allowed = {c for c in self.vars if c not in blocked}

        self.summary.configure(text=f"Разрешено серверов: {len(allowed)} из {len(self.vars)}")
        if blocked != self.applied:
            self.message.configure(text="Есть неприменённые изменения", fg=ACCENT)
        else:
            self.message.configure(text=self.message_text, fg=self.message_color)

        for codes, counter in self.sections:
            counter.configure(text=f"{sum(c in allowed for c in codes)}/{len(codes)}")
        for row in self.rows.values():
            row.update_state()
        for name, (codes, _) in PRESETS.items():
            target = set(self.vars) if codes is None else {c for c in codes if c in self.vars}
            self.preset_cards[name].set_active(allowed == target)

        if self.applied:
            self.pill.configure(text=f"●  Активно · скрыто серверов: {len(self.applied)}",
                                bg="#183526", fg=GOOD)
        else:
            self.pill.configure(text="○  Все серверы доступны", bg=SURFACE, fg=MUTED)

    def set_message(self, text, color):
        self.message_text, self.message_color = text, color
        self.on_change()

    def select_only(self, codes):
        codes = set(codes)
        self.batch = True
        for code, var in self.vars.items():
            var.set(code in codes)
        self.batch = False
        self.on_change()

    def set_many(self, codes, value):
        self.batch = True
        for code in codes:
            self.vars[code].set(value)
        self.batch = False
        self.on_change()

    # --- actions

    def apply(self):
        blocked = self.current_blocked()
        if len(blocked) == len(self.vars):
            self.set_message("Оставьте включённым хотя бы один сервер", BAD)
            return
        ips = self.blocked_ips(blocked)
        off = firewall_off_profiles() if ips else []
        if off:
            if not messagebox.askyesno(
                    "Брандмауэр выключен",
                    f"Брандмауэр Windows выключен для профиля сети: {', '.join(off)}.\n"
                    "Без него блокировка серверов не сработает.\n\n"
                    "Включить брандмауэр для этого профиля?"):
                self.set_message("Не применено: брандмауэр Windows выключен", BAD)
                return
            if not enable_firewall(off):
                self.set_message("Не удалось включить брандмауэр Windows", BAD)
                return
        try:
            if ips:
                block_ips(ips)
            else:
                remove_rules()
        except RuntimeError as e:
            messagebox.showerror("Ошибка брандмауэра", str(e))
            return
        save_state(blocked, ips)
        self.applied, self.applied_ips = blocked, ips
        self.set_message(f"Готово: заблокировано {len(ips)} IP. Перезапустите Deadlock.", GOOD)

    def reset(self):
        remove_rules()
        save_state(set(), [])
        self.applied, self.applied_ips = set(), []
        self.message_text, self.message_color = "Все правила удалены. Перезапустите Deadlock.", GOOD
        self.select_only(self.pops)

    def refresh_pings(self):
        self.pings.clear()
        self.best.configure(text="Измеряем…", fg=MUTED)
        for row in self.rows.values():
            row.ping.configure(text="…", fg=DIM)
            row.signal.set(0, DIM)

        def worker():
            # TEST-NET address never answers; a reply means ICMP is faked
            # locally (VPN in TUN mode, proxy) and the numbers are useless.
            if ping_ms("192.0.2.1", 500) is not None:
                self.after(0, self.ping_intercepted)
                return

            def measure(code):
                times = [t for t in (ping_ms(ip) for ip in self.pops[code]["ips"][:2]) if t is not None]
                return code, min(times) if times else None

            with ThreadPoolExecutor(max_workers=16) as pool:
                for code, ms in pool.map(measure, self.rows):
                    self.after(0, self.show_ping, code, ms)

        threading.Thread(target=worker, daemon=True).start()

    def ping_intercepted(self):
        for row in self.rows.values():
            row.set_unknown()
        self.best.configure(text="Пинг перехватывается (VPN в режиме TUN?), "
                                 "значения недоступны.", fg=WARN)

    def show_ping(self, code, ms):
        self.rows[code].set_ping(ms)
        if ms is not None:
            self.pings[code] = ms
            best = min(self.pings, key=self.pings.get)
            city = split_desc(self.pops[best]["desc"])[0]
            self.best.configure(text=f"Ближайший сервер: {city} · {self.pings[best]} мс",
                                fg=TEXT)


def main():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    if not is_admin():
        relaunch_as_admin()
        return
    try:
        pops, fresh = load_pops()
    except Exception as e:
        tk.Tk().withdraw()
        messagebox.showerror("Deadlock Region Changer",
                             f"Не удалось загрузить список серверов Steam:\n{e}")
        return
    App(pops, fresh).mainloop()


if __name__ == "__main__":
    main()
