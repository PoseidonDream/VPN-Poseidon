#!/usr/bin/env python3
"""
Free VPN - a simple Windows app that connects your PC to free public VPN servers.

How it works
  * The list of servers comes from VPN Gate (https://www.vpngate.net), a free
    research project at the University of Tsukuba, Japan. Volunteers around the
    world run the servers.
  * The OpenVPN client (free, official, from
    https://openvpn.net/community-downloads/) makes the encrypted tunnel. Install
    it once.
  * This file uses only Python's standard library, so nothing else needs
    installing. Double-click it, or "Start Free VPN.bat", to run it.
"""
from __future__ import annotations

import base64
import csv
import io
import ipaddress
import json
import math
import os
import queue
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.request
import webbrowser
import zlib
from dataclasses import dataclass
from xml.sax.saxutils import escape as xml_escape

import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, messagebox, ttk

IS_WINDOWS = os.name == "nt"
if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

APP_NAME = "Free VPN"
APP_VERSION = "1.4"
SERVER_LIST_URL = "https://www.vpngate.net/api/iphone/"
VPNGATE_URL = "https://www.vpngate.net/en/"
OPENVPN_DOWNLOAD_URL = "https://openvpn.net/community-downloads/"
IP_CHECK_URL = "https://api.ipify.org"
USER_AGENT = "FreeVPN/" + APP_VERSION
MAX_DOWNLOAD = 20 * 1024 * 1024   # refuse absurdly large responses
CONNECT_TIMEOUT = 30      # seconds to wait for one server before moving on
MAX_SERVERS_TO_TRY = 5    # how many servers "try the next one" attempts
ANY_COUNTRY = "Any country (best server)"
RECONNECT_DELAYS = (3, 15, 30, 60, 120)   # seconds to wait before each reconnect round
GOOD_SERVERS_KEPT = 5     # how many servers that worked are remembered


# --------------------------------------------------------------------------
# Settings and files
# --------------------------------------------------------------------------

def data_dir() -> str:
    """Folder for settings and the saved server list (%APPDATA%\\FreeVPN)."""
    if IS_WINDOWS:
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    else:
        base = os.path.join(os.path.expanduser("~"), ".config")
    path = os.path.join(base, "FreeVPN")
    os.makedirs(path, exist_ok=True)
    return path


DEFAULT_SETTINGS = {
    "openvpn_path": "",
    "prevent_dns_leaks": True,
    "auto_failover": True,
    "country": ANY_COUNTRY,
    "theme": "system",        # "system", "light" or "dark"
    "mode": "all",            # "all": everything uses the VPN; "discord": only Discord
    "split_dirty": False,     # Discord-only DNS rule may still be installed (see App)
    "autostart": False,       # start with Windows (a Task Scheduler task)
    "auto_connect": False,    # connect as soon as the app opens
    "auto_reconnect": True,   # reconnect by itself if the connection drops
    "tray": True,             # "Keep running" hides the window next to the clock
    "good_servers": [],       # servers that worked, most recent first ("host|ip")
    "tray_hint_shown": False,
    "check_updates": True,    # look for a new version on GitHub
}


def load_settings() -> dict:
    settings = dict(DEFAULT_SETTINGS)
    try:
        with open(os.path.join(data_dir(), "settings.json"), encoding="utf-8") as f:
            saved = json.load(f)
        if isinstance(saved, dict):
            settings.update({k: v for k, v in saved.items() if k in DEFAULT_SETTINGS})
    except (OSError, ValueError):
        pass
    return settings


def save_settings(settings: dict) -> None:
    path = os.path.join(data_dir(), "settings.json")
    try:
        with open(path + ".tmp", "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
        os.replace(path + ".tmp", path)
    except OSError:
        pass


def http_get(url: str, timeout: float = 20) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError("The download was unexpectedly large.")
    return data


def short_error(exc: BaseException) -> str:
    text = str(getattr(exc, "reason", "") or exc).strip() or exc.__class__.__name__
    return text if len(text) < 120 else text[:117] + "..."


# --------------------------------------------------------------------------
# VPN Gate server list
# --------------------------------------------------------------------------

@dataclass
class Server:
    host: str
    ip: str
    score: int
    ping: int | None
    speed_bps: int
    country: str
    country_code: str
    sessions: int
    uptime_ms: int
    operator: str
    config: str               # OpenVPN settings, already passed through sanitize_config
    proto: str = "?"
    port: int = 0


def _int(value, default=0):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


FRIENDLY_COUNTRY_NAMES = {
    "Korea Republic of": "South Korea",
    "Viet Nam": "Vietnam",
    "Russian Federation": "Russia",
    "Iran (Islamic Republic of)": "Iran",
    "Taiwan Province of China": "Taiwan",
    "United Kingdom of Great Britain and Northern Ireland": "United Kingdom",
}


def clean_country(name: str) -> str:
    # "Croatia (LOCAL Name: Hrvatska)" -> "Croatia"
    name = (name or "").split(" (LOCAL Name")[0].strip() or "Unknown"
    return FRIENDLY_COUNTRY_NAMES.get(name, name)


# The only OpenVPN settings a downloaded server config may contain. OpenVPN runs
# with administrator rights, and a config file can normally tell it to run other
# programs (up/down scripts, plugins) or write files. A VPN Gate connection never
# needs any of that, so everything not listed here is thrown away.
ALLOWED_OPTIONS = frozenset((
    "client", "tls-client", "pull", "dev", "dev-type", "proto", "remote",
    "remote-random", "resolv-retry", "nobind", "float", "persist-key", "persist-tun",
    "cipher", "data-ciphers", "data-ciphers-fallback", "ncp-ciphers", "auth",
    "auth-nocache", "remote-cert-tls", "tls-version-min", "key-direction", "keepalive",
    "ping", "ping-restart", "reneg-sec", "tun-mtu", "mssfix", "fragment",
    "explicit-exit-notify", "connect-retry", "verb", "mute",
))
ALLOWED_BLOCKS = frozenset(("ca", "cert", "key", "extra-certs", "tls-auth", "tls-crypt"))
_OPTION_VALUE = re.compile(r"^[A-Za-z0-9._:\- ]*$")       # no quotes, slashes or paths
_BLOCK_LINE = re.compile(r"^[A-Za-z0-9+/=\- ]+$")          # certificates and keys
_DEVICE = re.compile(r"^(tun|tap)\d*$")


def sanitize_config(text: str) -> str:
    """Return a copy of a downloaded OpenVPN config that keeps only harmless,
    connection-related settings. Raises ValueError if it isn't usable."""
    out: list[str] = []
    block = ""            # name of the <block> we're inside, if any
    keep_block = False
    lines: list[str] = []
    has_remote = has_ca = False
    for raw in text.replace("\r", "").split("\n"):
        line = raw.strip()
        if block:
            if line == f"</{block}>":
                if keep_block:
                    out += [f"<{block}>"] + lines + [f"</{block}>"]
                    has_ca = has_ca or block == "ca"
                block = ""
            elif not keep_block or not line or line.startswith("#"):
                continue
            elif _BLOCK_LINE.match(line):
                lines.append(line)
            else:
                raise ValueError("Unexpected text inside a certificate block.")
            continue
        if not line or line[0] in "#;":
            continue
        if line.startswith("<"):
            if not line.endswith(">") or line.startswith("</"):
                raise ValueError("Malformed block in the server config.")
            block, lines = line[1:-1].strip(), []
            keep_block = block in ALLOWED_BLOCKS
            continue
        name, _, value = line.partition(" ")
        value = " ".join(value.split())
        if name not in ALLOWED_OPTIONS or not _OPTION_VALUE.match(value):
            continue
        if name == "dev" and not _DEVICE.match(value):
            continue
        has_remote = has_remote or (name == "remote" and bool(value))
        out.append(f"{name} {value}".strip())
    if block:
        raise ValueError("Unfinished block in the server config.")
    if not (has_remote and has_ca):
        raise ValueError("The server config is missing its address or certificate.")
    return "\n".join(out) + "\n"


def parse_server_list(text: str) -> list[Server]:
    """Parse the CSV that https://www.vpngate.net/api/iphone/ returns."""
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("*")]
    if not lines or "OpenVPN_ConfigData_Base64" not in lines[0]:
        raise ValueError("VPN Gate sent a server list in an unexpected format.")
    lines[0] = lines[0].lstrip("#")
    servers = []
    for row in csv.DictReader(io.StringIO("\n".join(lines))):
        b64 = (row.get("OpenVPN_ConfigData_Base64") or "").strip()
        if not b64:
            continue
        try:
            config = sanitize_config(base64.b64decode(b64).decode("utf-8", "replace"))
        except ValueError:
            continue
        proto, port = "?", 0
        for line in config.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "proto":
                proto = parts[1].split("-")[0].upper()
            elif len(parts) >= 3 and parts[0] == "remote":
                port = _int(parts[2])
        servers.append(Server(
            host=(row.get("HostName") or "").strip() or "unknown",
            ip=(row.get("IP") or "").strip(),
            score=_int(row.get("Score")),
            ping=_int(row.get("Ping"), None),
            speed_bps=_int(row.get("Speed")),
            country=clean_country(row.get("CountryLong", "")),
            country_code=(row.get("CountryShort") or "").strip(),
            sessions=_int(row.get("NumVpnSessions")),
            uptime_ms=_int(row.get("Uptime")),
            operator=(row.get("Operator") or "").strip(),
            config=config,
            proto=proto,
            port=port,
        ))
    servers.sort(key=lambda s: s.score, reverse=True)
    return servers


def load_servers() -> tuple[list[Server], str, bool]:
    """Download the server list: (servers, note, is it fresh?). Falls back to the
    last saved copy if offline."""
    cache = os.path.join(data_dir(), "servers.csv")
    try:
        text = http_get(SERVER_LIST_URL).decode("utf-8", "replace")
        servers = parse_server_list(text)
        if not servers:
            raise ValueError("VPN Gate returned an empty server list.")
        try:
            with open(cache, "w", encoding="utf-8") as f:
                f.write(text)
        except OSError:
            pass
        return servers, f"{len(servers)} servers · updated {time.strftime('%H:%M')}", True
    except Exception:
        if not os.path.exists(cache):
            raise
        with open(cache, encoding="utf-8") as f:
            servers = parse_server_list(f.read())
        when = time.strftime("%d %b %H:%M", time.localtime(os.path.getmtime(cache)))
        return servers, f"Offline · showing the list saved {when}", False


# --------------------------------------------------------------------------
# OpenVPN
# --------------------------------------------------------------------------

def find_openvpn(saved_path: str = "") -> str | None:
    candidates = [os.environ.get("FREEVPN_OPENVPN", ""), saved_path]
    if IS_WINDOWS:
        try:
            import winreg
            for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\OpenVPN",
                                        0, winreg.KEY_READ | view) as key:
                        for name in ("exe_path", ""):
                            try:
                                value = winreg.QueryValueEx(key, name)[0]
                            except OSError:
                                continue
                            if name == "":
                                value = os.path.join(value, "bin", "openvpn.exe")
                            candidates.append(value)
                except OSError:
                    pass
        except ImportError:
            pass
        for env in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"):
            root = os.environ.get(env)
            if root:
                candidates.append(os.path.join(root, "OpenVPN", "bin", "openvpn.exe"))
    candidates.append(shutil.which("openvpn") or "")
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def build_config(server: Server, prevent_dns_leaks: bool, discord_only: bool = False) -> str:
    """The server's (sanitized) OpenVPN config, plus a few settings that make it
    work well with current OpenVPN versions and fail fast on dead servers."""
    extra = [
        "# ---- added by Free VPN ----",
        "connect-timeout 10",          # don't wait two minutes on a dead server
        "connect-retry-max 3",
        # VPN Gate uses AES-128-CBC, which OpenVPN's fast "DCO" driver can't do.
        "ignore-unknown-option disable-dco",
        "disable-dco",
    ]
    if discord_only:
        extra += [
            # Leave the PC's normal internet route and DNS exactly as they are...
            'pull-filter ignore "redirect-gateway"',
            'pull-filter ignore "dhcp-option"',
            'pull-filter ignore "block-outside-dns"',
        ]
        # ...and send only Discord's own networks (and the DNS servers used to
        # look Discord up) through the VPN. SplitTunnel adds the rest as needed.
        for network in list(DISCORD_NETWORKS) + [ip + "/32" for ip in SPLIT_DNS_SERVERS]:
            net = ipaddress.ip_network(network)
            extra.append(f"route {net.network_address} {net.netmask}")
    elif prevent_dns_leaks:
        extra += [
            # Look up website names through the tunnel instead of your ISP.
            "dhcp-option DNS 1.1.1.1",
            "dhcp-option DNS 8.8.8.8",
            "ignore-unknown-option block-outside-dns",
            "block-outside-dns",
        ]
    return server.config.rstrip() + "\n" + "\n".join(extra) + "\n"


# (text in OpenVPN's log, what to tell the user, is it a problem on this PC?)
FAILURE_PATTERNS = [
    ("adapters on this system", "OpenVPN's network adapter is missing or busy. Close other "
     "VPN apps, or reinstall OpenVPN.", True),
    ("Cannot open TUN/TAP dev", "OpenVPN couldn't open its network adapter. Close other "
     "VPN apps, or reinstall OpenVPN.", True),
    ("Options error", "OpenVPN didn't accept the settings. Install the latest OpenVPN "
     "and try again.", True),
    ("AUTH_FAILED", "The server refused the connection.", False),
    ("TLS key negotiation failed", "The server didn't answer.", False),
    ("TLS handshake failed", "The server didn't answer.", False),
    ("Connection reset", "The server dropped the connection.", False),
    ("Exiting due to fatal error", "OpenVPN stopped with an error (see the Log).", False),
]


def classify_log_line(line: str):
    """Turn an OpenVPN log line into an event, or None if it's routine."""
    if "Initialization Sequence Completed" in line:
        return ("connected", "with errors" if "With Errors" in line else "")
    if "TCP: connect to" in line and "failed" in line:
        return ("failed", ("Couldn't reach the server.", False))
    for pattern, reason, local in FAILURE_PATTERNS:
        if pattern in line:
            return ("failed", (reason, local))
    if "SIGUSR1[soft" in line or "Restart pause" in line:
        return ("reconnecting", "")
    return None


def free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ProcessGuard:
    """Windows only: puts openvpn.exe in a job object so it closes automatically
    if Free VPN is killed or crashes, instead of leaving the VPN half-running."""

    def __init__(self):
        self.handle = None
        if not IS_WINDOWS:
            return
        try:
            class IoCounters(ctypes.Structure):
                _fields_ = [(name, ctypes.c_ulonglong) for name in (
                    "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                    "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

            class BasicLimits(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_int64),
                    ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class ExtendedLimits(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", BasicLimits),
                    ("IoInfo", IoCounters),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.CreateJobObjectW.restype = wintypes.HANDLE
            k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
            k32.SetInformationJobObject.restype = wintypes.BOOL
            k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                    ctypes.c_void_p, wintypes.DWORD]
            k32.AssignProcessToJobObject.restype = wintypes.BOOL
            k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            job = k32.CreateJobObjectW(None, None)
            if not job:
                return
            info = ExtendedLimits()
            info.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
            # 9 = JobObjectExtendedLimitInformation
            if k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
                self.k32, self.handle = k32, job
        except Exception:
            self.handle = None

    def add(self, proc: subprocess.Popen) -> None:
        if self.handle:
            try:
                self.k32.AssignProcessToJobObject(self.handle, int(proc._handle))
            except Exception:
                pass


PROCESS_GUARD: ProcessGuard | None = None


class VpnConnection:
    """Runs one openvpn process and reports what happens through a queue as
    (connection id, kind, value) tuples."""

    _last_id = 0

    def __init__(self, openvpn_exe: str, server: Server, config: str, events: queue.Queue,
                 discord_only: bool = False):
        VpnConnection._last_id += 1
        self.id = VpnConnection._last_id
        self.server = server
        self.events = events
        self.discord_only = discord_only
        self.gateway: str | None = None     # the VPN's gateway, read from OpenVPN's log
        self.split: SplitTunnel | None = None
        self.workdir = tempfile.mkdtemp(prefix="freevpn-")
        self.mgmt_port = free_local_port()
        self.mgmt_password = secrets.token_hex(16)
        config_path = os.path.join(self.workdir, "server.ovpn")
        password_path = os.path.join(self.workdir, "management.txt")
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                f.write(config)
            with open(password_path, "w", encoding="utf-8") as f:
                f.write(self.mgmt_password + "\n")
            command = [openvpn_exe, "--config", config_path,
                       "--management", "127.0.0.1", str(self.mgmt_port), password_path]
            self.proc = subprocess.Popen(
                command, cwd=self.workdir,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0)
        except Exception:
            self._remove_files()
            raise
        if PROCESS_GUARD is not None:
            PROCESS_GUARD.add(self.proc)
        threading.Thread(target=self._read_output, daemon=True).start()

    def _emit(self, kind: str, value=None) -> None:
        self.events.put((self.id, kind, value))

    def _read_output(self) -> None:
        try:
            for line in self.proc.stdout:
                line = line.rstrip()
                if not line:
                    continue
                self._emit("log", line)
                if "PUSH_REPLY" in line:
                    self.gateway = parse_gateway(line) or self.gateway
                event = classify_log_line(line)
                if event:
                    self._emit(*event)
        except (OSError, ValueError):
            pass
        code = self.proc.wait()
        self._remove_files()
        self._emit("exited", code)

    def _remove_files(self) -> None:
        shutil.rmtree(self.workdir, ignore_errors=True)

    def stop(self, timeout: float = 8) -> None:
        """Ask OpenVPN to shut down cleanly (so it removes its routes and DNS
        settings), and force it closed if it doesn't."""
        if self.proc.poll() is None:
            try:
                with socket.create_connection(("127.0.0.1", self.mgmt_port), timeout=3) as s:
                    s.settimeout(3)
                    self._read_until(s, b"PASSWORD")
                    s.sendall(self.mgmt_password.encode() + b"\r\n")
                    self._read_until(s, b"SUCCESS")
                    s.sendall(b"signal SIGTERM\r\n")
                    self._read_until(s, b"SIGTERM")
            except OSError:
                pass
            try:
                self.proc.wait(timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                try:
                    self.proc.wait(5)
                except subprocess.TimeoutExpired:
                    pass
        self._remove_files()

    @staticmethod
    def _read_until(sock: socket.socket, marker: bytes) -> None:
        data = b""
        deadline = time.monotonic() + 3
        while marker not in data and time.monotonic() < deadline:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk


# --------------------------------------------------------------------------
# Discord-only mode ("split tunnelling")
#
# In this mode the PC's normal internet route is left alone, so games and
# everything else stay fast, and only Discord goes through the VPN.
#
# Windows can't route by program without a special driver, so this routes by
# destination instead:
#   * Discord's own networks are routed through the VPN by OpenVPN itself
#     (see build_config).
#   * A Windows DNS rule (NRPT) sends lookups of Discord's names to a tiny DNS
#     relay inside this app. The relay asks a public DNS server through the
#     VPN, routes every address in the answer through the VPN, and only then
#     passes the answer on. That catches voice servers and anything else that
#     isn't in a fixed list.
# --------------------------------------------------------------------------

DISCORD_DOMAINS = (
    "discord.com", "discord.gg", "discord.media", "discordapp.com", "discordapp.net",
    "discord.co", "discord.dev", "discord.new", "discord.gift", "discordstatus.com",
    "discordcdn.com", "discordsays.com", "discordactivities.com", "dis.gd",
    "discord-attachments-uploads-prd.storage.googleapis.com",
)
# Networks that belong to Discord (its Cloudflare front door and its own voice
# servers). Voice also uses shared Google/Cloudflare addresses; those are added
# one by one by the DNS relay, because games use the same shared ranges.
DISCORD_NETWORKS = ("162.159.128.0/20", "66.22.192.0/18", "138.128.136.0/21",
                    "5.200.14.128/25")
# Names looked up straight after connecting, so they're routed before Discord asks.
DISCORD_WARMUP = (
    "discord.com", "gateway.discord.gg", "cdn.discordapp.com", "media.discordapp.net",
    "discordapp.com", "discord.gg", "updates.discord.com", "dl.discordapp.net",
    "status.discord.com", "images-ext-1.discordapp.net", "router.discordapp.net",
    "latency.discord.media",
)
SPLIT_SUPPORTED = IS_WINDOWS
SPLIT_DNS_SERVERS = ("1.0.0.1", "8.8.4.4")   # public DNS, reached through the VPN
SPLIT_DNS_PORT = 53
SPLIT_LISTEN_PORT = 53       # Windows only ever asks DNS servers on port 53
SPLIT_CHECK_PORT = 443       # "is Discord reachable?" test
NRPT_COMMENT = "FreeVPN"     # marks our DNS rule so only ours is ever removed


def _system32(name: str) -> str:
    # Full paths: these run with administrator rights, so never search PATH.
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", name)


ROUTE_EXE = _system32("route.exe")
CMD_EXE = _system32("cmd.exe")
POWERSHELL_EXE = _system32(r"WindowsPowerShell\v1.0\powershell.exe")


def run_hidden(args: list, timeout: float = 30) -> tuple[int, str]:
    """Run a Windows command without flashing a console window.
    Returns (exit code, what it printed)."""
    try:
        done = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=timeout,
                              creationflags=subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0)
        return done.returncode, done.stdout.decode("utf-8", "replace").strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, short_error(exc)


def _powershell(script: str) -> list:
    return [POWERSHELL_EXE, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-Command", script]


_NRPT_REMOVE = ("Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '%s' } | "
                "ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }; "
                % NRPT_COMMENT)


def add_discord_dns_rule(servers: list) -> tuple[int, str]:
    """Tell Windows to look up Discord's names (and only those) at `servers`."""
    names = ",".join(f"'{n}'" for domain in DISCORD_DOMAINS for n in ("." + domain, domain))
    addresses = ",".join(f"'{server}'" for server in servers)
    return run_hidden(_powershell(
        "$ErrorActionPreference = 'Stop'; " + _NRPT_REMOVE +
        f"Add-DnsClientNrptRule -Namespace {names} -NameServers {addresses} "
        f"-Comment '{NRPT_COMMENT}'; Clear-DnsClientCache"))


def remove_discord_dns_rule() -> tuple[int, str]:
    return run_hidden(_powershell(
        "$ErrorActionPreference = 'SilentlyContinue'; " + _NRPT_REMOVE + "Clear-DnsClientCache"))


_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"


def parse_gateway(push_reply: str) -> str | None:
    """The VPN gateway's address, from the "PUSH_REPLY" line in OpenVPN's log."""
    found = re.search("route-gateway " + _IP, push_reply)
    if not found:
        # Older style: "ifconfig <my address> <gateway>" (not "<my address> <netmask>")
        found = re.search("ifconfig " + _IP + " " + _IP, push_reply)
        if not found or found.group(2).startswith("255."):
            return None
    try:
        return str(ipaddress.ip_address(found.group(found.lastindex)))
    except ValueError:
        return None


def is_discord_name(name: str) -> bool:
    return any(name == d or name.endswith("." + d) for d in DISCORD_DOMAINS)


# ---- just enough of the DNS wire format ----

DNS_A, DNS_AAAA, DNS_SVCB, DNS_HTTPS = 1, 28, 64, 65


def dns_query(name: str, record_type: int = DNS_A) -> bytes:
    """A DNS question for `name`."""
    header = struct.pack(">HHHHHH", secrets.randbelow(65536), 0x0100, 1, 0, 0, 0)
    labels = b"".join(bytes((len(part),)) + part.encode("ascii")
                      for part in name.strip(".").split("."))
    return header + labels + b"\x00" + struct.pack(">HH", record_type, 1)


def dns_question(packet: bytes) -> tuple[str, int, int]:
    """(name, record type, where the question ends) of a DNS query.
    Raises ValueError if the packet isn't a well-formed query."""
    if len(packet) < 17 or struct.unpack(">H", packet[4:6])[0] < 1:
        raise ValueError("not a DNS question")
    labels, pos = [], 12
    while True:
        if pos >= len(packet):
            raise ValueError("truncated DNS question")
        length = packet[pos]
        pos += 1
        if length == 0:
            break
        if length > 63 or pos + length > len(packet):
            raise ValueError("bad label in DNS question")
        labels.append(packet[pos:pos + length].decode("ascii", "replace").lower())
        pos += length
    if pos + 4 > len(packet):
        raise ValueError("truncated DNS question")
    return ".".join(labels), struct.unpack(">H", packet[pos:pos + 2])[0], pos + 4


def dns_addresses(packet: bytes) -> list[str]:
    """The IPv4 addresses (A records) in a DNS answer."""
    def skip_name(pos: int) -> int:
        while True:
            length = packet[pos]
            if length == 0:
                return pos + 1
            if length & 0xC0:          # a pointer to a name used earlier
                return pos + 2
            pos += 1 + length

    addresses = []
    try:
        questions, answers = struct.unpack(">HH", packet[4:8])
        pos = 12
        for _ in range(questions):
            pos = skip_name(pos) + 4
        for _ in range(answers):
            pos = skip_name(pos)
            record_type, _cls, _ttl, size = struct.unpack(">HHIH", packet[pos:pos + 10])
            pos += 10
            if record_type == DNS_A and size == 4 and pos + 4 <= len(packet):
                addresses.append(".".join(str(b) for b in packet[pos:pos + 4]))
            pos += size
    except (IndexError, struct.error):
        pass
    return addresses


def dns_empty_answer(query: bytes, question_end: int) -> bytes:
    """A "no such record" reply to `query`."""
    flags = struct.unpack(">H", query[2:4])[0]
    reply_flags = 0x8080 | (flags & 0x7900)    # a reply, recursion available, no error
    return (query[:2] + struct.pack(">HHHHH", reply_flags, 1, 0, 0, 0)
            + query[12:question_end])


class SplitTunnel:
    """Sends only Discord through an already-connected VPN. start() and stop()
    run Windows commands and take a second or two, so call them off the UI thread."""

    def __init__(self, log):
        self.log = log                    # function(text): goes to the Log view
        self.on_check = lambda ok: None   # told whether Discord answered through the VPN
        self.gateway = ""
        self.static = [ipaddress.ip_network(n) for n in DISCORD_NETWORKS]
        self.routed: set[str] = set()     # single addresses we routed ourselves
        self.lock = threading.Lock()
        self.sock: socket.socket | None = None
        self.running = False
        self.stopped = False

    # ---- start / stop ----

    def start(self, gateway: str | None) -> tuple[bool, str]:
        """Returns (it worked, a note). The note is "dns" if routing is set up
        but the Windows DNS rule couldn't be added."""
        self.gateway = gateway or self._find_gateway() or ""
        if not self.gateway:
            return False, "the VPN's gateway address wasn't found."
        self.log(f"Discord-only: the VPN gateway is {self.gateway}")
        relay = self._start_relay()
        servers = ["127.0.0.1"] if relay else list(SPLIT_DNS_SERVERS)
        code, output = add_discord_dns_rule(servers)
        if code == 0:
            self.log("Discord-only: Windows will look up Discord's names at "
                     + ", ".join(servers))
        else:
            self.log(f"Discord-only: couldn't add the Windows DNS rule ({code}): {output}")
        if self.stopped:                  # disconnected while this was being set up
            self._clean_up()
            return False, "cancelled."
        threading.Thread(target=self._warm_up, daemon=True).start()
        return True, "" if code == 0 else "dns"

    def stop(self) -> None:
        self.stopped = True
        self._clean_up()

    def _clean_up(self) -> None:
        self.running = False
        sock, self.sock = self.sock, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        code, output = remove_discord_dns_rule()
        if code != 0:
            self.log(f"Discord-only: couldn't remove the Windows DNS rule ({code}): {output}")
        with self.lock:
            addresses = sorted(self.routed)
            self.routed.clear()
        for i in range(0, len(addresses), 100):     # several per command: it's quicker
            run_hidden([CMD_EXE, "/c", " & ".join(
                f"{ROUTE_EXE} DELETE {ip}" for ip in addresses[i:i + 100])])
        self.log("Discord-only: switched off")

    def refresh(self, gateway: str | None) -> None:
        """After OpenVPN reconnects: if the gateway changed, re-point our routes."""
        if not gateway or gateway == self.gateway or self.stopped:
            return
        self.gateway = gateway
        with self.lock:
            addresses = sorted(self.routed)
            self.routed.clear()

        def again():
            for ip in addresses:
                run_hidden([ROUTE_EXE, "DELETE", ip])
                self.route(ip)
        threading.Thread(target=again, daemon=True).start()

    def _find_gateway(self) -> str | None:
        """Fallback: read the gateway from the route OpenVPN added for our DNS server."""
        target = SPLIT_DNS_SERVERS[0]
        code, output = run_hidden([ROUTE_EXE, "print", "-4", target])
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == target and parts[1] == "255.255.255.255":
                try:
                    return str(ipaddress.ip_address(parts[2]))
                except ValueError:
                    pass
        return None

    # ---- routing ----

    def route(self, ip: str) -> None:
        """Send one address through the VPN (unless it already goes that way)."""
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return
        if not address.is_global or any(address in network for network in self.static):
            return
        with self.lock:
            if ip in self.routed or self.stopped:
                return
            self.routed.add(ip)
        code, output = run_hidden([ROUTE_EXE, "ADD", ip, "MASK", "255.255.255.255",
                                   self.gateway, "METRIC", "1"])
        self.log(f"Discord-only: {ip} now goes through the VPN" if code == 0 else
                 f"Discord-only: couldn't route {ip} ({code}): {output}")

    def _warm_up(self) -> None:
        for i, name in enumerate(DISCORD_WARMUP):
            if self.stopped:
                return
            reply = self._ask_upstream(dns_query(name))
            addresses = dns_addresses(reply) if reply else []
            for ip in addresses:
                self.route(ip)
            if i == 0:
                ok = self._can_connect(addresses)
                self.log("Discord-only: Discord answered through the VPN" if ok else
                         "Discord-only: Discord did NOT answer through the VPN")
                if not self.stopped:
                    self.on_check(ok)

    @staticmethod
    def _can_connect(addresses: list) -> bool:
        for ip in addresses[:3]:
            try:
                socket.create_connection((ip, SPLIT_CHECK_PORT), timeout=6).close()
                return True
            except OSError:
                continue
        return False

    # ---- the DNS relay ----

    def _start_relay(self) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("127.0.0.1", SPLIT_LISTEN_PORT))
            sock.settimeout(0.5)
        except OSError as exc:
            self.log(f"Discord-only: DNS port {SPLIT_LISTEN_PORT} is taken ({short_error(exc)}); "
                     "using the simpler method (fixed address list only)")
            return False
        self.sock, self.running = sock, True
        threading.Thread(target=self._serve, args=(sock,), daemon=True).start()
        return True

    def _serve(self, sock: socket.socket) -> None:
        while self.running:
            try:
                query, client = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except ConnectionResetError:
                continue      # Windows: an asker stopped listening; harmless
            except OSError:
                if not self.running:
                    break
                time.sleep(0.05)
                continue
            threading.Thread(target=self._answer, args=(sock, query, client),
                             daemon=True).start()

    def _answer(self, sock: socket.socket, query: bytes, client) -> None:
        try:
            name, record_type, question_end = dns_question(query)
        except ValueError:
            return
        ours = is_discord_name(name)
        if ours and record_type in (DNS_AAAA, DNS_SVCB, DNS_HTTPS):
            # The VPN is IPv4-only. Saying "no IPv6 address" keeps Discord on IPv4,
            # so it can't slip past the VPN over IPv6.
            reply = dns_empty_answer(query, question_end)
        else:
            reply = self._ask_upstream(query)
            if reply is None:
                return
            if ours:
                for ip in dns_addresses(reply):
                    self.route(ip)        # route first, answer second
        try:
            sock.sendto(reply, client)
        except OSError:
            pass

    @staticmethod
    def _ask_upstream(query: bytes) -> bytes | None:
        """Ask the public DNS servers (their addresses are routed through the VPN)."""
        for server in SPLIT_DNS_SERVERS:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(2.5)
                    s.sendto(query, (server, SPLIT_DNS_PORT))
                    while True:
                        reply, sender = s.recvfrom(4096)
                        if sender[0] == server and reply[:2] == query[:2]:
                            return reply
            except OSError:
                continue
        return None


# --------------------------------------------------------------------------
# Starting with Windows
#
# Free VPN needs administrator rights, and programs in the normal Startup
# folder can't get those without asking every time. So it registers a Windows
# Task Scheduler task instead: "when I sign in, start Free VPN with highest
# privileges". That starts it minimized, without the permission question.
# --------------------------------------------------------------------------

AUTOSTART_TASK = "FreeVPN-Autostart"
AUTOSTART_ARG = "--startup"       # tells the app it was started at sign-in
AUTOSTART_DELAY = "PT10S"         # wait 10 seconds after sign-in (network comes up)
STARTUP_LIST_RETRIES = 8          # at sign-in, retry the server list for up to ~2 minutes
STARTUP_RETRY_MS = 15000


def gui_python() -> str:
    """The Python that shows no console window (pythonw.exe), if there is one."""
    exe = sys.executable
    pythonw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if os.path.basename(exe).lower() == "python.exe" and os.path.exists(pythonw):
        return pythonw
    return exe


def autostart_command() -> tuple[str, str, str]:
    """(program, arguments, folder) that start this copy of Free VPN at sign-in."""
    if getattr(sys, "frozen", False):          # FreeVPN.exe from "Build EXE"
        exe = os.path.abspath(sys.executable)
        return exe, AUTOSTART_ARG, os.path.dirname(exe)
    script = os.path.abspath(sys.argv[0])
    return gui_python(), subprocess.list2cmdline([script, AUTOSTART_ARG]), os.path.dirname(script)


def current_user() -> str:
    """The signed-in account as DOMAIN\\name (what Task Scheduler wants)."""
    if IS_WINDOWS:
        try:
            size = wintypes.ULONG(512)
            buffer = ctypes.create_unicode_buffer(size.value)
            if ctypes.windll.secur32.GetUserNameExW(2, buffer, ctypes.byref(size)):  # 2 = SAM
                return buffer.value
        except Exception:
            pass
    domain = os.environ.get("USERDOMAIN", "")
    name = os.environ.get("USERNAME") or os.environ.get("USER", "")
    return f"{domain}\\{name}" if domain else name


def autostart_task_xml(user: str, command: str, arguments: str, folder: str) -> str:
    """The Task Scheduler definition. Unlike the defaults, it keeps running on
    battery power and never times out (by default a task is stopped when a
    laptop is unplugged, and after 3 days)."""
    e = xml_escape
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Starts {e(APP_NAME)} (minimized) when you sign in to Windows. Turn this off in {e(APP_NAME)}: Settings, "Start Free VPN when Windows starts".</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{e(user)}</UserId>
      <Delay>{AUTOSTART_DELAY}</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{e(user)}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{e(command)}</Command>
      <Arguments>{e(arguments)}</Arguments>
      <WorkingDirectory>{e(folder)}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def _ps_quote(text: str) -> str:
    """A PowerShell single-quoted string: nothing inside is special except '."""
    return "'" + text.replace("'", "''") + "'"


def _powershell_encoded(script: str) -> list:
    """Run a script passed as -EncodedCommand, which avoids every quoting problem
    with paths and the task's XML on the command line."""
    wrapped = ("$ErrorActionPreference = 'Stop'\ntry {\n" + script +
               "\n    exit 0\n} catch {\n    Write-Output $_.Exception.Message\n    exit 1\n}\n")
    encoded = base64.b64encode(wrapped.encode("utf-16-le")).decode("ascii")
    return [POWERSHELL_EXE, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-EncodedCommand", encoded]


def set_autostart(enabled: bool) -> tuple[int, str]:
    """Add (or update) or remove the sign-in task. Returns (exit code, message)."""
    name = _ps_quote(AUTOSTART_TASK)
    if enabled:
        command, arguments, folder = autostart_command()
        task = autostart_task_xml(current_user(), command, arguments, folder)
        script = (f"    Register-ScheduledTask -TaskName {name} -Xml {_ps_quote(task)} "
                  "-Force | Out-Null")
    else:
        script = (f"    if (Get-ScheduledTask -TaskName {name} -ErrorAction SilentlyContinue) {{\n"
                  f"        Unregister-ScheduledTask -TaskName {name} -Confirm:$false\n    }}")
    return run_hidden(_powershell_encoded(script), timeout=60)


# --------------------------------------------------------------------------
# Updates
#
# Free VPN asks GitHub for the newest release of this project. If it's newer,
# the window offers it; one click downloads it, checks it, and hands over to a
# small helper that waits for Free VPN to close, puts the new file in place and
# starts it again (reconnecting if you were connected).
# --------------------------------------------------------------------------

UPDATE_REPO = "PoseidonDream/VPN-Poseidon"
UPDATE_API = f"https://api.github.com/repos/{UPDATE_REPO}/releases/latest"
UPDATE_DOWNLOAD_PREFIX = f"https://github.com/{UPDATE_REPO}/releases/download/"
RELEASES_PAGE = f"https://github.com/{UPDATE_REPO}/releases/latest"
UPDATE_CHECK_EVERY = 12 * 3600     # seconds between automatic checks while running
UPDATE_FIRST_CHECK_MS = 8000       # first check, a few seconds after opening
UPDATE_MAX_SIZE = 80 * 1024 * 1024
UPDATED_ARG, RESUME_ARG = "--updated", "--resume"


def parse_version(text: str) -> tuple:
    """"v1.10.2" -> (1, 10, 2)."""
    return tuple(int(n) for n in re.findall(r"\d+", text or "")[:3]) or (0,)


def is_newer(candidate: str, current: str) -> bool:
    a, b = parse_version(candidate), parse_version(current)
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) > b + (0,) * (width - len(b))


def update_file_name() -> str:
    """What this copy of Free VPN is made of: FreeVPN.exe or FreeVPN.pyw."""
    return "FreeVPN.exe" if getattr(sys, "frozen", False) else "FreeVPN.pyw"


def this_program_file() -> str:
    return os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__)


def check_for_update() -> dict | None:
    """Ask GitHub about the latest release. Returns details of the update, or
    None if this copy is up to date. Raises if GitHub can't be asked."""
    request = urllib.request.Request(UPDATE_API, headers={
        "User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=15) as response:
        release = json.loads(response.read(2 * 1024 * 1024).decode("utf-8"))
    if not isinstance(release, dict) or release.get("draft") or release.get("prerelease"):
        return None
    version = str(release.get("tag_name") or "").lstrip("vV")
    if not version or not is_newer(version, APP_VERSION):
        return None
    name = update_file_name()
    asset = next((a for a in release.get("assets") or []
                  if isinstance(a, dict) and a.get("name") == name), None)
    url = str((asset or {}).get("browser_download_url") or "")
    if not url.startswith(UPDATE_DOWNLOAD_PREFIX):    # only this project's own releases
        return None
    return {"version": version, "url": url, "size": int(asset.get("size") or 0),
            "page": str(release.get("html_url") or RELEASES_PAGE)}


def download_update(update: dict, folder: str) -> str:
    """Download the new version next to the current one (as "<name>.new"),
    check that it's complete and really is Free VPN, and return its path."""
    request = urllib.request.Request(update["url"], headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=120) as response:
        data = response.read(UPDATE_MAX_SIZE + 1)
    if len(data) > UPDATE_MAX_SIZE:
        raise ValueError("the download was unexpectedly large")
    if update.get("size") and len(data) != update["size"]:
        raise ValueError("the download was incomplete")
    name = update_file_name()
    if name.endswith(".exe"):
        if data[:2] != b"MZ" or len(data) < 1024 * 1024:
            raise ValueError("the download isn't a Windows program")
    else:
        text = data.decode("utf-8")
        compile(text, name, "exec")                  # a SyntaxError if it's damaged
        found = re.search(r'^APP_VERSION = "([^"]+)"', text, re.M)
        if not found or found.group(1) != update["version"]:
            raise ValueError("the download isn't the expected version")
    path = os.path.join(folder, name + ".new")
    with open(path, "wb") as f:
        f.write(data)
    return path


def update_helper_command(new_file: str, target: str, program: str, arguments: str,
                          folder: str, pid: int) -> list:
    """A hidden PowerShell that waits for process `pid` (this app) to close,
    moves `new_file` over `target`, and starts `program arguments`. If the move
    fails it still starts the program, so you're never left without Free VPN."""
    q = _ps_quote
    script = f"""    Wait-Process -Id {int(pid)} -Timeout 90 -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    for ($i = 0; $i -lt 20; $i++) {{
        try {{ Move-Item -LiteralPath {q(new_file)} -Destination {q(target)} -Force; break }}
        catch {{ Start-Sleep -Milliseconds 500 }}
    }}
    Start-Process -FilePath {q(program)} -ArgumentList {q(arguments)} -WorkingDirectory {q(folder)}"""
    return _powershell_encoded(script)


def start_update_helper(command: list) -> None:
    flags = 0x08000000 | 0x01000000            # no window; outlive our job, if we're in one
    try:
        subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, creationflags=flags if IS_WINDOWS else 0)
    except OSError:
        subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, creationflags=0x08000000 if IS_WINDOWS else 0)


# ---- one copy at a time: a second start just shows the first copy's window ----

SHOW_REQUEST, SHOW_REPLY = b"FreeVPN show\n", b"FreeVPN ok\n"


def _instance_file() -> str:
    return os.path.join(data_dir(), "instance.port")


def show_running_copy() -> bool:
    """If Free VPN is already running, ask it to show its window. Returns True
    if it did. Works without administrator rights, so it can be done before
    the permission question."""
    try:
        with open(_instance_file(), encoding="ascii") as f:
            port = int(f.read().strip())
    except (OSError, ValueError):
        return False
    if IS_WINDOWS:
        try:   # let the running copy bring its window to the front
            ctypes.windll.user32.AllowSetForegroundWindow(-1)    # -1 = ASFW_ANY
        except Exception:
            pass
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
            s.settimeout(3)
            s.sendall(SHOW_REQUEST)
            return s.recv(64).startswith(SHOW_REPLY.strip())
    except (OSError, ValueError):
        return False


# --------------------------------------------------------------------------
# Drawing
#
# Tk can't draw smooth (antialiased) shapes on Windows, so the round button,
# rounded panels and switches are computed here, pixel by pixel, and handed to
# Tk as PNG images. Shapes are described by a "signed distance" function:
# negative inside the shape, positive outside, in pixels from its edge.
# --------------------------------------------------------------------------

def hex_rgb(color: str) -> tuple[float, float, float]:
    color = color.lstrip("#")
    return (int(color[0:2], 16) / 255.0, int(color[2:4], 16) / 255.0, int(color[4:6], 16) / 255.0)


def mix(a: str, b: str, t: float) -> str:
    """Blend two colors: t=0 gives a, t=1 gives b."""
    pairs = zip(hex_rgb(a), hex_rgb(b))
    return "#%02x%02x%02x" % tuple(int(round(255 * (x + (y - x) * t))) for x, y in pairs)


def _pack(pixel) -> bytes:
    """Premultiplied float RGBA -> 4 bytes of straight RGBA."""
    r, g, b, a = pixel
    if a <= 0.002:
        return b"\x00\x00\x00\x00"
    return bytes((min(255, int(r / a * 255 + 0.5)), min(255, int(g / a * 255 + 0.5)),
                  min(255, int(b / a * 255 + 0.5)), min(255, int(a * 255 + 0.5))))


def png_encode(width: int, height: int, rgba: bytes) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)
    stride = width * 4
    raw = b"".join(b"\x00" + rgba[i:i + stride] for i in range(0, len(rgba), stride))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 6))
            + chunk(b"IEND", b""))


def photo_from_rgba(master, width: int, height: int, rgba: bytes) -> tk.PhotoImage:
    data = base64.b64encode(png_encode(width, height, rgba)).decode("ascii")
    return tk.PhotoImage(master=master, data=data, format="png")


def sdf_circle(cx, cy, radius):
    return lambda x, y: math.hypot(x - cx, y - cy) - radius


def sdf_round_rect(x0, y0, x1, y1, radius):
    cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
    hw, hh = (x1 - x0) / 2 - radius, (y1 - y0) / 2 - radius

    def distance(x, y):
        dx, dy = abs(x - cx) - hw, abs(y - cy) - hh
        return math.hypot(max(dx, 0.0), max(dy, 0.0)) + min(max(dx, dy), 0.0) - radius
    return distance


def sdf_capsule(ax, ay, bx, by, radius):
    """A line from A to B with round ends."""
    vx, vy = bx - ax, by - ay
    length2 = vx * vx + vy * vy or 1.0

    def distance(x, y):
        t = min(1.0, max(0.0, ((x - ax) * vx + (y - ay) * vy) / length2))
        return math.hypot(x - ax - t * vx, y - ay - t * vy) - radius
    return distance


class Pixmap:
    """A small transparent drawing surface with antialiased fills."""

    def __init__(self, width: int, height: int):
        self.w, self.h = int(width), int(height)
        self.rows = [[(0.0, 0.0, 0.0, 0.0)] * self.w for _ in range(self.h)]

    def fill(self, sdf, color: str, alpha: float = 1.0, soft: float = 0.0) -> None:
        """Paint a shape. With soft > 0 it fades out over that many pixels
        beyond its edge instead of ending crisply (used for shadows)."""
        r, g, b = hex_rgb(color)
        for y, row in enumerate(self.rows):
            for x in range(self.w):
                d = sdf(x + 0.5, y + 0.5)
                if soft:
                    a = alpha * max(0.0, 1.0 - max(d, 0.0) / soft) ** 2
                else:
                    a = alpha * min(1.0, max(0.0, 0.5 - d))
                if a <= 0.0:
                    continue
                pr, pg, pb, pa = row[x]
                k = 1.0 - a
                row[x] = (r * a + pr * k, g * a + pg * k, b * a + pb * k, a + pa * k)

    def stretched(self, extra_w: int, extra_h: int) -> "Pixmap":
        """A wider/taller copy made by repeating the middle column and row.
        Tk fills a stretched panel by tiling the picture's middle section, one
        draw per tile, so a tiny middle means thousands of slow draws; a wide
        flat middle keeps repainting fast."""
        out = Pixmap(self.w + extra_w, self.h + extra_h)
        mx, my = self.w // 2, self.h // 2
        rows = [row[:mx] + [row[mx]] * extra_w + row[mx:] for row in self.rows]
        out.rows = rows[:my] + [rows[my]] * extra_h + rows[my:]
        return out

    def photo(self, master) -> tk.PhotoImage:
        packed: dict = {}   # most pixels repeat, so convert each distinct one once
        for row in self.rows:
            for pixel in row:
                if pixel not in packed:
                    packed[pixel] = _pack(pixel)
        rgba = b"".join(b"".join([packed[p] for p in row]) for row in self.rows)
        return photo_from_rgba(master, self.w, self.h, rgba)


def panel_pixmap(width, height, radius, fill, border=None, border_width=1.0,
                 margin=0, shadow=0.0) -> Pixmap:
    """A rounded rectangle, meant to be stretched into buttons, cards and so on."""
    pm = Pixmap(width, height)
    x0, y0, x1, y1 = margin, margin, pm.w - margin, pm.h - margin
    if shadow and margin:
        drop = margin * 0.3
        pm.fill(sdf_round_rect(x0, y0 + drop, x1, y1 + drop, radius), "#0b1220",
                shadow, soft=margin * 0.95)
    if border:
        pm.fill(sdf_round_rect(x0, y0, x1, y1, radius), border)
        w = border_width
        pm.fill(sdf_round_rect(x0 + w, y0 + w, x1 - w, y1 - w, max(radius - w, 0.0)), fill)
    else:
        pm.fill(sdf_round_rect(x0, y0, x1, y1, radius), fill)
    return pm


def switch_pixmap(width, height, track, knob, on: bool) -> Pixmap:
    pm = Pixmap(width, height)
    r = pm.h / 2
    pm.fill(sdf_round_rect(0, 0, pm.w, pm.h, r), track)
    pm.fill(sdf_circle(pm.w - r if on else r, r, r - max(2.5, pm.h * 0.14)), knob)
    return pm


def chevron_pixmap(width, height, color, stroke) -> Pixmap:
    """The little "v" at the right of the country box."""
    pm = Pixmap(width, height)
    cx, cy = pm.w / 2 - pm.w * 0.08, pm.h / 2
    dx, dy = pm.h * 0.30, pm.h * 0.16
    left = sdf_capsule(cx - dx, cy - dy, cx, cy + dy, stroke / 2)
    right = sdf_capsule(cx + dx, cy - dy, cx, cy + dy, stroke / 2)
    pm.fill(lambda x, y: min(left(x, y), right(x, y)), color)
    return pm


# Building blocks for the round power button: each returns how opaque a layer is
# at a given distance from the centre.
def disc(radius, alpha=1.0):
    return lambda d: alpha * min(1.0, max(0.0, radius - d + 0.5))


def glow(radius, spread, alpha):
    return lambda d: alpha * max(0.0, 1.0 - max(0.0, d - radius) / spread) ** 2


class PowerArt:
    """Draws the round power button. Its circles depend only on the distance
    from the centre, so they come from a small lookup table, which keeps each
    picture down to a few milliseconds."""

    STEPS = 4   # table entries per pixel of distance

    def __init__(self, size: int, radius: float, icon_scale: float = 0.36):
        self.size = size = int(size)
        c = size / 2
        hyp = math.hypot
        steps = self.STEPS
        self.index = [[int(hyp(x + 0.5 - c, y + 0.5 - c) * steps) for x in range(size)]
                      for y in range(size)]
        self.table_size = max(max(row) for row in self.index) + 1

        # The power symbol: a ring with a gap at the top and a bar through the gap.
        ri = radius * icon_scale
        w = max(2.0, ri * 0.30)
        gap = math.radians(40)
        ex, ey = ri * math.sin(gap), -ri * math.cos(gap)
        bar_top, bar_bottom = -ri * 1.22, -ri * 0.16
        self.icon = []   # (x, y, coverage)
        lo, hi = max(0, int(c - ri - w - 2)), min(size, int(c + ri + w + 3))
        for y in range(max(0, int(c + bar_top - w - 2)), hi):
            for x in range(lo, hi):
                px_, py_ = x + 0.5 - c, y + 0.5 - c
                if math.atan2(abs(px_), -py_) >= gap:
                    d_ring = abs(hyp(px_, py_) - ri)
                else:
                    d_ring = hyp(abs(px_) - ex, py_ - ey)
                d_bar = hyp(px_, py_ - min(max(py_, bar_top), bar_bottom))
                coverage = min(1.0, max(0.0, 0.5 - (min(d_ring, d_bar) - w / 2)))
                if coverage > 0.0:
                    self.icon.append((x, y, coverage))

    def render(self, master, layers, icon_color: str) -> tk.PhotoImage:
        """layers: list of (opacity-by-distance function, color), bottom first."""
        return photo_from_rgba(master, self.size, self.size, self.rgba(layers, icon_color))

    def rgba(self, layers, icon_color: str) -> bytes:
        """The same picture as raw RGBA pixels."""
        steps = self.STEPS
        colors = [(fn, hex_rgb(color)) for fn, color in layers]
        table = []
        for i in range(self.table_size):
            d = (i + 0.5) / steps
            r = g = b = a = 0.0
            for fn, (cr, cg, cb) in colors:
                la = fn(d)
                if la > 0.0:
                    k = 1.0 - la
                    r, g, b, a = cr * la + r * k, cg * la + g * k, cb * la + b * k, la + a * k
            table.append((r, g, b, a))
        packed = [_pack(p) for p in table]
        rows = [bytearray(b"".join([packed[i] for i in row])) for row in self.index]
        ir, ig, ib = hex_rgb(icon_color)
        for x, y, la in self.icon:
            r, g, b, a = table[self.index[y][x]]
            k = 1.0 - la
            rows[y][4 * x:4 * x + 4] = _pack((ir * la + r * k, ig * la + g * k,
                                              ib * la + b * k, la + a * k))
        return b"".join(rows)


# --------------------------------------------------------------------------
# The icon next to the clock (Windows' "notification area")
#
# Python has no built-in way to make one, so this talks to Windows directly.
# Its messages arrive through Tk's own event loop (Tk handles every Windows
# message for this thread), so all of it runs on the main thread. If anything
# here fails, Free VPN carries on without the icon.
# --------------------------------------------------------------------------

TRAY_SUPPORTED = IS_WINDOWS
TRAY_COLORS = {"idle": "#7b8594", "busy": "#e09112", "on": "#1aa550", "error": "#dc3545"}
TRAY_SIZES = (16, 20, 24, 32, 40, 48)       # 100% to 300% display scaling


def ico_file(images: list) -> bytes:
    """A Windows .ico file holding PNG pictures [(size, png bytes)]."""
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, data = b"", b""
    for size, png in images:
        side = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", side, side, 0, 0, 1, 32, len(png), offset + len(data))
        data += png
    return header + entries + data


def make_tray_icons(folder: str) -> dict:
    """Write one .ico per state (a colored disc with the power symbol) and
    return {state: path}."""
    os.makedirs(folder, exist_ok=True)
    paths = {}
    for kind, color in TRAY_COLORS.items():
        images = []
        for n in TRAY_SIZES:
            art = PowerArt(n, n * 0.47, 0.44)
            images.append((n, png_encode(n, n, art.rgba([(disc(n * 0.47), color)], "#ffffff"))))
        path = os.path.join(folder, f"tray-{kind}.ico")
        with open(path, "wb") as f:
            f.write(ico_file(images))
        paths[kind] = path
    return paths


def _tray_api():
    """Windows functions and structures the tray icon needs, with exact
    argument types (handles are 64-bit; guessing them would corrupt them)."""
    from types import SimpleNamespace
    w = wintypes
    LRESULT = ctypes.c_ssize_t
    WNDPROC = ctypes.WINFUNCTYPE(LRESULT, w.HWND, w.UINT, w.WPARAM, w.LPARAM)

    class WNDCLASSW(ctypes.Structure):
        _fields_ = [("style", w.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
                    ("cbWndExtra", ctypes.c_int), ("hInstance", w.HINSTANCE),
                    ("hIcon", w.HICON), ("hCursor", w.HANDLE), ("hbrBackground", w.HBRUSH),
                    ("lpszMenuName", w.LPCWSTR), ("lpszClassName", w.LPCWSTR)]

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", w.DWORD), ("Data2", w.WORD), ("Data3", w.WORD),
                    ("Data4", ctypes.c_ubyte * 8)]

    class NOTIFYICONDATAW(ctypes.Structure):
        _fields_ = [("cbSize", w.DWORD), ("hWnd", w.HWND), ("uID", w.UINT),
                    ("uFlags", w.UINT), ("uCallbackMessage", w.UINT), ("hIcon", w.HICON),
                    ("szTip", w.WCHAR * 128), ("dwState", w.DWORD), ("dwStateMask", w.DWORD),
                    ("szInfo", w.WCHAR * 256), ("uVersion", w.UINT),
                    ("szInfoTitle", w.WCHAR * 64), ("dwInfoFlags", w.DWORD),
                    ("guidItem", GUID), ("hBalloonIcon", w.HICON)]

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    def sig(fn, restype, *argtypes):
        fn.restype, fn.argtypes = restype, list(argtypes)
        return fn

    return SimpleNamespace(
        WNDPROC=WNDPROC, WNDCLASSW=WNDCLASSW, NOTIFYICONDATAW=NOTIFYICONDATAW,
        GetModuleHandleW=sig(kernel32.GetModuleHandleW, w.HMODULE, w.LPCWSTR),
        RegisterClassW=sig(user32.RegisterClassW, w.ATOM, ctypes.POINTER(WNDCLASSW)),
        UnregisterClassW=sig(user32.UnregisterClassW, w.BOOL, w.LPCWSTR, w.HINSTANCE),
        CreateWindowExW=sig(user32.CreateWindowExW, w.HWND, w.DWORD, w.LPCWSTR, w.LPCWSTR,
                            w.DWORD, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                            w.HWND, w.HMENU, w.HINSTANCE, ctypes.c_void_p),
        DestroyWindow=sig(user32.DestroyWindow, w.BOOL, w.HWND),
        DefWindowProcW=sig(user32.DefWindowProcW, LRESULT, w.HWND, w.UINT, w.WPARAM, w.LPARAM),
        RegisterWindowMessageW=sig(user32.RegisterWindowMessageW, w.UINT, w.LPCWSTR),
        GetSystemMetrics=sig(user32.GetSystemMetrics, ctypes.c_int, ctypes.c_int),
        LoadImageW=sig(user32.LoadImageW, w.HANDLE, w.HINSTANCE, w.LPCWSTR, w.UINT,
                       ctypes.c_int, ctypes.c_int, w.UINT),
        DestroyIcon=sig(user32.DestroyIcon, w.BOOL, w.HICON),
        CreatePopupMenu=sig(user32.CreatePopupMenu, w.HMENU),
        AppendMenuW=sig(user32.AppendMenuW, w.BOOL, w.HMENU, w.UINT, ctypes.c_size_t, w.LPCWSTR),
        SetMenuDefaultItem=sig(user32.SetMenuDefaultItem, w.BOOL, w.HMENU, w.UINT, w.UINT),
        TrackPopupMenu=sig(user32.TrackPopupMenu, ctypes.c_int, w.HMENU, w.UINT, ctypes.c_int,
                           ctypes.c_int, ctypes.c_int, w.HWND, ctypes.c_void_p),
        DestroyMenu=sig(user32.DestroyMenu, w.BOOL, w.HMENU),
        GetCursorPos=sig(user32.GetCursorPos, w.BOOL, ctypes.POINTER(w.POINT)),
        SetForegroundWindow=sig(user32.SetForegroundWindow, w.BOOL, w.HWND),
        PostMessageW=sig(user32.PostMessageW, w.BOOL, w.HWND, w.UINT, w.WPARAM, w.LPARAM),
        Shell_NotifyIconW=sig(shell32.Shell_NotifyIconW, w.BOOL, w.DWORD,
                              ctypes.POINTER(NOTIFYICONDATAW)),
    )


class TrayIcon:
    """The icon next to the clock. on_command("open" | "toggle" | "quit") is called
    when it's clicked or a menu item is chosen; menu_state() gives the label of
    the Connect/Disconnect item and whether it can be used."""

    WM_TRAY = 0x8000 + 1             # WM_APP + 1: "something happened to the icon"
    ID_OPEN, ID_TOGGLE, ID_QUIT = 1, 2, 3
    CLASS_NAME = "FreeVPNTrayWindow"

    def __init__(self, on_command, menu_state, log):
        self.on_command, self.menu_state, self.log = on_command, menu_state, log
        self.api = None
        self.hwnd = None
        self.hinstance = None
        self.icons: dict = {}
        self.kind, self.tooltip = "idle", APP_NAME
        self.taskbar_created = 0
        self.added = False
        self._proc = None                 # must stay alive as long as the window exists

    def start(self, icon_files: dict) -> bool:
        try:
            api = self.api = _tray_api()
            self.hinstance = api.GetModuleHandleW(None)
            self._proc = api.WNDPROC(self._window_proc)
            wc = api.WNDCLASSW()
            wc.lpfnWndProc = self._proc
            wc.hInstance = self.hinstance
            wc.lpszClassName = self.CLASS_NAME
            if not api.RegisterClassW(ctypes.byref(wc)) and ctypes.get_last_error() != 1410:
                raise OSError(f"RegisterClass failed ({ctypes.get_last_error()})")
            # A hidden window (never shown) that receives the icon's messages.
            self.hwnd = api.CreateWindowExW(0, self.CLASS_NAME, "Free VPN tray", 0, 0, 0, 0, 0,
                                            None, None, self.hinstance, None)
            if not self.hwnd:
                raise OSError(f"CreateWindow failed ({ctypes.get_last_error()})")
            self.taskbar_created = api.RegisterWindowMessageW("TaskbarCreated")
            size = api.GetSystemMetrics(49) or 16            # SM_CXSMICON
            for kind, path in icon_files.items():
                handle = api.LoadImageW(None, path, 1, size, size, 0x10)   # icon, from file
                if handle:
                    self.icons[kind] = handle
            if "idle" not in self.icons:
                raise OSError(f"couldn't load the tray icon ({ctypes.get_last_error()})")
            if not self._add():
                raise OSError(f"Shell_NotifyIcon failed ({ctypes.get_last_error()})")
            return True
        except Exception as exc:
            self.log(f"Tray icon: not available ({short_error(exc)})")
            self.stop()
            return False

    def _data(self, flags: int):
        nid = self.api.NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(nid)
        nid.hWnd = self.hwnd
        nid.uID = 1
        nid.uFlags = flags
        nid.uCallbackMessage = self.WM_TRAY
        nid.hIcon = self.icons.get(self.kind) or self.icons.get("idle")
        nid.szTip = self.tooltip[:127]
        return nid

    def _add(self) -> bool:
        nid = self._data(0x1 | 0x2 | 0x4)                     # message, icon, tooltip
        self.added = bool(self.api.Shell_NotifyIconW(0, ctypes.byref(nid)))   # NIM_ADD
        return self.added

    def update(self, kind: str, tooltip: str) -> None:
        if not self.added or (kind, tooltip) == (self.kind, self.tooltip):
            return
        self.kind, self.tooltip = kind, tooltip
        try:
            nid = self._data(0x2 | 0x4)
            self.api.Shell_NotifyIconW(1, ctypes.byref(nid))                    # NIM_MODIFY
        except Exception:
            pass

    def notify(self, title: str, text: str, warning: bool = False) -> None:
        """A small pop-up message from the icon (shown as a notification)."""
        if not self.added:
            return
        try:
            nid = self._data(0x10)                                             # NIF_INFO
            nid.szInfoTitle = title[:63]
            nid.szInfo = text[:255]
            nid.dwInfoFlags = (2 if warning else 1) | 0x10       # warning/info, no sound
            self.api.Shell_NotifyIconW(1, ctypes.byref(nid))
        except Exception:
            pass

    def stop(self) -> None:
        api = self.api
        if api is None:
            return
        try:
            if self.added:
                self.api.Shell_NotifyIconW(2, ctypes.byref(self._data(0)))    # NIM_DELETE
            self.added = False
            for handle in self.icons.values():
                api.DestroyIcon(handle)
            self.icons.clear()
            if self.hwnd:
                api.DestroyWindow(self.hwnd)
                self.hwnd = None
            if self.hinstance is not None:
                api.UnregisterClassW(self.CLASS_NAME, self.hinstance)
        except Exception:
            pass

    def _window_proc(self, hwnd, message, wparam, lparam):
        try:
            if message == self.WM_TRAY:
                event = lparam & 0xFFFF
                if event in (0x0202, 0x0203):        # left button up, double-click
                    self.on_command("open")
                elif event in (0x0205, 0x007B):      # right button up, context menu
                    self._show_menu()
                return 0
            if message == self.taskbar_created and self.taskbar_created:
                self._add()                          # Explorer restarted: put the icon back
                return 0
        except Exception:
            pass                                     # never let an error reach Windows
        return self.api.DefWindowProcW(hwnd, message, wparam, lparam)

    def _show_menu(self) -> None:
        api = self.api
        label, enabled = self.menu_state()
        menu = api.CreatePopupMenu()
        if not menu:
            return
        try:
            api.AppendMenuW(menu, 0, self.ID_OPEN, "Open Free VPN")
            api.AppendMenuW(menu, 0 if enabled else 0x1, self.ID_TOGGLE, label)  # 0x1: greyed
            api.AppendMenuW(menu, 0x800, 0, None)                                 # separator
            api.AppendMenuW(menu, 0, self.ID_QUIT, "Quit Free VPN")
            api.SetMenuDefaultItem(menu, self.ID_OPEN, 0)
            point = wintypes.POINT()
            api.GetCursorPos(ctypes.byref(point))
            api.SetForegroundWindow(self.hwnd)       # so the menu closes when you click away
            chosen = api.TrackPopupMenu(menu, 0x100 | 0x2 | 0x80, point.x, point.y, 0,
                                        self.hwnd, None)   # return the choice, right button
            api.PostMessageW(self.hwnd, 0, 0, 0)
        finally:
            api.DestroyMenu(menu)
        command = {self.ID_OPEN: "open", self.ID_TOGGLE: "toggle",
                   self.ID_QUIT: "quit"}.get(chosen)
        if command:
            self.on_command(command)


# --------------------------------------------------------------------------
# Look and feel: colors, fonts and widget styles for the light and dark themes
# --------------------------------------------------------------------------

THEMES = {
    "light": {
        "bg": "#eef1f6", "surface": "#ffffff", "surface2": "#f3f5f9", "surface3": "#e7ebf1",
        "border": "#dfe4ec", "border_strong": "#c3cbd8",
        "text": "#17202c", "muted": "#5c6878", "disabled": "#a3acb9",
        "accent": "#2463eb", "accent_hover": "#3b76f2", "accent_press": "#1c50c7",
        "on_accent": "#ffffff",
        "green": "#1aa550", "green_hover": "#1fb65a", "green_text": "#15803d",
        "amber": "#e09112", "amber_text": "#b45309",
        "red": "#dc3545", "red_text": "#c62838", "red_tint": "#fdecee",
        "sel_bg": "#dbe7fe", "sel_fg": "#10203c", "stripe": "#f8fafc", "seg_on": "#ffffff",
        "banner_bg": "#fff5d6", "banner_fg": "#5a4300", "banner_border": "#f1dc9d",
        "info_bg": "#e8f0fe", "info_fg": "#173a78", "info_border": "#c3d6fb",
        "shadow": 0.16,
    },
    "dark": {
        "bg": "#0e1217", "surface": "#171c24", "surface2": "#1f2630", "surface3": "#28313d",
        "border": "#2b3441", "border_strong": "#3d4857",
        "text": "#e8ecf2", "muted": "#93a0b1", "disabled": "#5b6675",
        "accent": "#4f8ff7", "accent_hover": "#6ba2fa", "accent_press": "#3d7be0",
        "on_accent": "#ffffff",
        "green": "#28b467", "green_hover": "#31c574", "green_text": "#3fd07f",
        "amber": "#f0a732", "amber_text": "#f0a732",
        "red": "#ef5a67", "red_text": "#ff7a85", "red_tint": "#3a1f25",
        "sel_bg": "#243a5e", "sel_fg": "#ffffff", "stripe": "#1a2029", "seg_on": "#36414f",
        "banner_bg": "#33290f", "banner_fg": "#f3d48a", "banner_border": "#57461a",
        "info_bg": "#172741", "info_fg": "#b8cdf5", "info_border": "#2a426b",
        "shadow": 0.0,
    },
}


def system_prefers_dark() -> bool:
    """True if Windows is set to dark mode for apps."""
    if not IS_WINDOWS:
        return False
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as key:
            return winreg.QueryValueEx(key, "AppsUseLightTheme")[0] == 0
    except (OSError, ImportError):
        return False


def set_dark_title_bar(root: tk.Tk, dark: bool) -> None:
    """Windows 10/11: make the window's title bar match the theme."""
    if not IS_WINDOWS:
        return
    try:
        root.update_idletasks()
        user32, dwmapi = ctypes.windll.user32, ctypes.windll.dwmapi
        user32.GetParent.restype = wintypes.HWND
        user32.GetParent.argtypes = [wintypes.HWND]
        dwmapi.DwmSetWindowAttribute.argtypes = [wintypes.HWND, wintypes.DWORD,
                                                 ctypes.c_void_p, wintypes.DWORD]
        hwnd = user32.GetParent(root.winfo_id())
        value = ctypes.c_int(1 if dark else 0)
        for attribute in (20, 19):   # DWMWA_USE_IMMERSIVE_DARK_MODE (new, old)
            if dwmapi.DwmSetWindowAttribute(hwnd, attribute, ctypes.byref(value),
                                            ctypes.sizeof(value)) == 0:
                break
    except Exception:
        pass


class Skin:
    """Fonts, generated images and ttk styles. Sizes are in "design pixels" and
    go through px() so the app looks right on high-DPI (125%, 150%...) screens."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.scale = max(1.0, float(root.winfo_fpixels("1i")) / 96.0)
        self.style = ttk.Style(root)
        self.style.theme_use("clam")
        self.images: dict = {}        # keeps the generated images alive
        self._made: set[str] = set()  # themes whose images already exist
        self.name = ""
        self.c = THEMES["light"]
        self.card_margin = self.px(6)  # transparent rim around cards (holds the shadow)
        self._make_fonts()
        # Don't leave a focus ring stuck on a button after it's clicked with the
        # mouse; keyboard users still get one when they Tab to it.
        for cls in ("TButton", "TCheckbutton"):
            root.bind_class(cls, "<ButtonRelease-1>", self._drop_focus, add="+")

    def _drop_focus(self, event) -> None:
        try:
            if event.widget.winfo_exists():
                event.widget.winfo_toplevel().focus_set()
        except (tk.TclError, AttributeError):
            pass

    def px(self, n: float) -> int:
        return int(round(n * self.scale))

    def _make_fonts(self) -> None:
        root = self.root
        # Font names, ignoring case (some systems list them in lowercase).
        have = {name.lower(): name for name in tkfont.families(root)}

        def first(*names):
            return next((have[n.lower()] for n in names if n.lower() in have), None)

        default = tkfont.nametofont("TkDefaultFont")
        base = (first("Segoe UI", "Inter", "Helvetica Neue", "Noto Sans", "DejaVu Sans")
                or default.actual("family"))
        semibold = first("Segoe UI Semibold")
        mono = first("Cascadia Mono", "Consolas", "DejaVu Sans Mono", "Liberation Mono") or "Courier"
        for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
            try:
                tkfont.nametofont(name).configure(family=base, size=10)
            except tk.TclError:
                pass

        def make(size, strong=False):
            if strong and semibold:
                return tkfont.Font(root=root, family=semibold, size=size)
            return tkfont.Font(root=root, family=base, size=size,
                               weight="bold" if strong else "normal")

        self.f_base = make(10)
        self.f_small = make(9)
        self.f_strong = make(10, True)
        self.f_small_strong = make(9, True)
        self.f_key = make(8, True)
        self.f_brand = make(12, True)
        self.f_title = make(16, True)
        self.f_mono = tkfont.Font(root=root, family=mono, size=9)

    # ---- generated image elements -------------------------------------------

    def _element(self, name: str, default, *states, **options) -> None:
        """Register an image as a ttk element, with other images for states such
        as ("active", image) or ("disabled", "selected", image)."""
        spec = [str(default)]
        for *state, image in states:
            spec += [" ".join(state), str(image)]
        args = []
        for key, value in options.items():
            args += ["-" + key, value]
        self.root.tk.call("ttk::style", "element", "create", name, "image", spec, *args)

    def _make_elements(self, T: str, c: dict) -> None:
        px = self.px
        line = float(max(1, round(self.scale)))   # border thickness

        def keep(key, pixmap):
            image = pixmap.photo(self.root)
            self.images[T, key] = image
            return image

        def panel(key, radius, fill, border=None, margin=0, shadow=0.0, middle=48):
            """A rounded panel picture: drawn small, then given a wide flat
            middle (see Pixmap.stretched) so Tk can stretch it cheaply."""
            size = 2 * (radius + margin) + 2
            small = panel_pixmap(size, size, radius, fill, border, line, margin, shadow)
            return keep(key, small.stretched(px(middle), px(middle)))

        # The two big rounded cards (with a soft shadow in the light theme)
        r, m = px(12), self.card_margin
        card = panel("card", r, c["surface"], c["border"], margin=m, shadow=c["shadow"],
                     middle=240)
        least = 2 * (r + m) + 2   # smallest size Tk may squeeze the picture to
        self._element(f"{T}.Card.bg", card, border=r + m + 1, padding=0, sticky="nsew",
                      width=least, height=least)

        # Recessed panels and the yellow "install OpenVPN" banner
        r = px(10)
        nine = dict(border=r + 1, padding=0, sticky="nsew", width=2 * r + 2, height=2 * r + 2)
        self._element(f"{T}.Inset.bg", panel("inset", r, c["surface2"], middle=160), **nine)
        self._element(f"{T}.Banner.bg",
                      panel("banner", r, c["banner_bg"], c["banner_border"], middle=160),
                      **nine)
        self._element(f"{T}.Info.bg",
                      panel("info", r, c["info_bg"], c["info_border"], middle=160), **nine)

        # Buttons and the country box
        r = px(8)
        size = 2 * r + 2 + px(48)
        nine = dict(border=r + 1, padding=0, sticky="nsew", width=2 * r + 2, height=2 * r + 2)

        def box(key, fill, border=None):
            return panel(key, r, fill, border)

        self._element(f"{T}.Btn.bg", box("btn", c["surface2"], c["border"]),
                      ("disabled", box("btn_d", c["surface"], c["border"])),
                      ("pressed", box("btn_p", c["surface3"], c["border_strong"])),
                      ("active", box("btn_a", c["surface3"], c["border_strong"])),
                      ("focus", box("btn_f", c["surface2"], c["accent"])), **nine)
        self._element(f"{T}.Primary.bg", box("pri", c["accent"]),
                      ("disabled", box("pri_d", c["surface3"])),
                      ("pressed", box("pri_p", c["accent_press"])),
                      ("active", box("pri_a", c["accent_hover"])),
                      ("focus", box("pri_f", c["accent"], mix(c["accent"], "#ffffff", 0.6))),
                      **nine)
        self._element(f"{T}.Danger.bg",
                      box("dng", c["surface"], mix(c["red"], c["surface"], 0.5)),
                      ("pressed", box("dng_p", c["red_tint"], c["red"])),
                      ("active", box("dng_a", c["red_tint"], c["red"])),
                      ("focus", box("dng_f", c["surface"], c["red"])), **nine)
        self._element(f"{T}.Ghost.bg", keep("ghost", Pixmap(size, size)),
                      ("pressed", box("ghost_p", c["surface3"])),
                      ("active", box("ghost_a", c["surface2"])), **nine)
        self._element(f"{T}.Tab.bg", box("tab", c["surface3"]), **nine)
        # The two-way "Everything / Discord only" switch
        self._element(f"{T}.SegOn.bg", box("seg_on", c["seg_on"], c["border_strong"]), **nine)
        self._element(f"{T}.SegOff.bg", keep("seg_off", Pixmap(size, size)),
                      ("pressed", box("seg_off_p", c["surface3"])),
                      ("active", box("seg_off_a", c["surface3"])), **nine)
        self._element(f"{T}.Field.bg", box("field", c["surface2"], c["border"]),
                      ("focus", box("field_f", c["surface2"], c["accent"])),
                      ("active", box("field_a", c["surface2"], c["border_strong"])), **nine)
        self._element(f"{T}.Combo.arrow",
                      keep("chevron", chevron_pixmap(px(30), px(14), c["muted"],
                                                     max(1.5, 1.6 * self.scale))), sticky="")

        # On/off switches
        w, h = px(36), px(20)
        off = keep("sw_off", switch_pixmap(w, h, c["border_strong"], "#ffffff", False))
        on = keep("sw_on", switch_pixmap(w, h, c["accent"], "#ffffff", True))
        off_d = keep("sw_off_d", switch_pixmap(w, h, c["surface3"], c["disabled"], False))
        on_d = keep("sw_on_d", switch_pixmap(w, h, mix(c["accent"], c["surface"], 0.6),
                                             mix("#ffffff", c["surface"], 0.35), True))
        self._element(f"{T}.Switch.ind", off, ("disabled", "selected", on_d),
                      ("disabled", off_d), ("selected", on), sticky="")

        # Slim scrollbars: one for the white card, one for recessed panels
        tw = px(14)
        for key, color in (("trough", c["surface"]), ("trough2", c["surface2"])):
            trough = Pixmap(tw, px(64))
            trough.fill(lambda x, y: -1.0, color)
            self._element(f"{T}.Scroll.{key}", keep(key, trough), border=0,
                          padding=(px(4), px(2)), sticky="ns", height=px(8))
        r = px(3)

        def thumb(key, color):
            small = panel_pixmap(2 * r + 2, 2 * r + 2, r, color)
            return keep(key, small.stretched(0, px(40)))
        self._element(f"{T}.Scroll.thumb", thumb("thumb", c["border_strong"]),
                      ("pressed", thumb("thumb_p", c["muted"])),
                      ("active", thumb("thumb_a", c["muted"])),
                      border=r, padding=0, sticky="nsew", width=2 * r, height=px(28))

    # ---- styles ---------------------------------------------------------------

    def apply(self, name: str) -> None:
        """Switch every ttk widget to the light or dark theme."""
        self.name = T = name
        c = self.c = THEMES[name]
        if T not in self._made:
            self._make_elements(T, c)
            self._made.add(T)
        px, st = self.px, self.style
        self.root.configure(background=c["bg"])

        st.configure(".", background=c["surface"], foreground=c["text"], font=self.f_base,
                     bordercolor=c["border"], lightcolor=c["surface"], darkcolor=c["surface"],
                     troughcolor=c["surface"], fieldbackground=c["surface2"],
                     selectbackground=c["sel_bg"], selectforeground=c["sel_fg"],
                     insertcolor=c["text"], focuscolor=c["accent"])
        st.map(".", background=[], foreground=[("disabled", c["disabled"])],
               selectbackground=[], selectforeground=[], bordercolor=[],
               lightcolor=[], darkcolor=[])

        # Frames
        def rounded(element):
            return [("Panel.background", {"sticky": "nsew"}), (element, {"sticky": "nsew"})]
        st.configure("TFrame", background=c["surface"])
        st.configure("Window.TFrame", background=c["bg"])
        st.layout("Card.TFrame", rounded(f"{T}.Card.bg"))
        st.configure("Card.TFrame", background=c["bg"])
        st.layout("Inset.TFrame", rounded(f"{T}.Inset.bg"))
        st.configure("Inset.TFrame", background=c["surface"])
        st.layout("Banner.TFrame", rounded(f"{T}.Banner.bg"))
        st.configure("Banner.TFrame", background=c["surface"])
        st.configure("BannerFill.TFrame", background=c["banner_bg"])
        st.layout("Info.TFrame", rounded(f"{T}.Info.bg"))
        st.configure("Info.TFrame", background=c["surface"])
        st.configure("InfoFill.TFrame", background=c["info_bg"])

        # Text
        st.configure("TLabel", background=c["surface"], foreground=c["text"], font=self.f_base)
        st.configure("Muted.TLabel", foreground=c["muted"], font=self.f_small)
        st.configure("Title.TLabel", font=self.f_title)
        st.configure("Brand.TLabel", font=self.f_brand)
        st.configure("Key.TLabel", foreground=c["muted"], font=self.f_key)
        st.configure("Link.TLabel", foreground=c["accent"], font=self.f_small)
        for style, color in (("InsetKey", c["muted"]), ("InsetValue", c["text"]),
                             ("InsetGood", c["green_text"]), ("InsetWarn", c["amber_text"])):
            st.configure(f"{style}.TLabel", background=c["surface2"], foreground=color,
                         font=self.f_small if style == "InsetKey" else self.f_small_strong)
        st.configure("Banner.TLabel", background=c["banner_bg"], foreground=c["banner_fg"],
                     font=self.f_small)
        st.configure("BannerTitle.TLabel", background=c["banner_bg"],
                     foreground=c["banner_fg"], font=self.f_strong)
        st.configure("Info.TLabel", background=c["info_bg"], foreground=c["info_fg"],
                     font=self.f_small)
        st.configure("InfoTitle.TLabel", background=c["info_bg"], foreground=c["info_fg"],
                     font=self.f_strong)

        # Buttons
        def button(element):
            return [("Button.background", {"sticky": "nsew"}),
                    (element, {"sticky": "nsew", "children": [
                        ("Button.padding", {"sticky": "nsew", "children": [
                            ("Button.label", {"sticky": "nsew"})]})]})]
        big, normal, small = (px(14), px(9)), (px(14), px(7)), (px(10), px(4))
        st.layout("TButton", button(f"{T}.Btn.bg"))
        st.configure("TButton", background=c["surface"], foreground=c["text"],
                     font=self.f_base, padding=normal, anchor="center", width=-6,
                     relief="flat", borderwidth=0)
        st.map("TButton", background=[], foreground=[("disabled", c["disabled"])],
               bordercolor=[], lightcolor=[], darkcolor=[])
        st.layout("Action.TButton", button(f"{T}.Btn.bg"))
        st.configure("Action.TButton", font=self.f_strong, padding=big)
        st.layout("Primary.TButton", button(f"{T}.Primary.bg"))
        st.configure("Primary.TButton", foreground=c["on_accent"], font=self.f_strong,
                     padding=big)
        st.layout("Danger.TButton", button(f"{T}.Danger.bg"))
        st.configure("Danger.TButton", foreground=c["red_text"], font=self.f_strong,
                     padding=big)
        st.layout("Banner.TButton", button(f"{T}.Btn.bg"))
        st.configure("Banner.TButton", background=c["banner_bg"])
        st.layout("Info.TButton", button(f"{T}.Btn.bg"))
        st.configure("Info.TButton", background=c["info_bg"])
        st.layout("InfoPrimary.TButton", button(f"{T}.Primary.bg"))
        st.configure("InfoPrimary.TButton", background=c["info_bg"], foreground=c["on_accent"],
                     font=self.f_strong)
        st.layout("Ghost.TButton", button(f"{T}.Ghost.bg"))
        st.configure("Ghost.TButton", foreground=c["muted"], font=self.f_small, padding=small)
        st.layout("Tab.TButton", button(f"{T}.Ghost.bg"))
        st.configure("Tab.TButton", foreground=c["muted"], font=self.f_strong,
                     padding=(px(14), px(6)))
        st.layout("TabOn.TButton", button(f"{T}.Tab.bg"))
        st.configure("TabOn.TButton", foreground=c["text"], font=self.f_strong,
                     padding=(px(14), px(6)))
        for style, element, color in (("Seg", "SegOff", c["muted"]), ("SegOn", "SegOn", c["text"])):
            st.layout(f"{style}.TButton", button(f"{T}.{element}.bg"))
            st.configure(f"{style}.TButton", background=c["surface2"], foreground=color,
                         font=self.f_small_strong, padding=(px(6), px(5)), width=0)
        # Buttons in the "close?" dialog: colored like the big ones, normal height
        st.layout("SmallPrimary.TButton", button(f"{T}.Primary.bg"))
        st.configure("SmallPrimary.TButton", foreground=c["on_accent"], font=self.f_strong)
        st.layout("SmallDanger.TButton", button(f"{T}.Danger.bg"))
        st.configure("SmallDanger.TButton", foreground=c["red_text"], font=self.f_strong)

        # On/off switches (ttk checkbuttons with a different picture)
        st.layout("Switch.TCheckbutton", [
            ("Checkbutton.background", {"sticky": "nsew"}),
            ("Checkbutton.padding", {"sticky": "nsew", "children": [
                (f"{T}.Switch.ind", {"side": "right", "sticky": ""}),
                ("Checkbutton.label", {"side": "left", "sticky": "w"})]})])
        st.configure("Switch.TCheckbutton", background=c["surface"], foreground=c["text"],
                     font=self.f_small, padding=(0, px(4)))
        st.map("Switch.TCheckbutton", background=[],
               foreground=[("disabled", c["disabled"])])
        st.configure("Setting.Switch.TCheckbutton", font=self.f_strong)
        st.configure("Strong.TLabel", font=self.f_strong)

        # Country box
        st.layout("TCombobox", [
            ("Combobox.background", {"sticky": "nsew"}),
            (f"{T}.Field.bg", {"sticky": "nsew", "children": [
                (f"{T}.Combo.arrow", {"side": "right", "sticky": ""}),
                ("Combobox.padding", {"expand": "1", "sticky": "nsew", "children": [
                    ("Combobox.textarea", {"sticky": "nsew"})]})]})])
        st.configure("TCombobox", background=c["surface"], foreground=c["text"],
                     fieldbackground=c["surface2"], selectbackground=c["surface2"],
                     selectforeground=c["text"], padding=(px(10), px(7), px(2), px(7)))
        st.map("TCombobox", background=[], fieldbackground=[], bordercolor=[],
               foreground=[("disabled", c["disabled"])], arrowcolor=[],
               selectbackground=[], selectforeground=[])
        st.configure("ComboboxPopdownFrame", background=c["surface2"],
                     bordercolor=c["border_strong"], lightcolor=c["surface2"],
                     darkcolor=c["surface2"], relief="solid", borderwidth=1)
        for option, value in (("background", c["surface2"]), ("foreground", c["text"]),
                              ("selectBackground", c["sel_bg"]),
                              ("selectForeground", c["sel_fg"]), ("font", self.f_base)):
            self.root.option_add("*TCombobox*Listbox." + option, value)

        # Server table
        row_height = self.f_base.metrics("linespace") + px(14)
        st.configure("Treeview", background=c["surface"], fieldbackground=c["surface"],
                     foreground=c["text"], font=self.f_base, rowheight=row_height,
                     borderwidth=0, relief="flat", bordercolor=c["surface"],
                     lightcolor=c["surface"], darkcolor=c["surface"])
        st.map("Treeview", background=[("selected", c["sel_bg"])],
               foreground=[("selected", c["sel_fg"])], bordercolor=[],
               lightcolor=[], darkcolor=[])
        # Tk 8.6 insets cell text by 4 pixels on its own; Tk 9 doesn't. Allow for
        # that so the headings line up with the text under them on both.
        builtin_inset = 4 if tk.TkVersion < 9 else 0
        st.configure("Treeview.Cell", padding=(px(8) - builtin_inset, 0))
        st.configure("Treeview.Heading", background=c["surface"], foreground=c["muted"],
                     font=self.f_small_strong, relief="flat", borderwidth=0,
                     padding=(px(8), px(8)), bordercolor=c["surface"],
                     lightcolor=c["surface"], darkcolor=c["surface"])
        st.map("Treeview.Heading", background=[("active", c["surface2"])],
               foreground=[("active", c["text"])])

        # Scrollbars. The "Off" versions keep the space but draw no handle; they
        # are used while everything fits and there is nothing to scroll.
        for style, trough in (("Vertical.TScrollbar", "trough"),
                              ("Inset.Vertical.TScrollbar", "trough2")):
            st.layout(style, [(f"{T}.Scroll.{trough}", {"sticky": "ns", "children": [
                (f"{T}.Scroll.thumb", {"expand": "1", "sticky": "nsew"})]})])
            st.map(style, background=[])
            st.layout("Off." + style, [(f"{T}.Scroll.{trough}", {"sticky": "ns"})])
            st.map("Off." + style, background=[])

    def style_dropdown(self, combobox: ttk.Combobox) -> None:
        """The country box's drop-down list is an old-style Tk listbox; recolor
        it by hand so it matches the theme."""
        c = self.c
        try:
            popdown = self.root.tk.call("ttk::combobox::PopdownWindow", combobox)
            self.root.tk.call(f"{popdown}.f.l", "configure",
                              "-background", c["surface2"], "-foreground", c["text"],
                              "-selectbackground", c["sel_bg"],
                              "-selectforeground", c["sel_fg"], "-font", self.f_base,
                              "-borderwidth", self.px(6), "-relief", "flat",
                              "-highlightthickness", 0, "-activestyle", "none")
        except tk.TclError:
            pass


class PowerButton(tk.Canvas):
    """The big round on/off button, with a spinner while connecting."""

    DOTS = 10

    def __init__(self, parent, skin: Skin, command):
        px = skin.px
        self.radius = px(50)
        self.spread = px(20)
        size = 2 * (self.radius + self.spread + px(4))
        super().__init__(parent, width=size, height=size, highlightthickness=0, bd=0)
        self.skin = skin
        self.command = command
        self.center = size / 2
        self.art = PowerArt(size, self.radius)
        self.c: dict = {}
        self.cache: dict = {}
        self.kind = "idle"        # idle, busy, on or error
        self.enabled = True
        self.hover = False
        self.item = self.create_image(self.center, self.center)
        self.dot_images: list = []
        self.dot_items = [self.create_image(0, 0, state="hidden") for _ in range(self.DOTS)]
        self.angle = 0.0
        self.spin_job = None
        self.bind("<Button-1>", self._click)
        self.bind("<Motion>", self._motion)
        self.bind("<Leave>", lambda e: self._set_hover(False))

    def set_palette(self, c: dict) -> None:
        self.c = c
        self.cache.clear()
        self.configure(background=c["surface"])
        d = self.skin.px(7)
        self.dot_images = []
        for k in range(self.DOTS):
            pm = Pixmap(d + 2, d + 2)
            shrink = 1.0 - 0.45 * k / (self.DOTS - 1)
            pm.fill(sdf_circle((d + 2) / 2, (d + 2) / 2, d / 2 * shrink), c["amber"],
                    alpha=1.0 - 0.85 * k / (self.DOTS - 1))
            self.dot_images.append(pm.photo(self))
        for item, image in zip(self.dot_items, self.dot_images):
            self.itemconfigure(item, image=image)
        self._redraw()

    def set_kind(self, kind: str, enabled: bool = True) -> None:
        self.kind, self.enabled = kind, enabled
        self._redraw()
        if kind == "busy":
            for item in self.dot_items:
                self.itemconfigure(item, state="normal")
            if self.spin_job is None:
                self._spin()
        else:
            for item in self.dot_items:
                self.itemconfigure(item, state="hidden")
            if self.spin_job is not None:
                self.after_cancel(self.spin_job)
                self.spin_job = None

    def _redraw(self) -> None:
        if not self.c:
            return
        key = (self.kind, self.hover and self.enabled)
        if key not in self.cache:
            self.cache[key] = self._render(*key)
        self.itemconfigure(self.item, image=self.cache[key])

    def _render(self, kind: str, hover: bool) -> tk.PhotoImage:
        c, R = self.c, self.radius
        ring = max(1.5, 2.0 * self.skin.scale)
        if kind == "on":
            layers = [(glow(R, self.spread, 0.42), c["green"]),
                      (disc(R), c["green_hover"] if hover else c["green"])]
            icon = c["on_accent"]
        else:
            edge = {"idle": c["accent"] if hover else c["border_strong"],
                    "busy": c["border_strong"], "error": c["red"]}[kind]
            icon = {"idle": c["accent"] if hover else c["muted"],
                    "busy": c["amber"], "error": c["red"]}[kind]
            layers = []
            if kind == "error":
                layers.append((glow(R, self.spread, 0.22), c["red"]))
            elif c["shadow"]:
                layers.append((glow(R, self.spread * 0.6, c["shadow"]), "#0b1220"))
            layers += [(disc(R), edge),
                       (disc(R - ring), c["surface3"] if hover else c["surface2"])]
        return self.art.render(self, layers, icon)

    def _spin(self) -> None:
        self.angle = (self.angle + 9.0) % 360.0
        orbit = self.radius + self.skin.px(11)
        for k, item in enumerate(self.dot_items):
            a = math.radians(self.angle - k * 13.0)
            self.coords(item, self.center + orbit * math.sin(a),
                        self.center - orbit * math.cos(a))
        self.spin_job = self.after(40, self._spin)

    def _inside(self, event) -> bool:
        return math.hypot(event.x - self.center, event.y - self.center) <= self.radius + 3

    def _motion(self, event) -> None:
        self._set_hover(self._inside(event))

    def _set_hover(self, hover: bool) -> None:
        if hover != self.hover:
            self.hover = hover
            self.configure(cursor="hand2" if hover and self.enabled else "")
            self._redraw()

    def _click(self, event) -> None:
        if self.enabled and self._inside(event):
            self.command()


# --------------------------------------------------------------------------
# Window
# --------------------------------------------------------------------------

def fmt_speed(bps: int) -> str:
    mbps = bps / 1_000_000
    return f"{mbps:.0f} Mbps" if mbps >= 10 else f"{mbps:.1f} Mbps"


def fmt_uptime(ms: int) -> str:
    minutes = ms // 60000
    if minutes >= 1440:
        days = minutes // 1440
        return f"{days} day" + ("s" if days != 1 else "")
    if minutes >= 60:
        return f"{minutes // 60} h"
    return f"{minutes} min"


def fmt_ping(ping: int | None) -> str:
    return "—" if ping is None else f"{ping} ms"


SORT_KEYS = {
    "country": (lambda s: (s.country.lower(), -s.score), False),
    "host": (lambda s: s.host.lower(), False),
    "proto": (lambda s: (s.proto, -s.score), False),
    "ping": (lambda s: s.ping if s.ping is not None else 10 ** 9, False),
    "speed": (lambda s: s.speed_bps, True),
    "users": (lambda s: s.sessions, False),
    "uptime": (lambda s: s.uptime_ms, True),
}

COLUMNS = [
    # key, heading, width, anchor
    ("country", "Country", 104, "w"),     # these two grow to fill the space
    ("host", "Server", 114, "w"),
    ("proto", "Type", 58, "center"),
    ("ping", "Ping", 70, "e"),
    ("speed", "Speed", 94, "e"),
    ("users", "Users", 86, "e"),
    ("uptime", "Online for", 84, "e"),
]


# Typical widest values, used to size the columns (see App.set_theme).
COLUMN_SAMPLES = {"country": "United Kingdom", "host": "\u2605 public-vpn-000",
                  "proto": "UDP", "ping": "999 ms", "speed": "9999 Mbps", "users": "9999",
                  "uptime": "99 days"}


def auto_scrollbar(scrollbar: ttk.Scrollbar, style: str):
    """A scroll callback that hides the scrollbar's handle while everything
    fits, without changing the layout."""
    def update(first, last):
        fits = float(first) <= 0.0 and float(last) >= 1.0
        wanted = ("Off." if fits else "") + style
        if str(scrollbar.cget("style")) != wanted:
            scrollbar.configure(style=wanted)
        scrollbar.set(first, last)
    return update


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.settings = load_settings()
        self.skin = Skin(root)
        self.events: queue.Queue = queue.Queue()
        self.servers: list[Server] = []
        self.filtered: list[Server] = []   # servers in the chosen country, best first
        self.visible: list[Server] = []    # same, in the table's sort order
        self.country_labels: dict[str, str] = {}
        self.sort_col: str | None = None
        self.sort_reverse = False
        self.hover_row: str | None = None
        self.tab = "servers"
        self.conn: VpnConnection | None = None
        self.state = "idle"
        self.session = 0                   # bumps whenever the user starts/stops
        self.candidates: list[Server] = []
        self.attempt_no = 0
        self.attempt_started = 0.0
        self.connected_at = 0.0
        self._pending_stops = 0            # old openvpn processes still closing
        self.mode = self.settings.get("mode", "all")   # "all" or "discord"
        if self.mode not in ("all", "discord") or not SPLIT_SUPPORTED:
            self.mode = "all"
        self.setting_up = False            # Discord-only mode is being switched on
        self.auto_connect_pending = bool(self.settings.get("auto_connect"))
        # Reconnecting by itself: "keep_trying" is on once a connection has worked
        # (or auto-connect started one) and off again when the user disconnects.
        self.keep_trying = False
        self.automatic = False             # the current attempts were started by the app
        self.last_server: Server | None = None
        self.reconnect_round = 0
        self.reconnect_job = None
        self.reconnect_at = 0.0
        self._list_retries = 0
        self._autostart_wanted = False
        self._show_server: socket.socket | None = None
        self.tray: TrayIcon | None = None
        self.started_at_sign_in = AUTOSTART_ARG in sys.argv[1:]
        self.update: dict | None = None     # a newer version GitHub told us about
        self.update_busy = False
        self.update_job = None
        self.resuming = RESUME_ARG in sys.argv[1:]   # restarted by an update while connected
        if self.resuming:
            self.auto_connect_pending = True
        self._close_dialog: tk.Toplevel | None = None
        self._close_buttons: dict = {}
        self._closing = False
        self._close_deadline = 0.0
        self.original_ip: str | None = None
        self.openvpn = find_openvpn(self.settings.get("openvpn_path", ""))

        self._build_ui()
        theme = self.settings.get("theme")
        if theme not in THEMES:
            theme = "dark" if system_prefers_dark() else "light"
        self.set_theme(theme)
        self._set_state("idle", "Not connected", "Loading the list of free servers…")
        self._update_openvpn_banner()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(100, self._poll)
        self.root.after(1000, self._tick)
        self.refresh_servers()
        self._check_ip(initial=True)
        if SPLIT_SUPPORTED and self.settings.get("split_dirty"):
            # Free VPN was killed (or the PC lost power) while Discord-only mode
            # was on. Take its DNS rule out again, or Discord can't be looked up.
            self._run_in_background(remove_discord_dns_rule, "tidied")
        if IS_WINDOWS and self.settings.get("autostart"):
            # Keep the sign-in task pointing at this copy, in case the folder was
            # moved or Python was updated since it was made.
            self._run_in_background(lambda: set_autostart(True), "autostart_refresh")
        self._start_show_listener()
        self._start_tray()
        if UPDATED_ARG in sys.argv[1:]:
            self._log(f"Updated to version {APP_VERSION}")
            self._show_update(f"Free VPN was updated to version {APP_VERSION}",
                              "\u201cWhat's new\u201d shows what changed.", busy=False,
                              offer=False)
        self.update_job = self.root.after(UPDATE_FIRST_CHECK_MS, self._auto_check_update)

    # ---- layout -----------------------------------------------------------

    def _build_ui(self) -> None:
        root, sk = self.root, self.skin
        px = sk.px
        root.title(APP_NAME)
        width = min(px(1100), root.winfo_screenwidth() - px(40))
        height = min(px(620), root.winfo_screenheight() - px(110))
        root.geometry(f"{width}x{height}")
        root.minsize(min(px(1060), width), min(px(580), height))

        def logo(n):   # the app's icon: a blue disc with the power symbol
            return PowerArt(n, n * 0.48, 0.42).render(
                root, [(disc(n * 0.48), THEMES["light"]["accent"])], "#ffffff")
        sk.images["icons"] = [logo(n) for n in (64, 32, 16)]
        sk.images["logo"] = logo(px(22))
        try:
            root.iconphoto(True, *sk.images["icons"])
        except tk.TclError:
            pass

        outer = ttk.Frame(root, style="Window.TFrame", padding=px(8))
        outer.pack(fill="both", expand=True)
        rim = sk.card_margin              # the cards' shadow lives in this rim
        pad = rim + px(16)

        # ---------------- left: status and controls ----------------
        side = ttk.Frame(outer, style="Card.TFrame", padding=pad, width=px(300) + 2 * rim)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        inner_width = px(300) - 2 * px(16)

        top = ttk.Frame(side)
        top.pack(fill="x")
        ttk.Label(top, image=sk.images["logo"]).pack(side="left", padx=(0, px(8)))
        ttk.Label(top, text=APP_NAME, style="Brand.TLabel").pack(side="left")
        self.theme_btn = ttk.Button(top, style="Ghost.TButton", takefocus=False,
                                    command=self.toggle_theme)
        self.theme_btn.pack(side="right")

        self.power = PowerButton(side, sk, self.primary_action)
        self.power.pack(pady=(px(2), 0))
        self.status_var = tk.StringVar()
        ttk.Label(side, textvariable=self.status_var, style="Title.TLabel",
                  anchor="center").pack(fill="x")
        detail_box = ttk.Frame(side, height=3 * sk.f_small.metrics("linespace") + px(2))
        detail_box.pack(fill="x", pady=(px(2), px(10)))
        detail_box.pack_propagate(False)
        self.detail_var = tk.StringVar()
        ttk.Label(detail_box, textvariable=self.detail_var, style="Muted.TLabel", anchor="n",
                  justify="center", wraplength=inner_width - px(10)
                  ).pack(fill="both", expand=True)

        ttk.Label(side, text="USE THE VPN FOR", style="Key.TLabel").pack(anchor="w")
        modes = ttk.Frame(side, style="Inset.TFrame", padding=px(3))
        modes.pack(fill="x", pady=(px(4), px(10)))
        self.mode_buttons = {}
        for column, (key, text) in enumerate((("all", "Everything"), ("discord", "Discord only"))):
            button = ttk.Button(modes, text=text, style="Seg.TButton", takefocus=False,
                                command=lambda k=key: self.set_mode(k))
            button.grid(row=0, column=column, sticky="ew")
            modes.columnconfigure(column, weight=1, uniform="modes")
            self.mode_buttons[key] = button
        if not SPLIT_SUPPORTED:
            self.mode_buttons["discord"].state(["disabled"])
        self._show_mode()

        ttk.Label(side, text="LOCATION", style="Key.TLabel").pack(anchor="w")
        self.country_var = tk.StringVar(value=ANY_COUNTRY)
        self.country_box = ttk.Combobox(side, textvariable=self.country_var, height=12,
                                        state="readonly", values=[ANY_COUNTRY])
        self.country_box.pack(fill="x", pady=(px(4), px(10)))
        self.country_box.bind("<<ComboboxSelected>>", lambda e: self._on_country_change())
        self.action_btn = ttk.Button(side, text="Quick Connect", style="Primary.TButton",
                                     command=self.primary_action)
        self.action_btn.pack(fill="x")

        info = ttk.Frame(side, style="Inset.TFrame", padding=(px(12), px(8)))
        info.pack(fill="x", pady=(px(12), 0))
        info.columnconfigure(1, weight=1)
        self.ip_var = tk.StringVar(value="Checking…")
        self.server_var = tk.StringVar(value="—")
        self.clock_var = tk.StringVar(value="—")
        for i, (key, var) in enumerate((("Your IP address", self.ip_var),
                                        ("Server", self.server_var),
                                        ("Connected for", self.clock_var))):
            ttk.Label(info, text=key, style="InsetKey.TLabel").grid(
                row=i, column=0, sticky="w", pady=px(3))
            value = ttk.Label(info, textvariable=var, style="InsetValue.TLabel")
            value.grid(row=i, column=1, sticky="e", pady=px(3))
            if var is self.ip_var:
                self.ip_label = value

        self.dns_var = tk.BooleanVar(value=bool(self.settings["prevent_dns_leaks"]))
        self.failover_var = tk.BooleanVar(value=bool(self.settings["auto_failover"]))
        self.autostart_var = tk.BooleanVar(value=IS_WINDOWS and bool(self.settings["autostart"]))
        self.auto_connect_var = tk.BooleanVar(value=bool(self.settings["auto_connect"]))
        self.reconnect_var = tk.BooleanVar(value=bool(self.settings["auto_reconnect"]))
        self.tray_var = tk.BooleanVar(value=bool(self.settings["tray"]))

        # ---------------- right: servers, log and settings ----------------
        main = ttk.Frame(outer, style="Card.TFrame", padding=pad)
        main.pack(side="left", fill="both", expand=True)

        head = ttk.Frame(main)
        head.pack(fill="x")
        self.tab_buttons = {}
        for key, text in (("servers", "Servers"), ("log", "Log"), ("settings", "Settings")):
            button = ttk.Button(head, text=text, style="Tab.TButton", takefocus=False,
                                command=lambda k=key: self.show_tab(k))
            button.pack(side="left", padx=(0, px(4)))
            self.tab_buttons[key] = button
        self.refresh_btn = ttk.Button(head, text="Refresh list", command=self.refresh_servers)
        self.refresh_btn.pack(side="right")
        self.list_note = tk.StringVar()
        ttk.Label(head, textvariable=self.list_note, style="Muted.TLabel"
                  ).pack(side="right", padx=(0, px(12)))

        # "Install OpenVPN" banner (shown only when it's missing)
        self.banner = ttk.Frame(main, style="Banner.TFrame", padding=(px(14), px(12)))
        ttk.Label(self.banner, text="One more step: install OpenVPN",
                  style="BannerTitle.TLabel").pack(anchor="w")
        banner_text = ttk.Label(
            self.banner, style="Banner.TLabel", justify="left",
            text="Free VPN uses the free, official OpenVPN client to make the encrypted "
                 "connection. Install it with the default options, then press "
                 "“Check again”.")
        banner_text.pack(anchor="w", fill="x", pady=(px(2), px(10)))
        banner_buttons = ttk.Frame(self.banner, style="BannerFill.TFrame")
        banner_buttons.pack(anchor="w")
        for text, command in (
                ("Download OpenVPN", lambda: webbrowser.open(OPENVPN_DOWNLOAD_URL)),
                ("Check again", self.recheck_openvpn),
                ("Locate openvpn.exe…", self.locate_openvpn)):
            ttk.Button(banner_buttons, text=text, style="Banner.TButton",
                       command=command).pack(side="left", padx=(0, px(8)))

        # "A new version is available" banner (shown only then)
        self.update_banner = ttk.Frame(main, style="Info.TFrame", padding=(px(14), px(12)))
        self.update_title = tk.StringVar()
        self.update_text = tk.StringVar()
        ttk.Label(self.update_banner, textvariable=self.update_title,
                  style="InfoTitle.TLabel").pack(anchor="w")
        update_label = ttk.Label(self.update_banner, textvariable=self.update_text,
                                 style="Info.TLabel", justify="left")
        update_label.pack(anchor="w", fill="x", pady=(px(2), px(10)))
        update_buttons = ttk.Frame(self.update_banner, style="InfoFill.TFrame")
        update_buttons.pack(anchor="w")
        self.update_now_btn = ttk.Button(update_buttons, text="Update now",
                                         style="InfoPrimary.TButton", command=self.install_update)
        self.update_now_btn.pack(side="left", padx=(0, px(8)))
        self.whats_new_btn = ttk.Button(
            update_buttons, text="What's new", style="Info.TButton",
            command=lambda: webbrowser.open((self.update or {}).get("page", RELEASES_PAGE)))
        self.whats_new_btn.pack(side="left", padx=(0, px(8)))
        self.update_later_btn = ttk.Button(update_buttons, text="Not now", style="Info.TButton",
                                           command=self._hide_update)
        self.update_later_btn.pack(side="left")

        self.stack = ttk.Frame(main)
        self.stack.pack(fill="both", expand=True, pady=(px(10), 0))
        self.stack.rowconfigure(0, weight=1)
        self.stack.columnconfigure(0, weight=1)
        servers_view = ttk.Frame(self.stack)
        log_view = ttk.Frame(self.stack)
        settings_view = ttk.Frame(self.stack)
        self.views = {"servers": servers_view, "log": log_view, "settings": settings_view}
        for view in self.views.values():
            view.grid(row=0, column=0, sticky="nsew")

        table = ttk.Frame(servers_view)
        table.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(table, columns=[c[0] for c in COLUMNS], show="headings",
                                 selectmode="browse")
        for key, heading, width, anchor in COLUMNS:
            self.tree.heading(key, text=heading, anchor=anchor,
                              command=lambda k=key: self._sort_by(k))
            self.tree.column(key, width=px(width), minwidth=px(56), anchor=anchor,
                             stretch=key in ("country", "host"))
        scroll = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=auto_scrollbar(scroll, "Vertical.TScrollbar"))
        scroll.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.bind("<Return>", lambda e: self.connect_selected())
        self.tree.bind("<Motion>", lambda e: self._set_hover_row(self.tree.identify_row(e.y)))
        self.tree.bind("<Leave>", lambda e: self._set_hover_row(None))

        below = ttk.Frame(servers_view)
        below.pack(fill="x", pady=(px(10), 0))
        self.connect_sel_btn = ttk.Button(below, text="Connect to selected server",
                                          command=self.connect_selected)
        self.connect_sel_btn.pack(side="left")
        ttk.Label(below, style="Muted.TLabel",
                  text="or double-click a server").pack(side="left", padx=(px(10), 0))

        log_box = ttk.Frame(log_view, style="Inset.TFrame", padding=px(10))
        log_box.pack(fill="both", expand=True)
        self.log_text = tk.Text(log_box, wrap="none", height=5, width=20, state="disabled",
                                font=sk.f_mono, relief="flat", borderwidth=0,
                                highlightthickness=0, padx=px(4), pady=px(2))
        log_scroll = ttk.Scrollbar(log_box, orient="vertical", command=self.log_text.yview,
                                   style="Off.Inset.Vertical.TScrollbar")
        self.log_text.configure(
            yscrollcommand=auto_scrollbar(log_scroll, "Inset.Vertical.TScrollbar"))
        log_scroll.pack(side="right", fill="y")
        self.log_text.pack(side="left", fill="both", expand=True)
        log_buttons = ttk.Frame(log_view)
        log_buttons.pack(fill="x", pady=(px(10), 0))
        ttk.Button(log_buttons, text="Copy log", command=self.copy_log).pack(side="left")
        ttk.Label(log_buttons, style="Muted.TLabel",
                  text="If something goes wrong, the answer is usually in here."
                  ).pack(side="left", padx=(px(10), 0))

        # Settings: a title (with a switch, where there is something to switch)
        # and a plain-language explanation under it. It scrolls if the window is
        # too small to show it all.
        explanations = []
        canvas = self.settings_canvas = tk.Canvas(settings_view, highlightthickness=0, bd=0,
                                                  yscrollincrement=px(24))
        settings_scroll = ttk.Scrollbar(settings_view, orient="vertical", command=canvas.yview,
                                        style="Off.Vertical.TScrollbar")
        canvas.configure(yscrollcommand=auto_scrollbar(settings_scroll, "Vertical.TScrollbar"))
        settings_scroll.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        settings_body = ttk.Frame(canvas)
        body_item = canvas.create_window(0, 0, window=settings_body, anchor="nw")
        settings_body.bind("<Configure>",
                           lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(body_item, width=e.width))

        def wheel(event):
            if canvas.yview() == (0.0, 1.0):
                return            # everything fits: nothing to scroll
            if getattr(event, "num", 0) in (4, 5):           # Linux
                step = -1 if event.num == 4 else 1
            else:                                            # Windows
                step = -1 if event.delta > 0 else 1
            canvas.yview_scroll(step * 2, "units")
        for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            settings_view.bind(sequence, wheel)
        self._settings_wheel = wheel

        def setting(title, text, variable=None, enabled=True, command=None, first=False):
            gap = 0 if first else px(10)
            if variable is None:
                ttk.Label(settings_body, text=title, style="Strong.TLabel"
                          ).pack(anchor="w", pady=(gap + px(4), 0))
                switch = None
            else:
                switch = ttk.Checkbutton(settings_body, text=title, variable=variable,
                                         style="Setting.Switch.TCheckbutton",
                                         command=command or self._save_options)
                switch.pack(fill="x", pady=(gap, 0))
                if not enabled:
                    switch.state(["disabled"])
            label = ttk.Label(settings_body, text=text, style="Muted.TLabel", justify="left")
            label.pack(anchor="w", pady=(0, px(2)))
            explanations.append(label)
            return switch

        self.autostart_switch = setting(
            "Start Free VPN when Windows starts",
            "Opens Free VPN minimized when you sign in, without the permission question.",
            self.autostart_var, enabled=IS_WINDOWS, command=self._toggle_autostart, first=True)
        setting("Connect automatically when Free VPN opens",
                "Connects to the best server for your location and mode (Everything or "
                "Discord only) as soon as Free VPN opens.", self.auto_connect_var)
        self.tray_switch = setting(
            "Hide next to the clock when kept running",
            "\u201cKeep running\u201d hides Free VPN in the icons next to the clock. Click the "
            "icon to open it; right-click it to connect, disconnect or quit. With this off, "
            "it stays on the taskbar and in Alt+Tab.", self.tray_var, enabled=TRAY_SUPPORTED)
        setting("Reconnect automatically if the connection drops",
                "Tries the same server again first, then others, waiting a little longer "
                "after each try. Disconnect stops it.", self.reconnect_var)
        setting("Prevent DNS leaks",
                "Looks up website names through the VPN, so your internet provider can't see "
                "which sites you visit. Used in \u201cEverything\u201d mode.",
                self.dns_var, enabled=IS_WINDOWS)
        setting("Try the next server if one fails",
                "Volunteer servers are often busy or offline. With this on, Free VPN tries up "
                f"to {MAX_SERVERS_TO_TRY} servers before giving up.", self.failover_var)
        setting("About \u201cDiscord only\u201d",
                "Only Discord uses the VPN; games and everything else keep your normal "
                "connection and IP address. If Discord was already open when you connected, "
                "quit it completely (also from the icons next to the clock) and reopen it.")
        setting("Closing the window",
                "The X button asks whether to keep Free VPN running in the background or to "
                "quit. While it is minimized, the VPN stays on.")
        self.check_updates_var = tk.BooleanVar(value=bool(self.settings["check_updates"]))
        setting("Check for updates automatically",
                "Looks for a new version of Free VPN on GitHub when it opens and twice a day. "
                "Nothing is installed until you press \u201cUpdate now\u201d.",
                self.check_updates_var)
        version_row = ttk.Frame(settings_body)
        version_row.pack(fill="x", pady=(px(6), px(4)))
        ttk.Label(version_row, text=f"You have version {APP_VERSION}.", style="Muted.TLabel"
                  ).pack(side="left")
        self.check_now_btn = ttk.Button(version_row, text="Check now", style="Ghost.TButton",
                                        command=lambda: self.check_update(manual=True))
        self.check_now_btn.pack(side="left", padx=(px(8), 0))
        self.update_status = tk.StringVar()
        ttk.Label(version_row, textvariable=self.update_status, style="Muted.TLabel"
                  ).pack(side="left", padx=(px(6), 0))

        # Scroll with the mouse wheel anywhere over the settings, not just the gaps.
        def bind_wheel(widget):
            for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
                widget.bind(sequence, self._settings_wheel, add="+")
            for child in widget.winfo_children():
                bind_wheel(child)
        bind_wheel(canvas)

        foot = ttk.Frame(main)
        foot.pack(fill="x", pady=(px(10), 0))
        link = ttk.Label(foot, text="vpngate.net", style="Link.TLabel", cursor="hand2")
        link.pack(side="right", anchor="s")
        link.bind("<Button-1>", lambda e: webbrowser.open(VPNGATE_URL))
        footer = ttk.Label(
            foot, style="Muted.TLabel", justify="left",
            text="Servers are run by volunteers through VPN Gate, a free research project at "
                 "the University of Tsukuba. Good for unblocking sites and hiding your IP; "
                 "don't rely on it for anything sensitive.")
        footer.pack(side="left", fill="x", expand=True)

        def rewrap(event):
            inside = event.width - 2 * pad
            footer.configure(wraplength=max(inside - px(110), px(200)))
            banner_text.configure(wraplength=max(inside - px(30), px(200)))
            update_label.configure(wraplength=max(inside - px(30), px(200)))
            for label in explanations:
                label.configure(wraplength=max(inside - px(70), px(200)))
        main.bind("<Configure>", rewrap)

    def set_theme(self, name: str) -> None:
        sk = self.skin
        sk.apply(name)
        c = sk.c
        self.power.set_palette(c)
        self.settings_canvas.configure(background=c["surface"])
        self.log_text.configure(background=c["surface2"], foreground=c["text"],
                                insertbackground=c["text"], selectbackground=c["sel_bg"],
                                selectforeground=c["sel_fg"])
        # Size the columns for this PC's font: wide enough for the heading (plus
        # a sort arrow) and for typical values.
        for key, heading, width, _ in COLUMNS:
            sample = COLUMN_SAMPLES.get(key, "")
            needed = max(sk.f_small_strong.measure(heading + " \u25bc"),
                         sk.f_base.measure(sample)) + 2 * sk.px(8) + 6
            self.tree.column(key, minwidth=needed, width=needed)
        self.tree.tag_configure("current", foreground=c["green_text"])
        self.tree.tag_configure("hover", background=c["surface2"])
        self.tree.tag_configure("odd", background=c["stripe"])
        self.theme_btn.configure(text="Light mode" if name == "dark" else "Dark mode")
        sk.style_dropdown(self.country_box)
        set_dark_title_bar(self.root, name == "dark")
        self.show_tab(self.tab)

    def toggle_theme(self) -> None:
        name = "light" if self.skin.name == "dark" else "dark"
        self.settings["theme"] = name
        save_settings(self.settings)
        self.set_theme(name)

    def _show_mode(self) -> None:
        for key, button in self.mode_buttons.items():
            button.configure(style="SegOn.TButton" if key == self.mode else "Seg.TButton")

    def set_mode(self, mode: str) -> None:
        """Switch between "all" (everything through the VPN) and "discord"."""
        if mode == self.mode or (mode == "discord" and not SPLIT_SUPPORTED):
            return
        self.mode = self.settings["mode"] = mode
        save_settings(self.settings)
        self._show_mode()
        if self.conn is not None and self.state in ("connecting", "connected", "reconnecting"):
            # Already on a server: reconnect to it the new way.
            server = self.conn.server
            self._start([server] + [s for s in self._best_first(self.filtered)
                                    if s is not server])

    def show_tab(self, key: str) -> None:
        self.tab = key
        self.views[key].tkraise()
        for name, button in self.tab_buttons.items():
            button.configure(style="TabOn.TButton" if name == key else "Tab.TButton")

    # ---- updates ------------------------------------------------------------

    def _auto_check_update(self) -> None:
        self.update_job = self.root.after(UPDATE_CHECK_EVERY * 1000, self._auto_check_update)
        if self.check_updates_var.get():
            self.check_update(manual=False)

    def check_update(self, manual: bool = False) -> None:
        if self.update_busy:
            return
        self.update_busy = True
        self.check_now_btn.state(["disabled"])
        if manual:
            self.update_status.set("Checking\u2026")

        def work():
            try:
                return manual, check_for_update(), ""
            except Exception as exc:
                return manual, None, short_error(exc)
        self._run_in_background(work, "update_checked")

    def _on_update_checked(self, manual: bool, update, error: str) -> None:
        self.update_busy = False
        self.check_now_btn.state(["!disabled"])
        if error:
            self._log(f"Couldn't check for updates: {error}")
            self.update_status.set("Couldn't reach GitHub. Try again later." if manual else "")
            return
        if update is None:
            self.update_status.set("You have the newest version." if manual else "")
            return
        self.update_status.set(f"Version {update['version']} is available (see above).")
        first_time = self.update is None or self.update["version"] != update["version"]
        self.update = update
        self._show_update(f"Free VPN {update['version']} is available",
                          "Updating takes a few seconds. Free VPN restarts by itself and "
                          "reconnects if you're connected.", busy=False)
        if first_time:
            self._log(f"Update available: version {update['version']}")
            self._notify("Update available", f"Free VPN {update['version']} is ready. Open "
                         "Free VPN to update.")

    def _show_update(self, title: str, text: str, busy: bool, offer: bool = True) -> None:
        """The blue banner. offer=False: just news (no "Update now"; "OK" closes it)."""
        self.update_title.set(title)
        self.update_text.set(text)
        if offer and not self.update_now_btn.winfo_ismapped():
            self.update_now_btn.pack(side="left", padx=(0, self.skin.px(8)),
                                     before=self.whats_new_btn)
        elif not offer:
            self.update_now_btn.pack_forget()
        self.update_later_btn.configure(text="Not now" if offer else "OK")
        for button in (self.update_now_btn, self.update_later_btn):
            button.state(["disabled"] if busy else ["!disabled"])
        if not self.update_banner.winfo_ismapped():
            self.update_banner.pack(fill="x", pady=(self.skin.px(10), 0), before=self.stack)

    def _hide_update(self) -> None:
        self.update_banner.pack_forget()

    def install_update(self) -> None:
        """Download the new version, then restart into it."""
        update = self.update
        if update is None or self.update_busy:
            return
        self.update_busy = True
        self._show_update(f"Downloading Free VPN {update['version']}\u2026",
                          "This takes a few seconds.", busy=True)
        target = this_program_file()

        def work():
            try:
                return download_update(update, os.path.dirname(target)), ""
            except Exception as exc:
                return None, short_error(exc)
        self._run_in_background(work, "update_downloaded")

    def _on_update_downloaded(self, new_file, error: str) -> None:
        self.update_busy = False
        update = self.update or {}
        if not new_file:
            self._log(f"The update couldn't be downloaded: {error}")
            self._show_update(f"Free VPN {update.get('version', '')} couldn't be downloaded",
                              f"{error}. Try again, or download it from GitHub "
                              "(\u201cWhat's new\u201d).", busy=False)
            return
        target = this_program_file()
        arguments = [UPDATED_ARG]
        if self.conn is not None or self.state in ("connected", "connecting", "waiting"):
            arguments.append(RESUME_ARG)          # reconnect after the restart
        if getattr(sys, "frozen", False):
            program, args = target, subprocess.list2cmdline(arguments)
        else:
            program, args = gui_python(), subprocess.list2cmdline([target] + arguments)
        self._log(f"Installing version {update.get('version')} and restarting\u2026")
        self._show_update(f"Installing Free VPN {update.get('version', '')}\u2026",
                          "Free VPN closes and opens again in a moment.", busy=True)
        try:
            start_update_helper(update_helper_command(new_file, target, program, args,
                                                      os.path.dirname(target), os.getpid()))
        except Exception as exc:
            self._log(f"Couldn't start the updater: {exc}")
            self._show_update("The update couldn't be installed", f"{short_error(exc)}.",
                              busy=False)
            return
        self.quit()

    def _update_openvpn_banner(self) -> None:
        if self.openvpn:
            self.banner.pack_forget()
        else:
            self.banner.pack(fill="x", pady=(self.skin.px(10), 0), before=self.stack)

    # ---- state -------------------------------------------------------------

    def _set_state(self, state: str, title: str, detail: str | None = None) -> None:
        self.state = state
        self.setting_up = False
        self.status_var.set(title)
        if detail is not None:
            self.detail_var.set(detail)
        self.root.title(APP_NAME if state == "idle" else f"{APP_NAME} – {title}")
        kind = {"idle": "idle", "connected": "on", "error": "error",
                "waiting": "error"}.get(state, "busy")
        self.power.set_kind(kind, enabled=state != "stopping")
        if state in ("idle", "error"):
            self.action_btn.configure(text="Quick Connect", style="Primary.TButton",
                                      state="normal")
        elif state == "connected":
            self.action_btn.configure(text="Disconnect", style="Danger.TButton",
                                      state="normal")
        elif state == "stopping":
            self.action_btn.configure(text="Disconnecting…", style="Action.TButton",
                                      state="disabled")
        else:
            self.action_btn.configure(text="Cancel", style="Action.TButton", state="normal")
        self.connect_sel_btn.configure(state="disabled" if state == "stopping" else "normal")

        active = state in ("connecting", "connected", "reconnecting") and self.conn
        self.server_var.set(f"{self.conn.server.host} · {self.conn.server.proto}"
                            if active else "—")
        if state == "connected":
            self.connected_at = self.connected_at or time.monotonic()
        elif state != "reconnecting":
            self.connected_at = 0.0
        self._update_clock()
        self._refresh_row_tags()
        self._update_tray(kind, title)

    def primary_action(self) -> None:
        """The big round button and the button under it: connect, or stop."""
        if self.state in ("idle", "error"):
            self.quick_connect()
        elif self.state != "stopping":
            self.disconnect()

    def _update_clock(self) -> None:
        if not self.connected_at:
            self.clock_var.set("—")
            return
        seconds = int(time.monotonic() - self.connected_at)
        hours, rest = divmod(seconds, 3600)
        self.clock_var.set(f"{hours}:{rest // 60:02d}:{rest % 60:02d}" if hours
                           else f"{rest // 60:02d}:{rest % 60:02d}")

    def _tick(self) -> None:
        self._update_clock()
        if self.state == "waiting":
            left = max(0, int(self.reconnect_at - time.monotonic() + 0.99))
            self.detail_var.set(f"Trying again in {left} s\u2026  (Cancel stops it.)")
        self.root.after(1000, self._tick)

    def _show_ip(self, text: str, style: str = "InsetValue.TLabel") -> None:
        self.ip_var.set(text)
        self.ip_label.configure(style=style)

    def _save_options(self) -> None:
        self.settings["prevent_dns_leaks"] = bool(self.dns_var.get())
        self.settings["auto_failover"] = bool(self.failover_var.get())
        self.settings["auto_connect"] = bool(self.auto_connect_var.get())
        self.settings["auto_reconnect"] = bool(self.reconnect_var.get())
        self.settings["tray"] = bool(self.tray_var.get())
        self.settings["check_updates"] = bool(self.check_updates_var.get())
        save_settings(self.settings)

    def _toggle_autostart(self) -> None:
        """The "Start Free VPN when Windows starts" switch."""
        want = self._autostart_wanted = bool(self.autostart_var.get())
        self.autostart_switch.state(["disabled"])     # one change at a time

        def work():
            try:
                return set_autostart(want)
            except Exception as exc:
                return -1, short_error(exc)
        self._run_in_background(work, "autostart")

    # ---- one copy at a time -----------------------------------------------

    def _start_show_listener(self) -> None:
        """Listen for "show your window" from a second copy (see show_running_copy)."""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind(("127.0.0.1", 0))
            server.listen(4)
            with open(_instance_file(), "w", encoding="ascii") as f:
                f.write(str(server.getsockname()[1]))
        except OSError:
            return
        self._show_server = server
        events = self.events

        def serve():
            while True:
                try:
                    conn, _ = server.accept()
                except OSError:
                    return       # closed when the app quits
                with conn:
                    try:
                        conn.settimeout(2)
                        if conn.recv(64).startswith(SHOW_REQUEST.strip()):
                            events.put((0, "show", None))
                            conn.sendall(SHOW_REPLY)
                    except OSError:
                        pass
        threading.Thread(target=serve, daemon=True).start()

    def _stop_show_listener(self) -> None:
        server, self._show_server = self._show_server, None
        if server is None:
            return
        port = str(server.getsockname()[1])
        server.close()
        try:
            with open(_instance_file(), encoding="ascii") as f:
                mine = f.read().strip() == port
            if mine:
                os.remove(_instance_file())
        except OSError:
            pass

    def show_window(self) -> None:
        """Bring the window back (from minimized) and to the front."""
        root = self.root
        root.deiconify()
        root.lift()
        try:
            root.attributes("-topmost", True)
            root.after(400, lambda: root.attributes("-topmost", False))
            root.focus_force()
        except tk.TclError:
            pass

    # ---- the icon next to the clock ---------------------------------------------

    def _start_tray(self) -> None:
        if not TRAY_SUPPORTED:
            return
        events = self.events
        tray = TrayIcon(lambda command: events.put((0, "tray", command)),
                        self._tray_menu_state, self._log)
        try:
            files = make_tray_icons(os.path.join(data_dir(), "icons"))
        except OSError as exc:
            self._log(f"Tray icon: couldn't save its pictures ({short_error(exc)})")
            return
        if tray.start(files):
            self.tray = tray
            self._update_tray(*self._tray_look())
            if self.started_at_sign_in and self.tray_var.get():
                self.root.withdraw()      # started at sign-in: just the icon, no window
        else:
            self.tray_switch.state(["disabled"])

    def _tray_look(self) -> tuple:
        kind = {"idle": "idle", "connected": "on", "error": "error",
                "waiting": "error"}.get(self.state, "busy")
        return kind, self.status_var.get()

    def _update_tray(self, kind: str, title: str) -> None:
        if self.tray is None:
            return
        tip = f"{APP_NAME}: {title}"
        if self.state == "connected" and self.conn is not None:
            where = "Discord only" if self.conn.discord_only else "everything"
            tip += f" ({self.conn.server.country}, {where})"
        self.tray.update(kind, tip)

    def _tray_menu_state(self) -> tuple:
        if self.state in ("idle", "error"):
            return "Connect", bool(self.openvpn and self.filtered)
        if self.state == "stopping":
            return "Disconnecting\u2026", False
        if self.state == "waiting":
            return "Stop reconnecting", True
        return "Disconnect", True

    def _on_tray(self, command: str) -> None:
        if command == "open":
            self.show_window()
        elif command == "toggle":
            if self.state in ("idle", "error") and not (self.openvpn and self.filtered):
                return
            self.primary_action()
        elif command == "quit":
            self.quit()

    def _window_hidden(self) -> bool:
        try:
            return self.root.state() in ("withdrawn", "iconic")
        except tk.TclError:
            return True

    def _notify(self, title: str, text: str, warning: bool = False) -> None:
        """A pop-up from the tray icon, when the window isn't in view."""
        if self.tray is not None and self._window_hidden():
            self.tray.notify(title, text, warning)

    def _keep_running(self) -> None:
        """The "Keep running" choice in the close question."""
        if self.tray is not None and self.tray_var.get():
            self.root.withdraw()
            if not self.settings.get("tray_hint_shown"):
                self.settings["tray_hint_shown"] = True
                save_settings(self.settings)
                self.tray.notify(APP_NAME, "Still running here. Click the icon to open it, "
                                 "or right-click it for more.")
        else:
            self.root.iconify()       # on the taskbar; Alt+Tab brings it back

    def _maybe_auto_connect(self, fresh: bool) -> None:
        """After the server list arrives: connect automatically, if that's on.
        Right after sign-in the internet may not be up yet, so wait for a fresh
        list (for up to about two minutes) before trying."""
        if not self.auto_connect_pending or self.state != "idle":
            return
        if not fresh and self._list_retries < STARTUP_LIST_RETRIES and not self.resuming:
            self._list_retries += 1
            self.detail_var.set("Waiting for the internet before connecting…")
            self.root.after(STARTUP_RETRY_MS, self._retry_list)
            return
        self.auto_connect_pending = False
        if self.openvpn and self.filtered:
            self._start(self._best_first(self.filtered), automatic=True)

    def _retry_list(self) -> None:
        if self.auto_connect_pending and self.state == "idle":
            self.refresh_servers()

    def _log(self, line: str) -> None:
        text = self.log_text
        at_bottom = text.yview()[1] >= 0.999
        text.configure(state="normal")
        text.insert("end", line + "\n")
        lines = int(text.index("end-1c").split(".")[0])
        if lines > 5000:
            text.delete("1.0", f"{lines - 4000}.0")
        text.configure(state="disabled")
        if at_bottom:
            text.see("end")

    def copy_log(self) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(self.log_text.get("1.0", "end-1c"))

    # ---- background events -------------------------------------------------

    def _poll(self) -> None:
        try:
            while True:
                try:
                    conn_id, kind, value = self.events.get_nowait()
                except queue.Empty:
                    break
                if conn_id == 0:
                    self._on_app_event(kind, value)
                else:
                    self._on_vpn_event(conn_id, kind, value)
            if (self.state == "connecting" and self.conn is not None and not self.setting_up
                    and time.monotonic() - self.attempt_started > CONNECT_TIMEOUT):
                self._attempt_failed(f"No answer after {CONNECT_TIMEOUT} seconds.")
        finally:
            # Keep polling even if handling one event went wrong.
            self.root.after(120, self._poll)

    def _run_in_background(self, work, kind: str) -> None:
        def runner():
            try:
                result = (True, work())
            except Exception as exc:
                result = (False, exc)
            self.events.put((0, kind, result))
        threading.Thread(target=runner, daemon=True).start()

    def _on_app_event(self, kind: str, value) -> None:
        if kind == "stopped":
            then, had_split = value
            self._pending_stops -= 1
            if had_split and not (self.conn and self.conn.split):
                self._clear_split_flag()      # its DNS rule is gone again
            if then is not None:
                then()
        elif kind == "tidied":
            if not (self.conn and self.conn.split):
                self._clear_split_flag()
        elif kind == "servers":
            ok, result = value
            self.refresh_btn.configure(state="normal")
            if ok:
                self.servers, note, fresh = result
                self.list_note.set(note)
                self._fill_countries()
                if self.state == "idle" and self.detail_var.get().startswith("Loading"):
                    self.detail_var.set("Pick a location and press the button to connect.")
                self._maybe_auto_connect(fresh)
            else:
                self.list_note.set("No server list")
                self._log(f"Couldn't load the server list: {short_error(result)}")
                if self.auto_connect_pending and self._list_retries < STARTUP_LIST_RETRIES:
                    self._maybe_auto_connect(False)       # try again shortly
                elif self.state in ("idle", "error") and not self.servers:
                    self.auto_connect_pending = False
                    self._set_state("error", "No servers", "Couldn't load the server list. "
                                    "Check your internet, then press \u201cRefresh list\u201d.")
        elif kind == "show":
            self.show_window()
        elif kind == "update_checked":
            self._on_update_checked(*value[1])
        elif kind == "update_downloaded":
            self._on_update_downloaded(*value[1])
        elif kind == "tray":
            self._on_tray(value)
        elif kind in ("autostart", "autostart_refresh"):
            code, output = value[1]
            if kind == "autostart_refresh":
                if code != 0:
                    self._log(f"Couldn't update the start-with-Windows task ({code}): {output}")
                return
            want = self._autostart_wanted
            if IS_WINDOWS:
                self.autostart_switch.state(["!disabled"])
            if code == 0:
                self.settings["autostart"] = want
                save_settings(self.settings)
                self._log("Start with Windows: " + ("on" if want else "off"))
            else:
                self.autostart_var.set(not want)
                self._log(f"Couldn't change the start-with-Windows task ({code}): {output}")
                messagebox.showerror(APP_NAME, "Windows didn't accept the change to "
                                     "\u201cStart Free VPN when Windows starts\u201d.\n\n"
                                     f"{output or 'No details.'}", parent=self.root)
        elif kind == "ip":
            initial, session, ip = value[1]
            if session != self.session:
                return
            if initial and self.state == "idle":
                self.original_ip = ip
            if ip is None:
                self._show_ip("Unknown")
            elif self.state == "connected" and self.conn and self.conn.discord_only:
                self._show_ip(ip)     # stays the same on purpose: only Discord uses the VPN
            elif self.state == "connected":
                if self.original_ip and ip == self.original_ip:
                    self._show_ip(ip, "InsetWarn.TLabel")
                    self.detail_var.set("Warning: your IP address didn't change, so your "
                                        "traffic may not be going through the VPN.")
                else:
                    self._show_ip(ip, "InsetGood.TLabel")
            else:
                self._show_ip(ip)

    def _check_ip(self, initial: bool = False) -> None:
        session = self.session

        def work():
            try:
                text = http_get(IP_CHECK_URL, timeout=10).decode("ascii", "replace").strip()
                ip = str(ipaddress.ip_address(text))
            except Exception:
                ip = None
            return (initial, session, ip)
        self._show_ip("Checking…")
        self._run_in_background(work, "ip")

    # ---- server list -------------------------------------------------------

    def refresh_servers(self) -> None:
        self.refresh_btn.configure(state="disabled")
        self.list_note.set("Loading servers…")
        self._run_in_background(load_servers, "servers")

    def _fill_countries(self) -> None:
        counts: dict[str, int] = {}
        for s in self.servers:
            counts[s.country] = counts.get(s.country, 0) + 1
        self.country_labels = {ANY_COUNTRY: ANY_COUNTRY}
        for country in sorted(counts, key=str.lower):
            n = counts[country]
            self.country_labels[f"{country}  ({n} server{'s' if n != 1 else ''})"] = country
        self.country_box.configure(values=list(self.country_labels))
        wanted = self.settings.get("country", ANY_COUNTRY)
        label = next((lbl for lbl, c in self.country_labels.items() if c == wanted), ANY_COUNTRY)
        self.country_var.set(label)
        self._apply_filter()

    def _selected_country(self) -> str:
        return self.country_labels.get(self.country_var.get(), ANY_COUNTRY)

    def _on_country_change(self) -> None:
        self.country_box.selection_clear()
        self.settings["country"] = self._selected_country()
        save_settings(self.settings)
        self._apply_filter()

    def _apply_filter(self) -> None:
        country = self._selected_country()
        self.filtered = [s for s in self.servers if country in (ANY_COUNTRY, s.country)]
        self._render_table()

    def _sort_by(self, key: str) -> None:
        if self.sort_col == key:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_col, self.sort_reverse = key, SORT_KEYS[key][1]
        self._render_table()

    def _render_table(self) -> None:
        rows = list(self.filtered)
        if self.sort_col:
            rows.sort(key=SORT_KEYS[self.sort_col][0], reverse=self.sort_reverse)
        self.visible = rows
        self.hover_row = None
        for key, heading, _, _ in COLUMNS:
            arrow = ""
            if key == self.sort_col:
                arrow = " ▼" if self.sort_reverse else " ▲"   # both are in Segoe UI
            self.tree.heading(key, text=heading + arrow)
        self.tree.delete(*self.tree.get_children())
        good = set(self._good_keys())
        for i, s in enumerate(rows):
            host = ("\u2605 " + s.host) if self._key(s) in good else s.host   # ★ worked before
            self.tree.insert("", "end", iid=str(i), tags=self._row_tags(i), values=(
                s.country, host, s.proto, fmt_ping(s.ping), fmt_speed(s.speed_bps),
                s.sessions, fmt_uptime(s.uptime_ms)))

    def _row_tags(self, i: int) -> tuple:
        """Green for the server you're connected to, a highlight under the
        mouse, and a faint stripe on every other row."""
        tags = []
        if self.conn and self.state == "connected" and self.visible[i] is self.conn.server:
            tags.append("current")
        if str(i) == self.hover_row:
            tags.append("hover")
        elif i % 2:
            tags.append("odd")
        return tuple(tags)

    def _refresh_row_tags(self) -> None:
        for i in range(len(self.visible)):
            self.tree.item(str(i), tags=self._row_tags(i))

    def _set_hover_row(self, iid) -> None:
        iid = iid or None
        if iid == self.hover_row:
            return
        previous, self.hover_row = self.hover_row, iid
        for row in (previous, iid):
            if row is not None and self.tree.exists(row):
                self.tree.item(row, tags=self._row_tags(int(row)))

    # ---- OpenVPN location ---------------------------------------------------

    def recheck_openvpn(self) -> bool:
        self.openvpn = find_openvpn(self.settings.get("openvpn_path", ""))
        self._update_openvpn_banner()
        if not self.openvpn:
            messagebox.showinfo(APP_NAME, "OpenVPN still wasn't found. If you've just "
                                "installed it somewhere unusual, use “Locate "
                                "openvpn.exe…”.", parent=self.root)
        return bool(self.openvpn)

    def locate_openvpn(self) -> None:
        kinds = [("openvpn.exe", "openvpn.exe"), ("All files", "*.*")] if IS_WINDOWS else []
        path = filedialog.askopenfilename(parent=self.root, title="Find openvpn.exe",
                                          filetypes=kinds or [("All files", "*")])
        if path:
            self.settings["openvpn_path"] = path
            save_settings(self.settings)
            self.recheck_openvpn()

    # ---- servers that worked --------------------------------------------------

    @staticmethod
    def _key(server: Server) -> str:
        return f"{server.host}|{server.ip}"

    def _good_keys(self) -> list:
        keys = self.settings.get("good_servers")
        return [k for k in keys if isinstance(k, str)] if isinstance(keys, list) else []

    def _is_good(self, server: Server) -> bool:
        return self._key(server) in self._good_keys()

    def _remember(self, server: Server) -> None:
        key = self._key(server)
        keys = [key] + [k for k in self._good_keys() if k != key]
        if keys[:GOOD_SERVERS_KEPT] != self._good_keys():
            self.settings["good_servers"] = keys[:GOOD_SERVERS_KEPT]
            save_settings(self.settings)
            self._render_table()

    def _forget(self, server: Server | None) -> None:
        if server is not None and self._is_good(server):
            self.settings["good_servers"] = [k for k in self._good_keys()
                                             if k != self._key(server)]
            save_settings(self.settings)
            self._render_table()

    def _best_first(self, servers: list) -> list:
        """Servers that worked before come first (most recent first), then the
        rest by VPN Gate's own quality score."""
        rank = {key: i for i, key in enumerate(self._good_keys())}
        return sorted(servers, key=lambda s: (rank.get(self._key(s), len(rank)), -s.score))

    # ---- connecting ---------------------------------------------------------

    def quick_connect(self) -> None:
        if not self.filtered:
            messagebox.showinfo(APP_NAME, "There are no servers to connect to yet. "
                                "Press “Refresh list” and try again.",
                                parent=self.root)
            return
        self._start(self._best_first(self.filtered))

    def _on_double_click(self, event) -> None:
        if self.tree.identify_region(event.x, event.y) == "cell":
            self.connect_selected()

    def connect_selected(self) -> None:
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo(APP_NAME, "Click a server in the list first.",
                                parent=self.root)
            return
        chosen = self.visible[int(selection[0])]
        self._start([chosen] + [s for s in self._best_first(self.filtered) if s is not chosen])

    def _start(self, pool: list[Server], automatic: bool = False) -> None:
        """Connect to the first server in `pool` that works. `automatic`: started
        by the app (auto-connect or reconnect), so keep trying if all fail."""
        self.auto_connect_pending = False      # the user (or auto-connect) has acted
        if self.state == "stopping":
            return
        if not self.openvpn and not self.recheck_openvpn():
            return
        self._cancel_reconnect()
        if not automatic:
            self.keep_trying = False           # until this connection has worked
            self.reconnect_round = 0
        self.automatic = automatic
        self.session += 1
        self.candidates = pool[:MAX_SERVERS_TO_TRY] if self.failover_var.get() else pool[:1]
        self.attempt_no = 0
        old, self.conn = self.conn, None
        if old is not None:
            self._set_state("connecting", "Switching…", "Closing the old connection…")
            self._stop_in_background(old)
        self._try_next()

    def _try_next(self) -> None:
        if not self.candidates:
            return
        if self._pending_stops:
            # Wait until the previous openvpn has let go of the network adapter.
            session = self.session
            self.root.after(200, lambda: session == self.session and self._try_next())
            return
        server = self.candidates.pop(0)
        self.attempt_no += 1
        total = self.attempt_no + len(self.candidates)
        attempt = f" (attempt {self.attempt_no} of {total})" if total > 1 else ""
        self._log(f"===== Connecting to {server.host} {server.ip}:{server.port} "
                  f"{server.proto} ({server.country}) =====")
        try:
            discord_only = SPLIT_SUPPORTED and self.mode == "discord"
            config = build_config(server, IS_WINDOWS and bool(self.dns_var.get()), discord_only)
            self.conn = VpnConnection(self.openvpn, server, config, self.events, discord_only)
        except OSError as exc:
            self.conn = None
            self.candidates = []
            self._set_state("error", "Couldn't start OpenVPN", f"{short_error(exc)}. "
                            "Try reinstalling OpenVPN.")
            self._log(f"Couldn't start OpenVPN: {exc}")
            self.openvpn = find_openvpn(self.settings.get("openvpn_path", ""))
            self._update_openvpn_banner()
            return
        self.attempt_started = time.monotonic()
        known = " \u00b7 worked last time" if self._is_good(server) else ""
        self._set_state("connecting", "Reconnecting\u2026" if self.automatic else "Connecting\u2026",
                        f"{server.country}{known}{attempt}")

    def _connected(self, server: Server, detail: str) -> None:
        """The connection is fully up."""
        was_automatic = self.automatic and self.reconnect_round > 0
        self.keep_trying = True
        self.automatic = False
        self.reconnect_round = 0
        self.last_server = server
        self._remember(server)
        self._set_state("connected", "Connected", detail)
        self._check_ip()
        if was_automatic:
            self._notify("Reconnected", f"Free VPN is connected again ({server.country}).")

    def _cancel_reconnect(self) -> None:
        if self.reconnect_job is not None:
            self.root.after_cancel(self.reconnect_job)
            self.reconnect_job = None

    def _schedule_reconnect(self, title: str) -> None:
        """Wait a while, then try again: the same server first, then others."""
        self._cancel_reconnect()
        delay = RECONNECT_DELAYS[min(self.reconnect_round, len(RECONNECT_DELAYS) - 1)]
        self.reconnect_round += 1
        self.reconnect_at = time.monotonic() + delay
        self._set_state("waiting", title, f"Trying again in {delay} s\u2026  (Cancel stops it.)")
        session = self.session
        self.reconnect_job = self.root.after(
            int(delay * 1000), lambda: session == self.session and self._reconnect_now())

    def _reconnect_now(self) -> None:
        self.reconnect_job = None
        pool = self._best_first(self.filtered or self.servers)
        last = self.last_server
        if last is not None:
            same = [s for s in pool if self._key(s) == self._key(last)]
            pool = (same or [last]) + [s for s in pool if self._key(s) != self._key(last)]
        if not pool:
            self._schedule_reconnect("No servers")
            return
        self._start(pool, automatic=True)

    def _on_vpn_event(self, conn_id: int, kind: str, value) -> None:
        if kind == "log":
            self._log(value)
            return
        if self.conn is None or conn_id != self.conn.id:
            return  # from a connection we've already moved on from
        server = self.conn.server
        if kind == "connected":
            self.candidates = []
            if self.conn.discord_only and self.conn.split is None:
                self._begin_discord_only(self.conn)     # "discord_ready" follows
                return
            if self.conn.discord_only:
                self.conn.split.refresh(self.conn.gateway)
                detail = (f"Only Discord goes through {server.country}. Everything else "
                          "uses your normal connection.")
            else:
                detail = f"Your internet now goes through {server.country}."
            if value == "with errors":
                detail += " OpenVPN reported a setup problem; see the Log."
            self._connected(server, detail)
        elif kind == "discord_ready" and self.state == "connecting":
            worked, note = value
            if not worked:
                self._attempt_failed("Discord-only mode couldn't be set up: " + note, local=True)
                return
            detail = (f"Only Discord goes through {server.country}. Everything else uses "
                      "your normal connection.")
            if note == "dns":
                detail = "Connected, but a Windows setting couldn't be changed. See the Log."
            self._connected(server, detail)
        elif kind == "discord_check" and self.state == "connected":
            if not value:
                self.detail_var.set("Connected, but Discord didn't answer through this "
                                    "server. Try another server.")
        elif kind == "reconnecting" and self.state == "connected":
            self._set_state("reconnecting", "Reconnecting…",
                            "The connection dropped. Trying to get it back…")
        elif kind == "failed" and self.state == "connecting":
            reason, local = value
            self._attempt_failed(reason, local)
        elif kind == "exited":
            conn, self.conn = self.conn, None
            if conn.split is not None:
                self._stop_in_background(conn)     # take Discord-only mode down too
            if self.state == "connecting":
                self._attempt_failed("OpenVPN stopped (see the Log).", already_stopped=True,
                                     server=conn.server)
            elif self.state in ("connected", "reconnecting"):
                self._log("===== The connection was lost =====")
                if self.keep_trying and self.reconnect_var.get():
                    self.automatic = True
                    self._notify("Connection lost", "Free VPN is reconnecting\u2026",
                                 warning=True)
                    self._schedule_reconnect("Connection lost")
                else:
                    self._set_state("error", "Disconnected", "The connection to the server "
                                    "was lost. Press Quick Connect to connect again.")
                    self._check_ip()

    def _attempt_failed(self, reason: str, local: bool = False,
                        already_stopped: bool = False, server: Server | None = None) -> None:
        conn, self.conn = self.conn, None
        self._log(f"===== {reason} =====")
        if not local:
            self._forget(server or (conn.server if conn else None))
        if local:
            self.candidates = []
        if conn is not None and not already_stopped:
            self._stop_in_background(conn)
        if self.candidates:
            self.detail_var.set(f"{reason} Trying the next server\u2026")
            self._try_next()
        elif self.automatic and self.reconnect_var.get():
            self._schedule_reconnect("Couldn't reconnect")   # keep trying, more slowly
        else:
            hint = "" if local else " Try another server or country."
            self._set_state("error", "Couldn't connect", reason + hint)

    def _begin_discord_only(self, conn: VpnConnection) -> None:
        """The VPN is up; now point only Discord at it (takes a second or two)."""
        self.setting_up = True
        self.detail_var.set("Setting up Discord-only mode…")
        self.settings["split_dirty"] = True      # so a crash can be tidied up next start
        save_settings(self.settings)
        events = self.events
        conn.split = split = SplitTunnel(lambda text: events.put((conn.id, "log", text)))
        split.on_check = lambda ok: events.put((conn.id, "discord_check", ok))

        def work():
            try:
                result = split.start(conn.gateway)
            except Exception as exc:
                result = (False, short_error(exc))
            events.put((conn.id, "discord_ready", result))
        threading.Thread(target=work, daemon=True).start()

    def _clear_split_flag(self) -> None:
        if self.settings.get("split_dirty"):
            self.settings["split_dirty"] = False
            save_settings(self.settings)

    def _stop_in_background(self, conn: VpnConnection, then=None) -> None:
        self._pending_stops += 1
        split = conn.split

        def work():
            try:
                if split is not None:
                    split.stop()
                conn.stop()
            finally:
                self.events.put((0, "stopped", (then, split is not None)))
        threading.Thread(target=work, daemon=True).start()

    def disconnect(self) -> None:
        """Disconnect, or stop trying to reconnect."""
        self.auto_connect_pending = False
        self.keep_trying = self.automatic = False
        self._cancel_reconnect()
        self.session += 1
        self.candidates = []
        conn, self.conn = self.conn, None
        if conn is None:
            self._set_state("idle", "Not connected", "Disconnected.")
            return
        self._set_state("stopping", "Disconnecting…", "Closing the connection…")
        session = self.session

        def done():
            if session == self.session:
                self._set_state("idle", "Not connected", "Disconnected.")
                self._check_ip()
        self._stop_in_background(conn, done)

    def on_close(self) -> None:
        """The window's X button: ask, instead of closing straight away."""
        if self._closing or self._close_dialog is not None:
            return
        choice = self._ask_close()
        if choice == "minimize":
            self._keep_running()
        elif choice == "quit":
            self.quit()

    def _ask_close(self) -> str:
        """Returns "minimize", "quit" or "cancel"."""
        root, sk = self.root, self.skin
        px, c = sk.px, sk.c
        if root.state() == "iconic":
            root.deiconify()          # closed from the taskbar: show the question's owner
        vpn_on = self.conn is not None
        dialog = tk.Toplevel(root, background=c["surface"])
        self._close_dialog = dialog
        dialog.withdraw()
        dialog.title(APP_NAME)
        dialog.transient(root)
        dialog.resizable(False, False)
        choice = {"value": "cancel"}

        def choose(value):
            choice["value"] = value
            dialog.destroy()

        body = ttk.Frame(dialog, padding=px(22))
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Close Free VPN?", style="Brand.TLabel").pack(anchor="w")
        ttk.Label(body, style="Muted.TLabel", justify="left", wraplength=px(400),
                  text=("Your VPN is on. Keep Free VPN running in the background, or quit and "
                        "disconnect?" if vpn_on else
                        "Keep Free VPN running in the background, or quit?")
                  + (" It will be in the icons next to the clock."
                     if self.tray is not None and self.tray_var.get() else "")
                  ).pack(anchor="w", pady=(px(6), px(20)))
        row = ttk.Frame(body)
        row.pack(fill="x")
        keep = ttk.Button(row, text="Keep running", style="SmallPrimary.TButton",
                          command=lambda: choose("minimize"))
        leave = ttk.Button(row, text="Quit and disconnect" if vpn_on else "Quit",
                           style="SmallDanger.TButton", command=lambda: choose("quit"))
        cancel = ttk.Button(row, text="Cancel", command=lambda: choose("cancel"))
        cancel.pack(side="left", padx=(0, px(28)))
        keep.pack(side="right")
        leave.pack(side="right", padx=(0, px(8)))
        self._close_buttons = {"minimize": keep, "quit": leave, "cancel": cancel}
        dialog.bind("<Escape>", lambda e: choose("cancel"))
        dialog.bind("<Return>", lambda e: choose("minimize"))
        dialog.protocol("WM_DELETE_WINDOW", lambda: choose("cancel"))

        dialog.update_idletasks()     # work out its size, then centre it on the window
        x = root.winfo_rootx() + (root.winfo_width() - dialog.winfo_reqwidth()) // 2
        y = root.winfo_rooty() + (root.winfo_height() - dialog.winfo_reqheight()) // 3
        dialog.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        dialog.deiconify()
        set_dark_title_bar(dialog, sk.name == "dark")
        try:
            dialog.grab_set()         # the main window waits for an answer
        except tk.TclError:
            pass
        keep.focus_set()
        root.wait_window(dialog)
        self._close_dialog = None
        return choice["value"]

    def quit(self) -> None:
        """Disconnect cleanly, then exit."""
        if self._closing:
            return
        self._closing = True
        self._save_options()
        self._cancel_reconnect()
        if self.update_job is not None:
            self.root.after_cancel(self.update_job)
            self.update_job = None
        self._stop_show_listener()
        if self.tray is not None:
            self.tray.stop()
            self.tray = None
        self.session += 1
        self.candidates = []
        conn, self.conn = self.conn, None
        if conn is not None:
            self._set_state("stopping", "Disconnecting…",
                            "Closing the connection before exiting…")
            self._stop_in_background(conn)
        self._close_deadline = time.monotonic() + 15   # never hang on exit
        self._finish_close()

    def _finish_close(self) -> None:
        if self._pending_stops and time.monotonic() < self._close_deadline:
            self.root.after(100, self._finish_close)
        else:
            self.root.destroy()

    def report_error(self, exc_type, exc, tb) -> None:
        text = "".join(traceback.format_exception(exc_type, exc, tb))
        write_crash_log(text)
        try:
            self._log(text)
            messagebox.showerror(APP_NAME, f"Something went wrong:\n\n{exc}\n\nDetails are "
                                 "in the Log.", parent=self.root)
        except tk.TclError:
            pass


# --------------------------------------------------------------------------
# Start-up (Windows: admin rights, one copy at a time)
# --------------------------------------------------------------------------

def write_crash_log(text: str) -> None:
    try:
        with open(os.path.join(data_dir(), "error.log"), "a", encoding="utf-8") as f:
            f.write(time.strftime("\n[%Y-%m-%d %H:%M:%S]\n") + text)
    except OSError:
        pass


def is_admin() -> bool:
    if not IS_WINDOWS:
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """Show the Windows "allow this app to make changes?" prompt and restart
    elevated. Returns False if the user said no."""
    if getattr(sys, "frozen", False):
        exe, params = sys.executable, sys.argv[1:]
    else:
        exe, params = gui_python(), [os.path.abspath(sys.argv[0])] + sys.argv[1:]
    result = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", exe, subprocess.list2cmdline(params), None, 1)
    return int(result) > 32


_INSTANCE_MUTEX = None


def another_copy_running() -> bool:
    global _INSTANCE_MUTEX
    if not IS_WINDOWS:
        return False
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateMutexW.restype = wintypes.HANDLE
        k32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        _INSTANCE_MUTEX = k32.CreateMutexW(None, False, "Local\\FreeVPN-one-copy")
        return ctypes.get_last_error() == 183  # ERROR_ALREADY_EXISTS
    except Exception:
        return False


def show_message(text: str) -> None:
    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo(APP_NAME, text, parent=root)
    root.destroy()


def main() -> None:
    global PROCESS_GUARD
    if IS_WINDOWS:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)  # sharp text on HiDPI
        except Exception:
            pass
        if show_running_copy():
            return        # already running: its window was brought back instead
        if not is_admin():
            if not relaunch_as_admin():
                show_message("Free VPN needs administrator permission to route your "
                             "internet traffic through the VPN.\n\nStart it again and "
                             "choose “Yes” when Windows asks.")
            return
        if another_copy_running():
            if not show_running_copy():
                show_message("Free VPN is already running. Look for its window on the "
                             "taskbar.")
            return
        try:
            # Show our own icon on the taskbar instead of Python's.
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("FreeVPN.App")
        except Exception:
            pass
        PROCESS_GUARD = ProcessGuard()
    root = tk.Tk()
    if AUTOSTART_ARG in sys.argv[1:]:
        root.iconify()            # started at sign-in: open minimized, on the taskbar
    app = App(root)
    root.report_callback_exception = app.report_error
    root.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        details = traceback.format_exc()
        write_crash_log(details)
        try:
            show_message("Free VPN couldn't start:\n\n" + details[-1500:])
        except Exception:
            pass
        raise
