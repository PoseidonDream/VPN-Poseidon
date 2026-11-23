"""The whole app, driven through its window: connecting, failing over, reconnecting,
Discord-only mode, the tray, closing. A stand-in for openvpn (fake_openvpn.py) plays
the server side. Usage: run_gui_test.py <work folder> <FreeVPN.pyw> [screenshot tag]"""
import glob, importlib.machinery, os, subprocess, sys, tempfile, time, shutil
S = sys.argv[1]; APP = sys.argv[2]; TAG = sys.argv[3] if len(sys.argv) > 3 else "x"
HERE = os.path.dirname(os.path.abspath(__file__))


def isolate(folder):
    """Keep the app's settings and files for this run inside `folder`."""
    shutil.rmtree(folder, ignore_errors=True)
    os.makedirs(folder)
    os.environ["HOME"] = os.environ["APPDATA"] = folder


def offline_server_list(mod):
    """Use the saved server list in tests/fixtures (so tests don't depend on
    VPN Gate being reachable): put it where the app keeps its last download,
    and make the download itself fail at once."""
    shutil.copy(os.path.join(HERE, "fixtures", "servers.csv"), os.path.join(mod.data_dir(), "servers.csv"))
    mod.SERVER_LIST_URL = "http://127.0.0.1:9/"

isolate(os.path.join(S, "home-" + TAG))
os.environ.setdefault("FREEVPN_OPENVPN", os.path.join(HERE, "fake_openvpn.py"))   # an .exe on Windows
tempfile.tempdir = os.path.join(S, "tmp-" + TAG); shutil.rmtree(tempfile.tempdir, ignore_errors=True); os.makedirs(tempfile.tempdir)
mod = importlib.machinery.SourceFileLoader("freevpn", APP).load_module()
offline_server_list(mod)
CAN_SHOOT = shutil.which("import") is not None      # ImageMagick, for screenshots on Linux
import tkinter as tk, socket, struct, threading
results = []
commands = []
fake_result = [0, ""]
def fake_run(args, timeout=30):
    commands.append(list(args)); return tuple(fake_result)
errors_shown = []
mod.messagebox.showerror = lambda *a, **k: errors_shown.append(a)
mod.run_hidden = fake_run
mod.SPLIT_SUPPORTED = True
upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); upstream.bind(("127.0.0.1", 0))
ZONE = {"discord.com": ["127.0.0.1"], "gateway.discord.gg": ["162.159.130.234"], "frankfurt99.discord.media": ["35.214.1.2"]}
def dns_server():
    while True:
        try: data, addr = upstream.recvfrom(4096)
        except OSError: return
        n, t, e = mod.dns_question(data); ips = ZONE.get(n, []) if t == 1 else []
        rec = b"".join(b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes(int(x) for x in ip.split(".")) for ip in ips)
        upstream.sendto(data[:2] + struct.pack(">HHHHH", 0x8180, 1, len(ips), 0, 0) + data[12:e] + rec, addr)
threading.Thread(target=dns_server, daemon=True).start()
checker = socket.socket(); checker.bind(("127.0.0.1", 0)); checker.listen(5)
free = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); free.bind(("127.0.0.1", 0)); RELAY = free.getsockname()[1]; free.close()
mod.SPLIT_DNS_SERVERS = ("127.0.0.1",); mod.SPLIT_DNS_PORT = upstream.getsockname()[1]
mod.SPLIT_LISTEN_PORT = RELAY; mod.SPLIT_CHECK_PORT = checker.getsockname()[1]
def run_config(d, n): return open(os.path.join(d, "run%d" % n)).read()
def check(name, cond, extra=""):
    results.append((name, bool(cond))); print(("PASS " if cond else "FAIL ") + name, extra, flush=True)
def shot(name):
    root.update(); time.sleep(0.3); root.update()
    if not CAN_SHOOT: return
    subprocess.run(["import", "-window", "root", "-crop", f"{root.winfo_width()}x{root.winfo_height()}+{root.winfo_rootx()}+{root.winfo_rooty()}", os.path.join(S, f"{TAG}_{name}.png")], check=False)
def pump(sec, until=None):
    end = time.time() + sec
    while time.time() < end:
        root.update(); time.sleep(0.02)
        if until and until(): return True
    return bool(until and until())
def scenario(name, **modes):
    d = os.path.join(S, "state-" + TAG, name); shutil.rmtree(d, ignore_errors=True)
    for k in [k for k in os.environ if k.startswith("FAKE_MODE")]: del os.environ[k]
    os.environ["FAKE_STATE_DIR"] = d
    for k, v in modes.items(): os.environ["FAKE_MODE" + ("" if k == "all" else "_" + k[1:])] = v
    return d
def runs(d): return len(glob.glob(os.path.join(d, "run*")))
def graceful(d): return len(glob.glob(os.path.join(d, "graceful*")))
def leftovers(): return glob.glob(os.path.join(tempfile.tempdir, "freevpn-*"))

# ---- config sanitizer (no window needed) ----
evil = """client
dev tun
proto tcp
remote 1.2.3.4 443
cipher AES-128-CBC
script-security 2
up "C:\\\\Windows\\\\System32\\\\cmd.exe /c calc"
route-up evil.bat
plugin evil.dll
log C:\\\\Windows\\\\evil.log
tls-verify "cmd /c x"
auth-user-pass C:\\\\secret.txt
management 0.0.0.0 7505
remote 5.6.7.8 443;up=x
dev C:\\\\weird
<connection>
up evil2.bat
remote 9.9.9.9 1194
</connection>
<ca>
-----BEGIN CERTIFICATE-----
QUJDRA==
-----END CERTIFICATE-----
</ca>
"""
clean = mod.sanitize_config(evil)
bad = [w for w in ("script-security", "up ", "route-up", "plugin", "log ", "tls-verify", "auth-user-pass", "management", "evil", "9.9.9.9", "5.6.7.8", "weird", "connection") if w in clean]
check("sanitizer drops dangerous settings", not bad, str(bad))
check("sanitizer keeps the connection settings", all(w in clean for w in ("client", "dev tun", "proto tcp", "remote 1.2.3.4 443", "cipher AES-128-CBC", "<ca>", "QUJDRA==", "</ca>")))
for name, text in (("no certificate", "remote 1.2.3.4 443\n"), ("junk in certificate", "remote 1.2.3.4 443\n<ca>\n$(evil)\n</ca>\n"), ("unfinished block", "remote 1.2.3.4 443\n<ca>\nQUJD\n")):
    try: mod.sanitize_config(text); ok = False
    except ValueError: ok = True
    check("sanitizer rejects: " + name, ok)

class FakeTray:
    instances = []
    def __init__(self, on_command, menu_state, log):
        self.on_command, self.menu_state, self.log = on_command, menu_state, log
        self.updates, self.notes, self.stopped, self.files = [], [], False, None
        FakeTray.instances.append(self)
    def start(self, files): self.files = files; return True
    def update(self, kind, tip): self.updates.append((kind, tip))
    def notify(self, title, text, warning=False): self.notes.append((title, text, warning))
    def stop(self): self.stopped = True
mod.TRAY_SUPPORTED = True; mod.TrayIcon = FakeTray
mod.RECONNECT_DELAYS = (1, 1, 2)
root = tk.Tk(); root.geometry("+0+0")
app = mod.App(root)
tray = FakeTray.instances[0]
errors = []
root.report_callback_exception = lambda *a: (errors.append(a[1]), print("CALLBACK ERROR", repr(a[1]), flush=True))
print("Tk", root.tk.call("info", "patchlevel"), "scale", app.skin.scale, "window", root.winfo_width(), root.winfo_height(), flush=True)
check("starts in light theme off Windows", app.skin.name == "light")
check("T tray started with an icon file per state", app.tray is tray and sorted(tray.files) == ["busy", "error", "idle", "on"] and all(os.path.exists(f) for f in tray.files.values()))
check("server list loads", pump(40, lambda: len(app.servers) > 0), f"{len(app.servers)} servers; note={app.list_note.get()!r}")
raw_count = sum(1 for l in open(os.path.join(mod.data_dir(), "servers.csv"), encoding="utf-8") if l.count(",") > 10) - 1
check("every real server survives the sanitizer", len(app.servers) == raw_count, f"{len(app.servers)} of {raw_count}")
s0 = app.servers[0]
check("real config keeps what it needs", all(w in s0.config for w in ("dev tun", "proto ", "remote ", "cipher AES-128-CBC", "data-ciphers AES-128-CBC", "auth SHA1", "client", "<ca>", "<cert>", "<key>")) and "#" not in s0.config)
check("countries filled", len(app.country_labels) > 2, str(list(app.country_labels)[:4]))
check("table rows", len(app.tree.get_children()) == len(app.servers))
check("ip check finishes", pump(15, lambda: app.ip_var.get() != "Checking…"), app.ip_var.get())
shot("01_idle")
cfg = mod.build_config(s0, True)
check("config adds dco/dns lines", "disable-dco" in cfg and "block-outside-dns" in cfg and cfg.index("ignore-unknown-option disable-dco") < cfg.index("\ndisable-dco"))

# A: first two servers fail (TLS error), third connects
d = scenario("failover", m1="tls", m2="tls", all="ok")
app.primary_action(); pump(0.6); shot("02_connecting")
check("A button says Cancel while connecting", app.action_btn.cget("text") == "Cancel" and app.power.spin_job is not None)
check("A connects after failover", pump(30, lambda: app.state == "connected"), app.status_var.get() + " | " + app.detail_var.get())
check("A tried 3 servers", runs(d) == 3, f"runs={runs(d)}")
pump(3)
check("A failed ones stopped gracefully", graceful(d) == 2, f"graceful={graceful(d)}")
check("A only one temp dir (current)", len(leftovers()) == 1, str(leftovers()))
check("A sidebar shows server, clock, Disconnect", app.conn.server.host in app.server_var.get() and ":" in app.clock_var.get() and app.action_btn.cget("text") == "Disconnect" and app.power.spin_job is None, f"{app.server_var.get()} | {app.clock_var.get()}")
check("A connected row marked", "current" in app.tree.item(str(app.visible.index(app.conn.server)), "tags"))
shot("03_connected")
app.toggle_theme(); pump(0.3)
check("theme switches to dark and is saved", app.skin.name == "dark" and mod.load_settings()["theme"] == "dark")
shot("04_connected_dark")
app.show_tab("log"); shot("05_log_dark"); app.show_tab("servers")

# B: disconnect with the main button
app.primary_action()
check("B disconnects", pump(15, lambda: app.state == "idle"), app.status_var.get())
check("B graceful SIGTERM", graceful(d) == 3)
pump(1)
check("B temp files removed", not leftovers(), str(leftovers()))
check("B sidebar reset", app.server_var.get() == "—" and app.clock_var.get() == "—" and app.action_btn.cget("text") == "Quick Connect")
shot("06_idle_dark")

# C: hang with short timeout, failover off -> error after one try
mod.CONNECT_TIMEOUT = 2
app.failover_var.set(False)
d = scenario("hang", all="hang")
app.quick_connect(); pump(1.0); shot("07_connecting_dark")
check("C gives up", pump(15, lambda: app.state == "error"), app.status_var.get() + " | " + app.detail_var.get())
check("C tried only one", runs(d) == 1)
pump(2); check("C hung process stopped", graceful(d) == 1)
shot("08_failed_dark")
app.failover_var.set(True); mod.CONNECT_TIMEOUT = 30

# D: local driver problem -> no point trying other servers
d = scenario("nodriver", all="nodriver")
app.quick_connect()
check("D error", pump(15, lambda: app.state == "error"), app.detail_var.get())
pump(1.5)
check("D tried only one server", runs(d) == 1, f"runs={runs(d)}")
check("D message about adapter", "adapter" in app.detail_var.get())

# E: connection lost after connecting (auto-reconnect switched off)
app.reconnect_var.set(False)
d = scenario("die", all="die")
app.quick_connect()
check("E connected", pump(15, lambda: app.state == "connected"))
check("E reconnecting shown", pump(5, lambda: app.state == "reconnecting"), app.status_var.get())
check("E lost -> Disconnected", pump(10, lambda: app.state == "error" and app.status_var.get() == "Disconnected"), app.detail_var.get())
pump(2); check("E ...and stays disconnected when auto-reconnect is off", runs(d) == 1 and app.state == "error")
app.reconnect_var.set(True)

# R: auto-reconnect: same server first, keeps trying with pauses, Cancel stops it
d = scenario("reconnect", m1="die", all="ok")
app.quick_connect()
check("R connected", pump(15, lambda: app.state == "connected"))
first_server = app.conn.server; remote = lambda n: [l for l in open(os.path.join(d, "run%d" % n)).read().splitlines() if l.startswith("remote ")][0]
root.withdraw(); pump(0.3)
check("R connection lost -> waiting, with a countdown", pump(10, lambda: app.state == "waiting") and app.status_var.get() == "Connection lost" and "Trying again in" in app.detail_var.get(), app.detail_var.get())
check("R the tray warns while the window is hidden", any(n[0] == "Connection lost" and n[2] for n in tray.notes), str(tray.notes))
check("R Cancel button shown while waiting", app.action_btn.cget("text") == "Cancel")
check("R reconnects by itself", pump(20, lambda: app.state == "connected" and runs(d) == 2), f"runs={runs(d)} {app.status_var.get()}")
check("R ...to the same server first", remote(2) == remote(1), f"{remote(1)} / {remote(2)}")
check("R the tray says it's back", any(n[0] == "Reconnected" for n in tray.notes))
root.deiconify(); pump(0.3)
d = scenario("reconnect2", m1="die", m2="tls", m3="tls", m4="tls", m5="tls", m6="tls", all="ok")
app.quick_connect(); pump(15, lambda: app.state == "connected")
check("R2 a whole round fails -> waits, then tries again", pump(40, lambda: app.state == "waiting" and app.status_var.get() == "Couldn't reconnect"), f"{app.status_var.get()} runs={runs(d)}")
check("R2 ...and gets back on the next round", pump(40, lambda: app.state == "connected"), f"runs={runs(d)}")
check("R2 one round = up to 5 servers", runs(d) == 7, f"runs={runs(d)}")
d = scenario("reconnect3", m1="die", all="tls")
app.quick_connect(); pump(15, lambda: app.state == "connected")
pump(15, lambda: app.state == "waiting")
n_before = runs(d); app.primary_action()
check("R3 Cancel stops reconnecting for good", app.state == "idle" and app.reconnect_job is None)
pump(4); check("R3 ...no more attempts afterwards", runs(d) == n_before and app.state == "idle", f"{runs(d)} vs {n_before}")

# M: servers that worked are remembered and tried first
d = scenario("remember", all="ok")
app.country_var.set(mod.ANY_COUNTRY); app._on_country_change(); app._sort_by("ping")
low = [i for i, s in enumerate(app.visible) if not app._is_good(s)][-1]; target = app.visible[low]
app.tree.selection_set(str(low)); app.connect_selected()
check("M connected to a lower-ranked server", pump(15, lambda: app.state == "connected") and app.conn.server is target)
check("M it is remembered", mod.load_settings()["good_servers"][0] == f"{target.host}|{target.ip}")
check("M marked with a star in the list", any(app.tree.set(i, "host") == "\u2605 " + target.host for i in app.tree.get_children()))
app.disconnect(); pump(15, lambda: app.state == "idle"); app.quick_connect()
check("M Quick Connect tries it first", pump(15, lambda: app.state == "connected") and app.conn.server is target and "worked last time" not in app.detail_var.get())
app.disconnect(); pump(15, lambda: app.state == "idle")
d = scenario("remember2", m1="tls", all="ok")
app.quick_connect(); pump(20, lambda: app.state == "connected")
check("M a remembered server that fails is forgotten", f"{target.host}|{target.ip}" not in mod.load_settings()["good_servers"] and app.conn.server is not target)
app.disconnect(); pump(15, lambda: app.state == "idle")

# F: country filter + connect to a selected server, then switch servers while connected
app.toggle_theme(); pump(0.2)
check("theme back to light", app.skin.name == "light")
d = scenario("switch", all="ok")
label = [l for l in app.country_labels if l != mod.ANY_COUNTRY][0]
app.country_var.set(label); app._on_country_change()
country = app.country_labels[label]
check("F filter", all(s.country == country for s in app.filtered) and len(app.tree.get_children()) == len(app.filtered))
app._sort_by("ping")
pings = [s.ping if s.ping is not None else 10**9 for s in app.visible]
check("F sort by ping", pings == sorted(pings))
app.tree.selection_set("0"); app.connect_selected()
check("F connected to chosen", pump(15, lambda: app.state == "connected") and app.conn.server is app.visible[0])
first = app.conn
app.country_var.set(mod.ANY_COUNTRY); app._on_country_change()
app.tree.selection_set("1"); target = app.visible[1]; app.connect_selected()
check("F switched", pump(20, lambda: app.state == "connected" and app.conn is not first) and app.conn.server is target)
check("F old one stopped first", graceful(d) == 1 and runs(d) == 2)
check("F settings saved", mod.load_settings()["country"] == mod.ANY_COUNTRY)
app._set_hover_row("3"); root.update()
check("row hover tag", "hover" in app.tree.item("3", "tags") and "hover" not in app.tree.item("2", "tags"))

# I: Discord-only mode
app.disconnect(); pump(15, lambda: app.state == "idle"); pump(1)
check("I starts in Everything mode", app.mode == "all" and str(app.mode_buttons["all"].cget("style")) == "SegOn.TButton")
app.show_tab("settings"); shot("09_settings")
app.show_tab("servers")
app.set_mode("discord")
check("I mode switch saved and shown", mod.load_settings()["mode"] == "discord" and str(app.mode_buttons["discord"].cget("style")) == "SegOn.TButton" and app.state == "idle")
d = scenario("discord", all="ok"); commands.clear()
app.quick_connect()
check("I connects in Discord-only mode", pump(20, lambda: app.state == "connected"), app.status_var.get() + " | " + app.detail_var.get())
cfg = run_config(d, 1)
check("I OpenVPN told to leave the normal route alone", 'pull-filter ignore "redirect-gateway"' in cfg and "route 66.22.192.0 255.255.192.0" in cfg and "dhcp-option DNS" not in cfg)
check("I Windows DNS rule added for Discord", any("Add-DnsClientNrptRule" in c[-1] and "'.discord.gg'" in c[-1] for c in commands if "-Command" in c))
check("I gateway learned from OpenVPN", app.conn.gateway == "10.211.1.6" and app.conn.split.gateway == "10.211.1.6")
check("I status explains what is routed", "Only Discord" in app.detail_var.get() and app.conn.server.country in app.detail_var.get(), app.detail_var.get())
check("I crash-recovery flag set while on", mod.load_settings()["split_dirty"] is True)
pump(2)
check("I Discord check passed, no warning", "didn't answer" not in app.detail_var.get() and str(app.ip_label.cget("style")) == "InsetValue.TLabel", app.detail_var.get())
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.settimeout(4); q = mod.dns_query("frankfurt99.discord.media"); c.sendto(q, ("127.0.0.1", RELAY)); reply, _ = c.recvfrom(4096); c.close()
check("I voice server looked up through the relay and routed via the VPN", mod.dns_addresses(reply) == ["35.214.1.2"] and any(c[1:] == ["ADD", "35.214.1.2", "MASK", "255.255.255.255", "10.211.1.6", "METRIC", "1"] for c in commands))
pump(0.5); app.toggle_theme(); shot("10_discord_dark"); app.toggle_theme()
check("I log shows the steps", "Discord-only: the VPN gateway is 10.211.1.6" in app.log_text.get("1.0", "end") and "35.214.1.2 now goes through the VPN" in app.log_text.get("1.0", "end"))
# switch back to Everything while connected: reconnects to the same server the normal way
server = app.conn.server; first = app.conn; commands.clear()
app.set_mode("all")
check("I switching mode reconnects to the same server", pump(25, lambda: app.state == "connected" and app.conn is not first) and app.conn.server is server and not app.conn.discord_only, app.status_var.get())
check("I Everything-mode config is the normal one", "pull-filter" not in run_config(d, 2) and "route " not in run_config(d, 2))
pump(1)
check("I Discord-only cleaned up: DNS rule and route removed, flag cleared", any("Remove-DnsClientNrptRule" in c[-1] and "Add-" not in c[-1] for c in commands if "-Command" in c) and any(c[1] == "/c" and "DELETE 35.214.1.2" in c[2] for c in commands) and mod.load_settings()["split_dirty"] is False)
check("I Everything mode says so", "Your internet now goes through" in app.detail_var.get())
# OpenVPN dies while Discord-only is on -> still cleaned up
app.set_mode("discord"); pump(25, lambda: app.state == "connected" and app.conn.discord_only); pump(1); commands.clear()
app.reconnect_var.set(False)
app.conn.proc.kill()
check("I connection lost in Discord-only mode", pump(10, lambda: app.state == "error" and app.status_var.get() == "Disconnected"))
pump(2)
check("I ...and Discord-only was cleaned up anyway", any("Remove-DnsClientNrptRule" in c[-1] for c in commands if "-Command" in c) and mod.load_settings()["split_dirty"] is False and app._pending_stops == 0)
app.reconnect_var.set(True)
app.set_mode("all")

# K: start with Windows, auto-connect, and "already running" -> show window
import base64
app.disconnect(); pump(15, lambda: app.state == "idle"); pump(1)
app.show_tab("settings"); shot("12_settings")
check("K start-with-Windows off by default", not app.autostart_var.get() and mod.load_settings()["autostart"] is False)
commands.clear(); app.autostart_var.set(True); app._toggle_autostart()
check("K switch turned on: task registered, setting saved", pump(5, lambda: mod.load_settings()["autostart"] is True) and any(c[-2] == "-EncodedCommand" and "Register-ScheduledTask" in base64.b64decode(c[-1]).decode("utf-16-le") for c in commands))
fake_result[:] = [1, "Access is denied."]; app.autostart_var.set(False); app._toggle_autostart()
check("K a refused change is undone and explained", pump(5, lambda: errors_shown) and app.autostart_var.get() is True and mod.load_settings()["autostart"] is True and "Access is denied." in errors_shown[-1][1])
fake_result[:] = [0, ""]; app.autostart_var.set(False); app._toggle_autostart()
check("K switch turned off: task removed, setting saved", pump(5, lambda: mod.load_settings()["autostart"] is False) and "Unregister-ScheduledTask" in base64.b64decode(commands[-1][-1]).decode("utf-16-le"))
app.auto_connect_var.set(True); app._save_options()
check("K auto-connect setting saved", mod.load_settings()["auto_connect"] is True)
app.show_tab("servers")
d = scenario("autoconnect", all="ok")
mod.STARTUP_RETRY_MS = 300
app.auto_connect_pending = True; app._list_retries = 0
app.events.put((0, "servers", (True, (app.servers, "Offline · showing the list saved", False))))
check("K at sign-in with no internet yet: waits instead of connecting", pump(1.0, lambda: "Waiting for the internet" in app.detail_var.get()) and app.state == "idle" and runs(d) == 0)
check("K ...then connects once the list downloads", pump(60, lambda: app.state == "connected") and app._list_retries >= 1 and not app.auto_connect_pending, f"retries={app._list_retries}")
app.disconnect(); pump(15, lambda: app.state == "idle")
app.auto_connect_pending = True; app.quick_connect(); pump(15, lambda: app.state == "connected")
check("K a manual connect cancels the pending auto-connect", not app.auto_connect_pending)
app.disconnect(); pump(15, lambda: app.state == "idle")
app.auto_connect_var.set(False); app._save_options()
port_file = os.path.join(mod.data_dir(), "instance.port")
check("K the running copy can be found", os.path.exists(port_file))
root.iconify(); pump(0.5)
check("K window minimized", root.state() == "iconic", root.state())
found = []
threading.Thread(target=lambda: found.append(mod.show_running_copy()), daemon=True).start()
check("K a second start reaches the running copy and its window comes back", pump(5, lambda: found and root.state() == "normal") and found == [True], f"{found} {root.state()}")
open(port_file + ".bak", "w").write(open(port_file).read())
with open(port_file, "w") as f: f.write(str(checker.getsockname()[1]))   # a port that isn't ours
check("K a stale file pointing at another program is ignored", mod.show_running_copy() is False)
os.replace(port_file + ".bak", port_file)

# J: the X button asks first
d = scenario("closing", all="ok")
app.quick_connect(); pump(15, lambda: app.state == "connected")
minimized = []; orig_iconify = root.iconify; root.iconify = lambda: minimized.append(1)
hidden = []; orig_withdraw = root.withdraw; root.withdraw = lambda: hidden.append(1)
def answer(which, snap=None):
    def go():
        texts = " ".join(str(w.cget("text")) for w in app._close_dialog.winfo_children()[0].winfo_children() if w.winfo_class() == "TLabel")
        check("J dialog asks and says the VPN is on (%s)" % which, "Close Free VPN?" in texts and "Your VPN is on" in texts and app._close_buttons["quit"].cget("text") == "Quit and disconnect", texts)
        if snap and CAN_SHOOT:
            subprocess.run(["import", "-window", "root", os.path.join(S, f"{TAG}_{snap}.png")], check=False)
        app._close_buttons[which].invoke()
    root.after(700, go)
answer("cancel", "11_close_dialog"); app.on_close()
check("J Cancel: nothing happens", app.state == "connected" and not minimized and not app._closing and app._close_dialog is None)
answer("minimize"); app.on_close()
check("J Keep running: hidden next to the clock, VPN stays on", hidden == [1] and not minimized and app.state == "connected" and app.conn is not None and not app._closing)
check("J first time: the tray explains where it went", any("Still running here" in n[1] for n in tray.notes))
n_hints = sum("Still running here" in n[1] for n in tray.notes)
answer("minimize"); app.on_close()
check("J ...only the first time", sum("Still running here" in n[1] for n in tray.notes) == n_hints)
app.tray_var.set(False); app._save_options()
answer("minimize"); app.on_close()
check("J tray switch off: minimized to the taskbar instead (Alt+Tab)", minimized == [1])
app.tray_var.set(True); app._save_options()
root.iconify = orig_iconify; root.withdraw = orig_withdraw
check("T tray icon follows the state", tray.updates[-1][0] == "on" and app.conn.server.country in tray.updates[-1][1] and "everything" in tray.updates[-1][1], str(tray.updates[-1]))
check("T tray menu offers Disconnect while connected", tray.menu_state() == ("Disconnect", True))
root.withdraw(); pump(0.3); tray.on_command("open")
check("T clicking the icon brings the window back", pump(3, lambda: root.state() == "normal"))
tray.on_command("toggle")
check("T menu Disconnect works", pump(15, lambda: app.state == "idle"))
check("T menu then offers Connect", tray.menu_state() == ("Connect", True) and tray.updates[-1][0] == "idle")
tray.on_command("toggle")
check("T menu Connect works", pump(20, lambda: app.state == "connected"))

# H: a broken event must not stop the app from handling later ones
app.events.put((0, "servers", "garbage"))
pump(0.5)
check("H bad event was reported, not swallowed", len(errors) == 1)
errors.clear()

# G: closing the window while connected disconnects cleanly
destroyed = []
orig = root.destroy
root.destroy = lambda: destroyed.append(1)
stops_before = graceful(d)
answer("quit"); app.on_close()
check("G Quit: disconnects cleanly, then closes (events still flowing after H)", pump(15, lambda: destroyed) and graceful(d) == stops_before + 1 and app._closing, f"graceful={graceful(d)}")
root.destroy = orig
check("no unexpected errors", not errors, str(errors))
check("quitting removes the running-copy file", not os.path.exists(port_file))
check("T quitting removes the tray icon", tray.stopped and app.tray is None)
print("\n%d/%d passed" % (sum(ok for _, ok in results), len(results)))
root.destroy()
sys.exit(0 if all(ok for _, ok in results) else 1)
