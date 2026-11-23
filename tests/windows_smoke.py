"""Checks of Free VPN's Windows-only parts, on real Windows, with administrator
rights (GitHub's Windows machines have them). Everything it changes is undone
at the end. It doesn't connect to a VPN.

Usage: python -I tests/windows_smoke.py FreeVPN.pyw
"""
import importlib.machinery
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time

APP = os.path.abspath(sys.argv[1])
HERE = os.path.dirname(os.path.abspath(__file__))
WORK = tempfile.mkdtemp(prefix="freevpn-smoke-")
os.environ["APPDATA"] = WORK                        # keep the app's files in here
mod = importlib.machinery.SourceFileLoader("freevpn", APP).load_module()
assert mod.IS_WINDOWS, "run this on Windows"

results = []


def check(name, ok, extra=""):
    results.append((name, bool(ok)))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{extra}]" if extra else ""), flush=True)


def skip(name, why):
    print(f"SKIP {name}  [{why}]", flush=True)


def powershell(script, timeout=60):
    done = subprocess.run([mod.POWERSHELL_EXE, "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, timeout=timeout)
    return done.returncode, (done.stdout + done.stderr).strip()


def run_child(code, timeout=60):
    """Run Python code in a separate process (with the app module loaded as `mod`)."""
    script = os.path.join(WORK, "child.py")
    with open(script, "w", encoding="utf-8") as f:
        f.write("import importlib.machinery, os, sys, time, subprocess\n"
                f"os.environ['APPDATA'] = {WORK!r}\n"
                f"mod = importlib.machinery.SourceFileLoader('freevpn', {APP!r}).load_module()\n"
                + textwrap.dedent(code))
    return subprocess.run([sys.executable, "-I", script], capture_output=True, text=True,
                          timeout=timeout)


def process_alive(pid):
    out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"], capture_output=True,
                         text=True).stdout
    return str(pid) in out


print(f"Python {sys.version.split()[0]} on {sys.platform}; admin: {mod.is_admin()}", flush=True)
check("running with administrator rights", mod.is_admin())

# ---- who am I --------------------------------------------------------------
user = mod.current_user()
check("current_user() gives DOMAIN\\name", "\\" in user and len(user) > 2, user)

# ---- one copy at a time ----------------------------------------------------
check("first copy: no other copy running", mod.another_copy_running() is False)
child = run_child("print('OTHER' if mod.another_copy_running() else 'ALONE')")
check("second copy sees the first one", child.stdout.strip() == "OTHER", child.stdout + child.stderr)

# ---- openvpn is closed if the app dies (job object) ---------------------------
child = run_child("""
    guard = mod.ProcessGuard()
    p = subprocess.Popen(["ping", "-n", "120", "127.0.0.1"], stdout=subprocess.DEVNULL,
                         creationflags=subprocess.CREATE_NO_WINDOW)
    guard.add(p)
    print(p.pid, bool(guard.handle), flush=True)
    os._exit(0)      # like a crash: no clean-up code runs
""")
try:
    pid, had_guard = child.stdout.split()
    pid = int(pid)
    deadline = time.time() + 10
    while process_alive(pid) and time.time() < deadline:
        time.sleep(0.3)
    check("a crash also closes the program the app started", had_guard == "True" and not process_alive(pid),
          f"guard={had_guard}")
    if process_alive(pid):
        subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
except ValueError:
    check("a crash also closes the program the app started", False, child.stdout + child.stderr)

# ---- start with Windows (Task Scheduler) -------------------------------------
pythonw = mod.gui_python()
mod.autostart_command = lambda: (pythonw, f'"{APP}" --startup', os.path.dirname(APP))
code, out = mod.set_autostart(True)
check("start with Windows: task created", code == 0, out)
code, out = powershell(
    "$t = Get-ScheduledTask -TaskName 'FreeVPN-Autostart'; "
    "$s = $t.Settings; $p = $t.Principal; $a = $t.Actions[0]; $g = $t.Triggers[0]; "
    "Write-Output ('runlevel=' + $p.RunLevel); Write-Output ('logon=' + $p.LogonType); "
    "Write-Output ('user=' + $p.UserId); Write-Output ('battery=' + $s.DisallowStartIfOnBatteries); "
    "Write-Output ('stopbattery=' + $s.StopIfGoingOnBatteries); "
    "Write-Output ('limit=' + $s.ExecutionTimeLimit); Write-Output ('prio=' + $s.Priority); "
    "Write-Output ('exe=' + $a.Execute); Write-Output ('args=' + $a.Arguments); "
    "Write-Output ('delay=' + $g.Delay); Write-Output ('trigger=' + $g.CimClass.CimClassName)")
info = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
check("task: highest rights, this user, interactive", info.get("runlevel") == "Highest" and
      info.get("logon") == "Interactive" and info.get("user", "").lower() in user.lower(), out)
check("task: keeps running on battery, no time limit, normal priority",
      info.get("battery") == "False" and info.get("stopbattery") == "False" and
      info.get("limit") == "PT0S" and info.get("prio") == "5", out)
check("task: starts this app minimized, 10 s after sign-in",
      info.get("exe", "").lower() == pythonw.lower() and info.get("args") == f'"{APP}" --startup'
      and info.get("delay") == "PT10S" and info.get("trigger") == "MSFT_TaskLogonTrigger", out)
code, out = mod.set_autostart(True)
check("start with Windows: updating it again works", code == 0, out)
code, out = mod.set_autostart(False)
code2, out2 = powershell("if (Get-ScheduledTask -TaskName 'FreeVPN-Autostart' "
                         "-ErrorAction SilentlyContinue) { 'still there' } else { 'gone' }")
check("start with Windows: task removed", code == 0 and out2 == "gone", out + out2)
code, out = mod.set_autostart(False)
check("start with Windows: removing when already gone is fine", code == 0, out)

# ---- Discord-only: the Windows DNS rule --------------------------------------
code, out = mod.add_discord_dns_rule(["127.0.0.1"])
check("Discord-only: DNS rule added", code == 0, out)
code, out = powershell("Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'FreeVPN' } | "
                       "ForEach-Object { ($_.Namespace -join ',') + ' -> ' + ($_.NameServers -join ',') }")
check("Discord-only: rule covers Discord's names and points at the relay",
      ".discord.com" in out and ".discord.media" in out and "-> 127.0.0.1" in out, out[:300])
code, out = mod.remove_discord_dns_rule()
code2, out2 = powershell("@(Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'FreeVPN' }).Count")
check("Discord-only: DNS rule removed", code == 0 and out2.strip() == "0", out + out2)


# ---- Discord-only, for real: relay + rule + routes (through the normal gateway) ----
def default_gateway():
    code, out = powershell("(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
                           "Sort-Object RouteMetric | Select-Object -First 1).NextHop")
    return out.strip() if code == 0 and re.match(r"^\d+\.\d+\.\d+\.\d+$", out.strip()) else None


gateway = default_gateway()
if gateway is None:
    skip("Discord-only end to end", "no IPv4 default gateway")
else:
    logs, checks = [], []
    st = mod.SplitTunnel(logs.append)
    st.on_check = checks.append
    ok, note = st.start(gateway)
    relay = st.sock is not None
    check("Discord-only end to end: set up", ok and note == "", f"{note}; relay={relay}")
    name = "discord-attachments-uploads-prd.storage.googleapis.com"   # outside the fixed ranges
    code, out = powershell(f"(Resolve-DnsName -Name '{name}' -Type A -DnsOnly -ErrorAction Stop | "
                           "Where-Object { $_.Type -eq 'A' }).IPAddress")
    addresses = [a for a in out.split() if re.match(r"^\d+\.\d+\.\d+\.\d+$", a)]
    check("Discord-only end to end: Windows looks Discord names up through the app", code == 0 and addresses, out[:200])
    time.sleep(1)
    routed = [a for a in addresses if a in st.routed]
    code, table = powershell("route print -4")
    check("Discord-only end to end: those addresses were routed before the answer arrived",
          routed and all(a in table for a in routed), f"answer={addresses} routed={sorted(st.routed)}")
    code, out = powershell("(Resolve-DnsName -Name 'example.com' -Type A -DnsOnly -ErrorAction Stop)"
                           ".Count -gt 0")
    check("Discord-only end to end: other names still work normally", out.strip() == "True", out)
    deadline = time.time() + 20
    while not checks and time.time() < deadline:
        time.sleep(0.5)
    check("Discord-only end to end: Discord answers", checks == [True], str(checks))
    st.stop()
    code, table = powershell("route print -4")
    code2, out2 = powershell("@(Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'FreeVPN' }).Count")
    check("Discord-only end to end: everything undone afterwards",
          not any(a in table for a in routed) and out2.strip() == "0", out2)
    print("\n".join("    log: " + line for line in logs), flush=True)

# ---- the icon next to the clock ----------------------------------------------
import tkinter as tk  # noqa: E402

root = tk.Tk()
root.withdraw()
commands = []
files = mod.make_tray_icons(os.path.join(WORK, "icons"))
tray = mod.TrayIcon(commands.append, lambda: ("Connect", True), print)
real = tray.start(files)
if not real:
    skip("tray icon shown by Windows", "no notification area on this machine; testing the rest")
    tray = mod.TrayIcon(commands.append, lambda: ("Connect", True), print)
    tray._add = lambda: setattr(tray, "added", True) or True    # pretend the shell took it
    real_started = tray.start(files)
else:
    real_started = True
    check("tray icon shown by Windows", True)
check("tray: hidden window and icons created", real_started and tray.hwnd and
      set(tray.icons) == {"idle", "busy", "on", "error"})


def pump(seconds, until=None):
    end = time.time() + seconds
    while time.time() < end:
        root.update()
        if until and until():
            return True
        time.sleep(0.02)
    return bool(until and until())


api = tray.api
api.PostMessageW(tray.hwnd, tray.WM_TRAY, 1, 0x0202)            # a left click on the icon
check("tray: a click reaches the app through Tk's event loop", pump(3, lambda: commands == ["open"]),
      str(commands))
tray.update("on", "Free VPN: Connected (test)")
tray.notify("Free VPN", "Test message", warning=False)
check("tray: icon and tooltip change without errors", tray.kind == "on")


tray.stop()
check("tray: removed cleanly", tray.hwnd is None and not tray.icons)
root.destroy()

# The right-click menu waits for a choice, so try it in a separate process that
# can be stopped if it hangs; Escape / "cancel mode" should close the menu.
try:
    child = run_child(f"""
        import threading, tkinter as tk
        root = tk.Tk(); root.withdraw()
        tray = mod.TrayIcon(print, lambda: ("Disconnect", True), print)
        if not tray.start(mod.make_tray_icons(os.path.join({WORK!r}, "icons2"))):
            tray = mod.TrayIcon(print, lambda: ("Disconnect", True), print)
            tray._add = lambda: setattr(tray, "added", True) or True
            tray.start(mod.make_tray_icons(os.path.join({WORK!r}, "icons2")))
        api = tray.api
        def close_menu():
            time.sleep(2)
            for _ in range(3):
                api.PostMessageW(tray.hwnd, 0x0100, 0x1B, 0)    # Escape key
                api.PostMessageW(tray.hwnd, 0x001F, 0, 0)       # WM_CANCELMODE
                time.sleep(1)
        threading.Thread(target=close_menu, daemon=True).start()
        api.PostMessageW(tray.hwnd, tray.WM_TRAY, 1, 0x0205)    # a right click
        end = time.time() + 6
        while time.time() < end:
            root.update(); time.sleep(0.02)
        tray.stop()
        print("MENU-CLOSED", flush=True)
    """, timeout=60)
    check("tray: right-click menu opens and closes without hanging",
          "MENU-CLOSED" in child.stdout, (child.stdout + child.stderr)[-300:])
except subprocess.TimeoutExpired:
    check("tray: right-click menu opens and closes without hanging", False, "it hung")

# ---- summary -------------------------------------------------------------------
shutil.rmtree(WORK, ignore_errors=True)
failed = [name for name, ok in results if not ok]
print(f"\n{len(results) - len(failed)}/{len(results)} passed", flush=True)
sys.exit(1 if failed else 0)
