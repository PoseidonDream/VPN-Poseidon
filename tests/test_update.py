"""Updates: asking GitHub, downloading and checking the new version, the helper
that swaps it in, and the window's part. A local web server plays GitHub.
Usage: test_update.py <work folder> <FreeVPN.pyw>   (needs Tk and a display)"""
import base64, http.server, importlib.machinery, json, os, re, shutil, socketserver, sys, tempfile, threading, time
S, APP = sys.argv[1], os.path.abspath(sys.argv[2])
HERE = os.path.dirname(os.path.abspath(__file__))
home = os.path.join(S, "home-update"); shutil.rmtree(home, ignore_errors=True); os.makedirs(home)
os.environ["HOME"] = os.environ["APPDATA"] = home
mod = importlib.machinery.SourceFileLoader("freevpn", APP).load_module()
shutil.copy(os.path.join(HERE, "fixtures", "servers.csv"), os.path.join(mod.data_dir(), "servers.csv"))
mod.SERVER_LIST_URL = mod.IP_CHECK_URL = "http://127.0.0.1:9/"
results = []
def check(name, cond, extra=""):
    results.append(bool(cond)); print(("PASS " if cond else "FAIL ") + name, extra, flush=True)

# ---- versions ----
check("newer versions are recognised", all(mod.is_newer(a, b) for a, b in [("1.5", "1.4"), ("1.10", "1.9"), ("v2", "1.9.9"), ("1.4.1", "1.4")]))
check("same or older versions are not", not any(mod.is_newer(a, b) for a, b in [("1.4", "1.4"), ("1.3", "1.4"), ("v1.4.0", "1.4"), ("garbage", "1.4"), ("", "1.4")]))

# ---- a fake GitHub ----
source = open(APP, encoding="utf-8").read()
NEW = re.sub(r'^APP_VERSION = "[^"]+"', 'APP_VERSION = "9.9"', source, count=1, flags=re.M).encode("utf-8")
files = {"/download/v9.9/FreeVPN.pyw": NEW, "/download/v9.9/FreeVPN.exe": b"MZ" + b"\0" * (2 * 1024 * 1024)}
release = {}
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == "/latest":
            body = json.dumps(release).encode()
        elif self.path in files:
            body = files[self.path]
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler); server.daemon_threads = True
threading.Thread(target=server.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{server.server_address[1]}"
mod.UPDATE_API = base + "/latest"; mod.UPDATE_DOWNLOAD_PREFIX = base + "/download/"
def make_release(tag="v9.9", name="FreeVPN.pyw", url=None, size=None, **extra):
    release.clear()
    release.update({"tag_name": tag, "html_url": base + "/page", "draft": False, "prerelease": False, "assets": [
        {"name": name, "browser_download_url": url or f"{base}/download/v9.9/{name}", "size": len(files[f"/download/v9.9/{name}"]) if size is None else size}]}, **extra)

make_release()
u = mod.check_for_update()
check("a newer release is found, with its download", u and u["version"] == "9.9" and u["url"].endswith("/FreeVPN.pyw") and u["size"] == len(NEW), str(u))
make_release(tag="v" + mod.APP_VERSION); check("the same version: nothing to do", mod.check_for_update() is None)
make_release(prerelease=True); check("test releases are ignored", mod.check_for_update() is None)
make_release(draft=True); check("unfinished releases are ignored", mod.check_for_update() is None)
make_release(name="FreeVPN.exe"); check("no file for this kind of copy: nothing to do", mod.check_for_update() is None)
make_release(url="https://evil.example/FreeVPN.pyw"); check("downloads from anywhere else are refused", mod.check_for_update() is None)

folder = tempfile.mkdtemp(dir=S)
make_release(); u = mod.check_for_update()
path = mod.download_update(u, folder)
check("download: saved as FreeVPN.pyw.new and identical", path == os.path.join(folder, "FreeVPN.pyw.new") and open(path, "rb").read() == NEW)
def refused(update, label):
    try: mod.download_update(update, folder); ok = False
    except Exception as exc: ok = True; label += f" ({exc})"
    check("download refused: " + label, ok)
refused(dict(u, size=len(NEW) + 5), "incomplete")
files["/download/v9.9/broken.pyw"] = NEW[:len(NEW) // 2]
refused(dict(u, url=base + "/download/v9.9/broken.pyw", size=0), "damaged file")
refused(dict(u, version="9.8"), "different version inside")
mod.update_file_name = lambda: "FreeVPN.exe"
p = mod.download_update({"version": "9.9", "url": base + "/download/v9.9/FreeVPN.exe", "size": 0}, folder)
check("download (.exe copy): a Windows program is accepted", p.endswith("FreeVPN.exe.new"))
files["/download/v9.9/fake.exe"] = b"<html>not a program</html>" * 50000
refused({"version": "9.9", "url": base + "/download/v9.9/fake.exe", "size": 0}, "not a Windows program")
mod.update_file_name = lambda: "FreeVPN.pyw"

# ---- the helper ----
def ps_strings(script):
    out, i, code = [], 0, ""
    while i < len(script):
        if script[i] == "'":
            out.append(("code", code)); code = ""; j = i + 1; val = ""
            while True:
                if script[j] == "'":
                    if script[j + 1:j + 2] == "'": val += "'"; j += 2; continue
                    break
                val += script[j]; j += 1
            out.append(("str", val)); i = j + 1
        else: code += script[i]; i += 1
    out.append(("code", code)); return out
new_f, target, prog, args, fold = r"C:\Users\Ana O'Neil\Free VPN\FreeVPN.pyw.new", r"C:\Users\Ana O'Neil\Free VPN\FreeVPN.pyw", r"C:\Py\pythonw.exe", '"C:\\Users\\Ana O\'Neil\\Free VPN\\FreeVPN.pyw" --updated --resume', r"C:\Users\Ana O'Neil\Free VPN"
cmd = mod.update_helper_command(new_f, target, prog, args, fold, 4321)
script = base64.b64decode(cmd[-1]).decode("utf-16-le"); parts = ps_strings(script)
codes = "".join(t for k, t in parts if k == "code"); strings = [t for k, t in parts if k == "str"]
check("helper: hidden PowerShell with an encoded script", cmd[-2] == "-EncodedCommand" and "-NoProfile" in cmd)
check("helper: waits for this app to close first", "Wait-Process -Id 4321 -Timeout 90" in codes)
check("helper: moves the new file over the old one (retrying), then starts it",
      "Move-Item -LiteralPath  -Destination  -Force" in codes and "Start-Process -FilePath  -ArgumentList  -WorkingDirectory " in codes
      and strings[1:6] == [new_f, target, prog, args, fold] and codes.index("Move-Item") < codes.index("Start-Process"), str(strings))
check("helper: braces balanced", codes.count("{") == codes.count("}"))

# ---- the window ----
import tkinter as tk
make_release()
mod.UPDATE_FIRST_CHECK_MS = 300
fake_target = os.path.join(folder, "FreeVPN.pyw"); shutil.copy(APP, fake_target)
mod.this_program_file = lambda: fake_target
helpers = []; mod.start_update_helper = helpers.append
os.environ.setdefault("FREEVPN_OPENVPN", os.path.join(HERE, "fake_openvpn.py"))
os.environ["FAKE_STATE_DIR"] = os.path.join(S, "state-update"); shutil.rmtree(os.environ["FAKE_STATE_DIR"], ignore_errors=True); os.environ["FAKE_MODE"] = "ok"
mod.TRAY_SUPPORTED = False
def pump(sec, until=None):
    end = time.time() + sec
    while time.time() < end:
        root.update(); time.sleep(0.02)
        if until and until(): return True
    return bool(until and until())
root = tk.Tk(); app = mod.App(root)
check("window: the update is offered", pump(10, lambda: app.update_banner.winfo_ismapped()) and app.update_title.get() == "Free VPN 9.9 is available", app.update_title.get())
app.show_tab("settings"); app.check_update(manual=True)
check("window: Settings > Check now says so too", pump(10, lambda: "9.9 is available" in app.update_status.get()), app.update_status.get())
app.show_tab("servers")
app.update_later_btn.invoke(); pump(0.3)
check("window: Not now hides it", not app.update_banner.winfo_ismapped())
app.check_update(manual=True); pump(10, lambda: app.update_banner.winfo_ismapped())
pump(5, lambda: app.servers)
app.quick_connect(); check("window: connected before updating", pump(20, lambda: app.state == "connected"))
destroyed = []; root.destroy = lambda: destroyed.append(1)
app.update_now_btn.invoke()
check("window: Update now downloads, starts the helper and closes", pump(20, lambda: destroyed) and len(helpers) == 1)
check("window: the new version sits next to the old one", open(fake_target + ".new", "rb").read() == NEW)
script = base64.b64decode(helpers[0][-1]).decode("utf-16-le"); strings = [t for k, t in ps_strings(script) if k == "str"]
check("window: the helper restarts it with --updated --resume (it was connected)", strings[1] == fake_target + ".new" and strings[2] == fake_target and strings[4] == mod.subprocess.list2cmdline([fake_target, "--updated", "--resume"]), str(strings[1:6]))
check("window: disconnected cleanly before closing", app.conn is None and app._closing)
tk.Tk.destroy(root)

# a damaged download is reported, nothing is installed
helpers.clear(); files["/download/v9.9/FreeVPN.pyw"] = NEW[:1000]
root = tk.Tk(); app = mod.App(root)
pump(10, lambda: app.update_banner.winfo_ismapped()); app.update_now_btn.invoke()
check("window: a bad download is reported, nothing installed", pump(10, lambda: "couldn't be downloaded" in app.update_title.get()) and not helpers and str(app.update_now_btn.state()) in ("()", "('active',)", "('focus',)") or "disabled" not in app.update_now_btn.state(), app.update_title.get())
root.destroy(); files["/download/v9.9/FreeVPN.pyw"] = NEW

# the restarted copy
sys.argv[1:] = [mod.UPDATED_ARG, mod.RESUME_ARG]
root = tk.Tk(); app = mod.App(root); pump(0.3)
check("restarted copy: says it was updated (banner with What's new / OK)", app.update_banner.winfo_ismapped() and app.update_title.get() == f"Free VPN was updated to version {mod.APP_VERSION}" and not app.update_now_btn.winfo_ismapped() and app.update_later_btn.cget("text") == "OK", app.update_title.get())
check("restarted copy: reconnects straight away, with the saved list", pump(20, lambda: app.state == "connected") and app._list_retries == 0, app.status_var.get())
check("restarted copy: the banner stays while it reconnects", app.update_banner.winfo_ismapped())
app.update_later_btn.invoke(); pump(0.2); check("restarted copy: OK closes it", not app.update_banner.winfo_ismapped())
app.disconnect(); pump(10, lambda: app.state == "idle"); root.destroy()
server.shutdown()
print("\n%d/%d passed" % (sum(results), len(results))); sys.exit(0 if all(results) else 1)
