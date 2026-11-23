"""Started at sign-in: the window opens minimized; a second start brings it back."""
import importlib.machinery, os, shutil, sys, threading, time
S = sys.argv[1]
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

isolate(os.path.join(S, "home-startmin"))
mod = importlib.machinery.SourceFileLoader("freevpn", sys.argv[2]).load_module()
offline_server_list(mod)
mod.run_hidden = lambda a, timeout=30: (0, "")
import tkinter as tk
results = []
def check(name, cond, extra=""):
    results.append(bool(cond)); print(("PASS " if cond else "FAIL ") + name, extra, flush=True)
def pump(sec, until=None):
    end = time.time() + sec
    while time.time() < end:
        root.update(); time.sleep(0.02)
        if until and until(): return True
    return bool(until and until())
root = tk.Tk()
sys.argv[1:] = [mod.AUTOSTART_ARG]
if mod.AUTOSTART_ARG in sys.argv[1:]:   # same as main()
    root.iconify()
app = mod.App(root); pump(3)
check("opens minimized when started at sign-in", root.state() == "iconic", root.state())
found = []
threading.Thread(target=lambda: found.append(mod.show_running_copy()), daemon=True).start()
check("starting it again brings the window back", pump(5, lambda: found and root.state() == "normal") and found == [True], f"{found} {root.state()}")
pump(0.5)
root.iconify(); pump(1)
check("minimize from a normal window (Keep running)", root.state() == "iconic", root.state())
app.show_window(); pump(1)
check("and back again", root.state() == "normal" and root.attributes("-topmost") in (0, False, "0"))
root.destroy()
print("%d/%d passed" % (sum(results), len(results))); sys.exit(0 if all(results) else 1)
