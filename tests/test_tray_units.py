"""Tray icon pieces that can be checked without Windows."""
import ctypes, importlib.machinery, os, shutil, struct, sys, tempfile
mod = importlib.machinery.SourceFileLoader("freevpn", sys.argv[1]).load_module()
results = []
def check(name, cond, extra=""):
    results.append(bool(cond)); print(("PASS " if cond else "FAIL ") + name, extra, flush=True)
folder = tempfile.mkdtemp()
files = mod.make_tray_icons(folder)
check("one .ico per state", sorted(files) == ["busy", "error", "idle", "on"] and all(os.path.getsize(p) > 200 for p in files.values()))
data = open(files["on"], "rb").read()
reserved, kind, count = struct.unpack("<HHH", data[:6])
check(".ico header", (reserved, kind, count) == (0, 1, len(mod.TRAY_SIZES)))
ok = True; sizes = []
for i in range(count):
    w, h, colors, res, planes, bits, size, offset = struct.unpack("<BBBBHHII", data[6 + 16 * i: 22 + 16 * i])
    png = data[offset:offset + size]
    pw, ph = struct.unpack(">II", png[16:24])
    sizes.append(w); ok &= png[:8] == b"\x89PNG\r\n\x1a\n" and (pw, ph) == (w, h) and planes == 1 and bits == 32 and offset + size <= len(data)
check(".ico entries point at valid PNGs of the right size", ok and sizes == list(mod.TRAY_SIZES), str(sizes))
art = mod.PowerArt(16, 16 * 0.47, 0.44); px = art.rgba([(mod.disc(16 * 0.47), "#1aa550")], "#ffffff")
centre = px[(8 * 16 + 8) * 4:(8 * 16 + 8) * 4 + 4]; corner = px[0:4]
check("16px icon: corner transparent, centre opaque", corner[3] == 0 and centre[3] == 255, f"{corner} {centre}")
# Windows x64 structure sizes, rebuilt here with Windows' type sizes (WCHAR=2, handles=8)
W, H, U, D = ctypes.c_uint16, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32
class GUID(ctypes.Structure): _fields_ = [("a", D), ("b", ctypes.c_uint16), ("c", ctypes.c_uint16), ("d", ctypes.c_ubyte * 8)]
class NID(ctypes.Structure): _fields_ = [("cbSize", D), ("hWnd", H), ("uID", U), ("uFlags", U), ("uCallbackMessage", U), ("hIcon", H), ("szTip", W * 128), ("dwState", D), ("dwStateMask", D), ("szInfo", W * 256), ("uVersion", U), ("szInfoTitle", W * 64), ("dwInfoFlags", D), ("guidItem", GUID), ("hBalloonIcon", H)]
class WC(ctypes.Structure): _fields_ = [("style", U), ("proc", H), ("a", ctypes.c_int), ("b", ctypes.c_int), ("inst", H), ("icon", H), ("cur", H), ("br", H), ("menu", H), ("cls", H)]
check("NOTIFYICONDATAW layout is 976 bytes (Windows x64 value)", ctypes.sizeof(NID) == 976, str(ctypes.sizeof(NID)))
check("WNDCLASSW layout is 72 bytes (Windows x64 value)", ctypes.sizeof(WC) == 72, str(ctypes.sizeof(WC)))
src = open(sys.argv[1], encoding="utf-8").read()
tray_src = src[src.index("class NOTIFYICONDATAW"):src.index("user32 = ctypes.WinDLL")]
check("app's NOTIFYICONDATAW fields match the reference order", [f[0] for f in NID._fields_ if f[0] != "guidItem"] == [n for n in ("cbSize", "hWnd", "uID", "uFlags", "uCallbackMessage", "hIcon", "szTip", "dwState", "dwStateMask", "szInfo", "uVersion", "szInfoTitle", "dwInfoFlags", "hBalloonIcon") if f'("{n}"' in tray_src] and '("szTip", w.WCHAR * 128)' in tray_src and '("szInfo", w.WCHAR * 256)' in tray_src and '("szInfoTitle", w.WCHAR * 64)' in tray_src)
shutil.rmtree(folder)
print("\n%d/%d passed" % (sum(results), len(results))); sys.exit(0 if all(results) else 1)
