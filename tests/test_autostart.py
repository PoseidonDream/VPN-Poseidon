"""Start-with-Windows: the task definition and the PowerShell command (no Windows needed)."""
import base64, importlib.machinery, sys, xml.etree.ElementTree as ET
mod = importlib.machinery.SourceFileLoader("freevpn", sys.argv[1]).load_module()
results = []
def check(name, cond, extra=""):
    results.append(bool(cond)); print(("PASS " if cond else "FAIL ") + name, extra, flush=True)
NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}

def ps_strings(script):
    """Split a PowerShell script into ('code', text) and ('str', value) pieces, the way
    PowerShell reads single-quoted strings ('' inside means one ')."""
    out, i, code = [], 0, ""
    while i < len(script):
        if script[i] == "'":
            out.append(("code", code)); code = ""; j = i + 1; val = ""
            while True:
                if j >= len(script): raise ValueError("unterminated string")
                if script[j] == "'":
                    if script[j + 1:j + 2] == "'": val += "'"; j += 2; continue
                    break
                val += script[j]; j += 1
            out.append(("str", val)); i = j + 1
        else:
            code += script[i]; i += 1
    out.append(("code", code)); return out

user = "MY-PC\\Ana O'Neil & <Co>"
cmd, folder = r"C:\Users\Ana O'Neil\Python 3.13\pythonw.exe", r"C:\Users\Ana O'Neil\Free VPN & co"
args = '"' + folder + '\\FreeVPN.pyw" --startup'
assert "O'Neil" in args and "&" in args
text = mod.autostart_task_xml(user, cmd, args, folder)
root = ET.fromstring(text.encode("utf-16"))   # how Windows stores it
g = lambda path: root.find(path, NS).text
check("XML is well-formed with tricky names", root.tag.endswith("Task"))
check("runs at sign-in of this user, 10 s later", g("t:Triggers/t:LogonTrigger/t:UserId") == user and g("t:Triggers/t:LogonTrigger/t:Delay") == "PT10S")
check("runs as this user, with admin rights, no password", g("t:Principals/t:Principal/t:UserId") == user and g("t:Principals/t:Principal/t:LogonType") == "InteractiveToken" and g("t:Principals/t:Principal/t:RunLevel") == "HighestAvailable")
check("keeps running on battery, never times out, normal priority", g("t:Settings/t:DisallowStartIfOnBatteries") == "false" and g("t:Settings/t:StopIfGoingOnBatteries") == "false" and g("t:Settings/t:ExecutionTimeLimit") == "PT0S" and g("t:Settings/t:Priority") == "5")
check("starts the right program, arguments and folder (escaped correctly)", g("t:Actions/t:Exec/t:Command") == cmd and g("t:Actions/t:Exec/t:Arguments") == args and g("t:Actions/t:Exec/t:WorkingDirectory") == folder)

# what autostart_command gives for a normal run and for the .exe
import os
script = os.path.abspath(os.path.join(os.sep, "fake", "Free VPN", "FreeVPN.pyw"))   # C:\fake\... on Windows
sys.argv = [script]
c, a, f = mod.autostart_command()
check("command: script path quoted + --startup", a == '"%s" --startup' % script and f == os.path.dirname(script), a)
exe = os.path.abspath(os.path.join(os.sep, "fake", "dist", "FreeVPN.exe"))
sys.frozen = True; sys.executable_backup = sys.executable; sys.executable = exe
c, a, f = mod.autostart_command()
check("command for FreeVPN.exe", (c, a, f) == (exe, "--startup", os.path.dirname(exe)))
del sys.frozen; sys.executable = sys.executable_backup

# the PowerShell command
calls = []
mod.run_hidden = lambda args, timeout=30: (calls.append(args), (0, ""))[1]
mod.current_user = lambda: user
mod.autostart_command = lambda: (cmd, args, folder)   # Windows-style paths
code, out = mod.set_autostart(True)
argv = calls[-1]
check("PowerShell runs hidden, no profile, encoded script", argv[0].endswith("powershell.exe") and argv[1:6] == ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand"] and len(argv) == 7)
script = base64.b64decode(argv[6]).decode("utf-16-le")
check("command line is short enough for Windows", len(" ".join(argv)) < 32000, str(len(" ".join(argv))))
parts = ps_strings(script)
codes = "".join(t for k, t in parts if k == "code"); strings = [t for k, t in parts if k == "str"]
check("script: stop on error, report failure with exit code 1", codes.startswith("$ErrorActionPreference = ") and strings[0] == "Stop" and "try {" in codes and "exit 0" in codes and "} catch {" in codes and "Write-Output $_.Exception.Message" in codes and "exit 1" in codes)
check("script: Register-ScheduledTask -TaskName <name> -Xml <xml> -Force", "Register-ScheduledTask -TaskName  -Xml  -Force | Out-Null" in codes and strings[1] == "FreeVPN-Autostart", codes)
inner = ET.fromstring(strings[2].encode("utf-16"))
check("the XML inside the script survives PowerShell quoting intact", strings[2] == text and inner.find("t:Actions/t:Exec/t:WorkingDirectory", NS).text == folder and inner.find("t:Actions/t:Exec/t:Arguments", NS).text == args and inner.find("t:Principals/t:Principal/t:UserId", NS).text == user)
check("braces balanced", codes.count("{") == codes.count("}"))
code, out = mod.set_autostart(False)
script = base64.b64decode(calls[-1][6]).decode("utf-16-le"); parts = ps_strings(script)
codes = "".join(t for k, t in parts if k == "code"); strings = [t for k, t in parts if k == "str"]
check("off: removes the task only if it exists", "if (Get-ScheduledTask -TaskName  -ErrorAction SilentlyContinue) {" in codes and "Unregister-ScheduledTask -TaskName  -Confirm:$false" in codes and strings[1:3] == ["FreeVPN-Autostart", "FreeVPN-Autostart"] and codes.count("{") == codes.count("}"), codes)
print("\n%d/%d passed" % (sum(results), len(results))); sys.exit(0 if all(results) else 1)
