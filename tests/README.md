# Tests

None of the tests connect to a real VPN. `fake_openvpn.py` stands in for OpenVPN: it
prints the same log lines, offers the same management interface, and can be told to
fail (`FAKE_MODE`, `FAKE_MODE_<n>` for the n-th start). The server list comes from
`fixtures/servers.csv`, so no internet is needed.

| File | What it checks | Needs |
| --- | --- | --- |
| `test_split.py` | Discord-only engine: DNS relay, routing, clean-up | Python |
| `test_autostart.py` | Start-with-Windows task definition and PowerShell command | Python |
| `test_tray_units.py` | Tray icon files and Windows structure layouts | Python |
| `test_startup_min.py` | Opening minimized at sign-in; a second start shows the window | Python with Tk, a display |
| `test_update.py` | Updates: checking GitHub, downloading, the helper, the window's part | Python with Tk, a display |
| `run_gui_test.py` | The whole app through its window | Python with Tk, a display |
| `windows_smoke.py` | Real Windows: tray icon, Task Scheduler, DNS rule, routes, job object, update helper | Windows, administrator |

## On Windows

GitHub runs all of them on every push (`.github/workflows/windows.yml`). By hand, as
administrator:

```bat
python -I tests\windows_smoke.py FreeVPN.pyw
python -I tests\run_gui_test.py %TEMP%\freevpn-test FreeVPN.pyw
```

`run_gui_test.py` needs `FREEVPN_OPENVPN` set to an `.exe` build of `fake_openvpn.py`
(the workflow shows how to make one with PyInstaller).

## On Linux

```sh
python3 -I tests/test_split.py FreeVPN.pyw
xvfb-run -a sh -c 'openbox & sleep 1; python3 -I tests/run_gui_test.py /tmp/freevpn-test FreeVPN.pyw'
```

A window manager (here `openbox`) is needed for the minimize and restore checks.
