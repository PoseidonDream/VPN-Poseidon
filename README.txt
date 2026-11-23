FREE VPN for Windows
====================

A small app that connects your PC to free public VPN servers in other
countries, so you can unblock websites and hide your real IP address.

  * Servers: VPN Gate (www.vpngate.net), a free research project at the
    University of Tsukuba, Japan. Volunteers around the world run the servers.
  * Connection: made by OpenVPN, the free and official open-source VPN client.
  * No account, no sign-up, no payment.


SETUP (one time, about 5 minutes)
---------------------------------

1. Install Python (free)
   https://www.python.org/downloads/windows/
   Download the latest "Windows installer (64-bit)" and run it with the
   default options.

2. Install OpenVPN (free)
   https://openvpn.net/community-downloads/
   Download the Windows 64-bit installer (the .msi file) and run it with the
   default options. You do NOT need an OpenVPN account.

3. Put this FreeVPN folder somewhere permanent, e.g. your Documents folder.


USING IT
--------

1. Double-click "Start Free VPN.bat" (or FreeVPN.pyw directly).
2. Windows asks "Do you want to allow this app to make changes?". Click Yes.
   A VPN needs this permission to send your internet traffic through the
   tunnel.
3. Choose what should use the VPN (see the next section), pick a location
   or leave it on "Any country", and click the big round button (or Quick
   Connect under it).
4. When the round button turns green, you're connected.
5. Click the round button again (or Disconnect) when you're done.


EVERYTHING OR DISCORD ONLY
--------------------------
The switch "USE THE VPN FOR" in the left panel has two settings:

  Everything    All of your internet goes through the VPN. "Your IP address"
                turns green and shows the new address. Games will be slow,
                because their traffic travels to the VPN's country and back.

  Discord only  Only Discord goes through the VPN. Games and everything else
                keep using your normal connection at full speed, and keep
                your normal IP address (so "Your IP address" does not change).

You can flip the switch while connected; the app reconnects to the same
server the other way.

After connecting in "Discord only" for the first time, close Discord
completely (also right-click its icon next to the clock and choose Quit) and
open it again, so it picks up the new route.


START WITH WINDOWS
------------------
In the "Settings" tab, switch on "Start Free VPN when Windows starts".
From then on Free VPN opens by itself, minimized on the taskbar, about 10
seconds after you sign in. Windows doesn't ask for permission each time.

To have it connect by itself too, also switch on "Connect automatically when
Free VPN opens". It uses the location and mode (Everything or Discord only)
you picked last time. Right after sign-in it waits for the internet to come
up before connecting.

If you open Free VPN again while it's already running (for example from
"Start Free VPN.bat"), the window that's already running comes back instead
of a second copy starting.

If you move the FreeVPN folder, open the app once from its new place, and it
updates itself. To turn it off, switch it off in Settings again.

Behind the scenes this is a Windows Task Scheduler task called
"FreeVPN-Autostart". That's the standard way to start an app that needs
administrator rights at sign-in without a permission prompt.


THE X BUTTON AND THE ICON NEXT TO THE CLOCK
-------------------------------------------
Clicking X asks what you want:
  * Keep running : the window goes away, the VPN stays on, and Free VPN waits
                   in the icons next to the clock (a round power symbol;
                   Windows may tuck it under the little ^ arrow).
  * Quit         : disconnects and closes the app.
  * Cancel       : does nothing.

The icon's color shows the state: green = connected, orange = connecting,
red = a problem, grey = not connected. Click it to open Free VPN.
Right-click it for Connect / Disconnect and Quit.

Prefer the taskbar and Alt+Tab? In Settings, switch off "Hide next to the
clock when kept running"; "Keep running" then minimizes to the taskbar.

To always see the icon: Windows Settings > Personalization > Taskbar >
Other system tray icons, and switch on Free VPN (shown as "pythonw" or
"FreeVPN").


IF THE CONNECTION DROPS
-----------------------
Free VPN reconnects by itself: first to the same server, then to others.
If that doesn't work it waits a little longer each time (a few seconds, then
up to 2 minutes) and keeps trying. While it waits, the button shows
"Cancel": press it to stop. When the window is hidden, a notification tells
you the connection was lost and when it's back.

Switch it off in Settings: "Reconnect automatically if the connection drops".

Tips
  * Double-click any server in the list to connect to that one.
  * Servers that worked for you are marked with a star in the list, and
    Quick Connect tries them first (the last 5 are remembered).
  * Click a column heading (Ping, Speed, ...) to sort by it.
  * If a server doesn't work, the app tries the next one automatically (up to
    5). Volunteer servers come and go, so press "Refresh list" now and then.
  * The "Settings" tab (next to "Servers" and "Log") has the options, each
    with an explanation. "Prevent DNS leaks" (on by default) makes website
    lookups go through the VPN in "Everything" mode, so your internet
    provider can't see which sites you visit.
  * "Dark mode" / "Light mode" at the top of the left panel switches the
    look. The app starts in whichever one Windows is set to.


UPDATES
-------
Free VPN looks for a new version when it opens and twice a day while it
runs. When there is one, a blue bar appears at the top of the window: click
"Update now". It downloads the new version, closes, and opens again by itself
a few seconds later, and reconnects if you were connected. "What's new" shows
what changed; "Not now" hides the bar until the next check.

Nothing is installed without your click. To stop the checks, switch off
"Check for updates automatically" in Settings; "Check now" is right below it.

Updates come only from the releases of this project on GitHub:
https://github.com/PoseidonDream/VPN-Poseidon/releases


OPTIONAL: MAKE A REAL .EXE
--------------------------
Double-click "Build EXE (optional).bat". It creates dist\FreeVPN.exe, which
you can pin to your taskbar. Some antivirus programs wrongly flag new
home-made .exe files. If that happens, keep using "Start Free VPN.bat".


TROUBLESHOOTING
---------------
"One more step: install OpenVPN"
    Install OpenVPN (step 2 of SETUP above), then click "Check again".

"Couldn't connect" / "The server didn't answer"
    Volunteer servers are often busy or offline. Try another country, or
    click "Refresh list" and try again. Some networks (school, work, some
    countries) block VPNs. Servers marked "TCP" usually get through more
    often.

"OpenVPN's network adapter is missing or in use"
    Close any other VPN app. If it still happens, run the OpenVPN installer
    again, choose "Customize", and make sure "TAP-Windows6" is selected.

Connected, but websites don't load ("Everything" mode)
    Switch off "Prevent DNS leaks" in Settings and connect again, or try a
    different server.

"Discord only" is on, but Discord doesn't load or voice doesn't connect
    1. Close Discord completely (also from the icons next to the clock) and
       open it again.
    2. Try another server: double-click a different one in the list.
    3. If it still fails, open "Log", click "Copy log", and send it to
       whoever is helping you. The lines that start with "Discord-only:"
       show what was set up.

Discord can't be reached at all after a crash or power cut
    Start Free VPN once. "Discord only" adds a Windows setting while it is
    on and removes it when you disconnect; if the PC lost power in between,
    the app removes it the next time it starts.

Anything else
    Click "Log" (next to "Servers") to see exactly what OpenVPN is doing.
    "Copy log" copies it so you can search for the error or ask for help.


PRIVACY, HONESTLY
-----------------
Good for: unblocking websites and services, getting around network blocks,
hiding your IP address from the websites you visit.

Not good for: anything where your safety depends on privacy. Volunteers run
the VPN Gate servers, and by VPN Gate's rules they keep connection logs (who
connected and when) for at least 2 weeks. Never use these servers for
anything illegal. Don't log in to banking or similar sites while connected
unless the site uses https (the padlock in your browser).

What this app sends where:
  * www.vpngate.net : downloads the public server list.
  * api.github.com / github.com : looks for, and downloads, new versions of
    Free VPN (see UPDATES).
  * api.ipify.org : asks "what is my IP?" to show your IP before and after
    connecting.
  * In "Discord only" mode: public DNS servers (1.0.0.1 and 8.8.4.4) are
    asked, through the VPN, for the addresses of Discord's servers.
  * Settings and the last server list are saved in %APPDATA%\FreeVPN.
    Nothing else is collected or sent anywhere.

What "Discord only" changes on your PC while it is on (all undone when you
disconnect):
  * Routes that send Discord's server addresses through the VPN.
  * One Windows DNS rule (named "FreeVPN") so that Discord's names are looked
    up through the VPN.
