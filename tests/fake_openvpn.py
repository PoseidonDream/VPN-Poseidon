#!/usr/bin/env python3
"""Stand-in for openvpn used only to test Free VPN's process handling."""
import os, socket, sys, threading, time
args = sys.argv[1:]
cfg = args[args.index("--config") + 1]
m = args.index("--management")
port, pwfile = int(args[m + 2]), args[m + 3]
state = os.environ["FAKE_STATE_DIR"]
os.makedirs(state, exist_ok=True)
n = len([f for f in os.listdir(state) if f.startswith("run")]) + 1
open(os.path.join(state, f"run{n}"), "w").write(open(cfg).read())
mode = os.environ.get("FAKE_MODE_%d" % n) or os.environ.get("FAKE_MODE", "ok")
pw = open(pwfile).read().strip()
def log(s): print("2026-11-10 12:00:00 " + s, flush=True)
def mgmt():
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port)); srv.listen(1)
    while True:
        c, _ = srv.accept(); f = c.makefile("rwb")
        c.sendall(b"ENTER PASSWORD:")
        if f.readline().strip().decode() != pw:
            c.sendall(b"ERROR: bad password\r\n"); c.close(); continue
        c.sendall(b"SUCCESS: password is correct\r\n>INFO:OpenVPN Management Interface Version 5\r\n")
        for line in f:
            if line.strip() == b"signal SIGTERM":
                c.sendall(b"SUCCESS: signal SIGTERM thrown\r\n")
                log("SIGTERM[hard,] received, process exiting")
                open(os.path.join(state, f"graceful{n}"), "w").write("ok")
                os._exit(0)
threading.Thread(target=mgmt, daemon=True).start()
log("OpenVPN 2.6.12 [fake] x86_64")
log(f"MANAGEMENT: TCP Socket listening on [AF_INET]127.0.0.1:{port}")
time.sleep(0.5)
if mode == "ok" or mode == "die":
    log("TCP connection established with [AF_INET]1.2.3.4:443")
    log("PUSH: Received control message: 'PUSH_REPLY,ping 3,ping-restart 10,ifconfig 10.211.1.5 10.211.1.6,dhcp-option DNS 10.211.254.254,dhcp-option DNS 8.8.8.8,route-gateway 10.211.1.6,redirect-gateway def1'")
    time.sleep(0.8)
    log("Initialization Sequence Completed")
    if mode == "die":
        time.sleep(2); log("Connection reset, restarting [0]"); log("SIGUSR1[soft,connection-reset] received, process restarting")
        time.sleep(1); log("Exiting due to fatal error"); sys.exit(1)
elif mode == "tls":
    log("TLS Error: TLS key negotiation failed to occur within 60 seconds (check your network connectivity)")
    log("TLS Error: TLS handshake failed")
elif mode == "nodriver":
    log("There are no TAP-Windows, Wintun or ovpn-dco adapters on this system.")
    log("Exiting due to fatal error"); sys.exit(1)
elif mode == "hang":
    pass
while True:
    time.sleep(1)
