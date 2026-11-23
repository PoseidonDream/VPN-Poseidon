"""Tests for Discord-only mode's engine: no window, no Windows needed."""
import importlib.machinery, socket, struct, sys, threading, time
mod = importlib.machinery.SourceFileLoader("freevpn", sys.argv[1]).load_module()
results = []
def check(name, cond, extra=""):
    results.append(bool(cond)); print(("PASS " if cond else "FAIL ") + name, extra, flush=True)

# ---- DNS wire format ----
q = mod.dns_query("Gateway.Discord.gg")
name, rtype, end = mod.dns_question(q)
check("query round-trips", (name, rtype, end) == ("gateway.discord.gg", 1, len(q)), str((name, rtype, end, len(q))))
def answer(query, ips, cname=False):
    """Build a realistic reply: question echoed, optional CNAME, A records using name pointers."""
    n, t, e = mod.dns_question(query)
    records = b""
    count = 0
    if cname:
        target = b"\x03cdn\x07example\x03net\x00"
        records += b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, len(target)) + target; count += 1
    for ip in ips:
        records += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes(int(x) for x in ip.split(".")); count += 1
    return query[:2] + struct.pack(">HHHHH", 0x8180, 1, count, 0, 0) + query[12:e] + records
check("A records parsed (with CNAME and pointers)", mod.dns_addresses(answer(q, ["162.159.130.234", "104.18.5.5"], cname=True)) == ["162.159.130.234", "104.18.5.5"])
check("garbage answer -> no addresses, no crash", mod.dns_addresses(b"\x00" * 5) == [] and mod.dns_addresses(q[:12] + b"\xff" * 9) == [])
empty = mod.dns_empty_answer(mod.dns_query("discord.com", 28), len(mod.dns_query("discord.com", 28)))
check("empty answer is a valid no-record reply", empty[2] & 0x80 and struct.unpack(">HHHH", empty[4:12]) == (1, 0, 0, 0) and mod.dns_question(empty)[0] == "discord.com")
for bad in (b"", b"\x00" * 12, q[:15], q[:12] + b"\x7f" + b"a" * 10):
    try: mod.dns_question(bad); ok = False
    except ValueError: ok = True
    check("malformed question rejected (%d bytes)" % len(bad), ok)
check("discord names", mod.is_discord_name("discord.com") and mod.is_discord_name("rotterdam123.discord.media") and not mod.is_discord_name("notdiscord.com") and not mod.is_discord_name("discord.com.evil.net"))

# ---- gateway parsing ----
vg = "2026-11-10 12:00:00 PUSH: Received control message: 'PUSH_REPLY,ping 3,ping-restart 10,ifconfig 10.211.1.5 10.211.1.6,dhcp-option DNS 10.211.254.254,dhcp-option DNS 8.8.8.8,route-gateway 10.211.1.6,redirect-gateway def1'"
check("gateway from route-gateway", mod.parse_gateway(vg) == "10.211.1.6")
check("gateway from net30 ifconfig", mod.parse_gateway("PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5,ping 10") == "10.8.0.5")
check("subnet ifconfig without gateway -> None", mod.parse_gateway("PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0") is None)
check("nonsense -> None", mod.parse_gateway("PUSH_REPLY,route-gateway 999.1.1.1") is None)

# ---- config ----
server = mod.Server("h", "1.2.3.4", 1, 1, 1, "Japan", "JP", 1, 1, "", "client\ndev tun\nremote 1.2.3.4 443\n<ca>\nQUJD\n</ca>\n", "TCP", 443)
cfg = mod.build_config(server, True, discord_only=True)
check("discord config leaves normal route and DNS alone", all(w in cfg for w in ('pull-filter ignore "redirect-gateway"', 'pull-filter ignore "dhcp-option"')) and "block-outside-dns\n" not in cfg.replace('"block-outside-dns"', "") and "dhcp-option DNS" not in cfg)
check("discord config routes Discord's networks + DNS", all(w in cfg for w in ("route 162.159.128.0 255.255.240.0", "route 66.22.192.0 255.255.192.0", "route 138.128.136.0 255.255.248.0", "route 5.200.14.128 255.255.255.128", "route 1.0.0.1 255.255.255.255", "route 8.8.4.4 255.255.255.255")))
full = mod.build_config(server, True)
check("everything mode unchanged", "pull-filter" not in full and "route " not in full and "block-outside-dns" in full)

# ---- the relay, against a fake public DNS server ----
upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); upstream.bind(("127.0.0.1", 0)); asked = []
ZONE = {"gateway.discord.gg": ["162.159.130.234", "104.18.5.5"], "frankfurt99.discord.media": ["35.214.1.2"], "discord.com": ["127.0.0.1"], "example.org": ["93.184.215.14"], "lan.discord.gg": ["192.168.1.50", "10.0.0.1"]}
def serve():
    while True:
        try: data, addr = upstream.recvfrom(4096)
        except OSError: return
        n, t, e = mod.dns_question(data); asked.append((n, t))
        upstream.sendto(answer(data, ZONE.get(n, []) if t == 1 else []), addr)
threading.Thread(target=serve, daemon=True).start()
checker = socket.socket(); checker.bind(("127.0.0.1", 0)); checker.listen(5)
commands = []
def fake_run(args, timeout=30):
    commands.append(list(args))
    if "print" in args: return 0, "Active Routes:\n  %s  255.255.255.255   10.9.9.1   10.9.9.2   1\n" % args[-1]
    return 0, ""
mod.run_hidden = fake_run
mod.SPLIT_DNS_SERVERS = ("127.0.0.1",); mod.SPLIT_DNS_PORT = upstream.getsockname()[1]
free = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); free.bind(("127.0.0.1", 0)); mod.SPLIT_LISTEN_PORT = free.getsockname()[1]; free.close()
mod.SPLIT_CHECK_PORT = checker.getsockname()[1]
logs, checks = [], []
st = mod.SplitTunnel(logs.append); st.on_check = checks.append
ok, note = st.start("10.211.1.6")
check("start works", ok and note == "", str((ok, note)))
ps = [c for c in commands if "-Command" in c]
check("DNS rule points Discord's names at the relay", len(ps) == 1 and "Add-DnsClientNrptRule" in ps[0][-1] and "-NameServers '127.0.0.1'" in ps[0][-1] and "'.discord.com','discord.com'" in ps[0][-1] and "-Comment 'FreeVPN'" in ps[0][-1])
def ask(name, rtype=1):
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.settimeout(4)
    query = mod.dns_query(name, rtype); c.sendto(query, ("127.0.0.1", mod.SPLIT_LISTEN_PORT))
    reply, _ = c.recvfrom(4096); c.close()
    assert reply[:2] == query[:2]; return reply
time.sleep(1.5)   # let the warm-up finish
check("warm-up asked the main names, reported Discord reachable", ("discord.com", 1) in asked and ("gateway.discord.gg", 1) in asked and checks == [True], str(checks))
adds = lambda: [c for c in commands if c[1:2] == ["ADD"]]
check("warm-up routed the address outside the fixed list, via the gateway", [c[2:] for c in adds()] == [["104.18.5.5", "MASK", "255.255.255.255", "10.211.1.6", "METRIC", "1"]], str(adds()))
before = len(asked)
r = ask("frankfurt99.discord.media")
check("voice server lookup answered", mod.dns_addresses(r) == ["35.214.1.2"])
check("...and routed before the answer came back", ["35.214.1.2"] == [c[2] for c in adds()][1:], str(adds()))
ask("gateway.discord.gg")
check("no duplicate route for a known address", len(adds()) == 2)
r6 = ask("gateway.discord.gg", 28); r65 = ask("discord.com", 65)
check("IPv6 / HTTPS-record lookups get 'no record' without asking upstream", mod.dns_addresses(r6) == [] and struct.unpack(">H", r6[6:8])[0] == 0 and not any(t in (28, 65) for n, t in asked[before:]))
ask("lan.discord.gg")
check("private addresses are never routed", len(adds()) == 2)
ask("example.org")
check("non-Discord names are answered but not routed", len(adds()) == 2)
st.refresh("10.211.7.7"); time.sleep(0.5)
check("gateway change re-points routes", sorted(c[2] for c in commands if c[1:2] == ["ADD"] and c[5] == "10.211.7.7") == ["104.18.5.5", "35.214.1.2"])
commands.clear(); st.stop()
check("stop removes the DNS rule and our routes", any("Remove-DnsClientNrptRule" in c[-1] and "Add-" not in c[-1] for c in commands) and any(c[1] == "/c" and "DELETE 104.18.5.5" in c[2] and "DELETE 35.214.1.2" in c[2] for c in commands), str(commands))
try: ask("gateway.discord.gg"); alive = True
except OSError: alive = False
check("relay is closed after stop", not alive)

# port taken -> simpler method
blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); blocker.bind(("127.0.0.1", 0)); mod.SPLIT_LISTEN_PORT = blocker.getsockname()[1]
commands.clear(); logs.clear(); st2 = mod.SplitTunnel(logs.append)
ok, note = st2.start(None)
check("port taken: falls back to the public DNS servers, gateway read from the route table", ok and st2.gateway == "10.9.9.1" and any("-NameServers '127.0.0.1'" in c[-1] for c in commands if "-Command" in c) and any("simpler method" in l for l in logs), str((ok, note, st2.gateway)))
st2.stop()
# no gateway at all
mod.run_hidden = lambda args, timeout=30: (1, "")
ok, note = mod.SplitTunnel(logs.append).start(None)
check("no gateway -> clear failure", not ok and "gateway" in note)
# stopped during setup
mod.run_hidden = fake_run; commands.clear(); st3 = mod.SplitTunnel(logs.append); st3.stopped = True
ok, note = st3.start("10.1.1.1")
check("cancelled during setup cleans up", not ok and sum("Remove-DnsClientNrptRule" in c[-1] for c in commands if "-Command" in c) >= 2)
print("\n%d/%d passed" % (sum(results), len(results))); sys.exit(0 if all(results) else 1)
