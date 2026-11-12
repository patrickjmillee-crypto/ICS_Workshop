"""
recon_viz.py - your recon.py with a live raylib view of the scan.

    pip install raylib xmltodict pycomm3
    sudo -E python3 recon_viz.py        (nmap -sS / -O need root)

Window (dark theme):
  left   256 cells = the 192.168.10.x address space (assumes a /24)
  right  256x256 pixels = all 65,536 TCP ports of the selected host
         (hover a host cell to inspect it, hover the port map for port numbers)
  bottom ICS port hit counts + event log
ESC closes the window.
"""
import math
import os
import queue
import re
import subprocess
import tempfile
import threading
import time
from collections import deque

import pyray as rl
import xmltodict
from pycomm3 import LogixDriver

NETWORK_RANGE = "192.168.10.0/24"
BASE = NETWORK_RANGE.split("/")[0].rsplit(".", 1)[0]      # "192.168.10"

ICS_PORTS = {
    44818: "EtherNet/IP",
    2222: "EtherNet/IP I/O",
    502: "Modbus TCP",
    80: "HTTP",
    443: "HTTPS",
    21: "FTP",
    23: "Telnet",
}

events = queue.SimpleQueue()      # worker threads -> window (all drawing state lives on the main thread)
nmap_proc = None


# --------------------------------------------------------------------------
#  Your original recon logic (same output). Differences:
#   1. run_nmap streams nmap's live output to the window and writes the XML
#      to a temp file instead of stdout.
#   2. `hosts = [host]` was a NameError; it is now `[hosts]`.
#   3. a few events.put(...) calls feed the visualiser.
# --------------------------------------------------------------------------
def run_nmap(ip_range):
    """Run Nmap, stream its live output to the visualiser, return parsed XML."""
    global nmap_proc
    fd, xml_path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    cmd = ["nmap", "-n", "-O", "-sS", "-sV", ip_range,
           "-v", "--packet-trace", "--stats-every", "1s",
           "-oX", xml_path]
    nmap_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, bufsize=1)
    for line in nmap_proc.stdout:
        events.put(("line", line.rstrip()))
    if nmap_proc.wait() != 0:
        raise subprocess.CalledProcessError(nmap_proc.returncode, cmd)
    with open(xml_path) as f:
        xml_output = f.read()
    os.remove(xml_path)
    return xmltodict.parse(xml_output)


def run_recon():
    try:
        print(f"\n[+] Scanning network : {NETWORK_RANGE}\n")

        scan_data = run_nmap(NETWORK_RANGE)
        hosts = scan_data.get("nmaprun", {}).get("host", [])

        if isinstance(hosts, dict):
            hosts = [hosts]

        for host in hosts:
            print("=" * 60)
            addr_info = host.get("address", [])

            if isinstance(addr_info, dict):
                addr_info = [addr_info]

            ip_address = "Unknown"
            mac_address = "Unknown"
            vendor = "Unknown"

            for addr in addr_info:
                if addr["@addrtype"] == "ipv4":
                    ip_address = addr["@addr"]
                if addr["@addrtype"] == "mac":
                    mac_address = addr["@addr"]
                    vendor = addr.get("@vendor", "Unknown")

            print(f"[IP Address]   :  {ip_address}")
            print(f"[Mac Address]  :  {mac_address}")
            print(f"[Vendor]       :  {vendor}")

            print("\nOpen Ports")

            open_ports = []

            ports = host.get("ports", {}).get("port", [])
            if isinstance(ports, dict):
                ports = [ports]

            for p in ports:
                port_id = int(p["@portid"])
                state = p["state"]["@state"]
                service = p.get("service", {}).get("@name", "Unknown")

                if state == "open":
                    protocol_name = ICS_PORTS.get(port_id, service)
                    open_ports.append(port_id)
                    print(f"   Port {port_id:<6}  |  {protocol_name}")

            events.put(("host", ip_address, mac_address, vendor, open_ports))

            if 44818 in open_ports:
                print("\n[PLC Info]")
                events.put(("plc", ip_address, "start", None))

                try:
                    with LogixDriver(f"{ip_address}/1") as plc:
                        info = plc.info
                        print(f"   Product Name   : {info.get('product_name', 'Unknown')}")
                        print(f"   Firmware Rev   : {info.get('revision', 'Unknown')}")
                        print(f"   Serial Number  : {info.get('serial', 'Unknown')}")
                    events.put(("plc", ip_address, "ok", info))

                except Exception as e:
                    print(f"   Unable to enumerate PLC: {e}")
                    events.put(("plc", ip_address, "err", str(e)))

        print("\n[+] Scan Complete")
        events.put(("done",))
    except Exception as e:
        events.put(("error", str(e)))
        raise


# --------------------------------------------------------------------------
#  Visualiser
# --------------------------------------------------------------------------
def C(r, g, b, a=255):
    return rl.Color(r, g, b, a)


BG, PANEL, BORDER = C(13, 17, 23), C(22, 27, 34), C(48, 54, 61)
TEXT, DIM = C(230, 237, 243), C(125, 133, 144)
PENDING, SLATE = C(30, 36, 44), C(52, 60, 72)
BLUE, BLUE_DIM = C(47, 129, 247), C(31, 78, 150)
GREEN, ORANGE, RED = C(63, 185, 80), C(255, 166, 87), C(248, 81, 73)


def mix(a, b, t):
    t = max(0.0, min(1.0, t))
    return rl.Color(int(a.r + (b.r - a.r) * t), int(a.g + (b.g - a.g) * t),
                    int(a.b + (b.b - a.b) * t), 255)


WIN_W, WIN_H = 1180, 820
HOST_X, HOST_Y, CELL, GAP = 30, 118, 30, 4
STEP = CELL + GAP
PORT_X, PORT_Y, PSZ = 622, 118, 2          # 256 x 256 ports, 2 px each = 512 px
BOT_Y = 676

PORT_SENT, PORT_OPEN, PORT_CLOSED = 1, 2, 3

RE_PKT = re.compile(r"^(SENT|RCVD) \([\d.]+s\) TCP (\d+\.\d+\.\d+\.\d+):(\d+) > "
                    r"(\d+\.\d+\.\d+\.\d+):(\d+) (\w+)")
RE_PCT = re.compile(r"About ([\d.]+)% done")
RE_PHASE = re.compile(r"^Initiating (.+?) at ")
RE_REPORT = re.compile(r"^Nmap scan report for (\d+\.\d+\.\d+\.\d+)")


class Host:
    def __init__(self):
        self.ports = {}            # port -> [state, timestamp]
        self.n_open = 0
        self.confirmed = False     # present in nmap's final XML
        self.querying = False
        self.last_probe = 0.0
        self.mac = self.vendor = self.plc = ""

    def is_open(self, port):
        e = self.ports.get(port)
        return bool(e) and e[0] == PORT_OPEN


class Viz:
    def __init__(self):
        self.hosts = {}
        self.active = None
        self.target = 0.0
        self.shown = 0.0
        self.phase = "Starting nmap"
        self.probes = 0
        self.log = deque(maxlen=7)
        self.t0 = time.time()
        self.t_end = None
        self.done = False
        self.error = None

    # ---- state updates -------------------------------------------------
    def add_log(self, text, color=DIM):
        self.log.append((time.strftime("%H:%M:%S"), text, color))

    def host_for(self, ip):
        if not ip.startswith(BASE + "."):
            return None, None
        o = int(ip.rsplit(".", 1)[1])
        return o, self.hosts.setdefault(o, Host())

    def probe(self, ip, port, state, now):
        o, h = self.host_for(ip)
        if h is None:
            return
        cur = h.ports.get(port)
        if state == PORT_SENT:
            if cur is None:
                h.ports[port] = [PORT_SENT, now]
                self.probes += 1
            h.last_probe = now
            self.active = o
        elif cur is None or cur[0] != PORT_OPEN or state == PORT_OPEN:
            newly_open = state == PORT_OPEN and not h.is_open(port)
            h.ports[port] = [state, now]
            if newly_open:
                h.n_open += 1
                name = ICS_PORTS.get(port, "")
                self.add_log(f"OPEN  {ip}:{port}  {name}", ORANGE if name else GREEN)

    def on_line(self, line, now):
        m = RE_PKT.match(line)
        if m:
            kind, a_ip, a_port, b_ip, b_port, flags = m.groups()
            if kind == "SENT":
                if flags == "S":                       # SYN probe -> b_ip:b_port
                    self.probe(b_ip, int(b_port), PORT_SENT, now)
            elif "R" in flags:                         # RST  -> closed
                self.probe(a_ip, int(a_port), PORT_CLOSED, now)
            elif "S" in flags and "A" in flags:        # SYN/ACK -> open
                self.probe(a_ip, int(a_port), PORT_OPEN, now)
            return
        m = RE_PCT.search(line)
        if m:
            self.target = float(m.group(1)) / 100.0
            return
        m = RE_PHASE.match(line)
        if m:
            self.phase = m.group(1)
            self.target = 0.0
            self.shown = 0.0
            self.add_log(f"phase: {m.group(1)}", BLUE)
            return
        m = RE_REPORT.match(line)
        if m:
            _, h = self.host_for(m.group(1))
            if h:
                h.confirmed = True
            return
        if "requires root" in line or line.startswith("QUITTING"):
            self.add_log(line[:70], RED)

    def drain(self, limit=5000):
        now = time.time()
        for _ in range(limit):
            try:
                ev = events.get_nowait()
            except queue.Empty:
                break
            kind = ev[0]
            if kind == "line":
                self.on_line(ev[1], now)
            elif kind == "host":
                _, ip, mac, vendor, open_ports = ev
                _, h = self.host_for(ip)
                if h:
                    h.confirmed, h.mac, h.vendor = True, mac, vendor
                    for p in open_ports:
                        if not h.is_open(p):
                            h.ports[p] = [PORT_OPEN, now]
                            h.n_open += 1
            elif kind == "plc":
                _, ip, stage, data = ev
                o, h = self.host_for(ip)
                if h is None:
                    continue
                if stage == "start":
                    h.querying = True
                    self.active = o
                    self.add_log(f"querying PLC {ip} ...", ORANGE)
                else:
                    h.querying = False
                    if stage == "ok":
                        h.plc = f"{data.get('product_name', '?')}  rev {data.get('revision', '?')}"
                        self.add_log(f"PLC {ip}: {h.plc}", GREEN)
                    else:
                        self.add_log(f"PLC {ip}: {data[:50]}", RED)
            elif kind == "done":
                self.done, self.t_end = True, time.time()
                self.hosts = {o: h for o, h in self.hosts.items() if h.confirmed}
                plcs = [o for o, h in self.hosts.items() if h.is_open(44818)]
                if plcs:
                    self.active = plcs[0]
                self.add_log("scan complete", GREEN)
            elif kind == "error":
                self.error, self.t_end = ev[1], time.time()
                self.add_log(f"ERROR {ev[1][:60]}", RED)

    # ---- drawing -------------------------------------------------------
    def host_color(self, h, now):
        pulse = 0.5 + 0.5 * math.sin(now * 6)
        if h is None:
            return PENDING
        if h.querying:
            return mix(ORANGE, TEXT, pulse * 0.6)
        if h.is_open(44818):
            return ORANGE
        if h.n_open:
            return GREEN
        if h.confirmed:
            return BLUE_DIM
        return mix(BLUE_DIM, BLUE, pulse)                  # being probed

    @staticmethod
    def host_cell_at(mx, my):
        gx, gy = mx - HOST_X, my - HOST_Y
        if gx < 0 or gy < 0:
            return None
        col, row = gx // STEP, gy // STEP
        if col > 15 or row > 15 or gx % STEP >= CELL or gy % STEP >= CELL:
            return None
        return row * 16 + col

    @staticmethod
    def port_at(mx, my):
        gx, gy = mx - PORT_X, my - PORT_Y
        if 0 <= gx < 256 * PSZ and 0 <= gy < 256 * PSZ:
            return (gy // PSZ) * 256 + (gx // PSZ)
        return None

    def draw(self, mx, my, now):
        hover = self.host_cell_at(mx, my)
        sel = hover if hover is not None else self.active
        self.draw_header(now)
        self.draw_host_grid(sel, now)
        self.draw_port_map(sel, now)
        self.draw_bottom()
        self.draw_tooltips(mx, my, hover, sel)

    def draw_header(self, now):
        rl.draw_text("ICS RECON", 30, 16, 30, TEXT)
        rl.draw_text(f"nmap -sS -sV -O   |   {NETWORK_RANGE}", 30, 54, 14, DIM)

        if self.error:
            label, col = "ERROR", RED
        elif self.done:
            label, col = "COMPLETE", GREEN
        elif any(h.querying for h in self.hosts.values()):
            label, col = "ENUMERATING PLCs", ORANGE
        else:
            label, col = self.phase.upper(), BLUE
        w = rl.measure_text(label, 14) + 24
        rl.draw_rectangle_rounded(rl.Rectangle(PORT_X, 14, w, 24), 0.5, 8, col)
        rl.draw_text(label, PORT_X + 12, 20, 14, BG)

        end = self.t_end or now
        el = int(end - self.t0)
        t = f"{el // 60:02d}:{el % 60:02d}"
        rl.draw_text(t, PORT_X + 512 - rl.measure_text(t, 18), 17, 18, TEXT)

        self.target = 1.0 if self.done else self.target
        self.shown += (self.target - self.shown) * 0.15
        rl.draw_rectangle(PORT_X, 46, 512, 8, PANEL)
        rl.draw_rectangle(PORT_X, 46, int(512 * self.shown), 8, col)

        n_plc = sum(1 for h in self.hosts.values() if h.is_open(44818))
        n_open = sum(h.n_open for h in self.hosts.values())
        rl.draw_text(f"hosts {len(self.hosts)}    open ports {n_open}    "
                     f"probes {self.probes:,}    PLCs {n_plc}", PORT_X, 62, 14, DIM)

    def draw_host_grid(self, sel, now):
        rl.draw_text(f"ADDRESS SPACE  {BASE}.0 - {BASE}.255", HOST_X, 96, 14, DIM)
        for o in range(256):
            x = HOST_X + (o % 16) * STEP
            y = HOST_Y + (o // 16) * STEP
            h = self.hosts.get(o)
            rl.draw_rectangle(x, y, CELL, CELL, self.host_color(h, now))
            rl.draw_text(str(o), x + 3, y + 3, 10, TEXT if h else SLATE)
            if h and now - h.last_probe < 0.2:
                rl.draw_rectangle_lines(x, y, CELL, CELL, TEXT)
            if o == sel:
                rl.draw_rectangle_lines_ex(rl.Rectangle(x - 2, y - 2, CELL + 4, CELL + 4), 2, TEXT)

    def draw_port_map(self, sel, now):
        h = self.hosts.get(sel) if sel is not None else None
        title = f"PORT SPACE  {BASE}.{sel}" if h else "PORT SPACE  waiting for first probe"
        rl.draw_text(title, PORT_X, 96, 14, DIM)
        rl.draw_rectangle(PORT_X, PORT_Y, 256 * PSZ, 256 * PSZ, PANEL)

        def xy(p):
            return PORT_X + (p % 256) * PSZ, PORT_Y + (p // 256) * PSZ

        for p in ICS_PORTS:                                # where the ICS ports live
            x, y = xy(p)
            rl.draw_rectangle_lines(x - 3, y - 3, 8, 8, C(255, 166, 87, 110))
        if h:
            for port, (state, t) in h.ports.items():
                x, y = xy(port)
                flash = max(0.0, 1.0 - (now - t) / 0.4)
                if state == PORT_OPEN:
                    rl.draw_rectangle(x - 1, y - 1, 4, 4, mix(GREEN, TEXT, flash))
                else:
                    base = BLUE if state == PORT_SENT else SLATE
                    rl.draw_rectangle(x, y, PSZ, PSZ, mix(base, TEXT, flash))
            for p in ICS_PORTS:
                if h.is_open(p):
                    x, y = xy(p)
                    rl.draw_rectangle_lines(x - 5, y - 5, 12, 12, ORANGE)
        rl.draw_rectangle_lines(PORT_X - 1, PORT_Y - 1, 256 * PSZ + 2, 256 * PSZ + 2, BORDER)
        rl.draw_text("1 pixel = 1 TCP port, 0 to 65535, 256 per row.  orange boxes = ICS ports",
                     PORT_X, PORT_Y + 256 * PSZ + 8, 12, DIM)

    def draw_bottom(self):
        rl.draw_text("ICS PORT HITS", HOST_X, BOT_Y, 14, DIM)
        total = max(1, len(self.hosts))
        for i, (port, name) in enumerate(ICS_PORTS.items()):
            y = BOT_Y + 22 + i * 15
            n = sum(1 for h in self.hosts.values() if h.is_open(port))
            rl.draw_text(str(port), HOST_X, y, 12, ORANGE)
            rl.draw_text(name, HOST_X + 60, y, 12, TEXT)
            rl.draw_rectangle(HOST_X + 220, y + 2, 250, 8, PANEL)
            rl.draw_rectangle(HOST_X + 220, y + 2, int(250 * n / total), 8, GREEN)
            rl.draw_text(str(n), HOST_X + 485, y, 12, TEXT)

        rl.draw_text("EVENT LOG", PORT_X, BOT_Y, 14, DIM)
        for i, (ts, text, col) in enumerate(self.log):
            rl.draw_text(f"{ts}  {text}", PORT_X, BOT_Y + 22 + i * 15, 12, col)

    @staticmethod
    def tooltip(lines, mx, my):
        w = max(rl.measure_text(t, 12) for t, _ in lines) + 20
        h = len(lines) * 16 + 14
        x, y = min(mx + 16, WIN_W - w - 6), min(my + 16, WIN_H - h - 6)
        rl.draw_rectangle(x, y, w, h, C(1, 4, 9, 240))
        rl.draw_rectangle_lines(x, y, w, h, BORDER)
        for i, (t, c) in enumerate(lines):
            rl.draw_text(t, x + 10, y + 8 + i * 16, 12, c)

    def draw_tooltips(self, mx, my, hover, sel):
        if hover is not None and hover in self.hosts:
            h = self.hosts[hover]
            lines = [(f"{BASE}.{hover}", TEXT)]
            if h.mac:
                lines.append((f"{h.mac}  {h.vendor}", DIM))
            ports = sorted(p for p, e in h.ports.items() if e[0] == PORT_OPEN)
            lines.append(("open: " + (", ".join(map(str, ports)) or "none yet"), GREEN))
            if h.plc:
                lines.append((h.plc, ORANGE))
            self.tooltip(lines, mx, my)
            return
        p = self.port_at(mx, my)
        if p is not None and sel in self.hosts:
            e = self.hosts[sel].ports.get(p)
            state = {None: "not probed", PORT_SENT: "probing", PORT_OPEN: "open",
                     PORT_CLOSED: "closed"}[e[0] if e else None]
            name = ICS_PORTS.get(p, "")
            self.tooltip([(f"port {p}  {name}", ORANGE if name else TEXT), (state, DIM)], mx, my)


def main():
    viz = Viz()
    threading.Thread(target=run_recon, daemon=True).start()

    rl.init_window(WIN_W, WIN_H, "ICS Recon")
    rl.set_target_fps(60)
    while not rl.window_should_close():
        viz.drain()
        m = rl.get_mouse_position()
        rl.begin_drawing()
        rl.clear_background(BG)
        viz.draw(int(m.x), int(m.y), time.time())
        rl.end_drawing()
    rl.close_window()

    if nmap_proc and nmap_proc.poll() is None:      # window closed mid-scan
        nmap_proc.terminate()


if __name__ == "__main__":
    main()
