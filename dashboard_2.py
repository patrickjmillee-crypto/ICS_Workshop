import statistics
import subprocess
import threading
import time
from collections import deque

import pyray as pr
from pycomm3 import LogixDriver

PLC_IP = "192.168.10.245"
TEST_TAG = "Water_Tank_LVL"
TARGET_PORT = 44818

REFRESH_RATE = 1.0      # seconds between PLC polls
ROLLING_WINDOW = 10
GRAPH_POINTS = 120

BG        = pr.Color(18, 20, 26, 255)
PANEL     = pr.Color(30, 33, 42, 255)
BORDER    = pr.Color(55, 60, 75, 255)
TEXT      = pr.Color(230, 232, 238, 255)
MUTED     = pr.Color(140, 146, 160, 255)
GREEN     = pr.Color(80, 220, 120, 255)
YELLOW    = pr.Color(250, 200, 70, 255)
ORANGE    = pr.Color(255, 140, 60, 255)
RED       = pr.Color(255, 80, 80, 255)
CYAN      = pr.Color(80, 200, 255, 255)

STATUS_COLORS = {
    "Stable": GREEN,
    "ELEVATED": YELLOW,
    "High Latency": ORANGE,
    "ERROR": RED,
    "CRITICAL": RED,
    "CONNECTING": MUTED,
    "DISCONNECTED": RED,
}


def get_ping_latency(ip):
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for line in result.stdout.splitlines():
            if "time=" in line:
                return float(line.split("time=")[1].split()[0])
    except Exception:
        pass
    return None


def get_tcp_established_count(ip, port):
    try:
        result = subprocess.run(
            ["ss", "-tn", "state", "established"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return sum(1 for line in result.stdout.splitlines() if f"{ip}:{port}" in line)
    except Exception:
        return 0


def fmt_ms(value, none_text="ERROR"):
    return none_text if value is None else f"{value:.2f} ms"


def health_status(plc_ms, rolling_avg, consecutive_failures):
    if consecutive_failures >= 3:
        return "CRITICAL"
    if plc_ms is None:
        return "ERROR"
    if rolling_avg is not None:
        if rolling_avg >= 100:
            return "High Latency"
        if rolling_avg >= 40:
            return "ELEVATED"
    return "Stable"


# ---------------- background poller ----------------
class Poller(threading.Thread):
    """Polls the PLC in a thread so the UI never freezes on ping/ss/read."""

    def __init__(self):
        super().__init__(daemon=True)
        self.lock = threading.Lock()
        self.running = True
        self.start_time = time.time()
        self.history = deque(maxlen=GRAPH_POINTS)   # PLC read ms (None = failure)
        self.state = {
            "elapsed": 0.0,
            "ping_ms": None,
            "plc_ms": None,
            "tcp": 0,
            "last_value": None,
            "avg": None,
            "max": None,
            "samples": 0,
            "failures": 0,
            "consec": 0,
            "status": "CONNECTING",
            "connected": False,
            "error": "",
        }

    def snapshot(self):
        with self.lock:
            return dict(self.state), list(self.history)

    def run(self):
        plc_times = deque(maxlen=ROLLING_WINDOW)
        samples = failures = consec = 0
        last_value = None
        plc = None
        connected = False
        last_error = ""

        try:
            while self.running:
                loop_start = time.time()

                ping_ms = get_ping_latency(PLC_IP)
                tcp = get_tcp_established_count(PLC_IP, TARGET_PORT)

                plc_ms = None
                try:
                    if plc is None:
                        plc = LogixDriver(PLC_IP)
                    if not plc.connected:
                        plc.open()
                    connected = bool(plc.connected)

                    t0 = time.perf_counter()
                    result = plc.read(TEST_TAG)
                    elapsed_ms = (time.perf_counter() - t0) * 1000.0

                    if getattr(result, "error", None):
                        failures += 1
                        consec += 1
                        last_error = str(result.error)
                    else:
                        plc_ms = elapsed_ms
                        samples += 1
                        consec = 0
                        last_error = ""
                        plc_times.append(plc_ms)
                        last_value = result.value
                except Exception as e:
                    failures += 1
                    consec += 1
                    connected = False
                    last_error = str(e) or type(e).__name__
                    
                    try:
                        if plc is not None:
                            plc.close()
                    except Exception:
                        pass
                    plc = None

                if consec > 0:
                    plc_times.clear()

                rolling_avg = statistics.mean(plc_times) if plc_times else None
                rolling_max = max(plc_times) if plc_times else None
                status = health_status(plc_ms, rolling_avg, consec)
                if not connected:
                    status = "DISCONNECTED"

                with self.lock:
                    self.history.append(plc_ms)
                    self.state.update(
                        elapsed=time.time() - self.start_time,
                        ping_ms=ping_ms,
                        plc_ms=plc_ms,
                        tcp=tcp,
                        last_value=last_value,
                        avg=rolling_avg,
                        max=rolling_max,
                        samples=samples,
                        failures=failures,
                        consec=consec,
                        status=status,
                        connected=connected,
                        error=last_error,
                    )

                time.sleep(max(0.0, REFRESH_RATE - (time.time() - loop_start)))
        finally:
            try:
                if plc is not None:
                    plc.close()
            except Exception:
                pass


# ---------------- drawing ----------------
def draw_centered(text, cx, y, size, color):
    w = pr.measure_text(text, size)
    pr.draw_text(text, int(cx - w / 2), int(y), size, color)


def draw_panel(x, y, w, h, title):
    pr.draw_rectangle(int(x), int(y), int(w), int(h), PANEL)
    pr.draw_rectangle_lines(int(x), int(y), int(w), int(h), BORDER)
    pr.draw_text(title, int(x + 20), int(y + 14), 22, CYAN)
    pr.draw_line(int(x + 20), int(y + 46), int(x + w - 20), int(y + 46), BORDER)


def draw_row(label, value, x, y, w, color=TEXT):
    pr.draw_text(label, int(x + 20), int(y), 22, MUTED)
    vw = pr.measure_text(value, 22)
    pr.draw_text(value, int(x + w - 20 - vw), int(y), 22, color)


def draw_graph(x, y, w, h, history):
    draw_panel(x, y, w, h, "PLC READ LATENCY (ms)")
    gx, gy = x + 20, y + 60
    gw, gh = w - 40, h - 80
    pr.draw_rectangle_lines(int(gx), int(gy), int(gw), int(gh), BORDER)

    vals = [v for v in history if v is not None]
    top = max(vals + [50.0]) * 1.1
    for frac in (0.25, 0.5, 0.75):
        ly = gy + gh * frac
        pr.draw_line(int(gx), int(ly), int(gx + gw), int(ly), BORDER)
    pr.draw_text(f"{top:.0f}", int(gx + 6), int(gy + 4), 16, MUTED)
    pr.draw_text("0", int(gx + 6), int(gy + gh - 20), 16, MUTED)

    if len(history) < 2:
        return
    step = gw / (GRAPH_POINTS - 1)
    x0 = gx + gw - step * (len(history) - 1)
    prev = None
    for i, v in enumerate(history):
        px = x0 + i * step
        if v is None:
            # failed read: red tick along the bottom
            pr.draw_line(int(px), int(gy + gh - 12), int(px), int(gy + gh), RED)
            prev = None
            continue
        py = gy + gh - (v / top) * gh
        if prev is not None:
            pr.draw_line_ex(pr.Vector2(prev[0], prev[1]), pr.Vector2(px, py), 2, GREEN)
        prev = (px, py)


def draw_dashboard(s, history):
    sw, sh = pr.get_screen_width(), pr.get_screen_height()
    pad = 24
    pr.clear_background(BG)

    draw_centered("Read-Only PLC Monitor", sw / 2, 20, 40, TEXT)

    status = s["status"]
    scol = STATUS_COLORS.get(status, TEXT)
    info = f"{PLC_IP}   |   Tag: {TEST_TAG}   |   Refresh: {REFRESH_RATE}s   |   Uptime: {s['elapsed']:.0f}s"
    draw_centered(info, sw / 2, 72, 20, MUTED)
    draw_centered(f"STATUS: {status}", sw / 2, 100, 30, scol)

    dot = GREEN if s["connected"] else RED
    label = "PLC CONNECTED" if s["connected"] else "NO PLC CONNECTION - retrying..."
    lw = pr.measure_text(label, 20)
    pr.draw_circle(sw - pad - lw - 18, 32, 7, dot)
    pr.draw_text(label, sw - pad - lw, 22, 20, dot)
    if s["error"] and not s["connected"]:
        err = s["error"][:110]
        draw_centered(err, sw / 2, 132, 16, MUTED)

    top = 160
    pw = (sw - pad * 3) / 2
    ph = 270

    # CURRENT
    draw_panel(pad, top, pw, ph, "CURRENT")
    ping_txt = "TIMEOUT" if s["ping_ms"] is None else f"{s['ping_ms']:.2f} ms"
    rows = [
        ("Ping Latency", ping_txt, TEXT),
        ("PLC Read Latency", fmt_ms(s["plc_ms"]), TEXT),
        (f"TCP ESTAB on {TARGET_PORT}", str(s["tcp"]), TEXT),
        ("Last Tag Value", "N/A" if s["last_value"] is None else str(s["last_value"]), CYAN),
        ("Consecutive Failures", str(s["consec"]), RED if s["consec"] else TEXT),
    ]
    for i, (lbl, val, col) in enumerate(rows):
        draw_row(lbl, val, pad, top + 64 + i * 38, pw, col)

    # ROLLING
    rx = pad * 2 + pw
    draw_panel(rx, top, pw, ph, f"ROLLING ({ROLLING_WINDOW})")
    rows = [
        ("Rolling Average", fmt_ms(s["avg"], "N/A"), TEXT),
        ("Rolling Max", fmt_ms(s["max"], "N/A"), TEXT),
        ("Successful Samples", str(s["samples"]), GREEN),
        ("Failures", str(s["failures"]), RED if s["failures"] else TEXT),
    ]
    for i, (lbl, val, col) in enumerate(rows):
        draw_row(lbl, val, rx, top + 64 + i * 38, pw, col)

    # GRAPH
    gtop = top + ph + pad
    draw_graph(pad, gtop, sw - pad * 2, max(150, sh - gtop - pad), history)


def main():
    pr.set_config_flags(pr.ConfigFlags.FLAG_WINDOW_RESIZABLE | pr.ConfigFlags.FLAG_MSAA_4X_HINT)
    pr.init_window(1280, 800, "PLC DASHBOARD")
    pr.set_target_fps(60)

    poller = Poller()
    poller.start()

    try:
        while not pr.window_should_close():
            if pr.is_key_pressed(pr.KeyboardKey.KEY_F11):
                pr.toggle_fullscreen()
            s, history = poller.snapshot()
            pr.begin_drawing()
            draw_dashboard(s, history)
            pr.end_drawing()
    finally:
        poller.running = False
        pr.close_window()


if __name__ == "__main__":
    try:
        print("starting")
        main()
    except KeyboardInterrupt:
        print("\nMonitor stopped")