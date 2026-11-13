"""
cip_sessions_viz.py - your cip_sessions.py with a live raylib view.

    pip install raylib pycomm3
    python3 cip_sessions_viz.py

What it shows (dark theme):
  one lane per client, scrolling latency history (ms)
  a live summary header: samples, min/median/mean/max/stdev, errors
  a per-client strip: last latency, OK/ERR counts, connection state
ESC closes the window early (the worker threads are daemons and the
test just stops reporting; it does not stop mid-read on the wire).

This does not change cip_sessions.py's logic: same tags, same clients,
same read rate, same duration. It only taps the same data your
original print statements used and feeds it to the window instead of
(or alongside) the console.
"""
import queue
import statistics
import threading
import time

import pyray as rl
from pycomm3 import LogixDriver

# ---- same config as your original script -------------------------------
PLC_IP = "192.168.10.245"

TAGS_TO_READ = [
    "TEST_DINT_1",
    "TEST_DINT_2",
    "TEST_REAL_1",
    "Water_Tank_LVL",
    "EH_Flow",
    "False_Water_Level",
]

NUM_CLIENTS = 6
READS_PER_SECOND_PER_CLIENT = 4
TEST_DURATION_SEC = 60
STAGGER_START_SEC = 0.25

read_interval = 1.0 / READS_PER_SECOND_PER_CLIENT

events = queue.SimpleQueue()      # worker threads -> window
stop_event = threading.Event()


# ---- your original worker, instrumented to also report to the window ---
def worker(client_id):
    events.put(("connecting", client_id))
    try:
        with LogixDriver(PLC_IP, init_tags=True) as plc:
            events.put(("connected", client_id))
            start = time.time()

            while not stop_event.is_set() and (time.time() - start) < TEST_DURATION_SEC:
                t0 = time.perf_counter()
                try:
                    response = plc.read(*TAGS_TO_READ)
                    dt_ms = (time.perf_counter() - t0) * 1000.0

                    ok = True
                    if not isinstance(response, list):
                        response = [response]
                    for tag_result in response:
                        if getattr(tag_result, "error", None):
                            ok = False
                            break

                    if ok:
                        events.put(("ok", client_id, dt_ms))
                    else:
                        events.put(("err", client_id, "tag error"))

                except Exception as e:
                    events.put(("err", client_id, str(e)))

                elapsed = time.perf_counter() - t0
                time.sleep(max(0.0, read_interval - elapsed))

    except Exception as e:
        events.put(("connect_err", client_id, str(e)))

    events.put(("done", client_id))


def run_test():
    threads = []
    for i in range(NUM_CLIENTS):
        t = threading.Thread(target=worker, args=(i + 1,), daemon=True)
        threads.append(t)
        t.start()
        time.sleep(STAGGER_START_SEC)
    for t in threads:
        t.join()
    events.put(("all_done",))


# --------------------------------------------------------------------------
#  Visualiser
# --------------------------------------------------------------------------
def C(r, g, b, a=255):
    return rl.Color(r, g, b, a)


BG, PANEL, BORDER = C(13, 17, 23), C(22, 27, 34), C(48, 54, 61)
TEXT, DIM = C(230, 237, 243), C(125, 133, 144)
BLUE, GREEN, ORANGE, RED, SLATE = C(88, 166, 255), C(63, 185, 80), C(255, 166, 87), C(248, 81, 73), C(60, 68, 80)

WIN_W, WIN_H = 1100, 760
HIST_LEN = 240          # samples of history kept per client for the scroll


class Client:
    def __init__(self, cid):
        self.id = cid
        self.state = "pending"     # pending / connecting / connected / done / error
        self.history = []          # list of (latency_ms or None-for-error)
        self.ok = 0
        self.err = 0
        self.last = None
        self.err_msg = ""

    def push(self, val):
        self.history.append(val)
        if len(self.history) > HIST_LEN:
            self.history.pop(0)


class Viz:
    def __init__(self):
        self.clients = {i: Client(i) for i in range(1, NUM_CLIENTS + 1)}
        self.all_latencies = []
        self.t0 = time.time()
        self.t_end = None
        self.finished = False

    def drain(self):
        for _ in range(2000):
            try:
                ev = events.get_nowait()
            except queue.Empty:
                break
            kind = ev[0]
            if kind == "connecting":
                self.clients[ev[1]].state = "connecting"
            elif kind == "connected":
                self.clients[ev[1]].state = "connected"
            elif kind == "ok":
                c = self.clients[ev[1]]
                c.state, c.last, c.ok = "connected", ev[2], c.ok + 1
                c.push(ev[2])
                self.all_latencies.append(ev[2])
            elif kind == "err":
                c = self.clients[ev[1]]
                c.err, c.err_msg = c.err + 1, ev[2]
                c.push(None)
            elif kind == "connect_err":
                c = self.clients[ev[1]]
                c.state, c.err_msg = "error", ev[2]
            elif kind == "done":
                c = self.clients[ev[1]]
                if c.state != "error":
                    c.state = "done"
            elif kind == "all_done":
                self.finished, self.t_end = True, time.time()

    # ---- drawing ---------------------------------------------------
    @staticmethod
    def state_color(state):
        return {"pending": SLATE, "connecting": ORANGE, "connected": GREEN,
                "done": BLUE, "error": RED}.get(state, SLATE)

    def draw(self, now):
        rl.draw_text("CIP SESSION LOAD TEST", 30, 16, 28, TEXT)
        rl.draw_text(f"{PLC_IP}   |   {NUM_CLIENTS} clients x "
                     f"{READS_PER_SECOND_PER_CLIENT} reads/sec   |   {len(TAGS_TO_READ)} tags/read",
                     30, 50, 14, DIM)

        end = self.t_end or now
        el = int(end - self.t0)
        label = "COMPLETE" if self.finished else f"{el}s / {TEST_DURATION_SEC}s"
        col = GREEN if self.finished else BLUE
        w = rl.measure_text(label, 16) + 20
        rl.draw_rectangle_rounded(rl.Rectangle(WIN_W - w - 30, 20, w, 26), 0.5, 8, col)
        rl.draw_text(label, WIN_W - w - 20, 26, 16, BG)

        self.draw_summary()
        self.draw_lanes(now)

    def draw_summary(self):
        y = 80
        rl.draw_rectangle(30, y, WIN_W - 60, 70, PANEL)
        rl.draw_rectangle_lines(30, y, WIN_W - 60, 70, BORDER)
        lat = self.all_latencies
        total_ok = sum(c.ok for c in self.clients.values())
        total_err = sum(c.err for c in self.clients.values())
        if lat:
            stats = [
                ("samples", f"{len(lat)}"),
                ("min", f"{min(lat):.1f} ms"),
                ("median", f"{statistics.median(lat):.1f} ms"),
                ("mean", f"{statistics.mean(lat):.1f} ms"),
                ("max", f"{max(lat):.1f} ms"),
                ("stdev", f"{statistics.stdev(lat):.1f} ms" if len(lat) >= 2 else "-"),
            ]
        else:
            stats = [("samples", "0"), ("min", "-"), ("median", "-"),
                     ("mean", "-"), ("max", "-"), ("stdev", "-")]
        cw = (WIN_W - 60) // (len(stats) + 1)
        for i, (label, val) in enumerate(stats):
            x = 30 + i * cw + 20
            rl.draw_text(label.upper(), x, y + 10, 11, DIM)
            rl.draw_text(val, x, y + 28, 20, TEXT)
        x = 30 + len(stats) * cw + 20
        rl.draw_text("OK / ERR", x, y + 10, 11, DIM)
        rl.draw_text(f"{total_ok} / {total_err}", x, y + 28, 20, GREEN if total_err == 0 else ORANGE)

    def draw_lanes(self, now):
        top = 170
        lane_h = (WIN_H - top - 30) // NUM_CLIENTS
        graph_x, graph_w = 330, WIN_W - 330 - 50
        max_ms = 50.0  # scale ceiling; auto-raises below if exceeded

        all_vals = [v for c in self.clients.values() for v in c.history if v is not None]
        if all_vals:
            max_ms = max(50.0, max(all_vals) * 1.15)

        for i, c in enumerate(self.clients.values()):
            y = top + i * lane_h
            rl.draw_rectangle(30, y, WIN_W - 60, lane_h - 6, PANEL)
            col = self.state_color(c.state)
            rl.draw_rectangle(30, y, 6, lane_h - 6, col)

            rl.draw_text(f"Client {c.id}", 46, y + 6, 15, TEXT)
            rl.draw_text(c.state.upper(), 46, y + 26, 11, col)
            last_txt = f"{c.last:.1f} ms" if c.last is not None else "-"
            rl.draw_text(last_txt, 46, y + 42, 13, DIM)
            rl.draw_text(f"OK {c.ok}  ERR {c.err}", 180, y + 26, 11, DIM)
            if c.state == "error":
                rl.draw_text(c.err_msg[:30], 180, y + 42, 10, RED)

            # scrolling latency graph for this client
            gx, gy, gw, gh = graph_x, y + 6, graph_w, lane_h - 16
            rl.draw_rectangle(gx, gy, gw, gh, BG)
            n = len(c.history)
            if n > 1:
                step = gw / (HIST_LEN - 1)
                prev = None
                for idx, val in enumerate(c.history):
                    px = gx + idx * step
                    if val is None:
                        prev = None
                        rl.draw_line(int(px), gy, int(px), gy + gh, RED)
                        continue
                    py = gy + gh - int(min(1.0, val / max_ms) * gh)
                    if prev is not None:
                        rl.draw_line(int(prev[0]), int(prev[1]), int(px), int(py), col)
                    rl.draw_circle(int(px), int(py), 1.5, col)
                    prev = (px, py)
            rl.draw_rectangle_lines(gx, gy, gw, gh, BORDER)

        rl.draw_text(f"scale: 0 - {max_ms:.0f} ms    red tick = failed read", 30, WIN_H - 22, 12, DIM)


def main():
    threading.Thread(target=run_test, daemon=True).start()

    rl.init_window(WIN_W, WIN_H, "CIP Session Load Test")
    rl.set_target_fps(30)
    viz = Viz()
    while not rl.window_should_close():
        viz.drain()
        rl.begin_drawing()
        rl.clear_background(BG)
        viz.draw(time.time())
        rl.end_drawing()
    stop_event.set()
    rl.close_window()


if __name__ == "__main__":
    main()
