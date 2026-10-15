"""
TPMP Live Dashboard
====================
A real-time terminal dashboard. Run:  python dashboard.py
Press Ctrl+C to exit.
"""

import sys, os, time, threading, re, shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tpmp.core.portcalc import (
    get_current_port, get_valid_ports, get_port_schedule,
    time_until_rotation, _compute_port
)
from tpmp.core.keygen import derive_secret_from_psk
from tpmp.core.session import (
    Session, SessionState, generate_session_id
)
from tpmp.firewall import FirewallManager

# ─── ANSI helpers ──────────────────────────────────────────────────────────────

def clr():        return "\033[2J\033[H"
def bold(s):      return f"\033[1m{s}\033[0m"
def dim(s):       return f"\033[2m{s}\033[0m"
def c(s, n):      return f"\033[{n}m{s}\033[0m"
def green(s):     return c(s, 92)
def yellow(s):    return c(s, 93)
def red(s):       return c(s, 91)
def cyan(s):      return c(s, 96)
def blue(s):      return c(s, 94)
def magenta(s):   return c(s, 95)
def gray(s):      return c(s, 90)

ANSI = re.compile(r'\033\[[0-9;]*m')
def vlen(s): return len(ANSI.sub('', s))  # visible length (strips ANSI)

def pad(s, width):
    """Pad s to visible width."""
    return s + " " * max(0, width - vlen(s))

def prog_bar(val, total, width=20, hi_color=92, lo_color=91):
    ratio = min(1.0, max(0.0, val / total)) if total > 0 else 0
    filled = int(width * ratio)
    pct    = ratio * 100
    col    = hi_color if pct > 30 else lo_color
    return c("█" * filled, col) + gray("░" * (width - filled))


# ─── Fake Session Pool ─────────────────────────────────────────────────────────

class FakeSessionPool:
    def __init__(self, secret, window):
        self.secret = secret
        self.window = window
        self._sessions = []
        self._lock = threading.Lock()
        self._running = False

    def start(self):
        self._running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        import random
        addrs = [f"192.168.1.{i}" for i in range(10, 50)]
        while self._running:
            if random.random() < 0.35 and len(self._sessions) < 7:
                nonce = os.urandom(16)
                sid = generate_session_id(self.secret, nonce)
                s = Session(
                    session_id=sid, shared_secret=self.secret,
                    client_nonce=nonce, state=SessionState.ACTIVE,
                    current_port=get_current_port(self.secret, self.window),
                    peer_addr=f"{random.choice(addrs)}:{random.randint(1024,60000)}"
                )
                s.metadata["msgs"] = 0
                with self._lock:
                    self._sessions.append(s)

            with self._lock:
                alive = []
                for s in self._sessions:
                    s.metadata["msgs"] += random.randint(0, 4)
                    s.touch()
                    s.current_port = get_current_port(self.secret, self.window)
                    if s.age() < random.uniform(18, 45):
                        alive.append(s)
                self._sessions = alive

            time.sleep(1.5)

    def snapshot(self):
        with self._lock:
            return list(self._sessions)


# ─── Attacker Simulator ────────────────────────────────────────────────────────

class AttackSimulator:
    PORTS = 16383  # ephemeral range size

    def __init__(self, secret, window):
        self.secret = secret
        self.window = window
        self.progress = 0.0
        self.found_port = None
        self.found_at   = None
        self.scan_start = time.time()
        self.total_attempts = 0
        self._running = False

    def start(self):
        self._running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while self._running:
            self.scan_start  = time.time()
            self.progress    = 0.0
            self.found_port  = None
            self.found_at    = None
            port_at_scan_start = get_current_port(self.secret, self.window)

            for i in range(self.PORTS):
                if not self._running:
                    return
                self.progress = i / self.PORTS
                scan_port = 49152 + i
                current   = get_current_port(self.secret, self.window)
                if scan_port == current and self.found_port is None:
                    self.found_port = scan_port
                    self.found_at   = time.time() - self.scan_start
                    self.total_attempts += 1
                time.sleep(0.00183)  # ~546 ports/sec  → 30s full scan

            time.sleep(2.0)


# ─── Dashboard ────────────────────────────────────────────────────────────────

WINDOW = 30
PSK    = "dashboard-demo-key"
SALT   = b"dashboard-salt16"


def render_frame(secret, fw, pool, atk, tick):
    W, _ = shutil.get_terminal_size((110, 40))
    out = [clr()]

    def ln(s=""): out.append(s)

    # ── Title bar ──────────────────────────────────────────────────────────
    title = "  TPMP  ·  Temporal Port Mutation Protocol  ·  Live Dashboard  "
    ln(bold(cyan("╔" + "═" * (W - 2) + "╗")))
    ln(bold(cyan("║")) + bold(cyan(title.center(W - 2))) + bold(cyan("║")))
    ln(bold(cyan("╚" + "═" * (W - 2) + "╝")))
    ln()

    # ── Data ───────────────────────────────────────────────────────────────
    cur_port   = get_current_port(secret, WINDOW)
    ttr        = time_until_rotation(WINDOW)
    valid      = get_valid_ports(secret, WINDOW, drift=1)
    schedule   = get_port_schedule(secret, WINDOW, count=8)
    sessions   = pool.snapshot()
    fw_status  = fw.status()
    open_ports = fw_status["open_ports"]

    COL = (W - 6) // 2    # column content width

    # ── Row 1: Port Status  |  Session List ───────────────────────────────
    # ── Left: Port Status ─────────────────────────────────────────────────
    L, R = [], []

    L.append(bold(blue("┌─ Active Port" + " " + "─" * (COL - 14) + "┐")))
    L.append(blue("│") + f"  Port       : {bold(green(str(cur_port)))}" + " " * max(0, COL - 16 - len(str(cur_port))) + blue("│"))
    L.append(blue("│") + f"  Valid (±1)  : {dim(', '.join(str(p) for p in valid))}" + " " * max(0, COL - 16 - len(', '.join(str(p) for p in valid))) + blue("│"))

    bar_w = max(8, COL - 22)
    col   = 92 if ttr > 10 else (93 if ttr > 4 else 91)
    b     = prog_bar(WINDOW - ttr, WINDOW, width=bar_w, hi_color=col, lo_color=col)
    ttr_s = yellow(f"{ttr:4.1f}s")
    row   = blue("│") + f"  Rotates in : {b} {ttr_s}" + blue(" │")
    L.append(row)
    L.append(bold(blue("└" + "─" * (COL - 2) + "┘")))
    L.append("")

    # Port schedule
    L.append(bold(blue("┌─ Upcoming Port Schedule" + " " * (COL - 26) + "┐")))
    L.append(blue("│") + gray("   Port   Opens    Closes   Status       ") + " " * max(0, COL - 41) + blue("│"))
    for entry in schedule:
        port_s = str(entry["port"])
        opens  = time.strftime("%H:%M:%S", time.localtime(entry["window_start"]))
        closes = time.strftime("%H:%M:%S", time.localtime(entry["window_end"]))
        if entry["is_current"]:
            inner = green(f"  {port_s:<7} {opens}  {closes}  ◀ NOW")
            row   = blue("│") + pad(inner, COL - 2) + blue("│")
        else:
            inner = dim(f"  {port_s:<7} {opens}  {closes}")
            row   = blue("│") + pad(inner, COL - 2) + blue("│")
        L.append(row)
    L.append(bold(blue("└" + "─" * (COL - 2) + "┘")))

    # ── Right: Session List ────────────────────────────────────────────────
    R.append(bold(magenta("┌─ Server: Active Sessions" + " " * (COL - 27) + "┐")))
    R.append(magenta("│") + pad(dim(f"  {len(sessions)} session(s) authenticated"), COL - 2) + magenta("│"))
    R.append(magenta("│") + gray("  " + "─" * (COL - 4)) + magenta("│"))

    if not sessions:
        R.append(magenta("│") + pad(dim("  (waiting for connections...)"), COL - 2) + magenta("│"))
        for _ in range(4):
            R.append(magenta("│") + " " * (COL - 2) + magenta("│"))
    else:
        for s in sessions[:6]:
            sid8 = cyan(s.session_id.hex()[:8])
            peer = dim((s.peer_addr or "?")[:18])
            msgs = yellow(f"{s.metadata.get('msgs',0)}m")
            age  = dim(f"{int(s.age())}s")
            dot  = green("●") if s.state == SessionState.ACTIVE else yellow("◌")
            inner = f"  {dot} {sid8}  {peer}  {msgs} {age}"
            R.append(magenta("│") + pad(inner, COL - 2) + magenta("│"))
        for _ in range(max(0, 6 - len(sessions))):
            R.append(magenta("│") + " " * (COL - 2) + magenta("│"))

    R.append(bold(magenta("└" + "─" * (COL - 2) + "┘")))
    R.append("")

    # Attacker panel (right side, below sessions)
    R.append(bold(red("┌─ Attacker: nmap Scan Simulation" + " " * (COL - 34) + "┐")))
    bar_w2 = max(8, COL - 20)
    atk_b  = prog_bar(atk.progress, 1.0, width=bar_w2, hi_color=91, lo_color=91)
    R.append(red("│") + f"  Progress: {atk_b} {red(f'{atk.progress*100:5.1f}%')}" + red(" │"))

    scanned = int(atk.progress * 16383)
    R.append(red("│") + pad(gray(f"  Scanning ports 49152–65535 ({scanned:,}/16,383)"), COL - 2) + red("│"))

    if atk.found_port:
        tpmp_now  = get_current_port(secret, WINDOW)
        still_ok  = (atk.found_port == tpmp_now)
        status    = yellow("OPEN  but TLS blocks access!") if still_ok else red("CLOSED — port rotated away!")
        R.append(red("│") + f"  Found  : {yellow(str(atk.found_port))} at +{atk.found_at:.1f}s" + " " * max(0, COL - 2 - vlen(f"  Found  : {str(atk.found_port)} at +{atk.found_at:.1f}s")) + red("│"))
        R.append(red("│") + f"  Status : {status}" + " " * max(0, COL - 2 - 10 - vlen(status)) + red("│"))
    else:
        R.append(red("│") + pad(gray("  No open port found yet..."), COL - 2) + red("│"))
        R.append(red("│") + pad(gray("  Port rotates before scan completes!"), COL - 2) + red("│"))

    R.append(red("│") + pad(gray(f"  Total completed scans: {atk.total_attempts}"), COL - 2) + red("│"))
    R.append(bold(red("└" + "─" * (COL - 2) + "┘")))

    # ── Merge columns ──────────────────────────────────────────────────────
    max_rows = max(len(L), len(R))
    while len(L) < max_rows: L.append("")
    while len(R) < max_rows: R.append("")

    for l, r in zip(L, R):
        ln("   " + pad(l, COL + 2) + "  " + r)

    # ── Firewall row ───────────────────────────────────────────────────────
    ln()
    ln(bold(yellow("┌─ Firewall: iptables TPMP_PORTS chain" + " " * (W - 40) + "┐")))
    ports_str = "  ".join(green(str(p)) for p in open_ports) if open_ports else gray("none")
    fw_inner  = f"  Chain: {cyan('TPMP_PORTS')}  │  Open: {ports_str}  │  Mode: {gray('DRY-RUN (real: iptables -A TPMP_PORTS -p tcp --dport <port> -j ACCEPT)')}"
    ln(yellow("│") + pad(fw_inner, W - 4) + yellow("  │"))
    ln(bold(yellow("└" + "─" * (W - 2) + "┘")))

    # ── Footer ─────────────────────────────────────────────────────────────
    ln()
    ln(dim(f"   Tick #{tick:05d}  ·  {time.strftime('%Y-%m-%d %H:%M:%S')}  ·  Window size: {WINDOW}s  ·  Ctrl+C to exit"))

    sys.stdout.write("\n".join(out))
    sys.stdout.flush()


def main():
    secret = derive_secret_from_psk(PSK, SALT)

    fw = FirewallManager(dry_run=True)
    fw.initialize()

    pool = FakeSessionPool(secret, WINDOW)
    pool.start()

    atk = AttackSimulator(secret, WINDOW)
    atk.start()

    def _fw_sync():
        while True:
            for p in get_valid_ports(secret, WINDOW, drift=1):
                fw.open_port(p)
            time.sleep(2)

    threading.Thread(target=_fw_sync, daemon=True).start()

    tick = 0
    try:
        while True:
            render_frame(secret, fw, pool, atk, tick)
            tick += 1
            time.sleep(0.5)
    except KeyboardInterrupt:
        pool._running = False
        atk._running  = False
        fw.cleanup()
        sys.stdout.write(f"\n\n{bold(cyan('Dashboard stopped.'))}\n\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
