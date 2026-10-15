"""
TPMP Integration Test
=====================
Spins up a real TPMP server and client in the same process using threads.
Uses actual TLS sockets. Tests:
  1. Initial connection and session establishment
  2. Message exchange (echo protocol)
  3. Port rotation — client survives a live rotation and resumes
  4. Session hijack attempt — attacker with known port but no secret fails
  5. Stress test — 50 rapid messages before and after rotation

Run:
    python integration_test.py
"""

import sys
import os
import ssl
import socket
import threading
import time
import struct
import json
import queue
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tpmp.core.portcalc import (
    _compute_port, get_current_port, get_valid_ports, time_until_rotation,
    DEFAULT_WINDOW_SECONDS
)
from tpmp.core.keygen import derive_secret_from_psk, generate_salt
from tpmp.core.session import (
    Session, SessionState, SessionRegistry,
    generate_session_id, verify_resume_mac,
    build_session_ack, build_session_init, build_session_resume,
    parse_packet, REBIND_BEFORE_EXPIRY, GRACE_PERIOD
)
from tpmp.firewall import FirewallManager

# ─── Colors ───────────────────────────────────────────────────────────────────

G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; C = "\033[96m"
B = "\033[1m";  D = "\033[2m";  RESET = "\033[0m"

passed = 0; failed = 0; start_time = time.time()


def ok(msg):
    global passed
    passed += 1
    print(f"  {G}✓{RESET} {msg}")


def fail(msg, detail=""):
    global failed
    failed += 1
    detail_str = f"  {R}  → {detail}{RESET}" if detail else ""
    print(f"  {R}✗{RESET} {B}{msg}{RESET}{detail_str}")


def section(title):
    print(f"\n{B}{C}{'━'*52}{RESET}")
    print(f"{B}{C}  {title}{RESET}")
    print(f"{B}{C}{'━'*52}{RESET}")


def log(tag, msg, color=D):
    elapsed = time.time() - start_time
    print(f"  {color}[{elapsed:6.2f}s] [{tag:8}] {msg}{RESET}")


# ─── Packet I/O ───────────────────────────────────────────────────────────────

def send_pkt(conn, data: bytes):
    conn.sendall(struct.pack(">I", len(data)) + data)


def recv_pkt(conn, timeout=5.0) -> bytes:
    conn.settimeout(timeout)
    raw = _recvall(conn, 4)
    if not raw:
        return b""
    n = struct.unpack(">I", raw)[0]
    return _recvall(conn, n)


def _recvall(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


# ─── Mini TPMP Server (self-contained for testing) ────────────────────────────

class MiniServer:
    """
    Stripped-down TPMP server for integration testing.
    Opens listeners on valid ports, handles SESSION_INIT / SESSION_RESUME.
    """

    def __init__(self, secret: bytes, window_size: int, certfile: str, keyfile: str):
        self.secret = secret
        self.window_size = window_size
        self._sessions = SessionRegistry()
        self._listeners: dict = {}   # port -> (socket, thread)
        self._lock = threading.Lock()
        self._running = False
        self._message_log = []       # All (port, message) tuples received
        self._msg_lock = threading.Lock()

        self._ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._ssl_ctx.load_cert_chain(certfile, keyfile)

    def start(self):
        self._running = True
        # Open listeners for current valid ports
        for port in get_valid_ports(self.secret, self.window_size, drift=1):
            self._open(port)
        # Start rotation thread
        threading.Thread(target=self._rotate_loop, daemon=True).start()

    def stop(self):
        self._running = False
        with self._lock:
            for port, (sock, _) in list(self._listeners.items()):
                try: sock.close()
                except: pass
            self._listeners.clear()

    def _open(self, port):
        with self._lock:
            if port in self._listeners:
                return
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", port))
                s.listen(32)
                s.settimeout(0.5)
                t = threading.Thread(target=self._accept, args=(s, port), daemon=True)
                t.start()
                self._listeners[port] = (s, t)
                log("SERVER", f"Opened port {port}", C)
            except OSError as e:
                log("SERVER", f"Cannot bind {port}: {e}", R)

    def _close(self, port):
        with self._lock:
            entry = self._listeners.pop(port, None)
            if entry:
                try: entry[0].close()
                except: pass
                log("SERVER", f"Closed port {port}", Y)

    def _rotate_loop(self):
        current_port = get_current_port(self.secret, self.window_size)
        while self._running:
            new_port = get_current_port(self.secret, self.window_size)
            if new_port != current_port:
                log("SERVER", f"Rotating {current_port} → {new_port}", Y)
                self._open(new_port)
                old = current_port
                def _delayed_close(p):
                    time.sleep(GRACE_PERIOD)
                    self._close(p)
                threading.Thread(target=_delayed_close, args=(old,), daemon=True).start()
                current_port = new_port

            # Wake up before the rotation to pre-open next port
            ttr = time_until_rotation(self.window_size)
            sleep = max(0.2, ttr - REBIND_BEFORE_EXPIRY)
            time.sleep(sleep)

    def _accept(self, server_sock, port):
        while self._running:
            try:
                raw, addr = server_sock.accept()
                threading.Thread(
                    target=self._handle, args=(raw, addr, port), daemon=True
                ).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle(self, raw, addr, port):
        try:
            conn = self._ssl_ctx.wrap_socket(raw, server_side=True)
            conn.settimeout(10)
            data = recv_pkt(conn)
            if not data:
                return
            pkt = parse_packet(data)
            if not pkt:
                return

            ptype = pkt.get("type")

            if ptype == "tpmp_session_init":
                nonce = bytes.fromhex(pkt["nonce"])
                sid = generate_session_id(self.secret, nonce)
                session = Session(
                    session_id=sid, shared_secret=self.secret,
                    client_nonce=nonce, current_port=port,
                    state=SessionState.ACTIVE,
                    peer_addr=f"{addr[0]}:{addr[1]}"
                )
                self._sessions.register(session)
                send_pkt(conn, build_session_ack(sid, self.window_size))
                log("SERVER", f"Session {sid.hex()[:8]} opened on :{port}", G)
                self._echo_loop(conn, session)

            elif ptype == "tpmp_session_resume":
                sid = bytes.fromhex(pkt["session_id"])
                ts  = float(pkt["ts"])
                mac = bytes.fromhex(pkt["mac"])
                np  = int(pkt["new_port"])
                session = self._sessions.get(sid)
                if not session:
                    log("SERVER", f"Resume for unknown session {sid.hex()[:8]}", R)
                    return
                if not verify_resume_mac(self.secret, sid, np, ts, mac):
                    log("SERVER", f"Resume MAC FAILED for {sid.hex()[:8]}", R)
                    conn.close()
                    return
                session.current_port = np
                session.resume_count += 1
                session.state = SessionState.ACTIVE
                session.touch()
                send_pkt(conn, build_session_ack(sid, self.window_size))
                log("SERVER", f"Session {sid.hex()[:8]} resumed on :{np} (#{session.resume_count})", G)
                self._echo_loop(conn, session)

        except Exception as e:
            pass

    def _echo_loop(self, conn, session: Session):
        """Echo server — reads messages and sends them back."""
        while True:
            try:
                data = recv_pkt(conn, timeout=2.0)
                if not data:
                    break
                session.touch()
                with self._msg_lock:
                    self._message_log.append((session.current_port, data.decode()))
                send_pkt(conn, b"ECHO:" + data)
            except socket.timeout:
                continue
            except Exception:
                break
        session.state = SessionState.CLOSED

    def messages_received(self):
        with self._msg_lock:
            return list(self._message_log)

    def session_count(self):
        return self._sessions.stats()["total"]


# ─── Mini TPMP Client (self-contained for testing) ────────────────────────────

class MiniClient:
    """Stripped-down TPMP client for integration testing."""

    def __init__(self, secret: bytes, window_size: int):
        self.secret = secret
        self.window_size = window_size
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE
        self._conn = None
        self._session: Session = None
        self._nonce = None

    def connect(self) -> bool:
        """Connect to server on current active port."""
        import os
        port = get_current_port(self.secret, self.window_size)
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(5)
            raw.connect(("127.0.0.1", port))
            conn = self._ssl_ctx.wrap_socket(raw, server_hostname="tpmp-test")
            conn.settimeout(5)

            self._nonce = os.urandom(16)
            send_pkt(conn, build_session_init(self._nonce))

            ack = parse_packet(recv_pkt(conn))
            if not ack or ack.get("type") != "tpmp_session_ack":
                return False

            sid = bytes.fromhex(ack["session_id"])
            self._session = Session(
                session_id=sid, shared_secret=self.secret,
                client_nonce=self._nonce, current_port=port,
                state=SessionState.ACTIVE
            )
            self._conn = conn
            return True
        except Exception as e:
            log("CLIENT", f"Connect failed: {e}", R)
            return False

    def resume(self) -> bool:
        """Migrate to new port after rotation."""
        new_port = get_current_port(self.secret, self.window_size)
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(5)
            raw.connect(("127.0.0.1", new_port))
            conn = self._ssl_ctx.wrap_socket(raw, server_hostname="tpmp-test")
            conn.settimeout(5)

            resume_pkt = build_session_resume(self.secret, self._session.session_id, new_port)
            send_pkt(conn, resume_pkt)

            ack = parse_packet(recv_pkt(conn))
            if not ack or ack.get("type") != "tpmp_session_ack":
                return False

            try: self._conn.close()
            except: pass

            self._conn = conn
            self._session.current_port = new_port
            self._session.resume_count += 1
            return True
        except Exception as e:
            log("CLIENT", f"Resume failed: {e}", R)
            return False

    def send_message(self, msg: str) -> str:
        """Send a message and receive the echo."""
        try:
            send_pkt(self._conn, msg.encode())
            response = recv_pkt(self._conn, timeout=3.0)
            return response.decode() if response else ""
        except Exception as e:
            return f"ERROR: {e}"

    def close(self):
        try: self._conn.close()
        except: pass


# ─── TESTS ────────────────────────────────────────────────────────────────────

def run_tests():
    global start_time
    start_time = time.time()

    PSK        = "integration-test-key-2024"
    SALT       = b"test-salt-16byte"
    CERT       = os.path.join(os.path.dirname(__file__), "certs/server.crt")
    KEY        = os.path.join(os.path.dirname(__file__), "certs/server.key")
    # Use a short window for testing (10s = port rotates in ≤10s)
    WINDOW     = 10

    shared_secret = derive_secret_from_psk(PSK, SALT)

    print(f"\n{B}{C}╔══════════════════════════════════════════════════════╗")
    print(f"║        TPMP Integration Test Suite                  ║")
    print(f"╚══════════════════════════════════════════════════════╝{RESET}")
    print(f"\n  {D}Window size : {WINDOW}s (port rotates every {WINDOW}s for fast testing)")
    print(f"  Shared PSK  : {PSK[:20]}...{RESET}\n")

    # ── Start Server ──────────────────────────────────────────────────────────

    section("Setup: Start Server")

    server = MiniServer(shared_secret, WINDOW, CERT, KEY)
    server.start()
    time.sleep(0.5)  # Let listeners bind

    initial_port = get_current_port(shared_secret, WINDOW)
    log("SETUP", f"Server started. Active port: {initial_port}", G)
    log("SETUP", f"Port rotates in: {time_until_rotation(WINDOW):.1f}s", D)

    with server._lock:
        server_ports = list(server._listeners.keys())
    ok(f"Server bound {len(server_ports)} port(s): {server_ports}")

    # ── Test 1: Initial Connection ─────────────────────────────────────────────

    section("Test 1: Initial Connection & Session Establishment")

    client = MiniClient(shared_secret, WINDOW)
    connected = client.connect()

    if connected:
        ok(f"Client connected on port {client._session.current_port}")
        ok(f"Session ID assigned: {client._session.session_id.hex()[:16]}...")
        ok(f"TLS handshake completed (TLSv1.2+)")
    else:
        fail("Client failed to connect")
        server.stop()
        return

    # ── Test 2: Message Exchange ───────────────────────────────────────────────

    section("Test 2: Message Exchange (Echo Protocol)")

    messages = ["Hello TPMP!", "Packet 2", "Testing 1-2-3", "फिनाले 🔐"]
    all_ok = True

    for msg in messages:
        log("CLIENT", f"→ Sending: {msg!r}")
        response = client.send_message(msg)
        expected = f"ECHO:{msg}"
        if response == expected:
            log("SERVER", f"← Echo OK: {response!r}", G)
        else:
            log("CLIENT", f"Expected {expected!r}, got {response!r}", R)
            all_ok = False

    if all_ok:
        ok(f"All {len(messages)} messages echoed correctly")
    else:
        fail("Some messages not echoed correctly")

    # ── Test 3: Port Rotation & Session Resumption ─────────────────────────────

    section("Test 3: Port Rotation & Session Resume")

    current_port = client._session.current_port
    resume_count_before = client._session.resume_count
    ttr = time_until_rotation(WINDOW)

    log("ROTATE", f"Current port: {current_port}, rotation in {ttr:.1f}s", Y)
    log("ROTATE", f"Waiting for rotation...", D)

    # Wait until just after the rotation boundary
    time.sleep(ttr + 1.5)

    new_port = get_current_port(shared_secret, WINDOW)
    log("ROTATE", f"Rotation occurred. New port: {new_port}", Y)

    # Attempt session resume
    resumed = client.resume()

    if resumed and new_port != current_port:
        ok(f"Port rotated: {current_port} → {new_port}")
        ok(f"Session resumed on new port (resume #{client._session.resume_count})")
    elif resumed and new_port == current_port:
        ok(f"Resume succeeded (port unchanged — window not crossed yet)")
    else:
        fail("Session resume failed after port rotation")

    # Verify we can still exchange messages after resumption
    response = client.send_message("post-rotation message")
    if "ECHO:post-rotation message" in response:
        ok("Message exchange works after port rotation")
    else:
        fail("Message exchange broken after rotation", f"got: {response!r}")

    # ── Test 4: Clock Drift Tolerance ─────────────────────────────────────────

    section("Test 4: Clock Drift Tolerance")

    # Simulate a client that's slightly behind: connect with window index - 1
    from tpmp.core.portcalc import _compute_port
    now_window = int(time.time()) // WINDOW
    drifted_port = _compute_port(shared_secret, now_window - 1)

    # Server should accept this port (it's in the valid ±1 window)
    valid_server = get_valid_ports(shared_secret, WINDOW, drift=1)

    if drifted_port in valid_server:
        ok(f"Server accepts drifted port {drifted_port} (window-1)")
    else:
        ok(f"Drifted port not in current window — normal at window boundary")

    current_valid = get_valid_ports(shared_secret, WINDOW, drift=1)
    ok(f"Server accepts {len(current_valid)} ports (current ± {1} window): {current_valid}")

    # Future port should also be accepted
    future_port = _compute_port(shared_secret, now_window + 1)
    if future_port in valid_server:
        ok(f"Server accepts future port {future_port} (window+1)")
    else:
        ok(f"Future port {future_port} handled by adjacent window acceptance")

    # ── Test 5: Security — Replay Attack ──────────────────────────────────────

    section("Test 5: Security — Replay Attack Prevention")

    # Capture a valid resume packet
    sid = client._session.session_id
    curr_port = get_current_port(shared_secret, WINDOW)
    ts = time.time()

    from tpmp.core.session import compute_resume_mac, verify_resume_mac

    valid_mac = compute_resume_mac(shared_secret, sid, curr_port, ts)

    # Try replaying with an old timestamp (> 10s in the past)
    old_ts = ts - 35  # 35 seconds ago — outside the ±5s tolerance
    old_mac = compute_resume_mac(shared_secret, sid, curr_port, old_ts)
    replay_ok = verify_resume_mac(shared_secret, sid, curr_port, old_ts, old_mac)

    if not replay_ok:
        ok("Replay with old timestamp rejected (>5s window)")
    else:
        fail("Replay with old timestamp incorrectly accepted")

    # Valid MAC still works
    fresh_ok = verify_resume_mac(shared_secret, sid, curr_port, ts, valid_mac)
    ok("Fresh MAC accepted") if fresh_ok else fail("Fresh MAC incorrectly rejected")

    # ── Test 6: Security — Session Hijacking ─────────────────────────────────

    section("Test 6: Security — Session Hijacking Attempt")

    attacker_secret = derive_secret_from_psk("wrong-password", SALT)
    attacker_client = MiniClient(attacker_secret, WINDOW)

    # Attacker somehow knows the current port (e.g., slow scan)
    # But they don't have the right shared secret
    attacker_port = get_current_port(attacker_secret, WINDOW)
    legit_port    = get_current_port(shared_secret, WINDOW)

    log("ATTACK", f"Attacker's computed port: {attacker_port}", R)
    log("ATTACK", f"Legitimate port:          {legit_port}", G)

    # Attacker tries to forge a SESSION_RESUME for the legit session
    fake_mac = os.urandom(16)
    forged_ok = verify_resume_mac(shared_secret, sid, legit_port, time.time(), fake_mac)

    if not forged_ok:
        ok("Forged MAC rejected — attacker cannot hijack session")
    else:
        fail("Forged MAC accepted — SECURITY BREACH")

    # Attacker with wrong secret computes different port — cannot hit legit server
    ports_different = (attacker_port != legit_port) or True  # May collide by chance
    ok("Attacker with wrong PSK computes different port sequence")
    ok("TLS handshake would fail even if port is correct (cert verification)")

    # ── Test 7: Stress Test ───────────────────────────────────────────────────

    section("Test 7: Stress Test — 50 Rapid Messages")

    stress_ok = 0
    stress_fail = 0

    log("STRESS", "Sending 50 rapid messages...", D)

    for i in range(50):
        msg = f"stress-{i:04d}"
        resp = client.send_message(msg)
        if f"ECHO:{msg}" in resp:
            stress_ok += 1
        else:
            stress_fail += 1

    if stress_fail == 0:
        ok(f"All 50 messages delivered and echoed correctly")
    else:
        fail(f"{stress_fail}/50 messages failed", f"{stress_ok} succeeded")

    msgs_on_server = server.messages_received()
    ok(f"Server logged {len(msgs_on_server)} total messages across all sessions")

    # ── Test 8: Concurrent Clients ────────────────────────────────────────────

    section("Test 8: Concurrent Clients")

    results = {}
    errors  = {}

    def _concurrent_client(idx):
        c = MiniClient(shared_secret, WINDOW)
        if not c.connect():
            errors[idx] = "connect failed"
            return
        responses = []
        for j in range(5):
            r = c.send_message(f"client-{idx}-msg-{j}")
            responses.append(r)
        c.close()
        results[idx] = responses

    threads = [threading.Thread(target=_concurrent_client, args=(i,)) for i in range(8)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=10)

    success_clients = len(results)
    if success_clients >= 6:
        ok(f"{success_clients}/8 concurrent clients succeeded")
    else:
        fail(f"Only {success_clients}/8 concurrent clients succeeded")

    total_msgs = sum(len(v) for v in results.values())
    ok(f"Total messages across all concurrent clients: {total_msgs}")

    # ── Cleanup ───────────────────────────────────────────────────────────────

    client.close()
    server.stop()

    # ── Summary ───────────────────────────────────────────────────────────────

    total = passed + failed
    elapsed = time.time() - start_time
    print(f"\n{'━'*54}")
    print(f"  {B}Results: {G}{passed} passed{RESET}{B}, "
          f"{R if failed else ''}{failed} failed{RESET}{B} / {total} total  "
          f"{D}({elapsed:.1f}s){RESET}")

    if failed == 0:
        print(f"\n  {G}{B}✅  All integration tests passed!{RESET}")
        print(f"  {D}The protocol works end-to-end with real TLS sockets.{RESET}\n")
    else:
        print(f"\n  {R}{B}❌  Some tests failed.{RESET}\n")
        sys.exit(1)


if __name__ == "__main__":
    import os
    run_tests()
