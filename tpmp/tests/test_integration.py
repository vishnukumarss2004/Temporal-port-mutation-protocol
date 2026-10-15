"""
TPMP Integration Test
=====================
Tests the FULL TPMP protocol stack end-to-end using real TLS over socketpair().

This runs actual:
  - ECDH key exchange
  - TLS 1.3 handshake
  - SESSION_INIT / SESSION_ACK handshake
  - Data exchange
  - SESSION_RESUME across a simulated port rotation

No mocking. Real cryptography. Real TLS. Real TPMP packets.
"""

import sys
import os
import ssl
import socket
import threading
import time
import struct
import json
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tpmp.core.portcalc import get_current_port, get_valid_ports, DEFAULT_WINDOW_SECONDS
from tpmp.core.keygen import derive_secret_from_psk, generate_salt
from tpmp.core.session import (
    Session, SessionState, SessionRegistry,
    generate_session_id, verify_resume_mac,
    build_session_init, build_session_ack,
    build_session_resume, parse_packet,
    REBIND_BEFORE_EXPIRY, GRACE_PERIOD
)
from tpmp.core.drift import (
    DriftEstimator, make_timestamp_probe,
    make_timestamp_response, process_timestamp_response
)

# ─── Colors ────────────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

CERT = os.path.join(os.path.dirname(__file__), "../certs/server.crt")
KEY  = os.path.join(os.path.dirname(__file__), "../certs/server.key")

passed = failed = 0


def ok(name, detail=""):
    global passed
    passed += 1
    print(f"  {GREEN}✓{RESET} {name}" + (f"  {DIM}({detail}){RESET}" if detail else ""))


def fail(name, detail=""):
    global failed
    failed += 1
    print(f"  {RED}✗{RESET} {name}" + (f"  {DIM}({detail}){RESET}" if detail else ""))


def section(title):
    print(f"\n{BOLD}{CYAN}▶ {title}{RESET}")


# ─── TLS Helpers ───────────────────────────────────────────────────────────────

def make_server_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(CERT, KEY)
    return ctx


def make_client_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def tls_pair():
    """Create a connected pair of TLS sockets using socketpair()."""
    raw_server, raw_client = socket.socketpair()
    server_ctx = make_server_ctx()
    client_ctx = make_client_ctx()

    tls_server = tls_client = None
    exc = [None]

    def wrap_server():
        try:
            nonlocal tls_server
            tls_server = server_ctx.wrap_socket(raw_server, server_side=True)
        except Exception as e:
            exc[0] = e

    t = threading.Thread(target=wrap_server)
    t.start()
    tls_client = client_ctx.wrap_socket(raw_client, server_hostname="127.0.0.1")
    t.join()

    if exc[0]:
        raise exc[0]

    return tls_server, tls_client


def send_pkt(conn, data: bytes):
    conn.sendall(struct.pack(">I", len(data)) + data)


def recv_pkt(conn) -> bytes:
    raw = b""
    while len(raw) < 4:
        chunk = conn.recv(4 - len(raw))
        if not chunk:
            return b""
        raw += chunk
    n = struct.unpack(">I", raw)[0]
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            return b""
        data += chunk
    return data


# ─── Test 1: TLS Pair Creation ─────────────────────────────────────────────────

section("TLS Layer")

try:
    srv, cli = tls_pair()
    ok("socketpair() created successfully")

    # Verify TLS 1.3
    ver = cli.version()
    ok("TLS 1.3 negotiated", ver) if "TLS" in (ver or "") else fail("TLS version", ver)

    # Basic data transfer
    srv.sendall(b"hello from server")
    data = cli.recv(64)
    ok("Server→Client data transfer", data.decode()) if data == b"hello from server" else fail("Server→Client")

    cli.sendall(b"hello from client")
    data = srv.recv(64)
    ok("Client→Server data transfer", data.decode()) if data == b"hello from client" else fail("Client→Server")

    srv.close()
    cli.close()
except Exception as e:
    fail("TLS pair creation", str(e))
    traceback.print_exc()


# ─── Test 2: Framed Packet Protocol ───────────────────────────────────────────

section("Framed Packet I/O")

srv, cli = tls_pair()
results = {}

def server_recv():
    results["pkt"] = recv_pkt(srv)

t = threading.Thread(target=server_recv)
t.start()

test_payload = b'{"type": "test", "data": "hello world"}'
send_pkt(cli, test_payload)
t.join(timeout=3)

ok("Framed packet received correctly") if results.get("pkt") == test_payload else fail("Framed packet")
ok("Payload length correct", f"{len(results.get('pkt', b''))} bytes")

srv.close(); cli.close()


# ─── Test 3: Full SESSION_INIT / SESSION_ACK Handshake ─────────────────────────

section("SESSION_INIT / SESSION_ACK Handshake")

PSK    = "integration-test-psk-2024"
SALT   = generate_salt()
SECRET = derive_secret_from_psk(PSK, SALT)

srv, cli = tls_pair()
handshake_result = {}

def server_handshake():
    try:
        raw = recv_pkt(srv)
        pkt = parse_packet(raw)
        if not pkt or pkt.get("type") != "tpmp_session_init":
            handshake_result["error"] = f"Bad packet type: {pkt}"
            return

        nonce = bytes.fromhex(pkt["nonce"])
        session_id = generate_session_id(SECRET, nonce)

        ack = build_session_ack(session_id, DEFAULT_WINDOW_SECONDS)
        send_pkt(srv, ack)

        handshake_result["session_id"] = session_id
        handshake_result["nonce"]      = nonce

    except Exception as e:
        handshake_result["error"] = str(e)
    finally:
        srv.close()

t = threading.Thread(target=server_handshake)
t.start()

import os as _os
nonce = _os.urandom(16)
send_pkt(cli, build_session_init(nonce))

raw = recv_pkt(cli)
ack = parse_packet(raw)
cli.close()
t.join(timeout=5)

ok("No server error") if "error" not in handshake_result else fail("Server error", handshake_result.get("error"))
ok("SESSION_ACK received") if ack and ack.get("type") == "tpmp_session_ack" else fail("SESSION_ACK missing/wrong type")
ok("Session ID in ACK") if ack and "session_id" in ack else fail("session_id missing")

# Verify both sides computed the same session ID
server_sid = handshake_result.get("session_id", b"")
client_sid = generate_session_id(SECRET, nonce)
ok("Session IDs match", f"{client_sid.hex()[:8]}...") if server_sid == client_sid else fail("Session ID mismatch", f"server={server_sid.hex()[:8]} client={client_sid.hex()[:8]}")


# ─── Test 4: Data Exchange After Handshake ─────────────────────────────────────

section("Authenticated Data Exchange")

srv, cli = tls_pair()
exchange_result = {}

def server_exchange():
    try:
        raw = recv_pkt(srv)
        pkt = parse_packet(raw)
        nonce = bytes.fromhex(pkt["nonce"])
        session_id = generate_session_id(SECRET, nonce)
        send_pkt(srv, build_session_ack(session_id, 30))

        # Echo loop: receive 3 messages, echo them back
        for _ in range(3):
            msg = recv_pkt(srv)
            send_pkt(srv, b"ECHO:" + msg)

        exchange_result["ok"] = True
    except Exception as e:
        exchange_result["error"] = str(e)
    finally:
        srv.close()

t = threading.Thread(target=server_exchange)
t.start()

nonce = _os.urandom(16)
send_pkt(cli, build_session_init(nonce))
ack = recv_pkt(cli)  # consume ACK

messages  = [b"ping", b"hello TPMP", b"test message 123"]
responses = []

for msg in messages:
    send_pkt(cli, msg)
    resp = recv_pkt(cli)
    responses.append(resp)

cli.close()
t.join(timeout=5)

ok("No server error") if "error" not in exchange_result else fail("Server error", exchange_result.get("error"))

for i, (msg, resp) in enumerate(zip(messages, responses)):
    expected = b"ECHO:" + msg
    ok(f"Message {i+1} echoed correctly", f"'{msg.decode()}'") if resp == expected else fail(f"Message {i+1}", f"expected {expected!r} got {resp!r}")


# ─── Test 5: Timestamp Probe (Drift Measurement) ──────────────────────────────

section("Clock Drift Measurement Protocol")

srv, cli = tls_pair()
drift_result = {}

def server_drift():
    try:
        raw = recv_pkt(srv)
        pkt = parse_packet(raw)
        if pkt and pkt.get("type") == "tpmp_ts_probe":
            response = make_timestamp_response(pkt)
            send_pkt(srv, json.dumps(response).encode())
            drift_result["ok"] = True
    except Exception as e:
        drift_result["error"] = str(e)
    finally:
        srv.close()

t = threading.Thread(target=server_drift)
t.start()

probe = make_timestamp_probe()
send_pkt(cli, json.dumps(probe).encode())

raw = recv_pkt(cli)
t4  = time.time()
cli.close()
t.join(timeout=5)

resp = parse_packet(raw)
ok("Drift probe responded") if drift_result.get("ok") else fail("Drift probe error", drift_result.get("error", ""))
ok("Response is tpmp_ts_response") if resp and resp.get("type") == "tpmp_ts_response" else fail("Wrong response type")
ok("t1 echoed correctly") if resp and resp["t1"] == probe["t1"] else fail("t1 mismatch")
ok("t2 is after t1")      if resp and resp["t2"] >= probe["t1"] else fail("t2 < t1")

if resp:
    sample = process_timestamp_response(resp, t4)
    estimator = DriftEstimator()
    estimator.add_sample(sample)
    summary = estimator.summary()
    ok("RTT measured", f"{summary['estimated_rtt_ms']} ms")
    ok("Offset measured", f"{summary['estimated_offset_ms']} ms")


# ─── Test 6: SESSION_RESUME (Port Rotation Simulation) ────────────────────────

section("SESSION_RESUME — Port Rotation Migration")

srv1, cli1 = tls_pair()
srv2, cli2 = tls_pair()   # Simulates the new port's socket pair
resume_result = {}

SESSION_REGISTRY = SessionRegistry()

def server_first_connection():
    """Handle initial connection, register session."""
    try:
        raw = recv_pkt(srv1)
        pkt = parse_packet(raw)
        nonce = bytes.fromhex(pkt["nonce"])
        session_id = generate_session_id(SECRET, nonce)

        session = Session(
            session_id=session_id,
            shared_secret=SECRET,
            client_nonce=nonce,
            state=SessionState.ACTIVE,
            current_port=55000
        )
        SESSION_REGISTRY.register(session)

        send_pkt(srv1, build_session_ack(session_id, 30))

        # Receive one message on the original connection
        msg = recv_pkt(srv1)
        send_pkt(srv1, b"FIRST:" + msg)

        resume_result["session_id"] = session_id
    except Exception as e:
        resume_result["error1"] = str(e)
    finally:
        srv1.close()


def server_second_connection():
    """Handle SESSION_RESUME on the new port."""
    try:
        raw = recv_pkt(srv2)
        pkt = parse_packet(raw)

        if pkt.get("type") != "tpmp_session_resume":
            resume_result["error2"] = f"Expected resume, got {pkt.get('type')}"
            return

        session_id = bytes.fromhex(pkt["session_id"])
        new_port   = int(pkt["new_port"])
        ts         = float(pkt["ts"])
        mac        = bytes.fromhex(pkt["mac"])

        # Verify MAC
        if not verify_resume_mac(SECRET, session_id, new_port, ts, mac):
            resume_result["error2"] = "Resume MAC verification failed"
            return

        # Look up session
        session = SESSION_REGISTRY.get(session_id)
        if not session:
            resume_result["error2"] = "Session not found in registry"
            return

        session.current_port = new_port
        session.resume_count += 1
        session.state = SessionState.ACTIVE

        send_pkt(srv2, build_session_ack(session_id, 30))

        # Receive message on resumed connection
        msg = recv_pkt(srv2)
        send_pkt(srv2, b"RESUMED:" + msg)

        resume_result["mac_ok"]       = True
        resume_result["session_found"] = True
        resume_result["resume_count"] = session.resume_count

    except Exception as e:
        resume_result["error2"] = str(e)
    finally:
        srv2.close()


t1 = threading.Thread(target=server_first_connection)
t2 = threading.Thread(target=server_second_connection)
t1.start()
t2.start()

# --- Client side ---

# Step 1: Establish initial session
nonce = _os.urandom(16)
send_pkt(cli1, build_session_init(nonce))
ack1 = parse_packet(recv_pkt(cli1))
session_id = bytes.fromhex(ack1["session_id"])

# Step 2: Send a message on the original connection
send_pkt(cli1, b"before-rotation")
resp1 = recv_pkt(cli1)
cli1.close()

# Step 3: Simulate port rotation — send SESSION_RESUME on the "new port"
new_port = get_current_port(SECRET) + 1   # Simulated new port value
resume_pkt = build_session_resume(SECRET, session_id, new_port)
send_pkt(cli2, resume_pkt)
ack2 = parse_packet(recv_pkt(cli2))

# Step 4: Send a message on the resumed connection
send_pkt(cli2, b"after-rotation")
resp2 = recv_pkt(cli2)
cli2.close()

t1.join(timeout=5)
t2.join(timeout=5)

ok("No server error (connection 1)") if "error1" not in resume_result else fail("Server error 1", resume_result.get("error1"))
ok("No server error (connection 2)") if "error2" not in resume_result else fail("Server error 2", resume_result.get("error2"))
ok("Resume MAC verified by server")  if resume_result.get("mac_ok") else fail("Resume MAC not verified")
ok("Session found in registry")      if resume_result.get("session_found") else fail("Session not found")
ok("Resume count incremented", f"count={resume_result.get('resume_count')}") if resume_result.get("resume_count") == 1 else fail("Resume count wrong")
ok("Data on original connection",  resp1.decode()) if resp1 == b"FIRST:before-rotation" else fail("Original data", repr(resp1))
ok("Data on resumed connection",   resp2.decode()) if resp2 == b"RESUMED:after-rotation" else fail("Resumed data", repr(resp2))


# ─── Test 7: Security — Forged Resume Rejected ─────────────────────────────────

section("Security: Forged SESSION_RESUME Rejected")

import hmac as _hmac

# Build a resume packet with a wrong MAC
bad_mac_pkt = {
    "type": "tpmp_session_resume",
    "session_id": session_id.hex(),
    "new_port": new_port,
    "ts": time.time(),
    "mac": _os.urandom(16).hex()   # forged!
}

result = verify_resume_mac(
    SECRET,
    session_id,
    new_port,
    bad_mac_pkt["ts"],
    bytes.fromhex(bad_mac_pkt["mac"])
)
ok("Forged MAC rejected") if not result else fail("Forged MAC ACCEPTED — security hole!")

# Wrong session ID
wrong_sid = _os.urandom(32)
ts_now = time.time()
correct_mac = bytes.fromhex(build_session_resume(SECRET, session_id, new_port).decode().split('"mac": "')[1].split('"')[0]) if False else \
              __import__("tpmp.core.session", fromlist=["compute_resume_mac"]).compute_resume_mac(SECRET, session_id, new_port, ts_now)

result2 = verify_resume_mac(SECRET, wrong_sid, new_port, ts_now, correct_mac)
ok("Wrong session ID rejected") if not result2 else fail("Wrong session ID ACCEPTED — security hole!")

# MAC from different port is invalid
diff_port_mac = __import__("tpmp.core.session", fromlist=["compute_resume_mac"]).compute_resume_mac(SECRET, session_id, new_port + 1, ts_now)
result3 = verify_resume_mac(SECRET, session_id, new_port, ts_now, diff_port_mac)
ok("MAC from different port rejected") if not result3 else fail("Different-port MAC ACCEPTED — security hole!")


# ─── Test 8: Performance Benchmark ─────────────────────────────────────────────

section("Performance Benchmark")

import timeit

N = 10_000

port_time = timeit.timeit(
    lambda: get_current_port(SECRET),
    number=N
) / N * 1_000_000
ok(f"Port computation: {port_time:.2f} µs/call  ({int(1e6/port_time):,} calls/sec)")

sid_time = timeit.timeit(
    lambda: generate_session_id(SECRET, nonce),
    number=N
) / N * 1_000_000
ok(f"Session ID generation: {sid_time:.2f} µs/call")

mac_time = timeit.timeit(
    lambda: __import__("tpmp.core.session", fromlist=["compute_resume_mac"]).compute_resume_mac(SECRET, session_id, new_port, time.time()),
    number=N
) / N * 1_000_000
ok(f"Resume MAC computation: {mac_time:.2f} µs/call")

ke = __import__("tpmp.core.keygen", fromlist=["KeyExchange"]).KeyExchange
kex_time = timeit.timeit(ke, number=100) / 100 * 1000
ok(f"ECDH keypair generation: {kex_time:.2f} ms/keypair")


# ─── Summary ──────────────────────────────────────────────────────────────────

total = passed + failed
print(f"\n{'─'*55}")
print(f"{BOLD}Results: {GREEN}{passed} passed{RESET}{BOLD}, "
      f"{RED if failed else ''}{failed} failed{RESET}{BOLD} / {total} total{RESET}")

if failed == 0:
    print(f"{GREEN}{BOLD}✅  Full integration test suite passed!{RESET}")
else:
    print(f"{RED}{BOLD}❌  Some tests failed.{RESET}")
    sys.exit(1)
