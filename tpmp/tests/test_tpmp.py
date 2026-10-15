"""
TPMP Test Suite
===============
Tests every module: portcalc, keygen, drift, session, firewall (dry-run).

Run:
    python -m pytest tests/ -v
    # or
    python tests/test_tpmp.py
"""

import sys
import os
import time
import hmac
import hashlib
import struct
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tpmp.core.portcalc import (
    _compute_port, get_current_port, get_valid_ports,
    get_port_schedule, time_until_rotation,
    EPHEMERAL_PORT_BASE, EPHEMERAL_PORT_RANGE, DEFAULT_WINDOW_SECONDS
)
from tpmp.core.keygen import (
    KeyExchange, derive_secret_from_psk, hkdf, generate_salt,
    secret_to_hex, hex_to_secret
)
from tpmp.core.drift import (
    DriftSample, DriftEstimator,
    make_timestamp_probe, make_timestamp_response, process_timestamp_response
)
from tpmp.core.session import (
    Session, SessionState, SessionRegistry,
    generate_session_id, compute_resume_mac, verify_resume_mac,
    build_session_init, build_session_ack, build_session_resume, parse_packet
)
from tpmp.firewall import FirewallManager


# ─── Color helpers ─────────────────────────────────────────────────────────────

GREEN = "\033[92m"
RED   = "\033[91m"
CYAN  = "\033[96m"
BOLD  = "\033[1m"
RESET = "\033[0m"

passed = 0
failed = 0


def test(name: str, condition: bool, detail: str = ""):
    global passed, failed
    if condition:
        print(f"  {GREEN}✓{RESET} {name}")
        passed += 1
    else:
        print(f"  {RED}✗{RESET} {name}" + (f" — {detail}" if detail else ""))
        failed += 1


def section(title: str):
    print(f"\n{BOLD}{CYAN}▶ {title}{RESET}")


# ─── Port Calculator Tests ─────────────────────────────────────────────────────

section("Port Calculator")

secret = os.urandom(32)

# Port is in ephemeral range
port = get_current_port(secret)
test("Port in ephemeral range",
     EPHEMERAL_PORT_BASE <= port <= EPHEMERAL_PORT_BASE + EPHEMERAL_PORT_RANGE,
     f"got {port}")

# Same secret + same time → same port
port_a = _compute_port(secret, 999)
port_b = _compute_port(secret, 999)
test("Deterministic: same inputs = same port", port_a == port_b)

# Different windows → (usually) different ports
ports = {_compute_port(secret, w) for w in range(100)}
test("Different windows produce varied ports", len(ports) > 80,
     f"only {len(ports)} unique ports in 100 windows")

# Different secrets → different ports for the same window
secret2 = os.urandom(32)
port_s1 = _compute_port(secret, 500)
port_s2 = _compute_port(secret2, 500)
test("Different secrets → different ports", port_s1 != port_s2)

# Drift window acceptance
valid = get_valid_ports(secret, window_size=30, drift=1)
test("Valid ports includes 3 entries with drift=1", len(valid) == 3, str(valid))
test("Current port is in valid ports", get_current_port(secret) in valid)

# Schedule preview
schedule = get_port_schedule(secret, count=5)
test("Schedule returns 5 entries", len(schedule) == 5)
test("First entry is current window", schedule[0]["is_current"])

# Time until rotation
ttr = time_until_rotation(30)
test("Time until rotation is 0-30s", 0 <= ttr <= 30, f"got {ttr:.2f}s")


# ─── Key Exchange Tests ────────────────────────────────────────────────────────

section("Key Exchange")

# HKDF basic
ikm = b"test input key material"
derived1 = hkdf(ikm, salt=b"salt1", info=b"ctx", length=32)
derived2 = hkdf(ikm, salt=b"salt1", info=b"ctx", length=32)
test("HKDF is deterministic", derived1 == derived2)

derived3 = hkdf(ikm, salt=b"salt2", info=b"ctx", length=32)
test("Different salt → different output", derived1 != derived3)

test("HKDF output is correct length", len(derived1) == 32)

# ECDH key exchange
alice = KeyExchange()
bob = KeyExchange()
alice_pub = alice.get_public_bytes()
bob_pub = bob.get_public_bytes()
salt = generate_salt()

secret_alice = alice.derive_secret(bob_pub, salt)
secret_bob = bob.derive_secret(alice_pub, salt)

test("ECDH: both sides derive same secret", secret_alice == secret_bob)
test("ECDH secret is 32 bytes", len(secret_alice) == 32)

# PSK derivation
psk_secret1 = derive_secret_from_psk("correct-horse-battery-staple", b"salt")
psk_secret2 = derive_secret_from_psk("correct-horse-battery-staple", b"salt")
psk_secret3 = derive_secret_from_psk("different-password", b"salt")

test("PSK derivation is deterministic", psk_secret1 == psk_secret2)
test("Different PSK → different secret", psk_secret1 != psk_secret3)
test("PSK secret is 32 bytes", len(psk_secret1) == 32)

# Hex serialization
hex_s = secret_to_hex(psk_secret1)
restored = hex_to_secret(hex_s)
test("Hex serialization round-trip", restored == psk_secret1)


# ─── Drift Estimation Tests ────────────────────────────────────────────────────

section("Clock Drift Estimation")

estimator = DriftEstimator(window_size=5)

test("Empty estimator returns None", estimator.estimated_offset() is None)

# Simulate samples with ~50ms server-ahead drift
for i in range(5):
    t1 = time.time()
    t2 = t1 + 0.05 + 0.02 * i  # 50ms drift + some jitter
    t4 = t1 + 0.1               # 100ms RTT
    sample = DriftSample(t_send=t1, t_server=t2, t_recv=t4)
    estimator.add_sample(sample)

offset = estimator.estimated_offset()
test("Drift offset is estimated (not None)", offset is not None)
test("Drift offset is positive (server ahead)",
     offset is not None and offset > 0, f"got {offset:.3f}s")
test("Drift is acceptable (< 29s)", estimator.is_drift_acceptable(30))

# Packet builders
probe = make_timestamp_probe()
test("Probe has type field", probe.get("type") == "tpmp_ts_probe")
test("Probe has t1 timestamp", "t1" in probe)

response = make_timestamp_response(probe)
test("Response echoes t1", response["t1"] == probe["t1"])
test("Response has t2", "t2" in response)

t4 = time.time()
sample = process_timestamp_response(response, t4)
test("Sample RTT is positive", sample.rtt >= 0)


# ─── Session Tests ─────────────────────────────────────────────────────────────

section("Session Management")

import os
shared_secret = os.urandom(32)
nonce = os.urandom(16)

# Session ID generation
sid1 = generate_session_id(shared_secret, nonce)
sid2 = generate_session_id(shared_secret, nonce)
sid3 = generate_session_id(os.urandom(32), nonce)

test("Session ID is deterministic", sid1 == sid2)
test("Different secret → different session ID", sid1 != sid3)
test("Session ID is 32 bytes", len(sid1) == 32)

# Resume MAC
port = 54321
ts = time.time()
mac = compute_resume_mac(shared_secret, sid1, port, ts)
test("MAC is 16 bytes", len(mac) == 16)
test("MAC verification passes", verify_resume_mac(shared_secret, sid1, port, ts, mac))

# Wrong MAC fails
bad_mac = os.urandom(16)
test("Wrong MAC rejected", not verify_resume_mac(shared_secret, sid1, port, ts, bad_mac))

# Wrong session ID fails
wrong_sid = os.urandom(32)
test("Wrong session ID rejected", not verify_resume_mac(shared_secret, wrong_sid, port, ts, mac))

# Packet builders
init_pkt = build_session_init(nonce)
parsed = parse_packet(init_pkt)
test("SESSION_INIT parses correctly", parsed is not None and parsed.get("type") == "tpmp_session_init")
test("SESSION_INIT contains nonce", parsed.get("nonce") == nonce.hex())

ack_pkt = build_session_ack(sid1, 30)
parsed_ack = parse_packet(ack_pkt)
test("SESSION_ACK parses correctly", parsed_ack.get("type") == "tpmp_session_ack")

resume_pkt = build_session_resume(shared_secret, sid1, 55000)
parsed_resume = parse_packet(resume_pkt)
test("SESSION_RESUME parses correctly", parsed_resume.get("type") == "tpmp_session_resume")
test("SESSION_RESUME port matches", parsed_resume.get("new_port") == 55000)

# Verify the resume packet MAC
r_mac = bytes.fromhex(parsed_resume["mac"])
r_ts = parsed_resume["ts"]
test("SESSION_RESUME MAC is valid",
     verify_resume_mac(shared_secret, sid1, 55000, r_ts, r_mac))

# Session registry
registry = SessionRegistry()
session = Session(
    session_id=sid1,
    shared_secret=shared_secret,
    client_nonce=nonce,
    state=SessionState.ACTIVE
)
registry.register(session)

test("Registry stores session", registry.get(sid1) is not None)
test("Registry returns correct session", registry.get(sid1).session_id == sid1)
test("Registry returns None for unknown", registry.get(os.urandom(32)) is None)

registry.remove(sid1)
test("Registry removes session", registry.get(sid1) is None)

stats = registry.stats()
test("Registry stats has expected keys",
     all(k in stats for k in ["total", "active", "migrating"]))


# ─── Firewall (Dry Run) Tests ──────────────────────────────────────────────────

section("Firewall Manager (dry-run)")

fw = FirewallManager(dry_run=True)
test("Created in dry_run mode", fw._dry_run)

fw.initialize()
test("Initialize runs without error", fw._initialized)

fw.open_port(54321)
test("Port 54321 tracked as open", 54321 in fw._open_ports)

fw.open_port(54321)  # Idempotent
test("Duplicate open is idempotent", fw.status()["open_ports"].count(54321) == 1)

fw.open_port(55555)
test("Second port tracked", 55555 in fw._open_ports)

fw.close_port(54321)
test("Port 54321 removed", 54321 not in fw._open_ports)

status = fw.status()
test("Status has correct fields",
     all(k in status for k in ["initialized", "dry_run", "open_ports"]))

fw.cleanup()
test("Cleanup clears ports", len(fw._open_ports) == 0)
test("Cleanup marks uninitialized", not fw._initialized)


# ─── End-to-End Port Agreement Test ───────────────────────────────────────────

section("End-to-End: Client/Server Port Agreement")

psk = "test-password-for-e2e"
salt = b"test-salt-16byte"

secret_server = derive_secret_from_psk(psk, salt)
secret_client = derive_secret_from_psk(psk, salt)

test("Server and client derive same secret", secret_server == secret_client)

port_server = get_current_port(secret_server)
port_client = get_current_port(secret_client)
test("Server and client agree on current port", port_server == port_client,
     f"server={port_server}, client={port_client}")

valid_server = get_valid_ports(secret_server, drift=1)
valid_client = get_valid_ports(secret_client, drift=1)
test("Valid port sets match", valid_server == valid_client)
test("Client's port is in server's valid set", port_client in valid_server)


# ─── Summary ──────────────────────────────────────────────────────────────────

total = passed + failed
print(f"\n{'─'*50}")
print(f"{BOLD}Results: {GREEN}{passed} passed{RESET}{BOLD}, "
      f"{RED if failed else ''}{failed} failed{RESET}{BOLD} / {total} total{RESET}")

if failed == 0:
    print(f"{GREEN}{BOLD}✅  All tests passed!{RESET}")
else:
    print(f"{RED}{BOLD}❌  Some tests failed.{RESET}")
    sys.exit(1)
