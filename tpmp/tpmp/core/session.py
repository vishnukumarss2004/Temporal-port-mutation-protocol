"""
TPMP Session Manager
====================
The trickiest part of TPMP: keeping a session alive across port rotations.

Problem:
    TCP connections are bound to a (src_ip, src_port, dst_ip, dst_port) 4-tuple.
    When the server closes port 49218 and opens 50341, the existing TCP connection
    breaks. The client gets a RST or connection refused on the next packet.

Our Solution — Pre-Emptive Re-Binding:
    1. Before the current window expires (REBIND_BEFORE_EXPIRY seconds early),
       the server opens BOTH the current port AND the next port.
    2. The client notices we're near a rotation boundary and connects to the new port.
    3. The client sends a SESSION_RESUME packet with its session_id + MAC.
    4. The server verifies the MAC, migrates session state to the new socket.
    5. The old port is closed after a grace period.

Session Identity:
    session_id = HMAC(shared_secret, "session" + client_nonce)
    Each resume packet is authenticated with:
    resume_mac = HMAC(session_secret, session_id + new_port + timestamp)

This prevents session hijacking: an attacker who learns the new port cannot 
forge a resume packet without the shared secret.
"""

import hmac
import hashlib
import os
import time
import threading
import json
import struct
from dataclasses import dataclass, field
from typing import Optional, Dict, Callable
from enum import Enum


# ─── Configuration ──────────────────────────────────────────────────────────────

REBIND_BEFORE_EXPIRY = 5    # Open next port this many seconds before rotation
GRACE_PERIOD = 8            # Keep old port open this many seconds after rotation
SESSION_TOKEN_LENGTH = 32   # Session ID length in bytes


class SessionState(Enum):
    CONNECTING    = "connecting"
    ACTIVE        = "active"
    MIGRATING     = "migrating"   # Dual-port overlap window
    CLOSED        = "closed"


# ─── Session Data ───────────────────────────────────────────────────────────────

@dataclass
class Session:
    """Represents one authenticated TPMP session."""
    session_id: bytes                   # Unique session identifier
    shared_secret: bytes                # TPMP shared secret for this session
    client_nonce: bytes                 # Client-generated random nonce
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    state: SessionState = SessionState.CONNECTING
    current_port: int = 0
    next_port: int = 0
    resume_count: int = 0              # How many port rotations survived
    peer_addr: Optional[str] = None
    metadata: Dict = field(default_factory=dict)

    def touch(self):
        self.last_activity = time.time()

    def age(self) -> float:
        return time.time() - self.created_at

    def idle_time(self) -> float:
        return time.time() - self.last_activity


# ─── Session ID & MAC Computation ──────────────────────────────────────────────

def generate_session_id(shared_secret: bytes, client_nonce: bytes) -> bytes:
    """
    Derive a session ID from the shared secret and client nonce.
    Both sides compute the same session_id independently.
    """
    return hmac.new(
        shared_secret,
        b"tpmp-session-id:" + client_nonce,
        hashlib.sha256
    ).digest()[:SESSION_TOKEN_LENGTH]


def compute_resume_mac(
    shared_secret: bytes,
    session_id: bytes,
    new_port: int,
    timestamp: float
) -> bytes:
    """
    Compute the MAC that authenticates a SESSION_RESUME packet.
    
    Binds: secret + session_id + new_port + quantized_timestamp
    Timestamp is quantized to 5-second windows to allow for transit delay.
    """
    ts_quantized = int(timestamp) // 5  # 5-second grace window
    payload = (
        b"tpmp-resume:"
        + session_id
        + struct.pack(">H", new_port)
        + struct.pack(">Q", ts_quantized)
    )
    return hmac.new(shared_secret, payload, hashlib.sha256).digest()[:16]


def verify_resume_mac(
    shared_secret: bytes,
    session_id: bytes,
    new_port: int,
    timestamp: float,
    provided_mac: bytes,
    max_age_seconds: float = 10.0
) -> bool:
    """
    Verify a SESSION_RESUME MAC in constant time.

    Two-layer protection:
      1. Timestamp freshness check  — reject packets older than max_age_seconds
         (prevents replay attacks where an attacker re-sends a captured packet)
      2. HMAC verification          — reject packets with invalid MAC
         (prevents forgery without the shared secret)

    Accepts timestamps within ±5 seconds of now to handle clock drift.
    """
    now = time.time()

    # ── Layer 1: Freshness check ──────────────────────────────────────────────
    # Reject the packet if the embedded timestamp is too old or too far in the future.
    # This is independent of the HMAC — stale packets are dropped before MAC check.
    if abs(now - timestamp) > max_age_seconds:
        return False

    # ── Layer 2: HMAC verification ────────────────────────────────────────────
    # Allow ±5s drift within the freshness window for clock skew tolerance.
    for delta in [-5, 0, 5]:
        expected = compute_resume_mac(
            shared_secret, session_id, new_port, timestamp + delta
        )
        if hmac.compare_digest(expected, provided_mac):
            return True
    return False


# ─── Session Packet Builders ────────────────────────────────────────────────────

def build_session_init(client_nonce: bytes) -> bytes:
    """
    Build the SESSION_INIT packet sent by client after TLS handshake.
    """
    packet = {
        "type": "tpmp_session_init",
        "nonce": client_nonce.hex(),
        "ts": time.time()
    }
    return json.dumps(packet).encode()


def build_session_ack(session_id: bytes, window_size: int) -> bytes:
    """
    Build the SESSION_ACK packet sent by server to confirm session.
    """
    packet = {
        "type": "tpmp_session_ack",
        "session_id": session_id.hex(),
        "window_size": window_size,
        "ts": time.time()
    }
    return json.dumps(packet).encode()


def build_session_resume(
    shared_secret: bytes,
    session_id: bytes,
    new_port: int
) -> bytes:
    """
    Build the SESSION_RESUME packet sent by client when reconnecting to new port.
    """
    ts = time.time()
    mac = compute_resume_mac(shared_secret, session_id, new_port, ts)
    packet = {
        "type": "tpmp_session_resume",
        "session_id": session_id.hex(),
        "new_port": new_port,
        "ts": ts,
        "mac": mac.hex()
    }
    return json.dumps(packet).encode()


def parse_packet(data: bytes) -> Optional[dict]:
    """Parse a TPMP control packet."""
    try:
        return json.loads(data.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


# ─── Session Registry (Server-side) ────────────────────────────────────────────

class SessionRegistry:
    """
    Tracks all active sessions on the server.
    Thread-safe. Supports session lookup by session_id.
    """

    def __init__(self):
        self._sessions: Dict[bytes, Session] = {}
        self._lock = threading.RLock()

    def register(self, session: Session):
        with self._lock:
            self._sessions[session.session_id] = session

    def get(self, session_id: bytes) -> Optional[Session]:
        with self._lock:
            return self._sessions.get(session_id)

    def remove(self, session_id: bytes):
        with self._lock:
            self._sessions.pop(session_id, None)

    def all_sessions(self) -> list:
        with self._lock:
            return list(self._sessions.values())

    def purge_idle(self, max_idle_seconds: float = 300):
        """Remove sessions that have been idle too long."""
        with self._lock:
            to_remove = [
                sid for sid, s in self._sessions.items()
                if s.idle_time() > max_idle_seconds
            ]
            for sid in to_remove:
                del self._sessions[sid]
        return len(to_remove)

    def stats(self) -> dict:
        with self._lock:
            sessions = list(self._sessions.values())
        return {
            "total": len(sessions),
            "active": sum(1 for s in sessions if s.state == SessionState.ACTIVE),
            "migrating": sum(1 for s in sessions if s.state == SessionState.MIGRATING),
        }
