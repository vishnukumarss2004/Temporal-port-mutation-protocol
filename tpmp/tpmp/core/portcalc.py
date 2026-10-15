"""
TPMP Port Calculator
====================
Derives the active port using HMAC-SHA256 over a time window.

Formula:
    active_port = HMAC-SHA256(shared_secret, floor(unix_time / window)) mod 16383 + 49152

This places the port in the IANA ephemeral range (49152-65535).
Both client and server compute this independently — no negotiation needed.
"""

import hmac
import hashlib
import time
import struct
from typing import List


EPHEMERAL_PORT_BASE = 49152   # IANA dynamic port range start
EPHEMERAL_PORT_RANGE = 16383  # 49152..65535
DEFAULT_WINDOW_SECONDS = 30   # Port rotates every 30 seconds
DRIFT_WINDOWS = 1             # Accept ±1 window for clock drift tolerance


def _compute_port(secret: bytes, window_index: int) -> int:
    """
    Compute port for a given time window index.
    
    Args:
        secret: Shared secret bytes (256-bit recommended)
        window_index: floor(unix_timestamp / window_size)
    
    Returns:
        Port number in range [49152, 65535]
    """
    # Pack window_index as big-endian 8-byte integer (same as TOTP counter)
    counter_bytes = struct.pack(">Q", window_index & 0xFFFFFFFFFFFFFFFF)
    
    digest = hmac.new(secret, counter_bytes, hashlib.sha256).digest()
    
    # Use first 4 bytes as a 32-bit integer for port derivation
    port_seed = struct.unpack(">I", digest[:4])[0]
    
    port = (port_seed % EPHEMERAL_PORT_RANGE) + EPHEMERAL_PORT_BASE
    return port


def get_current_port(secret: bytes, window_size: int = DEFAULT_WINDOW_SECONDS) -> int:
    """
    Get the port that is currently active.
    
    Args:
        secret: Shared secret bytes
        window_size: Duration of each port window in seconds
    
    Returns:
        Currently active port number
    """
    window_index = int(time.time()) // window_size
    return _compute_port(secret, window_index)


def get_valid_ports(secret: bytes, window_size: int = DEFAULT_WINDOW_SECONDS,
                    drift: int = DRIFT_WINDOWS) -> List[int]:
    """
    Get all ports that should be accepted right now, accounting for clock drift.
    
    Returns ports for windows: [current-drift ... current+drift]
    This is critical — if the client's clock is 1 second behind the server
    and they're at a window boundary, one side may be on window N while
    the other is already on window N+1.
    
    Args:
        secret: Shared secret bytes
        window_size: Duration of each port window in seconds
        drift: Number of adjacent windows to accept on each side
    
    Returns:
        List of valid port numbers (deduplicated)
    """
    now_window = int(time.time()) // window_size
    ports = []
    seen = set()
    
    for offset in range(-drift, drift + 1):
        p = _compute_port(secret, now_window + offset)
        if p not in seen:
            ports.append(p)
            seen.add(p)
    
    return ports


def get_port_schedule(secret: bytes, window_size: int = DEFAULT_WINDOW_SECONDS,
                      count: int = 10) -> List[dict]:
    """
    Preview upcoming port schedule (useful for debugging and demo).
    
    Args:
        secret: Shared secret bytes
        window_size: Duration of each port window in seconds
        count: Number of upcoming windows to preview
    
    Returns:
        List of dicts with 'window_start', 'window_end', 'port'
    """
    now = time.time()
    current_window = int(now) // window_size
    schedule = []
    
    for i in range(count):
        w = current_window + i
        port = _compute_port(secret, w)
        schedule.append({
            "window_index": w,
            "window_start": w * window_size,
            "window_end": (w + 1) * window_size,
            "port": port,
            "is_current": (i == 0)
        })
    
    return schedule


def time_until_rotation(window_size: int = DEFAULT_WINDOW_SECONDS) -> float:
    """
    Returns seconds remaining until the next port rotation.
    Useful for reconnect timing and UI feedback.
    """
    now = time.time()
    return window_size - (now % window_size)
