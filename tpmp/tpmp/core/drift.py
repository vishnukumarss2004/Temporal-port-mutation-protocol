"""
TPMP Clock Drift Compensation
==============================
Handles the edge case where client and server clocks are slightly out of sync.

Problem:
    If the client's clock is T=29.9s into a window, it computes port for window N.
    The server's clock may be at T=30.1s — already in window N+1.
    Both are computing different ports from the same secret.

Solution:
    1. Accept ±DRIFT_WINDOWS adjacent windows (in portcalc.py)
    2. On connection, embed a client timestamp in the TLS handshake extension
    3. Server measures the delta and adjusts its acceptance window accordingly
    4. After session is established, server sends a drift_ack with its own timestamp
    5. Client can now predict when to rotate without needing the server

This module handles measurement, adjustment, and smoothed estimation.
"""

import time
import statistics
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, Deque


MAX_TOLERABLE_DRIFT_SECONDS = 29   # If drift > window_size - 1s, refuse session
DRIFT_SAMPLE_SIZE = 8              # Rolling window for drift estimation
NTP_OFFSET_THRESHOLD = 5.0        # Warn if estimated NTP offset exceeds 5s


@dataclass
class DriftSample:
    """A single round-trip timing measurement."""
    t_send: float       # Client timestamp when it sent a probe
    t_server: float     # Server's timestamp when it received the probe
    t_recv: float       # Client timestamp when it got the response
    
    @property
    def rtt(self) -> float:
        """Round-trip time in seconds."""
        return self.t_recv - self.t_send
    
    @property
    def one_way_delay(self) -> float:
        """Estimated one-way delay (half RTT)."""
        return self.rtt / 2
    
    @property
    def clock_offset(self) -> float:
        """
        Estimated clock offset between client and server.
        Positive = server is ahead of client.
        Uses the NTP formula: offset = ((T2-T1) + (T3-T4)) / 2
        where T1=t_send, T2=t_server, T3=t_server (echo), T4=t_recv
        Simplified since we don't have T3 separately: offset = T2 - T1 - RTT/2
        """
        return self.t_server - self.t_send - self.one_way_delay


class DriftEstimator:
    """
    Rolling drift estimator using a sliding window of RTT measurements.
    Uses median filtering to reject outliers (network jitter).
    """

    def __init__(self, window_size: int = DRIFT_SAMPLE_SIZE):
        self._samples: Deque[DriftSample] = deque(maxlen=window_size)
        self._window_size = window_size

    def add_sample(self, sample: DriftSample):
        """Record a new RTT/drift measurement."""
        self._samples.append(sample)

    def estimated_offset(self) -> Optional[float]:
        """
        Best estimate of clock offset in seconds.
        Returns None if not enough samples yet.
        """
        if not self._samples:
            return None
        offsets = [s.clock_offset for s in self._samples]
        return statistics.median(offsets)

    def estimated_rtt(self) -> Optional[float]:
        """Median RTT in seconds."""
        if not self._samples:
            return None
        return statistics.median(s.rtt for s in self._samples)

    def is_drift_acceptable(self, window_size: int) -> bool:
        """
        Returns True if the estimated clock drift is within tolerable bounds.
        We can compensate for drift up to (window_size - 1) seconds by
        accepting adjacent windows.
        """
        offset = self.estimated_offset()
        if offset is None:
            return True  # No data yet, be optimistic
        return abs(offset) < min(MAX_TOLERABLE_DRIFT_SECONDS, window_size - 1)

    def adjusted_window_index(self, window_size: int) -> int:
        """
        Return the window index adjusted for estimated clock drift.
        If the server is 5 seconds ahead of us, we shift our window index forward.
        """
        offset = self.estimated_offset() or 0.0
        adjusted_time = time.time() + offset
        return int(adjusted_time) // window_size

    def summary(self) -> dict:
        return {
            "samples": len(self._samples),
            "estimated_offset_ms": round((self.estimated_offset() or 0) * 1000, 2),
            "estimated_rtt_ms": round((self.estimated_rtt() or 0) * 1000, 2),
            "is_acceptable": self.is_drift_acceptable(30),
        }


# ─── Wire Protocol Helpers ─────────────────────────────────────────────────────

def make_timestamp_probe() -> dict:
    """
    Create a timestamp probe packet to send to the peer.
    The peer should echo it back with their own timestamp added.
    """
    return {
        "type": "tpmp_ts_probe",
        "t1": time.time()
    }


def make_timestamp_response(probe: dict) -> dict:
    """
    Create a response to a timestamp probe.
    Adds the server's receive time (T2).
    """
    return {
        "type": "tpmp_ts_response",
        "t1": probe["t1"],
        "t2": time.time()
    }


def process_timestamp_response(response: dict, t4: float) -> DriftSample:
    """
    Process a timestamp response and create a drift sample.
    
    Args:
        response: The response packet from the peer containing t1 and t2
        t4:       The local time when the response was received
    """
    return DriftSample(
        t_send=response["t1"],
        t_server=response["t2"],
        t_recv=t4
    )
