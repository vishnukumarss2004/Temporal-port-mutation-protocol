"""
TPMP Client
===========
Connects to a TPMP server on the dynamically computed port.

The client:
  1. Derives the current active port using the shared secret + current time
  2. Establishes a TLS connection to that port
  3. Performs the SESSION_INIT handshake
  4. Runs the application callback
  5. Before port rotation, seamlessly migrates to the next port via SESSION_RESUME

Usage:
    from tpmp.client import TPMPClient

    def my_app(conn, client):
        client.send(b"Hello, TPMP server!")
        response = client.recv()
        print(response)

    client = TPMPClient(psk="my-strong-password", host="192.168.1.100")
    client.connect(my_app)

Or from command line:
    python -m tpmp.client --psk "my-strong-password" --host 192.168.1.100
"""

import ssl
import socket
import threading
import time
import os
import logging
import json
import struct
import argparse

from .core.portcalc import (
    get_current_port, get_valid_ports, time_until_rotation, get_port_schedule,
    DEFAULT_WINDOW_SECONDS
)
from .core.keygen import derive_secret_from_psk
from .core.session import (
    Session, SessionState,
    generate_session_id, compute_resume_mac,
    build_session_init, build_session_resume, parse_packet,
    REBIND_BEFORE_EXPIRY
)
from .core.drift import (
    DriftEstimator, make_timestamp_probe,
    make_timestamp_response, process_timestamp_response
)

logger = logging.getLogger("tpmp.client")


class TPMPClient:
    """
    TPMP Client — connects to a server on time-rotating ports.
    Handles automatic port migration and session resumption.
    """

    def __init__(
        self,
        psk: str,
        salt_hex: str,
        host: str,
        window_size: int = DEFAULT_WINDOW_SECONDS,
        verify_cert: bool = False,
    ):
        """
        Args:
            psk:          Pre-shared key (must match server)
            salt_hex:     The server's salt (hex string, sent during provisioning)
            host:         Server hostname or IP
            window_size:  Must match server's window_size
            verify_cert:  Whether to verify TLS certificate
        """
        self.host = host
        self.window_size = window_size

        # Derive the same secret the server used
        salt = bytes.fromhex(salt_hex)
        self.secret = derive_secret_from_psk(psk, salt)

        # TLS context
        self._ssl_ctx = ssl.create_default_context()
        if not verify_cert:
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

        # Drift estimator
        self._drift = DriftEstimator()

        # Session state
        self._session: Session = None
        self._conn = None
        self._conn_lock = threading.Lock()
        self._running = False

    # ─── Port Computation ─────────────────────────────────────────────────────

    def _get_current_port(self) -> int:
        """Get the port we should be connecting to right now."""
        return get_current_port(self.secret, self.window_size)

    def _get_next_port(self) -> int:
        """Get the port for the next window."""
        from .core.portcalc import _compute_port
        next_window = int(time.time()) // self.window_size + 1
        return _compute_port(self.secret, next_window)

    # ─── Low-Level Connection ─────────────────────────────────────────────────

    def _raw_connect(self, port: int) -> ssl.SSLSocket:
        """Open a TLS connection to the given port."""
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(10)
        raw.connect((self.host, port))
        conn = self._ssl_ctx.wrap_socket(raw, server_hostname=self.host)
        conn.settimeout(30)
        return conn

    def _send_packet(self, conn, data: bytes):
        length = struct.pack(">I", len(data))
        conn.sendall(length + data)

    def _recv_packet(self, conn) -> bytes:
        raw_len = self._recvall(conn, 4)
        if not raw_len:
            return b""
        length = struct.unpack(">I", raw_len)[0]
        return self._recvall(conn, length)

    def _recvall(self, conn, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                return b""
            data += chunk
        return data

    # ─── Drift Measurement ────────────────────────────────────────────────────

    def measure_drift(self):
        """
        Probe the server to measure clock drift.
        Run this before connecting to improve port selection accuracy.
        """
        try:
            port = self._get_current_port()
            conn = self._raw_connect(port)

            probe = make_timestamp_probe()
            self._send_packet(conn, json.dumps(probe).encode())

            raw = self._recv_packet(conn)
            t4 = time.time()
            conn.close()

            response = parse_packet(raw)
            if response:
                sample = process_timestamp_response(response, t4)
                self._drift.add_sample(sample)
                summary = self._drift.summary()
                logger.info(
                    f"Drift measurement: offset={summary['estimated_offset_ms']}ms "
                    f"RTT={summary['estimated_rtt_ms']}ms"
                )

        except Exception as e:
            logger.debug(f"Drift measurement failed: {e}")

    # ─── Session Establishment ────────────────────────────────────────────────

    def _new_session(self) -> tuple:
        """
        Connect to the current active port and establish a new session.
        Returns (conn, session).
        """
        import os
        port = self._get_current_port()
        logger.info(f"Connecting to {self.host}:{port}")

        conn = self._raw_connect(port)

        # Generate client nonce
        nonce = os.urandom(16)

        # Send SESSION_INIT
        init_packet = build_session_init(nonce)
        self._send_packet(conn, init_packet)

        # Read SESSION_ACK
        raw = self._recv_packet(conn)
        ack = parse_packet(raw)

        if not ack or ack.get("type") != "tpmp_session_ack":
            conn.close()
            raise ConnectionError("Invalid session ACK from server")

        session_id = bytes.fromhex(ack["session_id"])
        server_window = ack.get("window_size", self.window_size)

        session = Session(
            session_id=session_id,
            shared_secret=self.secret,
            client_nonce=nonce,
            current_port=port,
            state=SessionState.ACTIVE
        )

        logger.info(f"Session established: {session_id.hex()[:8]}... on port {port}")
        return conn, session

    def _resume_session(self, session: Session) -> tuple:
        """
        Connect to the new port and resume an existing session.
        Returns (conn, session) or raises on failure.
        """
        new_port = self._get_current_port()
        logger.info(f"Resuming session on new port {new_port}")

        conn = self._raw_connect(new_port)

        # Send SESSION_RESUME
        resume_packet = build_session_resume(self.secret, session.session_id, new_port)
        self._send_packet(conn, resume_packet)

        # Read ACK
        raw = self._recv_packet(conn)
        ack = parse_packet(raw)

        if not ack or ack.get("type") != "tpmp_session_ack":
            conn.close()
            raise ConnectionError("Session resume rejected by server")

        session.current_port = new_port
        session.resume_count += 1
        session.state = SessionState.ACTIVE
        session.touch()

        logger.info(
            f"Session resumed: {session.session_id.hex()[:8]}... "
            f"on port {new_port} (resume #{session.resume_count})"
        )
        return conn, session

    # ─── High-Level API ───────────────────────────────────────────────────────

    def send(self, data: bytes):
        """Send data on the current connection."""
        with self._conn_lock:
            if self._conn:
                self._send_packet(self._conn, data)

    def recv(self) -> bytes:
        """Receive data from the current connection."""
        with self._conn_lock:
            if self._conn:
                return self._recv_packet(self._conn)
        return b""

    def connect(self, app_callback=None):
        """
        Connect to the server and run the application callback.
        Handles port rotation transparently.
        
        Args:
            app_callback: function(conn, client) called after session is established.
                          If None, runs an interactive echo loop.
        """
        self._running = True

        # Measure drift first
        self.measure_drift()

        # Establish initial session
        conn, session = self._new_session()
        self._conn = conn
        self._session = session

        if app_callback:
            # Start rotation watcher in background
            watcher = threading.Thread(
                target=self._rotation_watcher,
                daemon=True
            )
            watcher.start()

            try:
                app_callback(conn, self)
            finally:
                self._running = False
                try:
                    conn.close()
                except Exception:
                    pass
        else:
            self._interactive_loop(conn, session)

    def _rotation_watcher(self):
        """
        Background thread that triggers session migration before port rotates.
        Wakes up REBIND_BEFORE_EXPIRY seconds before each rotation.
        """
        while self._running:
            until = time_until_rotation(self.window_size)

            if until <= REBIND_BEFORE_EXPIRY:
                # Port is about to rotate — migrate now
                logger.info(f"Port rotation imminent ({until:.1f}s left), migrating...")
                try:
                    # Wait for the new window to open
                    time.sleep(until + 0.5)

                    new_conn, new_session = self._resume_session(self._session)

                    with self._conn_lock:
                        old_conn = self._conn
                        self._conn = new_conn
                        self._session = new_session

                    try:
                        old_conn.close()
                    except Exception:
                        pass

                except Exception as e:
                    logger.error(f"Session migration failed: {e}")

            time.sleep(1.0)

    def _interactive_loop(self, conn, session: Session):
        """
        Interactive CLI mode — type messages, see echoed responses.
        Handles port rotation in a background thread.
        """
        print(f"\n✅  TPMP session active (ID: {session.session_id.hex()[:8]}...)")
        print(f"📡  Connected to {self.host}:{session.current_port}")
        print(f"⏱️   Port rotates in {time_until_rotation(self.window_size):.0f}s")
        print("Type messages and press Enter. Ctrl+C to quit.\n")

        # Start rotation watcher
        watcher = threading.Thread(target=self._rotation_watcher, daemon=True)
        watcher.start()

        # Start receiver thread
        received = []
        def _recv_loop():
            while self._running:
                try:
                    data = self._recv_packet(self._conn)
                    if data:
                        print(f"\n← Server: {data.decode(errors='replace')}")
                        print("→ You: ", end="", flush=True)
                except Exception:
                    break

        receiver = threading.Thread(target=_recv_loop, daemon=True)
        receiver.start()

        try:
            while self._running:
                print("→ You: ", end="", flush=True)
                line = input()
                if line.lower() in ("quit", "exit"):
                    break
                self.send(line.encode())
        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            self._running = False
            print("\nDisconnected.")


# ─── CLI Entry Point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s  %(levelname)-8s  %(message)s")

    parser = argparse.ArgumentParser(description="TPMP Client")
    parser.add_argument("--psk", required=True, help="Pre-shared key")
    parser.add_argument("--salt", required=True, help="Server salt (hex)")
    parser.add_argument("--host", required=True, help="Server hostname or IP")
    parser.add_argument("--window", type=int, default=30, help="Port window size (seconds)")
    args = parser.parse_args()

    client = TPMPClient(
        psk=args.psk,
        salt_hex=args.salt,
        host=args.host,
        window_size=args.window,
    )
    client.connect()
