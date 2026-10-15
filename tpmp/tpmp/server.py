"""
TPMP Server
===========
The main server that:
  1. Listens on dynamically rotating ports
  2. Handles TLS + ECDH key exchange on first connect
  3. Manages session lifecycle and port rotation
  4. Runs the application handler for authenticated sessions

Usage:
    from tpmp.server import TMPServer

    def my_handler(conn, session):
        data = conn.recv(1024)
        conn.send(b"Echo: " + data)

    server = TPMPServer(psk="my-strong-password", handler=my_handler)
    server.run()

Or from command line:
    python -m tpmp.server --psk "my-strong-password" --host 0.0.0.0
"""

import ssl
import socket
import threading
import time
import os
import logging
import json
import argparse
import signal
import sys

from .core.portcalc import (
    get_current_port, get_valid_ports, time_until_rotation, get_port_schedule,
    DEFAULT_WINDOW_SECONDS
)
from .core.keygen import derive_secret_from_psk, generate_salt, KeyExchange
from .core.session import (
    Session, SessionState, SessionRegistry,
    generate_session_id, verify_resume_mac,
    build_session_ack, parse_packet,
    REBIND_BEFORE_EXPIRY, GRACE_PERIOD
)
from .core.drift import (
    DriftEstimator, make_timestamp_response, process_timestamp_response
)
from .firewall import FirewallManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
)
logger = logging.getLogger("tpmp.server")


class TPMPServer:
    """
    TPMP Server — listens on time-rotating ports, manages sessions.
    """

    def __init__(
        self,
        psk: str,
        host: str = "0.0.0.0",
        window_size: int = DEFAULT_WINDOW_SECONDS,
        certfile: str = None,
        keyfile: str = None,
        handler=None,
        dry_run_firewall: bool = True,
    ):
        """
        Args:
            psk:                  Pre-shared key string
            host:                 Interface to bind on
            window_size:          Port rotation interval in seconds
            certfile / keyfile:   TLS certificate and key paths
            handler:              Application callback(conn, session) for each client
            dry_run_firewall:     If True, don't actually call iptables
        """
        self.host = host
        self.window_size = window_size
        self.handler = handler or self._default_handler

        # Derive the TPMP shared secret from the PSK
        self._salt = generate_salt()
        self.secret = derive_secret_from_psk(psk, self._salt)
        logger.info(f"TPMP secret derived (salt={self._salt.hex()[:8]}...)")

        # TLS context
        self._ssl_ctx = self._build_ssl_context(certfile, keyfile)

        # Session registry
        self._sessions = SessionRegistry()

        # Firewall manager
        self._firewall = FirewallManager(dry_run=dry_run_firewall)

        # Active listeners: {port: (socket, thread)}
        self._listeners: dict = {}
        self._listener_lock = threading.Lock()

        # Shutdown flag
        self._running = False

    def _build_ssl_context(self, certfile, keyfile) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3

        if certfile and keyfile:
            ctx.load_cert_chain(certfile, keyfile)
        else:
            # Generate a self-signed cert for development
            logger.warning("No TLS cert provided — generating self-signed cert")
            certfile, keyfile = self._generate_self_signed()
            ctx.load_cert_chain(certfile, keyfile)

        return ctx

    def _generate_self_signed(self):
        """Generate a temporary self-signed TLS certificate."""
        import subprocess, tempfile, os

        cert_dir = "/tmp/tpmp_certs"
        os.makedirs(cert_dir, exist_ok=True)
        cert_path = os.path.join(cert_dir, "server.crt")
        key_path = os.path.join(cert_dir, "server.key")

        if not os.path.exists(cert_path):
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path,
                "-out", cert_path,
                "-days", "365",
                "-nodes",
                "-subj", "/CN=tpmp-server"
            ], capture_output=True, check=True)
            logger.info(f"Generated self-signed cert at {cert_path}")

        return cert_path, key_path

    # ─── Port Rotation Engine ──────────────────────────────────────────────────

    def _open_listener(self, port: int):
        """Bind and start listening on a port."""
        with self._listener_lock:
            if port in self._listeners:
                return

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.host, port))
                sock.listen(64)
                sock.settimeout(1.0)

                t = threading.Thread(
                    target=self._accept_loop,
                    args=(sock, port),
                    daemon=True
                )
                t.start()

                self._listeners[port] = (sock, t)
                self._firewall.open_port(port)
                logger.info(f"Listening on port {port}")

            except OSError as e:
                logger.error(f"Failed to bind port {port}: {e}")

    def _close_listener(self, port: int):
        """Stop listening on a port and close the socket."""
        with self._listener_lock:
            entry = self._listeners.pop(port, None)
            if entry:
                sock, _ = entry
                try:
                    sock.close()
                except Exception:
                    pass
                self._firewall.close_port(port)
                logger.info(f"Closed listener on port {port}")

    def _rotation_loop(self):
        """
        Main port rotation loop.
        Runs in a background thread. Wakes up near each window boundary
        to open the next port and schedule closure of the old port.
        """
        current_port = None

        while self._running:
            valid_ports = get_valid_ports(self.secret, self.window_size)
            new_port = valid_ports[len(valid_ports) // 2]  # Middle = current window

            if new_port != current_port:
                logger.info(f"Port rotation: {current_port} → {new_port}")

                # Open new port first
                self._open_listener(new_port)

                # Schedule old port closure after grace period
                if current_port is not None:
                    old = current_port

                    def _delayed_close(p):
                        time.sleep(GRACE_PERIOD)
                        self._close_listener(p)

                    threading.Thread(
                        target=_delayed_close, args=(old,), daemon=True
                    ).start()

                current_port = new_port

            # Sleep until REBIND_BEFORE_EXPIRY seconds before next rotation
            until_rotation = time_until_rotation(self.window_size)
            sleep_time = max(1.0, until_rotation - REBIND_BEFORE_EXPIRY)
            time.sleep(sleep_time)

    # ─── Connection Handling ───────────────────────────────────────────────────

    def _accept_loop(self, server_sock: socket.socket, port: int):
        """Accept connections on a specific port."""
        while self._running:
            try:
                conn, addr = server_sock.accept()
                t = threading.Thread(
                    target=self._handle_connection,
                    args=(conn, addr, port),
                    daemon=True
                )
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_connection(self, raw_conn, addr, port: int):
        """Handle a single incoming connection."""
        peer = f"{addr[0]}:{addr[1]}"
        logger.debug(f"New connection from {peer} on port {port}")

        try:
            # Wrap in TLS
            conn = self._ssl_ctx.wrap_socket(raw_conn, server_side=True)
            conn.settimeout(30)

            # Read first packet
            data = self._recv_packet(conn)
            if not data:
                return

            packet = parse_packet(data)
            if not packet:
                logger.warning(f"Invalid packet from {peer}")
                return

            ptype = packet.get("type")

            if ptype == "tpmp_session_init":
                self._handle_new_session(conn, packet, addr, port)

            elif ptype == "tpmp_session_resume":
                self._handle_session_resume(conn, packet, addr, port)

            elif ptype == "tpmp_ts_probe":
                # Drift measurement probe — respond with timestamp
                response = make_timestamp_response(packet)
                self._send_packet(conn, json.dumps(response).encode())
                conn.close()

            else:
                logger.warning(f"Unknown packet type '{ptype}' from {peer}")

        except ssl.SSLError as e:
            logger.debug(f"TLS error from {peer}: {e}")
        except socket.timeout:
            logger.debug(f"Timeout from {peer}")
        except Exception as e:
            logger.error(f"Error handling {peer}: {e}", exc_info=True)

    def _handle_new_session(self, conn, packet: dict, addr, port: int):
        """Process a SESSION_INIT from a new client."""
        try:
            nonce = bytes.fromhex(packet["nonce"])
        except (KeyError, ValueError):
            logger.warning("Invalid SESSION_INIT packet")
            return

        session_id = generate_session_id(self.secret, nonce)

        session = Session(
            session_id=session_id,
            shared_secret=self.secret,
            client_nonce=nonce,
            current_port=port,
            state=SessionState.ACTIVE,
            peer_addr=f"{addr[0]}:{addr[1]}"
        )
        self._sessions.register(session)

        # Send ACK
        ack = build_session_ack(session_id, self.window_size)
        self._send_packet(conn, ack)

        logger.info(f"Session established: {session_id.hex()[:8]}... from {session.peer_addr}")

        # Hand off to application handler
        try:
            self.handler(conn, session)
        finally:
            session.state = SessionState.CLOSED
            self._sessions.remove(session_id)
            conn.close()

    def _handle_session_resume(self, conn, packet: dict, addr, port: int):
        """Process a SESSION_RESUME for an existing session."""
        try:
            session_id = bytes.fromhex(packet["session_id"])
            ts = float(packet["ts"])
            mac = bytes.fromhex(packet["mac"])
            new_port = int(packet["new_port"])
        except (KeyError, ValueError, TypeError):
            logger.warning("Malformed SESSION_RESUME")
            return

        session = self._sessions.get(session_id)
        if not session:
            logger.warning(f"Resume for unknown session {session_id.hex()[:8]}")
            return

        # Verify the MAC
        if not verify_resume_mac(self.secret, session_id, new_port, ts, mac):
            logger.warning(f"Resume MAC failed for session {session_id.hex()[:8]}")
            return

        # Migrate session to new port
        session.current_port = new_port
        session.resume_count += 1
        session.state = SessionState.ACTIVE
        session.touch()

        ack = build_session_ack(session_id, self.window_size)
        self._send_packet(conn, ack)

        logger.info(
            f"Session resumed: {session_id.hex()[:8]}... on port {new_port} "
            f"(resume #{session.resume_count})"
        )

        try:
            self.handler(conn, session)
        finally:
            session.state = SessionState.CLOSED
            self._sessions.remove(session_id)
            conn.close()

    # ─── I/O Helpers ──────────────────────────────────────────────────────────

    def _send_packet(self, conn, data: bytes):
        """Send a length-prefixed packet."""
        import struct
        length = struct.pack(">I", len(data))
        conn.sendall(length + data)

    def _recv_packet(self, conn) -> bytes:
        """Receive a length-prefixed packet."""
        import struct
        raw_len = self._recvall(conn, 4)
        if not raw_len:
            return b""
        length = struct.unpack(">I", raw_len)[0]
        if length > 65536:
            raise ValueError(f"Packet too large: {length}")
        return self._recvall(conn, length)

    def _recvall(self, conn, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                return b""
            data += chunk
        return data

    # ─── Default Application Handler ──────────────────────────────────────────

    def _default_handler(self, conn, session: Session):
        """
        Default echo handler — replace with your application logic.
        """
        logger.info(f"[Default handler] Session {session.session_id.hex()[:8]} active")
        while True:
            try:
                data = self._recv_packet(conn)
                if not data:
                    break
                session.touch()
                echo = b"TPMP-ECHO: " + data
                self._send_packet(conn, echo)
            except (socket.timeout, OSError):
                break

    # ─── Lifecycle ────────────────────────────────────────────────────────────

    def run(self):
        """Start the server (blocking)."""
        self._running = True

        # Set up firewall chain
        self._firewall.initialize()

        # Start port rotation
        rotation_thread = threading.Thread(
            target=self._rotation_loop, daemon=True
        )
        rotation_thread.start()

        logger.info("TPMP Server running. Press Ctrl+C to stop.")
        logger.info(f"Window size: {self.window_size}s")

        # Print upcoming port schedule
        schedule = get_port_schedule(self.secret, self.window_size, count=5)
        logger.info("Upcoming port schedule:")
        for entry in schedule:
            marker = " ← NOW" if entry["is_current"] else ""
            logger.info(f"  Window {entry['window_index']}: port {entry['port']}{marker}")

        # Handle Ctrl+C
        def _signal_handler(sig, frame):
            logger.info("Shutdown signal received...")
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        # Keep main thread alive
        while self._running:
            time.sleep(1)

    def stop(self):
        """Graceful shutdown."""
        self._running = False
        with self._listener_lock:
            for port, (sock, _) in list(self._listeners.items()):
                try:
                    sock.close()
                except Exception:
                    pass
        self._listeners.clear()
        self._firewall.cleanup()
        logger.info("TPMP Server stopped.")


# ─── CLI Entry Point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TPMP Server")
    parser.add_argument("--psk", required=True, help="Pre-shared key")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--window", type=int, default=30, help="Port window size (seconds)")
    parser.add_argument("--cert", help="TLS certificate path")
    parser.add_argument("--key", help="TLS private key path")
    parser.add_argument("--dry-run-firewall", action="store_true",
                        help="Don't actually modify iptables")
    args = parser.parse_args()

    server = TPMPServer(
        psk=args.psk,
        host=args.host,
        window_size=args.window,
        certfile=args.cert,
        keyfile=args.key,
        dry_run_firewall=args.dry_run_firewall
    )
    server.run()
