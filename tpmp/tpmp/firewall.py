"""
TPMP Firewall Manager
=====================
Manages iptables rules to open and close ports dynamically.

Requires: root privileges (or CAP_NET_ADMIN capability)
Dependency: iptables (standard on Linux), python-iptables (optional)

Strategy:
    - A dedicated TPMP chain is created in the INPUT table
    - The main INPUT chain jumps to TPMP_CHAIN before the default DROP rule
    - TPMP_CHAIN contains only the currently active port ACCEPT rules
    - On rotation, new rules are added first, then old rules removed after grace period

This is safer than directly modifying INPUT because:
    1. TPMP rules are isolated — flushing TPMP_CHAIN doesn't affect other rules
    2. The grace period overlap (dual-port window) is atomic at the rule level
    3. Easy rollback: just flush TPMP_CHAIN and remove the jump rule

Fallback:
    If iptables is unavailable (e.g., development on macOS), the module logs
    what it *would* do and continues. The server still listens correctly;
    only the firewall enforcement is bypassed.
"""

import subprocess
import logging
import threading
import time
from typing import Set

logger = logging.getLogger("tpmp.firewall")

TPMP_CHAIN = "TPMP_PORTS"
PROTOCOL = "tcp"


class FirewallManager:
    """
    Manages iptables rules for TPMP port rotation.
    Thread-safe. Tracks currently open ports.
    """

    def __init__(self, dry_run: bool = False):
        """
        Args:
            dry_run: If True, log commands but don't execute them.
                     Useful for development on non-Linux systems.
        """
        self._dry_run = dry_run
        self._open_ports: Set[int] = set()
        self._lock = threading.Lock()
        self._initialized = False

        if not dry_run:
            self._check_iptables()

    def _check_iptables(self):
        """Verify iptables is available."""
        try:
            result = subprocess.run(
                ["iptables", "--version"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                logger.info(f"iptables found: {result.stdout.strip()}")
            else:
                logger.warning("iptables check failed — switching to dry_run mode")
                self._dry_run = True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.warning("iptables not found — switching to dry_run mode")
            self._dry_run = True

    def _run(self, args: list) -> bool:
        """Execute an iptables command."""
        cmd = ["iptables"] + args
        if self._dry_run:
            logger.debug(f"[DRY RUN] {' '.join(cmd)}")
            return True
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                logger.error(f"iptables error: {result.stderr.strip()}")
                return False
            return True
        except Exception as e:
            logger.error(f"iptables execution failed: {e}")
            return False

    def _chain_exists(self) -> bool:
        """Check if TPMP chain already exists."""
        result = subprocess.run(
            ["iptables", "-L", TPMP_CHAIN, "-n"],
            capture_output=True, timeout=5
        )
        return result.returncode == 0

    def initialize(self):
        """
        Set up the TPMP iptables chain.
        Call once at server startup.
        
        Creates:
            - TPMP_PORTS chain
            - Jump rule in INPUT: -j TPMP_PORTS
        """
        with self._lock:
            if self._initialized:
                return

            logger.info("Initializing TPMP firewall chain...")

            if not self._dry_run and self._chain_exists():
                logger.info(f"Chain {TPMP_CHAIN} already exists — flushing it")
                self._run(["-F", TPMP_CHAIN])
            else:
                # Create the chain
                self._run(["-N", TPMP_CHAIN])

            # Insert a jump from INPUT to our chain (position 1 = before DROP)
            self._run(["-I", "INPUT", "1", "-j", TPMP_CHAIN])

            self._initialized = True
            logger.info("Firewall chain initialized.")

    def open_port(self, port: int):
        """
        Open a port by adding an ACCEPT rule to the TPMP chain.
        
        Args:
            port: Port number to open
        """
        with self._lock:
            if port in self._open_ports:
                return
            
            ok = self._run([
                "-A", TPMP_CHAIN,
                "-p", PROTOCOL,
                "--dport", str(port),
                "-j", "ACCEPT"
            ])
            
            if ok:
                self._open_ports.add(port)
                logger.info(f"Opened port {port}")

    def close_port(self, port: int):
        """
        Close a port by removing its ACCEPT rule from the TPMP chain.
        
        Args:
            port: Port number to close
        """
        with self._lock:
            if port not in self._open_ports:
                return

            ok = self._run([
                "-D", TPMP_CHAIN,
                "-p", PROTOCOL,
                "--dport", str(port),
                "-j", "ACCEPT"
            ])

            if ok:
                self._open_ports.discard(port)
                logger.info(f"Closed port {port}")

    def rotate_port(self, old_port: int, new_port: int, grace_seconds: float = 8):
        """
        Open the new port immediately, then close the old port after grace period.
        
        This creates the dual-port overlap window for seamless session migration.
        
        Args:
            old_port:      Port to close after grace period
            new_port:      Port to open immediately
            grace_seconds: How long to keep the old port open
        """
        logger.info(f"Rotating: {old_port} → {new_port} (grace={grace_seconds}s)")
        
        # Open new port immediately (clients can start connecting)
        self.open_port(new_port)

        # Schedule old port closure after grace period
        def delayed_close():
            time.sleep(grace_seconds)
            self.close_port(old_port)
            logger.info(f"Closed old port {old_port} after grace period")

        t = threading.Thread(target=delayed_close, daemon=True)
        t.start()

    def cleanup(self):
        """
        Remove all TPMP rules and the chain.
        Call at server shutdown.
        """
        with self._lock:
            logger.info("Cleaning up TPMP firewall rules...")
            
            # Remove jump rule from INPUT
            self._run(["-D", "INPUT", "-j", TPMP_CHAIN])
            
            # Flush all rules from our chain
            self._run(["-F", TPMP_CHAIN])
            
            # Delete the chain
            self._run(["-X", TPMP_CHAIN])
            
            self._open_ports.clear()
            self._initialized = False
            logger.info("Firewall cleanup complete.")

    def status(self) -> dict:
        return {
            "initialized": self._initialized,
            "dry_run": self._dry_run,
            "open_ports": sorted(self._open_ports),
        }
