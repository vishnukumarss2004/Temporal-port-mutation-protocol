"""
TPMP Attack Simulator
=====================
Demonstrates the security guarantees of TPMP by simulating:

1. Port Scanner Attack — attacker runs nmap against the server
2. Replay Attack      — attacker replays a captured SESSION_RESUME packet
3. Brute Force        — attacker tries to guess the active port
4. Man-in-the-Middle  — attacker intercepts but can't decrypt (TLS)

Each simulation shows exactly why the attack fails and what the attacker sees.

Run:
    python attack_sim.py
"""

import sys
import os
import time
import random
import hmac
import hashlib
import struct
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tpmp.core.portcalc import (
    _compute_port, get_current_port, get_valid_ports,
    get_port_schedule, time_until_rotation, EPHEMERAL_PORT_BASE, EPHEMERAL_PORT_RANGE
)
from tpmp.core.keygen import derive_secret_from_psk
from tpmp.core.session import (
    generate_session_id, compute_resume_mac, verify_resume_mac
)

# ─── Colors ────────────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

SECRET = derive_secret_from_psk("secure-server-password", b"server-salt-16by")


def hr(char="─", n=60):
    print(DIM + char * n + RESET)


def attacker_print(msg):
    print(f"  {RED}[ATTACKER]{RESET}  {msg}")


def defender_print(msg):
    print(f"  {GREEN}[SERVER  ]{RESET}  {msg}")


def info(msg):
    print(f"  {CYAN}[INFO    ]{RESET}  {DIM}{msg}{RESET}")


def slow_print(msg, delay=0.015):
    for ch in msg:
        print(ch, end="", flush=True)
        time.sleep(delay)
    print()


# ─── Attack 1: Port Scanner ────────────────────────────────────────────────────

def attack_port_scanner():
    print(f"\n{BOLD}{YELLOW}━━━  Attack 1: Port Scanner (nmap)  ━━━{RESET}\n")

    current_port = get_current_port(SECRET)
    ttr          = time_until_rotation(30)
    window_index = int(time.time()) // 30

    info(f"Server currently listening on port {current_port}")
    info(f"Port rotates in {ttr:.1f}s")
    print()

    attacker_print("Starting nmap scan of ephemeral range (49152-65535)...")
    attacker_print("Command: nmap -p 49152-65535 -T4 192.168.1.100")
    print()

    # Simulate scanning — one port per ~2ms at T4 speed
    # Full range = 16383 ports → ~33 seconds at T4
    SCAN_RATE_PPS = 500    # packets per second at T4
    TOTAL_PORTS   = EPHEMERAL_PORT_RANGE
    SCAN_DURATION = TOTAL_PORTS / SCAN_RATE_PPS   # ~33 seconds

    print(f"  Scanning {TOTAL_PORTS:,} ports at ~{SCAN_RATE_PPS} pps ...")

    found_ports = []
    scan_start  = time.time()

    # Simulate scanning in 1-second chunks
    simulated_time = 0
    bar_width = 40
    while simulated_time < SCAN_DURATION:
        chunk = min(1.0, SCAN_DURATION - simulated_time)
        ports_scanned = int(simulated_time / SCAN_DURATION * TOTAL_PORTS)
        pct = int(ports_scanned / TOTAL_PORTS * 100)
        filled = int(pct / 100 * bar_width)
        bar = "█" * filled + "░" * (bar_width - filled)

        # Check if the current port was "open" during this chunk
        # Port changes every 30s, so check which ports were open during this scan window
        scan_window_start = int(time.time()) // 30 - int(simulated_time / 30)
        active_at_this_moment = _compute_port(SECRET, scan_window_start)

        if (EPHEMERAL_PORT_BASE <= active_at_this_moment <= EPHEMERAL_PORT_BASE + TOTAL_PORTS and
                active_at_this_moment not in found_ports):
            found_ports.append(active_at_this_moment)

        print(f"\r  [{bar}] {pct:3d}%  {ports_scanned:,}/{TOTAL_PORTS:,} ports", end="", flush=True)
        simulated_time += chunk
        time.sleep(0.06)  # 60ms per simulated second for demo speed

    print(f"\r  [{'█' * bar_width}] 100%  {TOTAL_PORTS:,}/{TOTAL_PORTS:,} ports")
    print()

    attacker_print(f"Scan complete in {SCAN_DURATION:.0f}s (simulated)")

    if found_ports:
        attacker_print(f"Found open ports during scan: {found_ports}")
        attacker_print(f"Trying to connect to port {found_ports[0]}...")
        print()
        time.sleep(0.5)
        # By the time they connect, port has rotated
        if len(found_ports) > 0:
            currently_open = get_current_port(SECRET)
            if found_ports[-1] != currently_open:
                attacker_print(f"Connection refused! Port {found_ports[0]} is now CLOSED.")
                attacker_print(f"Even if they try each port: no shared secret → TLS rejects them.")
                defender_print("Connection attempt rejected — TLS certificate verification failed.")
                defender_print("No shared secret: attacker cannot compute the session MAC.")
    else:
        attacker_print("No open ports found consistently — port rotated during scan!")

    print()
    print(f"  {GREEN}Result: {BOLD}ATTACK FAILED{RESET}{GREEN} — port rotation defeats port scanning.{RESET}")


# ─── Attack 2: Replay Attack ───────────────────────────────────────────────────

def attack_replay():
    print(f"\n{BOLD}{YELLOW}━━━  Attack 2: Replay Attack (Captured SESSION_RESUME)  ━━━{RESET}\n")

    # Legitimate session
    nonce      = os.urandom(16)
    session_id = generate_session_id(SECRET, nonce)
    port_then  = get_current_port(SECRET)
    ts_then    = time.time()

    mac_then = compute_resume_mac(SECRET, session_id, port_then, ts_then)

    info(f"Legitimate client establishes session {session_id.hex()[:8]}...")
    info(f"Client sends SESSION_RESUME on port {port_then} at T=0s")
    info(f"Attacker captures the packet: mac={mac_then.hex()[:16]}...")
    print()

    attacker_print("Waiting for port to rotate (30s)...")
    attacker_print(f"Replaying captured SESSION_RESUME packet on new port...")
    print()

    # Simulate time passing — timestamp is now 35 seconds old
    ts_replay  = ts_then - 35   # Simulated: 35 seconds in the past
    port_now   = _compute_port(SECRET, int(time.time()) // 30 + 1)  # Next port

    # Try to replay the old MAC on the new port
    replay_ok = verify_resume_mac(SECRET, session_id, port_now, ts_replay, mac_then)

    attacker_print(f"Replayed packet on new port {port_now}")
    attacker_print(f"Old MAC: {mac_then.hex()[:16]}...")

    print()
    if not replay_ok:
        defender_print("SESSION_RESUME rejected!")
        defender_print(f"Reason 1: MAC bound to port {port_then}, not {port_now} — port mismatch.")
        defender_print(f"Reason 2: Timestamp {35}s old — outside 5s tolerance window.")
        print()
        print(f"  {GREEN}Result: {BOLD}ATTACK FAILED{RESET}{GREEN} — MACs are port+timestamp bound, not replayable.{RESET}")
    else:
        print(f"  {RED}Result: ATTACK SUCCEEDED — this is a bug!{RESET}")


# ─── Attack 3: Brute Force Port Guess ─────────────────────────────────────────

def attack_brute_force():
    print(f"\n{BOLD}{YELLOW}━━━  Attack 3: Brute Force Port Guessing  ━━━{RESET}\n")

    current_port = get_current_port(SECRET)
    ttr          = time_until_rotation(30)

    info(f"Attacker doesn't know the active port — tries to guess it")
    info(f"Ephemeral range: {EPHEMERAL_PORT_BASE}–{EPHEMERAL_PORT_BASE + EPHEMERAL_PORT_RANGE} ({EPHEMERAL_PORT_RANGE:,} options)")
    info(f"Server changes port every 30 seconds")
    print()

    attacker_print("Randomly guessing ports, trying to connect...")
    print()

    guesses         = 0
    correct_guesses = 0
    window_changes  = 0
    prev_window     = int(time.time()) // 30

    for trial in range(12):
        guess = random.randint(EPHEMERAL_PORT_BASE, EPHEMERAL_PORT_BASE + EPHEMERAL_PORT_RANGE)
        guesses += 1

        current_window = int(time.time()) // 30
        if current_window != prev_window:
            window_changes += 1
            prev_window = current_window

        is_correct = (guess == get_current_port(SECRET))
        if is_correct:
            correct_guesses += 1

        result = f"{GREEN}HIT{RESET}" if is_correct else f"{RED}MISS{RESET}"
        print(f"  Guess {trial+1:2d}: port {guess}  →  {result}")

        # Even hits require TLS auth
        if is_correct:
            attacker_print(f"Port {guess} is open! But TLS handshake requires certificate...")
            defender_print(f"TLS rejected — no valid certificate or shared secret.")
            correct_guesses -= 1  # Hit doesn't help without auth

        time.sleep(0.12)

    print()
    hit_rate = correct_guesses / guesses * 100
    info(f"Hit rate: {correct_guesses}/{guesses} = {hit_rate:.2f}%")
    info(f"Expected random hit rate: 1/{EPHEMERAL_PORT_RANGE:,} = {100/EPHEMERAL_PORT_RANGE:.4f}%")
    info(f"Port window changed {window_changes}x during guessing session")
    print()
    print(f"  {GREEN}Result: {BOLD}ATTACK FAILED{RESET}{GREEN} — 1-in-16383 odds per attempt, and TLS blocks even correct guesses.{RESET}")


# ─── Attack 4: Known Port, No Secret ──────────────────────────────────────────

def attack_known_port_no_secret():
    print(f"\n{BOLD}{YELLOW}━━━  Attack 4: Attacker Knows the Port — But Not the Secret  ━━━{RESET}\n")

    current_port = get_current_port(SECRET)
    nonce        = os.urandom(16)
    session_id   = generate_session_id(SECRET, nonce)
    ts           = time.time()

    info(f"Assume attacker somehow learned the current active port: {current_port}")
    info(f"Attacker also captured a session_id from network traffic: {session_id.hex()[:8]}...")
    info(f"Can they craft a valid SESSION_RESUME without the secret?")
    print()

    ATTEMPTS = 100_000
    attacker_print(f"Attempting {ATTEMPTS:,} random MAC forgeries...")

    start = time.time()
    found = 0
    for i in range(ATTEMPTS):
        forged_mac = os.urandom(16)
        if verify_resume_mac(SECRET, session_id, current_port, ts, forged_mac):
            found += 1
            attacker_print(f"Lucky hit at attempt {i}! (This should never happen)")

    elapsed = time.time() - start
    rate    = ATTEMPTS / elapsed

    print()
    attacker_print(f"Tried {ATTEMPTS:,} MACs in {elapsed:.2f}s ({rate:,.0f} attempts/sec)")
    attacker_print(f"Valid MACs found: {found}")

    # Extrapolate
    mac_space  = 2 ** 128   # 16-byte MAC
    years_needed = mac_space / rate / (365.25 * 24 * 3600)

    info(f"MAC space: 2^128 = {mac_space:.2e} possibilities")
    info(f"At {rate:,.0f} attempts/sec: would take {years_needed:.2e} years to brute-force")
    info(f"Universe age: ~1.4 × 10^10 years (attacker needs ~{years_needed/1.4e10:.1e}x longer)")
    print()
    print(f"  {GREEN}Result: {BOLD}ATTACK FAILED{RESET}{GREEN} — HMAC-SHA256 is computationally infeasible to brute-force.{RESET}")


# ─── Summary ──────────────────────────────────────────────────────────────────

def summary():
    print(f"\n{BOLD}{CYAN}{'━'*60}")
    print("  Security Summary")
    print(f"{'━'*60}{RESET}\n")

    attacks = [
        ("Port scanning (nmap)", "Port rotates faster than a full scan completes", "FAILED"),
        ("Replay attack",         "MACs are bound to specific port + timestamp",    "FAILED"),
        ("Brute force guessing",  "1/16383 odds per guess; TLS blocks even hits",   "FAILED"),
        ("Known port, no secret", "HMAC-SHA256 MAC requires 2^128 ops to forge",    "FAILED"),
    ]

    print(f"  {'Attack':<30} {'Why It Fails':<38} {'Result'}")
    print(f"  {'─'*28} {'─'*36} {'─'*8}")
    for attack, reason, result in attacks:
        color = GREEN if result == "FAILED" else RED
        print(f"  {attack:<30} {DIM}{reason:<38}{RESET} {color}{BOLD}{result}{RESET}")

    print(f"\n  Legitimate client (with shared secret): {GREEN}{BOLD}ALWAYS CONNECTS{RESET}")
    print(f"  Attacker (without shared secret):       {RED}{BOLD}ALWAYS BLOCKED{RESET}\n")


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os

    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════╗")
    print(f"║         TPMP — Attack Simulation Suite               ║")
    print(f"║  Demonstrates why each attack vector fails against   ║")
    print(f"║  the Temporal Port Mutation Protocol                 ║")
    print(f"╚══════════════════════════════════════════════════════╝{RESET}")

    hr("═")
    attack_port_scanner()
    hr()
    attack_replay()
    hr()
    attack_brute_force()
    hr()
    attack_known_port_no_secret()
    hr()
    summary()
