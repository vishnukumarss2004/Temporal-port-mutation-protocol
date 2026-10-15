"""
TPMP Demo
=========
Interactive demonstration of the Temporal Port Mutation Protocol.
Shows port computation, rotation schedule, and key exchange — no sockets needed.

Run:
    python demo.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tpmp.core.portcalc import (
    get_current_port, get_valid_ports, get_port_schedule, time_until_rotation
)
from tpmp.core.keygen import derive_secret_from_psk, KeyExchange, generate_salt
from tpmp.core.session import generate_session_id, compute_resume_mac
from tpmp.firewall import FirewallManager

GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
RESET  = "\033[0m"


def banner():
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════╗
║          TPMP — Temporal Port Mutation Protocol      ║
║          Cryptographic port-hopping for zero-trust   ║
╚══════════════════════════════════════════════════════╝{RESET}
""")


def demo_port_calculation():
    print(f"{BOLD}━━━  1. Port Calculation Engine  ━━━{RESET}\n")

    psk = "demo-password-123"
    salt = b"demo-salt-16byte"
    secret = derive_secret_from_psk(psk, salt)

    print(f"  Pre-shared key : {CYAN}{psk}{RESET}")
    print(f"  Salt           : {CYAN}{salt.hex()}{RESET}")
    print(f"  Derived secret : {DIM}{secret.hex()[:16]}...{RESET}\n")

    current = get_current_port(secret)
    valid   = get_valid_ports(secret, drift=1)
    ttr     = time_until_rotation(30)

    print(f"  {GREEN}Active port right now  : {BOLD}{current}{RESET}")
    print(f"  {YELLOW}Valid ports (±1 drift) : {', '.join(str(p) for p in valid)}{RESET}")
    print(f"  Next rotation in       : {ttr:.1f}s\n")

    print(f"  {BOLD}Upcoming port schedule:{RESET}")
    print(f"  {'Window':>8}  {'Port':>6}  {'Opens at':>12}  {'Closes at':>12}  Status")
    print(f"  {'─'*60}")

    for entry in get_port_schedule(secret, count=8):
        marker = f"  {GREEN}◀ ACTIVE{RESET}" if entry["is_current"] else ""
        opens  = time.strftime("%H:%M:%S", time.localtime(entry["window_start"]))
        closes = time.strftime("%H:%M:%S", time.localtime(entry["window_end"]))
        print(f"  {entry['window_index']:>8}  {entry['port']:>6}  {opens:>12}  {closes:>12}{marker}")

    print()


def demo_key_exchange():
    print(f"{BOLD}━━━  2. ECDH Key Exchange  ━━━{RESET}\n")

    print("  Simulating server-side and client-side key exchange...\n")

    # Server side
    server_ke = KeyExchange()
    server_pub = server_ke.get_public_bytes()
    server_salt = generate_salt()
    print(f"  [Server] Generated EC keypair (P-256)")
    print(f"  [Server] Public key : {DIM}{server_pub.hex()[:20]}...{RESET}")
    print(f"  [Server] Salt       : {DIM}{server_salt.hex()}{RESET}")

    # Client side
    client_ke = KeyExchange()
    client_pub = client_ke.get_public_bytes()
    print(f"\n  [Client] Generated EC keypair (P-256)")
    print(f"  [Client] Public key : {DIM}{client_pub.hex()[:20]}...{RESET}")

    # Key derivation
    server_secret = server_ke.derive_secret(client_pub, server_salt)
    client_secret = client_ke.derive_secret(server_pub, server_salt)

    match = server_secret == client_secret
    print(f"\n  [Server] Derived secret: {DIM}{server_secret.hex()[:16]}...{RESET}")
    print(f"  [Client] Derived secret: {DIM}{client_secret.hex()[:16]}...{RESET}")
    print(f"\n  Match: {GREEN + '✅  Yes — both compute the same secret' if match else RED + '❌  No — mismatch!'}{RESET}\n")


def demo_session_security():
    print(f"{BOLD}━━━  3. Session MAC & Anti-Hijacking  ━━━{RESET}\n")

    shared_secret = derive_secret_from_psk("demo-password", b"salt")
    nonce = os.urandom(16)
    session_id = generate_session_id(shared_secret, nonce)
    new_port = get_current_port(shared_secret)
    ts = time.time()

    mac = compute_resume_mac(shared_secret, session_id, new_port, ts)

    print(f"  Session ID : {CYAN}{session_id.hex()[:16]}...{RESET}")
    print(f"  New port   : {CYAN}{new_port}{RESET}")
    print(f"  Resume MAC : {CYAN}{mac.hex()}{RESET}")
    print()

    print("  Scenario: Attacker knows the new port (from a slow port scan).")
    print("  Can they hijack the session by forging a RESUME packet?\n")

    # Attacker tries random MACs
    forged_mac = os.urandom(16)
    from tpmp.core.session import verify_resume_mac
    forgery_result = verify_resume_mac(shared_secret, session_id, new_port, ts, forged_mac)
    print(f"  Attacker forged MAC  : {RED}{'✅ Accepted (BAD!)' if forgery_result else '❌  Rejected'}{RESET}")

    # Correct MAC
    legit_result = verify_resume_mac(shared_secret, session_id, new_port, ts, mac)
    print(f"  Legitimate MAC       : {GREEN}{'✅  Accepted' if legit_result else '❌  Rejected (BAD!)'}{RESET}\n")

    print("  Without the shared secret, an attacker CANNOT forge a valid")
    print("  SESSION_RESUME even if they know the current port.\n")


def demo_firewall():
    print(f"{BOLD}━━━  4. Firewall Rule Rotation  ━━━{RESET}\n")

    fw = FirewallManager(dry_run=True)
    fw.initialize()

    secret = derive_secret_from_psk("demo", b"salt")
    from tpmp.core.portcalc import _compute_port
    now_w = int(time.time()) // 30

    for i in range(3):
        old_port = _compute_port(secret, now_w + i)
        new_port = _compute_port(secret, now_w + i + 1)

        print(f"  Window {now_w + i} → {now_w + i + 1}:")
        print(f"    Open  new port : {GREEN}{new_port}{RESET}")
        print(f"    Grace period   : 8 seconds (old port {old_port} stays open)")
        print(f"    Close old port : {YELLOW}{old_port}{RESET}")
        print()

    fw.cleanup()
    print(f"  {DIM}(Actual iptables commands are logged in real mode){RESET}\n")


def demo_attacker_view():
    print(f"{BOLD}━━━  5. What an Attacker Sees  ━━━{RESET}\n")

    secret = derive_secret_from_psk("demo", b"salt")
    current = get_current_port(secret)
    ttr = time_until_rotation(30)

    print(f"  Attacker runs: nmap -p 49152-65535 <server>\n")
    print(f"  Time required for full ephemeral port scan: ~30-60 seconds")
    print(f"  Port {current} is currently open for: {ttr:.1f}s more\n")

    scan_time = 45  # typical nmap time for this range
    if scan_time > 30:
        print(f"  {RED}By the time nmap finishes, the port has already rotated!{RESET}")
        print(f"  The port found at second 0 is CLOSED by second 30.")
        print(f"  The port open at second 30 wasn't open when the scan started.\n")
    print(f"  Result: {RED}No consistently open port found.{RESET}")
    print(f"  Even if the attacker finds the port in the scan window,")
    print(f"  they cannot connect without the shared secret (needed for TLS).\n")


if __name__ == "__main__":
    import os
    banner()
    demo_port_calculation()
    demo_key_exchange()
    demo_session_security()
    demo_firewall()
    demo_attacker_view()

    print(f"{BOLD}{GREEN}Demo complete. Run `python tests/test_tpmp.py` to run the full test suite.{RESET}\n")
