"""
TPMP — Temporal Port Mutation Protocol
=======================================
A cryptographic port-hopping protocol for zero-trust network access.

Modules:
    tpmp.server     — TPMP server
    tpmp.client     — TPMP client
    tpmp.firewall   — iptables manager
    tpmp.core.portcalc  — HMAC-based port computation
    tpmp.core.keygen    — ECDH + HKDF key exchange
    tpmp.core.session   — Session lifecycle management
    tpmp.core.drift     — Clock drift compensation
"""

__version__ = "1.0.0"
__author__ = "TPMP Project"
