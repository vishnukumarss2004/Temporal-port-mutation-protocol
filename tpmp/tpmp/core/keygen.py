"""
TPMP Key Exchange
=================
Establishes a shared secret between client and server using
Elliptic Curve Diffie-Hellman (ECDH) over P-256.

Flow:
    1. Both sides generate ephemeral EC keypairs
    2. Exchange public keys over an initial TLS-secured channel
    3. Derive shared secret via ECDH
    4. Run HKDF to expand the raw shared secret into a strong symmetric key
    5. Store the derived key — this becomes the TPMP shared secret

The derived key is deterministic given the same ECDH exchange,
so both sides arrive at the same port sequence independently.
"""

import os
import hashlib
import hmac
import json
import base64
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, EllipticCurvePublicKey, generate_private_key, SECP256R1
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_der_public_key
)
from cryptography.hazmat.backends import default_backend


# ─── HKDF (RFC 5869) ──────────────────────────────────────────────────────────

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract: compress input key material into a pseudorandom key."""
    if not salt:
        salt = bytes(32)
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand: expand pseudorandom key to desired output length."""
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def hkdf(ikm: bytes, salt: bytes = b"", info: bytes = b"tpmp-v1", length: int = 32) -> bytes:
    """
    Full HKDF derivation.
    
    Args:
        ikm:    Input key material (raw ECDH shared secret)
        salt:   Optional salt (use server's random nonce)
        info:   Context string binding key to this protocol
        length: Output key length in bytes
    
    Returns:
        Derived key bytes
    """
    prk = _hkdf_extract(salt, ikm)
    return _hkdf_expand(prk, info, length)


# ─── ECDH Key Exchange ─────────────────────────────────────────────────────────

class KeyExchange:
    """
    Manages one side of an ECDH key exchange over P-256.
    
    Usage (server):
        ke = KeyExchange()
        pub_bytes = ke.get_public_bytes()   # send to client
        secret = ke.derive_secret(client_pub_bytes, salt)
    
    Usage (client):
        ke = KeyExchange()
        pub_bytes = ke.get_public_bytes()   # send to server
        secret = ke.derive_secret(server_pub_bytes, salt)
    """

    def __init__(self):
        self._private_key = generate_private_key(SECP256R1(), default_backend())
        self._public_key = self._private_key.public_key()

    def get_public_bytes(self) -> bytes:
        """Serialize public key in DER format for transmission."""
        return self._public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    def get_public_b64(self) -> str:
        """Base64-encoded public key for JSON transport."""
        return base64.b64encode(self.get_public_bytes()).decode()

    def derive_secret(self, peer_public_bytes: bytes, salt: bytes = b"") -> bytes:
        """
        Perform ECDH with peer's public key, then HKDF to derive the TPMP secret.
        
        Args:
            peer_public_bytes: DER-encoded peer public key
            salt:              Server-generated random salt (sent alongside pub key)
        
        Returns:
            32-byte derived shared secret for use in port calculation
        """
        peer_pub = load_der_public_key(peer_public_bytes, backend=default_backend())
        
        # Raw ECDH shared secret (X coordinate of the shared point)
        raw_secret = self._private_key.exchange(ECDH(), peer_pub)
        
        # Expand via HKDF with protocol binding
        derived = hkdf(
            ikm=raw_secret,
            salt=salt,
            info=b"tpmp-port-secret-v1",
            length=32
        )
        return derived

    def derive_secret_b64(self, peer_public_b64: str, salt_b64: str = "") -> bytes:
        """Convenience wrapper that accepts base64-encoded inputs (for JSON transport)."""
        peer_bytes = base64.b64decode(peer_public_b64)
        salt = base64.b64decode(salt_b64) if salt_b64 else b""
        return self.derive_secret(peer_bytes, salt)


# ─── Pre-Shared Key (PSK) Mode ─────────────────────────────────────────────────

def derive_secret_from_psk(psk: str, salt: bytes = b"") -> bytes:
    """
    Simpler mode: derive TPMP secret from a pre-shared password/key string.
    Useful for manual device provisioning (IoT, embedded systems).
    
    Args:
        psk:  Pre-shared key string (treat as password)
        salt: Optional per-device salt for uniqueness
    
    Returns:
        32-byte derived secret
    """
    ikm = hashlib.pbkdf2_hmac(
        "sha256",
        psk.encode(),
        salt or b"tpmp-default-salt",
        iterations=100_000
    )
    return hkdf(ikm, salt=salt, info=b"tpmp-psk-v1", length=32)


def generate_salt() -> bytes:
    """Generate a 16-byte cryptographically random salt."""
    return os.urandom(16)


# ─── Serialization helpers ─────────────────────────────────────────────────────

def secret_to_hex(secret: bytes) -> str:
    return secret.hex()


def hex_to_secret(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)
