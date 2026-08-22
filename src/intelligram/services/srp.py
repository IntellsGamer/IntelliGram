"""Telegram-compatible SRP primitives used by IntelliGram's Web K password fallback.

Web K computes ``inputCheckPasswordSRP`` with the Layer 228
``passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow``
algorithm. This module implements only the matching server operations:
password-verifier creation, a short-lived SRP challenge, and proof validation.
Password text is neither persisted here nor sent over MTProto.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass


# Exact 2048-bit safe prime and generator Web K fast-accepts in
# ``verifyDhPrimeAndGenerator``. The source is client/src/mock/srp.ts.
P_BYTES = bytes.fromhex(
    "c71caeb9c6b1c9048e6c522f70f13f73980d40238e3e21c14934d037563d930f"
    "48198a0aa7c14058229493d22530f4dbfa336f6e0ac925139543aed44cce7c37"
    "20fd51f69458705ac68cd4fe6b6b13abdc9746512969328454f18faf8c595f64"
    "2477fe96bb2a941d5bcd1d4ac8cc49880708fa9b378e3c4f3a9060bee67cf9a4"
    "a4a695811051907e162753b56b0f6b410dba74d8a84b2a14b3144e0ef1284754"
    "fd17ed950d5965b4b9dd46582db1178d169c6bc465b0d6ff9ca3928fef5b9ae4"
    "e418fc15e83ebea0f87fa9ff5eed70050ded2849f47bf959d956850ce929851f"
    "0d8115f635b105ee2e4e15d04b2454bf6f4fadf034b10403119cd8e3b92fcc5b"
)
P = int.from_bytes(P_BYTES, "big")
G = 3
PAD_LENGTH = 256
CHALLENGE_LIFETIME_SECONDS = 60 * 5
MAX_PASSWORD_ATTEMPTS = 5


@dataclass(frozen=True, slots=True)
class PasswordVerifier:
    salt1: bytes
    salt2: bytes
    verifier: bytes


@dataclass(frozen=True, slots=True)
class SRPChallenge:
    srp_id: int
    salt1: bytes
    salt2: bytes
    srp_B: bytes
    private_b: bytes


def _sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _pad(value: int) -> bytes:
    if value < 0 or value >= 1 << (PAD_LENGTH * 8):
        raise ValueError("SRP value cannot be padded to 256 bytes")
    return value.to_bytes(PAD_LENGTH, "big")


def _password_x(password: str, salt1: bytes, salt2: bytes) -> int:
    password_bytes = password.encode("utf-8")
    first_hash = _sha256(salt1 + password_bytes + salt1)
    second_hash = _sha256(salt2 + first_hash + salt2)
    stretched = hashlib.pbkdf2_hmac("sha512", second_hash, salt1, 100_000, dklen=64)
    return int.from_bytes(_sha256(salt2 + stretched + salt2), "big")


def make_password_verifier(password: str) -> PasswordVerifier:
    """Create random Web K-compatible salts and an SRP verifier for ``password``."""

    salt1 = secrets.token_bytes(32)
    salt2 = secrets.token_bytes(32)
    verifier = _pad(pow(G, _password_x(password, salt1, salt2), P))
    return PasswordVerifier(salt1=salt1, salt2=salt2, verifier=verifier)


def make_challenge(*, salt1: bytes, salt2: bytes, verifier: bytes) -> SRPChallenge:
    """Create a one-time server SRP challenge for a stored verifier."""

    if len(verifier) != PAD_LENGTH:
        raise ValueError("Invalid stored SRP verifier")
    verifier_value = int.from_bytes(verifier, "big")
    if not 1 < verifier_value < P:
        raise ValueError("Stored SRP verifier is out of range")
    multiplier = int.from_bytes(_sha256(_pad(P) + _pad(G)), "big")
    while True:
        private_b = secrets.token_bytes(PAD_LENGTH)
        private_b_value = int.from_bytes(private_b, "big")
        public_B = (multiplier * verifier_value + pow(G, private_b_value, P)) % P
        if 1 < public_B < P:
            return SRPChallenge(
                srp_id=secrets.randbelow((1 << 63) - 1) + 1,
                salt1=salt1,
                salt2=salt2,
                srp_B=_pad(public_B),
                private_b=private_b,
            )


def verify_proof(
    *,
    salt1: bytes,
    salt2: bytes,
    verifier: bytes,
    private_b: bytes,
    srp_B: bytes,
    client_A: bytes,
    client_M1: bytes,
) -> bool:
    """Verify a Web K ``inputCheckPasswordSRP`` proof in constant time."""

    if len(verifier) != PAD_LENGTH or len(private_b) != PAD_LENGTH or len(srp_B) != PAD_LENGTH:
        return False
    if len(client_A) != PAD_LENGTH or len(client_M1) != 32:
        return False
    client_a_value = int.from_bytes(client_A, "big")
    public_b_value = int.from_bytes(srp_B, "big")
    if not 1 < client_a_value < P or not 1 < public_b_value < P:
        return False
    verifier_value = int.from_bytes(verifier, "big")
    private_b_value = int.from_bytes(private_b, "big")
    scrambling = int.from_bytes(_sha256(_pad(client_a_value) + _pad(public_b_value)), "big")
    shared_secret = pow((client_a_value * pow(verifier_value, scrambling, P)) % P, private_b_value, P)
    session_key = _sha256(_pad(shared_secret))
    hash_prime_xor_generator = bytes(
        left ^ right for left, right in zip(_sha256(_pad(P)), _sha256(_pad(G)), strict=True)
    )
    expected_m1 = _sha256(
        hash_prime_xor_generator
        + _sha256(salt1)
        + _sha256(salt2)
        + _pad(client_a_value)
        + _pad(public_b_value)
        + session_key
    )
    return hmac.compare_digest(expected_m1, client_M1)
