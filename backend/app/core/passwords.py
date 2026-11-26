"""Argon2id password hashing using cryptography's maintained implementation."""

import base64
import hmac
import os

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

MEMORY_COST = 64 * 1024
ITERATIONS = 3
LANES = 4
LENGTH = 32


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    derived = Argon2id(
        salt=salt, length=LENGTH, iterations=ITERATIONS, lanes=LANES, memory_cost=MEMORY_COST,
    ).derive(password.encode("utf-8"))
    return "$argon2id$v=19$m=65536,t=3,p=4$%s$%s" % (
        base64.urlsafe_b64encode(salt).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(derived).decode("ascii").rstrip("="),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        parts = encoded.split("$")
        if len(parts) != 6 or parts[1] != "argon2id":
            return False
        params = dict(item.split("=") for item in parts[3].split(","))
        decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        salt = decode(parts[4])
        expected = decode(parts[5])
        actual = Argon2id(
            salt=salt,
            length=len(expected),
            iterations=int(params["t"]),
            lanes=int(params["p"]),
            memory_cost=int(params["m"]),
        ).derive(password.encode("utf-8"))
        return hmac.compare_digest(actual, expected)
    except (KeyError, TypeError, ValueError):
        return False
