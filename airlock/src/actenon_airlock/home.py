"""Airlock's per-user home: signing keys, the local certificate authority, approval keys.

Everything here is created on first use with 0600/0700 permissions. Nothing in it is ever written into a
project, and the agent process is never told where it is.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path


def airlock_home() -> Path:
    base = os.environ.get("AIRLOCK_HOME")
    if base:
        p = Path(base)
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        p = (Path(xdg) if xdg else Path.home() / ".config") / "airlock"
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    return p


def _secret_file(name: str, nbytes: int = 32) -> Path:
    path = airlock_home() / name
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(nbytes))
    return path


def grant_key_file() -> Path:
    """HMAC key Permit signs grants with (ACTENON_SIGNING_KEY_FILE)."""
    return _secret_file("grant-signing.key")


def approval_key() -> bytes:
    """Key that seals local approval records of a project's manifest."""
    return bytes.fromhex(_secret_file("approval.key").read_text().strip())


def proof_key_file() -> Path:
    """Ed25519 keypair the edge signs proofs (kernel PCCBs) with."""
    path = airlock_home() / "proof-ed25519.json"
    if not path.exists():
        from actenon_permit.ed25519_signer import generate_ed25519_keypair, save_ed25519_keypair

        save_ed25519_keypair(generate_ed25519_keypair(), path)
        os.chmod(path, 0o600)
    return path


def ca_dir() -> Path:
    d = airlock_home() / "ca"
    d.mkdir(exist_ok=True, mode=0o700)
    return d
