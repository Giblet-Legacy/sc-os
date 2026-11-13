"""
nerves.py — SC-OS v0.3.0 Nerves: a read-only view of a node's verified pin store

Function:
    Lets the rest of the stack (The Legacy's Nerves view) see who a node
    has pinned, without its private key and without writing anything.
    Verification is v0.2.0's own: the file is loaded through
    pins.PinStore with a public-key-only stand-in for the node key, so
    every SPEC_V2 §7.2 check runs unchanged and fails closed
    (SPEC_V3.md). Defines the stack's pin-file location under
    FORGE_HOME.

Public API:
    1. default_pin_path(env=None) -> str
    2. read_nerves(pin_path, owner_did=None) -> dict | None

Internal helpers (not exported):
    3. _PublicOnly    — exposes public_key() and nothing else
    4. _claimed_owner — the owner did a pin file names, or PinStoreError

Layer:    Tier 1 Consumer — SC-OS, Nerves
Depends:  pins.py (v0.2.0), P1 envelope_v2
Spec:     SPEC_V3.md 0.3.0
Version:  0.3.0 (signed off 2026-11-13)
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import pins  # noqa: E402  (puts P1, P2, P7 on sys.path)
import envelope_v2  # noqa: E402


# ---------------------------------------------------------------------------
# 3. _PublicOnly
#    PinStore calls private_key.public_key() to name and verify the owner.
#    This stand-in can do that and nothing more: it cannot sign, so a
#    reader can never write a pin file.
# ---------------------------------------------------------------------------
class _PublicOnly:
    def __init__(self, public_key):
        self._public_key = public_key

    # 3a. public_key
    def public_key(self):
        return self._public_key


# ---------------------------------------------------------------------------
# 4. _claimed_owner
# ---------------------------------------------------------------------------
def _claimed_owner(pin_path):
    try:
        with open(pin_path, "r", encoding="utf-8") as f:
            owner = json.load(f).get("owner")
        return owner, envelope_v2.did_key_decode(owner)
    except (OSError, ValueError, TypeError, AttributeError):
        raise pins.PinStoreError("pin file is unreadable or names no valid owner") from None


# ---------------------------------------------------------------------------
# 1. default_pin_path
#    SPEC_V3 §1.
# ---------------------------------------------------------------------------
def default_pin_path(env=None):
    env = os.environ if env is None else env
    home = env.get("FORGE_HOME") or os.path.join(os.path.expanduser("~"), ".forge")
    return os.path.join(home, "sc-os", "pins.sc.json")


# ---------------------------------------------------------------------------
# 2. read_nerves
#    SPEC_V3 §2.
# ---------------------------------------------------------------------------
def read_nerves(pin_path, owner_did=None):
    if not os.path.lexists(pin_path):
        return None
    owner, public_key = _claimed_owner(pin_path)
    if owner_did is not None and owner != owner_did:
        raise pins.PinStoreError("pin file belongs to another node")
    store = pins.PinStore(pin_path, _PublicOnly(public_key))  # full v0.2.0 verification
    peers = sorted(store.dids)
    return {"owner": store.owner, "owner_pinned": owner_did is not None,
            "peers": peers, "addresses": store.addresses, "peer_count": len(peers)}
