"""
pins.py — SC-OS pin store, persisted as a P7 signed record

Function:
    Holds a node's pinned did:keys and its address pins
    ("host:port" -> did). With a path, every change is written to
    disk as a P7 signed record (self-signed by the node's key), and
    the file is verified through P7 and P2 on load. A bad file raises
    PinStoreError: pins are never silently dropped (SPEC_V2.md §7.2).
    With no path, pins live in memory only.

    No storage or signature format is invented here: writing is P7
    record_v2.save_signed_record, checking is P7
    record_v2.verify_record_file plus P2 sign_v2.verify_capsule, and
    did decoding is P1 envelope_v2.did_key_decode.

Public API:
    1. PinStoreError     — the pin file failed verification or shape checks
    2. PinStore          — the pin table
       2a. owner         — this node's did:key (attribute)
       2b. dids          — frozenset of pinned dids
       2c. addresses     — copy of {"host:port": did}
       2d. address_did   — did pinned for an address, or None
       2e. add           — pin a did (and optionally an address); persist
       2f. _load         — read, verify (P7 then P2) and shape-check the file
       2g. _save         — P7 write to <path>.tmp, then os.replace

Internal helpers:
    3. _decodes          — True if P1 accepts the did

Layer:    Tier 1 Consumer — SC-OS, Handshake v2 (pins)
Depends:  P1 envelope_v2 2.0.0, P2 sign_v2 2.0.0, P7 record_v2 2.0.0
Spec:     SPEC_V2.md 0.2.0 §7
Version:  0.2.0
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import json
import os
import sys
import threading

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (os.path.join(_ROOT, "envelope-layer"), os.path.join(_ROOT, "sign-layer"),
           os.path.join(_ROOT, "record-layer")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import envelope_v2  # noqa: E402  (P1)
import record_v2  # noqa: E402  (P7)
import sign_v2  # noqa: E402  (P2)

RECORD_TYPE = "sc-os/pins"
RECORD_VERSION = "0.2.0"
_FIELDS = frozenset({"type", "version", "owner", "dids", "addresses", "signature"})


# ---------------------------------------------------------------------------
# 1. PinStoreError
# ---------------------------------------------------------------------------
class PinStoreError(Exception):
    """The pin file on disk failed SPEC_V2.md §7.2 checks."""


# ---------------------------------------------------------------------------
# 3. _decodes
# ---------------------------------------------------------------------------
def _decodes(did):
    if not isinstance(did, str):
        return False
    try:
        envelope_v2.did_key_decode(did)
    except Exception:
        return False
    return True


# ---------------------------------------------------------------------------
# 2. PinStore
# ---------------------------------------------------------------------------
class PinStore:
    """Pinned dids and address pins. Thread-safe. Persisted through P7 if path is set."""

    def __init__(self, path, private_key):
        self._path = path
        self._key = private_key
        # 2a. owner
        self.owner = envelope_v2.did_key_encode(private_key.public_key())
        self._lock = threading.Lock()
        self._dids = set()
        self._addresses = {}
        if path is not None and os.path.lexists(path):
            self._load()

    # -----------------------------------------------------------------------
    # 2b. dids
    # -----------------------------------------------------------------------
    @property
    def dids(self):
        with self._lock:
            return frozenset(self._dids)

    # -----------------------------------------------------------------------
    # 2c. addresses
    # -----------------------------------------------------------------------
    @property
    def addresses(self):
        with self._lock:
            return dict(self._addresses)

    # -----------------------------------------------------------------------
    # 2d. address_did
    # -----------------------------------------------------------------------
    def address_did(self, address):
        with self._lock:
            return self._addresses.get(address)

    # -----------------------------------------------------------------------
    # 2e. add — ValueError for an undecodable did. Persists only on change.
    # -----------------------------------------------------------------------
    def add(self, did, address=None):
        if not _decodes(did):
            raise ValueError("did is not a valid Ed25519 did:key")
        if address is not None and not isinstance(address, str):
            raise TypeError(f"address must be str, got {type(address).__name__}")
        with self._lock:
            changed = did not in self._dids
            self._dids.add(did)
            if address is not None and self._addresses.get(address) != did:
                self._addresses[address] = did
                changed = True
            if changed and self._path is not None:
                self._save()
        return changed

    # -----------------------------------------------------------------------
    # 2f. _load — P7 verify, single read, P2 re-verify, then shape
    # -----------------------------------------------------------------------
    def _load(self):
        public_key = self._key.public_key()
        if not record_v2.verify_record_file(self._path, public_key):
            raise PinStoreError("pin file does not verify against this node's key")
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)
            ok = isinstance(data, dict) and sign_v2.verify_capsule(data, public_key)
        except (ValueError, OSError, TypeError):
            ok = False
        if not ok:
            raise PinStoreError("pin file changed between verify and read, or is malformed")

        if set(data) != _FIELDS or data["type"] != RECORD_TYPE or data["version"] != RECORD_VERSION:
            raise PinStoreError("pin file has the wrong shape")
        if data["owner"] != self.owner:
            raise PinStoreError("pin file belongs to another node")
        dids, addresses = data["dids"], data["addresses"]
        if not isinstance(dids, list) or not all(_decodes(d) for d in dids):
            raise PinStoreError("pin file dids are malformed")
        if not isinstance(addresses, dict) or not all(
                isinstance(k, str) and v in dids for k, v in addresses.items()):
            raise PinStoreError("pin file addresses are malformed")

        self._dids = set(dids)
        self._addresses = dict(addresses)

    # -----------------------------------------------------------------------
    # 2g. _save — caller holds the lock. Crash-safe via os.replace.
    # -----------------------------------------------------------------------
    def _save(self):
        record = {
            "type": RECORD_TYPE,
            "version": RECORD_VERSION,
            "owner": self.owner,
            "dids": sorted(self._dids),
            "addresses": dict(self._addresses),
        }
        tmp = self._path + ".tmp"
        record_v2.save_signed_record(record, tmp, self._key)
        os.replace(tmp, self._path)
