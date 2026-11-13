"""
peer.py — SC-OS v0.1.0 handshake: signed Hellos, key pinning, payload/ACK

Function:
    A Peer is one node of the Nervous System. As a server it accepts
    a signed Hello, verifies it through P2, pins the sender's did:key
    in memory, replies with its own signed Hello, then verifies and
    ACKs signed payloads (SPEC.md §5–§7). As a client it runs the
    mirror image and returns a Session for sending payloads.

    Every signature, did:key, canonical byte and hash comes from the
    frozen layers: P2 sign_v2 for capsules, P1 envelope_v2 for
    did:key and hashing. Nothing cryptographic is implemented here.

Public API:
    1. HandshakeError  — a Hello failed SPEC §6, or the peer refused ours
    2. PayloadError    — a payload or ACK failed SPEC §7
    3. new_nonce       — 32 lowercase hex chars from `secrets`
    4. make_hello      — build and P2-sign a Hello (or Hello reply)
    5. check_hello     — SPEC §6 checks; returns (did, public_key)
    6. Peer            — a node: identity, pin table, listener
       6a. did         — this node's did:key (attribute)
       6b. pins        — copy of the pin table {did: public_key}
       6c. received    — copy of accepted payload records
       6d. address     — (host, port) the listener is bound to
       6e. listen      — start the threaded TCP server
       6f. connect     — client handshake; returns a Session
       6g. close       — stop the listener
       6h. _pin        — record did -> key under the lock
       6i. _handle     — server side of one connection
    7. Session         — client side of a completed handshake
       7a. send        — sign a payload, send, verify the ACK
       7b. close       — close the connection

Internal helpers:
    8.  _is_nonce      — exactly 32 lowercase hex chars
    9.  _verify        — sign_v2.verify_capsule, False instead of raising
    10. _check_payload — SPEC §7 checks on B
    11. _check_ack     — SPEC §7 checks on A
    12. _send_error    — best-effort unsigned error frame (SPEC §4.5)

Layer:    Tier 1 Consumer — SC-OS, Handshake (peer)
Depends:  P1 Envelope v2.0.0 (envelope_v2), P2 Sign v2.0.0 (sign_v2),
          transport.py
Spec:     SPEC.md 0.1.0 §4–§7
Version:  0.1.0
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import os
import secrets
import sys
import threading

# Locate P1 and P2 from this file, not the working directory.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (os.path.join(_ROOT, "envelope-layer"), os.path.join(_ROOT, "sign-layer")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import envelope_v2  # noqa: E402  (P1)
import sign_v2  # noqa: E402  (P2)
import transport  # noqa: E402

PROTOCOL = "sc-os/0.1.0"
_NONCE_HEX = frozenset("0123456789abcdef")
_HELLO_FIELDS = frozenset({"type", "protocol", "did", "nonce", "signature"})
_REPLY_FIELDS = _HELLO_FIELDS | {"reply_to"}
_PAYLOAD_FIELDS = frozenset({"type", "seq", "body", "signature"})
_ACK_FIELDS = frozenset({"type", "seq", "ref", "signature"})


# ---------------------------------------------------------------------------
# 1. HandshakeError
# ---------------------------------------------------------------------------
class HandshakeError(Exception):
    """A Hello failed SPEC.md §6, or the remote refused our Hello."""


# ---------------------------------------------------------------------------
# 2. PayloadError
# ---------------------------------------------------------------------------
class PayloadError(Exception):
    """A payload or ACK failed SPEC.md §7."""


# ---------------------------------------------------------------------------
# 3. new_nonce
# ---------------------------------------------------------------------------
def new_nonce():
    return secrets.token_hex(16)


# ---------------------------------------------------------------------------
# 8. _is_nonce
# ---------------------------------------------------------------------------
def _is_nonce(value):
    return isinstance(value, str) and len(value) == 32 and set(value) <= _NONCE_HEX


# ---------------------------------------------------------------------------
# 9. _verify
#    P2 verify. Malformed input from the wire is False, never a crash.
# ---------------------------------------------------------------------------
def _verify(capsule, public_key):
    try:
        return sign_v2.verify_capsule(capsule, public_key) is True
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# 4. make_hello
#    SPEC §4.1, or §4.2 when reply_to is given. Signed by P2.
# ---------------------------------------------------------------------------
def make_hello(private_key, nonce, reply_to=None):
    hello = {
        "type": "hello",
        "protocol": PROTOCOL,
        "did": envelope_v2.did_key_encode(private_key.public_key()),
        "nonce": nonce,
    }
    if reply_to is not None:
        hello["reply_to"] = reply_to
    return sign_v2.sign_capsule(hello, private_key)


# ---------------------------------------------------------------------------
# 5. check_hello
#    SPEC §6, checks 1–6 in order. expected_reply_to=None means this is
#    an initiating Hello (no reply_to allowed); otherwise it is a reply
#    and reply_to must equal the nonce we sent.
# ---------------------------------------------------------------------------
def check_hello(hello, expected_reply_to=None):
    is_reply = expected_reply_to is not None
    fields = _REPLY_FIELDS if is_reply else _HELLO_FIELDS

    if not isinstance(hello, dict) or set(hello) != fields:
        raise HandshakeError("hello has the wrong fields")
    if hello["type"] != "hello" or hello["protocol"] != PROTOCOL:
        raise HandshakeError("not an sc-os/0.1.0 hello")
    if not _is_nonce(hello["nonce"]) or (is_reply and not _is_nonce(hello["reply_to"])):
        raise HandshakeError("malformed nonce")

    did = hello["did"]
    if not isinstance(did, str):
        raise HandshakeError("did is not a string")
    try:
        public_key = envelope_v2.did_key_decode(did)
    except Exception:  # any decode failure is a bad did (SPEC §6.4)
        raise HandshakeError("did is not a valid Ed25519 did:key") from None

    if not _verify(hello, public_key):
        raise HandshakeError("hello signature does not verify")
    if is_reply and hello["reply_to"] != expected_reply_to:
        raise HandshakeError("reply_to does not match our nonce")
    return did, public_key


# ---------------------------------------------------------------------------
# 10. _check_payload
# ---------------------------------------------------------------------------
def _check_payload(capsule, pinned_key, expected_seq):
    if set(capsule) != _PAYLOAD_FIELDS or capsule["type"] != "payload":
        return False
    seq = capsule["seq"]
    if type(seq) is not int or seq != expected_seq:
        return False
    return _verify(capsule, pinned_key)


# ---------------------------------------------------------------------------
# 11. _check_ack
# ---------------------------------------------------------------------------
def _check_ack(ack, pinned_key, sent):
    if not isinstance(ack, dict) or set(ack) != _ACK_FIELDS or ack["type"] != "ack":
        return False
    if type(ack["seq"]) is not int or ack["seq"] != sent["seq"]:
        return False
    if ack["ref"] != envelope_v2.sha256_hex(envelope_v2.canonical_bytes(sent)):
        return False
    return _verify(ack, pinned_key)


# ---------------------------------------------------------------------------
# 12. _send_error
# ---------------------------------------------------------------------------
def _send_error(conn, reason):
    try:
        conn.send({"type": "error", "reason": reason})
    except OSError:
        pass


# ---------------------------------------------------------------------------
# 6. Peer
# ---------------------------------------------------------------------------
class Peer:
    """One SC-OS node. Holds its private key, an in-memory pin table and a listener."""

    def __init__(self, private_key=None):
        self._key = private_key if private_key is not None else Ed25519PrivateKey.generate()
        # 6a. did
        self.did = envelope_v2.did_key_encode(self._key.public_key())
        self._lock = threading.Lock()
        self._pins = {}
        self._received = []
        self._listener = None

    # -----------------------------------------------------------------------
    # 6b. pins — copy, so callers cannot edit the table
    # -----------------------------------------------------------------------
    @property
    def pins(self):
        with self._lock:
            return dict(self._pins)

    # -----------------------------------------------------------------------
    # 6c. received — copy of {"from", "seq", "body", "capsule"} records
    # -----------------------------------------------------------------------
    @property
    def received(self):
        with self._lock:
            return list(self._received)

    # -----------------------------------------------------------------------
    # 6d. address
    # -----------------------------------------------------------------------
    @property
    def address(self):
        if self._listener is None:
            raise RuntimeError("peer is not listening")
        return self._listener.address

    # -----------------------------------------------------------------------
    # 6e. listen
    # -----------------------------------------------------------------------
    def listen(self, host="127.0.0.1", port=0):
        if self._listener is not None:
            raise RuntimeError("peer is already listening")
        listener = transport.Listener(host, port, self._handle)
        listener.start()
        self._listener = listener
        return listener.address

    # -----------------------------------------------------------------------
    # 6f. connect — SPEC §5, A's side. Pins B before returning.
    # -----------------------------------------------------------------------
    def connect(self, address):
        conn = transport.connect(*address)
        try:
            nonce = new_nonce()
            conn.send(make_hello(self._key, nonce))
            try:
                reply = conn.recv()
            except transport.FrameError as exc:
                raise HandshakeError(f"bad frame from remote: {exc}") from None
            if reply is None:
                raise HandshakeError("remote closed before replying")
            if reply.get("type") == "error":
                raise HandshakeError(f"remote refused hello: {reply.get('reason')}")
            did, public_key = check_hello(reply, expected_reply_to=nonce)
            self._pin(did, public_key)
            return Session(conn, self._key, did, public_key)
        except BaseException:
            conn.close()
            raise

    # -----------------------------------------------------------------------
    # 6g. close
    # -----------------------------------------------------------------------
    def close(self):
        if self._listener is not None:
            self._listener.close()
            self._listener = None

    # -----------------------------------------------------------------------
    # 6h. _pin
    # -----------------------------------------------------------------------
    def _pin(self, did, public_key):
        with self._lock:
            self._pins[did] = public_key

    # -----------------------------------------------------------------------
    # 6i. _handle — SPEC §5, B's side, one connection per call
    # -----------------------------------------------------------------------
    def _handle(self, conn):
        try:
            hello = conn.recv()
        except transport.FrameError:
            _send_error(conn, "bad_frame")
            return
        if hello is None:
            return
        try:
            remote_did, remote_key = check_hello(hello)
        except HandshakeError:
            _send_error(conn, "bad_hello")
            return

        self._pin(remote_did, remote_key)
        conn.send(make_hello(self._key, new_nonce(), reply_to=hello["nonce"]))

        expected_seq = 1
        while True:
            try:
                capsule = conn.recv()
            except transport.FrameError:
                _send_error(conn, "bad_frame")
                return
            if capsule is None:
                return
            if not _check_payload(capsule, remote_key, expected_seq):
                _send_error(conn, "bad_payload")
                return

            with self._lock:
                self._received.append({
                    "from": remote_did,
                    "seq": expected_seq,
                    "body": capsule["body"],
                    "capsule": capsule,
                })
            conn.send(sign_v2.sign_capsule({
                "type": "ack",
                "seq": expected_seq,
                "ref": envelope_v2.sha256_hex(envelope_v2.canonical_bytes(capsule)),
            }, self._key))
            expected_seq += 1


# ---------------------------------------------------------------------------
# 7. Session
# ---------------------------------------------------------------------------
class Session:
    """A's side of a completed handshake. One payload in flight at a time."""

    def __init__(self, conn, private_key, remote_did, remote_key):
        self._conn = conn
        self._key = private_key
        self._remote_key = remote_key
        self._seq = 0
        self.remote_did = remote_did

    # -----------------------------------------------------------------------
    # 7a. send — returns the verified ACK; closes and raises on failure
    # -----------------------------------------------------------------------
    def send(self, body):
        self._seq += 1
        capsule = sign_v2.sign_capsule({"type": "payload", "seq": self._seq, "body": body}, self._key)
        try:
            self._conn.send(capsule)
            ack = self._conn.recv()
        except transport.FrameError as exc:
            self.close()
            raise PayloadError(f"bad frame from remote: {exc}") from None
        if ack is None or ack.get("type") == "error":
            self.close()
            reason = "connection closed" if ack is None else ack.get("reason")
            raise PayloadError(f"payload refused: {reason}")
        if not _check_ack(ack, self._remote_key, capsule):
            self.close()
            raise PayloadError("ack does not verify")
        return ack

    # -----------------------------------------------------------------------
    # 7b. close
    # -----------------------------------------------------------------------
    def close(self):
        self._conn.close()
