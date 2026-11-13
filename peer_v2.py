"""
peer_v2.py — SC-OS v0.2.0: 3-way handshake, persistent pins, keepalive

Function:
    The layer above the signed-off v0.1.0 peer.py. Adds a Confirm
    step so A must prove key possession against B's fresh nonce
    (replay-proof), binds every post-handshake capsule to a session
    id, persists pins through P7 (pins.py), enforces address pins and
    an optional "pinned" trust policy, and keeps long sessions alive
    with signed Ping/Pong (SPEC_V2.md).

    peer.py and transport.py are not edited. Framing is transport.py;
    nonce, verify and error helpers are peer.py's; every signature,
    did:key and hash is P1/P2; key loading is P7.

Public API:
    1.  PROTOCOL       — "sc-os/0.2.0"
    2.  HandshakeError, PayloadError, new_nonce — re-exported from peer.py
    3.  session_id     — sha256 of canonical {"a": nA, "b": nB}
    4.  make_hello     — P2-signed v0.2.0 Hello / Hello reply
    5.  make_confirm   — P2-signed Confirm for B's nonce
    6.  check_hello    — SPEC.md §6 checks with the v0.2.0 protocol
    7.  Peer           — a node
        7a. from_pem   — identity from passphrase-protected PEM (P7)
        7b. did        — this node's did:key (attribute)
        7c. pins       — {did: public_key}
        7d. addresses  — {"host:port": did}
        7e. received   — accepted payload records
        7f. address    — (host, port) of the listener
        7g. pin        — pin a did (and optionally an address) by hand
        7h. listen     — start the threaded TCP server
        7i. connect    — A's side of the handshake; returns a Session
        7j. close      — stop the listener
        7k. _handle    — B's side of one connection
    8.  Session        — A's side after the handshake
        8a. send       — signed payload -> verified ACK
        8b. alive      — False once the session has failed or closed
        8c. close      — stop keepalive, close the connection
        8d. _exchange  — one request/response, lock held
        8e. _kill      — mark dead and close
        8f. _keepalive_loop — Ping when idle

Internal helpers:
    9.  _addr_key        — (host, port) -> "host:port"
    10. _check_confirm   — SPEC_V2 §6.2
    11. _check_request   — SPEC_V2 §8.1 (payload / ping) on B
    12. _check_response  — SPEC_V2 §8.1/§8.3 (ack / pong) on A

Layer:    Tier 1 Consumer — SC-OS, Handshake v2
Depends:  peer.py + transport.py (SC-OS 0.1.0), pins.py,
          P1 envelope_v2 2.0.0, P2 sign_v2 2.0.0, P7 record_v2 2.0.0
Spec:     SPEC_V2.md 0.2.0
Version:  0.2.0
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import os
import sys
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (os.path.join(_ROOT, "envelope-layer"), os.path.join(_ROOT, "sign-layer"),
           os.path.join(_ROOT, "record-layer")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

import envelope_v2  # noqa: E402  (P1)
import peer as _v1  # noqa: E402  (SC-OS 0.1.0)
import pins  # noqa: E402
import record_v2  # noqa: E402  (P7)
import sign_v2  # noqa: E402  (P2)
import transport  # noqa: E402

# 1. PROTOCOL
PROTOCOL = "sc-os/0.2.0"

# 2. Re-exports from SC-OS 0.1.0
HandshakeError = _v1.HandshakeError
PayloadError = _v1.PayloadError
new_nonce = _v1.new_nonce

_HELLO_FIELDS = frozenset({"type", "protocol", "did", "nonce", "signature"})
_REPLY_FIELDS = _HELLO_FIELDS | {"reply_to"}
_CONFIRM_FIELDS = frozenset({"type", "protocol", "did", "reply_to", "signature"})
_REQUEST_FIELDS = {
    "payload": frozenset({"type", "session", "seq", "body", "signature"}),
    "ping": frozenset({"type", "session", "seq", "signature"}),
}
_RESPONSE_FIELDS = {
    "ack": frozenset({"type", "session", "seq", "ref", "signature"}),
    "pong": frozenset({"type", "session", "seq", "signature"}),
}
_RESPONSE_TO = {"payload": "ack", "ping": "pong"}
_TRUST = ("tofu", "pinned")


# ---------------------------------------------------------------------------
# 3. session_id
# ---------------------------------------------------------------------------
def session_id(nonce_a, nonce_b):
    return envelope_v2.sha256_hex(envelope_v2.canonical_bytes({"a": nonce_a, "b": nonce_b}))


# ---------------------------------------------------------------------------
# 4. make_hello
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
# 5. make_confirm
# ---------------------------------------------------------------------------
def make_confirm(private_key, reply_to):
    return sign_v2.sign_capsule({
        "type": "confirm",
        "protocol": PROTOCOL,
        "did": envelope_v2.did_key_encode(private_key.public_key()),
        "reply_to": reply_to,
    }, private_key)


# ---------------------------------------------------------------------------
# 6. check_hello — SPEC.md §6 steps 1–6, protocol "sc-os/0.2.0"
# ---------------------------------------------------------------------------
def check_hello(hello, expected_reply_to=None):
    is_reply = expected_reply_to is not None
    fields = _REPLY_FIELDS if is_reply else _HELLO_FIELDS

    if not isinstance(hello, dict) or set(hello) != fields:
        raise HandshakeError("hello has the wrong fields")
    if hello["type"] != "hello" or hello["protocol"] != PROTOCOL:
        raise HandshakeError("not an sc-os/0.2.0 hello")
    if not _v1._is_nonce(hello["nonce"]) or (is_reply and not _v1._is_nonce(hello["reply_to"])):
        raise HandshakeError("malformed nonce")

    did = hello["did"]
    if not isinstance(did, str):
        raise HandshakeError("did is not a string")
    try:
        public_key = envelope_v2.did_key_decode(did)
    except Exception:
        raise HandshakeError("did is not a valid Ed25519 did:key") from None

    if not _v1._verify(hello, public_key):
        raise HandshakeError("hello signature does not verify")
    if is_reply and hello["reply_to"] != expected_reply_to:
        raise HandshakeError("reply_to does not match our nonce")
    return did, public_key


# ---------------------------------------------------------------------------
# 9. _addr_key
# ---------------------------------------------------------------------------
def _addr_key(address):
    host, port = address[0], address[1]
    return f"{host}:{int(port)}"


# ---------------------------------------------------------------------------
# 10. _check_confirm — SPEC_V2 §6.2
# ---------------------------------------------------------------------------
def _check_confirm(confirm, did, public_key, nonce_b):
    if set(confirm) != _CONFIRM_FIELDS:
        return False
    if confirm["type"] != "confirm" or confirm["protocol"] != PROTOCOL:
        return False
    if confirm["did"] != did or confirm["reply_to"] != nonce_b:
        return False
    return _v1._verify(confirm, public_key)


# ---------------------------------------------------------------------------
# 11. _check_request — payload or ping on B
# ---------------------------------------------------------------------------
def _check_request(msg, public_key, sid, expected_seq):
    fields = _REQUEST_FIELDS.get(msg.get("type"))
    if fields is None or set(msg) != fields:
        return False
    if msg["session"] != sid:
        return False
    if type(msg["seq"]) is not int or msg["seq"] != expected_seq:
        return False
    return _v1._verify(msg, public_key)


# ---------------------------------------------------------------------------
# 12. _check_response — ack or pong on A, matched to the request sent
# ---------------------------------------------------------------------------
def _check_response(resp, public_key, sent):
    kind = _RESPONSE_TO[sent["type"]]
    if not isinstance(resp, dict) or resp.get("type") != kind or set(resp) != _RESPONSE_FIELDS[kind]:
        return False
    if resp["session"] != sent["session"]:
        return False
    if type(resp["seq"]) is not int or resp["seq"] != sent["seq"]:
        return False
    if kind == "ack" and resp["ref"] != envelope_v2.sha256_hex(envelope_v2.canonical_bytes(sent)):
        return False
    return _v1._verify(resp, public_key)


# ---------------------------------------------------------------------------
# 7. Peer
# ---------------------------------------------------------------------------
class Peer:
    """One SC-OS v0.2.0 node."""

    def __init__(self, private_key=None, pin_path=None, trust="tofu",
                 idle_timeout=30.0, keepalive_interval=10.0):
        if trust not in _TRUST:
            raise ValueError(f"trust must be one of {_TRUST}, got {trust!r}")
        self._key = private_key if private_key is not None else Ed25519PrivateKey.generate()
        # 7b. did
        self.did = envelope_v2.did_key_encode(self._key.public_key())
        self._trust = trust
        self._idle_timeout = idle_timeout
        self._keepalive_interval = keepalive_interval
        self._store = pins.PinStore(pin_path, self._key)  # raises PinStoreError
        self._lock = threading.Lock()
        self._received = []
        self._listener = None

    # -----------------------------------------------------------------------
    # 7a. from_pem — P7 loads; wrong passphrase / unencrypted PEM -> ValueError
    # -----------------------------------------------------------------------
    @classmethod
    def from_pem(cls, key_path, passphrase, **kwargs):
        return cls(private_key=record_v2.load_private_key(key_path, passphrase), **kwargs)

    # -----------------------------------------------------------------------
    # 7c. pins
    # -----------------------------------------------------------------------
    @property
    def pins(self):
        return {did: envelope_v2.did_key_decode(did) for did in self._store.dids}

    # -----------------------------------------------------------------------
    # 7d. addresses
    # -----------------------------------------------------------------------
    @property
    def addresses(self):
        return self._store.addresses

    # -----------------------------------------------------------------------
    # 7e. received
    # -----------------------------------------------------------------------
    @property
    def received(self):
        with self._lock:
            return list(self._received)

    # -----------------------------------------------------------------------
    # 7f. address
    # -----------------------------------------------------------------------
    @property
    def address(self):
        if self._listener is None:
            raise RuntimeError("peer is not listening")
        return self._listener.address

    # -----------------------------------------------------------------------
    # 7g. pin
    # -----------------------------------------------------------------------
    def pin(self, did, address=None):
        return self._store.add(did, None if address is None else _addr_key(address))

    # -----------------------------------------------------------------------
    # 7h. listen — B's idle timeout is the per-connection socket timeout
    # -----------------------------------------------------------------------
    def listen(self, host="127.0.0.1", port=0):
        if self._listener is not None:
            raise RuntimeError("peer is already listening")
        listener = transport.Listener(host, port, self._handle, timeout=self._idle_timeout)
        listener.start()
        self._listener = listener
        return listener.address

    # -----------------------------------------------------------------------
    # 7i. connect — SPEC_V2 §5, §7.3, §7.4
    # -----------------------------------------------------------------------
    def connect(self, address):
        conn = transport.connect(*address)
        try:
            nonce_a = new_nonce()
            conn.send(make_hello(self._key, nonce_a))
            try:
                reply = conn.recv()
            except transport.FrameError as exc:
                raise HandshakeError(f"bad frame from remote: {exc}") from None
            if reply is None:
                raise HandshakeError("remote closed before replying")
            if reply.get("type") == "error":
                raise HandshakeError(f"remote refused hello: {reply.get('reason')}")
            did, public_key = check_hello(reply, expected_reply_to=nonce_a)

            addr = _addr_key(address)
            pinned = self._store.address_did(addr)
            if pinned is not None and pinned != did:
                raise HandshakeError(f"key changed for {addr}: pinned {pinned}, got {did}")
            if self._trust == "pinned" and did not in self._store.dids:
                raise HandshakeError(f"unknown peer {did} (trust=pinned)")

            conn.send(make_confirm(self._key, reply["nonce"]))
            self._store.add(did, addr)
            return Session(conn, self._key, did, public_key,
                           session_id(nonce_a, reply["nonce"]), self._keepalive_interval)
        except BaseException:
            conn.close()
            raise

    # -----------------------------------------------------------------------
    # 7j. close
    # -----------------------------------------------------------------------
    def close(self):
        if self._listener is not None:
            self._listener.close()
            self._listener = None

    # -----------------------------------------------------------------------
    # 7k. _handle — B's side; returns (and the connection closes) on any failure
    # -----------------------------------------------------------------------
    def _handle(self, conn):
        try:
            hello = conn.recv()
        except transport.FrameError:
            _v1._send_error(conn, "bad_frame")
            return
        if hello is None:
            return
        try:
            remote_did, remote_key = check_hello(hello)
        except HandshakeError:
            _v1._send_error(conn, "bad_hello")
            return
        if self._trust == "pinned" and remote_did not in self._store.dids:
            _v1._send_error(conn, "unknown_peer")
            return

        nonce_b = new_nonce()
        conn.send(make_hello(self._key, nonce_b, reply_to=hello["nonce"]))

        try:
            confirm = conn.recv()
        except transport.FrameError:
            _v1._send_error(conn, "bad_frame")
            return
        if confirm is None:
            return
        if not _check_confirm(confirm, remote_did, remote_key, nonce_b):
            _v1._send_error(conn, "bad_confirm")
            return

        self._store.add(remote_did)
        sid = session_id(hello["nonce"], nonce_b)

        expected_seq = 1
        while True:
            try:
                msg = conn.recv()
            except transport.FrameError:
                _v1._send_error(conn, "bad_frame")
                return
            if msg is None:
                return
            if not _check_request(msg, remote_key, sid, expected_seq):
                _v1._send_error(conn, "bad_payload")
                return

            if msg["type"] == "payload":
                with self._lock:
                    self._received.append({
                        "from": remote_did,
                        "session": sid,
                        "seq": expected_seq,
                        "body": msg["body"],
                        "capsule": msg,
                    })
                conn.send(sign_v2.sign_capsule({
                    "type": "ack",
                    "session": sid,
                    "seq": expected_seq,
                    "ref": envelope_v2.sha256_hex(envelope_v2.canonical_bytes(msg)),
                }, self._key))
            else:
                conn.send(sign_v2.sign_capsule({
                    "type": "pong", "session": sid, "seq": expected_seq,
                }, self._key))
            expected_seq += 1


# ---------------------------------------------------------------------------
# 8. Session
# ---------------------------------------------------------------------------
class Session:
    """A's side after the handshake. One exchange in flight at a time."""

    def __init__(self, conn, private_key, remote_did, remote_key, sid, keepalive_interval):
        self._conn = conn
        self._key = private_key
        self._remote_key = remote_key
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._seq = 0
        self._dead = None
        self._last = time.monotonic()
        self.remote_did = remote_did
        self.session_id = sid
        self._thread = None
        if keepalive_interval is not None:
            self._thread = threading.Thread(target=self._keepalive_loop, args=(keepalive_interval,),
                                            name="sc-os-keepalive", daemon=True)
            self._thread.start()

    # -----------------------------------------------------------------------
    # 8a. send
    # -----------------------------------------------------------------------
    def send(self, body):
        with self._lock:
            return self._exchange("payload", {"body": body})

    # -----------------------------------------------------------------------
    # 8b. alive
    # -----------------------------------------------------------------------
    @property
    def alive(self):
        return self._dead is None

    # -----------------------------------------------------------------------
    # 8c. close — waits for any in-flight exchange, then closes
    # -----------------------------------------------------------------------
    def close(self):
        self._stop.set()
        with self._lock:
            if self._dead is None:
                self._kill("closed")
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2)

    # -----------------------------------------------------------------------
    # 8d. _exchange — caller holds self._lock
    # -----------------------------------------------------------------------
    def _exchange(self, kind, fields):
        if self._dead is not None:
            raise PayloadError(f"session is dead: {self._dead}")
        self._seq += 1
        request = sign_v2.sign_capsule(
            dict(fields, type=kind, session=self.session_id, seq=self._seq), self._key)
        try:
            self._conn.send(request)
            resp = self._conn.recv()
        except (OSError, transport.FrameError) as exc:
            self._kill(f"{kind} failed: {exc}")
            raise PayloadError(f"{kind} failed: {exc}") from None
        self._last = time.monotonic()

        if resp is None or resp.get("type") == "error":
            reason = "connection closed" if resp is None else resp.get("reason")
            self._kill(f"{kind} refused: {reason}")
            raise PayloadError(f"{kind} refused: {reason}")
        if not _check_response(resp, self._remote_key, request):
            self._kill(f"{_RESPONSE_TO[kind]} does not verify")
            raise PayloadError(f"{_RESPONSE_TO[kind]} does not verify")
        return resp

    # -----------------------------------------------------------------------
    # 8e. _kill — caller holds self._lock
    # -----------------------------------------------------------------------
    def _kill(self, reason):
        self._dead = reason
        self._conn.close()

    # -----------------------------------------------------------------------
    # 8f. _keepalive_loop — wakes every interval/4; pings when idle >= interval
    # -----------------------------------------------------------------------
    def _keepalive_loop(self, interval):
        while not self._stop.wait(interval / 4):
            with self._lock:
                if self._dead is not None or self._stop.is_set():
                    return
                if time.monotonic() - self._last < interval:
                    continue
                try:
                    self._exchange("ping", {})
                except PayloadError:
                    return
