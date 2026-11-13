"""
test_peer.py — SPEC §8 tests for the SC-OS v0.1.0 handshake

Function:
    Exercises transport.py (framing, listener) and peer.py (Hello
    exchange, key pinning, payload/ACK) over real loopback sockets.
    Each test maps to one row of SPEC.md §8 (T1–T9). Written before
    the code, per the stack rule: spec, then tests, then code.

Tests (numbered, SPEC §8 ID in brackets):
    1. test_listener_binds_and_listens        [T1]
    2. test_frame_round_trip                  [T2]
    3. test_frame_errors                      [T2]
    4. test_frame_clean_eof_returns_none      [T2]
    5. test_peers_exchange_hellos             [T3]
    6. test_forged_hello_signature_rejected   [T4]
    7. test_bad_hello_variants_rejected       [T5]
    8. test_client_rejects_bad_reply          [T6]
    9. test_payload_accepted_and_acked        [T7]
    10. test_payload_from_unpinned_key_rejected [T8]
    11. test_payload_without_hello_rejected    [T9]

Helpers (numbered):
    12. _raw_connect   — transport.Connection to a listening Peer
    13. _flip_hex      — change one hex char of a signature value
    14. _assert_closed — next recv is EOF (None) or a closed socket
    15–18. Hello tamper functions for test 7

Layer:    Tier 1 Consumer — SC-OS, Handshake
Spec:     SPEC.md 0.1.0, §8
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import socket

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import envelope_v2
import sign_v2
import peer
import transport


# ---------------------------------------------------------------------------
# Fixtures — a listening B and a client A, closed after each test.
# ---------------------------------------------------------------------------
@pytest.fixture
def node_b():
    b = peer.Peer()
    b.listen()
    yield b
    b.close()


@pytest.fixture
def node_a():
    a = peer.Peer()
    yield a
    a.close()


# ---------------------------------------------------------------------------
# 12. _raw_connect
# ---------------------------------------------------------------------------
def _raw_connect(node):
    return transport.connect(*node.address)


# ---------------------------------------------------------------------------
# 13. _flip_hex
# ---------------------------------------------------------------------------
def _flip_hex(value, index=0):
    ch = value[index]
    return value[:index] + ("0" if ch != "0" else "1") + value[index + 1:]


# ---------------------------------------------------------------------------
# 14. _assert_closed
# ---------------------------------------------------------------------------
def _assert_closed(conn):
    try:
        assert conn.recv() is None
    except OSError:
        pass  # reset by peer also counts as closed


# ---------------------------------------------------------------------------
# 1. test_listener_binds_and_listens  [T1]
# ---------------------------------------------------------------------------
def test_listener_binds_and_listens():
    seen = []
    listener = transport.Listener("127.0.0.1", 0, seen.append)
    listener.start()
    try:
        host, port = listener.address
        assert host == "127.0.0.1"
        assert port > 0
        with socket.create_connection((host, port), timeout=5):
            pass
    finally:
        listener.close()


# ---------------------------------------------------------------------------
# 2. test_frame_round_trip  [T2]
# ---------------------------------------------------------------------------
def test_frame_round_trip():
    left, right = socket.socketpair()
    a, b = transport.Connection(left), transport.Connection(right)
    try:
        obj = {"z": 1, "a": "line\nbreak", "u": "é"}
        a.send(obj)
        assert b.recv() == obj
    finally:
        a.close()
        b.close()


# ---------------------------------------------------------------------------
# 3. test_frame_errors  [T2]
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("raw", [
    b"[1,2,3]\n",                                   # not an object
    b"{not json}\n",                                 # not JSON
    b'{"x":NaN}\n',                                  # non-finite
    b'{"x":-Infinity}\n',                            # non-finite
    b"\xff\xfe\n",                                   # not UTF-8
    b'{"x":"' + b"a" * transport.MAX_FRAME + b'"}\n',  # oversize
    b'{"x":1}',                                      # EOF mid-frame
], ids=["array", "not-json", "nan", "neg-infinity", "not-utf8", "oversize", "truncated"])
def test_frame_errors(raw):
    left, right = socket.socketpair()
    b = transport.Connection(right)
    try:
        left.sendall(raw)
        left.shutdown(socket.SHUT_WR)
        with pytest.raises(transport.FrameError):
            b.recv()
    finally:
        left.close()
        b.close()


# ---------------------------------------------------------------------------
# 4. test_frame_clean_eof_returns_none  [T2]
# ---------------------------------------------------------------------------
def test_frame_clean_eof_returns_none():
    left, right = socket.socketpair()
    b = transport.Connection(right)
    try:
        left.shutdown(socket.SHUT_WR)
        assert b.recv() is None
    finally:
        left.close()
        b.close()


# ---------------------------------------------------------------------------
# 5. test_peers_exchange_hellos  [T3]
# ---------------------------------------------------------------------------
def test_peers_exchange_hellos(node_a, node_b):
    session = node_a.connect(node_b.address)
    try:
        assert session.remote_did == node_b.did
        assert node_b.did in node_a.pins
        assert node_a.did in node_b.pins
        assert node_a.did.startswith("did:key:z")
        assert node_a.did != node_b.did
    finally:
        session.close()


# ---------------------------------------------------------------------------
# 6. test_forged_hello_signature_rejected  [T4]
# ---------------------------------------------------------------------------
def test_forged_hello_signature_rejected(node_b):
    key = Ed25519PrivateKey.generate()
    hello = peer.make_hello(key, peer.new_nonce())
    hello["signature"]["value"] = _flip_hex(hello["signature"]["value"])

    conn = _raw_connect(node_b)
    try:
        conn.send(hello)
        assert conn.recv() == {"type": "error", "reason": "bad_hello"}
        _assert_closed(conn)
    finally:
        conn.close()
    assert node_b.pins == {}


# ---------------------------------------------------------------------------
# 15. _tamper_body — signed field changed after signing
# ---------------------------------------------------------------------------
def _tamper_body(hello, other):
    hello["nonce"] = _flip_hex(hello["nonce"])


# ---------------------------------------------------------------------------
# 16. _claim_other_did — did names a key other than the signer
# ---------------------------------------------------------------------------
def _claim_other_did(hello, other):
    hello["did"] = envelope_v2.did_key_encode(other.public_key())


# ---------------------------------------------------------------------------
# 17. _extra_field — field outside the §4.1 set
# ---------------------------------------------------------------------------
def _extra_field(hello, other):
    hello["extra"] = 1


# ---------------------------------------------------------------------------
# 18. _bad_did — undecodable did:key
# ---------------------------------------------------------------------------
def _bad_did(hello, other):
    hello["did"] = "did:key:not-a-key"


# ---------------------------------------------------------------------------
# 7. test_bad_hello_variants_rejected  [T5]
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("tamper", [_tamper_body, _claim_other_did, _extra_field, _bad_did])
def test_bad_hello_variants_rejected(node_b, tamper):
    key, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    hello = peer.make_hello(key, peer.new_nonce())
    tamper(hello, other)

    conn = _raw_connect(node_b)
    try:
        conn.send(hello)
        assert conn.recv() == {"type": "error", "reason": "bad_hello"}
        _assert_closed(conn)
    finally:
        conn.close()
    assert node_b.pins == {}


# ---------------------------------------------------------------------------
# 8. test_client_rejects_bad_reply  [T6]
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("fault", ["forged_signature", "wrong_reply_to", "no_reply_to"])
def test_client_rejects_bad_reply(node_a, fault):
    server_key = Ed25519PrivateKey.generate()

    def fake_b(conn):
        hello = conn.recv()
        reply_to = hello["nonce"]
        if fault == "wrong_reply_to":
            reply_to = _flip_hex(reply_to)
        reply = peer.make_hello(
            server_key, peer.new_nonce(),
            reply_to=None if fault == "no_reply_to" else reply_to,
        )
        if fault == "forged_signature":
            reply["signature"]["value"] = _flip_hex(reply["signature"]["value"])
        conn.send(reply)
        conn.recv()  # wait for A to hang up

    listener = transport.Listener("127.0.0.1", 0, fake_b)
    listener.start()
    try:
        with pytest.raises(peer.HandshakeError):
            node_a.connect(listener.address)
        assert node_a.pins == {}
    finally:
        listener.close()


# ---------------------------------------------------------------------------
# 9. test_payload_accepted_and_acked  [T7]
# ---------------------------------------------------------------------------
def test_payload_accepted_and_acked(node_a, node_b):
    session = node_a.connect(node_b.address)
    try:
        ack1 = session.send({"msg": "test capsule", "n": 1})
        ack2 = session.send(["second", 2])

        b_key = envelope_v2.did_key_decode(node_b.did)
        for ack, seq in ((ack1, 1), (ack2, 2)):
            assert ack["type"] == "ack"
            assert ack["seq"] == seq
            assert sign_v2.verify_capsule(ack, b_key)

        received = node_b.received
        assert [r["body"] for r in received] == [{"msg": "test capsule", "n": 1}, ["second", 2]]
        assert all(r["from"] == node_a.did for r in received)
        assert ack1["ref"] == envelope_v2.sha256_hex(envelope_v2.canonical_bytes(received[0]["capsule"]))
    finally:
        session.close()


# ---------------------------------------------------------------------------
# 10. test_payload_from_unpinned_key_rejected  [T8]
# ---------------------------------------------------------------------------
def test_payload_from_unpinned_key_rejected(node_b):
    key, intruder = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    conn = _raw_connect(node_b)
    try:
        nonce = peer.new_nonce()
        conn.send(peer.make_hello(key, nonce))
        reply = conn.recv()
        assert reply["type"] == "hello" and reply["reply_to"] == nonce

        forged = sign_v2.sign_capsule({"type": "payload", "seq": 1, "body": "x"}, intruder)
        conn.send(forged)
        assert conn.recv() == {"type": "error", "reason": "bad_payload"}
        _assert_closed(conn)
    finally:
        conn.close()
    assert node_b.received == []


# ---------------------------------------------------------------------------
# 11. test_payload_without_hello_rejected  [T9]
# ---------------------------------------------------------------------------
def test_payload_without_hello_rejected(node_b):
    key = Ed25519PrivateKey.generate()
    conn = _raw_connect(node_b)
    try:
        conn.send(sign_v2.sign_capsule({"type": "payload", "seq": 1, "body": "x"}, key))
        assert conn.recv() == {"type": "error", "reason": "bad_hello"}
        _assert_closed(conn)
    finally:
        conn.close()
    assert node_b.pins == {}
    assert node_b.received == []
