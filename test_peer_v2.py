"""
test_peer_v2.py — SPEC_V2 §9 tests for the SC-OS v0.2.0 layer

Function:
    Exercises peer_v2.py (3-way handshake, session binding, trust
    policy, keepalive) and pins.py (P7-persisted pin store) over real
    loopback sockets and real files in pytest's tmp_path. Each test
    maps to one row of SPEC_V2.md §9 (V1–V15). Written before the
    code. test_peer.py (v0.1.0) is untouched and must stay green.

Tests (numbered, SPEC_V2 §9 ID in brackets):
    1.  test_three_way_handshake                [V1]
    2.  test_no_pin_before_confirm               [V2]
    3.  test_bad_confirm_rejected                [V3]
    4.  test_replayed_hello_and_confirm_rejected [V4]
    5.  test_cross_session_payload_rejected      [V5]
    6.  test_v010_hello_rejected                 [V6]
    7.  test_payload_accepted_and_acked          [V7]
    8.  test_pins_survive_restart                [V8]
    9.  test_bad_pin_file_raises                 [V9]
    10. test_identity_from_pem                   [V10]
    11. test_address_key_change_refused          [V11]
    12. test_pinned_trust_policy                 [V12]
    13. test_keepalive_outlives_idle_timeout     [V13]
    14. test_silent_handshake_times_out          [V14]
    15. test_bad_ping_rejected                   [V15]

Helpers (numbered):
    16. _write_pem       — encrypted Ed25519 PEM in tmp_path (test-only key creation)
    17. _raw_handshake   — drive A's side by hand with a given key
    18. _signed          — sign_v2.sign_capsule shorthand
    19. _flip_hex        — change one hex char
    20. _assert_closed   — next recv is EOF or a reset
    21. _wait_for        — poll a condition with a deadline

Layer:    Tier 1 Consumer — SC-OS, Handshake v2
Spec:     SPEC_V2.md 0.2.0, §9
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import envelope_v2
import peer
import peer_v2
import pins
import record_v2
import sign_v2
import transport

PASS = "correct horse battery staple"


# ---------------------------------------------------------------------------
# 16. _write_pem — test fixture only; SC-OS itself never writes keys
# ---------------------------------------------------------------------------
def _write_pem(path, key=None):
    key = key or Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(PASS.encode()),
    ))
    return key


# ---------------------------------------------------------------------------
# 17. _raw_handshake — returns (conn, hello, reply, confirm, session)
# ---------------------------------------------------------------------------
def _raw_handshake(node, key):
    conn = transport.connect(*node.address)
    nonce = peer_v2.new_nonce()
    hello = peer_v2.make_hello(key, nonce)
    conn.send(hello)
    reply = conn.recv()
    assert reply["type"] == "hello" and reply["reply_to"] == nonce
    confirm = peer_v2.make_confirm(key, reply["nonce"])
    conn.send(confirm)
    return conn, hello, reply, confirm, peer_v2.session_id(nonce, reply["nonce"])


# ---------------------------------------------------------------------------
# 18. _signed
# ---------------------------------------------------------------------------
def _signed(obj, key):
    return sign_v2.sign_capsule(obj, key)


# ---------------------------------------------------------------------------
# 19. _flip_hex
# ---------------------------------------------------------------------------
def _flip_hex(value, index=0):
    return value[:index] + ("0" if value[index] != "0" else "1") + value[index + 1:]


# ---------------------------------------------------------------------------
# 20. _assert_closed
# ---------------------------------------------------------------------------
def _assert_closed(conn):
    try:
        assert conn.recv() is None
    except OSError:
        pass


# ---------------------------------------------------------------------------
# 21. _wait_for
# ---------------------------------------------------------------------------
def _wait_for(cond, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def node_b():
    b = peer_v2.Peer()
    b.listen()
    yield b
    b.close()


@pytest.fixture
def node_a():
    a = peer_v2.Peer(keepalive_interval=None)
    yield a
    a.close()


# ---------------------------------------------------------------------------
# 1. test_three_way_handshake  [V1]
# ---------------------------------------------------------------------------
def test_three_way_handshake(node_a, node_b):
    session = node_a.connect(node_b.address)
    try:
        assert session.remote_did == node_b.did
        assert node_b.did in node_a.pins
        assert _wait_for(lambda: node_a.did in node_b.pins)
        assert node_a.addresses == {"%s:%d" % node_b.address: node_b.did}
        session.send("x")
        assert node_b.received[0]["session"] == session.session_id
    finally:
        session.close()


# ---------------------------------------------------------------------------
# 2. test_no_pin_before_confirm  [V2]
# ---------------------------------------------------------------------------
def test_no_pin_before_confirm(node_b):
    key = Ed25519PrivateKey.generate()
    conn = transport.connect(*node_b.address)
    try:
        nonce = peer_v2.new_nonce()
        conn.send(peer_v2.make_hello(key, nonce))
        assert conn.recv()["reply_to"] == nonce
        assert node_b.pins == {}
    finally:
        conn.close()
    time.sleep(0.1)
    assert node_b.pins == {}


# ---------------------------------------------------------------------------
# 3. test_bad_confirm_rejected  [V3]
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("fault", ["wrong_reply_to", "other_key", "other_did", "extra_field"])
def test_bad_confirm_rejected(node_b, fault):
    key, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    conn = transport.connect(*node_b.address)
    try:
        conn.send(peer_v2.make_hello(key, peer_v2.new_nonce()))
        reply = conn.recv()
        if fault == "wrong_reply_to":
            confirm = peer_v2.make_confirm(key, _flip_hex(reply["nonce"]))
        elif fault == "other_key":
            confirm = peer_v2.make_confirm(other, reply["nonce"])
        elif fault == "other_did":
            confirm = _signed({"type": "confirm", "protocol": peer_v2.PROTOCOL,
                               "did": envelope_v2.did_key_encode(other.public_key()),
                               "reply_to": reply["nonce"]}, key)
        else:
            confirm = _signed({"type": "confirm", "protocol": peer_v2.PROTOCOL,
                               "did": envelope_v2.did_key_encode(key.public_key()),
                               "reply_to": reply["nonce"], "extra": 1}, key)
        conn.send(confirm)
        assert conn.recv() == {"type": "error", "reason": "bad_confirm"}
        _assert_closed(conn)
    finally:
        conn.close()
    assert node_b.pins == {}


# ---------------------------------------------------------------------------
# 4. test_replayed_hello_and_confirm_rejected  [V4]
# ---------------------------------------------------------------------------
def test_replayed_hello_and_confirm_rejected(node_b):
    key = Ed25519PrivateKey.generate()
    conn1, hello1, _, confirm1, sid1 = _raw_handshake(node_b, key)
    conn1.close()

    # Attacker without `key` replays the recorded Hello and Confirm.
    conn2 = transport.connect(*node_b.address)
    try:
        conn2.send(hello1)
        reply2 = conn2.recv()
        assert reply2["type"] == "hello"
        conn2.send(confirm1)
        assert conn2.recv() == {"type": "error", "reason": "bad_confirm"}
        _assert_closed(conn2)
    finally:
        conn2.close()
    assert node_b.received == []


# ---------------------------------------------------------------------------
# 5. test_cross_session_payload_rejected  [V5]
# ---------------------------------------------------------------------------
def test_cross_session_payload_rejected(node_b):
    key = Ed25519PrivateKey.generate()
    conn1, _, _, _, sid1 = _raw_handshake(node_b, key)
    old = _signed({"type": "payload", "session": sid1, "seq": 1, "body": "pay me"}, key)
    conn1.send(old)
    assert conn1.recv()["type"] == "ack"
    conn1.close()

    conn2, _, _, _, sid2 = _raw_handshake(node_b, key)
    try:
        assert sid2 != sid1
        conn2.send(old)
        assert conn2.recv() == {"type": "error", "reason": "bad_payload"}
        _assert_closed(conn2)
    finally:
        conn2.close()
    assert len(node_b.received) == 1


# ---------------------------------------------------------------------------
# 6. test_v010_hello_rejected  [V6]
# ---------------------------------------------------------------------------
def test_v010_hello_rejected(node_b):
    key = Ed25519PrivateKey.generate()
    conn = transport.connect(*node_b.address)
    try:
        conn.send(peer.make_hello(key, peer.new_nonce()))
        assert conn.recv() == {"type": "error", "reason": "bad_hello"}
    finally:
        conn.close()
    assert node_b.pins == {}


# ---------------------------------------------------------------------------
# 7. test_payload_accepted_and_acked  [V7]
# ---------------------------------------------------------------------------
def test_payload_accepted_and_acked(node_a, node_b):
    session = node_a.connect(node_b.address)
    try:
        ack1 = session.send({"msg": "test capsule"})
        ack2 = session.send([2])
        b_key = envelope_v2.did_key_decode(node_b.did)
        for ack, seq in ((ack1, 1), (ack2, 2)):
            assert set(ack) == {"type", "session", "seq", "ref", "signature"}
            assert ack["session"] == session.session_id and ack["seq"] == seq
            assert sign_v2.verify_capsule(ack, b_key)
        rec = node_b.received
        assert [r["body"] for r in rec] == [{"msg": "test capsule"}, [2]]
        assert ack1["ref"] == envelope_v2.sha256_hex(envelope_v2.canonical_bytes(rec[0]["capsule"]))
    finally:
        session.close()


# ---------------------------------------------------------------------------
# 8. test_pins_survive_restart  [V8]
# ---------------------------------------------------------------------------
def test_pins_survive_restart(tmp_path, node_a):
    pem, pin_file = tmp_path / "b.pem", tmp_path / "b.pins.sc.json"
    _write_pem(pem)

    b1 = peer_v2.Peer.from_pem(str(pem), PASS, pin_path=str(pin_file))
    b1.listen()
    try:
        node_a.connect(b1.address).close()
        assert _wait_for(lambda: node_a.did in b1.pins)
    finally:
        b1.close()

    assert record_v2.verify_record_file(str(pin_file), envelope_v2.did_key_decode(b1.did))
    assert not (tmp_path / "b.pins.sc.json.tmp").exists()

    b2 = peer_v2.Peer.from_pem(str(pem), PASS, pin_path=str(pin_file))
    assert b2.did == b1.did
    assert set(b2.pins) == {node_a.did}

    # Client side: A's address pin persists too.
    a_pem, a_pins = tmp_path / "a.pem", tmp_path / "a.pins.sc.json"
    _write_pem(a_pem)
    b2.listen()
    try:
        a1 = peer_v2.Peer.from_pem(str(a_pem), PASS, pin_path=str(a_pins), keepalive_interval=None)
        a1.connect(b2.address).close()
        a2 = peer_v2.Peer.from_pem(str(a_pem), PASS, pin_path=str(a_pins))
        assert a2.addresses == {"%s:%d" % b2.address: b2.did}
    finally:
        b2.close()


# ---------------------------------------------------------------------------
# 9. test_bad_pin_file_raises  [V9]
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("fault", ["tampered", "other_signer", "bad_shape", "other_owner", "not_json"])
def test_bad_pin_file_raises(tmp_path, fault):
    key, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    pin_file = tmp_path / "pins.sc.json"
    a_did = envelope_v2.did_key_encode(Ed25519PrivateKey.generate().public_key())
    store = pins.PinStore(str(pin_file), key)
    store.add(a_did)

    data = json.loads(pin_file.read_text())
    if fault == "tampered":
        data["dids"].append(envelope_v2.did_key_encode(other.public_key()))
        pin_file.write_text(json.dumps(data))
    elif fault == "other_signer":
        data.pop("signature")
        record_v2.save_signed_record(data, str(pin_file), other)
    elif fault == "bad_shape":
        data.pop("signature")
        data["dids"] = "not-a-list"
        record_v2.save_signed_record(data, str(pin_file), key)
    elif fault == "other_owner":
        data.pop("signature")
        data["owner"] = envelope_v2.did_key_encode(other.public_key())
        record_v2.save_signed_record(data, str(pin_file), key)
    else:
        pin_file.write_text("{not json")

    with pytest.raises(pins.PinStoreError):
        pins.PinStore(str(pin_file), key)
    with pytest.raises(pins.PinStoreError):
        peer_v2.Peer(private_key=key, pin_path=str(pin_file))


# ---------------------------------------------------------------------------
# 10. test_identity_from_pem  [V10]
# ---------------------------------------------------------------------------
def test_identity_from_pem(tmp_path):
    pem = tmp_path / "node.pem"
    key = _write_pem(pem)
    p1 = peer_v2.Peer.from_pem(str(pem), PASS)
    p2 = peer_v2.Peer.from_pem(str(pem), PASS)
    assert p1.did == p2.did == envelope_v2.did_key_encode(key.public_key())
    with pytest.raises(ValueError):
        peer_v2.Peer.from_pem(str(pem), "wrong passphrase")


# ---------------------------------------------------------------------------
# 11. test_address_key_change_refused  [V11]
# ---------------------------------------------------------------------------
def test_address_key_change_refused(node_a, node_b):
    impostor_did = envelope_v2.did_key_encode(Ed25519PrivateKey.generate().public_key())
    node_a.pin(impostor_did, address=node_b.address)
    with pytest.raises(peer_v2.HandshakeError, match="key changed"):
        node_a.connect(node_b.address)
    assert node_b.did not in node_a.pins
    time.sleep(0.1)
    assert node_a.did not in node_b.pins  # no Confirm was sent


# ---------------------------------------------------------------------------
# 12. test_pinned_trust_policy  [V12]
# ---------------------------------------------------------------------------
def test_pinned_trust_policy(node_b):
    strict_b = peer_v2.Peer(trust="pinned")
    strict_b.listen()
    a = peer_v2.Peer(keepalive_interval=None)
    try:
        with pytest.raises(peer_v2.HandshakeError, match="unknown_peer"):
            a.connect(strict_b.address)
        assert strict_b.pins == {}

        strict_b.pin(a.did)
        a.connect(strict_b.address).close()

        strict_a = peer_v2.Peer(trust="pinned", keepalive_interval=None)
        with pytest.raises(peer_v2.HandshakeError, match="unknown peer"):
            strict_a.connect(node_b.address)
        strict_a.pin(node_b.did)
        strict_a.connect(node_b.address).close()
    finally:
        strict_b.close()


# ---------------------------------------------------------------------------
# 13. test_keepalive_outlives_idle_timeout  [V13]
# ---------------------------------------------------------------------------
def test_keepalive_outlives_idle_timeout():
    b = peer_v2.Peer(idle_timeout=0.6)
    b.listen()
    alive = peer_v2.Peer(keepalive_interval=0.15)
    silent = peer_v2.Peer(keepalive_interval=None)
    try:
        s_alive = alive.connect(b.address)
        s_silent = silent.connect(b.address)
        time.sleep(1.5)

        assert s_alive.send("still here")["type"] == "ack"
        with pytest.raises(peer_v2.PayloadError):
            s_silent.send("too late")
        s_alive.close()
        s_silent.close()
    finally:
        b.close()


# ---------------------------------------------------------------------------
# 14. test_silent_handshake_times_out  [V14]
# ---------------------------------------------------------------------------
def test_silent_handshake_times_out():
    b = peer_v2.Peer(idle_timeout=0.3)
    b.listen()
    key = Ed25519PrivateKey.generate()
    conn = transport.connect(*b.address)
    try:
        conn.send(peer_v2.make_hello(key, peer_v2.new_nonce()))
        assert conn.recv()["type"] == "hello"
        time.sleep(0.8)  # never send Confirm
        _assert_closed(conn)
    finally:
        conn.close()
        b.close()
    assert b.pins == {}


# ---------------------------------------------------------------------------
# 15. test_bad_ping_rejected  [V15]
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("fault", ["wrong_seq", "wrong_session"])
def test_bad_ping_rejected(node_b, fault):
    key = Ed25519PrivateKey.generate()
    conn, _, _, _, sid = _raw_handshake(node_b, key)
    try:
        conn.send(_signed({"type": "ping", "session": sid, "seq": 1}, key))
        pong = conn.recv()
        assert set(pong) == {"type", "session", "seq", "signature"}
        assert pong["type"] == "pong" and pong["seq"] == 1 and pong["session"] == sid
        assert sign_v2.verify_capsule(pong, envelope_v2.did_key_decode(node_b.did))

        seq, session = (5, sid) if fault == "wrong_seq" else (2, _flip_hex(sid))
        conn.send(_signed({"type": "ping", "session": session, "seq": seq}, key))
        assert conn.recv() == {"type": "error", "reason": "bad_payload"}
        _assert_closed(conn)
    finally:
        conn.close()
