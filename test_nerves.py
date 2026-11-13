"""
test_nerves.py — SC-OS v0.3.0 Nerves reader tests (SPEC_V3 §3, N1–N6)

Function:
    Executable expression of SPEC_V3.md. Written before nerves.py and
    run red first. Pin files are written by the real v0.2.0 PinStore.

Functions in this file (pytest-collected):
    1. test_n1_reads_peers
    2. test_n2_missing
    3. test_n3_bad_files
    4. test_n4_owner_anchor
    5. test_n5_read_only
    6. test_n6_default_path

Helpers:
    7. _pinned — a pin file with two peers, one address-pinned

Layer:    Tier 1 Consumer — SC-OS, Nerves v0.3.0
Spec:     SPEC_V3.md 0.3.0
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import json
import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import envelope_v2
import nerves
import pins
import sign_v2


# 7. _pinned
def _pinned(tmp_path):
    key = Ed25519PrivateKey.generate()
    path = str(tmp_path / "pins.sc.json")
    a = envelope_v2.did_key_encode(Ed25519PrivateKey.generate().public_key())
    b = envelope_v2.did_key_encode(Ed25519PrivateKey.generate().public_key())
    store = pins.PinStore(path, key)
    store.add(a, "127.0.0.1:9001")
    store.add(b)
    return path, key, a, b


# 1. test_n1_reads_peers
def test_n1_reads_peers(tmp_path):
    path, key, a, b = _pinned(tmp_path)
    out = nerves.read_nerves(path)
    assert out["owner"] == envelope_v2.did_key_encode(key.public_key())
    assert out["peers"] == sorted([a, b]) and out["peer_count"] == 2
    assert out["addresses"] == {"127.0.0.1:9001": a} and out["owner_pinned"] is False


# 2. test_n2_missing
def test_n2_missing(tmp_path):
    assert nerves.read_nerves(str(tmp_path / "absent.sc.json")) is None


# 3. test_n3_bad_files
def test_n3_bad_files(tmp_path):
    path, key, a, _ = _pinned(tmp_path)
    good = open(path, "rb").read()
    open(path, "wb").write(good.replace(b"9001", b"9002"))
    with pytest.raises(pins.PinStoreError):
        nerves.read_nerves(path)
    record = json.loads(good)
    other = Ed25519PrivateKey.generate()
    forged = sign_v2.sign_capsule(dict(record, signature=None), other)
    open(path, "w", encoding="utf-8").write(json.dumps(forged))
    with pytest.raises(pins.PinStoreError):
        nerves.read_nerves(path)
    extra = sign_v2.sign_capsule(dict(record, signature=None, extra=1), key)
    open(path, "w", encoding="utf-8").write(json.dumps(extra))
    with pytest.raises(pins.PinStoreError):
        nerves.read_nerves(path)
    open(path, "w", encoding="utf-8").write("not json")
    with pytest.raises(pins.PinStoreError):
        nerves.read_nerves(path)


# 4. test_n4_owner_anchor
def test_n4_owner_anchor(tmp_path):
    path, key, _, _ = _pinned(tmp_path)
    me = envelope_v2.did_key_encode(key.public_key())
    assert nerves.read_nerves(path, owner_did=me)["owner_pinned"] is True
    stranger = envelope_v2.did_key_encode(Ed25519PrivateKey.generate().public_key())
    with pytest.raises(pins.PinStoreError):
        nerves.read_nerves(path, owner_did=stranger)


# 5. test_n5_read_only
def test_n5_read_only(tmp_path):
    path, _, _, _ = _pinned(tmp_path)
    before = open(path, "rb").read()
    nerves.read_nerves(path)
    assert open(path, "rb").read() == before


# 6. test_n6_default_path
def test_n6_default_path(tmp_path):
    assert nerves.default_pin_path({"FORGE_HOME": str(tmp_path)}) == os.path.join(str(tmp_path), "sc-os", "pins.sc.json")
    assert nerves.default_pin_path({}).endswith(os.path.join(".forge", "sc-os", "pins.sc.json"))
