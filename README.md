# SC-OS — The Nervous System

README.md — What this repository is and how to run it.

Function:
    Introduces SC-OS, the Tier 1 Consumer of the Forge Stack that
    carries signed messages between nodes. It states what v0.1.0
    does, what it depends on and how to verify it.

SC-OS is the **Nervous System** of the Forge Stack. It moves signed capsules between nodes. It does not reimplement anything: crypto, canonicalisation and identity come from the frozen P1–P15 layers.

This repository replaces the old SC-OS monolith, which reimplemented crypto, storage and trust.

## v0.1.0 — The Handshake

- Newline-delimited JSON over TCP (`transport.py`).
- Two nodes exchange P2-signed Hello capsules carrying their `did:key`, verify them, and pin each other's key in memory (`peer.py`).
- After the handshake, node A sends signed payload capsules and node B returns signed ACKs.

The full rules are in [SPEC.md](SPEC.md).

## Dependencies

| Layer | Location |
| --- | --- |
| P1 Envelope v2.0.0 (`envelope_v2`) | `../envelope-layer` |
| P2 Sign v2.0.0 (`sign_v2`) | `../sign-layer` |

Clone the layer repos as siblings of this one. Runtime: Python 3 standard library plus `cryptography`. Tests: `pytest`.

## Usage

```python
from peer import Peer

b = Peer(); b.listen()            # 127.0.0.1, ephemeral port
a = Peer()
session = a.connect(b.address)    # Hello exchange; each side pins the other
ack = session.send({"msg": "hi"}) # signed payload -> verified, signed ACK
session.close(); b.close()
```

## Verify

```
python -m pytest -q    # 22 passed
```

Licence: MSL-1.0. Author: James Gilbert (Giblets Forge).
