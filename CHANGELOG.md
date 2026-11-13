# CHANGELOG — SC-OS

CHANGELOG.md — Release history in Good / Bad / Ugly format, latest at top.

Function:
    One block per release. Every block has all three sections.

## 0.1.0 — 2026-11-13 — The Handshake

**Good**
- SPEC.md 0.1.0: framing, Hello exchange, in-memory key pinning, payload/ACK.
- `transport.py`: newline-delimited canonical JSON over stdlib TCP, threaded listener, 64 KiB frame cap.
- `peer.py`: signed Hello and reply (with nonce echo), pinning, signed payloads with seq, signed ACKs bound by sha256 ref.
- 22 tests (SPEC §8 T1–T9) pass on the laptop (Windows, Python 3.13).
- Nothing reimplemented: all signing goes through P2 `sign_v2`, all did:key/hash/canonical bytes through P1 `envelope_v2`.

**Bad**
- No replay protection for A's Hello or payloads across connections (NOTES Q1).
- Pins are lost when the process exits.
- Not yet run on the S24 (Termux).

**Ugly**
- The previous commit (`df820c1`) was titled "handshake v0.1.0 (tests pass)" but held only `.gitattributes`, `.gitignore` and `VERSION`. This release is the first one with code.
