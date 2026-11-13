# CHANGELOG — SC-OS

CHANGELOG.md — Release history in Good / Bad / Ugly format, latest at top.

Function:
    One block per release. Every block has all three sections.

## 0.2.0 — 2026-11-13 — Replay-proof, persistent, long-lived

Pending James's sign-off. Tested on the laptop only.

**Good**

- SPEC_V2.md 0.2.0, written before the tests and code. Resolves NOTES Q1, Q2 and Q4.
- 3-way handshake (Hello, reply, Confirm). A recorded Hello and Confirm replayed on a new connection is rejected.
- Session id in every post-handshake capsule. A payload recorded in one session is rejected in another.
- `pins.py`: pins persist as a self-signed P7 record, are verified on load and fail closed. Writes are crash-safe.
- Address pins refuse a changed key; optional `trust="pinned"`; identity loads from PEM via P7.
- Signed Ping/Pong keepalive; B's idle timeout covers the handshake too.
- 45 tests pass (22 v0.1.0 unchanged + 23 v0.2.0), stable across repeated runs and from another directory.
- v0.1.0 files untouched; `transport.py` reused as is.

**Bad**

- Not yet run on the S24 (Termux).
- The test suite now takes about 9 s, because the keepalive and timeout tests sleep in real time.
- v0.1.0 and v0.2.0 nodes cannot talk to each other.

**Ugly**

- P7 has no "load verified record" call, so `pins.py` verifies twice to avoid reading a different file than the one checked (NOTES D1).

## 0.1.0 (scaffold) — 2026-11-13 — The Handshake

Scaffold release: the handshake only. SPEC.md and VERSION both stay at 0.1.0. v1.0.0 needs the criteria in NOTES.md ("Road to v1.0.0").

**Good**
- SPEC.md 0.1.0: framing, Hello exchange, in-memory key pinning, payload/ACK.
- `transport.py`: newline-delimited canonical JSON over stdlib TCP, threaded listener, 64 KiB frame cap.
- `peer.py`: signed Hello and reply (with nonce echo), pinning, signed payloads with seq, signed ACKs bound by sha256 ref.
- 22 tests (SPEC §8 T1–T9) pass on the laptop (Windows, Python 3.13) and the S24 (Termux), confirmed by James.
- SPEC 0.1.0 and the NOTES decisions P1–P6 signed off by James.
- Nothing reimplemented: all signing goes through P2 `sign_v2`, all did:key/hash/canonical bytes through P1 `envelope_v2`.

**Bad**
- No replay protection for A's Hello or payloads across connections (NOTES Q1).
- Pins are lost when the process exits.

**Ugly**
- The previous commit (`df820c1`) was titled "handshake v0.1.0 (tests pass)" but held only `.gitattributes`, `.gitignore` and `VERSION`. This release is the first one with code.
