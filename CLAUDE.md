# Forge Stack Context — SC-OS (Tier 1: The Nervous System)

CLAUDE.md — Context briefing for AI assistants working in this repository.

Function:
    Instructs the AI assistant on the strict architectural rules of the
    Forge Stack and the current state of SC-OS. SC-OS is a Tier 1
    Consumer: it consumes the frozen P1–P15 layers and never
    reimplements them. Do not hallucinate external frameworks. Reason
    strictly within these boundaries.

## The Immutable Rule

Never rewrite a primitive. Add a layer.

- P1–P15 are frozen. SC-OS imports them; it never copies, patches, wraps-to-replace or re-derives them. No crypto, canonicalisation, did:key, hashing, storage or trust logic is written here.
- If a layer looks wrong, record it in NOTES.md with an owner. The fix is a new version of *that* layer, in *its* repo. Never a workaround here.
- Do not write `envelope.py`, `sign.py`, `weight.py` or any other layer file in this repo. Import from the sibling directory (`../envelope-layer`, `../sign-layer`, …).
- Import the current layer version. Today that is `envelope_v2` (P1 v2.0.0) and `sign_v2` (P2 v2.0.0), not `envelope` or `sign`.
- Locate sibling layers from `__file__`, never from the working directory.
- The old SC-OS monolith reimplemented crypto, storage and trust. That is exactly what this rebuild exists to stop.

## Strict adherence to P1–P15

| Layer | Repo | Used by SC-OS v0.1.0 |
| --- | --- | --- |
| P1 Envelope | `../envelope-layer` (`envelope_v2`) | did:key encode/decode, canonical bytes, sha256 |
| P2 Sign | `../sign-layer` (`sign_v2`) | `sign_capsule`, `verify_capsule` |
| P7 Record | `../record-layer` (`record_v2`) | v0.2.0: PEM identity, signed pin store on disk |
| Others in P3–P15 | sibling repos | Not yet. Add one only through a new SPEC version |

## SC-OS layers

- v0.1.0 (`SPEC.md`, `peer.py`, `transport.py`, `test_peer.py`) is signed off and **frozen**. Do not edit it.
- v0.2.0 (`SPEC_V2.md`, `peer_v2.py`, `pins.py`, `test_peer_v2.py`) is the current layer. New code imports `peer_v2`.

A new dependency on any layer is a SPEC change first.

## Spec → tests → code

A change is specified first (SPEC.md, new version), then tested (`test_peer.py`), then implemented. Never code-first. Spec wins over code.

## Header Discipline

Every file MUST have a top header paragraph explaining its function.
Every function, method and class MUST have a numbered header (e.g., `# 1. make_hello`), and the file header lists them by number.

- Python files: docstring with Function, numbered API list, Layer, Depends, Spec, Version, Licence, Author.
- Config files (`.gitignore`, `requirements.txt`, `VERSION`): `#` comment header.
- Tests: numbered headers, each mapped to a SPEC §8 ID.

## Constraints

- Standard library only, plus `cryptography` (via P1) and `pytest` (tests).
- Transport is stdlib `socket` + `threading`. No asyncio frameworks, no third-party networking.
- Never log or print private keys. Keys are passed as arguments.
- Pins are in memory only in v0.1.0. Persistent pins are a later layer (likely via a storage layer from P1–P15, not hand-rolled).

## Dual-Device Workflow

We build on an S24 (Termux) and a laptop (VS Code). State is confirmed, never assumed. Always use LF line endings. AI on VS Code is a co-worker, not the author. Commit messages must be clear. CHANGELOG is Good/Bad/Ugly, latest at top.

- Decisions the AI makes are recorded as "Proposed … pending James's sign-off" unless James explicitly delegates.
- Laptop is Windows: use `python`, not `python3`. Termux uses `python3`.
- Do not commit, tag or push unless asked.

## Repository map

| Path | Role |
| --- | --- |
| `SPEC.md` | Handshake spec v0.1.0 (frozen). Spec wins over code |
| `transport.py` | TCP framing (newline-delimited canonical JSON) + threaded listener (frozen) |
| `peer.py` | v0.1.0 Hello exchange, in-memory pinning, payload/ACK (frozen) |
| `test_peer.py` | SPEC §8 tests (T1–T9) (frozen) |
| `SPEC_V2.md` | v0.2.0 deltas: 3-way handshake, P7 pins, trust policy, keepalive |
| `peer_v2.py` | v0.2.0 Peer/Session (current layer) |
| `pins.py` | Pin store persisted as a P7 signed record |
| `test_peer_v2.py` | SPEC_V2 §9 tests (V1–V15) |
| `conftest.py` | Puts this dir and sibling layers on `sys.path` |
| `NOTES.md` | Open questions (Q) and decisions |
| `CHANGELOG.md` | Good / Bad / Ugly, latest at top |
| `VERSION` | Current release version |

## Verify before claiming anything works

1. `python -m pytest -q` (from repo root) → 45 passed (22 v0.1.0 + 23 v0.2.0), about 9 s
2. The layers it consumes are still green: `../envelope-layer` 113 passed, `../sign-layer` 23 passed, `../record-layer` (v1 + v2)
3. `git ls-files --eol` → every file `i/lf`
