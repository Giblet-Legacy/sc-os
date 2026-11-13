# NOTES — SC-OS

NOTES.md — Decisions, open questions (Q) and divergences for SC-OS.

Function:
    Records what was decided while building, what is still open and
    who owns it, so nothing is silently assumed. Decisions made by the
    AI are proposals pending James's sign-off.

## Proposed decisions (v0.1.0) — pending James's sign-off

- **P1 — Consume `sign_v2`, not `sign`.** The brief names P2 `sign` / `sign_capsule`. sign-layer's own CLAUDE.md says new code imports `sign_v2` (strict, locates P1 from its own file). `sign_v2.sign_capsule` *is* v1's `sign_capsule`, re-exported, so the signing behaviour the brief asks for is unchanged.
- **P2 — Hello reply echoes A's nonce (`reply_to`).** Not in the brief. It costs one field and stops a recorded B reply being replayed to A.
- **P3 — Payloads carry a per-connection `seq`; ACKs carry `ref` = sha256 of the payload's canonical bytes.** This binds each ACK to exactly one payload.
- **P4 — Strict field sets.** Unknown fields reject a Hello, payload or ACK in v0.1.0. They can be relaxed in a later SPEC version; tightening later would be harder.
- **P5 — 64 KiB frame cap, 5 s socket timeout.** A server-side session idle for more than 5 s is closed.
- **P6 — VERSION set to 0.1.0.** No git tag created.

## Open questions

| ID | Question | Owner |
| --- | --- | --- |
| Q1 | B issues no challenge to A, so a recorded A Hello plus recorded payloads can be replayed to B on a new connection. Add a B→A challenge (3-way handshake) in v0.2.0? | James |
| Q2 | Which P-layer owns persistent pin storage when pins leave memory? | James |
| Q3 | The brief says to import `weight.py` from `../envelope-layer`. It is not there (there is a `../weight-layer`), and v0.1.0 does not need it. Confirm which layer and version SC-OS should consume when weights arrive. | James |
| Q4 | Should idle sessions get a keepalive rather than the 5 s timeout? | James |
