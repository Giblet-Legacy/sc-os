# NOTES — SC-OS

NOTES.md — Decisions, open questions (Q) and divergences for SC-OS.

Function:
    Records what was decided while building, what is still open and
    who owns it, so nothing is silently assumed. Decisions made by the
    AI are proposals pending James's sign-off.

## Decisions (v0.1.0) — proposed by the VS Code AI, signed off by James 2026-11-13

Tested and confirmed by James on the laptop (Windows) and the S24 (Termux).

- **P1 — Consume `sign_v2`, not `sign`.** The brief names P2 `sign` / `sign_capsule`. sign-layer's own CLAUDE.md says new code imports `sign_v2` (strict, locates P1 from its own file). `sign_v2.sign_capsule` *is* v1's `sign_capsule`, re-exported, so the signing behaviour the brief asks for is unchanged.
- **P2 — Hello reply echoes A's nonce (`reply_to`).** Not in the brief. It costs one field and stops a recorded B reply being replayed to A.
- **P3 — Payloads carry a per-connection `seq`; ACKs carry `ref` = sha256 of the payload's canonical bytes.** This binds each ACK to exactly one payload.
- **P4 — Strict field sets.** Unknown fields reject a Hello, payload or ACK in v0.1.0. They can be relaxed in a later SPEC version; tightening later would be harder.
- **P5 — 64 KiB frame cap, 5 s socket timeout.** A server-side session idle for more than 5 s is closed.
- **P6 — VERSION set to 0.1.0.** No git tag created.

## Decisions (v0.2.0) — proposed by the VS Code AI, pending James's sign-off

- **P7 — v0.2.0 is a new layer, not an edit.** `peer_v2.py` + `pins.py` + `SPEC_V2.md` sit above the frozen v0.1.0 files. `transport.py` is reused unchanged. v0.1.0 and v0.2.0 nodes do not interoperate (no downgrade path).
- **P8 — Session id** = `sha256_hex(canonical_bytes({"a": nA, "b": nB}))`, carried in every post-handshake capsule. Without it, a payload recorded in one session could be injected into a later session of the same A.
- **P9 — Address pins (`known_hosts` semantics) plus `trust="tofu"|"pinned"`.** v0.1.0 pins recorded keys but never refused one. Address pins are what make a persisted pin do something.
- **P10 — The pin store is self-signed by the node's own key.** The node identity must therefore be stable; it is loaded from PEM via P7. A bad pin file stops the node from starting (fail closed).
- **P11 — Crash-safe writes.** P7 writes `<pin_path>.tmp`, then `os.replace` moves it over the old file.
- **P12 — Keepalive defaults:** ping after 10 s idle; B's idle timeout 30 s. Pings share the payload seq counter.
- **P13 — A learns of a rejected Confirm on its first `send`.** There is no 4th handshake message; `send` then raises `PayloadError: bad_confirm`.

## Divergences / gaps in consumed layers

| ID | Gap | Handling in SC-OS | Owner |
| --- | --- | --- | --- |
| D1 | P7 `record_v2` has no "load verified record" call. `verify_record_file` returns only a bool, so a caller must read the file again and could see a different file than the one checked. | `pins.py` calls P7 verify, reads once, then re-verifies the parsed dict with P2 `sign_v2.verify_capsule`. Proper fix: a P7 v3 `load_record` returning the verified dict. | James |
| D2 | P7 has no "save key to PEM" call. | Key creation is out of scope for SC-OS. Tests create PEM files with `cryptography` directly, as fixtures only. | James |

## Open questions

| ID | Question | Owner |
| --- | --- | --- |
| Q5 | Should a P7 v3 add `load_record` (D1) and key creation (D2)? | James |
| Q6 | Address pins match the literal `"host:port"` string, so `localhost` and `127.0.0.1` are different addresses. Normalise in v0.3.0, or leave as is? | James |
| Q7 | Sign off SPEC_V3 0.3.0 (Nerves reader, `$FORGE_HOME/sc-os/pins.sc.json`)? Built and green on the laptop (51/51); not yet run on the S24. **Resolved 2026-11-13 — James: "freeze all".** S24: confirmed on the S24 by James, 2026-11-13. | James |

## Resolved questions

| ID | Question | Resolution (decided by James, 2026-11-13) |
| --- | --- | --- |
| Q1 | B issues no challenge to A, so a recorded A Hello plus recorded payloads can be replayed to B on a new connection. Add a B→A challenge (3-way handshake) in v0.2.0? | **Yes, v0.2.0.** It is the right next layer above v0.1.0. |
| Q2 | Which P-layer owns persistent pin storage when pins leave memory? | **P7 Record** (`../record-layer`, `record_v2` 2.0.0). P7 already handles passphrase-protected PEM keys and disk I/O. Pins are the same kind of thing: cryptographic material that needs safe persistence. SC-OS does not hand-roll pin storage. |
| Q3 | The brief says to import `weight.py` from `../envelope-layer`. It is not there (there is a `../weight-layer`), and v0.1.0 does not need it. Confirm which layer SC-OS should consume when weights arrive. | **Deferred.** Consume the weight layer in v0.2.0 if, and only when, SC-OS actually needs trust scoring (rule engine, learning). Not before. |
| Q4 | Should idle sessions get a keepalive rather than the 5 s timeout? | **Keepalive is a new SPEC item for v0.2.0.** The 5 s timeout stays for v0.1.0, which is tested in a controlled environment. |

## v0.2.0 scope (from Q1–Q4)

Spec first (SPEC.md 0.2.0), then tests, then code:

1. 3-way handshake: B challenges A, so A's Hello cannot be replayed (Q1).
2. Persistent pins through P7 Record `record_v2`; add P7 to the dependency table (Q2).
3. Keepalive frame and idle-timeout rules (Q4).
4. Weight layer only if trust scoring is needed in this version (Q3).

## Road to v1.0.0 (decided by James, 2026-11-13)

SPEC.md and VERSION stay together at 0.x until SC-OS has all of:

1. A real rule engine
2. Persistent pins (via P7, Q2)
3. The edge gateway
4. Multi-node tests

v0.1.0 is the handshake scaffold. The version number states that honestly.
