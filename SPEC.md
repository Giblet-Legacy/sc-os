# SPEC — SC-OS Handshake (v0.1.0)

SPEC.md — Normative specification for the SC-OS peer handshake and TCP framing.

Function:
    Defines the wire format, message shapes, handshake sequence, key
    pinning rule and error behaviour for v0.1.0 of SC-OS (Tier 1:
    The Nervous System). Spec wins over code. Tests in `test_peer.py`
    map to §8.

| Field | Value |
| --- | --- |
| Version | 0.1.0 |
| Status | Signed off by James, 2026-11-13. Tested on laptop (Windows) and S24 (Termux) |
| Layer | Tier 1 Consumer — SC-OS, Handshake |
| Depends | P1 Envelope v2.0.0 (`envelope_v2`), P2 Sign v2.0.0 (`sign_v2`) |
| Licence | MSL-1.0 |
| Author | James Gilbert (Giblets Forge) |

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

---

## 1. Scope

In scope for v0.1.0:

- One TCP connection between two nodes, A (client, initiator) and B (server, responder).
- A mutual signed Hello exchange, after which each side has pinned the other's `did:key`.
- Signed capsules sent A → B after the handshake, each answered by a signed ACK.

Out of scope for v0.1.0. These are recorded in NOTES.md and are not to be built without a new SPEC version:

- Encryption. Traffic is signed, not confidential.
- Persistent pin storage. Pins live in memory and die with the process.
- Discovery, routing, gossip, multi-hop.
- Replay protection for payload capsules (see §7).
- B → A payloads. Only A sends payloads in v0.1.0.

## 2. Dependencies (consume, never reimplement)

SC-OS MUST NOT implement any cryptographic, canonicalisation or key-encoding primitive. All of these come from the frozen layers:

| Need | Source |
| --- | --- |
| Sign a capsule | P2 `sign_v2.sign_capsule` |
| Verify a capsule | P2 `sign_v2.verify_capsule` |
| `did:key` encode | P1 `envelope_v2.did_key_encode` |
| `did:key` decode → public key | P1 `envelope_v2.did_key_decode` |
| Canonical bytes (framing, ACK digest) | P1 `envelope_v2.canonical_bytes` |
| SHA-256 (ACK reference) | P1 `envelope_v2.sha256_hex` |

The layers are imported from sibling directories (`../envelope-layer`, `../sign-layer`), located from the importing file, not the working directory. SC-OS does not copy `envelope.py`, `sign.py` or any other layer file into this repository.

Capsule signing follows P2's capsule rule unchanged: a signed capsule carries `"signature": {"algorithm": "Ed25519", "key_id": <did:key>, "value": <128 lowercase hex>}`.

## 3. Transport and framing (`transport.py`)

### 3.1 Socket

- TCP over IPv4 via the standard library `socket` module.
- The server binds, listens, and handles each accepted connection on its own `threading` thread.
- Binding to port `0` MUST be supported; the bound address is then readable from the listener.
- Every connected socket SHOULD carry a timeout (default 5 seconds) so a silent peer cannot hang a thread forever.

### 3.2 Frame

A frame is one JSON object serialised as P1 canonical bytes followed by a single `\n` (0x0A).

- P1 canonical bytes are pure ASCII and JSON escapes every control character, so a canonical frame never contains a raw `\n`. The newline is an unambiguous delimiter.
- A sender MUST emit canonical bytes (`envelope_v2.canonical_bytes`).
- A receiver MUST accept any valid UTF-8 JSON object on a line. It MUST NOT require the received bytes to be canonical. Signature checks re-canonicalise, so non-canonical whitespace cannot change a verify result.

### 3.3 Frame limits and errors

- Maximum frame length: 65 536 bytes including the `\n`. A longer line is a `FrameError`.
- A line that is not valid UTF-8 JSON, or whose top-level value is not an object, is a `FrameError`.
- The bare tokens `NaN`, `Infinity` and `-Infinity` are a `FrameError`, because P1 v2 gives them no canonical form.
- A clean EOF before any byte of a frame is read is not an error. `recv_frame` returns `None`.
- EOF in the middle of a frame (bytes without the terminating `\n`) is a `FrameError`.

## 4. Message shapes

Every message below except `error` is a P2-signed capsule. Field values are exact; unknown extra fields MUST cause rejection in v0.1.0.

### 4.1 Hello (A → B)

```json
{
  "type": "hello",
  "protocol": "sc-os/0.1.0",
  "did": "<A's did:key>",
  "nonce": "<32 lowercase hex chars, fresh per connection>",
  "signature": { ... }
}
```

### 4.2 Hello reply (B → A)

Same as §4.1 with B's `did` and nonce, plus:

```json
  "reply_to": "<A's nonce, echoed>"
```

The echo binds B's reply to this connection, so a recorded reply from B cannot be replayed to A on a later connection.

### 4.3 Payload (A → B)

```json
{
  "type": "payload",
  "seq": <int, starting at 1, +1 per payload on this connection>,
  "body": <any JSON value>,
  "signature": { ... }
}
```

### 4.4 ACK (B → A)

```json
{
  "type": "ack",
  "seq": <the payload's seq>,
  "ref": "<sha256_hex of the payload's canonical bytes, signature included>",
  "signature": { ... }
}
```

### 4.5 Error (either direction, unsigned)

```json
{ "type": "error", "reason": "<short machine-readable code>" }
```

An error frame is advisory only. The sender closes the connection right after sending it. Reason codes for v0.1.0: `bad_hello`, `bad_payload`, `bad_frame`.

## 5. Handshake sequence

```
A                                         B
| -- connect ---------------------------> |
| -- Hello(did_A, nonce_A) -------------> |  B verifies (§6), pins did_A
| <-------- Hello(did_B, nonce_B, nonce_A) |  A verifies (§6), checks reply_to, pins did_B
| -- Payload(seq=1, body) --------------> |  B verifies against pinned did_A
| <-------------------- ACK(seq=1, ref)   |  A verifies against pinned did_B, checks seq and ref
| -- ... further payloads ... ----------> |
| -- close ----------------------------->  |
```

- B MUST NOT send anything before it has received and verified A's Hello.
- B MUST pin `did_A` before sending its reply. A MUST pin `did_B` before sending any payload.
- Any check failure on either side ends the connection. B sends the matching `error` frame before closing. A raises to its caller and closes.

## 6. Hello verification and key pinning

A received Hello is valid only if every check below passes, in this order:

1. It is a dict whose key set is exactly the §4.1 set (plus `reply_to` for a reply).
2. `type == "hello"` and `protocol == "sc-os/0.1.0"`.
3. `nonce` (and `reply_to`, if present) is exactly 32 lowercase hex characters.
4. `did` is a string that `envelope_v2.did_key_decode` accepts. Any exception raised by the decode is a failure.
5. `sign_v2.verify_capsule(hello, decoded_key)` returns True. P2 checks that `signature.key_id == did`, so a Hello cannot claim one identity while being signed by another key.
6. For a reply only: `reply_to` equals the nonce this side sent.

On success the receiver **pins** `did → public key` in an in-memory table owned by its Peer object. A `did:key` is the public key itself, so a pin cannot conflict with an earlier pin of the same did. Pinning records "this key completed a handshake with me". After the handshake every capsule on the connection MUST verify against the key pinned for that connection, and no other key.

A failed Hello pins nothing.

## 7. Payload and ACK verification

B accepts a payload only if:

1. Its key set is exactly `{type, seq, body, signature}` and `type == "payload"`.
2. `seq` is an int (not bool) equal to the previous accepted seq on this connection + 1, starting at 1.
3. `sign_v2.verify_capsule(payload, pinned_key_A)` returns True.

B then records the payload and replies with the §4.4 ACK. On any failure B sends `error: bad_payload` and closes.

A accepts an ACK only if its key set is exactly `{type, seq, ref, signature}`, `type == "ack"`, `seq` matches the payload just sent, `ref` equals `sha256_hex(canonical_bytes(sent_payload))`, and it verifies against `pinned_key_B`.

The per-connection `seq` blocks reordering and in-connection replay. It does not stop a recorded payload being replayed on a new connection by an attacker who also replays A's Hello. A's Hello carries no challenge from B in v0.1.0. This is a known gap (NOTES Q1).

## 8. Tests (`test_peer.py`)

| ID | Requirement | Spec |
| --- | --- | --- |
| T1 | A listener binds port 0, reports a real port, and accepts a plain TCP connect | §3.1 |
| T2 | A frame round-trips; oversize, non-object, non-finite and truncated frames raise `FrameError`; clean EOF returns `None` | §3.2, §3.3 |
| T3 | Two Peers exchange Hellos; each pins the other's did | §5, §6 |
| T4 | A forged Hello (tampered signature) is rejected: B sends `error: bad_hello`, closes, pins nothing | §6.5 |
| T5 | A Hello with a tampered body, a did that does not match the signing key, or an extra field is rejected | §6.1, §6.5 |
| T6 | A rejects a forged Hello reply, or a reply with the wrong `reply_to` | §6.5, §6.6 |
| T7 | A payload sent after the handshake is accepted, recorded by B, and ACKed with a verified ACK whose `ref` matches | §7 |
| T8 | A payload signed by a key other than the pinned one is rejected | §7.3 |
| T9 | A payload sent with no prior Hello is rejected as `bad_hello` | §5 |

## Document control

| Version | Date | Change |
| --- | --- | --- |
| 0.1.0 | 2026-11-13 | First draft: handshake, framing, pinning, payload/ACK |
| 0.1.0 | 2026-11-13 | Signed off by James after passing on laptop and S24. Status line only, no rule changes |
