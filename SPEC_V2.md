# SPEC_V2 — SC-OS Handshake v0.2.0

SPEC_V2.md — Normative specification for the SC-OS v0.2.0 layer: 3-way handshake, persistent pins, keepalive.

Function:
    Defines what `peer_v2.py` and `pins.py` add above the signed-off
    v0.1.0 layer (SPEC.md). Lists only deltas: anything not stated
    here (framing, frame limits, error frame shape, P2 capsule rule)
    is exactly SPEC.md 0.1.0. Spec wins over code. Tests in
    `test_peer_v2.py` map to §9.

| Field | Value |
| --- | --- |
| Version | 0.2.0 |
| Status | Signed off by James, 2026-11-13. 45/45 on laptop and S24 (VERSION, CHANGELOG v0.2.0) |
| Layer | Tier 1 Consumer — SC-OS, Handshake v2 |
| Over | SPEC.md 0.1.0 (frozen; `peer.py`, `transport.py` unchanged) |
| Depends | P1 `envelope_v2` 2.0.0, P2 `sign_v2` 2.0.0, P7 `record_v2` 2.0.0 |
| Licence | MSL-1.0 |
| Author | James Gilbert (Giblets Forge) |

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

---

## 1. Relationship to v0.1.0

- `SPEC.md`, `peer.py`, `transport.py` and `test_peer.py` are frozen at 0.1.0 and are not edited. Their 22 tests MUST still pass.
- `peer_v2.py` is a new layer. It reuses `transport.py` for every byte on the wire and reuses `peer.py`'s nonce, verify and error helpers. It does not reimplement them.
- v0.2.0 and v0.1.0 do **not** interoperate. A v0.2.0 node rejects a `sc-os/0.1.0` Hello as `bad_hello`, and a v0.1.0 node does the same in reverse. There is no downgrade path.

This version resolves NOTES Q1 (3-way handshake), Q2 (persistent pins via P7) and Q4 (keepalive).

## 2. Dependencies (additions)

| Need | Source |
| --- | --- |
| Load a node identity from passphrase-protected PEM | P7 `record_v2.load_private_key` |
| Write the signed pin store to disk | P7 `record_v2.save_signed_record` |
| Verify the pin store on disk | P7 `record_v2.verify_record_file` |

P7 is located from the importing file (`../record-layer`). SC-OS does not write keys to disk and does not write its own record format. Key creation is out of scope.

## 3. Protocol identifier

`protocol` is `"sc-os/0.2.0"` in every Hello and Confirm.

## 4. Message shapes (deltas over SPEC.md §4)

All messages except `error` are P2-signed capsules. Key sets are exact; any extra or missing field is a rejection.

| Message | Direction | Fields (besides `signature`) |
| --- | --- | --- |
| Hello | A → B | `type="hello"`, `protocol`, `did`, `nonce` |
| Hello reply | B → A | as Hello, plus `reply_to` = A's nonce |
| **Confirm** | A → B | `type="confirm"`, `protocol`, `did` (A's), `reply_to` = B's nonce |
| Payload | A → B | `type="payload"`, `session`, `seq`, `body` |
| ACK | B → A | `type="ack"`, `session`, `seq`, `ref` |
| **Ping** | A → B | `type="ping"`, `session`, `seq` |
| **Pong** | B → A | `type="pong"`, `session`, `seq` |
| Error | either | `type="error"`, `reason` (unsigned, advisory) |

`nonce` and `reply_to` are 32 lowercase hex characters, as in v0.1.0.

**Session id.** Both sides compute `session = sha256_hex(canonical_bytes({"a": nonce_A, "b": nonce_B}))` using P1. Every post-handshake capsule carries it. It binds the capsule to this one connection.

**seq.** Payloads and Pings share one counter on A, starting at 1 and incrementing by 1 per message. B accepts only `seq == previous + 1`. ACK and Pong echo the seq they answer.

**ref.** As in v0.1.0: `sha256_hex(canonical_bytes(payload))`, signature included.

Error reasons for v0.2.0: `bad_frame`, `bad_hello`, `bad_confirm`, `unknown_peer`, `bad_payload`.

## 5. 3-way handshake (resolves Q1)

```text
A                                              B
| -- Hello(did_A, nA) -----------------------> |  §6.1 checks; trust check (§7.3)
| <------------------ Hello(did_B, nB, nA)     |  B has NOT pinned A yet
|  §6.1 checks, reply_to == nA,                 |
|  address check + trust check (§7.3, §7.4)     |
| -- Confirm(did_A, reply_to=nB) ------------> |  §6.2 checks; B pins did_A
|  A pins did_B (and the address)               |
| -- Payload / Ping (session, seq) ----------> |
| <---------------------- ACK / Pong (session)  |
```

- B MUST NOT pin A, or accept any post-handshake message, until a valid Confirm arrives.
- A pins B only after its Confirm has been sent.
- A replayed Hello from A gets a reply with a fresh `nB`. Without A's private key the attacker cannot sign a Confirm for that `nB`, so the handshake fails and nothing is pinned. A Confirm recorded on an earlier connection names an old `nB` and fails §6.2.
- Payloads and Pings recorded on an earlier connection carry an old `session` and fail §8.

## 6. Handshake checks

### 6.1 Hello and Hello reply

The checks in SPEC.md §6, steps 1–6, unchanged, except `protocol` MUST be `"sc-os/0.2.0"`.

### 6.2 Confirm (B)

1. Key set is exactly `{type, protocol, did, reply_to, signature}`, `type == "confirm"`, `protocol == "sc-os/0.2.0"`.
2. `did` equals the did from this connection's Hello.
3. `reply_to` equals the nonce B sent in its reply on this connection.
4. `sign_v2.verify_capsule(confirm, key_A)` is True.

Any failure: B sends `error: bad_confirm` and closes. Nothing is pinned.

## 7. Pins (resolves Q2)

### 7.1 What is pinned

A node's pin table has two parts:

- **dids**: the set of `did:key`s that have completed a handshake with this node, or were pinned by hand. The public key is the did, decoded by P1.
- **addresses** (client side): `"host:port"` → the did that answered there. This is SSH `known_hosts` semantics: once an address is pinned, a different key at that address is refused.

Every did named in `addresses` MUST also be in `dids`.

### 7.2 Persistence through P7

If a Peer is given a `pin_path`, its pins are persisted as a P7 signed record:

```json
{
  "type": "sc-os/pins",
  "version": "0.2.0",
  "owner": "<this node's did:key>",
  "dids": ["<did>", ...],
  "addresses": {"host:port": "<did>", ...},
  "signature": { ... }
}
```

- The record is signed by the node's own key, so the node's identity MUST be stable across restarts. In practice it is loaded from PEM via P7 (§2).
- **Write**: `record_v2.save_signed_record` writes to `<pin_path>.tmp`. That file is then moved over `<pin_path>` with `os.replace`. A crash mid-write therefore leaves the previous good file. `dids` is written sorted. A write happens after every new pin.
- **Load** (at Peer construction):
  - A missing file means empty pins.
  - An existing file MUST pass `record_v2.verify_record_file(path, own_public_key)`. It is then read once, and the parsed dict MUST pass `sign_v2.verify_capsule` again. This closes the gap between check and read, because P7 v2 has no "load verified record" call (NOTES D1).
  - The record MUST then have exactly the shape above, `owner` MUST equal this node's did, and every did MUST decode through P1.
  - Any failure raises `PinStoreError`, and the Peer does not start. Pins are never silently dropped (fail closed).
- With no `pin_path`, pins are in memory only (v0.1.0 behaviour).

### 7.3 Trust policy

`trust` is `"tofu"` (default) or `"pinned"`.

- `tofu`: any peer that completes the handshake is pinned.
- `pinned`: B refuses a Hello whose did is not already pinned (`error: unknown_peer`, sent before B's reply). A raises `HandshakeError` if B's did is not already pinned, and sends no Confirm.
- `Peer.pin(did, address=None)` pins a did (and optionally an address) by hand. This is how a `pinned` node is introduced to its peers.

### 7.4 Address check (A, always)

Before sending Confirm, if `"host:port"` of the connected address is pinned to a different did, A MUST raise `HandshakeError` (key changed) and send no Confirm. This applies in both trust modes.

## 8. Post-handshake and keepalive (resolves Q4)

### 8.1 B

B accepts a message only if its key set is exact for its type (§4), `session` matches, `seq == previous + 1`, and it verifies against the key pinned for this connection.

- On a valid Payload, B records it and replies with an ACK.
- On a valid Ping, B replies with a Pong.
- Anything else gets `error: bad_payload` and the connection closes.

### 8.2 Idle timeout

B closes any connection that sends nothing for `idle_timeout` seconds (default 30), in any state, including mid-handshake. Silent clients therefore cannot hold threads open.

### 8.3 Keepalive

If `keepalive_interval` (default 10 s) is set, A's Session runs a background thread. Whenever nothing has been sent for `keepalive_interval`, the thread sends a Ping and verifies the Pong: exact keys, `session`, echoed `seq`, and a valid signature from B's pinned key. The thread checks for idleness every `keepalive_interval / 4`. The worst-case gap B sees is therefore about 1.25 × `keepalive_interval`. Operators SHOULD set B's `idle_timeout` to at least 2 × A's `keepalive_interval`.

Ping/Pong and Payload/ACK exchanges never interleave: one exchange is in flight per Session at a time. If a keepalive exchange fails, the Session becomes dead. The next `send` raises `PayloadError` with the reason.

`keepalive_interval=None` disables keepalive. B then times the session out after `idle_timeout`.

## 9. Tests (`test_peer_v2.py`)

| ID | Requirement | Spec |
| --- | --- | --- |
| V1 | Two v2 Peers complete the 3-way handshake; both pin; both agree on the session id | §5 |
| V2 | B has not pinned A after Hello/reply, before Confirm | §5 |
| V3 | A Confirm that has the wrong `reply_to`, is signed by another key, names another did, or has an extra field is rejected (`bad_confirm`) | §6.2 |
| V4 | A recorded Hello + Confirm replayed on a new connection is rejected (`bad_confirm`), and no payload is accepted | §5 |
| V5 | A payload recorded in session 1 is rejected in session 2 (`bad_payload`) | §4, §8.1 |
| V6 | A v0.1.0 Hello is rejected by a v0.2.0 node (`bad_hello`) | §1, §3 |
| V7 | Payload is accepted and ACKed with session, seq, ref and a verified signature | §8.1 |
| V8 | Pins survive a restart: same PEM key + pin file → same pins; the file verifies through P7 | §7.2 |
| V9 | A tampered pin file, one signed by another key, or one with a bad shape raises `PinStoreError` | §7.2 |
| V10 | Identity loads from passphrase-protected PEM through P7; the did is stable | §2 |
| V11 | A refuses an address pinned to another did (key changed), and sends no Confirm | §7.4 |
| V12 | `pinned` trust: B refuses an unknown A (`unknown_peer`) and accepts once A is pinned; A refuses an unknown B | §7.3 |
| V13 | With keepalive, a session outlives B's idle timeout; without it, B closes it and `send` raises `PayloadError` | §8.2, §8.3 |
| V14 | B closes a connection that goes silent mid-handshake | §8.2 |
| V15 | A Ping with a wrong seq or session is rejected (`bad_payload`) | §8.1 |

## Document control

| Version | Date | Change |
| --- | --- | --- |
| 0.2.0 | 2026-11-13 | First draft: 3-way handshake, P7 persistent pins, trust policy, keepalive |
| 0.2.0 | 2026-11-13 | Signed off by James after passing on laptop and S24 (VERSION, CHANGELOG v0.2.0). Status line updated in `dc36bea`; this row added afterwards, at James's request to record every change. Status line only, no rule changes |
