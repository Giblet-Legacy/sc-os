# SPEC_V3 — SC-OS Nerves v0.3.0 (read-only status bridge)

SPEC_V3.md — Normative specification for `nerves.py`: a read-only view of a node's verified pin store for the rest of the stack.

Function:
    SC-OS kept its only persistent state (the P7-signed pin store) to
    itself, so no other consumer could see the network. The Legacy's
    v0.4.0 "Nerves" view needs exactly that. This version adds a
    read-only reader and a FORGE_HOME location for the pin file. It
    changes nothing on the wire and edits no v0.1.0 or v0.2.0 file.

| Field | Value |
| --- | --- |
| Version | 0.3.0 |
| Status | Signed off by James, 2026-11-13 ("freeze all"). Tested on the laptop; S24 run to be confirmed |
| Over | SPEC_V2.md 0.2.0 (`peer_v2.py`, `pins.py` unchanged) |
| Depends | P1 `envelope_v2`, P2 `sign_v2`, P7 `record_v2` (via `pins.py`) |
| Licence | MSL-1.0 |
| Author | James Gilbert (Giblets Forge) |

---

## 1. Location

`default_pin_path(env=None)` returns `$FORGE_HOME/sc-os/pins.sc.json`,
else `~/.forge/sc-os/pins.sc.json`. A node run for the stack passes
this as `pin_path`; any other path still works.

## 2. read_nerves(pin_path, owner_did=None) -> dict | None

- Missing file → None (the node has pinned nobody yet, or never ran).
- Otherwise the file is verified exactly as `pins.PinStore` verifies it
  on load (SPEC_V2 §7.2: P7 verify, single read, P2 re-verify, exact
  shape, every did decodes, every address names a pinned did), using
  only the owner's **public** key. No private key or passphrase is
  needed, and nothing is written.
- With `owner_did`, the record's `owner` must equal it (the caller's
  trust anchor). Without it, the record is checked only against the
  owner it names, and the result says so (`owner_pinned: false`).
- Any failure raises `pins.PinStoreError` (fail closed).
- Returns `{owner, owner_pinned, peers (sorted dids), addresses,
  peer_count}`.

## 3. Tests (test_nerves.py)

| ID | Requirement |
| --- | --- |
| N1 | A pin file written by `PinStore` reads back with its peers and addresses |
| N2 | Missing file → None |
| N3 | Tampered, foreign-signed or reshaped file → PinStoreError |
| N4 | `owner_did` mismatch → PinStoreError; match → `owner_pinned: true` |
| N5 | File bytes unchanged after reading |
| N6 | `default_pin_path` follows FORGE_HOME |

## Document control

| Version | Date | Change |
| --- | --- | --- |
| 0.3.0 | 2026-11-13 | First draft, by the VS Code AI on James's delegation ("fix all 11 issues") |
| 0.3.0 | 2026-11-13 | Signed off by James ("freeze all"). Status line only, no rule changes |
