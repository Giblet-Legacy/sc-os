"""
transport.py — SC-OS raw TCP framing and threaded listener

Function:
    Moves JSON objects over TCP as newline-delimited frames (SPEC.md
    §3). Sends P1 canonical bytes + "\\n"; receives any JSON object on
    a line, bounded by MAX_FRAME. Knows nothing about signatures,
    Hellos or peers — that is peer.py. Canonical bytes come from P1;
    no primitive is reimplemented here.

Public API:
    1. FrameError          — malformed, oversize or truncated frame
    2. Connection          — one framed TCP connection
       2a. send            — write one canonical frame
       2b. recv            — read one frame; None on clean EOF
       2c. close           — close reader and socket (idempotent)
    3. connect             — open a client Connection to (host, port)
    4. Listener            — threading TCP server, one thread per connection
       4a. start           — bind, listen, start the accept thread
       4b. address         — (host, port) actually bound
       4c. close           — stop accepting, close the listening socket
       4d. _accept_loop    — accept until closed, hand off to _serve
       4e. _serve          — run the handler, always close the Connection

Internal helpers:
    5. _reject_constant    — json.loads hook that fires on NaN/±Infinity

Layer:    Tier 1 Consumer — SC-OS, Handshake (transport)
Depends:  P1 Envelope v2.0.0 (envelope_v2.canonical_bytes)
Spec:     SPEC.md 0.1.0 §3
Version:  0.1.0
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import json
import os
import socket
import sys
import threading

_HERE = os.path.dirname(os.path.abspath(__file__))
_P1 = os.path.join(os.path.dirname(_HERE), "envelope-layer")
if _P1 not in sys.path:
    sys.path.insert(0, _P1)

import envelope_v2  # noqa: E402  (P1, located above)

MAX_FRAME = 65536
DEFAULT_TIMEOUT = 5.0


# ---------------------------------------------------------------------------
# 1. FrameError
# ---------------------------------------------------------------------------
class FrameError(Exception):
    """A received frame broke SPEC.md §3.2–§3.3."""


# ---------------------------------------------------------------------------
# 5. _reject_constant
# ---------------------------------------------------------------------------
def _reject_constant(token):
    raise FrameError(f"non-finite number in frame: {token}")


# ---------------------------------------------------------------------------
# 2. Connection
# ---------------------------------------------------------------------------
class Connection:
    """One framed TCP connection. Not thread-safe; one owner at a time."""

    def __init__(self, sock, timeout=DEFAULT_TIMEOUT):
        sock.settimeout(timeout)
        self._sock = sock
        self._reader = sock.makefile("rb")
        self._closed = False

    # -----------------------------------------------------------------------
    # 2a. send — canonical bytes + "\n" (SPEC §3.2)
    # -----------------------------------------------------------------------
    def send(self, obj):
        if not isinstance(obj, dict):
            raise TypeError(f"frame must be a dict, got {type(obj).__name__}")
        self._sock.sendall(envelope_v2.canonical_bytes(obj) + b"\n")

    # -----------------------------------------------------------------------
    # 2b. recv — one JSON object, or None on clean EOF (SPEC §3.3)
    # -----------------------------------------------------------------------
    def recv(self):
        line = self._reader.readline(MAX_FRAME + 1)
        if line == b"":
            return None
        if not line.endswith(b"\n"):
            if len(line) > MAX_FRAME:
                raise FrameError(f"frame exceeds {MAX_FRAME} bytes")
            raise FrameError("EOF in the middle of a frame")
        try:
            obj = json.loads(line.decode("utf-8"), parse_constant=_reject_constant)
        except ValueError as exc:  # JSONDecodeError and UnicodeDecodeError
            raise FrameError(f"frame is not UTF-8 JSON: {exc}") from None
        if not isinstance(obj, dict):
            raise FrameError(f"frame must be a JSON object, got {type(obj).__name__}")
        return obj

    # -----------------------------------------------------------------------
    # 2c. close — idempotent
    # -----------------------------------------------------------------------
    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self._reader.close()
        finally:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._sock.close()


# ---------------------------------------------------------------------------
# 3. connect
# ---------------------------------------------------------------------------
def connect(host, port, timeout=DEFAULT_TIMEOUT):
    return Connection(socket.create_connection((host, port), timeout=timeout), timeout)


# ---------------------------------------------------------------------------
# 4. Listener
# ---------------------------------------------------------------------------
class Listener:
    """Threading TCP server. handler(conn) runs on its own thread per connection."""

    def __init__(self, host, port, handler, timeout=DEFAULT_TIMEOUT):
        self._host = host
        self._port = port
        self._handler = handler
        self._timeout = timeout
        self._sock = None
        self._thread = None
        self._stop = threading.Event()

    # -----------------------------------------------------------------------
    # 4a. start — bind, listen, spawn the accept thread
    # -----------------------------------------------------------------------
    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind((self._host, self._port))
            sock.listen()
            sock.settimeout(0.2)  # lets the accept loop notice close()
        except OSError:
            sock.close()
            raise
        self._sock = sock
        self._thread = threading.Thread(target=self._accept_loop, name="sc-os-listener", daemon=True)
        self._thread.start()
        return self.address

    # -----------------------------------------------------------------------
    # 4b. address — (host, port) actually bound
    # -----------------------------------------------------------------------
    @property
    def address(self):
        if self._sock is None:
            raise RuntimeError("listener not started")
        return self._sock.getsockname()[:2]

    # -----------------------------------------------------------------------
    # 4c. close — stop accepting; open connections finish on their own
    # -----------------------------------------------------------------------
    def close(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        if self._sock is not None:
            self._sock.close()

    # -----------------------------------------------------------------------
    # 4d. _accept_loop
    # -----------------------------------------------------------------------
    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            conn = Connection(client, self._timeout)
            threading.Thread(target=self._serve, args=(conn,), name="sc-os-conn", daemon=True).start()

    # -----------------------------------------------------------------------
    # 4e. _serve — handler errors end only this connection
    # -----------------------------------------------------------------------
    def _serve(self, conn):
        try:
            self._handler(conn)
        except (OSError, FrameError):
            pass
        finally:
            conn.close()
