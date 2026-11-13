"""
conftest.py — pytest path setup for SC-OS

Function:
    Puts this directory and the sibling frozen layers (P1
    ../envelope-layer, P2 ../sign-layer) on sys.path, located from
    this file rather than the working directory, so `pytest -q` runs
    from anywhere. peer.py does the same for itself at import time;
    this file exists so tests can import envelope_v2 and sign_v2
    directly. Contains no functions.

Layer:    Tier 1 Consumer — SC-OS
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)

for _p in (os.path.join(_ROOT, "envelope-layer"), os.path.join(_ROOT, "sign-layer"), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)
