"""Member A tooling tests. Run from the repository root:

    python3 -m pytest eval/tests -q

These are unit tests for the client-side evaluation plumbing. They do not replace
the measured traffic runs and they must not be reported as ASR/FPR evidence.
"""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
