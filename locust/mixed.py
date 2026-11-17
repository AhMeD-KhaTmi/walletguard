"""Mixed and combined workloads (MASTER_PLAN 7.1 and 7.2.4).

The plan asks for two runs that the separated workloads cannot provide:

``mixed``     benign users and all three attack pools concurrently on the same timeline,
              from their own source IPs and account pools. This is not a substitute for
              the benign-only FPR run: it measures whether defense traffic against
              attackers harms the innocent users sharing the system at that moment.
``combined``  one end-to-end attack with *no special setup phase*, as required by 7.1.

`P20_ROLE` selects this process's behaviour. The attack classes are imported from their
own files rather than re-implemented, so a mixed run measures exactly the behaviours the
separated runs measure.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# name -> (file, class)
ROLES = {
    "benign": ("benign.py", "BenignUser"),
    "credential_stuffing": ("attack_credential_stuffing.py", "CredentialStuffingUser"),
    "scraping": ("attack_scraping.py", "ScrapingUser"),
    "dow": ("attack_dow.py", "TokenExhaustionUser"),
}

ROLE = os.environ.get("P20_ROLE", "")
if ROLE not in ROLES:
    raise RuntimeError(f"P20_ROLE must be one of {sorted(ROLES)}; got {ROLE!r}")

_filename, _classname = ROLES[ROLE]
_spec = importlib.util.spec_from_file_location(f"p20_role_{ROLE}", ROOT / "locust" / _filename)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)

# Locust discovers User subclasses in this module's namespace.
Selected = getattr(_module, _classname)
