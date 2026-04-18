"""
Load local KEY=VALUE pairs from `.env` into os.environ (only if not already set).

Searched in order (first wins per key):
  experiments/bitcoin-signature-binding-experiments/.env
  <repo root>/.env

So you can keep `CAT_DEMO_WIF` (and `INQUISITION_*`, etc.) in a gitignored `.env`
instead of exporting in every shell. Import this module once after `sys.path` is set:

    sys.path.insert(0, ".")
    import experiments.load_local_env  # noqa: F401
"""

from __future__ import annotations

import os
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_BINDING_ENV = _REPO_ROOT / "experiments" / "bitcoin-signature-binding-experiments" / ".env"
_ROOT_ENV = _REPO_ROOT / ".env"


def load_dotenv_files() -> None:
    """Parse KEY=VALUE from `.env` files; only set keys that are not already in os.environ."""
    for env_path in (_BINDING_ENV, _ROOT_ENV):
        if not env_path.is_file():
            continue
        try:
            text = env_path.read_text(encoding="utf-8")
        except OSError:
            continue
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            if not key:
                continue
            val = val.strip().strip('"').strip("'")
            if key not in os.environ:
                os.environ[key] = val


load_dotenv_files()
