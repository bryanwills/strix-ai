"""Local credential store for subscription-based model auth.

Mirrors the viewer-auth store (see ``strix/viewer/auth.py``): a single JSON file
under ``~/.strix`` written ``0600``, holding one record per provider. It is kept
deliberately separate from ``cli-config.json`` — that file only ever holds env
vars, so OAuth tokens never leak into the env-var config that gets echoed back
to the user or copied into CI secrets.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import Any


AUTH_PATH = Path.home() / ".strix" / "subscription-auth.json"


def read_all() -> dict[str, Any]:
    """Return the full provider→record mapping, or ``{}`` if absent/unreadable."""
    try:
        data = json.loads(AUTH_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def read_provider(provider: str) -> dict[str, Any] | None:
    """Return the stored record for ``provider``, or None."""
    record = read_all().get(provider)
    return record if isinstance(record, dict) else None


def write_provider(provider: str, record: dict[str, Any]) -> None:
    """Persist ``record`` for ``provider``, preserving other providers' records."""
    data = read_all()
    data[provider] = record
    _atomic_write(data)


def forget(provider: str) -> None:
    """Delete the stored record for ``provider``. No-op if it is absent.

    Removes the file entirely once the last record is gone, so ``logout`` leaves
    nothing behind.
    """
    data = read_all()
    if provider not in data:
        return
    del data[provider]
    if data:
        _atomic_write(data)
        return
    with contextlib.suppress(OSError):
        AUTH_PATH.unlink()


def _atomic_write(data: dict[str, Any]) -> None:
    AUTH_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = AUTH_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    with contextlib.suppress(OSError):
        tmp.chmod(0o600)
    tmp.replace(AUTH_PATH)
    with contextlib.suppress(OSError):
        AUTH_PATH.chmod(0o600)


__all__ = ["AUTH_PATH", "forget", "read_all", "read_provider", "write_provider"]
