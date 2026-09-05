from __future__ import annotations

from datetime import datetime, timezone

__all__ = ["now"]


def now() -> str:
    """UTC timestamp shared by the audit log, the beacon and the status file."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
