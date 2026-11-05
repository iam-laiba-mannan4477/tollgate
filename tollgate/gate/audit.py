"""Append-only, hash-chained audit log (JSON lines).

Each line stores `prev_hash` (hash of the previous line) and `hash` (hash of
this line's content). Editing, deleting or reordering a line breaks the chain,
and `verify` reports it.

Known limit: removing lines from the END of the file leaves a valid shorter
chain. To catch that, pass the last hash you saw (`expected_last_hash`) to
`verify`; Day 3+ can anchor it somewhere outside the log file.

Fields are fixed (id, time, decision, reason, amount_cents, recipient). There is
no field for stamps or keys, and free text that looks like a secret is redacted.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from pathlib import Path
from typing import Callable

GENESIS = "0" * 64
MAX_REASON_LEN = 200
_SECRET_LIKE = re.compile(
    r"(?i)(private[_-]?key|api[_-]?key|secret|token|password|stamp\s*[:=])"
    r"|[A-Za-z0-9_\-]{32,}"           # long random-looking strings (e.g. stamps)
    r"|\b\d{13,19}\b"                 # card-number-like digit runs
)
REDACTED = "[redacted]"


def _clean(text: object, max_len: int) -> str:
    value = str(text)[:max_len]
    return REDACTED if _SECRET_LIKE.search(value) else value


def _line_hash(prev_hash: str, body: dict) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path, clock: Callable[[], float] = time.time) -> None:
        self._path = Path(path)
        self._clock = clock
        self._lock = threading.Lock()

    def append(self, event_id: str, decision: str, reason: str,
               amount_cents: object, recipient: object) -> str:
        """Write one event and return its hash."""
        with self._lock:
            prev = _last_hash(self._path)
            body = {
                "id": _clean(event_id, 64),
                "time": self._clock(),
                "decision": _clean(decision, 10),
                "reason": _clean(reason, MAX_REASON_LEN),
                "amount_cents": amount_cents if isinstance(amount_cents, int)
                and not isinstance(amount_cents, bool) else None,
                "recipient": _clean(recipient, 128),
                "prev_hash": prev,
            }
            line_hash = _line_hash(prev, body)
            with self._path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({**body, "hash": line_hash}, sort_keys=True) + "\n")
            return line_hash


def _last_hash(path: Path) -> str:
    if not path.exists():
        return GENESIS
    last = GENESIS
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.strip():
                last = json.loads(line)["hash"]
    return last


def verify(path: str | Path, expected_last_hash: str | None = None) -> bool:
    """True only if every line is intact and correctly chained. Fails closed."""
    try:
        prev = GENESIS
        with Path(path).open(encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    return False
                record = json.loads(line)
                claimed = record.pop("hash")
                if record.get("prev_hash") != prev or _line_hash(prev, record) != claimed:
                    return False
                prev = claimed
        return expected_last_hash is None or prev == expected_last_hash
    except Exception:
        return False
