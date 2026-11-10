"""Owner notifications. In mock and sandbox modes they go to an OUTBOX FILE (JSON lines).

No email or push is sent. A real deployment would need a real channel, and the
cooling-off delay only protects if the owner actually sees the alert.
Messages hold ids, amounts and kinds only: never codes, secrets or passwords.
"""
from __future__ import annotations

import itertools
import json
import threading
from pathlib import Path
from typing import Callable

from tollgate.gate.audit import _clean


class Outbox:
    def __init__(self, path: str | Path, clock: Callable[[], float]) -> None:
        self._path = Path(path)
        self._clock = clock
        self._lock = threading.Lock()
        self._seq = itertools.count(1)

    @property
    def path(self) -> Path:
        return self._path

    def notify(self, destination: str, kind: str, text: str) -> str:
        """Write one notification and return its id."""
        with self._lock:
            note_id = f"note-{next(self._seq)}"
            record = {"id": note_id, "time": self._clock(), "to": _clean(destination, 128),
                      "kind": _clean(kind, 32), "text": _clean(text, 300),
                      "channel": "outbox-file (no real email in sandbox)"}
            with self._path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, sort_keys=True) + "\n")
            return note_id

    def read(self) -> list[dict]:
        if not self._path.exists():
            return []
        return [json.loads(line) for line in self._path.read_text(encoding="utf-8").splitlines()
                if line.strip()]
