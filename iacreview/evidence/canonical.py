"""Canonical serialization of evaluation results (Phase 2 M1 WP4-4).

Specification (fixed before the evaluator was written; ``replay-reproducibility-report.md`` §1):

* JSON text; object keys sorted by code point (``sort_keys``)
* encoding: ASCII only; every non-ASCII character is a ``\\uXXXX`` escape (``ensure_ascii``)
* separators ``,`` and ``:`` with no whitespace; one trailing ``\\n``; no other newline
* ``null``, ``true`` and ``false`` as JSON literals
* numbers: integers only. Floats, NaN and Infinity are refused (no platform-dependent repr)
* arrays: the producer sorts every array whose order is not meaningful; the serializer does not reorder
* forbidden content: keys that carry run time (:data:`FORBIDDEN_KEYS`), and strings that look like an
  absolute host path (``/`` followed by a path segment other than an API-relative ``/repos`` style
  endpoint is not emitted by the evaluator at all, so any leading ``/`` is refused), a Windows drive path,
  or a backslash

The output hash is the SHA-256 of these bytes.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, List

FORBIDDEN_KEYS = frozenset({
    "generated_at", "evaluated_at", "checked_at", "verified_at", "captured_at", "sealed_at", "observed_at", "run_at",
    "timestamp", "duration_ms", "hostname", "cwd", "tmpdir", "pid",
})
_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


class CanonicalError(ValueError):
    """The object cannot be serialized canonically."""


def _check(value: Any, where: str, problems: List[str]) -> None:
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        problems.append("{0}: floats are not allowed".format(where))
    elif isinstance(value, str):
        if value.startswith("/") or "\\" in value or _DRIVE.match(value):
            problems.append("{0}: looks like a host path".format(where))
    elif isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                problems.append("{0}: non-string key".format(where))
                continue
            if k in FORBIDDEN_KEYS:
                problems.append("{0}.{1}: run-time key is not allowed in a canonical result".format(where, k))
            _check(v, where + "." + k, problems)
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _check(v, "{0}[{1}]".format(where, i), problems)
    else:
        problems.append("{0}: unsupported type {1}".format(where, type(value).__name__))


def problems(obj: Any) -> List[str]:
    out: List[str] = []
    _check(obj, "$", out)
    return out


def dumps(obj: Any) -> bytes:
    """The canonical bytes of ``obj``; raises CanonicalError if ``obj`` breaks the specification."""
    found = problems(obj)
    if found:
        raise CanonicalError("; ".join(found[:10]))
    return (json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")


def sha256(obj: Any) -> str:
    return hashlib.sha256(dumps(obj)).hexdigest()
