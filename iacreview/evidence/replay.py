"""Deterministic Offline Replay (Phase 2 M1 WP4-4).

    python3 -m iacreview.evidence.replay SPEC.json [--expect RESULT.json]

``SPEC.json`` names the store (root and containment base), the validation groups and the scenario bundles.
The replay validates the groups (WP3), takes a hash-bound snapshot, evaluates the bundles (NATIVE_RAW_REPLAY)
and writes the canonical result bytes to stdout. The SHA-256 of those bytes is the output hash. Run metadata
(time) is written to stderr only, never into the canonical result.

No network: nothing here imports a transport, and the evaluator reads only bound bytes from the local store.
With ``--expect`` the replay is compared with a result made earlier (WP5-4). The comparison refuses, before any
byte comparison, a result made with another Definition (``DEFINITION_CHANGED``) or another evaluator source
(``SOURCE_CHANGED``), then a result whose snapshot differs (``SNAPSHOT_CHANGED``: a raw, envelope or manifest hash,
a revision or the set of bound evidence changed), and last any other byte difference (``RESULT_MISMATCH``).

Exit codes: 0 result written (and, with ``--expect``, identical), 2 invalid spec, 3 the store changed after the
snapshot (evaluation refused), 4 the replay does not reproduce the expected result.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from iacreview.evidence import canonical, evaluator, integrity, registry, snapshot
from iacreview.evidence.store import EvidenceStore

DEFINITION_PATH = registry.DEFINITIONS_DIR / "phase1-app-demo-s7.v1.json"
SPEC_KEYS = frozenset({"store_root", "containment_base", "groups", "bundles"})


def load_definition() -> Tuple[Dict[str, Any], str]:
    data = DEFINITION_PATH.read_bytes()
    doc = registry.parse_definition_bytes(data)
    problems = registry.validate_definition(doc, DEFINITION_PATH.name)
    if problems:
        raise registry.RegistryError(problems)
    return doc, hashlib.sha256(data).hexdigest()


def replay(spec: Mapping[str, Any], store: Optional[EvidenceStore] = None) -> bytes:
    """Canonical result bytes for ``spec``. Raises ValueError (bad spec) or SnapshotDrift (store changed)."""
    if not isinstance(spec, dict) or set(spec) != SPEC_KEYS:
        raise ValueError("spec must have exactly {0}".format(sorted(SPEC_KEYS)))
    definition, definition_sha = load_definition()
    st = store or EvidenceStore(Path(spec["store_root"]), Path(spec["containment_base"]))
    groups = {}
    for name, g in spec["groups"].items():
        req = g.get("requirement") or {}
        groups[name] = (list(g["evidence_ids"]), integrity.Requirement(req.get("source_type", "API"), req.get("subject_commit_sha"),
                                                                       bool(req.get("require_complete", True))))
    snap = snapshot.take(st, groups, definition, definition_sha, evaluator.EVALUATOR_VERSION)
    return evaluator.canonical_bytes(evaluator.native_replay(snap, spec["bundles"], definition, definition_sha))


class ReplayMismatch(Exception):
    """The replay does not reproduce an expected result. ``code`` names the first difference found."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


MISMATCH_CODES = ("EXPECTED_NOT_CANONICAL", "DEFINITION_CHANGED", "SOURCE_CHANGED", "SNAPSHOT_CHANGED", "RESULT_MISMATCH")


def verify(spec: Mapping[str, Any], expected: bytes, store: Optional[EvidenceStore] = None) -> bytes:
    """Replay ``spec`` and compare with ``expected`` (canonical result bytes). Returns the replay bytes if identical;
    raises ReplayMismatch, SnapshotDrift or ValueError otherwise."""
    try:
        exp = json.loads(expected.decode("ascii"))
        if canonical.dumps(exp) != expected:
            raise ValueError
    except (UnicodeDecodeError, ValueError, canonical.CanonicalError):
        raise ReplayMismatch("EXPECTED_NOT_CANONICAL") from None
    _, definition_sha = load_definition()
    if (exp.get("definition") or {}).get("definition_sha256") != definition_sha:
        raise ReplayMismatch("DEFINITION_CHANGED")
    if (exp.get("evaluator") or {}).get("source_sha256") != evaluator.evaluator_source_sha256():
        raise ReplayMismatch("SOURCE_CHANGED")
    out = replay(spec, store)
    if json.loads(out.decode("ascii")).get("snapshot_sha256") != exp.get("snapshot_sha256"):
        raise ReplayMismatch("SNAPSHOT_CHANGED")
    if out != expected:
        raise ReplayMismatch("RESULT_MISMATCH")
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m iacreview.evidence.replay")
    parser.add_argument("spec")
    parser.add_argument("--expect", default=None, help="canonical result to reproduce byte for byte")
    args = parser.parse_args(argv)
    try:
        spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
        out = verify(spec, Path(args.expect).read_bytes()) if args.expect else replay(spec)
    except ReplayMismatch as exc:
        sys.stderr.write("replay does not reproduce the expected result: {0}\n".format(exc.code))
        return 4
    except snapshot.SnapshotDrift as exc:
        sys.stderr.write("replay refused: {0}\n".format(exc))
        return 3
    except (OSError, ValueError, KeyError, TypeError) as exc:
        sys.stderr.write("invalid replay spec ({0})\n".format(type(exc).__name__))
        return 2
    sys.stdout.buffer.write(out)
    sys.stderr.write("replay output sha256 {0} at {1}\n".format(hashlib.sha256(out).hexdigest(),
                                                                 datetime.datetime.now(datetime.timezone.utc).isoformat()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
