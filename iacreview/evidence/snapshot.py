"""Verified Evidence Snapshot: the evaluator's only input (Phase 2 M1 WP4-1).

Source: WP3 ``integrity.py`` (V1-V9, W1-W5) and the WP4 instruction. Purpose:
the evaluator never reads the store by evidence id alone. A snapshot is made
once, after the integrity validator returned PASS for each group of evidence,
and binds every evidence id to

    raw SHA-256, envelope SHA-256, manifest SHA-256, revision id, subject commit,

together with the Definition (id, version, SHA-256) and the evaluator version.
:meth:`Snapshot.read` then returns bytes only if

1. the id is bound in this snapshot (no unbound or re-pointed id),
2. the bound revision's ``MANIFEST.json`` still has the bound SHA-256,
3. the envelope file still has the bound SHA-256,
4. the raw file still has the bound SHA-256.

Any difference raises :class:`SnapshotDrift` and the evaluation is refused.
``read`` deliberately does not call ``store.verify()`` again: each binding check
stands on its own (and is mutation-tested on its own, ``mutation-test-results.md``).
Files are opened with ``O_NOFOLLOW``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from iacreview.evidence import canonical
from iacreview.evidence import envelope as env
from iacreview.evidence import integrity
from iacreview.evidence.store import MANIFEST, EvidenceStore, _open_dir, _read_file

SNAPSHOT_FORMAT = "iacreview.evidence.snapshot/1"


class SnapshotDrift(Exception):
    """The store changed after the snapshot, or an id is not bound. The message holds no content."""


class SnapshotRefused(Exception):
    """A group of evidence did not pass the integrity validator; no snapshot is made from it."""

    def __init__(self, group: str, result: Dict[str, Any]) -> None:
        super().__init__("integrity validation of group {0} is {1}".format(group, result["overall_status"]))
        self.group = group
        self.result = result


@dataclass(frozen=True)
class Binding:
    evidence_id: str
    revision_id: str
    raw_sha256: Optional[str]
    envelope_sha256: str
    manifest_sha256: str
    subject_commit_sha: Optional[str]
    source_type: str

    def as_dict(self) -> Dict[str, Any]:
        return {"evidence_id": self.evidence_id, "revision_id": self.revision_id, "raw_sha256": self.raw_sha256,
                "envelope_sha256": self.envelope_sha256, "manifest_sha256": self.manifest_sha256,
                "subject_commit_sha": self.subject_commit_sha, "source_type": self.source_type}


@dataclass
class Snapshot:
    store: EvidenceStore
    definition_id: str
    definition_version: int
    definition_sha256: str
    evaluator_version: str
    bindings: Dict[str, Binding]
    validation: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # per group: overall + check statuses

    def binding_table(self) -> List[Dict[str, Any]]:
        return [self.bindings[k].as_dict() for k in sorted(self.bindings)]

    @property
    def digest(self) -> str:
        return canonical.sha256({"format": SNAPSHOT_FORMAT, "definition_id": self.definition_id,
                                 "definition_version": self.definition_version, "definition_sha256": self.definition_sha256,
                                 "evaluator_version": self.evaluator_version, "bindings": self.binding_table()})

    def is_bound(self, evidence_id: str) -> bool:
        return evidence_id in self.bindings

    def read(self, evidence_id: str) -> Tuple[Dict[str, Any], Optional[bytes]]:
        """(envelope, raw bytes) of a bound evidence, re-checked against the binding. Raises SnapshotDrift."""
        b = self.bindings.get(evidence_id)
        if b is None:
            raise SnapshotDrift("evidence {0} is not bound in this snapshot".format(evidence_id))
        fd = _open_dir(self.store.root / b.revision_id)
        try:
            manifest, _, _ = _read_file(fd, MANIFEST)
            if manifest is None or env.sha256_hex(manifest) != b.manifest_sha256:
                raise SnapshotDrift("{0}: the manifest of {1} changed after the snapshot".format(evidence_id, b.revision_id))
            env_bytes, _, _ = _read_file(fd, evidence_id + ".envelope.json")
            if env_bytes is None or env.sha256_hex(env_bytes) != b.envelope_sha256:
                raise SnapshotDrift("{0}: the envelope changed after the snapshot".format(evidence_id))
            raw: Optional[bytes] = None
            if b.raw_sha256 is not None:
                raw, _, _ = _read_file(fd, evidence_id + ".raw")
                if raw is None or env.sha256_hex(raw) != b.raw_sha256:
                    raise SnapshotDrift("{0}: the raw content changed after the snapshot".format(evidence_id))
        finally:
            os.close(fd)
        try:
            envelope = env.parse_envelope_bytes(env_bytes)
        except (ValueError, UnicodeDecodeError):
            raise SnapshotDrift("{0}: the envelope no longer parses".format(evidence_id)) from None
        return envelope, raw


def take(store: EvidenceStore, groups: Mapping[str, Tuple[Sequence[str], integrity.Requirement]], definition: Mapping[str, Any],
         definition_sha256: str, evaluator_version: str) -> Snapshot:
    """Validate each group; bind every evidence of every group that PASSes. A group that does not PASS is left out
    (its evidence is not bound, so rules that need it are NOT_PROVEN); its validator result is kept."""
    report = store.verify()
    bindings: Dict[str, Binding] = {}
    validation: Dict[str, Dict[str, Any]] = {}
    for name in sorted(groups):
        ids, requirement = groups[name]
        result = integrity.validate(store, list(ids), requirement, report)
        validation[name] = {"overall_status": result["overall_status"],
                            "checks": {c["check_id"]: c["status"] for c in result["checks"]},
                            "evidence_ids": sorted(set(ids))}
        if result["overall_status"] != "PASS":
            continue
        for eid in result["usable_evidence_ids"]:
            found = report.find(eid)
            if found is None:  # pragma: no cover - usable ids are found by construction
                continue
            rev, envelope = found
            entry = next(e for e in (rev.manifest or {}).get("entries", []) if e.get("evidence_id") == eid)
            bindings[eid] = Binding(eid, rev.revision_id, envelope["raw_content_sha256"], entry["envelope_sha256"],
                                    str(rev.manifest_sha256), envelope["subject_commit_sha"], envelope["source_type"])
    return Snapshot(store, str(definition["definition_id"]), int(definition["definition_version"]), definition_sha256,
                    evaluator_version, bindings, validation)
