"""Artifact Integrity: Source / Commit / Published Artifact (Phase 2 M1 WP3-3).

Source: ``docs/v2/phase2/m1/wp0/helper-audit.md`` §2-6 and §3 (the Phase 1
helper's ``committed_tree`` / ``compare_tree`` / ``artifact_record`` /
``require_artifact``), rev2 C4 and the G11 artifact-mismatch incident (a stale
workflow was pushed although a newer one had been audited). Purpose: show,
separately, that

1. **Git tree** — the artifact commit is the expected one and its tree can be
   read (:func:`read_artifact`, through the read-only, tracked
   :mod:`iacreview.remediation.gitsnap`: plumbing commands only, hooks and
   fsmonitor off, no network);
2. **Content** — every path, mode and byte of that tree equals the approved
   source, and every blob's bytes hash to its git object id
   (:func:`compare_content`);
3. **Evidence manifest** — the artifact record kept in the Evidence Store names
   the same commit, tree and file hashes (:func:`manifest_reference_problems`).

Reuse decision (D-7): the helper read trees with its own ``subprocess`` calls
and no safety options, and compared bytes and modes in one function that also
built the push record. ``gitsnap`` already gives a safe, tested tree reader, so
it is reused for reading, and only the comparison rules of ``compare_tree``
(exact path set, regular ``100644`` files only, byte equality) are carried over.
Nothing here pushes, fetches or writes to a repository.

Rules ``phase2.artifact.whole_tree_matches_source`` (P2-AI-01) and
``phase2.artifact.published_matches_source`` (P2-AI-02) are at the end.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from iacreview.evidence import envelope as env
from iacreview.evidence.rule_s7_evidence import RuleResult
from iacreview.evidence.store import StoreReport
from iacreview.remediation import gitsnap

RULE_WHOLE_TREE = "phase2.artifact.whole_tree_matches_source"
RULE_PUBLISHED = "phase2.artifact.published_matches_source"
#: The only mode an approved artifact file may have (the helper's rule): no executable bit, no link, no gitlink.
APPROVED_MODE = gitsnap.MODE_FILE
MAX_BLOB_BYTES = 8 * 1024 * 1024
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_PATH = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9._/-]{1,300}$")

#: Mismatch kinds (closed).
KINDS = ("source_commit_mismatch", "artifact_commit_mismatch", "content_mismatch", "extra_file", "missing_file", "mode_changed",
         "symlink", "gitlink", "invalid_git_object", "blob_too_large", "manifest_reference_mismatch")


def git_blob_id(data: bytes) -> str:
    """The git (SHA-1) blob id of ``data``."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # noqa: S324 - git object id, not a security hash


@dataclass(frozen=True)
class ApprovedSource:
    """The approved bytes of an artifact, and the commit of the source they were taken from."""

    source_commit: str
    files: Mapping[str, bytes]

    def problems(self) -> List[str]:
        out = []
        if not _SHA40.match(self.source_commit or ""):
            out.append("source_commit must be 40 lowercase hex")
        if not self.files:
            out.append("an approved source has at least one file")
        out += ["approved path {0!r} is not a plain relative path".format(p) for p in sorted(self.files) if not _PATH.match(p)]
        return out


@dataclass(frozen=True)
class ArtifactClaim:
    """What a push record says: the artifact commit and the source commit it was built from."""

    ref: str
    artifact_commit: str
    source_commit: str


@dataclass
class TreeRead:
    """Layer 1. ``files``: path -> (mode, object id, bytes or None)."""

    commit: Optional[str]
    tree: Optional[str]
    files: Dict[str, Tuple[str, str, Optional[bytes]]] = field(default_factory=dict)
    error: Optional[str] = None
    unreadable: List[str] = field(default_factory=list)


@dataclass
class Comparison:
    """Result of comparing an artifact with its approved source. ``status``: MATCH / MISMATCH / UNVERIFIABLE."""

    status: str
    mismatches: List[Tuple[str, str]] = field(default_factory=list)  # (kind, path or "")
    file_sha256: Dict[str, str] = field(default_factory=dict)
    commit: Optional[str] = None
    tree: Optional[str] = None
    reason: str = ""

    def record(self) -> Dict[str, Any]:
        """The canonical artifact record (what the Evidence Store keeps as LOCAL evidence)."""
        return {"record_type": "artifact_integrity", "record_version": 1, "commit": self.commit, "tree": self.tree,
                "status": self.status, "files": dict(sorted(self.file_sha256.items())),
                "mismatches": sorted([list(m) for m in self.mismatches])}


BlobReader = Callable[[Path, str, int], Optional[bytes]]


def read_artifact(repo: Path, ref: str, reader: BlobReader = gitsnap.read_blob) -> TreeRead:
    """Layer 1: resolve ``ref`` and read every entry of its tree (blob bytes for regular files and links)."""
    try:
        top = gitsnap.check_repo(repo)
        commit = gitsnap.resolve_commit(top, ref)
        snap = gitsnap.commit_snapshot(top, commit)
    except gitsnap.GitError as exc:
        return TreeRead(None, None, error="git read failed ({0})".format(exc.code))
    out = TreeRead(commit, snap.tree)
    for path, entry in sorted(snap.entries.items()):
        data: Optional[bytes] = None
        if entry.mode in (gitsnap.MODE_FILE, gitsnap.MODE_EXEC, gitsnap.MODE_LINK):
            try:
                data = reader(top, entry.oid, MAX_BLOB_BYTES)
            except gitsnap.GitError:
                out.files[path] = (entry.mode, entry.oid, None)
                out.unreadable.append(path)
                continue
        out.files[path] = (entry.mode, entry.oid, data)
    return out


def compare_content(tree: TreeRead, approved: ApprovedSource, claim: ArtifactClaim) -> Comparison:
    """Layers 1+2: commit identity, then paths, modes, bytes and object ids. Never raises for a mismatch."""
    bad = approved.problems()
    if bad:
        return Comparison("UNVERIFIABLE", reason="; ".join(bad))
    if tree.commit is None:
        return Comparison("UNVERIFIABLE", reason=tree.error or "tree not read")
    result = Comparison("MATCH", commit=tree.commit, tree=tree.tree)
    m = result.mismatches
    if claim.artifact_commit != tree.commit:
        m.append(("artifact_commit_mismatch", ""))
    if claim.source_commit != approved.source_commit:
        m.append(("source_commit_mismatch", ""))
    unreadable = False
    for path, (mode, oid, data) in tree.files.items():
        if mode == gitsnap.MODE_LINK:
            m.append(("symlink", path))
        elif mode == gitsnap.MODE_GITLINK:
            m.append(("gitlink", path))
        elif mode != APPROVED_MODE:
            m.append(("mode_changed", path))
        if data is None and mode != gitsnap.MODE_GITLINK:
            if path in tree.unreadable:
                unreadable = True
            else:
                m.append(("blob_too_large", path))
            if path not in approved.files:
                m.append(("extra_file", path))
            continue
        if data is not None:
            if len(oid) == 40 and git_blob_id(data) != oid:
                m.append(("invalid_git_object", path))
            result.file_sha256[path] = hashlib.sha256(data).hexdigest()
        if path not in approved.files:
            m.append(("extra_file", path))
        elif data is not None and data != approved.files[path]:
            m.append(("content_mismatch", path))
    for path in sorted(set(approved.files) - set(tree.files)):
        m.append(("missing_file", path))
    result.mismatches = sorted(set(m))
    if result.mismatches:
        result.status = "MISMATCH"
    elif unreadable:
        result.status, result.reason = "UNVERIFIABLE", "object(s) could not be read: {0}".format(sorted(tree.unreadable))
    return result


def manifest_reference_problems(report: StoreReport, evidence_id: str, comparison: Comparison,
                                read_raw: Callable[[StoreReport, str], Optional[bytes]]) -> List[str]:
    """Layer 3: the artifact record stored as LOCAL evidence matches the comparison (commit, tree, file hashes)."""
    if not report.valid:
        return ["the evidence store does not verify"]
    found = report.find(evidence_id)
    if found is None:
        return ["artifact record {0} is not in a valid revision".format(evidence_id)]
    envelope = found[1]
    problems = []
    if envelope["source_type"] != "LOCAL":
        problems.append("artifact record is not LOCAL evidence")
    if envelope["subject_commit_sha"] != comparison.commit:
        problems.append("artifact record subject commit differs from the artifact commit")
    raw = read_raw(report, evidence_id)
    if raw is None:
        return problems + ["artifact record raw content unavailable"]
    if raw != env.canonical_bytes(comparison.record()):
        problems.append("artifact record content differs from the recomputed record")
    return problems


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def whole_tree_matches_source(comparison: Comparison, manifest_problems: Optional[Sequence[str]] = None) -> RuleResult:
    """P2-AI-01. PASS: MATCH and (if given) the stored record matches. FAILED: any mismatch. NOT_PROVEN: unverifiable."""
    if comparison.status == "MISMATCH":
        return RuleResult(RULE_WHOLE_TREE, "FAILED", comparison.mismatches[0][0], ())
    if comparison.status != "MATCH":
        return RuleResult(RULE_WHOLE_TREE, "NOT_PROVEN", "artifact_unverifiable", ())
    if manifest_problems:
        if any("differs" in p for p in manifest_problems):
            return RuleResult(RULE_WHOLE_TREE, "FAILED", "manifest_reference_mismatch", ())
        return RuleResult(RULE_WHOLE_TREE, "NOT_PROVEN", "artifact_record_unavailable", ())
    return RuleResult(RULE_WHOLE_TREE, "PASS", "whole_tree_matches_source", ())


def _contents_target(endpoint: str) -> Optional[Tuple[str, str]]:
    """(path, ref) of a Contents API endpoint ``/repos/<o>/<r>/contents/<path>?ref=<sha>``."""
    m = re.match(r"^/repos/[A-Za-z0-9-]+/[A-Za-z0-9._-]+/contents/([A-Za-z0-9._/-]+)\?ref=([0-9a-f]{40})$", endpoint)
    return (m.group(1), m.group(2)) if m else None


def published_matches_source(report: StoreReport, evidence_id: str, comparison: Comparison, approved: ApprovedSource,
                             read_raw: Callable[[StoreReport, str], Optional[bytes]]) -> RuleResult:
    """P2-AI-02: the content GitHub served for the pushed commit equals the approved source, shown by the git blob id
    recomputed from the bytes in the stored Contents API answer.

    NOT_PROVEN: store not valid, evidence missing, not COMPLETE API evidence of a Contents endpoint for the artifact
    commit, raw unavailable or not decodable. FAILED: the served bytes, their blob id, the committed blob or the
    approved bytes disagree. PASS says nothing about authenticity (the API origin is self-declared).
    """
    ids = (evidence_id,)
    if not report.valid:
        return RuleResult(RULE_PUBLISHED, "NOT_PROVEN", "store_integrity_not_verified", ids)
    found = report.find(evidence_id)
    if found is None:
        return RuleResult(RULE_PUBLISHED, "NOT_PROVEN", "evidence_missing", ids)
    raw = read_raw(report, evidence_id) if found[1]["raw_content_sha256"] is not None else None
    return judge_contents(found[1], raw, comparison, {p: hashlib.sha256(b).hexdigest() for p, b in approved.files.items()}, ids)


def judge_contents(envelope: Mapping[str, Any], raw: Optional[bytes], comparison: Comparison,
                   approved_sha256: Mapping[str, str], ids: Tuple[str, ...]) -> RuleResult:
    """The P2-AI-02 judgement on one Contents API evidence (shared by the store path and the WP4 evaluator).

    ``approved_sha256``: SHA-256 of each approved file. With a MATCH comparison these equal the committed files.
    """
    if envelope["source_type"] != "API" or envelope["completeness_status"] != "COMPLETE":
        return RuleResult(RULE_PUBLISHED, "NOT_PROVEN", "capture_incomplete", ids)
    target = _contents_target(envelope["api"]["endpoint"])
    if target is None or comparison.status != "MATCH" or target[1] != comparison.commit:
        return RuleResult(RULE_PUBLISHED, "NOT_PROVEN", "not_a_contents_answer_for_the_artifact", ids)
    path, _ = target
    if raw is None:
        return RuleResult(RULE_PUBLISHED, "NOT_PROVEN", "raw_unavailable", ids)
    try:
        doc = json.loads(raw.decode("utf-8"))
        served = base64.b64decode("".join(str(doc["content"]).split()), validate=True)
        reported_sha = str(doc["sha"])
    except (UnicodeDecodeError, ValueError, KeyError, TypeError, binascii.Error):
        return RuleResult(RULE_PUBLISHED, "NOT_PROVEN", "contents_answer_not_decodable", ids)
    if doc.get("encoding") != "base64" or doc.get("path") != path:
        return RuleResult(RULE_PUBLISHED, "NOT_PROVEN", "contents_answer_not_decodable", ids)
    blob = git_blob_id(served)
    if blob != reported_sha:
        return RuleResult(RULE_PUBLISHED, "FAILED", "served_bytes_do_not_hash_to_reported_blob", ids)
    served_sha = hashlib.sha256(served).hexdigest()
    if approved_sha256.get(path) != served_sha:
        return RuleResult(RULE_PUBLISHED, "FAILED", "served_bytes_differ_from_approved_source", ids)
    if comparison.file_sha256.get(path) != served_sha:
        return RuleResult(RULE_PUBLISHED, "FAILED", "served_bytes_differ_from_committed_blob", ids)
    return RuleResult(RULE_PUBLISHED, "PASS", "published_matches_source", ids)


def comparison_from_record(raw: bytes) -> Optional[Comparison]:
    """Rebuild a Comparison from a stored artifact record (``Comparison.record()`` bytes); None if not one."""
    try:
        rec = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(rec, dict) or rec.get("record_type") != "artifact_integrity" or rec.get("record_version") != 1 \
            or rec.get("status") not in ("MATCH", "MISMATCH", "UNVERIFIABLE") or not isinstance(rec.get("files"), dict):
        return None
    c = Comparison(rec["status"], [tuple(m) for m in rec.get("mismatches") or []], dict(rec["files"]), rec.get("commit"), rec.get("tree"))
    return c if env.canonical_bytes(c.record()) == raw else None
