"""Legacy Evidence Map: read-only traceability of the Phase 1 evidence (Phase 2 M1 WP3-2).

Source: ``.agents/tasks/phase1/final-acceptance/rev2/phase1-evidence-index.md``
(E01-E40, H01-H03), rev3 (AC traceability, finalization, handoff),
``github-evidence-20261028/`` and the WP0 helper audit. Purpose: record, for
every Phase 1 evidence id, where it is, what kind of record it is, whether a
raw API response or a hash from the time exists, and what it cannot show
(M1-10). The map lives in ``legacy/phase1-legacy-evidence-map.v1.json``.

The map is not a re-evaluation. Phase 1 results in it are quoted and checked
against :data:`iacreview.evidence.registry.PHASE1_LOCKED`; no rule is run on
legacy evidence here.

Fixed rules (a map that breaks one is refused):

* there is no "raw available" value for Phase 1: an API-derived record is
  ``RAW_UNAVAILABLE``; the two base64 content fields of the GitHub supplement
  are ``RAW_FIELD_ONLY``
* without a hash recorded at the time, ``HISTORICAL_INTEGRITY_NOT_PROVEN``
* the Phase 1 helper revision is ``UNKNOWN``
* no legacy entry is ``COMPLETE``
* G3 / G3S / G6 FAILED, G11 NOT_PROVEN, G11b PASS, G12 PARTIAL, AC27 FAILED

:func:`current_state` re-reads the source files (read-only). A missing file is
``SOURCE_MISSING``, never treated as present, and a changed file is
``CHANGED``. A raw response captured later is a new observation and is never
attached to a legacy entry.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Mapping, Optional

from iacreview.evidence import registry

MAP_PATH = Path(__file__).resolve().parent / "legacy" / "phase1-legacy-evidence-map.v1.json"
MAP_SCHEMA_VERSION = 1

TOP_KEYS: FrozenSet[str] = frozenset({
    "map_schema_version", "map_id", "map_version", "created_by_work_package", "is_reevaluation", "statement",
    "historical_helper_revision", "index_sources", "entries", "subjects",
})
ENTRY_KEYS: FrozenSet[str] = frozenset({
    "legacy_evidence_id", "description", "source_files", "source_type", "provenance_assurance", "raw_api_response",
    "historical_hash", "completeness", "related", "historical_classification", "traceability_limitations",
})
FILE_KEYS: FrozenSet[str] = frozenset({"path", "present", "current_sha256", "size"})
HIST_KEYS: FrozenSet[str] = frozenset({"status", "kind", "recorded_in", "values"})
SUBJECT_KEYS: FrozenSet[str] = frozenset({"subject", "phase1_result", "axes", "evidence_ids", "basis", "limitations"})

SOURCE_TYPES: FrozenSet[str] = frozenset({
    "DERIVED_HELPER_OUTPUT", "LOCAL_FILE", "LOCAL_GIT_DERIVED", "API_TRANSCRIBED", "HUMAN_REPORT", "DOCUMENT", "HELPER_CODE",
    "GIT_HISTORY",
})
PROVENANCE: FrozenSet[str] = frozenset({"SELF_DECLARED_UNVERIFIED", "HUMAN_REPORTED", "DOCUMENTARY"})
RAW_VALUES: FrozenSet[str] = frozenset({"RAW_UNAVAILABLE", "RAW_FIELD_ONLY", "NOT_APPLICABLE"})
HIST_STATUSES: FrozenSet[str] = frozenset({"HISTORICAL_HASH_MATCHES", "HISTORICAL_HASH_MISMATCH", "HISTORICAL_INTEGRITY_NOT_PROVEN"})
HIST_KINDS: FrozenSet[str] = frozenset({"none", "recorded_sha256", "git_blob", "git_section"})
COMPLETENESS: FrozenSet[str] = frozenset({"INCOMPLETE", "SOURCE_MISSING", "NOT_CAPTURED"})
INDEX_STATUSES: FrozenSet[str] = frozenset({"current", "revoked", "superseded", "intermediate", "stale", "not_used", "supporting_only"})

#: Every id of the rev2 Evidence Index, plus the rev3 supplement and the revision documents. All must be mapped.
REQUIRED_IDS: FrozenSet[str] = frozenset(
    ["E{0:02d}".format(i) for i in range(1, 41) if i != 23]
    + ["E23-1", "E23-2", "E23-3"] + ["E23b-{0}".format(i) for i in range(1, 7)] + ["E28-i", "H01", "H02", "H03"]
    + ["GE-JSON", "GE-RAW-PROBE", "GE-RAW-STEAL", "GE-README", "P1-REVISIONS"]
)
REQUIRED_PREFIXES = ("P1-REV1-", "P1-REV2-", "P1-REV3-")
REQUIRED_SUBJECTS: Mapping[str, str] = {"G3": "FAILED", "G3S": "FAILED", "G6": "FAILED", "G11": "NOT_PROVEN", "G11b": "PASS",
                                        "G12": "PARTIAL", "AC27": "FAILED"}
_ID = re.compile(r"^[A-Z0-9][A-Za-z0-9-]{1,40}$")
_SHA64 = re.compile(r"^[0-9a-f]{64}$")
MAX_SOURCE_BYTES = 64 * 1024 * 1024


class LegacyMapError(Exception):
    def __init__(self, problems: List[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


def _keys(obj: Any, allowed: FrozenSet[str], where: str) -> List[str]:
    if not isinstance(obj, dict):
        return ["{0}: must be an object".format(where)]
    missing, unknown = sorted(allowed - set(obj)), sorted(set(obj) - allowed)
    return ["{0}: missing {1}, unknown {2}".format(where, missing, unknown)] if missing or unknown else []


def _entry_problems(e: Dict[str, Any]) -> List[str]:
    eid = e.get("legacy_evidence_id")
    w = "entry {0}".format(eid)
    problems = _keys(e, ENTRY_KEYS, w)
    if problems:
        return problems
    if not (isinstance(eid, str) and _ID.match(eid)):
        problems.append(w + ": invalid id")
    if e["source_type"] not in SOURCE_TYPES:
        problems.append(w + ": unknown source_type")
    if e["provenance_assurance"] not in PROVENANCE:
        problems.append(w + ": unknown provenance_assurance")
    if e["raw_api_response"] not in RAW_VALUES:
        problems.append(w + ": raw_api_response must be one of {0} (Phase 1 has no raw API body)".format(sorted(RAW_VALUES)))
    if e["source_type"] in ("DERIVED_HELPER_OUTPUT", "HUMAN_REPORT") and e["raw_api_response"] != "RAW_UNAVAILABLE":
        problems.append(w + ": helper output and human reports are RAW_UNAVAILABLE")
    if e["raw_api_response"] == "RAW_FIELD_ONLY" and e["source_type"] != "API_TRANSCRIBED":
        problems.append(w + ": RAW_FIELD_ONLY only for the transcribed GitHub supplement")
    if e["completeness"] not in COMPLETENESS:
        problems.append(w + ": completeness must be one of {0} (no legacy record is COMPLETE)".format(sorted(COMPLETENESS)))
    files = e["source_files"]
    if not isinstance(files, list):
        problems.append(w + ": source_files must be a list")
        files = []
    for f in files:
        p = _keys(f, FILE_KEYS, w + " file")
        if p:
            problems += p
            continue
        if f["present"] is not (f["current_sha256"] is not None) or (f["current_sha256"] is not None and not _SHA64.match(f["current_sha256"])):
            problems.append(w + ": file {0} must have a sha256 exactly when present".format(f["path"]))
        if not isinstance(f["path"], str) or f["path"].startswith("/") or ".." in f["path"].split("/"):
            problems.append(w + ": source path must be repository-relative")
    if e["source_type"] == "HUMAN_REPORT":
        if files or e["completeness"] != "NOT_CAPTURED" or e["provenance_assurance"] != "HUMAN_REPORTED":
            problems.append(w + ": a human report has no source file, is NOT_CAPTURED and HUMAN_REPORTED")
    elif not files:
        problems.append(w + ": a record other than a human report names its source file(s)")
    missing = any(not f.get("present") for f in files if isinstance(f, dict))
    if missing and e["completeness"] != "SOURCE_MISSING":
        problems.append(w + ": a missing source file makes the entry SOURCE_MISSING")
    h = e["historical_hash"]
    p = _keys(h, HIST_KEYS, w + " historical_hash")
    if p:
        problems += p
    else:
        if h["status"] not in HIST_STATUSES or h["kind"] not in HIST_KINDS:
            problems.append(w + ": unknown historical hash status or kind")
        if (h["kind"] == "none") != (h["status"] == "HISTORICAL_INTEGRITY_NOT_PROVEN") or (h["kind"] == "none") != (not h["values"]):
            problems.append(w + ": without a recorded hash the status is HISTORICAL_INTEGRITY_NOT_PROVEN, and only then")
    lim = e["traceability_limitations"]
    if not isinstance(lim, list):
        problems.append(w + ": traceability_limitations must be a list")
        lim = []
    needed = []
    if e["raw_api_response"] == "RAW_UNAVAILABLE":
        needed.append("RAW_UNAVAILABLE")
    if isinstance(h, dict) and h.get("status") != "HISTORICAL_HASH_MATCHES":
        needed.append("HISTORICAL_INTEGRITY_NOT_PROVEN")
    if e["source_type"] in ("DERIVED_HELPER_OUTPUT", "HELPER_CODE"):
        needed.append("HELPER_REVISION_UNKNOWN")
    problems += ["{0}: limitation {1} must be recorded".format(w, n) for n in needed if n not in lim]
    hc = e["historical_classification"]
    if not isinstance(hc, dict) or hc.get("index_status") not in INDEX_STATUSES:
        problems.append(w + ": historical_classification.index_status unknown")
    return problems


def _subject_problems(subjects: Any, ids: FrozenSet[str]) -> List[str]:
    if not isinstance(subjects, list):
        return ["subjects: must be a list"]
    problems: List[str] = []
    by = {}
    for s in subjects:
        p = _keys(s, SUBJECT_KEYS, "subject {0}".format(s.get("subject") if isinstance(s, dict) else s))
        if p:
            problems += p
            continue
        by[s["subject"]] = s
        problems += ["subject {0}: unknown evidence id {1}".format(s["subject"], i) for i in s["evidence_ids"] if i not in ids]
    lock = registry.PHASE1_LOCKED["phase1-app-demo-s7"]
    for name, want in REQUIRED_SUBJECTS.items():
        s = by.get(name)
        if s is None:
            problems.append("subject {0}: missing".format(name))
            continue
        if s["phase1_result"] != want:
            problems.append("subject {0}: Phase 1 result is {1}, the final acceptance fixed {2}".format(name, s["phase1_result"], want))
        if name in lock["scenarios"] and lock["scenarios"][name] != s["phase1_result"]:
            problems.append("subject {0}: differs from the registry's locked scenario result".format(name))
    for subject, axis, status in lock["classifications"]:
        s = by.get(subject)
        if s is not None and s["axes"].get(axis) != status:
            problems.append("subject {0}: axis {1} is {2!r}, Phase 1 fixed {3}".format(subject, axis, s["axes"].get(axis), status))
    return problems


def map_problems(doc: Any) -> List[str]:
    """Every problem with the map document; empty means valid. No filesystem access."""
    problems = _keys(doc, TOP_KEYS, "map")
    if problems:
        return problems
    if doc["map_schema_version"] != MAP_SCHEMA_VERSION or doc["map_id"] != "phase1-legacy-evidence-map":
        problems.append("map: unknown schema version or id")
    if doc["is_reevaluation"] is not False:
        problems.append("map: is_reevaluation must be false (the map quotes Phase 1, it does not re-decide it)")
    if doc["historical_helper_revision"] != "UNKNOWN":
        problems.append("map: the Phase 1 helper revision is UNKNOWN")
    entries = doc["entries"] if isinstance(doc["entries"], list) else []
    ids = [str(e.get("legacy_evidence_id")) for e in entries if isinstance(e, dict)]
    problems += ["map: duplicate id {0}".format(i) for i in sorted({i for i in ids if ids.count(i) > 1})]
    problems += ["map: required id {0} is not mapped".format(i) for i in sorted(REQUIRED_IDS - set(ids))]
    problems += ["map: no entry with prefix {0}".format(p) for p in REQUIRED_PREFIXES if not any(str(i).startswith(p) for i in ids)]
    for e in entries:
        problems += _entry_problems(e)
    problems += _subject_problems(doc["subjects"], frozenset(i for i in ids if isinstance(i, str)))
    return problems


def load_map(path: Path = MAP_PATH) -> Dict[str, Any]:
    doc = registry.parse_definition_bytes(path.read_bytes())
    problems = map_problems(doc)
    if problems:
        raise LegacyMapError(problems)
    return doc


def _sha256_file(path: Path) -> Optional[str]:
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_SOURCE_BYTES:
            return None
        h = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
        return h.hexdigest()
    finally:
        os.close(fd)


def current_state(doc: Mapping[str, Any], repo_root: Path) -> Dict[str, Any]:
    """Read-only re-check of every source file. Per file: MATCH / CHANGED / SOURCE_MISSING."""
    rows = []
    for e in doc["entries"]:
        for f in e["source_files"]:
            got = _sha256_file(repo_root / f["path"])
            status = "SOURCE_MISSING" if got is None else ("MATCH" if got == f["current_sha256"] else "CHANGED")
            if f["current_sha256"] is None and got is not None:
                status = "APPEARED_AFTER_MAPPING"
            rows.append({"legacy_evidence_id": e["legacy_evidence_id"], "path": f["path"], "status": status})
        h = e["historical_hash"]
        if h["kind"] == "recorded_sha256":
            for path, value in sorted(h["values"].items()):
                got = _sha256_file(repo_root / path)
                rows.append({"legacy_evidence_id": e["legacy_evidence_id"], "path": path, "status":
                             "SOURCE_MISSING" if got is None else ("HISTORICAL_MATCH" if got == value else "HISTORICAL_MISMATCH")})
    statuses = {r["status"] for r in rows}
    return {"files": rows, "all_match": statuses <= {"MATCH", "HISTORICAL_MATCH"},
            "missing": sorted({r["legacy_evidence_id"] for r in rows if r["status"] == "SOURCE_MISSING"}),
            "changed": sorted({r["legacy_evidence_id"] for r in rows if r["status"] in ("CHANGED", "HISTORICAL_MISMATCH")})}


def traceability_summary(doc: Mapping[str, Any], state: Mapping[str, Any]) -> Dict[str, Any]:
    """M1-10 in two separate parts: (a) gaps are traced correctly, (b) the raw evidence of the time can be reached."""
    entries = doc["entries"]
    raw_reachable = [e["legacy_evidence_id"] for e in entries if e["raw_api_response"] not in ("RAW_UNAVAILABLE", "NOT_APPLICABLE")]
    unavailable = [e["legacy_evidence_id"] for e in entries if e["raw_api_response"] == "RAW_UNAVAILABLE"]
    gaps_traced = not map_problems(doc) and not state["changed"]
    return {
        "gap_traceability": "PASS" if gaps_traced and not state["missing"] else ("NOT_PROVEN" if not state["changed"] else "FAILED"),
        "gap_traceability_note": "every required id is mapped, its limitations recorded and its current files re-hashed",
        "historical_raw_reachability": "NOT_PROVEN",
        "historical_raw_note": "{0} entries are RAW_UNAVAILABLE; {1} carry only a transcribed content field; no Phase 1 raw API body "
                               "exists".format(len(unavailable), len(raw_reachable)),
        "raw_unavailable_ids": sorted(unavailable), "raw_field_only_ids": sorted(raw_reachable),
        "historical_integrity_not_proven_ids": sorted(e["legacy_evidence_id"] for e in entries
                                                      if e["historical_hash"]["status"] == "HISTORICAL_INTEGRITY_NOT_PROVEN"),
        "missing_source_ids": state["missing"], "changed_source_ids": state["changed"],
    }

