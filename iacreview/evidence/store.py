"""Immutable Evidence Store: revisions of evidence that are never overwritten (Phase 2 M1 WP2-4, WP3-4).

Source: ``docs/v2/phase2/m1/wp0/m1-architecture-proposal.md`` §3-4 and §5-4,
WP0 helper audit HA-8 (Phase 1 overwrote part of its evidence) and rev2 §2
(revocations kept only in prose). Purpose: write each piece of evidence once,
bind it to a manifest of hashes, and chain the manifests so that a missing,
added or changed file, an interrupted write and a broken chain are all
detected.

Layout (flat, one directory per revision)::

    <root>/rev-0001/<evidence_id>.raw            raw bytes (absent when nothing was received)
    <root>/rev-0001/<evidence_id>.envelope.json  envelope (canonical JSON)
    <root>/rev-0001/MANIFEST.json                written last: seals the revision

Rules, all fail-closed:

* every file is created with ``O_CREAT | O_EXCL | O_NOFOLLOW`` relative to the
  revision directory opened with ``O_NOFOLLOW``: an existing file, a symbolic
  link and a path component swapped for a link are refused, never followed
* directories are ``0700``, files ``0600``; looser modes are reported
* an evidence id is unique across the whole store and is matched by
  :data:`iacreview.evidence.envelope.EVIDENCE_ID` (no separator, no ``..``)
* the store root must be a real directory strictly inside the containment base,
  with no symbolic link on the way
* a revision is sealed by writing ``MANIFEST.json.tmp`` and hard-linking it to
  ``MANIFEST.json`` (``link`` never replaces an existing file). A revision
  directory without a manifest is an interrupted (incomplete) bundle; no new
  revision is started while one exists
* each manifest records the previous revision id and the SHA-256 of the
  previous manifest's bytes
* nothing is stored unless the envelope is valid, its raw bytes match it, and
  :mod:`iacreview.evidence.secretgate` says ``CLEAN`` for the raw bytes, the
  envelope and the manifest

Recovery (WP3-4) never repairs, deletes or rewrites a broken revision. The
store produces a read-only diagnostic (:meth:`EvidenceStore.diagnose`); a Human
decides; only with an approval bound to the exact on-disk state of the broken
revision (its *state digest*) does :meth:`EvidenceStore.quarantine_latest`
record a QUARANTINE in a new revision. A quarantined revision stays on disk,
its evidence is unusable, and any later change to it breaks the chain again.

Every problem is also a structured :class:`Finding` with the integrity check id
it belongs to (V1-V4, V8, W1, W3, W5; see :mod:`iacreview.evidence.integrity`).

What hashes do not prove (``docs/v2/phase2/m1/wp2/wp2-architecture-note.md`` §5-1):
someone with write access to the store can rewrite every file and recompute
every hash and every chain link; the store has no signature, no external
timestamp and no write-once medium.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from iacreview.evidence import envelope as env
from iacreview.evidence import secretgate
from iacreview.evidence.collector import CapturedEvidence, utc_stamp

STORE_FORMAT = "iacreview.evidence.store/1"
MANIFEST_SCHEMA_VERSION = 1
MANIFEST = "MANIFEST.json"
MANIFEST_TMP = "MANIFEST.json.tmp"
DIR_MODE = 0o700
FILE_MODE = 0o600
_REV = re.compile(r"^rev-([0-9]{4})$")
MAX_REVISIONS = 9999
MAX_FILE_BYTES = 64 * 1024 * 1024
MANIFEST_KEYS = frozenset({
    "manifest_schema_version", "store_format", "revision", "revision_id", "previous_revision_id",
    "previous_manifest_sha256", "reason", "sealed_at", "sealed_by_tool_version", "entries", "entry_count",
})
ENTRY_KEYS = frozenset({
    "evidence_id", "envelope_file", "envelope_sha256", "envelope_length", "raw_file", "raw_sha256", "raw_length",
    "source_type", "completeness_status",
})

#: Quarantine records: HUMAN evidence whose raw bytes are this canonical JSON.
QUARANTINE_PREFIX = "quarantine-"
QUARANTINE_KEYS = frozenset({
    "record_type", "record_version", "quarantined_revision_id", "state_sha256", "diagnostic_sha256", "action",
    "approved_by_role", "approval_statement", "approved_at",
})

_OPEN_DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_CREATE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
_READ = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)


class StoreError(Exception):
    """The store refused an operation. The message never contains evidence content."""


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _rev_id(n: int) -> str:
    return "rev-{0:04d}".format(n)


def _fsync_dir(fd: int) -> None:
    """Persist directory entries (created names). Ignored where the platform refuses fsync on a directory."""
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover - some filesystems do not support it; documented as a limit
        pass


def _write_exclusive(dir_fd: int, name: str, data: bytes) -> None:
    """Create ``name`` in the directory ``dir_fd``; refuse if it exists or is a link. File data is fsynced."""
    try:
        fd = os.open(name, _CREATE, FILE_MODE, dir_fd=dir_fd)
    except FileExistsError:
        raise StoreError("refusing to overwrite {0}".format(name)) from None
    except OSError as exc:
        raise StoreError("cannot create {0} ({1})".format(name, type(exc).__name__)) from None
    try:
        os.fchmod(fd, FILE_MODE)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_file(dir_fd: int, name: str) -> Tuple[Optional[bytes], Optional[str], int]:
    """(bytes, problem, mode). Refuses links and non-regular files."""
    try:
        fd = os.open(name, _READ, dir_fd=dir_fd)
    except FileNotFoundError:
        return None, "missing", 0
    except OSError as exc:
        return None, "cannot open ({0}; a symbolic link is refused)".format(type(exc).__name__), 0
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, "not a regular file", st.st_mode
        if st.st_size > MAX_FILE_BYTES:
            return None, "larger than {0} bytes".format(MAX_FILE_BYTES), st.st_mode
        chunks = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks), None, st.st_mode
    finally:
        os.close(fd)


def _open_dir(path: Path) -> int:
    try:
        return os.open(str(path), _OPEN_DIR)
    except OSError as exc:
        raise StoreError("cannot open directory {0} ({1}; a symbolic link is refused)".format(path.name, type(exc).__name__)) from None


def _scan_or_refuse(what: str, data: bytes) -> None:
    result = secretgate.scan(data)
    if not result.storable:
        raise secretgate.SecurityGateRefused(what, result)


def manifest_bytes(manifest: Dict[str, Any]) -> bytes:
    return env.canonical_bytes(manifest)


@dataclass(frozen=True)
class Finding:
    """One integrity problem: the check it belongs to, a stable code, a message (no content), an evidence id."""

    check_id: str
    code: str
    message: str
    evidence_id: Optional[str] = None


@dataclass
class RevisionReport:
    revision_id: str
    status: str  # VALID, INVALID, INCOMPLETE, QUARANTINED
    findings: List[Finding] = field(default_factory=list)
    chain_findings: List[Finding] = field(default_factory=list)
    manifest: Optional[Dict[str, Any]] = None
    manifest_sha256: Optional[str] = None
    state_sha256: Optional[str] = None
    envelopes: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    quarantine_records: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def add(self, check: str, code: str, message: str, evidence_id: Optional[str] = None) -> None:
        self.findings.append(Finding(check, code, message, evidence_id))

    @property
    def problems(self) -> List[str]:
        return [f.message for f in self.findings + self.chain_findings]

    @property
    def all_findings(self) -> List[Finding]:
        return self.findings + self.chain_findings


@dataclass
class StoreReport:
    """Result of :meth:`EvidenceStore.verify`. ``verified_at`` is the verification time, not a capture time."""

    verified_at: str
    revisions: List[RevisionReport]
    findings: List[Finding]

    @property
    def problems(self) -> List[str]:
        return [f.message for f in self.findings]

    @property
    def valid(self) -> bool:
        return not self.findings and all(r.status in ("VALID", "QUARANTINED") for r in self.revisions)

    def find(self, evidence_id: str) -> Optional[Tuple[RevisionReport, Dict[str, Any]]]:
        """Evidence of a VALID revision only: a quarantined revision's evidence is never returned."""
        for rev in self.revisions:
            if rev.status == "VALID" and evidence_id in rev.envelopes:
                return rev, rev.envelopes[evidence_id]
        return None

    def located(self, evidence_id: str) -> Optional[RevisionReport]:
        """The revision that holds ``evidence_id`` whatever its status (for diagnostics)."""
        for rev in self.revisions:
            if evidence_id in rev.envelopes:
                return rev
        return None

    def unusable_evidence_ids(self) -> List[str]:
        if not self.valid:
            return sorted({eid for r in self.revisions for eid in r.envelopes})
        return sorted({eid for r in self.revisions if r.status != "VALID" for eid in r.envelopes})


def _state_digest(dir_fd: int, revision_id: str) -> str:
    """SHA-256 of the on-disk state of a revision: every name, its kind, size and content hash. Links are not followed."""
    items: List[Dict[str, Any]] = []
    with os.scandir(dir_fd) as it:
        names = sorted((e.name, e.is_symlink(), e.is_dir(follow_symlinks=False)) for e in it)
    for name, is_link, is_dir in names:
        if is_link:
            items.append({"name": name, "kind": "link"})
        elif is_dir:
            items.append({"name": name, "kind": "dir"})
        else:
            data, problem, _ = _read_file(dir_fd, name)
            items.append({"name": name, "kind": "file", "sha256": env.sha256_hex(data) if data is not None else None,
                          "size": len(data) if data is not None else None, "problem": problem})
    return env.sha256_hex(json.dumps({"revision_id": revision_id, "entries": items}, sort_keys=True).encode("ascii"))


def quarantine_record_bytes(record: Dict[str, Any]) -> bytes:
    return env.canonical_bytes(record)


@dataclass(frozen=True)
class QuarantineApproval:
    """A Human's decision to quarantine one broken revision, bound to its exact state and diagnostic."""

    quarantined_revision_id: str
    state_sha256: str
    diagnostic_sha256: str
    approved_by_role: str
    approval_statement: str


class EvidenceStore:
    """An evidence store rooted at ``root``, which must lie strictly inside ``containment_base``."""

    def __init__(self, root: Path, containment_base: Path, now: Callable[[], datetime.datetime] = _now) -> None:
        self.now = now
        base = Path(containment_base)
        if not base.is_absolute() or base.is_symlink() or not base.is_dir():
            raise StoreError("containment base must be an existing absolute directory, not a link")
        base_real = Path(os.path.realpath(str(base)))
        root = Path(root)
        if not root.is_absolute():
            root = base / root
        if ".." in root.parts:
            raise StoreError("store root must not contain '..'")
        try:
            rel = root.relative_to(base)
        except ValueError:
            raise StoreError("store root is outside the containment base") from None
        if not rel.parts:
            raise StoreError("store root must be strictly inside the containment base")
        current = base
        for part in rel.parts:
            current = current / part
            if current.is_symlink():
                raise StoreError("store root path contains a symbolic link ({0})".format(part))
            if current.exists() and not current.is_dir():
                raise StoreError("store root path component is not a directory ({0})".format(part))
        if not root.parent.is_dir():
            raise StoreError("the parent of the store root must exist")
        if not root.exists():
            os.mkdir(str(root), DIR_MODE)
            os.chmod(str(root), DIR_MODE)
            parent_fd = _open_dir(root.parent)
            try:
                _fsync_dir(parent_fd)
            finally:
                os.close(parent_fd)
        try:
            Path(os.path.realpath(str(root))).relative_to(base_real)
        except ValueError:
            raise StoreError("store root resolves outside the containment base") from None
        self.root = root

    # -- listing ------------------------------------------------------------------------------------

    def _entries(self) -> Tuple[List[Tuple[int, str]], List[Finding]]:
        """Revision directories (number, name) sorted, and findings about other entries."""
        findings: List[Finding] = []
        revs: List[Tuple[int, str]] = []
        fd = _open_dir(self.root)
        try:
            with os.scandir(fd) as it:
                for entry in it:
                    m = _REV.match(entry.name)
                    if entry.is_symlink():
                        findings.append(Finding("V2", "link_in_store_root", "{0}: symbolic link in the store root".format(entry.name)))
                    elif not m or not entry.is_dir(follow_symlinks=False):
                        findings.append(Finding("V2", "unexpected_store_entry", "{0}: unexpected entry in the store root".format(entry.name)))
                    else:
                        revs.append((int(m.group(1)), entry.name))
        finally:
            os.close(fd)
        return sorted(revs), findings

    # -- verification ------------------------------------------------------------------------------

    def verify(self) -> StoreReport:
        revs, findings = self._entries()
        reports: List[RevisionReport] = []
        seen: Set[str] = set()
        previous: Optional[RevisionReport] = None
        for expected, (n, name) in enumerate(revs, start=1):
            if n != expected:
                findings.append(Finding("V3", "revision_gap",
                                        "revision numbers are not contiguous: {0} where {1} was expected".format(name, _rev_id(expected))))
            report = self._verify_revision(name, n, previous, seen)
            if previous is not None:
                self._resolve_quarantine(previous, report)
            reports.append(report)
            previous = report
        for r in reports[:-1]:
            if r.status == "INCOMPLETE":
                findings.append(Finding("W3", "unsealed_revision_followed",
                                        "{0}: an unsealed revision is followed by a later revision".format(r.revision_id)))
        return StoreReport(utc_stamp(self.now()), reports, findings)

    @staticmethod
    def _resolve_quarantine(previous: RevisionReport, report: RevisionReport) -> None:
        """A non-VALID revision becomes QUARANTINED only if the next revision records a quarantine for it bound to its
        current state digest and chains to that digest. A quarantine record for a VALID revision is itself an error."""
        record = report.quarantine_records.get(previous.revision_id)
        for named in sorted(set(report.quarantine_records) - {previous.revision_id}):
            report.add("V8", "quarantine_not_of_previous", "quarantine record for {0}, which is not the previous revision".format(named))
        if record is None:
            return
        if previous.status in ("VALID", "QUARANTINED"):
            report.add("V8", "quarantine_of_valid_revision", "quarantine record for {0}, which is {1}".format(
                previous.revision_id, previous.status))
        else:
            m = report.manifest or {}
            if record.get("state_sha256") != previous.state_sha256 or m.get("previous_manifest_sha256") != previous.state_sha256 \
                    or m.get("previous_revision_id") != previous.revision_id:
                report.add("V8", "quarantine_state_mismatch",
                           "quarantine of {0} does not match its current state (changed after approval?)".format(previous.revision_id))
            else:
                previous.status = "QUARANTINED"
                report.chain_findings = []
        report.status = "VALID" if not report.all_findings else ("INCOMPLETE" if report.status == "INCOMPLETE" else "INVALID")

    def _verify_revision(self, name: str, number: int, previous: Optional[RevisionReport], seen: Set[str]) -> RevisionReport:
        report = RevisionReport(name, "VALID")
        try:
            fd = _open_dir(self.root / name)
        except StoreError as exc:
            report.add("V2", "revision_dir_unreadable", str(exc))
            report.status = "INVALID"
            return report
        try:
            report.state_sha256 = _state_digest(fd, name)
            st = os.fstat(fd)
            if stat.S_IMODE(st.st_mode) & 0o077:
                report.add("W5", "permissions", "directory permissions wider than 0700")
            with os.scandir(fd) as it:
                names = {entry.name: entry.is_symlink() for entry in it}
            for n in sorted(n for n, is_link in names.items() if is_link):
                report.add("V2", "link_in_revision", "{0}: symbolic link".format(n))
            if MANIFEST_TMP in names:
                report.status = "INCOMPLETE"
                report.add("W3", "interrupted_seal", "an interrupted seal left {0}".format(MANIFEST_TMP))
            if MANIFEST not in names:
                report.status = "INCOMPLETE"
                report.add("W3", "manifest_missing", "no {0}: the revision was never sealed (interrupted or in progress)".format(MANIFEST))
                # Envelopes written before the interruption are listed (never usable) so that a named id is
                # reported as held by this revision instead of "missing".
                for n in sorted(names):
                    if n.endswith(".envelope.json") and not names[n]:
                        data, _, _ = _read_file(fd, n)
                        try:
                            doc = env.parse_envelope_bytes(data) if data is not None else None
                        except (ValueError, UnicodeDecodeError):
                            doc = None
                        if isinstance(doc, dict) and doc.get("evidence_id") == n[: -len(".envelope.json")]:
                            report.envelopes[n[: -len(".envelope.json")]] = doc
                return report
            data, problem, mode = _read_file(fd, MANIFEST)
            if data is None:
                report.add("V1", "manifest_unreadable", "{0}: {1}".format(MANIFEST, problem))
                report.status = "INVALID"
                return report
            report.manifest_sha256 = env.sha256_hex(data)
            if stat.S_IMODE(mode) & 0o077:
                report.add("W5", "permissions", "{0}: permissions wider than 0600".format(MANIFEST))
            try:
                manifest = env.parse_envelope_bytes(data)
            except (ValueError, UnicodeDecodeError):
                report.add("V1", "manifest_not_json", "{0}: not strict JSON".format(MANIFEST))
                report.status = "INVALID"
                return report
            report.manifest = manifest
            self._manifest_problems(report, manifest, name, number, previous)
            if data != manifest_bytes(manifest):
                report.add("V1", "manifest_not_canonical", "{0}: not in canonical form".format(MANIFEST))
            listed = {MANIFEST}
            entries: List[Any] = manifest["entries"] if isinstance(manifest.get("entries"), list) else []
            for entry in entries:
                listed |= self._verify_entry(fd, entry, report, seen)
            for n in sorted(set(names) - listed - {MANIFEST_TMP}):
                report.add("V2", "unlisted_file", "{0}: file not listed in the manifest".format(n))
        finally:
            os.close(fd)
        if report.status == "VALID" and report.all_findings:
            report.status = "INVALID"
        return report

    def _manifest_problems(self, report: RevisionReport, m: Dict[str, Any], name: str, number: int,
                           previous: Optional[RevisionReport]) -> None:
        missing = sorted(MANIFEST_KEYS - set(m))
        unknown = sorted(set(m) - MANIFEST_KEYS)
        if missing or unknown:
            report.add("V1", "manifest_fields", "manifest: missing field(s) {0}, unknown field(s) {1}".format(missing, unknown))
            return
        if m["manifest_schema_version"] != MANIFEST_SCHEMA_VERSION:
            report.add("V1", "manifest_schema_version",
                       "manifest: schema version {0!r} is not {1}".format(m["manifest_schema_version"], MANIFEST_SCHEMA_VERSION))
        if m["store_format"] != STORE_FORMAT:
            report.add("V1", "store_format", "manifest: unknown store format")
        if m["revision"] != number or m["revision_id"] != name:
            report.add("V3", "revision_mismatch",
                       "manifest: revision {0!r}/{1!r} does not match the directory {2}".format(m["revision"], m["revision_id"], name))
        chain = report.chain_findings
        if previous is None:
            if m["previous_revision_id"] is not None or m["previous_manifest_sha256"] is not None:
                report.add("V3", "first_revision_names_previous", "manifest: the first revision must not name a previous revision")
        else:
            if m["previous_revision_id"] != previous.revision_id:
                chain.append(Finding("V3", "previous_revision_mismatch",
                                     "manifest: previous revision {0!r}, expected {1}".format(m["previous_revision_id"], previous.revision_id)))
            if previous.manifest_sha256 is None or m["previous_manifest_sha256"] != previous.manifest_sha256:
                chain.append(Finding("V3", "previous_manifest_sha256_mismatch",
                                     "manifest: previous manifest sha256 does not match {0}".format(previous.revision_id)))
            if previous.status != "VALID":
                chain.append(Finding("V3", "previous_revision_not_valid",
                                     "manifest: the previous revision {0} is {1}".format(previous.revision_id, previous.status)))
        if not isinstance(m["entries"], list) or not m["entries"]:
            report.add("V1", "manifest_entries", "manifest: entries must be a non-empty list")
        elif m["entry_count"] != len(m["entries"]):
            report.add("V1", "manifest_entry_count", "manifest: entry_count does not match the entries")
        elif [str(e.get("evidence_id")) for e in m["entries"] if isinstance(e, dict)] != sorted(
                str(e.get("evidence_id")) for e in m["entries"] if isinstance(e, dict)):
            report.add("V1", "manifest_entries_unsorted", "manifest: entries are not sorted by evidence id")

    def _verify_entry(self, fd: int, entry: Any, report: RevisionReport, seen: Set[str]) -> Set[str]:
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
            report.add("V1", "manifest_entry_fields", "manifest entry: wrong fields")
            return set()
        eid = entry["evidence_id"]
        if not (isinstance(eid, str) and env.EVIDENCE_ID.match(eid)):
            report.add("V1", "manifest_entry_id", "manifest entry: invalid evidence id")
            return set()
        if eid in seen:
            report.add("W1", "duplicate_evidence_id", "{0}: duplicate evidence id".format(eid), eid)
        seen.add(eid)
        if entry["envelope_file"] != eid + ".envelope.json" or entry["raw_file"] not in (None, eid + ".raw"):
            report.add("V1", "manifest_file_names", "{0}: unexpected file names in the manifest".format(eid), eid)
            return set()
        files = {entry["envelope_file"]} | ({entry["raw_file"]} if entry["raw_file"] else set())
        env_data, problem, mode = _read_file(fd, entry["envelope_file"])
        if env_data is None:
            report.add("V1", "envelope_unreadable", "{0}: envelope {1}".format(eid, problem), eid)
            return files
        if stat.S_IMODE(mode) & 0o077:
            report.add("W5", "permissions", "{0}: envelope permissions wider than 0600".format(eid), eid)
        if env.sha256_hex(env_data) != entry["envelope_sha256"] or len(env_data) != entry["envelope_length"]:
            report.add("V1", "envelope_hash_mismatch", "{0}: envelope differs from the manifest (sha256 or length)".format(eid), eid)
        raw: Optional[bytes] = None
        if entry["raw_file"]:
            raw, problem, mode = _read_file(fd, entry["raw_file"])
            if raw is None:
                report.add("V1", "raw_unreadable", "{0}: raw content {1}".format(eid, problem), eid)
            else:
                if stat.S_IMODE(mode) & 0o077:
                    report.add("W5", "permissions", "{0}: raw permissions wider than 0600".format(eid), eid)
                if env.sha256_hex(raw) != entry["raw_sha256"] or len(raw) != entry["raw_length"]:
                    report.add("V1", "raw_hash_mismatch", "{0}: raw content differs from the manifest (sha256 or length)".format(eid), eid)
        elif entry["raw_sha256"] is not None or entry["raw_length"] is not None:
            report.add("V1", "raw_file_not_named", "{0}: the manifest records raw content but names no raw file".format(eid), eid)
        try:
            envelope = env.parse_envelope_bytes(env_data)
        except (ValueError, UnicodeDecodeError):
            report.add("V4", "envelope_not_json", "{0}: envelope is not strict JSON".format(eid), eid)
            return files
        for p in env.envelope_problems(envelope, raw, raw_supplied=raw is not None or not entry["raw_file"]):
            check = "V1" if p.startswith("raw content") else "V4"
            report.add(check, "envelope_invalid", "{0}: {1}".format(eid, p), eid)
        if envelope.get("evidence_id") != eid or envelope.get("raw_content_sha256") != entry["raw_sha256"]:
            report.add("V1", "envelope_entry_mismatch", "{0}: the envelope does not match its manifest entry".format(eid), eid)
        if (envelope.get("source_type"), envelope.get("completeness_status")) != (entry["source_type"], entry["completeness_status"]):
            report.add("V1", "envelope_entry_mismatch",
                       "{0}: source type or completeness differ between envelope and manifest".format(eid), eid)
        report.envelopes[eid] = envelope
        if eid.startswith(QUARANTINE_PREFIX) and raw is not None:
            record = _parse_quarantine(raw, envelope)
            if record is None:
                report.add("V8", "quarantine_record_invalid", "{0}: invalid quarantine record".format(eid), eid)
            else:
                report.quarantine_records[record["quarantined_revision_id"]] = record
        return files

    # -- reading ----------------------------------------------------------------------------------

    def read_raw(self, report: StoreReport, evidence_id: str) -> Optional[bytes]:
        """Raw bytes of a usable evidence, re-read and re-checked against its envelope; None otherwise."""
        if not report.valid:
            return None
        found = report.find(evidence_id)
        if found is None or found[1]["raw_content_sha256"] is None:
            return None
        fd = _open_dir(self.root / found[0].revision_id)
        try:
            data, _, _ = _read_file(fd, evidence_id + ".raw")
        finally:
            os.close(fd)
        if data is None or env.sha256_hex(data) != found[1]["raw_content_sha256"]:
            return None
        return data

    # -- diagnostics and recovery ----------------------------------------------------------------

    def diagnose(self) -> Dict[str, Any]:
        """Read-only diagnostic of the whole store. ``diagnostic_sha256`` covers everything except ``generated_at``."""
        report = self.verify()
        body = {
            "diagnostic_version": 1,
            "store_valid": report.valid,
            "store_findings": [f.__dict__ for f in report.findings],
            "revisions": [{"revision_id": r.revision_id, "status": r.status, "state_sha256": r.state_sha256,
                           "findings": [f.__dict__ for f in r.all_findings]} for r in report.revisions],
            "unusable_evidence_ids": report.unusable_evidence_ids(),
            "recommended_action": "none" if report.valid else
            "do not use this store; a Human reviews this diagnostic and, if approved, records a QUARANTINE of the latest broken "
            "revision in a new revision (quarantine_latest). Nothing is repaired, deleted or rewritten automatically",
        }
        digest = env.sha256_hex(json.dumps(body, sort_keys=True, ensure_ascii=True).encode("ascii"))
        return dict(body, diagnostic_sha256=digest, generated_at=report.verified_at)

    def write_diagnostic(self, diagnostic: Dict[str, Any], path: Path) -> None:
        """Write a diagnostic outside the store, exclusively (never overwrites, never inside the store root)."""
        target = Path(os.path.realpath(str(Path(path).parent))) / Path(path).name
        root_real = Path(os.path.realpath(str(self.root)))
        if target == root_real or root_real in target.parents:
            raise StoreError("a diagnostic is never written inside the store")
        fd = _open_dir(target.parent)
        try:
            _write_exclusive(fd, target.name, env.canonical_bytes(diagnostic))
        finally:
            os.close(fd)

    def quarantine_latest(self, approval: QuarantineApproval) -> str:
        """Record a Human-approved QUARANTINE of the latest revision in a new revision; returns its manifest sha256.

        Refused unless: the latest revision is the only broken one, the approval names it, and the approval's state and
        diagnostic digests equal the current ones (a stale or mismatched approval is refused).
        """
        report = self.verify()
        if not report.revisions or report.revisions[-1].status in ("VALID", "QUARANTINED"):
            raise StoreError("nothing to quarantine: the latest revision is not broken")
        broken = report.revisions[-1]
        if report.findings or any(r.status not in ("VALID", "QUARANTINED") for r in report.revisions[:-1]):
            raise StoreError("only the latest revision can be quarantined; earlier problems need a Human decision outside the store")
        diagnostic = self.diagnose()
        if approval.quarantined_revision_id != broken.revision_id:
            raise StoreError("the approval names {0}, the broken revision is {1}".format(approval.quarantined_revision_id, broken.revision_id))
        if approval.state_sha256 != broken.state_sha256 or approval.diagnostic_sha256 != diagnostic["diagnostic_sha256"]:
            raise StoreError("the approval does not match the current state of {0} (stale approval)".format(broken.revision_id))
        for text in (approval.approved_by_role, approval.approval_statement):
            if not isinstance(text, str) or not text.strip() or len(text) > 300:
                raise StoreError("the approval needs a role and a statement of at most 300 characters")
        record = {
            "record_type": "revision_quarantine", "record_version": 1, "quarantined_revision_id": broken.revision_id,
            "state_sha256": broken.state_sha256, "diagnostic_sha256": diagnostic["diagnostic_sha256"], "action": "QUARANTINE",
            "approved_by_role": approval.approved_by_role, "approval_statement": approval.approval_statement,
            "approved_at": utc_stamp(self.now()),
        }
        raw = quarantine_record_bytes(record)
        number = len(report.revisions) + 1
        eid = QUARANTINE_PREFIX + broken.revision_id
        captured = _human_record(eid, raw, utc_stamp(self.now()), broken.revision_id)
        stand_in = RevisionReport(broken.revision_id, broken.status, manifest_sha256=broken.state_sha256)
        used = {e for r in report.revisions for e in r.envelopes}
        writer = RevisionWriter(self, number, stand_in, used, "quarantine of {0} (approved)".format(broken.revision_id))
        writer.add(captured)
        return writer.seal()

    # -- writing ----------------------------------------------------------------------------------

    def begin_revision(self, reason: str) -> "RevisionWriter":
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
            raise StoreError("a revision needs a reason of at most 500 characters")
        report = self.verify()
        if not report.valid:
            raise StoreError("the store does not verify; no new revision until a Human resolves: {0}".format(
                "; ".join(report.problems + [p for r in report.revisions for p in r.problems])[:500]))
        number = len(report.revisions) + 1
        if number > MAX_REVISIONS:
            raise StoreError("revision limit reached")
        previous = report.revisions[-1] if report.revisions else None
        if previous is not None and previous.status == "QUARANTINED":  # pragma: no cover - a quarantine is always followed
            raise StoreError("the latest revision is quarantined")
        used = {eid for r in report.revisions for eid in r.envelopes}
        return RevisionWriter(self, number, previous, used, reason)

    def _create_revision_dir(self, number: int) -> Path:
        path = self.root / _rev_id(number)
        try:
            os.mkdir(str(path), DIR_MODE)
        except FileExistsError:
            raise StoreError("refusing to overwrite revision {0}".format(path.name)) from None
        os.chmod(str(path), DIR_MODE)
        root_fd = _open_dir(self.root)
        try:
            _fsync_dir(root_fd)
        finally:
            os.close(root_fd)
        return path


def _parse_quarantine(raw: bytes, envelope: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        record = env.parse_envelope_bytes(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    if set(record) != QUARANTINE_KEYS or record["record_type"] != "revision_quarantine" or record["action"] != "QUARANTINE":
        return None
    if envelope.get("source_type") != "HUMAN" or raw != quarantine_record_bytes(record):
        return None
    if not (isinstance(record["quarantined_revision_id"], str) and _REV.match(record["quarantined_revision_id"])):
        return None
    if envelope.get("evidence_id") != QUARANTINE_PREFIX + record["quarantined_revision_id"]:
        return None
    return record


def _human_record(eid: str, raw: bytes, stamp: str, revision_id: str) -> CapturedEvidence:
    record: Dict[str, Any] = {
        "schema_version": env.ENVELOPE_SCHEMA_VERSION, "evidence_id": eid, "capture_id": eid, "source_type": "HUMAN",
        "source_locator": "human approval: quarantine of {0}".format(revision_id), "captured_at": stamp, "repository": None,
        "subject_commit_sha": None, "api": None, "http_status": None, "pagination_complete": None, "page": None,
        "raw_content_sha256": env.sha256_hex(raw), "raw_content_length": len(raw), "response_headers": {},
        "capture_tool_version": env.CAPTURE_TOOL_VERSION, "provenance_assurance": env.PROVENANCE_ASSURANCE["HUMAN"],
        "authenticity_verified": False, "security_scan_status": "CLEAN", "capture_errors": [], "completeness_status": "COMPLETE",
    }
    return CapturedEvidence(record, raw)


class RevisionWriter:
    """Adds evidence to one new revision, then seals it. Not reusable after :meth:`seal`."""

    def __init__(self, store: EvidenceStore, number: int, previous: Optional[RevisionReport], used: Set[str], reason: str) -> None:
        self.store = store
        self.reason = reason
        self.number = number
        self.revision_id = _rev_id(number)
        self.previous = previous
        self.used = set(used)
        self.entries: List[Dict[str, Any]] = []
        self.sealed = False
        self.path = store._create_revision_dir(number)

    def add(self, captured: CapturedEvidence) -> None:
        if self.sealed:
            raise StoreError("{0} is sealed; nothing can be added".format(self.revision_id))
        envelope, raw = captured.envelope, captured.raw
        problems = env.envelope_problems(envelope, raw, raw_supplied=True)
        if problems:
            raise StoreError("invalid evidence: " + "; ".join(problems)[:500])
        eid = str(envelope["evidence_id"])
        if eid in self.used:
            raise StoreError("duplicate evidence id {0}".format(eid))
        if raw is not None:
            if envelope["security_scan_status"] != "CLEAN":
                raise StoreError("{0}: raw content without a CLEAN security scan".format(eid))
            _scan_or_refuse(eid + " raw content", raw)
        env_data = env.canonical_bytes(envelope)
        _scan_or_refuse(eid + " envelope", env_data)
        fd = _open_dir(self.path)
        try:
            if raw is not None:
                _write_exclusive(fd, eid + ".raw", raw)
            _write_exclusive(fd, eid + ".envelope.json", env_data)
            _fsync_dir(fd)
        finally:
            os.close(fd)
        self.used.add(eid)
        self.entries.append({
            "evidence_id": eid, "envelope_file": eid + ".envelope.json", "envelope_sha256": env.sha256_hex(env_data),
            "envelope_length": len(env_data), "raw_file": eid + ".raw" if raw is not None else None,
            "raw_sha256": env.sha256_hex(raw) if raw is not None else None, "raw_length": len(raw) if raw is not None else None,
            "source_type": envelope["source_type"], "completeness_status": envelope["completeness_status"],
        })

    def seal(self) -> str:
        """Write the manifest; returns its sha256. The revision is immutable afterwards."""
        if self.sealed:
            raise StoreError("{0} is already sealed".format(self.revision_id))
        if not self.entries:
            raise StoreError("refusing to seal an empty revision")
        manifest = {
            "manifest_schema_version": MANIFEST_SCHEMA_VERSION, "store_format": STORE_FORMAT, "revision": self.number,
            "revision_id": self.revision_id, "previous_revision_id": self.previous.revision_id if self.previous else None,
            "previous_manifest_sha256": self.previous.manifest_sha256 if self.previous else None, "reason": self.reason,
            "sealed_at": utc_stamp(self.store.now()), "sealed_by_tool_version": env.CAPTURE_TOOL_VERSION,
            "entries": sorted(self.entries, key=lambda e: e["evidence_id"]), "entry_count": len(self.entries),
        }
        data = manifest_bytes(manifest)
        _scan_or_refuse(self.revision_id + " manifest", data)
        fd = _open_dir(self.path)
        try:
            _write_exclusive(fd, MANIFEST_TMP, data)
            _fsync_dir(fd)
            try:
                os.link(MANIFEST_TMP, MANIFEST, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            except FileExistsError:
                raise StoreError("refusing to overwrite {0} of {1}".format(MANIFEST, self.revision_id)) from None
            _fsync_dir(fd)
            os.unlink(MANIFEST_TMP, dir_fd=fd)
            _fsync_dir(fd)
        finally:
            os.close(fd)
        self.sealed = True
        return env.sha256_hex(data)
