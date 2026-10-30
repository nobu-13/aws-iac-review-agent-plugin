"""Chain Manifest reader (``iacreview.chain.manifest/1``) and safe reads below the chain root.

Source: ``docs/v2/phase2/m2/wp0/m2-schemas.md`` rev1 §1. The manifest is untrusted input. It is parsed
strictly (no duplicate key, no NaN / Infinity, no float, a size and depth limit, UTF-8), checked against
a closed schema, and its values are used as references only: no link takes a value of the manifest as
established without re-reading the artifact it names.

Locators are chain-root relative POSIX paths. Every component is opened with ``O_NOFOLLOW`` from a
directory descriptor, so neither ``..``, an absolute path nor a symbolic link can lead outside the root.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from iacreview.evidence import envelope as m1_envelope
from iacreview.remediation import report as remediation_report

MANIFEST_FORMAT = "iacreview.chain.manifest/1"
MAX_MANIFEST_BYTES = 256 * 1024
MAX_DEPTH = 16
MAX_LIST = 256

ACQUISITIONS = ("local_recompute", "local_import")  # "api_artifact" is not selectable in M2 (TC-01-04)
GATE_KINDS = ("contract_approval", "candidate_review", "merge_decision")

TOP_KEYS = ("manifest_format", "chain_id", "repository_id", "subject", "contract", "review", "verification",
            "gate_records", "github_evidence")

_CHAIN_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
_REPO_ID = re.compile(r"^r:[0-9a-f]{12}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^rev-[0-9]{4}$")
_SEGMENT = re.compile(r"^[A-Za-z0-9._-]{1,255}$")

_OPEN_DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_OPEN_FILE = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)


class ManifestError(Exception):
    """The manifest cannot be used. ``code`` is ``manifest_invalid``, ``manifest_unreadable`` or ``locator_outside_root``."""

    def __init__(self, code: str, field: str = "") -> None:
        super().__init__("{0} ({1})".format(code, field or "-"))
        self.code = code
        self.field = field


class ReadError(Exception):
    """A file below the chain root could not be read. ``kind``: ``missing``, ``too_large``, ``unreadable``, ``outside``."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


@dataclass(frozen=True)
class Manifest:
    """A manifest that passed the schema. ``doc`` is the parsed object; ``sha256`` is its canonical digest."""

    doc: Dict[str, Any]
    sha256: str


# ---------------------------------------------------------------------------
# Strict JSON
# ---------------------------------------------------------------------------


def _pairs(items: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in items:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _no_constant(name: str) -> Any:
    raise ValueError("non-finite number")


def _no_float(text: str) -> Any:
    raise ValueError("float")


def _depth(value: Any, level: int = 0) -> int:
    if level > MAX_DEPTH:
        return level
    if isinstance(value, dict):
        return max([_depth(v, level + 1) for v in value.values()] or [level + 1])
    if isinstance(value, list):
        return max([_depth(v, level + 1) for v in value] or [level + 1])
    return level


def strict_json(data: bytes, max_depth: Optional[int] = None) -> Any:
    """Parse UTF-8 JSON strictly. Raises ``ValueError`` on any violation (never a partial value)."""
    try:
        text = data.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_no_constant, parse_float=_no_float)
    except (UnicodeDecodeError, RecursionError) as exc:
        raise ValueError("not strict JSON") from exc
    if max_depth is not None and _depth(value) > max_depth:
        raise ValueError("too deep")
    return value


def canonical_sha256(value: Any) -> str:
    """SHA-256 of the canonical bytes (the Phase 1 report rule: sorted keys, ASCII, compact separators)."""
    return hashlib.sha256(remediation_report.canonical(value)).hexdigest()


# ---------------------------------------------------------------------------
# Safe reads below the chain root
# ---------------------------------------------------------------------------


def locator_is_safe(value: Any) -> bool:
    """A chain-root relative POSIX path of plain segments (no ``..``, ``.``, empty, ``\\``, NUL or absolute)."""
    if not isinstance(value, str) or not 0 < len(value) <= 1024:
        return False
    return all(seg not in (".", "..") and _SEGMENT.match(seg) is not None for seg in value.split("/"))


def _walk(root: Path, rel: str) -> Tuple[int, str]:
    """Open every directory of ``rel`` below ``root`` without following links; returns (dir fd, last name)."""
    if not locator_is_safe(rel):
        raise ReadError("outside")
    parts = rel.split("/")
    try:
        fd = os.open(str(root), _OPEN_DIR)
    except OSError:
        raise ReadError("unreadable") from None
    try:
        for part in parts[:-1]:
            try:
                nxt = os.open(part, _OPEN_DIR, dir_fd=fd)
            except FileNotFoundError:
                raise ReadError("missing") from None
            except OSError:
                raise ReadError("outside") from None  # a link or a non-directory component
            os.close(fd)
            fd = nxt
    except BaseException:
        os.close(fd)
        raise
    return fd, parts[-1]


def read_below(root: Path, rel: str, limit: int) -> bytes:
    """The bytes of the regular file ``rel`` below ``root``; raises :class:`ReadError`."""
    fd, name = _walk(root, rel)
    try:
        try:
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            raise ReadError("missing") from None
        except OSError:
            raise ReadError("unreadable") from None
        if not _is_regular(st.st_mode):
            raise ReadError("outside")
        if st.st_size > limit:
            raise ReadError("too_large")
        try:
            ffd = os.open(name, _OPEN_FILE, dir_fd=fd)
        except FileNotFoundError:
            raise ReadError("missing") from None
        except OSError:
            raise ReadError("outside") from None
        try:
            chunks, total = [], 0
            while True:
                chunk = os.read(ffd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise ReadError("too_large")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(ffd)
    finally:
        os.close(fd)


def directory_below(root: Path, rel: str) -> Optional[Path]:
    """``root / rel`` when it is a real directory reached without links; ``None`` when absent; raises ReadError('outside')."""
    fd, name = _walk(root, rel)
    try:
        try:
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError:
            raise ReadError("unreadable") from None
        if not _is_dir(st.st_mode):
            raise ReadError("outside")
        return root / rel
    finally:
        os.close(fd)


def _is_regular(mode: int) -> bool:
    return stat.S_ISREG(mode)


def _is_dir(mode: int) -> bool:
    return stat.S_ISDIR(mode)


def _probe_locator(root: Path, rel: str, field: str) -> None:
    """Pre-check of a locator: a link or a non-directory on the way is ``locator_outside_root``."""
    try:
        fd, name = _walk(root, rel)
    except ReadError as exc:
        if exc.kind == "outside":
            raise ManifestError("locator_outside_root", field) from None
        return  # a missing component is the link's business (artifact missing)
    try:
        try:
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except OSError:
            return
        if stat.S_ISLNK(st.st_mode):
            raise ManifestError("locator_outside_root", field)
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def _obj(value: Any, field: str, keys: Tuple[str, ...]) -> Dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ManifestError("manifest_invalid", field)
    return value


def _match(value: Any, pattern: "re.Pattern[str]", field: str) -> str:
    if not isinstance(value, str) or pattern.match(value) is None:
        raise ManifestError("manifest_invalid", field)
    return value


def _locator(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ManifestError("manifest_invalid", field)
    if not locator_is_safe(value):
        raise ManifestError("locator_outside_root", field)
    return value


def _file_ref(value: Any, field: str) -> Dict[str, str]:
    ref = _obj(value, field, ("locator", "sha256"))
    _locator(ref["locator"], field + ".locator")
    _match(ref["sha256"], _SHA256, field + ".sha256")
    return ref


def _list(value: Any, field: str, min_items: int) -> List[Any]:
    if not isinstance(value, list) or not min_items <= len(value) <= MAX_LIST:
        raise ManifestError("manifest_invalid", field)
    return value


def check_schema(doc: Any) -> Dict[str, Any]:
    """Raise :class:`ManifestError` unless ``doc`` is a Chain Manifest (closed schema, every level)."""
    _obj(doc, "", TOP_KEYS)
    if doc["manifest_format"] != MANIFEST_FORMAT:
        raise ManifestError("manifest_invalid", "manifest_format")
    _match(doc["chain_id"], _CHAIN_ID, "chain_id")
    _match(doc["repository_id"], _REPO_ID, "repository_id")
    subject = _obj(doc["subject"], "subject", ("base_commit", "head_commit"))
    for key in ("base_commit", "head_commit"):
        _match(subject[key], _COMMIT, "subject." + key)
    contract = _obj(doc["contract"], "contract", ("config_commit", "contract_path", "contract_sha256"))
    _match(contract["config_commit"], _COMMIT, "contract.config_commit")
    if not locator_is_safe(contract["contract_path"]):  # a repository path, same segment rules
        raise ManifestError("manifest_invalid", "contract.contract_path")
    _match(contract["contract_sha256"], _SHA256, "contract.contract_sha256")
    if doc["review"] is not None:
        review = _obj(doc["review"], "review", ("review_report", "finding_refs"))
        _file_ref(review["review_report"], "review.review_report")
        seen = set()
        for i, ref in enumerate(_list(review["finding_refs"], "review.finding_refs", 1)):
            field = "review.finding_refs[{0}]".format(i)
            ref = _obj(ref, field, ("finding_id", "identity_key_sha256", "finding_sha256"))
            fid = ref["finding_id"]
            if not isinstance(fid, int) or isinstance(fid, bool) or fid < 1 or fid in seen:
                raise ManifestError("manifest_invalid", field + ".finding_id")
            seen.add(fid)
            _match(ref["identity_key_sha256"], _SHA256, field + ".identity_key_sha256")
            _match(ref["finding_sha256"], _SHA256, field + ".finding_sha256")
    verification = _obj(doc["verification"], "verification", ("report", "payload_sha256", "acquisition"))
    _file_ref(verification["report"], "verification.report")
    _match(verification["payload_sha256"], _SHA256, "verification.payload_sha256")
    if verification["acquisition"] not in ACQUISITIONS:
        raise ManifestError("manifest_invalid", "verification.acquisition")
    for i, rec in enumerate(_list(doc["gate_records"], "gate_records", 0)):
        field = "gate_records[{0}]".format(i)
        rec = _obj(rec, field, ("locator", "sha256", "kind"))
        _locator(rec["locator"], field + ".locator")
        _match(rec["sha256"], _SHA256, field + ".sha256")
        if rec["kind"] not in GATE_KINDS:
            raise ManifestError("manifest_invalid", field + ".kind")
    if doc["github_evidence"] is not None:
        gh = _obj(doc["github_evidence"], "github_evidence", ("store_locator", "revision", "manifest_sha256", "evidence_ids"))
        _locator(gh["store_locator"], "github_evidence.store_locator")
        _match(gh["revision"], _REVISION, "github_evidence.revision")
        _match(gh["manifest_sha256"], _SHA256, "github_evidence.manifest_sha256")
        ids = _list(gh["evidence_ids"], "github_evidence.evidence_ids", 1)
        if len(set(map(str, ids))) != len(ids):
            raise ManifestError("manifest_invalid", "github_evidence.evidence_ids")
        for eid in ids:
            _match(eid, m1_envelope.EVIDENCE_ID, "github_evidence.evidence_ids")
    return doc


def locators(doc: Dict[str, Any]) -> List[Tuple[str, str]]:
    """(field, locator) of every chain-root path the manifest names."""
    out = [("verification.report", doc["verification"]["report"]["locator"])]
    if doc["review"] is not None:
        out.append(("review.review_report", doc["review"]["review_report"]["locator"]))
    out += [("gate_records[{0}]".format(i), r["locator"]) for i, r in enumerate(doc["gate_records"])]
    if doc["github_evidence"] is not None:
        out.append(("github_evidence.store_locator", doc["github_evidence"]["store_locator"]))
    return out


def load(path: Path) -> Manifest:
    """Read, parse and check the manifest at ``path`` (its directory is the chain root)."""
    root, name = path.parent, path.name
    try:
        data = read_below(root, name, MAX_MANIFEST_BYTES)
    except ReadError as exc:
        raise ManifestError("locator_outside_root" if exc.kind == "outside" else "manifest_unreadable", "manifest") from None
    try:
        doc = strict_json(data, MAX_DEPTH)
    except ValueError:
        raise ManifestError("manifest_invalid", "json") from None
    check_schema(doc)
    for field, rel in locators(doc):
        _probe_locator(root, rel, field)
    return Manifest(doc, canonical_sha256(doc))
