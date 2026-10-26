"""Read-only Git Snapshot Adapter (Design 4).

Git runs through :func:`iacreview.proc.run_bounded`: argv array, no shell, the
minimal environment, a timeout and an output limit. Every call carries options
that switch off what could run code or reach the network while reading
(``core.fsmonitor``, hooks, external diff, pager, transports), and only
plumbing commands are used, none of which applies clean/smudge filters or
textconv. Nothing here writes to the repository.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from iacreview import proc
from iacreview.errors import IacReviewError
from iacreview.remediation import rschema

GIT = "git"

#: Prepended to every git invocation (after ``-C <repo>``).
SAFE_OPTIONS: Tuple[str, ...] = (
    "--no-pager",
    "--no-optional-locks",
    "--literal-pathspecs",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "protocol.allow=never",
    "-c",
    "core.untrackedCache=false",
    "-c",
    "diff.external=",
    "-c",
    "core.pager=cat",
)

_REV = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@{}^~-]{0,254}$")
_OID = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
MODE_FILE = "100644"
MODE_EXEC = "100755"
MODE_LINK = "120000"
MODE_GITLINK = "160000"
MODE_TREE = "040000"
#: Regular files; the executable bit is compared separately (file_mode_changed).
REGULAR_MODES = (MODE_FILE, MODE_EXEC)


class GitError(Exception):
    """A git read failed. ``code`` is a decision code of ``rschema.CODES``."""

    def __init__(self, code: str, step: str) -> None:
        super().__init__("{0} ({1})".format(code, step))
        self.code = code
        self.step = step


@dataclass(frozen=True)
class Entry:
    mode: str
    oid: str


@dataclass
class Snapshot:
    """A whole-tree map ``path -> Entry``. Paths are str (surrogateescape)."""

    kind: str  # "commit" or "worktree"
    commit: Optional[str]
    tree: Optional[str]
    entries: Dict[str, Entry]
    notes: List[str] = field(default_factory=list)

    @property
    def digest(self) -> str:
        h = hashlib.sha256()
        for path in sorted(self.entries):
            e = self.entries[path]
            h.update(e.mode.encode("ascii") + b" " + e.oid.encode("ascii") + b" ")
            h.update(path.encode("utf-8", "surrogateescape") + b"\x00")
        return h.hexdigest()


def _git(repo: Path, args: List[str], step: str, max_bytes: int = rschema.GIT_MAX_OUTPUT_BYTES) -> proc.BoundedResult:
    argv = [GIT, "-C", str(repo), *SAFE_OPTIONS, *args]
    try:
        result = proc.run_bounded(argv, timeout_s=rschema.GIT_TIMEOUT_S, max_output_bytes=max_bytes)
    except IacReviewError:
        raise GitError("repository_unreadable", step) from None
    if result.timed_out or result.output_exceeded:
        raise GitError("repository_unreadable", step)
    return result


def check_repo(repo: Path) -> Path:
    """The repository top level, resolved. Raises GitError if not a work tree."""
    try:
        resolved = repo.resolve(strict=True)
    except (OSError, RuntimeError):
        raise GitError("repository_unreadable", "resolve") from None
    result = _git(resolved, ["rev-parse", "--show-toplevel"], "toplevel")
    if result.exit_code != 0:
        raise GitError("repository_unreadable", "toplevel")
    top = result.stdout.decode("utf-8", "surrogateescape").strip()
    try:
        return Path(top).resolve(strict=True)
    except (OSError, RuntimeError):
        raise GitError("repository_unreadable", "toplevel") from None


def object_format(repo: Path) -> str:
    result = _git(repo, ["rev-parse", "--show-object-format"], "object-format")
    fmt = result.stdout.decode("ascii", "replace").strip()
    if result.exit_code != 0 or fmt not in ("sha1", "sha256"):
        raise GitError("repository_unreadable", "object-format")
    return fmt


def resolve_commit(repo: Path, rev: str) -> str:
    """Resolve ``rev`` to a full commit id. The text is validated first."""
    if not isinstance(rev, str) or _REV.match(rev) is None or ".." in rev:
        raise GitError("invalid_arguments", "revision")
    result = _git(repo, ["rev-parse", "--verify", "--quiet", "--end-of-options", rev + "^{commit}"], "rev-parse")
    oid = result.stdout.decode("ascii", "replace").strip()
    if result.exit_code != 0 or _OID.match(oid) is None:
        raise GitError("revision_not_found", "rev-parse")
    return oid


def tree_of(repo: Path, commit: str) -> str:
    result = _git(repo, ["rev-parse", "--verify", "--quiet", "--end-of-options", commit + "^{tree}"], "tree")
    oid = result.stdout.decode("ascii", "replace").strip()
    if result.exit_code != 0 or _OID.match(oid) is None:
        raise GitError("revision_not_found", "tree")
    return oid


def is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
    result = _git(repo, ["merge-base", "--is-ancestor", ancestor, descendant], "merge-base")
    if result.exit_code == 0:
        return True
    if result.exit_code == 1:
        return False
    raise GitError("repository_unreadable", "merge-base")


def commit_snapshot(repo: Path, commit: str) -> Snapshot:
    """Every entry of ``commit``'s tree, recursively, gitlinks included."""
    result = _git(repo, ["ls-tree", "-r", "-z", "--full-tree", commit], "ls-tree")
    if result.exit_code != 0:
        raise GitError("repository_unreadable", "ls-tree")
    entries: Dict[str, Entry] = {}
    for record in result.stdout.split(b"\x00"):
        if not record:
            continue
        head, sep, raw_path = record.partition(b"\t")
        parts = head.split(b" ")
        if not sep or len(parts) != 3:
            raise GitError("repository_unreadable", "ls-tree-format")
        mode, _type, oid = (p.decode("ascii", "replace") for p in parts)
        if _OID.match(oid) is None:
            raise GitError("repository_unreadable", "ls-tree-format")
        entries[raw_path.decode("utf-8", "surrogateescape")] = Entry(mode, oid)
        if len(entries) > rschema.MAX_TREE_ENTRIES:
            raise GitError("repository_unreadable", "tree-too-large")
    return Snapshot("commit", commit, tree_of(repo, commit), entries)


def read_blob(repo: Path, oid: str, limit: int) -> Optional[bytes]:
    """The blob's bytes, or ``None`` when it is larger than ``limit``."""
    if _OID.match(oid) is None:
        raise GitError("repository_unreadable", "oid")
    size = _git(repo, ["cat-file", "-s", oid], "cat-file-size")
    try:
        length = int(size.stdout.decode("ascii").strip())
    except ValueError:
        raise GitError("repository_unreadable", "cat-file-size") from None
    if size.exit_code != 0:
        raise GitError("repository_unreadable", "cat-file-size")
    if length > limit:
        return None
    data = _git(repo, ["cat-file", "blob", oid], "cat-file", max_bytes=limit + 1)
    if data.exit_code != 0 or len(data.stdout) != length:
        raise GitError("repository_unreadable", "cat-file")
    return data.stdout


# ---------------------------------------------------------------------------
# Worktree preview
# ---------------------------------------------------------------------------


def _blob_hasher(fmt: str, size: int) -> "hashlib._Hash":
    h = hashlib.sha1() if fmt == "sha1" else hashlib.sha256()  # noqa: S324 - git object id
    h.update(b"blob " + str(size).encode("ascii") + b"\x00")
    return h


def _inside(repo: Path, path: str) -> Path:
    candidate = repo / path
    parent = os.path.realpath(str(candidate.parent))
    root = str(repo)
    if parent != root and not parent.startswith(root + os.sep):
        raise GitError("repository_unreadable", "worktree-path")
    return candidate


def _hash_worktree_file(repo: Path, path: str, fmt: str) -> Optional[Entry]:
    candidate = _inside(repo, path)
    try:
        st = os.lstat(str(candidate))
    except FileNotFoundError:
        return None
    except OSError:
        raise GitError("repository_unreadable", "worktree-stat") from None
    if stat.S_ISLNK(st.st_mode):
        target = os.readlink(os.fsencode(str(candidate)))
        h = _blob_hasher(fmt, len(target))
        h.update(target)
        return Entry(MODE_LINK, h.hexdigest())
    if not stat.S_ISREG(st.st_mode):
        return Entry("000000", "0" * (40 if fmt == "sha1" else 64))
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(candidate), flags)
    except OSError:
        raise GitError("repository_unreadable", "worktree-open") from None
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            raise GitError("repository_unreadable", "worktree-open")
        h = _blob_hasher(fmt, fst.st_size)
        read = 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            read += len(chunk)
            h.update(chunk)
        if read != fst.st_size:
            raise GitError("snapshot_changed", "worktree-read")
    finally:
        os.close(fd)
    mode = MODE_EXEC if fst.st_mode & stat.S_IXUSR else MODE_FILE
    return Entry(mode, h.hexdigest())


def worktree_snapshot(repo: Path) -> Snapshot:
    """Tracked files as they are on disk, plus untracked files that are not ignored."""
    fmt = object_format(repo)
    staged = _git(repo, ["ls-files", "-z", "-s"], "ls-files")
    if staged.exit_code != 0:
        raise GitError("repository_unreadable", "ls-files")
    entries: Dict[str, Entry] = {}
    notes: List[str] = ["ignored_files_not_inspected", "raw_bytes_compared_without_filters"]
    for record in staged.stdout.split(b"\x00"):
        if not record:
            continue
        head, sep, raw_path = record.partition(b"\t")
        parts = head.split(b" ")
        if not sep or len(parts) != 3:
            raise GitError("repository_unreadable", "ls-files-format")
        mode, oid, stage = (p.decode("ascii", "replace") for p in parts)
        if stage != "0":
            raise GitError("repository_unreadable", "unmerged-index")
        path = raw_path.decode("utf-8", "surrogateescape")
        if mode == MODE_GITLINK:
            entries[path] = Entry(mode, oid)
            if "submodule_worktree_not_inspected" not in notes:
                notes.append("submodule_worktree_not_inspected")
            continue
        entry = _hash_worktree_file(repo, path, fmt)
        if entry is not None:
            entries[path] = entry
    others = _git(repo, ["ls-files", "-z", "-o", "--exclude-standard"], "ls-files-others")
    if others.exit_code != 0:
        raise GitError("repository_unreadable", "ls-files-others")
    for raw_path in others.stdout.split(b"\x00"):
        if not raw_path:
            continue
        path = raw_path.decode("utf-8", "surrogateescape")
        entry = _hash_worktree_file(repo, path, fmt)
        if entry is not None:
            entries[path] = entry
        if len(entries) > rschema.MAX_TREE_ENTRIES:
            raise GitError("repository_unreadable", "tree-too-large")
    return Snapshot("worktree", None, None, entries, notes)


def read_worktree_file(repo: Path, path: str, limit: int) -> Optional[bytes]:
    """Read a regular worktree file without following a final symlink."""
    candidate = _inside(repo, path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(candidate), flags)
    except OSError:
        raise GitError("repository_unreadable", "worktree-open") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise GitError("repository_unreadable", "worktree-open")
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                return None
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)
