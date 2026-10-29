"""Repository public-safety preflight (Phase 2 M1 WP1).

Placement: a repository-hygiene tool beside ``scan_secrets.py``, not part of
the plugin package. It names the private Kiro directory as a path to keep out
of the public set, and plugin runtime files may not reference that directory
(``tests/unit/test_docs.py::test_no_runtime_file_reads_the_kiro_directory``).
Standard library only, like the other scripts here.

Source: ``docs/v2/phase2/m1/wp0/repository-baseline.md`` §3-1 (``.agents/`` is
untracked but not ignored; ``scan_secrets.py`` scans tracked files only) and
``m1-architecture-proposal.md`` §5-5. Purpose: before anything is staged or
committed, show that the set of files git would publish holds no private path,
no nested repository, no local targets file and nothing the secret rules match.

    python3 .github/scripts/public_preflight.py [--root DIR]

Exit codes: 0 PASS, 1 FAILED (a violation was found), 2 ERROR (the check could
not be completed). FAILED and ERROR both block: an enumeration that fails, a
file that cannot be read and a file too large to scan are never a pass.

The public candidate set is ``git ls-files --cached --others --exclude-standard``:
tracked files plus untracked files that ``.gitignore`` does not exclude, i.e.
exactly what ``git add -A`` would stage. Secret matching reuses the rules of
``.github/scripts/scan_secrets.py`` (loaded read-only, never modified) and is
applied to every candidate, tracked or not. A binary file is scanned as its
printable ASCII runs, so that a credential embedded in one is still matched. Matched
values are never printed.

A clean result means the rules matched nothing. It is not a proof that the
files hold no secret.

Read-only: only ``git ls-files``, ``git check-ignore``, ``git diff --cached
--name-only`` and ``git rev-parse`` are run, as argv arrays without a shell,
with a timeout and an output limit.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import types
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

PASS, FAILED, ERROR = "PASS", "FAILED", "ERROR"
EXIT_CODES = {PASS: 0, FAILED: 1, ERROR: 2}

#: Path prefixes that must never be published.
PRIVATE_PREFIXES: Tuple[str, ...] = (".agents/", ".kiro/")
#: Paths whose ignore status is probed (a directory and a file inside it).
IGNORE_PROBES: Tuple[str, ...] = (".agents/", ".agents/tasks/phase1/henv/appdemo-targets.json")
#: File names that hold local targets, keys or credentials.
SENSITIVE_SUFFIXES: Tuple[str, ...] = ("-targets.json", ".pem", ".key", ".p12", ".pfx")
SENSITIVE_NAMES: Tuple[str, ...] = (".env", "credentials", "credentials.json", "id_rsa", "id_ed25519")
SCANNER_PATH = ".github/scripts/scan_secrets.py"
#: Larger files are not scanned and therefore block (the scanner's own limit is 2 MiB).
MAX_SCAN_BYTES = 2 * 1024 * 1024
GIT_TIMEOUT_S = 60
GIT_MAX_OUTPUT = 64 * 1024 * 1024
SAMPLE = 20

Runner = Callable[[List[str]], Tuple[Optional[int], bytes]]


def default_runner(argv: List[str]) -> Tuple[Optional[int], bytes]:
    """Run ``argv`` without a shell; (None, b"") on timeout, output over the limit or a missing tool."""
    try:
        done = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=GIT_TIMEOUT_S, check=False)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None, b""
    if len(done.stdout) > GIT_MAX_OUTPUT:
        return None, b""
    return done.returncode, done.stdout


def _check(cid: str, status: str, detail: str, paths: Sequence[str] = ()) -> Dict[str, Any]:
    return {"id": cid, "status": status, "detail": detail, "count": len(paths), "paths": sorted(paths)[:SAMPLE]}


def _git_list(run: Runner, root: Path, *args: str) -> Optional[List[str]]:
    code, out = run(["git", "-C", str(root), *args])
    if code != 0:
        return None
    try:
        return [p for p in out.decode("utf-8").split("\0") if p]
    except UnicodeDecodeError:
        return None


def public_path_problems(path: str) -> List[str]:
    """Why ``path`` (repository-relative, ``/``-separated) must not be published; empty if it may."""
    problems = []
    parts = PurePosixPath(path.rstrip("/")).parts
    name = parts[-1] if parts else ""
    if path.startswith(PRIVATE_PREFIXES) or path.rstrip("/") + "/" in PRIVATE_PREFIXES:
        problems.append("private prefix")
    if path.endswith("/"):
        problems.append("nested repository (untracked directory reported by git)")
    if ".git" in parts:
        problems.append("path inside a .git directory")
    if name.endswith(SENSITIVE_SUFFIXES) or name in SENSITIVE_NAMES or name.startswith(".env."):
        problems.append("local targets, key or credential file name")
    return problems


def load_scanner(root: Path) -> types.ModuleType:
    """The secret rules of ``.github/scripts/scan_secrets.py``, executed without writing bytecode.

    Raises OSError / SyntaxError / AttributeError when the scanner cannot be used.
    """
    path = root / SCANNER_PATH
    source = path.read_text(encoding="utf-8")
    module = types.ModuleType("scan_secrets_preflight")
    module.__file__ = str(path)
    # The scanner's NamedTuples resolve their module through sys.modules while the class body runs.
    sys.modules[module.__name__] = module
    try:
        exec(compile(source, str(path), "exec"), module.__dict__)  # noqa: S102 - the repository's own scanner
    finally:
        sys.modules.pop(module.__name__, None)
    if not callable(getattr(module, "scan_text", None)) or not getattr(module, "RULES", None):
        raise AttributeError("scan_secrets.py has no scan_text / RULES")
    return module


_NON_PRINTABLE = re.compile(rb"[^\x20-\x7e\t\n\r]+")


def _scan_text_of(data: bytes) -> str:
    """Text for the secret rules. A binary (NUL or invalid UTF-8) keeps only its printable ASCII runs,
    each on its own line, so a credential embedded in it is still matched."""
    if b"\0" not in data:
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            pass
    return _NON_PRINTABLE.sub(b"\n", data).decode("ascii")


def _scan(root: Path, paths: Sequence[str], scanner: types.ModuleType) -> Tuple[List[str], List[str], int]:
    """(rendered findings, unscannable paths, files scanned)."""
    findings: List[str] = []
    unscannable: List[str] = []
    scanned = 0
    for rel in paths:
        path = root / rel
        if path.is_symlink() or not path.exists():
            continue  # a symlink carries no bytes of its own; a deleted tracked file is not published content
        try:
            if path.stat().st_size > MAX_SCAN_BYTES:
                unscannable.append(rel)
                continue
            data = path.read_bytes()
        except OSError:
            unscannable.append(rel)
            continue
        text = _scan_text_of(data)
        findings += [f.render() for f in scanner.scan_text(rel, text)]
        scanned += 1
    return findings, unscannable, scanned


def run_preflight(root: Path, runner: Optional[Runner] = None, scanner: Optional[types.ModuleType] = None) -> Dict[str, Any]:
    """Every check, with the overall status (ERROR before FAILED before PASS)."""
    run = runner or default_runner
    root = root.resolve()
    checks: List[Dict[str, Any]] = []

    code, out = run(["git", "-C", str(root), "rev-parse", "--show-toplevel"])
    top = out.decode("utf-8", "replace").strip() if code == 0 else ""
    if code != 0 or Path(top).resolve() != root:
        checks.append(_check("repository_root", ERROR, "not the top level of a git work tree (or git unavailable)"))
        return _result(root, checks, 0)
    checks.append(_check("repository_root", PASS, "git work tree top level"))

    not_ignored = []
    for probe in IGNORE_PROBES:
        code, _ = run(["git", "-C", str(root), "check-ignore", "-q", "--no-index", "--", probe])
        if code is None or code not in (0, 1):
            checks.append(_check("agents_ignored", ERROR, "git check-ignore failed for {0}".format(probe)))
            return _result(root, checks, 0)
        if code == 1:
            not_ignored.append(probe)
    checks.append(_check("agents_ignored", FAILED if not_ignored else PASS,
                         ".agents/ is not excluded by .gitignore" if not_ignored else ".agents/ is excluded by .gitignore", not_ignored))

    tracked_private = _git_list(run, root, "ls-files", "-z", "--cached", "--", *[p.rstrip("/") for p in PRIVATE_PREFIXES])
    staged = _git_list(run, root, "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMRT")
    stage_listing = _git_list(run, root, "ls-files", "-z", "--stage")
    candidates = _git_list(run, root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    if tracked_private is None or staged is None or stage_listing is None or candidates is None:
        checks.append(_check("enumeration", ERROR, "a git listing failed; the public set is unknown"))
        return _result(root, checks, 0)
    checks.append(_check("enumeration", PASS, "{0} public candidate path(s)".format(len(candidates))))

    checks.append(_check("no_tracked_private_path", FAILED if tracked_private else PASS,
                         "files under .agents/ or .kiro/ are tracked" if tracked_private else "nothing under .agents/ or .kiro/ is tracked",
                         tracked_private))
    bad_staged = [p for p in staged if public_path_problems(p)]
    checks.append(_check("staged_paths_public", FAILED if bad_staged else PASS,
                         "staged non-public path(s)" if bad_staged else "{0} staged path(s), none private".format(len(staged)), bad_staged))
    gitlinks = [line.split("\t", 1)[-1] for line in stage_listing if line.startswith("160000 ")]
    bad_candidates = sorted({p for p in candidates if public_path_problems(p)} | set(gitlinks))
    checks.append(_check("public_candidates", FAILED if bad_candidates else PASS,
                         "non-public path(s) or nested repositories in the public set" if bad_candidates
                         else "no private path, nested repository or local targets file in the public set", bad_candidates))

    try:
        scanner = scanner or load_scanner(root)
    except (OSError, SyntaxError, AttributeError, UnicodeDecodeError) as exc:
        checks.append(_check("secret_scan", ERROR, "secret rules could not be loaded ({0})".format(type(exc).__name__)))
        return _result(root, checks, 0)
    findings, unscannable, scanned = _scan(root, [p for p in candidates if not p.endswith("/")], scanner)
    if unscannable:
        checks.append(_check("secret_scan_coverage", ERROR, "file(s) could not be scanned (unreadable or over {0} bytes)".format(MAX_SCAN_BYTES),
                             unscannable))
    else:
        checks.append(_check("secret_scan_coverage", PASS, "{0} file(s) scanned, tracked and untracked".format(scanned)))
    checks.append(_check("secret_scan", FAILED if findings else PASS,
                         "secret rule match(es); values not shown" if findings else "no secret rule matched (not a proof of absence)", findings))
    return _result(root, checks, scanned)


def _result(root: Path, checks: List[Dict[str, Any]], scanned: int) -> Dict[str, Any]:
    statuses = {c["status"] for c in checks}
    status = ERROR if ERROR in statuses else (FAILED if FAILED in statuses else PASS)
    return {"preflight": "public-safety", "status": status, "files_scanned": scanned, "checks": checks,
            "limits": ["secret rules are those of .github/scripts/scan_secrets.py; a clean result is not a proof of absence"]}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="public_preflight.py", description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--root", default=None, help="repository root (default: this checkout)")
    args = parser.parse_args(argv)
    root = Path(args.root) if args.root else Path(__file__).resolve().parents[2]
    result = run_preflight(root)
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return EXIT_CODES[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
