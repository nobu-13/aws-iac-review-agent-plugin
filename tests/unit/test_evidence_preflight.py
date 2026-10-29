"""Repository public-safety preflight, .github/scripts/public_preflight.py (Phase 2 M1 WP1-1).

Source: docs/v2/phase2/m1/wp0/repository-baseline.md §3-1. Each case builds a
throwaway git repository under pytest's tmp_path (never the work tree), with a
copy of .github/scripts/scan_secrets.py so that the same secret rules apply.
Nothing is committed: tracked files are created with ``git add`` only. Canary
credentials are assembled at run time and are not real; no fixture file holds
one, so the repository's own secret scan does not match this file.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Dict, List, Optional, Tuple

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / ".github" / "scripts" / "scan_secrets.py"
PREFLIGHT = ROOT / ".github" / "scripts" / "public_preflight.py"


def _load(path: Path) -> ModuleType:
    """Load a script by path (``.github`` is not an importable package; same approach as test_ci.py)."""
    name = "ci_script_{0}".format(path.stem)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


preflight = _load(PREFLIGHT)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

#: Canaries, assembled so that this file itself never contains the shape.
PEM_CANARY = "-----BEGIN " + "RSA PRIVATE KEY-----"
TOKEN_CANARY = "gh" + "p_" + "Q7" * 18


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    (r / ".github" / "scripts").mkdir(parents=True)
    git(r, "init", "-q")
    shutil.copyfile(str(SCANNER), str(r / ".github" / "scripts" / "scan_secrets.py"))
    (r / ".gitignore").write_text(".agents/\n", encoding="utf-8")
    (r / "README.md").write_text("public\n", encoding="utf-8")
    return r


def status(result: Dict, check: str) -> str:
    return next(c["status"] for c in result["checks"] if c["id"] == check)


def check(result: Dict, cid: str) -> Dict:
    return next(c for c in result["checks"] if c["id"] == cid)


def test_a_clean_repository_passes_and_scans_untracked_files(repo: Path) -> None:
    git(repo, "add", "README.md")
    (repo / "notes.md").write_text("untracked, not ignored\n", encoding="utf-8")
    result = preflight.run_preflight(repo)
    assert result["status"] == "PASS", result
    assert result["files_scanned"] == 4  # .gitignore, README.md (tracked), notes.md (untracked), scan_secrets.py


def test_agents_not_ignored_fails(repo: Path) -> None:
    (repo / ".gitignore").write_text("", encoding="utf-8")
    (repo / ".agents").mkdir()
    (repo / ".agents" / "x.md").write_text("private\n", encoding="utf-8")
    result = preflight.run_preflight(repo)
    assert result["status"] == "FAILED"
    assert status(result, "agents_ignored") == "FAILED" and status(result, "public_candidates") == "FAILED"


def test_ignored_agents_content_is_outside_the_public_set_even_with_a_secret(repo: Path) -> None:
    (repo / ".agents" / "out").mkdir(parents=True)
    (repo / ".agents" / "out" / "raw.json").write_text(TOKEN_CANARY + "\n", encoding="utf-8")
    result = preflight.run_preflight(repo)
    assert result["status"] == "PASS" and status(result, "agents_ignored") == "PASS"


def test_a_force_added_private_file_fails(repo: Path) -> None:
    (repo / ".agents").mkdir()
    (repo / ".agents" / "helper.py").write_text("x = 1\n", encoding="utf-8")
    git(repo, "add", "-f", ".agents/helper.py")
    result = preflight.run_preflight(repo)
    assert status(result, "no_tracked_private_path") == "FAILED"
    assert status(result, "staged_paths_public") == "FAILED"
    assert ".agents/helper.py" in check(result, "staged_paths_public")["paths"]


def test_a_nested_repository_in_the_public_set_fails(repo: Path) -> None:
    nested = repo / "demo-repo"
    nested.mkdir()
    git(nested, "init", "-q")
    (nested / "f.txt").write_text("x\n", encoding="utf-8")
    result = preflight.run_preflight(repo)
    assert status(result, "public_candidates") == "FAILED"
    assert "demo-repo/" in check(result, "public_candidates")["paths"]


@pytest.mark.parametrize("name", ["appdemo-targets.json", "app.pem", ".env", ".env.local", "credentials.json"])
def test_local_targets_and_key_files_fail(repo: Path, name: str) -> None:
    (repo / ".gitignore").write_text(".agents/\n", encoding="utf-8")  # the repository's .gitignore would hide some of these
    (repo / "docs").mkdir()
    (repo / "docs" / name).write_text("{}\n", encoding="utf-8")
    result = preflight.run_preflight(repo)
    assert status(result, "public_candidates") == "FAILED"


@pytest.mark.parametrize("tracked", [True, False])
@pytest.mark.parametrize("canary", [PEM_CANARY, TOKEN_CANARY])
def test_a_secret_in_a_tracked_or_untracked_file_fails_without_printing_it(repo: Path, tracked: bool, canary: str) -> None:
    (repo / "leak.md").write_text("value " + canary + "\n", encoding="utf-8")
    if tracked:
        git(repo, "add", "leak.md")
    result = preflight.run_preflight(repo)
    assert result["status"] == "FAILED" and status(result, "secret_scan") == "FAILED"
    assert canary not in repr(result)


def test_a_secret_inside_a_binary_file_is_still_matched(repo: Path) -> None:
    (repo / "blob.bin").write_bytes(b"\x00\xff" + TOKEN_CANARY.encode("ascii") + b"\x00")
    result = preflight.run_preflight(repo)
    assert status(result, "secret_scan") == "FAILED"


def test_a_file_too_large_to_scan_is_an_error(repo: Path) -> None:
    (repo / "big.txt").write_bytes(b"a" * (preflight.MAX_SCAN_BYTES + 1))
    result = preflight.run_preflight(repo)
    assert result["status"] == "ERROR" and status(result, "secret_scan_coverage") == "ERROR"


def test_a_missing_scanner_is_an_error(repo: Path) -> None:
    (repo / ".github" / "scripts" / "scan_secrets.py").unlink()
    result = preflight.run_preflight(repo)
    assert result["status"] == "ERROR" and status(result, "secret_scan") == "ERROR"


def test_a_directory_that_is_not_a_repository_is_an_error(tmp_path: Path) -> None:
    result = preflight.run_preflight(tmp_path)
    assert result["status"] == "ERROR" and status(result, "repository_root") == "ERROR"


def fake_runner(fail_on: str, gitlink: bool = False):
    """Answers as git would for a clean repository, except for the call containing ``fail_on``."""

    def run(argv: List[str]) -> Tuple[Optional[int], bytes]:
        joined = " ".join(argv)
        if fail_on and fail_on in joined:
            return None, b""
        if "rev-parse" in argv:
            return 0, (str(Path("/").resolve()) + "\n").encode()
        if "check-ignore" in argv:
            return 0, b""
        if "--stage" in argv:
            return 0, (b"160000 " + b"a" * 40 + b" 0\tvendor/sub\0") if gitlink else b""
        return 0, b""

    return run


@pytest.mark.parametrize("fail_on,check_id", [
    ("rev-parse", "repository_root"),
    ("check-ignore", "agents_ignored"),
    ("--others", "enumeration"),
    ("--stage", "enumeration"),
    ("diff --cached", "enumeration"),
])
def test_a_failed_git_call_is_an_error_never_a_pass(fail_on: str, check_id: str) -> None:
    result = preflight.run_preflight(Path("/"), runner=fake_runner(fail_on))
    assert result["status"] == "ERROR" and status(result, check_id) == "ERROR"


def test_a_staged_gitlink_is_reported_as_a_nested_repository() -> None:
    result = preflight.run_preflight(Path("/"), runner=fake_runner("", gitlink=True), scanner=preflight.load_scanner(ROOT))
    assert status(result, "public_candidates") == "FAILED" and "vendor/sub" in check(result, "public_candidates")["paths"]


@pytest.mark.parametrize("path,private", [
    (".agents/tasks/x.json", True), (".kiro/steering/a.md", True), (".agents/", True), ("a/b/", True),
    ("x/.git/config", True), ("docs/v2/phase2/m1/wp1/note.md", False), ("iacreview/evidence/registry.py", False),
    ("henv-targets.json", True), ("docs/target.json", False),
])
def test_public_path_rules(path: str, private: bool) -> None:
    assert bool(preflight.public_path_problems(path)) is private


def test_the_preflight_cli_exit_code_follows_the_status(repo: Path) -> None:
    assert preflight.main(["--root", str(repo)]) == 0
    (repo / "leak.md").write_text(TOKEN_CANARY + "\n", encoding="utf-8")
    assert preflight.main(["--root", str(repo)]) == 1


def test_the_scanner_is_loaded_without_changing_it() -> None:
    before = SCANNER.read_bytes()
    module = preflight.load_scanner(ROOT)
    assert module.RULES and SCANNER.read_bytes() == before


def test_this_repository_public_set_passes_the_preflight() -> None:
    """The current checkout: .agents/ ignored, nothing private tracked or staged, no secret rule match."""
    if not (ROOT / ".git").exists():
        pytest.skip("NOT VERIFIED: not a git checkout")
    result = preflight.run_preflight(ROOT)
    assert result["status"] == "PASS", [c for c in result["checks"] if c["status"] != "PASS"]
