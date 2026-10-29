"""Artifact Integrity: Git tree, content, evidence manifest; rules P2-AI-01 / P2-AI-02 (Phase 2 M1 WP3-3).

Each case builds a throwaway git repository under pytest's tmp_path (commits
are made there only, never in the work tree). No Phase 1 helper is imported or
run, nothing is pushed, and the Contents API answer is synthetic.
"""

from __future__ import annotations

import base64
import datetime
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from iacreview.evidence import artifact, collector, envelope, rules, store

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

WORKFLOW = b"name: probe\non: [pull_request]\npermissions: {}\n"
README = b"# synthetic artifact\n"
APPROVED_FILES = {".github/workflows/probe.yml": WORKFLOW, "README.md": README}
SOURCE_COMMIT = "1" * 40
T0 = datetime.datetime(2026, 10, 29, 4, 0, 0, tzinfo=datetime.timezone.utc)
GIT_ENV = {"GIT_AUTHOR_NAME": "synthetic", "GIT_AUTHOR_EMAIL": "synthetic@example.invalid", "GIT_COMMITTER_NAME": "synthetic",
           "GIT_COMMITTER_EMAIL": "synthetic@example.invalid", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}


def git(repo: Path, *args: str) -> str:
    done = subprocess.run(["git", "-C", str(repo), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env=dict(os.environ, **GIT_ENV))
    return done.stdout.decode().strip()


def make_repo(tmp_path: Path, files: Dict[str, bytes], name: str = "artifact") -> Path:
    repo = tmp_path / name
    repo.mkdir()
    git(repo, "init", "-q")
    for rel, data in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_bytes(data)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "synthetic artifact")
    return repo


def approved() -> artifact.ApprovedSource:
    return artifact.ApprovedSource(SOURCE_COMMIT, dict(APPROVED_FILES))


def compare(repo: Path, claim_commit: Optional[str] = None, source: str = SOURCE_COMMIT) -> artifact.Comparison:
    tree = artifact.read_artifact(repo, "HEAD")
    claim = artifact.ArtifactClaim("probe", claim_commit or (tree.commit or ""), source)
    return artifact.compare_content(tree, approved(), claim)


def kinds(c: artifact.Comparison) -> List[str]:
    return sorted({k for k, _ in c.mismatches})


def test_a_matching_artifact_matches(tmp_path: Path) -> None:
    c = compare(make_repo(tmp_path, APPROVED_FILES))
    assert c.status == "MATCH" and c.mismatches == [] and set(c.file_sha256) == set(APPROVED_FILES)


def test_source_and_artifact_commit_mismatches_are_detected(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, APPROVED_FILES)
    assert kinds(compare(repo, source="2" * 40)) == ["source_commit_mismatch"]
    assert kinds(compare(repo, claim_commit="3" * 40)) == ["artifact_commit_mismatch"]


def test_one_byte_of_difference_is_detected(tmp_path: Path) -> None:
    c = compare(make_repo(tmp_path, dict(APPROVED_FILES, **{"README.md": README + b" "})))
    assert c.status == "MISMATCH" and c.mismatches == [("content_mismatch", "README.md")]


def test_extra_and_missing_files_are_detected(tmp_path: Path) -> None:
    files = dict(APPROVED_FILES)
    del files["README.md"]
    files["extra.txt"] = b"x\n"
    assert kinds(compare(make_repo(tmp_path, files))) == ["extra_file", "missing_file"]


def test_a_mode_change_is_detected(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, APPROVED_FILES)
    os.chmod(repo / "README.md", 0o755)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "exec bit")
    assert compare(repo).mismatches == [("mode_changed", "README.md")]


def test_a_symlink_is_detected(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, APPROVED_FILES)
    (repo / "README.md").unlink()
    (repo / "README.md").symlink_to(".github/workflows/probe.yml")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "link")
    assert "symlink" in kinds(compare(repo))


def test_a_gitlink_is_detected(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, APPROVED_FILES)
    git(repo, "update-index", "--add", "--cacheinfo", "160000,{0},vendor/sub".format("4" * 40))
    git(repo, "commit", "-q", "-m", "gitlink")
    assert kinds(compare(repo)) == ["extra_file", "gitlink"]


def test_an_object_whose_bytes_do_not_hash_to_its_id_is_detected(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, APPROVED_FILES)

    def lying_reader(top: Path, oid: str, limit: int) -> Optional[bytes]:
        return README if oid == artifact.git_blob_id(README) else WORKFLOW + b"#"

    tree = artifact.read_artifact(repo, "HEAD", reader=lying_reader)
    c = artifact.compare_content(tree, approved(), artifact.ArtifactClaim("probe", tree.commit or "", SOURCE_COMMIT))
    assert ("invalid_git_object", ".github/workflows/probe.yml") in c.mismatches


def test_an_unreadable_object_is_unverifiable_not_a_match(tmp_path: Path) -> None:
    repo = make_repo(tmp_path, APPROVED_FILES)
    from iacreview.remediation import gitsnap

    def failing(top: Path, oid: str, limit: int) -> Optional[bytes]:
        raise gitsnap.GitError("repository_unreadable", "cat-file")

    tree = artifact.read_artifact(repo, "HEAD", reader=failing)
    c = artifact.compare_content(tree, approved(), artifact.ArtifactClaim("probe", tree.commit or "", SOURCE_COMMIT))
    assert c.status == "UNVERIFIABLE"
    assert artifact.whole_tree_matches_source(c).status == "NOT_PROVEN"


def test_a_missing_ref_or_repository_is_unverifiable(tmp_path: Path) -> None:
    assert artifact.read_artifact(tmp_path, "HEAD").error is not None
    repo = make_repo(tmp_path, APPROVED_FILES)
    tree = artifact.read_artifact(repo, "no-such-branch")
    assert artifact.compare_content(tree, approved(), artifact.ArtifactClaim("probe", "5" * 40, SOURCE_COMMIT)).status == "UNVERIFIABLE"


@pytest.mark.parametrize("source", [artifact.ApprovedSource("abc", APPROVED_FILES), artifact.ApprovedSource(SOURCE_COMMIT, {}),
                                    artifact.ApprovedSource(SOURCE_COMMIT, {"../escape": b"x"})])
def test_an_invalid_approved_source_is_unverifiable(tmp_path: Path, source: artifact.ApprovedSource) -> None:
    tree = artifact.read_artifact(make_repo(tmp_path, APPROVED_FILES), "HEAD")
    assert artifact.compare_content(tree, source, artifact.ArtifactClaim("p", tree.commit or "", SOURCE_COMMIT)).status == "UNVERIFIABLE"


# ---------------------------------------------------------------------------
# Layer 3: the artifact record in the Evidence Store
# ---------------------------------------------------------------------------


def _store(tmp_path: Path) -> store.EvidenceStore:
    base = tmp_path / "work"
    base.mkdir()
    return store.EvidenceStore(base / "evidence-store", base, now=lambda: T0)


def _record_evidence(c: artifact.Comparison, data: Optional[bytes] = None, subject: Optional[str] = None) -> collector.CapturedEvidence:
    raw = data if data is not None else envelope.canonical_bytes(c.record())
    ev, refusal = collector.non_api_evidence("LOCAL", "art-0001", "art-cap-0001", "artifact integrity record (git ls-tree + cat-file)",
                                             raw, T0, subject_commit_sha=subject or c.commit)
    assert refusal is None and ev is not None
    return ev


def _seal(st: store.EvidenceStore, items: List[collector.CapturedEvidence]) -> store.StoreReport:
    w = st.begin_revision("artifact")
    for e in items:
        w.add(e)
    w.seal()
    return st.verify()


def test_the_manifest_reference_matches_and_a_changed_record_is_detected(tmp_path: Path) -> None:
    c = compare(make_repo(tmp_path, APPROVED_FILES))
    st = _store(tmp_path)
    report = _seal(st, [_record_evidence(c)])
    assert artifact.manifest_reference_problems(report, "art-0001", c, st.read_raw) == []
    other = artifact.Comparison("MATCH", commit=c.commit, tree=c.tree, file_sha256=dict(c.file_sha256, **{"README.md": "0" * 64}))
    assert any("differs" in p for p in artifact.manifest_reference_problems(report, "art-0001", other, st.read_raw))


def test_a_record_naming_another_commit_is_a_manifest_mismatch(tmp_path: Path) -> None:
    c = compare(make_repo(tmp_path, APPROVED_FILES))
    st = _store(tmp_path)
    report = _seal(st, [_record_evidence(c, subject="6" * 40)])
    problems = artifact.manifest_reference_problems(report, "art-0001", c, st.read_raw)
    assert "artifact record subject commit differs from the artifact commit" in problems
    assert artifact.whole_tree_matches_source(c, problems).status == "FAILED"


def test_phase2_artifact_whole_tree_matches_source(tmp_path: Path) -> None:
    """Rule behaviour test named by the Definition for P2-AI-01."""
    assert rules.RULE_CATALOG[artifact.RULE_WHOLE_TREE].status == "IMPLEMENTED"
    good = compare(make_repo(tmp_path, APPROVED_FILES, "good"))
    st = _store(tmp_path)
    report = _seal(st, [_record_evidence(good)])
    assert artifact.whole_tree_matches_source(good, artifact.manifest_reference_problems(report, "art-0001", good, st.read_raw)).status == "PASS"
    assert artifact.whole_tree_matches_source(good).status == "PASS"
    bad = compare(make_repo(tmp_path, dict(APPROVED_FILES, **{"README.md": b"other\n"}), "bad"))
    result = artifact.whole_tree_matches_source(bad)
    assert result.status == "FAILED" and result.reason_code == "content_mismatch"
    assert artifact.whole_tree_matches_source(artifact.Comparison("UNVERIFIABLE")).status == "NOT_PROVEN"
    assert artifact.whole_tree_matches_source(good, ["the evidence store does not verify"]).status == "NOT_PROVEN"


def _contents_capture(path: str, commit: str, served: bytes, sha: Optional[str] = None, status: int = 200) -> collector.CaptureResult:
    body = json.dumps({"type": "file", "encoding": "base64", "path": path, "sha": sha or artifact.git_blob_id(served),
                       "content": base64.b64encode(served).decode("ascii")}).encode()
    endpoint = "/repos/synthetic-owner/synthetic-repo/contents/{0}?ref={1}".format(path, commit)
    queue = [collector.HttpResponse(status, {"Content-Type": "application/json"}, body)]
    c = collector.Collector(lambda r: queue.pop(0), "synthetic-owner/synthetic-repo", now=lambda: T0, id_factory=lambda: "cap-contents-1")
    return c.capture("GET", endpoint, subject_commit_sha=commit)


def test_phase2_artifact_published_matches_source(tmp_path: Path) -> None:
    """Rule behaviour test named by the Definition for P2-AI-02 (synthetic Contents API answers only)."""
    assert rules.RULE_CATALOG[artifact.RULE_PUBLISHED].status == "IMPLEMENTED"
    path = ".github/workflows/probe.yml"
    c = compare(make_repo(tmp_path, APPROVED_FILES))
    assert c.commit is not None

    def judge(served: bytes, sha: Optional[str] = None, status: int = 200, commit: Optional[str] = None, sub: str = "s") -> str:
        work = tmp_path / "work-{0}".format(sub)
        work.mkdir()
        st = store.EvidenceStore(work / "store", work, now=lambda: T0)
        cap = _contents_capture(path, commit or c.commit or "", served, sha, status)
        report = _seal(st, cap.evidence)
        return artifact.published_matches_source(report, cap.evidence[0].evidence_id, c, approved(), st.read_raw).status

    assert judge(WORKFLOW, sub="pass") == "PASS"
    assert judge(WORKFLOW + b"# drift\n", sub="drift") == "FAILED"                 # GitHub serves other bytes (the G11 case)
    assert judge(WORKFLOW, sha="7" * 40, sub="sha") == "FAILED"                   # reported blob id does not match the bytes
    assert judge(WORKFLOW, status=404, sub="404") == "NOT_PROVEN"                 # incomplete capture
    assert judge(WORKFLOW, commit="8" * 40, sub="other") == "NOT_PROVEN"          # answer for another commit
    st = _store(tmp_path)
    report = _seal(st, [_record_evidence(c)])
    assert artifact.published_matches_source(report, "missing-0001", c, approved(), st.read_raw).status == "NOT_PROVEN"
