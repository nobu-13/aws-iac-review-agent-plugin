"""Synthetic chains for the Phase 2 M2 WP1 tests (not a test module).

Everything here is invented or built from the frozen Phase 1 fixtures: the case repositories come from
``tests/remediation_bench/casegen.py`` (fixed dates and identities, so the commit ids are stable), the
GitHub answers are synthetic and go through the M1 collector with a fake transport into an M1 store, and
nothing reaches a network.

The replay fixtures under ``tests/fixtures/chain_replay/`` (a Review_Report, ``review.json``, and a
Remediation Verification Report per scenario; ``review-report.json`` is a git-ignored name) are inputs,
written once by::

    PYTHONPATH=. python3 tests/unit/chain_synth.py --write-fixtures

and reviewed before they were committed. The expected chain result digests in
``tests/fixtures/chain_replay/expected.json`` are not written by any code (m2-acceptance-test-matrix.md
TC-07-04).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

ROOT = Path(__file__).resolve().parents[2]
for extra in (ROOT, ROOT / "tests" / "remediation_bench"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import casegen  # noqa: E402

from iacreview.chain import links as chain_links  # noqa: E402
from iacreview.chain import manifest as chain_manifest  # noqa: E402
from iacreview.evidence import collector, store  # noqa: E402
from iacreview.remediation import report as remediation_report  # noqa: E402
from iacreview.remediation import verify  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "chain_replay"
REVIEW_SCRIPT = ROOT / "skills" / "iac-review" / "scripts" / "run_iac_review.py"
REPO = "synthetic-owner/synthetic-repo"
OTHER_REPO = "synthetic-owner/other-repo"
T0 = datetime.datetime(2026, 10, 30, 6, 0, 0, tzinfo=datetime.timezone.utc)
REVIEW_SOURCES: Sequence[str] = ("cfn-lint", "iam-review")
#: scenario -> (case id of a VERIFIED candidate, case id of a BLOCKED candidate or None)
SCENARIO_CASES = {"sc01": "C01", "sc02": "C02"}
BLOCKED_CASE = "C05"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def block_network(monkeypatch: Any) -> None:
    """P1 of the M2 matrix: no socket connects while a chain test runs (child processes are not affected)."""
    import socket

    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError("network access is blocked in the chain tests")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


_REVIEW_CACHE: Dict[Any, bytes] = {}


def cached_review(scenario: str, variant: str = "base", sources: Sequence[str] = REVIEW_SOURCES, without_tools: bool = False) -> bytes:
    """``review_report_bytes`` of a scenario template, computed once per process."""
    key = (scenario, variant, tuple(sources), without_tools)
    if key not in _REVIEW_CACHE:
        path_env = tempfile.mkdtemp(prefix="chain-empty-path-") if without_tools else None
        _REVIEW_CACHE[key] = review_report_bytes(casegen.scenario_text(scenario, variant), sources, path_env)
    return _REVIEW_CACHE[key]


def case(case_id: str) -> Dict[str, Any]:
    return next(c for c in casegen.load_cases() if c["id"] == case_id)


def build_case(tmp: Path, case_id: str) -> casegen.Setup:
    return casegen.build(case(case_id), tmp / ("case-" + case_id))


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------


def review_report_bytes(template_text: str, sources: Sequence[str] = REVIEW_SOURCES, path_env: Optional[str] = None) -> bytes:
    """A real Review_Report of ``template_text`` reviewed as ``infra/template.yaml``."""
    work = Path(tempfile.mkdtemp(prefix="chain-review-"))
    try:
        (work / "infra").mkdir()
        (work / "infra" / "template.yaml").write_text(template_text, encoding="utf-8")
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        if path_env is not None:
            env["PATH"] = path_env
        argv = [sys.executable, str(REVIEW_SCRIPT), "--target", "infra/template.yaml"]
        for source in sources:
            argv += ["--sources", source]
        out = subprocess.run(argv,
                             cwd=str(work), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600, check=False)
        if out.returncode not in (0, 5, 6):
            raise AssertionError("review exited {0}".format(out.returncode))
        return out.stdout
    finally:
        shutil.rmtree(str(work), ignore_errors=True)


def verification_report_bytes(setup: casegen.Setup, execution_mode: str = "local_preview") -> bytes:
    """A Remediation_Verification_Report of the case, made in this process (the Phase 1 verify)."""
    req = verify.Request(repo=setup.repo, base=setup.base, head=setup.head, config_rev=setup.config_rev,
                         contract_path=setup.contract_path, contract_file=None, execution_mode=execution_mode,
                         repository_id=REPO)
    rep = remediation_report.build_report(verify.run(req), 0.0)
    rep["metadata"]["generated_at"] = "2026-10-30T06:00:00Z"
    rep["metadata"]["run_id"] = "1"
    rep["metadata"]["duration_ms"] = 0
    return remediation_report.serialize(rep).encode("ascii")


def finding_ref(review: bytes, resource: str) -> Dict[str, Any]:
    """The manifest reference of the one finding on ``resource``."""
    doc = json.loads(review.decode("utf-8"))
    found = [f for f in doc["findings"] if f.get("Resource") == resource]
    assert len(found) >= 1, "no finding on {0}".format(resource)
    raw = found[0]
    return {"finding_id": raw["ID"], "identity_key_sha256": chain_links.identity_key_sha256(raw),
            "finding_sha256": chain_manifest.canonical_sha256(raw)}


# ---------------------------------------------------------------------------
# M1 store with synthetic GitHub answers
# ---------------------------------------------------------------------------


def github_answers(base: str, head: str, number: int = 7) -> Dict[str, bytes]:
    pull = {"number": number, "state": "open", "merged": False, "user": {"id": 5000001},
            "head": {"sha": head}, "base": {"sha": base}}
    reviews = [{"id": 81000001, "state": "COMMENTED", "commit_id": head, "user": {"id": 5000001},
                "author_association": "OWNER", "submitted_at": "2026-10-30T06:00:00Z"}]
    compare = {"status": "ahead", "ahead_by": 1, "behind_by": 0, "merge_base_commit": {"sha": base}}
    return {"pulls/{0}".format(number): json.dumps(pull, sort_keys=True).encode(),
            "pulls/{0}/reviews?per_page=100".format(number): json.dumps(reviews, sort_keys=True).encode(),
            "compare/{0}...{1}".format(base, head): json.dumps(compare, sort_keys=True).encode()}


def make_store(root: Path, base: str, head: str, repo: str = REPO, locator: str = "evidence-store",
               incomplete: bool = False) -> Dict[str, Any]:
    """An M1 store (one revision) below ``root``; returns the manifest's ``github_evidence`` object."""
    n = [0]

    def ids() -> str:
        n[0] += 1
        return "cap-chain-{0:04d}".format(n[0])

    st = store.EvidenceStore(root / locator, root, now=lambda: T0)
    captured: List[collector.CapturedEvidence] = []
    for rel, body in sorted(github_answers(base, head).items()):
        headers = {"Content-Type": "application/json"}
        if incomplete and rel.startswith("pulls/7/reviews"):
            headers["Link"] = '</repos/{0}/pulls/7/reviews?per_page=100&page=2>; rel="next"'.format(repo)
        queue = [collector.HttpResponse(200, headers, body)]
        cap = collector.Collector(lambda r: queue.pop(0) if queue else None, repo, now=lambda: T0, id_factory=ids,
                                  max_pages=1).capture("GET", "/repos/{0}/{1}".format(repo, rel), subject_commit_sha=head)
        captured.extend(cap.evidence)
    w = st.begin_revision("synthetic M2 chain evidence")
    for e in captured:
        w.add(e)
    w.seal()
    revision = w.revision_id
    report = st.verify()
    rev = next(r for r in report.revisions if r.revision_id == revision)
    return {"store_locator": locator, "revision": revision, "manifest_sha256": rev.manifest_sha256,
            "evidence_ids": sorted(e.evidence_id for e in captured)}


# ---------------------------------------------------------------------------
# Chain root and manifest
# ---------------------------------------------------------------------------


def write(root: Path, rel: str, data: bytes) -> str:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return rel


def manifest_doc(setup: casegen.Setup, review: Optional[bytes], resource: Optional[str], verification: bytes,
                 github: Optional[Dict[str, Any]], chain_id: str = "chain-test-0001",
                 acquisition: str = "local_recompute", gate_records: Sequence[Dict[str, Any]] = ()) -> Dict[str, Any]:
    contract_bytes = subprocess.run(["git", "-C", str(setup.repo), "cat-file", "blob", "{0}:{1}".format(setup.config_rev, setup.contract_path)],
                                    check=True, stdout=subprocess.PIPE).stdout
    payload = json.loads(verification.decode("ascii"))["payload"]
    return {
        "manifest_format": "iacreview.chain.manifest/1",
        "chain_id": chain_id,
        "repository_id": chain_links.repository_id(REPO),
        "subject": {"base_commit": setup.base, "head_commit": setup.head},
        "contract": {"config_commit": setup.config_rev, "contract_path": setup.contract_path,
                     "contract_sha256": sha256(contract_bytes)},
        "review": None if review is None else {
            "review_report": {"locator": "artifacts/review-report.json", "sha256": sha256(review)},
            "finding_refs": [finding_ref(review, resource or "")]},
        "verification": {"report": {"locator": "artifacts/remediation-report.json", "sha256": sha256(verification)},
                         "payload_sha256": chain_manifest.canonical_sha256(payload), "acquisition": acquisition},
        "gate_records": list(gate_records),
        "github_evidence": github,
    }


def write_manifest(root: Path, doc: Dict[str, Any], name: str = "chain-manifest.json") -> Path:
    path = root / name
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


class Chain:
    """One synthetic chain: the case repository, the chain root, the artifacts and the manifest."""

    def __init__(self, tmp: Path, case_id: str, resource: str, review: Optional[bytes], verification: Optional[bytes] = None,
                 with_github: bool = True, **manifest_over: Any) -> None:
        self.setup = build_case(tmp, case_id)
        self.root = tmp / "chain"
        self.root.mkdir(parents=True, exist_ok=True)
        self.verification = verification if verification is not None else verification_report_bytes(self.setup)
        self.review = review
        write(self.root, "artifacts/remediation-report.json", self.verification)
        if review is not None:
            write(self.root, "artifacts/review-report.json", review)
        self.github = make_store(self.root, self.setup.base, self.setup.head) if with_github else None
        self.doc = manifest_doc(self.setup, review, resource, self.verification, self.github, **manifest_over)
        self.path = write_manifest(self.root, self.doc)

    def rewrite(self) -> Path:
        self.path = write_manifest(self.root, self.doc)
        return self.path


# ---------------------------------------------------------------------------
# Replay fixtures (written once, reviewed, committed)
# ---------------------------------------------------------------------------

#: scenario -> the Resource the scenario's contract names (and the review finding is on)
RESOURCES = {"sc01": "OrdersTable", "sc02": "IngestRole"}


def fixture_chain(tmp: Path, scenario: str) -> Chain:
    """The replay chain of ``scenario`` from the committed fixtures (the case repository is rebuilt)."""
    subject = json.loads((FIXTURES / scenario / "subject.json").read_text(encoding="utf-8"))
    review = (FIXTURES / scenario / "review.json").read_bytes()
    verification = (FIXTURES / scenario / "remediation-report.json").read_bytes()
    chain = Chain(tmp, subject["case"], RESOURCES[scenario], review, verification, chain_id="chain-replay-" + scenario)
    built = {"case": subject["case"], "base": chain.setup.base, "head": chain.setup.head, "config": chain.setup.config_rev}
    assert built == subject, "the case repository no longer reproduces the fixture's commits"
    return chain


def write_fixtures() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="chain-fixtures-") as tmp:
        for scenario, case_id in sorted(SCENARIO_CASES.items()):
            setup = build_case(Path(tmp), case_id)
            out = FIXTURES / scenario
            out.mkdir(exist_ok=True)
            (out / "review.json").write_bytes(review_report_bytes(casegen.scenario_text(scenario, "base")))
            (out / "remediation-report.json").write_bytes(verification_report_bytes(setup))
            (out / "subject.json").write_text(json.dumps({"case": case_id, "base": setup.base, "head": setup.head,
                                                          "config": setup.config_rev}, indent=2, sort_keys=True) + "\n",
                                              encoding="utf-8")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write-fixtures", action="store_true")
    args = parser.parse_args(argv)
    if args.write_fixtures:
        write_fixtures()
    return 0


if __name__ == "__main__":
    sys.exit(main())
