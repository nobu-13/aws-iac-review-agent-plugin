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
from typing import Any, Dict, List, Optional, Sequence, Tuple

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
# WP2: synthetic pull and review answers for the gate
# ---------------------------------------------------------------------------

PR_AUTHOR = 5000001
REVIEWER_A = 5000002
REVIEWER_B = 5000003


def review(rid: int, state: str, user: Optional[int], at: Optional[str], commit: Optional[str],
           assoc: Optional[str] = "COLLABORATOR", **extra: Any) -> Dict[str, Any]:
    """One GitHub review object (the fields the gate reads, plus the kind of extra fields GitHub sends)."""
    obj: Dict[str, Any] = {"id": rid, "state": state, "user": None if user is None else {"id": user, "login": "user-{0}".format(user)},
                           "submitted_at": at, "commit_id": commit, "author_association": assoc, "body": ""}
    obj.update(extra)
    return obj


def stamp(minute: int) -> str:
    return "2026-10-30T06:{0:02d}:00Z".format(minute)


def make_gate_store(root: Path, base: str, head: str, reviews: List[Dict[str, Any]], pr_author: Optional[int] = PR_AUTHOR,
                    pr_head: Optional[str] = None, pages: int = 1, locator: str = "gate-store", repo: str = REPO,
                    number: int = 7, review_number: Optional[int] = None, state: str = "open", merged: bool = False,
                    mutate: Any = None, pull_extra: Optional[Dict[str, Any]] = None, with_pull: bool = True) -> Dict[str, Any]:
    """An M1 store with a pull capture and a review capture of ``pages`` pages; returns ``github_evidence``.

    ``mutate(captured)`` may change the list of captured pages before the revision is sealed (to build
    missing, duplicated or reordered pages)."""
    n = [0]

    def ids() -> str:
        n[0] += 1
        return "cap-gate-{0:04d}".format(n[0])

    pull = {"number": number, "state": state, "merged": merged, "merged_at": "2026-10-30T07:00:00Z" if merged else None,
            "user": None if pr_author is None else {"id": pr_author, "login": "user-{0}".format(pr_author)},
            "head": {"sha": pr_head or head}, "base": {"sha": base}}
    pull.update(pull_extra or {})
    captured: List[collector.CapturedEvidence] = []
    queue = [collector.HttpResponse(200, {"Content-Type": "application/json"}, json.dumps(pull, sort_keys=True).encode())]
    cap = collector.Collector(lambda r: queue.pop(0) if queue else None, repo, now=lambda: T0, id_factory=ids).capture(
        "GET", "/repos/{0}/pulls/{1}".format(repo, number), subject_commit_sha=head)
    if with_pull:
        captured.extend(cap.evidence)
    chunks = [reviews[i::pages] for i in range(pages)] if reviews else [[] for _ in range(pages)]
    rn = review_number or number
    path = "/repos/{0}/pulls/{1}/reviews".format(repo, rn)
    responses = []
    for i, chunk in enumerate(chunks):
        headers = {"Content-Type": "application/json"}
        if i + 1 < pages:
            headers["Link"] = '<{0}{1}?per_page=100&page={2}>; rel="next"'.format(collector.API_ROOT, path, i + 2)
        responses.append(collector.HttpResponse(200, headers, json.dumps(chunk, sort_keys=True).encode()))
    cap = collector.Collector(lambda r: responses.pop(0) if responses else None, repo, now=lambda: T0, id_factory=ids).capture(
        "GET", path + "?per_page=100", subject_commit_sha=head)
    captured.extend(cap.evidence)
    if mutate is not None:
        captured = mutate(captured)
    st = store.EvidenceStore(root / locator, root, now=lambda: T0)
    w = st.begin_revision("synthetic M2 gate evidence")
    for e in captured:
        w.add(e)
    w.seal()
    rev = next(r for r in st.verify().revisions if r.revision_id == w.revision_id)
    return {"store_locator": locator, "revision": w.revision_id, "manifest_sha256": rev.manifest_sha256,
            "evidence_ids": sorted(e.evidence_id for e in captured)}


def write_gate_records(root: Path, records: List[Dict[str, Any]], prefix: str = "gate") -> List[Dict[str, Any]]:
    """Write each record as canonical JSON below ``root``; returns the manifest's ``gate_records``."""
    entries = []
    for i, rec in enumerate(records):
        data = remediation_report.canonical(rec)
        kind = rec.get("kind") if rec.get("kind") in ("contract_approval", "candidate_review", "merge_decision") else "candidate_review"
        rel = write(root, "{0}/{1:02d}-{2}.json".format(prefix, i, kind), data)
        entries.append({"locator": rel, "sha256": sha256(data), "kind": kind})
    return entries


class GateChain:
    """A C02 chain with a gate store and the records regenerated from it (the correct records)."""

    def __init__(self, tmp: Path, reviews: List[Dict[str, Any]], with_review: bool = True, review_bytes: Optional[bytes] = None,
                 verification: Optional[bytes] = None, chain_id: str = "chain-gate-0001", **store_over: Any) -> None:
        from iacreview.chain import gate

        review_data = review_bytes if review_bytes is not None else (cached_review("sc02") if with_review else None)
        self.chain = Chain(tmp, "C02", "IngestRole", review_data, verification, with_github=False, chain_id=chain_id)
        self.setup = self.chain.setup
        self.root = self.chain.root
        self.chain.doc["github_evidence"] = make_gate_store(self.root, self.setup.base, self.setup.head, reviews, **store_over)
        self.chain.rewrite()
        self.records = gate.regenerate(self.chain.path)
        self.chain.doc["gate_records"] = write_gate_records(self.root, self.records)
        self.path = self.chain.rewrite()

    @property
    def doc(self) -> Dict[str, Any]:
        return self.chain.doc

    def with_records(self, records: List[Dict[str, Any]], name: str, prefix: str = "") -> Path:
        doc = dict(self.chain.doc, gate_records=write_gate_records(self.root, records, prefix or "gate-" + name))
        return write_manifest(self.root, doc, name + "-manifest.json")


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


#: WP2 gate Regression Anchor scenarios (D2-4, R2-4): name -> (reviews(head), store options).
GATE_SCENARIOS = ("gate-complete", "gate-not-proven", "gate-broken")


def gate_scenario(name: str, head: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    if name == "gate-complete":  # another account approves the head
        return [review(81000010, "APPROVED", REVIEWER_A, stamp(10), head)], {}
    if name == "gate-not-proven":  # single owner: GitHub accepts only a comment from the author
        return [review(81000010, "COMMENTED", PR_AUTHOR, stamp(10), head, assoc="OWNER")], {}
    if name == "gate-broken":  # a push after the approval: the chain verified a head that is no longer the PR's
        return [review(81000010, "APPROVED", REVIEWER_A, stamp(10), head)], {"pr_head": "f" * 40}
    raise KeyError(name)


def fixture_gate_chain(tmp: Path, name: str) -> "GateChain":
    """A gate anchor chain: the committed sc02 review and verification fixtures plus synthetic gate evidence."""
    subject = json.loads((FIXTURES / "sc02" / "subject.json").read_text(encoding="utf-8"))
    reviews, over = gate_scenario(name, subject["head"])
    g = GateChain(tmp, reviews, review_bytes=(FIXTURES / "sc02" / "review.json").read_bytes(),
                  verification=(FIXTURES / "sc02" / "remediation-report.json").read_bytes(), chain_id="chain-" + name, **over)
    built = {"case": "C02", "base": g.setup.base, "head": g.setup.head, "config": g.setup.config_rev}
    assert built == subject, "the case repository no longer reproduces the fixture's commits"
    return g


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
