"""CI gate for the M1 Evidence Integrity Foundation (Phase 2 M1 CI Integration).

    python3 .github/scripts/evidence_ci_check.py --junit JUNIT.xml --expected EXPECTED.json [--summary OUT.md]

Run after ``pytest --junitxml=JUNIT.xml tests/unit/test_evidence_*.py`` in the ``evidence-integrity`` job. The checks,
in this order (every check runs; the exit code is the one of the first check that failed):

====  =========================  ===========================================================================
exit  name                       condition
====  =========================  ===========================================================================
10    EXPECTED_INVALID           the expected-hash file is not exactly the documented JSON object
11    SOURCE_MISMATCH            the current evaluator source SHA-256 is not the expected one
12    DEFINITION_MISMATCH        the current Definition (id, version, SHA-256) or evaluator version differs
13    BASELINE_MISMATCH          the baseline commit is not in this clone, is not an ancestor of HEAD, or its
                                 evaluator source / Definition do not hash to the expected values
14    HISTORY_INSUFFICIENT       a verified commit of the Definition is not in this clone (shallow checkout)
15    REPLAY_MISMATCH            the synthetic native replay (2 in-process, 2 separate processes with
                                 PYTHONHASHSEED=random) does not give the expected bytes
16    REPORT_MISMATCH            the final report of that replay does not give the expected bytes
17    LEGACY_RESULT_MISMATCH     the committed legacy re-evaluation result differs from the expected hash, or
                                 its recorded evaluator source / Definition hashes are not the current ones
18    FORBIDDEN_CHANGE           a path that must not change since the baseline (Phase 1 originals, private
                                 directories) changed
19    REQUIRED_TEST_SKIPPED      a required test is skipped or missing, or a test skipped without being on the
                                 local-only list
20    TEST_FAILURES              the JUnit report has failures or errors, or no test case
2     CHECK_ERROR                bad arguments, an unreadable input, or an unexpected exception in this script
====  =========================  ===========================================================================

Never updates the expected file: a difference is reported, not accepted. Standard library and the plugin only;
no network call (the replay runs with sockets disabled in-process). Tests that need the private Phase 1 evidence
(``.agents/``) are reported as NOT_VERIFIED (CI) in the summary, never as PASS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[2]

EXIT = {"OK": 0, "CHECK_ERROR": 2, "EXPECTED_INVALID": 10, "SOURCE_MISMATCH": 11, "DEFINITION_MISMATCH": 12,
        "BASELINE_MISMATCH": 13, "HISTORY_INSUFFICIENT": 14, "REPLAY_MISMATCH": 15, "REPORT_MISMATCH": 16,
        "LEGACY_RESULT_MISMATCH": 17, "FORBIDDEN_CHANGE": 18, "REQUIRED_TEST_SKIPPED": 19, "TEST_FAILURES": 20}
ORDER = ("EXPECTED_INVALID", "SOURCE_MISMATCH", "DEFINITION_MISMATCH", "BASELINE_MISMATCH", "HISTORY_INSUFFICIENT",
         "REPLAY_MISMATCH", "REPORT_MISMATCH", "LEGACY_RESULT_MISMATCH", "FORBIDDEN_CHANGE", "REQUIRED_TEST_SKIPPED",
         "TEST_FAILURES")

EXPECTED_FORMAT = "iacreview.evidence.ci-expected/1"
EXPECTED_KEYS = frozenset({"expected_format", "baseline_commit", "evaluator_version", "evaluator_source_sha256",
                           "definition_id", "definition_version", "definition_sha256", "definition_path",
                           "synthetic_spec", "native_result_sha256", "final_report_sha256", "legacy_result_path",
                           "legacy_result_sha256"})
SYNTHETIC_SPEC = "m1-pipeline-seven-scenarios/1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_REL = re.compile(r"^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$")

#: Tests in these files must all run (none may be skipped): registry / Definition validation, rule outcomes,
#: replay, the pipeline, S7-19 / final report, mutation.
REQUIRED_FILES = ("tests/unit/test_evidence_registry.py", "tests/unit/test_evidence_s7_definition.py",
                  "tests/unit/test_evidence_rule_outcomes.py", "tests/unit/test_evidence_replay.py",
                  "tests/unit/test_evidence_pipeline.py", "tests/unit/test_evidence_report.py",
                  "tests/unit/test_evidence_mutations.py")
#: Single tests that must be present and must run.
REQUIRED_TESTS = ("tests/unit/test_evidence_s7_definition.py::test_every_historical_clause_occurs_once_at_every_verified_commit",
                  "tests/unit/test_evidence_preflight.py::test_this_repository_public_set_passes_the_preflight",
                  "tests/unit/test_evidence_mutations.py::test_every_mutant_is_killed_in_an_isolated_copy",
                  "tests/unit/test_evidence_mutations.py::test_every_mutant_edit_matches_its_source_exactly_once",
                  "tests/unit/test_evidence_rule_outcomes.py::test_the_shipped_definition_agrees_with_the_reachable_outcomes")
#: Tests that need the private Phase 1 evidence under .agents/: skipped in CI, reported NOT_VERIFIED (CI).
LOCAL_ONLY = {
    "tests/unit/test_evidence_legacy.py::test_every_phase1_source_is_unchanged_since_the_map_was_made":
        "needs the private Phase 1 sources (.agents/); M1-10 current-file trace",
    "tests/unit/test_evidence_legacy_reeval.py::test_the_committed_results_are_reproduced_byte_for_byte":
        "needs the private Phase 1 sources (.agents/); M1-12 legacy re-evaluation regeneration",
    "tests/unit/test_evidence_legacy_reeval.py::test_the_phase1_sources_are_unchanged_by_the_reevaluation":
        "needs the private Phase 1 sources (.agents/); M1-12 Phase 1 originals unchanged",
}
#: Paths that must not change since the baseline commit (Phase 1 originals, private work areas).
FORBIDDEN_PREFIXES = ("docs/v2/phase1/", ".agents/", ".kiro/")
#: Paths whose change since the baseline is reported for Human review (they can weaken this gate).
REVIEW_PREFIXES = (".github/workflows/", ".github/scripts/", "tests/fixtures/evidence_replay/", "tests/unit/test_ci.py",
                   "tests/unit/test_evidence_", "tests/unit/evidence_synth.py", "tests/mutation/", "iacreview/evidence/")

WORKFLOW = b"name: probe\non: [pull_request]\npermissions: {}\n"

Git = Callable[[Sequence[str]], Tuple[int, bytes]]


class CheckError(Exception):
    """An input this script cannot work with (exit 2)."""


@dataclass
class Outcome:
    failures: List[Tuple[str, str]] = field(default_factory=list)  # (exit name, message)
    notes: List[str] = field(default_factory=list)
    values: Dict[str, Any] = field(default_factory=dict)
    local_only: List[Tuple[str, str]] = field(default_factory=list)
    review_paths: List[str] = field(default_factory=list)

    def fail(self, name: str, message: str) -> None:
        assert name in EXIT, name
        self.failures.append((name, message))

    @property
    def exit_code(self) -> int:
        names = {n for n, _ in self.failures}
        for name in ORDER:
            if name in names:
                return EXIT[name]
        return 0


def _git(root: Path) -> Git:
    def run(args: Sequence[str]) -> Tuple[int, bytes]:
        env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
        done = subprocess.run(["git", "-C", str(root), *args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, check=False)
        return done.returncode, done.stdout
    return run


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Expected file
# ---------------------------------------------------------------------------


def load_expected(path: Path) -> Dict[str, Any]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        raise CheckError("expected file {0} is unreadable".format(path.name)) from None
    except ValueError:
        raise CheckError("expected file {0} is not JSON".format(path.name)) from None
    return doc


def expected_problems(doc: Any) -> List[str]:
    if not isinstance(doc, dict):
        return ["not a JSON object"]
    problems = []
    if set(doc) != EXPECTED_KEYS:
        problems.append("keys differ: missing {0}, unknown {1}".format(sorted(EXPECTED_KEYS - set(doc)), sorted(set(doc) - EXPECTED_KEYS)))
        return problems
    if doc["expected_format"] != EXPECTED_FORMAT:
        problems.append("expected_format is not {0}".format(EXPECTED_FORMAT))
    if doc["synthetic_spec"] != SYNTHETIC_SPEC:
        problems.append("synthetic_spec is not {0}".format(SYNTHETIC_SPEC))
    if not (isinstance(doc["baseline_commit"], str) and _COMMIT.match(doc["baseline_commit"])):
        problems.append("baseline_commit is not a 40-hex commit id")
    for key in ("evaluator_source_sha256", "definition_sha256", "native_result_sha256", "final_report_sha256", "legacy_result_sha256"):
        if not (isinstance(doc[key], str) and _SHA256.match(doc[key])):
            problems.append("{0} is not a lower-case SHA-256".format(key))
    if not (isinstance(doc["definition_version"], int) and not isinstance(doc["definition_version"], bool) and doc["definition_version"] >= 1):
        problems.append("definition_version is not a positive integer")
    for key in ("evaluator_version", "definition_id"):
        if not (isinstance(doc[key], str) and doc[key]):
            problems.append("{0} is empty".format(key))
    for key in ("definition_path", "legacy_result_path"):
        if not (isinstance(doc[key], str) and _REL.match(doc[key]) and ".." not in doc[key].split("/")):
            problems.append("{0} is not a safe relative path".format(key))
    return problems


# ---------------------------------------------------------------------------
# Source, Definition, baseline, history
# ---------------------------------------------------------------------------


def _evaluator_sources() -> Tuple[str, ...]:
    from iacreview.evidence import evaluator
    return tuple(evaluator._SOURCES)


def _source_digest(read: Callable[[str], Optional[bytes]]) -> Optional[str]:
    h = hashlib.sha256()
    for name in _evaluator_sources():
        data = read(name)
        if data is None:
            return None
        h.update(name.encode("ascii") + b"\0" + data + b"\0")
    return h.hexdigest()


def check_source_and_definition(exp: Dict[str, Any], out: Outcome) -> None:
    from iacreview.evidence import evaluator, replay
    current = evaluator.evaluator_source_sha256()
    out.values["evaluator_source_sha256"] = current
    if current != exp["evaluator_source_sha256"]:
        out.fail("SOURCE_MISMATCH", "evaluator source {0} != expected {1}".format(current, exp["evaluator_source_sha256"]))
    try:
        definition, dsha = replay.load_definition()
    except Exception as exc:  # the registry refuses an invalid Definition
        out.fail("DEFINITION_MISMATCH", "the Definition does not validate ({0})".format(type(exc).__name__))
        return
    out.values.update(definition_sha256=dsha, definition_version=definition["definition_version"], evaluator_version=evaluator.EVALUATOR_VERSION)
    if replay.DEFINITION_PATH.resolve() != (ROOT / exp["definition_path"]).resolve():
        out.fail("DEFINITION_MISMATCH", "the replay reads {0}, not {1}".format(replay.DEFINITION_PATH.name, exp["definition_path"]))
    if (definition["definition_id"], definition["definition_version"], dsha) != (exp["definition_id"], exp["definition_version"], exp["definition_sha256"]):
        out.fail("DEFINITION_MISMATCH", "Definition {0} v{1} {2} != expected {3} v{4} {5}".format(
            definition["definition_id"], definition["definition_version"], dsha, exp["definition_id"], exp["definition_version"], exp["definition_sha256"]))
    if evaluator.EVALUATOR_VERSION != exp["evaluator_version"]:
        out.fail("DEFINITION_MISMATCH", "evaluator version {0} != expected {1}".format(evaluator.EVALUATOR_VERSION, exp["evaluator_version"]))


def check_baseline(exp: Dict[str, Any], out: Outcome, git: Git) -> None:
    """The expected values must come from the baseline commit: its evaluator sources and Definition hash to them,
    and the commit is an ancestor of the commit under test (a PR merge commit included)."""
    base = exp["baseline_commit"]
    head_code, head = git(["rev-parse", "HEAD"])
    out.values["head_commit"] = head.decode("ascii", "replace").strip() if head_code == 0 else None
    if git(["cat-file", "-e", base + "^{commit}"])[0] != 0:
        out.fail("BASELINE_MISMATCH", "baseline commit {0} is not in this clone".format(base))
        return
    if git(["merge-base", "--is-ancestor", base, "HEAD"])[0] != 0:
        out.fail("BASELINE_MISMATCH", "baseline commit {0} is not an ancestor of HEAD".format(base))
        return

    def read(rel: str) -> Optional[bytes]:
        code, data = git(["cat-file", "blob", "{0}:{1}".format(base, rel)])
        return data if code == 0 else None

    digest = _source_digest(lambda n: read("iacreview/evidence/" + n))
    if digest != exp["evaluator_source_sha256"]:
        out.fail("BASELINE_MISMATCH", "the evaluator source at the baseline commit hashes to {0}, not the expected value".format(digest))
    data = read(exp["definition_path"])
    if data is None or _sha(data) != exp["definition_sha256"]:
        out.fail("BASELINE_MISMATCH", "the Definition at the baseline commit does not hash to the expected value")


def check_history(out: Outcome, git: Git) -> None:
    from iacreview.evidence import replay
    definition, _ = replay.load_definition()
    commits = sorted({c for s in definition["historical_sources"] for c in s["verified_commits"]})
    missing = [c for c in commits if git(["cat-file", "-e", c + "^{commit}"])[0] != 0]
    out.values["verified_commits"] = len(commits)
    if missing:
        out.fail("HISTORY_INSUFFICIENT", "{0} of {1} verified commits are not in this clone (use fetch-depth: 0): {2}".format(
            len(missing), len(commits), ", ".join(c[:12] for c in missing)))
    not_ancestors = [c for c in commits if c not in missing and git(["merge-base", "--is-ancestor", c, "HEAD"])[0] != 0]
    if not_ancestors:
        out.notes.append("verified commits present but not ancestors of HEAD: {0}".format(", ".join(c[:12] for c in not_ancestors)))


def check_changed_paths(exp: Dict[str, Any], out: Outcome, git: Git) -> None:
    code, data = git(["diff", "--name-only", "-z", exp["baseline_commit"], "HEAD"])
    if code != 0:
        out.fail("FORBIDDEN_CHANGE", "cannot list the paths changed since the baseline commit")
        return
    changed = sorted(p for p in data.decode("utf-8", "replace").split("\0") if p)
    forbidden = [p for p in changed if p.startswith(FORBIDDEN_PREFIXES)]
    if forbidden:
        out.fail("FORBIDDEN_CHANGE", "changed since the baseline (must not change): {0}".format(", ".join(forbidden)))
    out.review_paths = [p for p in changed if p.startswith(REVIEW_PREFIXES)]
    out.values["changed_since_baseline"] = len(changed)


# ---------------------------------------------------------------------------
# Replay, final report, legacy result
# ---------------------------------------------------------------------------


@contextmanager
def no_network() -> Iterator[None]:
    saved = (socket.socket, socket.create_connection, socket.getaddrinfo)

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise OSError("network access is not allowed during the replay check")

    socket.socket, socket.create_connection, socket.getaddrinfo = refuse, refuse, refuse  # type: ignore[assignment,misc]
    try:
        yield
    finally:
        socket.socket, socket.create_connection, socket.getaddrinfo = saved  # type: ignore[misc]


def build_spec(workdir: Path) -> Dict[str, Any]:
    """The synthetic spec of tests/unit/test_evidence_pipeline.py::build (seven scenarios)."""
    sys.path.insert(0, str(ROOT / "tests" / "unit"))
    try:
        import evidence_synth as syn
    finally:
        sys.path.pop(0)
    b = syn.Builder(workdir)
    for gid in ("G0", "G1", "G2", "G3S", "G6"):
        b.add_scenario(syn.scenario_spec(gid))
    b.add_scenario(syn.scenario_spec("G3", impostor_required=True))
    g11 = syn.scenario_spec("G11")
    b.add_scenario(g11, b.add_artifact(g11["head"], {".github/workflows/probe.yml": WORKFLOW}, {".github/workflows/probe.yml": WORKFLOW}))
    return b.seal()


def check_replay(exp: Dict[str, Any], out: Outcome, separate_process: bool = True) -> None:
    from iacreview.evidence import final_report, replay
    tmp = Path(tempfile.mkdtemp(prefix="evidence-ci-"))
    try:
        spec = build_spec(tmp)
        with no_network():
            runs = [replay.replay(spec) for _ in range(2)]
            reports = [final_report.report_bytes(r) for r in runs]
        shas = [_sha(r) for r in runs]
        if separate_process:
            (tmp / "spec.json").write_text(json.dumps(spec), encoding="utf-8")
            (tmp / "expected.json").write_bytes(runs[0])
            env = dict(os.environ, PYTHONHASHSEED="random", PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(ROOT))
            for _ in range(2):
                done = subprocess.run([sys.executable, "-m", "iacreview.evidence.replay", "spec.json", "--expect", "expected.json"],
                                      cwd=str(tmp), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                if done.returncode != 0:
                    out.fail("REPLAY_MISMATCH", "separate-process replay exited {0}".format(done.returncode))
                shas.append(_sha(done.stdout))
        out.values.update(native_result_sha256=shas[0], replay_runs=len(shas), final_report_sha256=_sha(reports[0]))
        if set(shas) != {exp["native_result_sha256"]}:
            out.fail("REPLAY_MISMATCH", "native replay hashes {0} != expected {1}".format(sorted(set(shas)), exp["native_result_sha256"]))
        if {_sha(r) for r in reports} != {exp["final_report_sha256"]}:
            out.fail("REPORT_MISMATCH", "final report {0} != expected {1}".format(_sha(reports[0]), exp["final_report_sha256"]))
    finally:
        shutil.rmtree(str(tmp), ignore_errors=True)


def check_legacy_result(exp: Dict[str, Any], out: Outcome) -> None:
    path = ROOT / exp["legacy_result_path"]
    try:
        data = path.read_bytes()
    except OSError:
        out.fail("LEGACY_RESULT_MISMATCH", "{0} is missing".format(exp["legacy_result_path"]))
        return
    out.values["legacy_result_sha256"] = _sha(data)
    if _sha(data) != exp["legacy_result_sha256"]:
        out.fail("LEGACY_RESULT_MISMATCH", "legacy result {0} != expected {1}".format(_sha(data), exp["legacy_result_sha256"]))
    try:
        doc = json.loads(data.decode("ascii"))
        heads = {(r["evaluator"]["source_sha256"], r["definition"]["definition_sha256"]) for r in doc["results"]}
    except (UnicodeDecodeError, ValueError, KeyError, TypeError):
        out.fail("LEGACY_RESULT_MISMATCH", "legacy result is not a re-evaluation report")
        return
    if heads != {(exp["evaluator_source_sha256"], exp["definition_sha256"])}:
        out.fail("LEGACY_RESULT_MISMATCH", "legacy result was made with another evaluator source or Definition")
    out.notes.append("legacy result: header checked only; regeneration needs .agents/ (NOT_VERIFIED in CI)")


# ---------------------------------------------------------------------------
# JUnit classification
# ---------------------------------------------------------------------------


def _node_id(case: ET.Element) -> str:
    cls, name = case.get("classname", ""), case.get("name", "")
    return "{0}.py::{1}".format(cls.replace(".", "/"), name.split("[", 1)[0])


def check_junit(path: Path, out: Outcome) -> None:
    try:
        tree = ET.parse(str(path))
    except (OSError, ET.ParseError):
        raise CheckError("JUnit report {0} is unreadable".format(path.name)) from None
    cases = list(tree.getroot().iter("testcase"))
    if not cases:
        out.fail("TEST_FAILURES", "the JUnit report has no test case")
        return
    seen: Dict[str, List[str]] = {}
    for case in cases:
        state = "passed"
        for child in case:
            if child.tag in ("failure", "error"):
                state = child.tag
            elif child.tag == "skipped" and state == "passed":
                state = "skipped"
        seen.setdefault(_node_id(case), []).append(state)
    failed = sorted(n for n, s in seen.items() if "failure" in s or "error" in s)
    if failed:
        out.fail("TEST_FAILURES", "{0} test(s) failed: {1}".format(len(failed), ", ".join(failed[:5])))
    for test in REQUIRED_TESTS:
        if test not in seen:
            out.fail("REQUIRED_TEST_SKIPPED", "required test did not run: {0}".format(test))
        elif "skipped" in seen[test]:
            out.fail("REQUIRED_TEST_SKIPPED", "required test skipped: {0}".format(test))
    for f in REQUIRED_FILES:
        if not any(n.startswith(f + "::") for n in seen):
            out.fail("REQUIRED_TEST_SKIPPED", "no test of {0} ran".format(f))
    for node, states in sorted(seen.items()):
        if "skipped" not in states:
            continue
        if node in LOCAL_ONLY:
            out.local_only.append((node, LOCAL_ONLY[node]))
        elif node not in REQUIRED_TESTS:
            out.fail("REQUIRED_TEST_SKIPPED", "skipped and not on the local-only list: {0}".format(node))
    out.values.update(test_cases=len(cases), skipped=sum(s.count("skipped") for s in seen.values()))


# ---------------------------------------------------------------------------
# Summary and entry point
# ---------------------------------------------------------------------------


#: The checks each AC depends on in this job (failure names); "local" marks a part only the local-only tests show.
AC_CHECKS: Tuple[Tuple[str, Tuple[str, ...], str], ...] = (
    ("M1-01 git-managed, runs from a clone without .agents/", ("TEST_FAILURES", "REQUIRED_TEST_SKIPPED", "FORBIDDEN_CHANGE"), ""),
    ("M1-02 criteria, rules, tests, history", ("DEFINITION_MISMATCH", "HISTORY_INSUFFICIENT", "REQUIRED_TEST_SKIPPED", "TEST_FAILURES"), ""),
    ("M1-03 mutation (32 mutants)", ("REQUIRED_TEST_SKIPPED", "TEST_FAILURES"), ""),
    ("M1-04..M1-09, M1-11 (synthetic evidence)", ("TEST_FAILURES", "REQUIRED_TEST_SKIPPED"), ""),
    ("M1-05 replay bytes against the baseline", ("SOURCE_MISMATCH", "DEFINITION_MISMATCH", "BASELINE_MISMATCH", "REPLAY_MISMATCH", "REPORT_MISMATCH"), ""),
    ("M1-10 Phase 1 file trace", (), "local"),
    ("M1-12 legacy result header", ("LEGACY_RESULT_MISMATCH",), ""),
    ("M1-12 legacy regeneration, Phase 1 originals and helper tests", (), "local"),
)


def ac_table(out: Outcome) -> List[Tuple[str, str]]:
    failed = {n for n, _ in out.failures}
    rows = []
    for ac, checks, kind in AC_CHECKS:
        if kind == "local":
            rows.append((ac, "NOT_VERIFIED (CI): needs .agents/"))
        elif failed & set(checks):
            rows.append((ac, "FAILED"))
        else:
            rows.append((ac, "PASS (this job's checks)"))
    return rows


def summary(out: Outcome, exp: Optional[Dict[str, Any]]) -> str:
    verdict = "FAILED (exit {0})".format(out.exit_code) if out.exit_code else "PASS for the checks this job runs"
    lines = ["## M1 evidence integrity (CI)", "", "* verdict: **{0}**".format(verdict),
             "* this is not a PASS of M1 as a whole: the local-only tests below and the NOT_PROVEN items are not shown by CI",
             "* commit under test: `{0}` (GITHUB_SHA `{1}`, PR head `{2}`)".format(out.values.get("head_commit"), os.environ.get("GITHUB_SHA", "-"),
                                                                               os.environ.get("EVIDENCE_PR_HEAD_SHA") or "-"),
             "* baseline commit: `{0}`".format(exp.get("baseline_commit") if exp else "-"),
             "* Python {0} on {1}".format(platform.python_version(), platform.system()), "", "| value | observed |", "| --- | --- |"]
    for key in ("evaluator_version", "evaluator_source_sha256", "definition_version", "definition_sha256", "native_result_sha256",
                "final_report_sha256", "legacy_result_sha256", "replay_runs", "test_cases", "skipped", "verified_commits",
                "changed_since_baseline"):
        if key in out.values:
            lines.append("| {0} | `{1}` |".format(key, out.values[key]))
    lines += ["", "### M1 acceptance in this CI run", "", "| AC | CI result |", "| --- | --- |"]
    for ac, verdict_ in ac_table(out):
        lines.append("| {0} | {1} |".format(ac, verdict_))
    lines += ["", "### Failures", ""] + (["* {0}: {1}".format(n, m) for n, m in out.failures] or ["* none"])
    lines += ["", "### Local-only tests (NOT_VERIFIED in CI)", ""]
    lines += ["* `{0}`: {1}".format(n, r) for n, r in out.local_only] or ["* none skipped"]
    lines += ["", "### Changed since the baseline, review required", ""]
    lines += ["* `{0}`".format(p) for p in out.review_paths] or ["* none"]
    lines += ["", "### Notes", ""] + (["* " + n for n in out.notes] or ["* none"])
    lines += ["", "### Always NOT_PROVEN", "",
              "* real GitHub raw evidence end to end, capture authenticity, independent third-party reproduction",
              "* M1-10 historical raw responses; S7-17, S7-18 (limits); S7-19 Q2 / Q3"]
    return "\n".join(lines) + "\n"


def run(junit: Path, expected_path: Path, git: Optional[Git] = None, separate_process: bool = True) -> Tuple[Outcome, Optional[Dict[str, Any]]]:
    out = Outcome()
    exp_doc = load_expected(expected_path)
    problems = expected_problems(exp_doc)
    if problems:
        out.fail("EXPECTED_INVALID", "; ".join(problems))
        check_junit(junit, out)
        return out, None
    exp: Dict[str, Any] = exp_doc
    g = git or _git(ROOT)
    check_source_and_definition(exp, out)
    check_baseline(exp, out, g)
    check_history(out, g)
    check_replay(exp, out, separate_process)
    check_legacy_result(exp, out)
    check_changed_paths(exp, out, g)
    check_junit(junit, out)
    return out, exp


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="evidence_ci_check.py")
    parser.add_argument("--junit", required=True)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY"))
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return EXIT["CHECK_ERROR"]
    sys.path.insert(0, str(ROOT))
    try:
        out, exp = run(Path(args.junit), Path(args.expected))
    except CheckError as exc:
        sys.stderr.write("evidence CI check error: {0}\n".format(exc))
        return EXIT["CHECK_ERROR"]
    except Exception as exc:  # reported, never treated as a pass
        sys.stderr.write("evidence CI check aborted: {0}\n".format(type(exc).__name__))
        return EXIT["CHECK_ERROR"]
    text = summary(out, exp)
    sys.stdout.write(text)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(text)
    return out.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
