#!/usr/bin/env python3
"""Verify that every Ground_Truth was committed no later than its Template.

Requirement 11 AC14 and AC15 are process rules: Ground_Truth is authored from
the *intended* defects of a Benchmark_Template before any review runs, and never
derived from observed review output. ``CONTRIBUTING.md`` states them and
``tests/unit/test_ground_truth.py`` asserts that each case *declares*
``authored_before_review: true``. Neither can tell whether the declaration is
true.

Commit history can, partially. If ``ground_truth.json`` first appears in the same
commit as its template, or in an earlier one, then no review of that template
existed in the repository when the expectations were written down. If it first
appears in a *later* commit, the expectations were added after the template, and
the reviewer of that pull request should be told so. This is evidence about
ordering, not proof of intent -- which is why the failure message says what was
observed rather than accusing anyone of back-filling.

Design
------

The comparison is separated from the git access, for two reasons. The comparison
is the part with rules in it and it is unit-tested directly against injected
commit data (``tests/unit/test_ci.py``), needing no repository and no fixture
commits. The git access is the part that can be unavailable, and it fails with
one clear message instead of one per case.

"Earlier commit" is decided by ancestry (``git merge-base --is-ancestor``), not
by commit timestamp. A rebase, a cherry-pick or a machine with a skewed clock can
make an ancestor carry a later timestamp than its descendant, and a check that
compared timestamps would report a violation that is not one.

Every git invocation passes an argument array; no value from a file name or a
case ID is ever concatenated into a shell command (steering/security.md).

Exit codes
----------

===== ==========================================================
0     Every case is ordered correctly.
1     At least one Ground_Truth was added after its Template.
2     Bad arguments, or a case whose ``template`` field is unusable.
3     Commit history is unavailable, so nothing could be verified.
===== ==========================================================

Exit 3 is a failure and not a pass. A check that cannot see history has verified
nothing, and reporting success for it would make the gate meaningless in exactly
the situation that hides a problem: a shallow clone. Continuous integration must
therefore check out full history (``fetch-depth: 0``).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Sequence

__all__ = [
    "EXIT_OK",
    "EXIT_UNAVAILABLE",
    "EXIT_USAGE",
    "EXIT_VIOLATION",
    "GROUND_TRUTH_FILENAME",
    "CasePaths",
    "GitHistory",
    "Verdict",
    "VERDICT_EARLIER_COMMIT",
    "VERDICT_GROUND_TRUTH_UNTRACKED",
    "VERDICT_LATER_COMMIT",
    "VERDICT_SAME_COMMIT",
    "VERDICT_TEMPLATE_UNTRACKED",
    "classify",
    "classify_all",
    "discover_cases",
    "exit_code_for",
    "main",
]

EXIT_OK = 0
EXIT_VIOLATION = 1
EXIT_USAGE = 2
EXIT_UNAVAILABLE = 3

#: The file that makes a directory a case. The same name
#: ``benchmark/harness/run_benchmark.py`` discovers cases by; restated here
#: rather than imported so that this script depends on nothing but the standard
#: library and can run before ``iacreview`` is importable.
GROUND_TRUTH_FILENAME = "ground_truth.json"

#: Ordering is correct: both files entered the repository in one commit.
VERDICT_SAME_COMMIT = "same_commit"

#: Ordering is correct: the Ground_Truth commit is an ancestor of the Template
#: commit, so the expectations existed first.
VERDICT_EARLIER_COMMIT = "earlier_commit"

#: Ordering is wrong: the Ground_Truth was added after the Template.
VERDICT_LATER_COMMIT = "later_commit"

#: The Ground_Truth has no add-commit. Either it is not committed yet, or the
#: clone is too shallow to contain the commit that added it.
VERDICT_GROUND_TRUTH_UNTRACKED = "ground_truth_untracked"

#: The Template has no add-commit, for the same two possible reasons.
VERDICT_TEMPLATE_UNTRACKED = "template_untracked"

#: Verdicts that mean the pair was checked and is acceptable.
PASSING_VERDICTS = frozenset({VERDICT_SAME_COMMIT, VERDICT_EARLIER_COMMIT})

#: Verdicts that mean nothing could be concluded about the pair.
UNKNOWN_VERDICTS = frozenset(
    {VERDICT_GROUND_TRUTH_UNTRACKED, VERDICT_TEMPLATE_UNTRACKED}
)


class CasePaths(NamedTuple):
    """One case, as the two repository-relative paths to compare.

    Attributes:
        case_id: The case directory name, used in the report.
        ground_truth: Repository-relative, ``/``-separated path to
            ``ground_truth.json``.
        template: Repository-relative, ``/``-separated path to the template the
            Ground_Truth's ``template`` field names.
    """

    case_id: str
    ground_truth: str
    template: str


class Verdict(NamedTuple):
    """The outcome for one case.

    Attributes:
        case: The case the verdict is about.
        verdict: One of the ``VERDICT_*`` constants.
        ground_truth_commit: Commit that added the Ground_Truth, or ``None``.
        template_commit: Commit that added the Template, or ``None``.
    """

    case: CasePaths
    verdict: str
    ground_truth_commit: Optional[str]
    template_commit: Optional[str]

    def render(self) -> str:
        """One report line, naming the case, the verdict and the two commits."""
        return "{0}: {1} (ground_truth={2}, template={3})".format(
            self.case.case_id,
            self.verdict,
            _short(self.ground_truth_commit),
            _short(self.template_commit),
        )


def _short(commit: Optional[str]) -> str:
    """A commit for display: the first 12 characters, or ``none``."""
    if not commit:
        return "none"
    return commit[:12]


class GitHistory:
    """The two questions this check asks of git.

    Kept behind a class so that :func:`classify` can be given a stand-in holding
    fixed answers. The stand-in needs only these two methods; there is no
    inheritance requirement.

    Args:
        root: Repository root. Passed to git as ``-C``, so the working directory
            of the process does not matter.
        git_executable: Name or path of the git binary. Resolved by the operating
            system on ``PATH``; never interpolated into a shell.
    """

    def __init__(self, root: Path, git_executable: str = "git") -> None:
        self.root = root
        self.git_executable = git_executable

    def _run(self, arguments: Sequence[str]) -> "subprocess.CompletedProcess[bytes]":
        """Run one git command with an argument array and no shell."""
        argv = [self.git_executable, "-C", str(self.root)]
        argv.extend(arguments)
        return subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
        )

    def available(self) -> bool:
        """Whether git can answer questions about :attr:`root`."""
        try:
            completed = self._run(["rev-parse", "--is-inside-work-tree"])
        except (OSError, ValueError):
            return False
        return completed.returncode == 0

    def is_shallow(self) -> bool:
        """Whether the clone is shallow, which truncates add-commit lookups."""
        try:
            completed = self._run(["rev-parse", "--is-shallow-repository"])
        except (OSError, ValueError):
            return False
        return completed.stdout.decode("utf-8", "replace").strip() == "true"

    def added_commit(self, relative_path: str) -> Optional[str]:
        """The commit that first added ``relative_path``, or ``None``.

        ``--diff-filter=A`` keeps additions; ``--reverse`` puts the oldest
        first, so the first line is the commit that introduced the file. A file
        deleted and re-added has more than one addition and the earliest is the
        right one to compare: it is when the content first existed.
        """
        try:
            completed = self._run(
                [
                    "log",
                    "--diff-filter=A",
                    "--reverse",
                    "--format=%H",
                    "--",
                    relative_path,
                ]
            )
        except (OSError, ValueError):
            return None
        if completed.returncode != 0:
            return None
        lines = [
            line.strip()
            for line in completed.stdout.decode("utf-8", "replace").splitlines()
            if line.strip()
        ]
        if not lines:
            return None
        return lines[0]

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        """Whether ``ancestor`` is reachable from ``descendant``."""
        try:
            completed = self._run(
                ["merge-base", "--is-ancestor", ancestor, descendant]
            )
        except (OSError, ValueError):
            return False
        return completed.returncode == 0


def classify(case: CasePaths, history: "GitHistory") -> Verdict:
    """Decide the ordering for one case.

    Args:
        case: The two paths to compare.
        history: Anything exposing ``added_commit`` and ``is_ancestor``. Tests
            pass a stand-in holding fixed commit data, which is what makes this
            function testable without a repository.

    Returns:
        A :class:`Verdict`. The two "untracked" verdicts mean the question could
        not be answered for that case, not that it passed.
    """
    ground_truth_commit = history.added_commit(case.ground_truth)
    template_commit = history.added_commit(case.template)

    if ground_truth_commit is None:
        return Verdict(
            case, VERDICT_GROUND_TRUTH_UNTRACKED, ground_truth_commit, template_commit
        )
    if template_commit is None:
        return Verdict(
            case, VERDICT_TEMPLATE_UNTRACKED, ground_truth_commit, template_commit
        )
    if ground_truth_commit == template_commit:
        return Verdict(
            case, VERDICT_SAME_COMMIT, ground_truth_commit, template_commit
        )
    if history.is_ancestor(ground_truth_commit, template_commit):
        return Verdict(
            case, VERDICT_EARLIER_COMMIT, ground_truth_commit, template_commit
        )
    return Verdict(case, VERDICT_LATER_COMMIT, ground_truth_commit, template_commit)


def classify_all(cases: Sequence[CasePaths], history: "GitHistory") -> List[Verdict]:
    """Verdicts for every case, in the order given."""
    return [classify(case, history) for case in cases]


def exit_code_for(verdicts: Sequence[Verdict]) -> int:
    """The process status for a set of verdicts.

    A violation outranks an unknown: if one Ground_Truth was demonstrably added
    late, that is the finding worth reporting, and the exit code should say so
    even when another case could not be resolved.
    """
    if any(verdict.verdict == VERDICT_LATER_COMMIT for verdict in verdicts):
        return EXIT_VIOLATION
    if any(verdict.verdict in UNKNOWN_VERDICTS for verdict in verdicts):
        return EXIT_UNAVAILABLE
    return EXIT_OK


class CaseError(Exception):
    """A case directory that cannot be turned into a pair of paths."""


def template_name(document: Dict[str, object], case_id: str) -> str:
    """The template file name a Ground_Truth declares.

    Read from the document rather than assumed to be ``template.yaml``: the
    ``template`` field is what ``benchmark/harness/run_benchmark.py`` resolves,
    so it is the file whose commit matters. All v0.1 cases happen to name
    ``template.yaml``, and a case that named something else would still be
    checked.

    Raises:
        CaseError: The field is absent, is not a string, is empty, or is not a
            plain file name. The same three rejections the harness makes, for the
            same reason: the field is untrusted input, and ``../`` in it must not
            become a path this script hands to git.
    """
    name = document.get("template")
    if not isinstance(name, str) or not name:
        raise CaseError(
            "{0}: 'template' must be a non-empty file name, got {1!r}".format(
                case_id, name
            )
        )
    if name in (".", "..") or name != Path(name).name:
        raise CaseError(
            "{0}: 'template' must be a plain file name with no path "
            "separator, got {1!r}".format(case_id, name)
        )
    return name


def discover_cases(root: Path, cases_dir: Path) -> List[CasePaths]:
    """Every case under ``cases_dir``, as repository-relative path pairs.

    Args:
        root: Repository root, which the returned paths are relative to.
        cases_dir: Directory of case directories, normally
            ``benchmark/cases``.

    Returns:
        One :class:`CasePaths` per directory holding a
        :data:`GROUND_TRUTH_FILENAME`, sorted by case ID so the report order does
        not depend on how the filesystem lists a directory.

    Raises:
        CaseError: A ``ground_truth.json`` is unreadable, is not JSON, is not an
            object, or names an unusable template.
    """
    cases: List[CasePaths] = []
    for directory in sorted(path for path in cases_dir.iterdir() if path.is_dir()):
        ground_truth = directory / GROUND_TRUTH_FILENAME
        if not ground_truth.is_file():
            continue
        try:
            document = json.loads(ground_truth.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise CaseError(
                "{0}: {1} is unreadable or not JSON: {2}".format(
                    directory.name, GROUND_TRUTH_FILENAME, exc
                )
            ) from exc
        if not isinstance(document, dict):
            raise CaseError(
                "{0}: {1} must hold a JSON object".format(
                    directory.name, GROUND_TRUTH_FILENAME
                )
            )
        name = template_name(document, directory.name)
        cases.append(
            CasePaths(
                case_id=directory.name,
                ground_truth=ground_truth.relative_to(root).as_posix(),
                template=(directory / name).relative_to(root).as_posix(),
            )
        )
    return cases


def build_parser() -> argparse.ArgumentParser:
    """The command line: which case tree to check, and in which repository."""
    parser = argparse.ArgumentParser(
        prog="check_ground_truth_order.py",
        description=(
            "Verify that each benchmark ground_truth.json was committed in the "
            "same commit as its template, or in an earlier one "
            "(Requirement 11 AC14, AC15)."
        ),
    )
    parser.add_argument(
        "--cases",
        metavar="DIR",
        default=None,
        help=(
            "Directory of case directories. Defaults to benchmark/cases in the "
            "repository this script lives in."
        ),
    )
    parser.add_argument(
        "--root",
        metavar="DIR",
        default=None,
        help=(
            "Repository root. Defaults to the repository this script lives in."
        ),
    )
    return parser


def default_root() -> Path:
    """The repository root, derived from this file's location.

    ``.github/scripts/check_ground_truth_order.py`` is two directories below the
    root, so no absolute path needs to be written down.
    """
    return Path(__file__).resolve().parents[2]


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point. See the module docstring for the exit codes."""
    arguments = build_parser().parse_args(argv)
    root = Path(arguments.root).resolve() if arguments.root else default_root()
    cases_dir = (
        Path(arguments.cases).resolve()
        if arguments.cases
        else root / "benchmark" / "cases"
    )

    if not cases_dir.is_dir():
        print(
            "ground truth order: not a directory: {0}".format(cases_dir),
            file=sys.stderr,
        )
        return EXIT_USAGE

    try:
        cases = discover_cases(root, cases_dir)
    except (CaseError, ValueError) as exc:
        print("ground truth order: {0}".format(exc), file=sys.stderr)
        return EXIT_USAGE

    if not cases:
        print(
            "ground truth order: no case directory under {0}".format(cases_dir),
            file=sys.stderr,
        )
        return EXIT_USAGE

    history = GitHistory(root)
    if not history.available():
        print(
            "ground truth order: cannot read commit history. Either git is not "
            "installed or {0} is not a git work tree, so the commit order of "
            "{1} case(s) was not verified.".format(root, len(cases)),
            file=sys.stderr,
        )
        return EXIT_UNAVAILABLE

    verdicts = classify_all(cases, history)
    for verdict in verdicts:
        print(verdict.render())

    checked = sum(1 for verdict in verdicts if verdict.verdict in PASSING_VERDICTS)
    print(
        "ground truth order: {0}/{1} case(s) verified".format(checked, len(verdicts))
    )

    status = exit_code_for(verdicts)
    if status == EXIT_VIOLATION:
        print(
            "ground truth order: a ground_truth.json was added after the "
            "template it describes. Requirement 11 AC14 requires the "
            "expectations to be authored from the template's intended defects "
            "before any review of it, and AC15 forbids deriving them from "
            "review output.",
            file=sys.stderr,
        )
    elif status == EXIT_UNAVAILABLE:
        if history.is_shallow():
            print(
                "ground truth order: the clone is shallow, so the commit that "
                "added a file may be missing. Check out full history "
                "(fetch-depth: 0).",
                file=sys.stderr,
            )
        else:
            print(
                "ground truth order: a file has no add-commit in this history. "
                "An uncommitted case cannot be verified.",
                file=sys.stderr,
            )
    return status


if __name__ == "__main__":
    raise SystemExit(main())
