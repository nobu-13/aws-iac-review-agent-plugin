#!/usr/bin/env python3
"""Fail the build when a repository file carries something shaped like a credential.

Requirement 9 AC1 forbids AWS credentials, API keys and secrets in *any*
repository file, and design.md's security table assigns the enforcement of that
criterion to continuous integration ("Repository 内の credential 不在 (Req 9 AC1)
| SMOKE | CI の secret scan"). This script is that scan.

Why a scanner in the repository rather than a third-party action
---------------------------------------------------------------

A hosted secret-scanning action would have to be pinned and trusted, and it
would still be wrong for this repository in one specific way: the benchmark and
the examples deliberately contain credential-*shaped* placeholders. The AWS
documentation account ID ``123456789012`` appears throughout ``benchmark/`` and
``examples/``; AWS's own documentation example access key ID appears in
``tests/`` as the value an IAM detector must not echo. A generic scanner reports
those, and the usual response -- a suppression file, or ``continue-on-error`` --
turns the gate off. Keeping the rules here means the allowlist is reviewable in
the same pull request as the placeholder it exempts, the scan needs no network
access, it behaves identically on Linux and macOS, and it costs no dependency
(steering/tech.md: standard library first).

What it looks for
-----------------

:data:`RULES` covers the credential classes steering/security.md enumerates: AWS
access key IDs, AWS secret access keys, session tokens, API keys, passwords, MCP
secrets (an API key or token in a configuration file is the same shape), plus
private key blocks and credentials embedded in a URL.

Every rule requires a *value*, not merely a keyword. Prose that names
``AWS_SECRET_ACCESS_KEY`` -- which the README, ``docs/security-model.md`` and
``iacreview/proc.py`` all do, because withholding it from child processes is a
documented guarantee -- is not a finding. An assignment of forty base64
characters to it is.

What it deliberately does not look for
--------------------------------------

A bare 12-digit number. ``123456789012`` is AWS's documentation placeholder
account ID and ``benchmark/README.md`` fixes it as the only account ID benchmark
templates may contain. ``tests/unit/test_ground_truth.py`` already asserts that
no *other* 12-digit number appears in a benchmark template, which is the check
that actually distinguishes a real account ID from the placeholder.

Reporting
---------

A finding prints its path, line number and rule name. It never prints the
matched text: steering/security.md forbids writing a credential to a log, and a
CI log is public on a public repository. The location is enough to find it, and
whoever fixes it can already read the file.

Exit codes
----------

===== ==========================================================
0     No finding.
1     At least one finding.
2     Bad arguments, or the requested root does not exist.
===== ==========================================================
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import List, NamedTuple, Optional, Pattern, Sequence, Tuple

__all__ = [
    "ALLOWLIST_PATTERN",
    "EXIT_FINDINGS",
    "EXIT_OK",
    "EXIT_USAGE",
    "Finding",
    "INLINE_ALLOW_MARKER",
    "MAX_FILE_BYTES",
    "RULES",
    "Rule",
    "SKIPPED_DIRECTORIES",
    "TRACKED_MODE",
    "WORKTREE_MODE",
    "candidate_files",
    "is_allowlisted",
    "main",
    "scan_file",
    "scan_text",
]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

#: How the file list was obtained. ``tracked`` is the accurate answer to "any
#: repository file": it is what ``git`` has under version control. ``worktree``
#: is the fallback for a checkout without git metadata (a release tarball, or a
#: machine without ``git`` installed), and it is reported so that a reader of the
#: output knows which set was scanned.
TRACKED_MODE = "tracked"
WORKTREE_MODE = "worktree"

#: Directory names never scanned, in either mode. Caches and virtual
#: environments are not repository content; scanning them is slow and, for a
#: virtual environment, reports other people's test fixtures.
SKIPPED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hypothesis",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "htmlcov",
        "cdk.out",
        "build",
        "dist",
    }
)

#: Files above this size are skipped. Nothing in this repository approaches it,
#: and the cap keeps a stray artifact from turning the scan into a long job.
MAX_FILE_BYTES = 2 * 1024 * 1024

#: Trailing marker that exempts one line. An escape hatch that stays visible in
#: the diff, unlike a suppression file: exempting a line requires editing the
#: line, so a reviewer sees the exemption next to what it exempts.
INLINE_ALLOW_MARKER = "secret-scan:allow"

#: What makes a value obviously not a credential. Applied to the whole matched
#: text, so it exempts both the placeholder value and a keyword paired with one.
#:
#: The two groups are placeholder vocabulary (``EXAMPLE``, ``placeholder``, ...)
#: and unresolved references (``!Ref``, ``${...}``, ``<your-key>``), which are
#: what a template or a documented configuration snippet contains where a real
#: deployment would hold a secret.
ALLOWLIST_PATTERN: Pattern[str] = re.compile(
    r"""
    example | placeholder | dummy | sample | redacted | changeme | change[_-]me
    | not[_-]?a[_-]?real | your[_-] | xxxx | fake | secret[_-]scan
    | \{\{ | \$\{ | !Ref | !Sub | !GetAtt | !Select | !ImportValue
    | <[a-z_-]+> | \.\.\. | \*\*\*
    """,
    re.IGNORECASE | re.VERBOSE,
)


class Rule(NamedTuple):
    """One credential shape.

    Attributes:
        name: Reported identifier, stable enough to grep a CI log for.
        description: What the shape is, for the failure message.
        pattern: Compiled regular expression. Matched per line.
    """

    name: str
    description: str
    pattern: Pattern[str]


class Finding(NamedTuple):
    """One line that matched one rule.

    Attributes:
        path: Repository-relative path, ``/``-separated so the report reads the
            same on both supported operating systems.
        line: 1-based line number.
        rule: The :attr:`Rule.name` that matched.
        description: The rule's description.
    """

    path: str
    line: int
    rule: str
    description: str

    def render(self) -> str:
        """One report line. Carries no matched text, by design."""
        return "{0}:{1}: {2} ({3})".format(
            self.path, self.line, self.rule, self.description
        )


#: Separator between a keyword and its value: ``=``, ``:`` or ``=>``.
_ASSIGN = r"""\s*(?:=>|[:=])\s*"""

#: Characters that end a bare value. A bare value also has to be at least eight
#: characters long, which is short enough to catch a weak password and long
#: enough that a keyword followed by an English word is not a finding.
_BARE = r"""[^\s"'`,;#}{\]\[|)(]{8,}"""

#: The three shapes an assigned *literal* takes, as opposed to an assigned
#: expression. This distinction is the one that matters for a repository whose
#: tests are full of lines like ``document, secret = template`` and
#: ``password = _parameter(facts, "DatabasePassword")``: those assign a value
#: computed elsewhere, and no credential is written down. The shapes kept are:
#:
#: quoted
#:     ``password = "..."``, ``"api_key": "..."`` -- a literal in source or in
#:     JSON, whatever the spacing.
#: bare after a colon
#:     ``password: ...`` -- a YAML scalar, which is how a credential most often
#:     reaches a CloudFormation template.
#: bare after an equals sign with no spacing
#:     ``PASSWORD=...`` -- the ``.env`` and shell-export form. Spacing is
#:     required to be absent here precisely because ``name = expression`` with
#:     spaces is Python assignment.
#: An optional closing quote after the keyword, for the JSON and YAML form
#: ``"api_key": "..."`` where the keyword itself is quoted.
_KEYWORD_END = r"""["']?"""

_LITERAL_VALUE = (
    r"""(?:"""
    + _KEYWORD_END
    + _ASSIGN
    + r"""["'](?P<quoted>[^\s"'`]{8,})["']"""
    + r"""|""" + _KEYWORD_END + r"""\s*:\s*(?P<yaml>""" + _BARE + r""")"""
    + r"""|""" + _KEYWORD_END + r"""=(?P<env>""" + _BARE + r""")"""
    + r""")"""
)

RULES: Tuple[Rule, ...] = (
    Rule(
        name="aws_access_key_id",
        description="AWS access key ID",
        # AKIA is a long-term key, ASIA a temporary one. Case-sensitive: a real
        # key ID is uppercase, and lowering the case here would match prose.
        pattern=re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ),
    Rule(
        name="aws_secret_access_key",
        description="AWS secret access key assigned a value",
        pattern=re.compile(
            r"(?i)\baws[_-]?secret[_-]?access[_-]?key\b"
            + _ASSIGN
            + r"""["']?(?P<value>[A-Za-z0-9/+=]{40})\b"""
        ),
    ),
    Rule(
        name="aws_session_token",
        description="AWS session token assigned a value",
        pattern=re.compile(
            r"(?i)\baws[_-]?session[_-]?token\b"
            + _ASSIGN
            + r"""["']?(?P<value>[A-Za-z0-9/+=]{40,})"""
        ),
    ),
    Rule(
        name="private_key_block",
        description="PEM private key header",
        pattern=re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    ),
    Rule(
        name="provider_token",
        description="provider-issued token with a recognizable prefix",
        # GitHub personal access, OAuth, user-to-server, server-to-server and
        # refresh tokens; Slack tokens; Stripe keys. All are prefixed by design
        # so that they can be recognized, which is what makes them worth listing
        # by prefix rather than by entropy.
        pattern=re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}"
            r"|xox[abposr]-[A-Za-z0-9-]{10,}"
            r"|sk_live_[A-Za-z0-9]{16,})\b"
        ),
    ),
    Rule(
        name="secret_assignment",
        description="password, API key, token or client secret assigned a value",
        pattern=re.compile(
            # No leading word boundary: the keyword is allowed a prefix, so that
            # ``MasterUserPassword``, ``DB_PASSWORD`` and ``MCP_SECRET_TOKEN``
            # are recognized. Those are the names a credential actually carries
            # in a CloudFormation template, a ``.env`` file and an MCP
            # configuration respectively.
            r"(?i)[a-z0-9_.-]*"
            r"(?:password|passwd|pwd"
            r"|secret|secret[_-]?key|client[_-]?secret"
            r"|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|bearer[_-]?token"
            r"|token"
            r")\b"
            + _LITERAL_VALUE
        ),
    ),
    Rule(
        name="url_credentials",
        description="credentials embedded in a URL",
        pattern=re.compile(r"://[^\s/:@]+:(?P<value>[^\s/:@]{4,})@"),
    ),
)


def is_allowlisted(line: str, matched: str) -> bool:
    """Whether a match on ``line`` is exempt.

    Args:
        line: The whole source line, so that the inline marker is honoured
            wherever on the line it sits.
        matched: The text the rule matched, which is what the placeholder
            vocabulary is applied to.

    Returns:
        ``True`` when the line carries :data:`INLINE_ALLOW_MARKER`, or when the
        matched text is recognizably a placeholder or an unresolved reference.
    """
    if INLINE_ALLOW_MARKER in line:
        return True
    return ALLOWLIST_PATTERN.search(matched) is not None


def scan_text(relative_path: str, text: str) -> List[Finding]:
    """Findings in one file's text.

    Args:
        relative_path: Repository-relative, ``/``-separated path, used only for
            reporting.
        text: The file's decoded content.

    Returns:
        Findings in ascending line order, and within a line in
        :data:`RULES` order, so that two runs over the same input print the same
        report.
    """
    findings: List[Finding] = []
    for number, line in enumerate(text.splitlines(), start=1):
        for rule in RULES:
            for match in rule.pattern.finditer(line):
                if is_allowlisted(line, match.group()):
                    continue
                findings.append(
                    Finding(
                        path=relative_path,
                        line=number,
                        rule=rule.name,
                        description=rule.description,
                    )
                )
                # One finding per rule per line. A line that matched twice has
                # one problem to fix, and repeating it adds noise.
                break
    return findings


def scan_file(root: Path, path: Path) -> List[Finding]:
    """Findings in one file, or none if it is not scannable text.

    A file is skipped when it is larger than :data:`MAX_FILE_BYTES`, when it
    holds a NUL byte, or when it is not valid UTF-8. Those are binaries; a
    credential hidden in one would be missed, and reporting every byte sequence
    that happens to look like a keyword in a compiled artifact would be worse.
    """
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return []
        data = path.read_bytes()
    except OSError:
        # A path that vanished or cannot be read is not a finding. It is also
        # not a reason to abandon the scan of everything else.
        return []
    if b"\x00" in data:
        return []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return []
    return scan_text(relative_posix(root, path), text)


def relative_posix(root: Path, path: Path) -> str:
    """``path`` relative to ``root`` with ``/`` separators.

    Falls back to the file name when ``path`` is not under ``root``, which
    cannot happen for a file this script discovered but keeps the reporting
    total.
    """
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def tracked_files(root: Path, git_executable: str = "git") -> Optional[List[Path]]:
    """Paths git has under version control, or ``None`` if git cannot say.

    ``None`` means git is absent, ``root`` is not a repository, or the command
    failed. The caller falls back to a filesystem walk and says so, rather than
    reporting a clean scan of nothing.
    """
    argv = [git_executable, "-C", str(root), "ls-files", "-z"]
    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except (OSError, ValueError):
        return None
    if completed.returncode != 0:
        return None
    names = [name for name in completed.stdout.decode("utf-8").split("\0") if name]
    if not names:
        return None
    return [root / name for name in names]


def walked_files(root: Path) -> List[Path]:
    """Every file under ``root``, minus :data:`SKIPPED_DIRECTORIES`.

    Sorted, so the report order does not depend on how the filesystem lists a
    directory (design.md, Determinism Design).
    """
    found: List[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        parts = path.relative_to(root).parts
        if any(part in SKIPPED_DIRECTORIES for part in parts):
            continue
        found.append(path)
    return found


def candidate_files(
    root: Path, git_executable: str = "git"
) -> Tuple[List[Path], str]:
    """The files to scan, and which mode produced them.

    Returns:
        ``(paths, mode)`` where ``mode`` is :data:`TRACKED_MODE` or
        :data:`WORKTREE_MODE`. Paths are sorted and exclude
        :data:`SKIPPED_DIRECTORIES` in both modes.
    """
    tracked = tracked_files(root, git_executable)
    if tracked is not None:
        paths = [
            path
            for path in sorted(tracked)
            if path.is_file()
            and not any(
                part in SKIPPED_DIRECTORIES for part in path.relative_to(root).parts
            )
        ]
        return paths, TRACKED_MODE
    return walked_files(root), WORKTREE_MODE


def scan(root: Path, git_executable: str = "git") -> Tuple[List[Finding], str, int]:
    """Scan a repository tree.

    Returns:
        ``(findings, mode, files_scanned)``.
    """
    paths, mode = candidate_files(root, git_executable)
    findings: List[Finding] = []
    for path in paths:
        findings.extend(scan_file(root, path))
    return findings, mode, len(paths)


def build_parser() -> argparse.ArgumentParser:
    """The command line: a root to scan, defaulting to the repository."""
    parser = argparse.ArgumentParser(
        prog="scan_secrets.py",
        description=(
            "Fail when a repository file carries something shaped like a "
            "credential (Requirement 9 AC1)."
        ),
    )
    parser.add_argument(
        "--root",
        metavar="DIR",
        default=None,
        help=(
            "Directory to scan. Defaults to the repository this script lives "
            "in."
        ),
    )
    return parser


def default_root() -> Path:
    """The repository root, derived from this file's location.

    ``.github/scripts/scan_secrets.py`` sits two directories below the root. No
    absolute path is written down anywhere, so the script works from any
    checkout.
    """
    return Path(__file__).resolve().parents[2]


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point. See the module docstring for the exit codes."""
    arguments = build_parser().parse_args(argv)
    root = Path(arguments.root).resolve() if arguments.root else default_root()
    if not root.is_dir():
        print("secret scan: not a directory: {0}".format(root), file=sys.stderr)
        return EXIT_USAGE

    findings, mode, scanned = scan(root)

    for finding in findings:
        print(finding.render())
    print(
        "secret scan: {0} finding(s) in {1} file(s) ({2} mode)".format(
            len(findings), scanned, mode
        )
    )
    if findings:
        print(
            "secret scan: remove the value, rotate it if it was ever real, and "
            "use an obvious placeholder instead. A line that is genuinely not a "
            "credential can carry the marker {0!r}.".format(INLINE_ALLOW_MARKER),
            file=sys.stderr,
        )
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
