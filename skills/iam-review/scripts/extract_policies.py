#!/usr/bin/env python3
"""Layer 2 input of the ``iam-review`` Skill: the policy inventory as JSON.

The second entry point of this Skill. It prints the structured policy inventory
design.md specifies as the input to Layer 2 -- the contextual reasoning the host
Agent performs -- so that the Agent reads an inventory the deterministic code
produced instead of reading the Template itself.

Two properties follow from that, and they are the reason this file exists at all:

the Agent sees what the detectors saw
    ``policy_sites[]`` is built by the same
    :mod:`iacreview.iam.locate` / :mod:`iacreview.iam.intrinsics` code Layer 1
    runs on, so an ``Fn::Sub`` is presented the way the detectors interpreted it
    and a value neither could interpret appears in ``unresolvable_locations``
    rather than as a plausible-looking string.

the Agent is told what is already reported
    ``deterministic_findings_summary[]`` names every Layer 1 match by rule,
    resource and severity. Requirement 2 AC14 and AC15 forbid Agent reasoning
    from restating a check a deterministic tool already performed, and this is
    the list it must not restate.

All generation logic lives in :func:`iacreview.iam.extract_policy_sites`; this
script is argv, containment, and stdout. Keeping it thin is what lets the output
contract be tested as a pure function (``tests/unit/test_iam_source.py``) rather
than only through a subprocess.

Streams
-------

stdout
    The inventory JSON, and nothing else. Byte-stable for a given Template, with
    or without ``--verbose`` (Requirement 16 AC11). Empty when the run failed.
stderr
    Diagnostics only.

Exit codes
----------

===  =====================================================================
0    The inventory was written. An empty ``policy_sites`` is a valid answer:
     the Template holds no IAM policy.
2    Argument validation failed: no ``--target``, unknown flag, or a shell
     metacharacter in the path.
3    The ``--target`` path does not exist or cannot be read.
4    The Template could not be parsed as YAML or JSON.
7    The ``--target`` path resolves outside the workspace root.
8    The Template holds no non-empty ``Resources`` mapping.
1    Unexpected internal error; the trace is on stderr.
===  =====================================================================

Nothing is written to stdout for any non-zero exit. The output object has
exactly the three keys of :data:`iacreview.iam.LAYER2_KEYS` and no envelope to
carry an ``errors[]`` array, and an Agent that received a partially populated
inventory would reason about a Template it had only partly seen. The failure is
described on stderr and by the exit code instead.
"""

import sys
from pathlib import Path

# scripts/ -> skill dir -> skills/ -> plugin root
_PLUGIN_ROOT = Path(__file__).resolve().parents[3]
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

from iacreview import bootstrap  # noqa: E402

bootstrap.require_plugin_root(__file__)

import argparse  # noqa: E402
from typing import Any, Dict, Optional, Sequence  # noqa: E402

from iacreview import iam, pathguard, template  # noqa: E402
from iacreview.source import workspace_relative  # noqa: E402

#: Shown in ``--help``.
DESCRIPTION = (
    "Extract the IAM policy inventory of one CloudFormation template as JSON: "
    "every policy site with its actions, resources, principals and conditions, "
    "which resources each policy owner is attached to, and a summary of the "
    "findings the deterministic IAM checks already reported."
)


def build_parser() -> bootstrap.EntryPointParser:
    """Build the argument parser.

    Returns:
        A parser accepting ``--target`` (required, exactly once) and
        ``--verbose``.

    Note:
        Unlike ``run_iam_scan.py``, ``--target`` is not repeatable. The output
        object names no file, and logical IDs are unique only within one
        Template, so two Templates merged into one inventory would give the
        Agent ``json_path`` values and an ``attached_to`` graph it could not
        attribute. Run the script once per Template instead.
    """
    parser = bootstrap.new_parser(Path(__file__).name, DESCRIPTION)
    parser.add_argument(
        "--target",
        metavar="PATH",
        required=True,
        help=(
            "Path to the CloudFormation template file to inventory, relative "
            "to the current working directory."
        ),
    )
    return parser


def workspace_root() -> Path:
    """Containment root for ``--target``.

    Returns:
        The current working directory, for the reason given in
        ``run_iam_scan.py``: the invoking workspace is what a reviewed Template
        must stay inside (Requirement 9 AC4).
    """
    return Path.cwd()


def validate(args: argparse.Namespace) -> None:
    """Resolve ``--target`` before the file is opened.

    Args:
        args: Parsed arguments. Gains a ``resolved_target`` attribute holding the
            absolute, contained path.

    Raises:
        UnsafeArgumentError: The target contains a shell metacharacter (exit 2).
        InvalidArgumentsError: The target is empty or cannot be normalized (exit 2).
        InputNotFoundError: The target does not exist (exit 3).
        PathContainmentError: The target resolves outside the workspace (exit 7).
    """
    args.resolved_target = pathguard.resolve_within(args.target, workspace_root())


def run(args: argparse.Namespace) -> Dict[str, Any]:
    """Load the Template and return its policy inventory.

    Args:
        args: Parsed arguments, carrying ``resolved_target`` from
            :func:`validate`.

    Returns:
        The Layer 2 input JSON: the three keys of
        :data:`iacreview.iam.LAYER2_KEYS`, with
        :data:`iacreview.iam.POLICY_SITE_KEYS` in each ``policy_sites`` entry.

    Raises:
        TemplateParseError: The file is not parsable as YAML or JSON (exit 4).
        NotReviewableError: The document has no non-empty ``Resources`` mapping
            (exit 8).
    """
    root = workspace_root()
    resolved = args.resolved_target
    relative = workspace_relative(str(resolved), root) or resolved.name

    loaded = template.load_template(resolved)
    inventory = iam.extract_policy_sites(loaded.doc, template_file=relative)

    sites = inventory[iam.POLICY_SITES_KEY]
    bootstrap.verbose_diagnostic(
        "{0}: {1} policy sites, {2} already reported by the deterministic "
        "checks".format(
            relative,
            len(sites),
            len(inventory[iam.DETERMINISTIC_FINDINGS_SUMMARY_KEY]),
        ),
        verbose=args.verbose,
    )
    return inventory


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point.

    Args:
        argv: Arguments without the program name. Defaults to ``sys.argv[1:]``.

    Returns:
        A documented exit code from :mod:`iacreview.exitcodes`.

    Note:
        No ``partial_report`` is supplied, which is what keeps stdout empty on
        failure; see the module docstring.
    """
    return bootstrap.run_entry_point(
        parser=build_parser(),
        run=run,
        argv=argv,
        validate=validate,
    )


if __name__ == "__main__":
    sys.exit(main())
