#!/usr/bin/env python3
"""Build an Agent review prompt from a Template's deterministic facts.

This is the v0.3.0 companion to ``extract_facts.py``. Where that script produces
the facts, this one wraps them in the structured review prompt a host Agent
reads (:mod:`iacreview.agentprompt`). It runs no language model and makes no
network call: the prompt is a deterministic function of the facts, and the
judgement stays with whatever consumes the prompt.

Two ways to use it:

1. Directly, when the host Agent (for example Kiro) is the reasoning engine.
   Run this script, hand the prompt to the Agent, collect its findings JSON, and
   feed that back through ``iac-review --agent-findings``.

2. Through an MCP server, when a model is reached over MCP. The prompt this
   script emits is the payload such a server sends. The plugin itself never
   opens that connection; ``docs/mcp/`` documents the optional integration.

The facts are read from ``--facts`` (a file produced by ``extract_facts.py``) or,
when ``--target`` is given instead, extracted in process first. stdout carries
one JSON object: the prompt string, the checklist, and the prompt schema
version. Nothing else is written there, and on failure stdout stays empty.
"""

from __future__ import annotations

import sys
from pathlib import Path

# scripts/ -> skill dir -> skills/ -> plugin root
_PLUGIN_ROOT = Path(__file__).resolve().parents[3]
if str(_PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_ROOT))

import argparse  # noqa: E402
import json  # noqa: E402
from typing import Any, Dict, Optional, Sequence  # noqa: E402

from iacreview import agentprompt, bootstrap, pathguard  # noqa: E402
from iacreview.errors import InputNotFoundError, SchemaViolationError  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    """Build this script's argument parser."""
    parser = bootstrap.new_parser(
        Path(__file__).name,
        "Build an Agent review prompt from deterministic Template facts.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--facts",
        metavar="PATH",
        help=(
            "A facts JSON file produced by extract_facts.py. Must resolve "
            "inside the workspace root."
        ),
    )
    group.add_argument(
        "--target",
        metavar="PATH",
        help=(
            "A CloudFormation Template to extract facts from in process before "
            "building the prompt. Must resolve inside the workspace root."
        ),
    )
    return parser


def _load_facts(path: Path) -> Dict[str, Any]:
    """Read and validate a facts JSON document.

    Raises:
        InputNotFoundError: The file cannot be read.
        SchemaViolationError: The file is not a JSON object.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputNotFoundError(
            "cannot read facts file {0}: {1}".format(path.name, exc)
        ) from exc
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise SchemaViolationError(
            "<facts file>", "not valid JSON: {0}".format(exc)
        )
    if not isinstance(document, dict):
        raise SchemaViolationError(
            "<facts file>", "must be a JSON object, got {0}".format(type(document).__name__)
        )
    return document


def _facts_from_target(target: Path, root: Path, verbose: bool) -> Dict[str, Any]:
    """Extract facts in process for a Template target."""
    from iacreview import iam  # local import: only needed on this path
    from iacreview.template import load_template
    from iacreview.source import workspace_relative

    # Reuse extract_facts' builder so the two paths stay identical.
    scripts_dir = Path(__file__).resolve().parent
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    import extract_facts  # noqa: E402

    loaded = load_template(target)
    template_file = workspace_relative(str(target), root) or target.name
    iam_result = iam.run_and_normalize(target, workspace_root=root, loaded=loaded)
    bootstrap.verbose_diagnostic(
        "extracted facts in process from {0}".format(template_file),
        verbose=verbose,
    )
    return extract_facts.build_facts(
        loaded,
        template_file=template_file,
        iam_findings=iam_result.findings,
    )


def run(args: argparse.Namespace) -> Dict[str, Any]:
    """Build the prompt and return the JSON payload for stdout."""
    root = Path.cwd()

    if args.facts:
        facts_path = pathguard.resolve_within(args.facts, root)
        facts = _load_facts(facts_path)
        bootstrap.verbose_diagnostic(
            "loaded facts from {0}".format(facts_path.name), verbose=args.verbose
        )
    else:
        target = pathguard.resolve_within(args.target, root)
        facts = _facts_from_target(target, root, args.verbose)

    prompt = agentprompt.build_prompt(facts)
    checklist = agentprompt.build_checklist(facts)
    bootstrap.verbose_diagnostic(
        "built prompt ({0} chars, {1} checklist item(s))".format(
            len(prompt), len(checklist)
        ),
        verbose=args.verbose,
    )

    return {
        "schema_version": agentprompt.PROMPT_SCHEMA_VERSION,
        "prompt": prompt,
        "checklist": checklist,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the script and return its exit code.

    Exit codes are the shared table: 0 on success, 2 for an invalid invocation,
    3 for a missing file, 4 for facts that are not JSON or a Template that does
    not parse, 5 for a YAML target when PyYAML is missing, 7 for a path outside
    the workspace, 8 for a file that is not a reviewable Template, 1 for an
    internal error. Only the prompt JSON reaches stdout; on failure stdout stays
    empty.
    """
    return bootstrap.run_entry_point(parser=build_parser(), run=run, argv=argv)


if __name__ == "__main__":
    raise SystemExit(main())
