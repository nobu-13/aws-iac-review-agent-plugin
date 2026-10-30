"""Legacy Derived Re-evaluation of the Phase 1 helper evidence (Phase 2 M1 WP4-5).

    python3 -m iacreview.evidence.legacy_reeval OUTPUT.json

Re-evaluates E18, E19, E20 and E21 (the helper's ``app-evidence`` files) with the WP4 evaluator in mode
``LEGACY_DERIVED_REEVALUATION``, attaches the Phase 1 results from the Legacy Evidence Map as
``HISTORICAL_CLASSIFICATION_REFERENCE`` (after evaluation, for comparison only) and writes one canonical
JSON document to OUTPUT (exclusive create: an existing file is never overwritten).

This is a new artifact. It does not change, replace or re-decide any Phase 1 result. Where the helper's
evidence lacks a raw GitHub response (all of it), completeness and authenticity of what was captured in
Phase 1 stay NOT_PROVEN. Reads ``.agents/`` read-only; every file read is bound to its Legacy Map SHA-256.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from iacreview.evidence import canonical, evaluator, legacy, replay

OUT = ".agents/tasks/phase1/henv/out/app-demo-2/"
TARGETS = (
    ("E18", OUT + "app-evidence.20261028T045529589034Z-1.json"),
    ("E19", OUT + "app-evidence.20261028T044355543031Z-1.json"),
    ("E20", OUT + "app-evidence-reclassified.json"),
    ("E21", OUT + "app-evidence.json"),
)
W0 = OUT + "app-w0-views.json"
ARTIFACTS = OUT + "artifacts"


def run(repo_root: Path) -> Dict[str, Any]:
    definition, dsha = replay.load_definition()
    lmap = legacy.load_map()
    results: List[Dict[str, Any]] = []
    for lid, rel in TARGETS:
        r = evaluator.legacy_reevaluation(repo_root, rel, lid, lmap, definition, dsha, W0, ARTIFACTS)
        results.append(evaluator.attach_historical_reference(r, lmap))
    return {"report_kind": "phase1_legacy_derived_reevaluation", "report_version": 1,
            "statement": "New artifact. Phase 1 results are unchanged and are quoted only as HISTORICAL_CLASSIFICATION_REFERENCE. "
                         "No raw GitHub response of Phase 1 exists; the completeness and authenticity of the helper's capture stay NOT_PROVEN.",
            "results": results}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m iacreview.evidence.legacy_reeval")
    parser.add_argument("output")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[2]
    try:
        data = canonical.dumps(run(root))
    except (evaluator.LegacyDrift, OSError, ValueError) as exc:
        sys.stderr.write("legacy re-evaluation refused ({0}: {1})\n".format(type(exc).__name__, exc))
        return 3
    try:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    except FileExistsError:
        sys.stderr.write("refusing to overwrite {0}\n".format(Path(args.output).name))
        return 2
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
