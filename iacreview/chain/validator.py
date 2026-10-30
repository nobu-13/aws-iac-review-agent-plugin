"""Chain Validator: one manifest in, one ``iacreview.chain.result/1`` document out.

Source: ``docs/v2/phase2/m2/wp0/m2-schemas.md`` rev1 §3. The payload is deterministic (no time, host
path, process id or float); the metadata holds the run time and the payload digest. A manifest that
cannot be used yields ``chain_status: BROKEN``, no links and its reason in ``manifest_codes``; an
unexpected error inside a link check becomes that link's ``link_check_error`` (INCOMPLETE), never a pass.
"""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from iacreview.chain import links as lk
from iacreview.chain import manifest as mf
from iacreview.chain import status as st
from iacreview.remediation import gitsnap
from iacreview.remediation import report as remediation_report

RESULT_FORMAT = "iacreview.chain.result/1"
VALIDATOR_VERSION = "iacreview.chain.validator/1"
_PACKAGE = Path(__file__).resolve().parent


def validator_source_sha256() -> str:
    """SHA-256 over the name and bytes of every ``.py`` file of this package, in name order."""
    h = hashlib.sha256()
    for path in sorted(_PACKAGE.glob("*.py")):
        h.update(path.name.encode("ascii") + b"\0" + path.read_bytes() + b"\0")
    return h.hexdigest()


def _guarded(link: str, check: Callable[[], lk.LinkResult]) -> lk.LinkResult:
    try:
        return check()
    except Exception:  # noqa: BLE001 - fail closed: an unexpected error is never a pass
        res = lk.LinkResult(link)
        res.add("link_check_error")
        return res


def _payload(manifest_sha: Optional[str], manifest_codes: List[str], results: List[lk.LinkResult]) -> Dict[str, Any]:
    links = [r.as_dict() for r in results]
    statuses = {r["link"]: r["status"] for r in links}
    chain = st.BROKEN if manifest_codes else st.compose(statuses)
    return {
        "chain_status": chain,
        "manifest_sha256": manifest_sha,
        "manifest_codes": sorted(manifest_codes),
        "validator": {"version": VALIDATOR_VERSION, "source_sha256": validator_source_sha256()},
        "links": links,
        "not_claimed": list(st.NOT_CLAIMED),
    }


def _result(payload: Dict[str, Any], started: float, diagnostics: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    return {
        "result_format": RESULT_FORMAT,
        "payload": payload,
        "metadata": {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "duration_ms": int((time.monotonic() - started) * 1000),
            "payload_sha256": hashlib.sha256(remediation_report.canonical(payload)).hexdigest(),
            # Environment-dependent notes (status.DIAGNOSTICS): outside the payload, so outside its digest.
            "diagnostics": sorted(diagnostics or [], key=lambda d: (d["link"], d["code"])),
        },
    }


def evaluate(doc: Dict[str, Any], root: Path, repo: Optional[Path]) -> List[lk.LinkResult]:
    """Run the six link checks on a schema-checked manifest, in :data:`status.LINKS` order."""
    ctx = lk.Context(root=root, repo=repo, doc=doc)
    loaded = lk.LinkResult("verification")
    try:
        lk.load_report(ctx, loaded)
    except Exception:  # noqa: BLE001
        loaded.add("link_check_error")
    out: Dict[str, lk.LinkResult] = {
        "subject": _guarded("subject", lambda: lk.check_subject(ctx)),
        "contract": _guarded("contract", lambda: lk.check_contract(ctx)),
    }
    out["review"] = _guarded("review", lambda: lk.check_review(ctx))
    out["verification"] = _guarded("verification", lambda: lk.check_verification(ctx, loaded))
    out["gate"] = _guarded("gate", lambda: lk.check_gate(ctx))
    out["github"] = _guarded("github", lambda: lk.check_github(ctx))
    return [out[name] for name in st.LINKS]


def validate(manifest_path: Path, repo: Path) -> Dict[str, Any]:
    """Validate the chain whose manifest is ``manifest_path`` against the local git repository ``repo``.

    The manifest's directory is the chain root. Returns the result document; never raises for bad input.
    """
    started = time.monotonic()
    manifest_path = Path(os.path.abspath(str(manifest_path)))  # absolute, links not resolved
    try:
        manifest = mf.load(manifest_path)
    except mf.ManifestError as exc:
        return _result(_payload(None, [exc.code], []), started)
    except Exception:  # noqa: BLE001
        return _result(_payload(None, ["manifest_unreadable"], []), started)
    try:
        resolved: Optional[Path] = gitsnap.check_repo(Path(repo))
    except gitsnap.GitError:
        resolved = None
    results = evaluate(manifest.doc, manifest_path.parent, resolved)
    diagnostics = [d for r in results for d in r.diagnostics]
    return _result(_payload(manifest.sha256, [], results), started, diagnostics)


def exit_code(result: Dict[str, Any]) -> int:
    """The reserved exit code for a result document (34 when the manifest was unusable)."""
    payload = result.get("payload") or {}
    return st.exit_code_for(payload.get("chain_status", st.INCOMPLETE), input_invalid=bool(payload.get("manifest_codes")))
