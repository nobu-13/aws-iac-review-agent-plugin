"""cfn-lint and cfn-guard adapters of the verifier (Design 6).

Each call goes through :func:`iacreview.proc.run_bounded` with the Phase 1
limits. Output is parsed with the existing strict parsers
(``cfnlint.parse_output``, ``cfnguard.parse_records``) and reduced to states,
counts, rule names that the profile itself declares, rule IDs of a fixed shape
and digests. Raw tool output never leaves this module.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from iacreview import cfnlint, deltaio, pathguard, proc, toolcheck
from iacreview.errors import IacReviewError
from iacreview.remediation import rschema

CFN_LINT = "cfn-lint"
CFN_GUARD = "cfn-guard"
VERSION_TIMEOUT_S = 10
VERSION_MAX_BYTES = 64 * 1024
GUARD_EXIT_PASS = 0
GUARD_EXIT_FAIL = 19
_LINT_RULE_ID = re.compile(r"^[EWI][0-9]{4}$")

#: Tool state -> decision code, for every state other than PASS / FAIL.
STATE_CODES: Dict[str, str] = {
    "TOOL_UNAVAILABLE": "tool_unavailable",
    "VERSION_MISMATCH": "tool_version_mismatch",
    "TIMEOUT": "tool_timeout",
    "FAILED": "tool_failed",
    "OUTPUT_INVALID": "tool_output_invalid",
    "OUTPUT_TOO_LARGE": "tool_output_too_large",
    "NOT_PASSED": "check_not_passed",
    "NOT_RUN": "check_not_passed",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class ToolIdentity:
    name: str
    required_version: str
    observed_version: Optional[str]
    state: str  # PASS, TOOL_UNAVAILABLE, VERSION_MISMATCH, TIMEOUT, FAILED, OUTPUT_INVALID
    executable: Optional[str] = field(default=None, compare=False)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "required_version": self.required_version,
            "observed_version": self.observed_version,
            "state": self.state,
        }


def identify(name: str, pinned: str) -> ToolIdentity:
    """Find ``name`` on PATH and require exactly the pinned version."""
    resolved = shutil.which(name)
    if resolved is None:
        return ToolIdentity(name, pinned, None, "TOOL_UNAVAILABLE")
    try:
        result = proc.run_bounded([resolved, "--version"], VERSION_TIMEOUT_S, VERSION_MAX_BYTES)
    except IacReviewError:
        return ToolIdentity(name, pinned, None, "FAILED")
    if result.timed_out:
        return ToolIdentity(name, pinned, None, "TIMEOUT")
    if result.output_exceeded or result.exit_code != 0:
        return ToolIdentity(name, pinned, None, "FAILED")
    version = toolcheck.extract_version(
        (result.stdout + b"\n" + result.stderr).decode("utf-8", "replace")
    )
    if version is None:
        return ToolIdentity(name, pinned, None, "OUTPUT_INVALID")
    if version != pinned:
        return ToolIdentity(name, pinned, version, "VERSION_MISMATCH")
    return ToolIdentity(name, pinned, version, "PASS", resolved)


@dataclass
class CheckRun:
    """One tool execution, reduced to what may be reported."""

    check_id: str
    side: str
    state: str = "NOT_RUN"
    exit_code: Optional[int] = None
    input_sha256: Optional[str] = None
    output_sha256: Optional[str] = None
    counts: Dict[str, int] = field(default_factory=dict)
    rule_ids: Tuple[str, ...] = ()
    rule_states: Dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "side": self.side,
            "state": self.state,
            "exit_code": self.exit_code,
            "input_sha256": self.input_sha256,
            "output_sha256": self.output_sha256,
            "counts": dict(sorted(self.counts.items())),
            "rule_ids": list(self.rule_ids),
            "rule_states": dict(sorted(self.rule_states.items())),
        }


#: Environment variable that may LOWER the check timeout (tests, slow-tool
#: drills). It can never raise it above ``rschema.CHECK_TIMEOUT_S``, and a
#: lower timeout can only turn a result into TIMEOUT (UNVERIFIED).
TIMEOUT_OVERRIDE_ENV = "IACREVIEW_REMEDIATION_CHECK_TIMEOUT_S"


def check_timeout_s() -> int:
    raw = os.environ.get(TIMEOUT_OVERRIDE_ENV, "")
    if raw.isdigit() and 0 < int(raw) < rschema.CHECK_TIMEOUT_S:
        return int(raw)
    return rschema.CHECK_TIMEOUT_S


def _output_digest(result: proc.BoundedResult, input_path: Path) -> str:
    """SHA-256 of stdout + stderr with the random temp-file name replaced.

    The tools echo the data file name; without this the digest would differ
    on every run for the same input (Design 8, determinism).
    """
    out = result.stdout + b"\x00" + result.stderr
    for name in sorted({str(input_path), os.path.realpath(str(input_path))}, key=len, reverse=True):
        out = out.replace(name.encode("utf-8", "surrogateescape"), b"<input>")
    return _sha256(out)


def _execute(run: CheckRun, argv: List[str], input_path: Path) -> Optional[proc.BoundedResult]:
    try:
        result = proc.run_bounded(argv, check_timeout_s(), rschema.CHECK_MAX_OUTPUT_BYTES)
    except IacReviewError:
        run.state = "FAILED"
        return None
    # A run stopped by the timeout or the output limit left an arbitrary prefix
    # of its output behind: how much was read before the stop depends on pipe
    # buffering and scheduling (it differed between runs on Linux CI). That
    # prefix is not evidence of anything and is never parsed, so it gets no
    # digest; the state (TIMEOUT / OUTPUT_TOO_LARGE) is the whole result.
    if result.timed_out:
        run.state = "TIMEOUT"
        return None
    if result.output_exceeded:
        run.state = "OUTPUT_TOO_LARGE"
        return None
    run.output_sha256 = _output_digest(result, input_path)
    run.exit_code = result.exit_code
    return result


def run_cfn_lint(tool: ToolIdentity, template_bytes: bytes, fmt: str, side: str) -> CheckRun:
    """cfn-lint on one Template. PASS: no Error-level result."""
    run = CheckRun("cfn-lint", side, input_sha256=_sha256(template_bytes))
    if tool.state != "PASS" or tool.executable is None:
        run.state = tool.state
        return run
    suffix = ".json" if fmt == "json" else ".yaml"
    with pathguard.secure_temp_file(suffix) as path:
        Path(path).write_bytes(template_bytes)
        result = _execute(run, cfnlint.build_argv(path, executable=tool.executable), Path(path))
    if result is None:
        return run
    assert result.exit_code is not None
    if result.exit_code < 0 or not cfnlint.decode_cfnlint_exit(result.exit_code).ok:
        run.state = "FAILED"
        return run
    try:
        results = cfnlint.parse_output(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, IacReviewError):
        run.state = "OUTPUT_INVALID"
        return run
    counts = {"Error": 0, "Warning": 0, "Informational": 0}
    ids = set()
    for item in results:
        if item.level not in counts:
            run.state = "OUTPUT_INVALID"
            return run
        counts[item.level] += 1
        ids.add(item.rule_id if _LINT_RULE_ID.match(item.rule_id) else "other")
    has_error_bit = bool(result.exit_code & 2)
    if has_error_bit != (counts["Error"] > 0) or (result.exit_code == 0) != (not results):
        run.state = "OUTPUT_INVALID"
        return run
    # cfn-lint gives each result an "Id" derived from the file name, so the raw
    # output differs between runs on the same input. The digest is taken over
    # the parsed results without that Id and without the file name instead.
    run.output_sha256 = _sha256(
        json.dumps(
            [[r.rule_id, r.level, r.message, r.line, r.column, list(r.template_path or ())] for r in results],
            sort_keys=True,
            ensure_ascii=True,
            default=str,
        ).encode("ascii")
    )
    run.counts = counts
    run.rule_ids = tuple(sorted(ids))
    run.state = rschema.CHECK_FAIL if counts["Error"] else rschema.CHECK_PASS
    return run


def guard_argv(executable: str, data: Path, rules: Path) -> List[str]:
    """The fixed cfn-guard command line.

    ``cfnguard.build_argv`` adds ``--type CFNTemplate``, which is for a whole
    Template; the verifier evaluates a projection (Design 6), so the same flags
    are used without it.
    """
    return [
        executable,
        "validate",
        "--data",
        str(data),
        "--rules",
        str(rules),
        "--output-format",
        "json",
        "--show-summary",
        "none",
    ]


def projection(doc: Any, resource: str, parameters: Mapping[str, str]) -> bytes:
    """The Guard input: the contract's Resource and the contract parameters."""
    # Target is always present: an absent Resource becomes {} so every rule
    # FAILs on a missing property below /Target. (cfnguard.parse_records
    # rejects an unresolved clause at the document root, which an absent
    # Target would produce.)
    data: Dict[str, Any] = {"Params": dict(parameters), "Target": {}}
    resources = doc.get("Resources") if isinstance(doc, dict) else None
    if isinstance(resources, dict) and resource in resources:
        data["Target"] = resources[resource]
    return json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(",", ":"), default=_reject).encode("ascii")


def _reject(value: Any) -> Any:
    raise TypeError("not JSON serializable")


def run_guard(tool: ToolIdentity, rules: Path, data: bytes, rule_names: Sequence[str], side: str) -> CheckRun:
    """cfn-guard on one projection. Each named rule is PASS, FAIL or NOT_PASSED."""
    run = CheckRun("profile-guard", side, input_sha256=_sha256(data))
    run.rule_states = {name: "NOT_RUN" for name in rule_names}
    if tool.state != "PASS" or tool.executable is None:
        run.state = tool.state
        return run
    with pathguard.secure_temp_file(".json") as path:
        Path(path).write_bytes(data)
        result = _execute(run, guard_argv(tool.executable, Path(path), rules), Path(path))
    if result is None:
        return run
    if result.exit_code not in (GUARD_EXIT_PASS, GUARD_EXIT_FAIL):
        run.state = "FAILED"
        return run
    parsed = parse_guard_record(result.stdout)
    if parsed is None:
        run.state = "OUTPUT_INVALID"
        return run
    failed, passed, skipped = parsed
    if (failed & passed) or (failed & skipped) or (passed & skipped):
        run.state = "OUTPUT_INVALID"
        return run
    if (result.exit_code == GUARD_EXIT_FAIL) != bool(failed):
        run.state = "OUTPUT_INVALID"
        return run
    states: Dict[str, str] = {}
    for name in rule_names:
        if name in failed:
            states[name] = rschema.CHECK_FAIL
        elif name in passed:
            states[name] = rschema.CHECK_PASS
        else:
            states[name] = "NOT_PASSED"  # skipped, not applicable or never evaluated
    run.rule_states = states
    run.counts = {"compliant": len(passed), "not_compliant": len(failed), "not_applicable": len(skipped)}
    if any(s == "NOT_PASSED" for s in states.values()):
        run.state = "NOT_PASSED"
    elif any(s == rschema.CHECK_FAIL for s in states.values()):
        run.state = rschema.CHECK_FAIL
    else:
        run.state = rschema.CHECK_PASS
    return run


_GUARD_RECORD_KEYS = frozenset(("name", "metadata", "status", "not_compliant", "not_applicable", "compliant"))
_GUARD_STATUSES = frozenset(("PASS", "FAIL", "SKIP"))


def parse_guard_record(raw: bytes) -> Optional[Tuple[set, set, set]]:
    """Rule names per status from one cfn-guard 3.x JSON record, or ``None``.

    ``cfnguard.parse_records`` parses every violated clause for Findings and
    rejects clause shapes the profile rules produce (``Block`` from a ``some``
    block, ``InResolved``, an unresolved query at the root). The verifier only
    needs which named rules passed, failed or were skipped, so this reads the
    record envelope strictly and nothing below ``Rule.name``: exactly one JSON
    object with exactly the cfn-guard 3.2 record keys, string lists, rule
    names matching the profile's rule-name shape, and a ``status`` consistent
    with the lists. Anything else is ``None`` (OUTPUT_INVALID).
    """
    loaded = deltaio.parse_report_bytes(raw, None)
    if isinstance(loaded, deltaio.Failure):
        return None
    record = loaded.obj
    if not isinstance(record, dict) or set(record) != _GUARD_RECORD_KEYS:
        return None
    status = record["status"]
    lists = (record["not_compliant"], record["compliant"], record["not_applicable"])
    if status not in _GUARD_STATUSES or not all(isinstance(item, list) for item in lists):
        return None
    failed = set()
    for entry in record["not_compliant"]:
        rule = entry.get("Rule") if isinstance(entry, dict) and set(entry) == {"Rule"} else None
        name = rule.get("name") if isinstance(rule, dict) else None
        if not isinstance(name, str) or _GUARD_RULE_NAME.match(name) is None:
            return None
        failed.add(name)
    passed: set = set()
    skipped: set = set()
    for target, items in ((passed, record["compliant"]), (skipped, record["not_applicable"])):
        for name in items:
            if not isinstance(name, str) or _GUARD_RULE_NAME.match(name) is None:
                return None
            target.add(name)
    if failed:
        consistent = status == "FAIL"
    elif passed:
        consistent = status == "PASS"
    else:
        # Nothing evaluated. Whatever the status claims, every named rule ends
        # up NOT_PASSED below; an empty evaluation is never a pass.
        consistent = status in ("PASS", "SKIP")
    if not consistent:
        return None
    return failed, passed, skipped


_GUARD_RULE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def rule_state(run: CheckRun, rule: str) -> str:
    """The state of one rule: the run state unless the run itself completed."""
    if run.state in (rschema.CHECK_PASS, rschema.CHECK_FAIL, "NOT_PASSED"):
        return run.rule_states.get(rule, "NOT_PASSED")
    return run.state


def digest_rules(paths: List[Path]) -> List[Tuple[str, str]]:
    return [(p.name, _sha256(p.read_bytes())) for p in paths]
