"""``python3 -m iacreview.remediation {init,verify,explain}`` (Design 7).

* ``init``    writes a DRAFT contract for a shipped profile. Not an approval.
* ``verify``  verifies one candidate and writes the report JSON to stdout (or
              ``--output``). Exit: VERIFIED 0, BLOCKED 20, UNVERIFIED 21, ERROR 22.
* ``explain`` prints the human Summary of a report. It never re-decides;
              ``--check-binding`` exits 21 when the report is stale.

stdout carries one artefact only (JSON for ``verify``, text for ``explain``,
YAML for ``init``); every other message goes to stderr. ``iacreview.exitcodes``
is not used: these codes belong to this CLI alone.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, NoReturn, Optional, Sequence

from iacreview import deltaio
from iacreview.remediation import contract as contract_mod
from iacreview.remediation import gitsnap, profiles, report, rschema, verify

PROG = "python3 -m iacreview.remediation"
EXIT_OK = 0
EXIT_STALE = rschema.DECISION_EXIT_CODES[rschema.UNVERIFIED]
EXIT_INVALID = rschema.DECISION_EXIT_CODES[rschema.ERROR]
_REPOSITORY_ID = re.compile(r"^[A-Za-z0-9._-]{1,100}(/[A-Za-z0-9._-]{1,100})?$")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        sys.stderr.write("{0}: error: {1}\n".format(self.prog, message))
        raise SystemExit(EXIT_INVALID)


def _fail(message: str) -> int:
    sys.stderr.write("error: {0}\n".format(message))
    return EXIT_INVALID


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog=PROG, description="Phase 1 bounded remediation verifier.")
    sub = parser.add_subparsers(dest="command", parser_class=_Parser)

    p_init = sub.add_parser("init", help="write a DRAFT contract for a profile")
    p_init.add_argument("--list-profiles", action="store_true", help="list shipped profiles and exit")
    p_init.add_argument("--profile", help="profile id")
    p_init.add_argument("--template", help="repository-relative Template path (read from the working directory)")
    p_init.add_argument("--resource", help="Logical ID of the Resource to repair")
    p_init.add_argument("--parameter", action="append", default=[], metavar="NAME=VALUE", help="profile parameter")
    p_init.add_argument("--output", help="write the draft here instead of stdout (must not exist)")

    p_verify = sub.add_parser("verify", help="verify one candidate change")
    p_verify.add_argument("--repo", default=".", help="git work tree (default: .)")
    p_verify.add_argument("--base", required=True, help="Base revision")
    head = p_verify.add_mutually_exclusive_group(required=True)
    head.add_argument("--head", help="Head revision")
    head.add_argument("--worktree", action="store_true", help="preview the working tree as Head")
    p_verify.add_argument("--config-rev", help="trusted revision holding the approved contract")
    p_verify.add_argument("--contract", help="contract path inside --config-rev")
    p_verify.add_argument("--contract-file", help="DRAFT contract file on disk (preview only, never VERIFIED)")
    p_verify.add_argument("--execution-mode", choices=rschema.EXECUTION_MODES, default="local_preview")
    p_verify.add_argument("--repository-id", help="owner/name, recorded in the report")
    p_verify.add_argument("--output", help="write the report here instead of stdout (must not exist)")
    p_verify.add_argument("--summary", action="store_true", help="also print the human Summary to stderr")

    p_explain = sub.add_parser("explain", help="print the human Summary of a report")
    p_explain.add_argument("report", help="report JSON file")
    p_explain.add_argument("--check-binding", action="store_true", help="compare the report with the current revisions")
    p_explain.add_argument("--repo", default=".")
    p_explain.add_argument("--base")
    p_explain.add_argument("--head")
    p_explain.add_argument("--config-rev")
    p_explain.add_argument("--contract")
    return parser


def _write_new(path_text: str, data: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path_text, flags, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(data)


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:40] or "resource"


def cmd_init(args: argparse.Namespace) -> int:
    shipped = profiles.load_all()
    if args.list_profiles:
        for pid in sorted(shipped):
            listed = shipped[pid]
            names = ", ".join(sorted(listed.parameters)) or "-"
            sys.stdout.write("{0}\t{1}\t{2}\tparameters: {3}\n".format(pid, listed.resource_type, listed.title, names))
        return EXIT_OK
    if not (args.profile and args.template and args.resource):
        return _fail("init needs --profile, --template and --resource (or --list-profiles)")
    prof = shipped.get(args.profile)
    if prof is None:
        return _fail("unknown profile; run `init --list-profiles`")
    try:
        template_path = contract_mod.validate_template_path(args.template)
    except contract_mod.ContractError:
        return _fail("--template must be a repository-relative Template path without '..'")
    if not re.match(r"^[A-Za-z0-9]{1,255}$", args.resource):
        return _fail("--resource must be a CloudFormation Logical ID")
    parsed = deltaio.read_template(template_path, Path.cwd(), "base")
    if isinstance(parsed, deltaio.Failure):
        return _fail("the Template could not be read ({0})".format(parsed.code))
    resources = parsed.doc.get("Resources")
    resource = resources.get(args.resource) if isinstance(resources, dict) else None
    if not isinstance(resource, dict) or resource.get("Type") != prof.resource_type:
        return _fail("the Template has no Resource with that Logical ID and Type {0}".format(prof.resource_type))
    params: Dict[str, str] = {}
    for item in args.parameter:
        name, sep, value = item.partition("=")
        if not sep or name not in prof.parameters or not re.match(prof.parameters[name], value):
            return _fail("invalid --parameter; this profile takes: {0}".format(", ".join(sorted(prof.parameters)) or "none"))
        params[name] = value
    if set(params) != set(prof.parameters):
        return _fail("missing --parameter; this profile takes: {0}".format(", ".join(sorted(prof.parameters))))
    slug = _slug(args.resource)
    init = prof.init
    edits = init["allowed_edits"]
    assert isinstance(edits, list)
    fields: Dict[str, object] = {
        "contract_id": str(init["contract_id"]).format(resource_slug=slug)[:64].rstrip("-"),
        "profile_id": prof.profile_id,
        "profile_version": prof.profile_version,
        "task_id": str(init["task_id"]).format(resource_slug=slug)[:64].rstrip("-"),
        "template_path": template_path,
        "allowed_edits": [
            {"resource": args.resource, "property": e["property"], "operations": list(e["operations"])}
            for e in edits
        ],
        "required_outcomes": sorted(prof.outcomes),
        "preserve_invariants": sorted(prof.invariants),
        "parameters": params,
        "required_checks": list(prof.mandatory_checks),
    }
    text = contract_mod.render_contract(fields)
    # The draft must load under the same rules verify applies.
    contract_mod.bind_profile(contract_mod.parse_contract_bytes(text.encode("utf-8")), shipped)
    if args.output:
        try:
            _write_new(args.output, text)
        except OSError:
            return _fail("--output must name a new file")
        sys.stderr.write("draft contract written; it is NOT approved until committed to the protected configuration revision\n")
    else:
        sys.stdout.write(text)
    return EXIT_OK


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def cmd_verify(args: argparse.Namespace) -> int:
    started = time.monotonic()
    approved = args.config_rev is not None or args.contract is not None
    if approved == (args.contract_file is not None):
        return _fail("give either --config-rev with --contract, or --contract-file (draft preview)")
    if approved and not (args.config_rev and args.contract):
        return _fail("--config-rev and --contract go together")
    if args.contract and not contract_mod.is_safe_relative_path(args.contract):
        return _fail("--contract must be a repository-relative path without '..'")
    if args.repository_id and not _REPOSITORY_ID.match(args.repository_id):
        return _fail("--repository-id must look like owner/name")
    req = verify.Request(
        repo=Path(args.repo),
        base=args.base,
        head=None if args.worktree else args.head,
        config_rev=args.config_rev,
        contract_path=args.contract,
        contract_file=Path(args.contract_file) if args.contract_file else None,
        execution_mode=args.execution_mode,
        repository_id=args.repository_id,
    )
    result = verify.run(req)
    rep = report.build_report(result, started)
    text = report.serialize(rep)
    if args.output:
        try:
            _write_new(args.output, text)
        except OSError:
            sys.stderr.write("error: --output must name a new file; the report was not written\n")
            return EXIT_INVALID
    else:
        sys.stdout.write(text)
    if args.summary:
        sys.stderr.write(report.summary(rep))
    return int(rep["payload"]["exit_code"])


# ---------------------------------------------------------------------------
# explain
# ---------------------------------------------------------------------------


def _load_report(path_text: str) -> Optional[dict]:
    try:
        with open(path_text, "rb") as handle:
            raw = handle.read(rschema.MAX_REPORT_BYTES + 1)
    except OSError:
        return None
    if len(raw) > rschema.MAX_REPORT_BYTES:
        return None
    parsed = deltaio.parse_report_bytes(raw, None)
    if isinstance(parsed, deltaio.Failure):
        return None
    try:
        return report.validate(parsed.obj)
    except report.ReportError:
        return None


def binding_mismatches(rep: dict, args: argparse.Namespace) -> List[str]:
    """What no longer matches between a report and the current state."""
    p = rep["payload"]
    mismatches: List[str] = []
    current = report.validator_identity()
    if p["validator"]["source_sha256"] != current["source_sha256"]:
        mismatches.append("validator changed")
    shipped = profiles.load_all()
    prof = shipped.get(p["trust"]["profile_id"] or "")
    if prof is None or prof.digest != p["trust"]["profile_sha256"]:
        mismatches.append("profile or rules changed")
    try:
        repo = gitsnap.check_repo(Path(args.repo))
        for label, rev, recorded in (
            ("base", args.base, p["subject"]["base"]["commit"]),
            ("head", args.head, p["subject"]["head"]["commit"]),
            ("trusted config", args.config_rev, p["trust"]["trusted_config_commit"]),
        ):
            if rev is None:
                mismatches.append("{0} not given; cannot confirm".format(label))
            elif gitsnap.resolve_commit(repo, rev) != recorded:
                mismatches.append("{0} revision differs".format(label))
        if args.config_rev and args.contract:
            snap = gitsnap.commit_snapshot(repo, gitsnap.resolve_commit(repo, args.config_rev))
            entry = snap.entries.get(args.contract)
            data = gitsnap.read_blob(repo, entry.oid, rschema.MAX_CONTRACT_BYTES) if entry else None
            import hashlib

            if data is None or hashlib.sha256(data).hexdigest() != p["trust"]["contract_sha256"]:
                mismatches.append("contract changed")
        else:
            mismatches.append("contract not given; cannot confirm")
    except gitsnap.GitError:
        mismatches.append("repository could not be read")
    if p["subject"]["head"]["kind"] != "commit":
        mismatches.append("report is a worktree preview")
    return mismatches


def cmd_explain(args: argparse.Namespace) -> int:
    rep = _load_report(args.report)
    if rep is None:
        return _fail("not a valid Remediation_Verification_Report (shape or payload digest)")
    sys.stdout.write(report.summary(rep))
    sys.stdout.write(
        "This Summary restates the report. A report file proves nothing by itself: "
        "only a required check re-run by the trusted gate counts.\n"
    )
    if args.check_binding:
        mismatches = binding_mismatches(rep, args)
        if mismatches:
            sys.stdout.write("STALE: this report does not describe the current state:\n")
            sys.stdout.writelines("  - {0}\n".format(m) for m in mismatches)
            return EXIT_STALE
        sys.stdout.write("Binding: report matches the given revisions, contract, profile and validator.\n")
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.command == "init":
            return cmd_init(args)
        if args.command == "verify":
            return cmd_verify(args)
        if args.command == "explain":
            return cmd_explain(args)
    except Exception:  # noqa: BLE001 - no traceback on any input
        sys.stderr.write("error: internal error in {0}\n".format(PROG))
        return EXIT_INVALID
    parser.print_usage(sys.stderr)
    return EXIT_INVALID
