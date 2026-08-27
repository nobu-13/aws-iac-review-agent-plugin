"""The IAM review Source: deterministic IAM findings for one Template.

This package holds Layer 1 of design.md's *IAM Review Architecture*. The three
implementation modules each answer one question --
:mod:`~iacreview.iam.locate` where the policies are,
:mod:`~iacreview.iam.intrinsics` what a value says (and when that cannot be
known), :mod:`~iacreview.iam.detectors` which of the fifteen dangerous patterns
matched -- and this module is the Source that binds them into the single call
design.md's orchestration loop makes: ``spec.fn(template)`` returning a
:class:`~iacreview.source.SourceResult`. It is the same shape
``cfnlint.run_and_normalize`` and ``cfnguard.run_and_normalize`` return, so the
orchestrator treats all three Sources identically and a fourth could be added
without touching it.

Every Finding this Source produces carries ``Confidence: "Confirmed"``
(Requirement 7 AC9). Layer 2 -- the contextual reasoning the ``iam-review``
Skill asks of the host Agent -- runs outside this package and may never claim
``Confirmed``. :func:`extract_policy_sites` is Layer 2's *input*: the structured
policy inventory design.md specifies, built here rather than in the Skill script
so that the script stays a thin argv-and-stdout wrapper and so that the Agent's
view of the Template is produced by the same code the deterministic checks used.

Three things this Source reports that a naive one would leave silent, and why
each is a Finding rather than nothing at all:

a value that could not be resolved
    ``Fn::ImportValue``, ``Fn::GetAtt``, and a ``Ref`` to a deploy-time
    parameter stand for values static analysis cannot know. The detectors
    return those locations instead of guessing, and
    :func:`unresolvable_finding` turns each into the ``Informational`` / ``INFO``
    / ``Confirmed`` disclosure design.md specifies. The Finding asserts no risk
    -- "this could not be evaluated" is itself a deterministic fact -- while
    telling the reader which locations the ``Confirmed`` findings do not cover.

a policy document that is not a policy document
    A ``PolicyDocument`` written as a JSON string, or as a bare list of
    statements, parses fine and analyses to nothing.
    :func:`malformed_document_finding` discloses it (design.md,
    ``iacreview.iam`` / Failure modes: "policy document が dict でない場合は
    ``Informational`` Finding として記録し例外にしない"). cfn-lint is what
    reports it as an error; this Source only records that it did not look.

a Template with no IAM at all
    Requirement 6 AC12 asks for zero findings *with an informational message*,
    which is not the same result as a Template that was examined and found
    clean. The message goes in ``stats.informational_message``, not into a
    Finding: a Finding names a resource, and here there is none to name.

Nothing here runs a process or reads anything but the Template that was asked
for, so unlike the other two Sources this one has no external tool to be absent,
time out, or emit unparsable output. ``SourceResult.errors`` is consequently
always empty, and the failures that *can* happen -- a path outside the
workspace, a Template that will not parse -- are raised rather than reported,
because they mean no review took place at all. The orchestrator's ``collect()``
loop turns them into one ``errors[]`` entry and moves to the next Source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from iacreview import pathguard
from iacreview.finding import (
    CONFIRMED,
    UNASSIGNED_ID,
    Evidence,
    Finding,
    Location,
    noecho_parameter_names,
    redact_findings,
    sorted_sources,
)
from iacreview.iam import detectors, locate
from iacreview.iam.detectors import (
    NO_IAM_RESOURCES_MESSAGE,
    SOURCE_NAME,
    PolicyTarget,
    ScanResult,
)
from iacreview.iam.intrinsics import (
    FN_GETATT,
    FN_SUB,
    REF,
    ResolutionContext,
    UnresolvedValue,
    dedupe_unresolved,
    expand_conditionals,
    resolve,
)
from iacreview.iam.locate import PolicySite
from iacreview.source import SourceResult, workspace_relative
from iacreview.template import LoadedTemplate, load_template

__all__ = [
    "SOURCE_NAME",
    "CATEGORY",
    "INFORMATIONAL_TYPE",
    "INFO_SEVERITY",
    "MALFORMED_DOCUMENT_RULE_ID",
    "MALFORMED_DOCUMENT_WHY_IT_MATTERS",
    "MALFORMED_DOCUMENT_RECOMMENDATION",
    "NO_IAM_RESOURCES_MESSAGE",
    "STATS_KEYS",
    "POLICY_SITE_KEYS",
    "SUMMARY_FINDING_KEYS",
    "LAYER2_KEYS",
    "POLICY_SITES_KEY",
    "ATTACHED_TO_KEY",
    "DETERMINISTIC_FINDINGS_SUMMARY_KEY",
    "PRINCIPAL_TYPE_KEYS",
    "initial_stats",
    "unresolvable_finding",
    "malformed_document_finding",
    "run_and_normalize",
    "extract_policy_sites",
    "attachments",
]


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

#: ``Normalized_Category`` of every Finding this Source builds, disclosures
#: included. Taken from :mod:`~iacreview.iam.detectors` so the value is written
#: once: a disclosure landing in a different category would stop deduplicating
#: against the findings it qualifies.
CATEGORY = detectors.CATEGORY

#: ``FindingType`` of both disclosures. Neither asserts a risk, so neither is
#: ``Security``.
INFORMATIONAL_TYPE = "Informational"

#: ``Severity`` of both disclosures. Requirement 12 AC6 excludes
#: ``Informational`` + ``INFO`` from the negative-test false-positive count, so
#: disclosing a coverage gap cannot make a clean Template look dirty.
INFO_SEVERITY = "INFO"

#: ``Evidence[].RuleId`` of the malformed-document disclosure. The unresolvable
#: one uses :attr:`~iacreview.iam.intrinsics.UnresolvedValue.rule_id`, which
#: :mod:`~iacreview.iam.intrinsics` owns.
MALFORMED_DOCUMENT_RULE_ID = "malformed_policy_document"

#: ``WhyItMatters`` of the malformed-document disclosure. Parallel to
#: :data:`~iacreview.iam.intrinsics.UNRESOLVABLE_WHY_IT_MATTERS`: it states the
#: coverage gap and stops there, because a document this Source could not read
#: may be perfectly safe.
MALFORMED_DOCUMENT_WHY_IT_MATTERS = (
    "The deterministic IAM checks examine the statements of a policy document, "
    "and this location does not hold one, so no check was applied to it. Any "
    "permissions granted here are not covered by the Confirmed findings in "
    "this report."
)

#: ``Recommendation`` of the malformed-document disclosure.
MALFORMED_DOCUMENT_RECOMMENDATION = (
    "Rewrite this property as a policy document mapping with Version and "
    "Statement so that it can be reviewed, and run cfn-lint to confirm the "
    "property type is the one CloudFormation expects."
)

#: Fixed keys of :attr:`~iacreview.source.SourceResult.stats`. Always all of
#: them, so the report's stats section has the same shape whatever the Template
#: contained (Requirement 16 AC11).
#:
#: There is no ``tool_version`` or ``exit_code`` key, which the other two
#: Sources have: this Source is the plugin's own code and has no external tool
#: whose version or exit status could be reported.
STATS_KEYS: Tuple[str, ...] = (
    "policy_sites",
    "policy_documents_analysed",
    "malformed_documents",
    "statements_analysed",
    "detectors_evaluated",
    "unresolvable_locations",
    "informational_message",
)

#: Keys of one ``policy_sites[]`` entry in the Layer 2 input JSON, in design.md's
#: order.
POLICY_SITE_KEYS: Tuple[str, ...] = (
    "logical_id",
    "kind",
    "json_path",
    "statement_count",
    "actions",
    "resources",
    "principals",
    "has_conditions",
    "unresolvable_locations",
)

#: Keys of one ``deterministic_findings_summary[]`` entry.
SUMMARY_FINDING_KEYS: Tuple[str, ...] = ("rule", "resource", "severity")

POLICY_SITES_KEY = "policy_sites"
ATTACHED_TO_KEY = "attached_to"
DETERMINISTIC_FINDINGS_SUMMARY_KEY = "deterministic_findings_summary"

#: Top-level keys of the Layer 2 input JSON, in design.md's order.
LAYER2_KEYS: Tuple[str, ...] = (
    POLICY_SITES_KEY,
    ATTACHED_TO_KEY,
    DETERMINISTIC_FINDINGS_SUMMARY_KEY,
)

#: The ``Principal`` type keys a policy nests values under. A mapping whose keys
#: are these is a Principal wrapper to unwrap, not a value to render.
PRINCIPAL_TYPE_KEYS: Tuple[str, ...] = ("AWS", "Service", "Federated", "CanonicalUser")

#: ``Fn::GetAtt`` in its short and long argument forms both name a logical ID
#: first; this splits the ``"Role.Arn"`` string form.
_GETATT_SEPARATOR = "."

#: One ``${Name}`` or ``${Name.Attr}`` substitution in an ``Fn::Sub`` string,
#: used to find logical IDs referenced from anywhere in a resource body. Inner
#: braces are excluded so a malformed string cannot make the match run away.
_SUB_REFERENCE = re.compile(r"\$\{([^{}!][^{}]*)\}")

#: Marks a pseudo parameter (``AWS::Region``) rather than a logical ID.
_PSEUDO_PARAMETER_MARKER = "::"

#: Depth limit for the reference walk of :func:`attachments`. Matches the spirit
#: of :data:`iacreview.iam.intrinsics.MAX_NESTING_DEPTH`: an adversarial Template
#: should cost bounded work rather than a recursion error.
_MAX_WALK_DEPTH = 40


def initial_stats() -> Dict[str, Any]:
    """Return the :data:`STATS_KEYS` dict for a review that has not run.

    ``detectors_evaluated`` is filled in immediately because it is a property of
    this plugin, not of the Template: all fifteen detectors run against every
    site, always. Recording it means the report says how much was checked
    without the reader having to know the version's detector list.
    """
    return {
        "policy_sites": 0,
        "policy_documents_analysed": 0,
        "malformed_documents": 0,
        "statements_analysed": 0,
        "detectors_evaluated": len(detectors.DETECTOR_NAMES),
        "unresolvable_locations": 0,
        "informational_message": None,
    }


# ---------------------------------------------------------------------------
# The two disclosures
# ---------------------------------------------------------------------------


def unresolvable_finding(value: UnresolvedValue, *, template_file: str) -> Finding:
    """Build the ``unresolvable_value`` Finding design.md specifies.

    ``FindingType: "Informational"``, ``Severity: "INFO"``,
    ``Confidence: "Confirmed"``. The Confidence is not a contradiction: the
    claim is "this location was not evaluated", which the review established for
    certain. Nothing about the value's safety is asserted, which is what
    steering/security.md requires of a Finding with no evidence behind it.

    Args:
        value: A record from
            :attr:`~iacreview.iam.detectors.ScanResult.unresolved`. All of the
            wording comes from it, so the text lives next to the logic that
            decided the value was unresolvable and the two cannot drift.
        template_file: Workspace-relative path of the reviewed Template.

    Returns:
        The Finding, with :data:`~iacreview.finding.UNASSIGNED_ID` for ``ID``
        like every Source's output.
    """
    return _disclosure(
        logical_id=value.logical_id,
        template_file=template_file,
        template_path=list(value.template_path),
        text=value.finding_text,
        why_it_matters=value.why_it_matters,
        detail=value.detail,
        rule_id=value.rule_id,
        recommendation=value.recommendation,
    )


def malformed_document_finding(site: PolicySite, *, template_file: str) -> Finding:
    """Disclose a policy document this Source could not read.

    Args:
        site: A site from
            :func:`iacreview.iam.locate.malformed_document_sites`, whose
            :attr:`~iacreview.iam.locate.PolicySite.malformed_reason` is a
            complete sentence naming the path and the type found. It names the
            type only, never the content: a Template is untrusted input and a
            malformed document is exactly where a pasted credential would sit.
        template_file: Workspace-relative path of the reviewed Template.

    Returns:
        The Finding.

    Raises:
        ValueError: ``site`` holds a readable policy document, so there is
            nothing to disclose. A caller reaching this has filtered wrongly,
            and a Finding claiming a well-formed document is malformed would be
            worse than the exception.
    """
    reason = site.malformed_reason
    if reason is None:
        raise ValueError(
            "site at {0} holds a readable policy document; there is nothing to "
            "disclose".format(site.json_path)
        )
    return _disclosure(
        logical_id=site.logical_id,
        template_file=template_file,
        template_path=site.template_path,
        text="[{0}] {1}".format(MALFORMED_DOCUMENT_RULE_ID, reason),
        why_it_matters=MALFORMED_DOCUMENT_WHY_IT_MATTERS,
        detail=reason,
        rule_id=MALFORMED_DOCUMENT_RULE_ID,
        recommendation=MALFORMED_DOCUMENT_RECOMMENDATION,
    )


def _disclosure(
    *,
    logical_id: str,
    template_file: str,
    template_path: List[Any],
    text: str,
    why_it_matters: str,
    detail: str,
    rule_id: str,
    recommendation: str,
) -> Finding:
    """Build a coverage-gap Finding: the fields both disclosures share.

    One construction site, so the two disclosures cannot end up with different
    ``FindingType`` / ``Severity`` / ``Confidence`` triples. ``Excerpt`` is
    ``None``, which the schema permits because ``Confidence`` is ``Confirmed``;
    the ``RuleId`` and the path are the evidence, and quoting the Template here
    would risk echoing a value that should not be echoed.
    """
    return Finding(
        ID=UNASSIGNED_ID,
        Normalized_Category=CATEGORY,
        FindingType=INFORMATIONAL_TYPE,
        Severity=INFO_SEVERITY,
        Confidence=CONFIRMED,
        Source=sorted_sources([SOURCE_NAME]),
        Resource=logical_id,
        Location=Location(
            File=template_file,
            Line=None,
            Column=None,
            TemplatePath=list(template_path),
        ),
        Finding=text,
        WhyItMatters=why_it_matters,
        Evidence=[
            Evidence(
                Source=SOURCE_NAME,
                Detail=detail,
                RuleId=rule_id,
                Excerpt=None,
            )
        ],
        Recommendation=recommendation,
        SuggestedRemediation=None,
    )


# ---------------------------------------------------------------------------
# Scanning, with per-site attribution kept
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _SiteScan:
    """One site, prepared and scanned, with its own results still separate.

    :func:`iacreview.iam.detectors.scan_sites` concatenates across sites, which
    is what the Source wants; the Layer 2 inventory needs each site's
    unresolvable locations attributed to *that* site. Rather than scanning twice
    or matching paths back up afterwards, both callers share this list.
    """

    target: PolicyTarget
    result: ScanResult


def _scan(
    sites: Sequence[PolicySite], *, template_file: str, context: ResolutionContext
) -> List[_SiteScan]:
    """Prepare and scan every site, in Template order."""
    return [
        _SiteScan(target=target, result=detectors.scan_target(target))
        for target in (
            PolicyTarget.from_site(site, template_file=template_file, context=context)
            for site in sites
        )
    ]


def _resolved_template_file(template: Path, workspace_root: Optional[Path]) -> Tuple[Path, str]:
    """Contain ``template`` and render the ``Location.File`` it will carry."""
    root = Path.cwd() if workspace_root is None else Path(workspace_root)
    resolved = pathguard.resolve_within(str(template), root)
    # resolve_within guarantees containment, so this is relative; `.name` covers
    # only the degenerate case of the root itself being handed in.
    return resolved, workspace_relative(str(resolved), root) or resolved.name


# ---------------------------------------------------------------------------
# The Source
# ---------------------------------------------------------------------------


def run_and_normalize(
    template: Path,
    *,
    workspace_root: Optional[Path] = None,
    loaded: Optional[LoadedTemplate] = None,
) -> SourceResult:
    """Review one Template's IAM policies and return normalized Findings.

    The whole Source in one call, as design.md's ``SOURCES`` list requires:
    contain the path, load the Template, locate every policy site, run the
    fifteen detectors, and disclose what could not be checked.

    Args:
        template: Path to the Template. Passed through
            :func:`iacreview.pathguard.resolve_within` before it is opened, so
            containment holds even if the caller forgot (Requirement 9 AC4,
            AC5).
        workspace_root: Containment root, and the root ``Location.File`` is
            relative to. Defaults to the current working directory, which is the
            workspace root for every entry point of this plugin.
        loaded: An already-parsed Template. Optional purely to save a second
            parse in an orchestrator that has one; it is verified to be the same
            file, so it cannot silently redirect the review.

    Returns:
        A :class:`~iacreview.source.SourceResult` whose ``source`` is always
        ``"IAM Review"``, in one of three shapes:

        ==================================  =======================================
        Template                            Result
        ==================================  =======================================
        no IAM-relevant resource            ``findings=[]``, and
                                            ``stats.informational_message`` set to
                                            :data:`~iacreview.iam.detectors.NO_IAM_RESOURCES_MESSAGE`
                                            (Requirement 6 AC12)
        IAM present, nothing dangerous      ``findings=[]`` with
                                            ``informational_message`` ``None`` --
                                            reviewed and clean, which is a
                                            different statement
        IAM present, patterns matched       ``Confirmed`` Security Findings, then
                                            the ``Informational`` disclosures
        ==================================  =======================================

        ``errors`` is always empty: this Source runs no external tool, so it has
        no partial failure to report. Findings come out in site order, and
        within a site in :data:`~iacreview.iam.detectors.DETECTORS` order, with
        both disclosure groups last; report-wide ordering and ``ID`` assignment
        happen once every Source has run (Requirement 7 AC15).

    Raises:
        UnsafeArgumentError: ``template`` contains a shell metacharacter.
        InvalidArgumentsError: ``template`` is empty or cannot be normalized.
        PathContainmentError: ``template`` resolves outside ``workspace_root``.
        InputNotFoundError: ``template`` or ``workspace_root`` does not exist.
        TemplateParseError: The file is not parsable as YAML or JSON.
        NotReviewableError: The document has no non-empty ``Resources`` mapping.
        ValueError: ``loaded`` is a different file than ``template``.

        None of these is folded into ``errors``: each means no review happened
        at all, and reporting an empty findings list as a successful IAM review
        would be a false clean bill. design.md's ``collect()`` loop catches them
        and records one ``errors[]`` entry, so the other Sources still run.

    Template *content* never raises. Every value is treated as untrusted, and a
    shape the detectors cannot read yields a disclosure or one fewer Finding.
    """
    resolved, template_file = _resolved_template_file(template, workspace_root)
    document = _document(resolved, loaded)

    stats = initial_stats()
    sites = locate.find_policy_documents(document)
    stats["policy_sites"] = len(sites)

    if detectors.no_iam_resources(sites):
        # Requirement 6 AC12. Not a Finding: a Finding names a resource, and the
        # point of this result is that there is no IAM resource to name.
        stats["informational_message"] = NO_IAM_RESOURCES_MESSAGE
        return SourceResult(source=SOURCE_NAME, findings=[], errors=[], stats=stats)

    scans = _scan(
        sites,
        template_file=template_file,
        context=ResolutionContext.from_template(document),
    )
    malformed = locate.malformed_document_sites(sites)
    unresolved = dedupe_unresolved(
        value for scan in scans for value in scan.result.unresolved
    )

    stats["policy_documents_analysed"] = len(locate.policy_document_sites(sites))
    stats["malformed_documents"] = len(malformed)
    stats["statements_analysed"] = sum(len(scan.target.statements) for scan in scans)
    stats["unresolvable_locations"] = len(unresolved)

    findings: List[Finding] = [
        finding for scan in scans for finding in scan.result.findings
    ]
    findings.extend(
        malformed_document_finding(site, template_file=template_file)
        for site in malformed
    )
    findings.extend(
        unresolvable_finding(value, template_file=template_file)
        for value in unresolved
    )
    # Credential redaction (design.md, O-11) on the way out, as for every Source.
    # This Source has the parsed Template, so it can supply the NoEcho Parameter
    # names condition (a) needs. Its own Findings quote no Template text, so
    # nothing is redacted today; the wiring is what makes a future Excerpt from
    # this Source subject to the same rule.
    findings = redact_findings(
        findings, noecho_parameters=noecho_parameter_names(document)
    )
    return SourceResult(
        source=SOURCE_NAME, findings=findings, errors=[], stats=stats
    )


def _document(resolved: Path, loaded: Optional[LoadedTemplate]) -> Dict[str, Any]:
    """Return the parsed Template, loading it unless the caller supplied it.

    Raises:
        ValueError: ``loaded`` describes a different file. Accepting it would
            let a report attribute one Template's findings to another's path,
            which is worse than refusing the shortcut.
    """
    if loaded is None:
        return load_template(resolved).doc
    if Path(loaded.path).resolve() != resolved:
        raise ValueError(
            "loaded template is {0!r}, but the requested template is {1!r}".format(
                str(loaded.path), str(resolved)
            )
        )
    return loaded.doc


# ---------------------------------------------------------------------------
# Layer 2 input (design.md, "Layer 2: Agent reasoning の入力と制約")
# ---------------------------------------------------------------------------


def extract_policy_sites(
    doc: Dict[str, Any], *, template_file: str
) -> Dict[str, Any]:
    """Build the policy inventory the Layer 2 Agent reasons over.

    design.md's Layer 2 input JSON, with :data:`LAYER2_KEYS` at the top level and
    :data:`POLICY_SITE_KEYS` in each ``policy_sites`` entry. The Agent reads this
    instead of the Template so that two properties hold: it sees the same policy
    inventory the deterministic checks saw, and ``deterministic_findings_summary``
    tells it what Layer 1 already reported ``Confirmed`` -- which is what
    Requirement 2 AC14 and AC15 forbid it from restating.

    Task 18.4's ``extract_policies.py`` is a wrapper over this function, so the
    generation logic is tested here as a pure function rather than through a
    subprocess.

    Args:
        doc: A parsed Template, normally
            :attr:`iacreview.template.LoadedTemplate.doc`. Untrusted: a section
            of the wrong type contributes nothing rather than raising.
        template_file: Workspace-relative path of the Template. Not part of the
            output -- the entry point states the target once, and repeating it
            per site would only be another place to disagree -- but the
            deterministic scan needs it to address its own Findings.

    Returns:
        A JSON-serializable dict. Deterministic for a given ``doc``: every list
        is in Template order with duplicates dropped on first sight, and every
        mapping is keyed by logical ID, so serializing it twice yields identical
        bytes (Requirement 16 AC11).

    Note:
        ``actions``, ``resources``, and ``principals`` are the candidate strings
        :mod:`iacreview.iam.intrinsics` derived, not raw Template values: an
        ``Fn::Sub`` appears with its substitutions still standing as
        ``${Name}``, and a value no candidate could be derived from (an
        ``Fn::ImportValue``) is absent from those lists and present in
        ``unresolvable_locations`` instead. The Agent therefore never has to
        interpret an intrinsic function, and can see which values were beyond
        interpretation.
    """
    context = ResolutionContext.from_template(doc)
    sites = locate.find_policy_documents(doc)
    scans = _scan(sites, template_file=template_file, context=context)
    logical_ids = _unique(scan.target.logical_id for scan in scans)
    return {
        POLICY_SITES_KEY: [_site_entry(scan, context) for scan in scans],
        ATTACHED_TO_KEY: attachments(doc, logical_ids),
        DETERMINISTIC_FINDINGS_SUMMARY_KEY: [
            _summary_entry(finding)
            for scan in scans
            for finding in scan.result.findings
        ],
    }


def _site_entry(scan: _SiteScan, context: ResolutionContext) -> Dict[str, Any]:
    """One ``policy_sites[]`` entry.

    ``statement_count`` counts the statements that were *examined*, so each
    ``Fn::If`` alternative counts separately and an ``AWS::Lambda::Permission``
    counts as the one statement its properties stand for. That is the number the
    other four lists are consistent with, which matters more here than matching
    the literal length of the ``Statement`` array.
    """
    views = scan.target.statements
    return {
        "logical_id": scan.target.logical_id,
        "kind": scan.target.kind.value,
        "json_path": scan.target.site.json_path,
        "statement_count": len(views),
        "actions": _element_texts(views, detectors.ACTION_KEY, context),
        "resources": _element_texts(views, detectors.RESOURCE_KEY, context),
        "principals": _principal_texts(views, context),
        "has_conditions": [bool(view.statement.get(detectors.CONDITION_KEY)) for view in views],
        "unresolvable_locations": _unique(
            value.json_path for value in scan.result.unresolved
        ),
    }


def _summary_entry(finding: Finding) -> Dict[str, Any]:
    """One ``deterministic_findings_summary[]`` entry.

    ``rule`` is read from ``Evidence[0].RuleId``, which is where each detector
    records its identity, so the summary does not depend on Finding wording. The
    entry deliberately carries no description: its purpose is to tell the Agent
    "already reported, do not restate", and reproducing the prose would invite
    paraphrasing it back as a new Finding.
    """
    rule = next(
        (
            entry.RuleId
            for entry in finding.Evidence
            if isinstance(entry, Evidence) and entry.RuleId
        ),
        None,
    )
    return {"rule": rule, "resource": finding.Resource, "severity": finding.Severity}


def _element_texts(
    views: Sequence[Any], key: str, context: ResolutionContext
) -> List[str]:
    """Candidate strings for one statement element across every statement."""
    texts: List[str] = []
    for view in views:
        value = view.statement.get(key)
        if value is None:
            continue
        texts.extend(
            candidate.text for candidate in resolve(value, context).candidates
        )
    return _unique(texts)


def _principal_texts(
    views: Sequence[Any], context: ResolutionContext
) -> List[str]:
    """Candidate strings for the Principals every statement admits.

    ``Principal`` differs from ``Action`` and ``Resource`` in nesting its values
    under a type key (``{"AWS": ...}``), so the wrapper is unwrapped before
    resolution -- otherwise the type key would look like an unsupported mapping
    and every Principal would resolve to nothing. The type key itself is dropped:
    Layer 2 is being told which principals are admitted, and
    :func:`~iacreview.iam.intrinsics.classify_principal` is what cares whether
    one arrived as ``AWS`` or as ``Service``.
    """
    texts: List[str] = []
    for view in views:
        value = view.statement.get(detectors.PRINCIPAL_KEY)
        if value is None:
            continue
        for branch in expand_conditionals(value):
            _principal_into(branch.value, context, texts)
    return _unique(texts)


def _principal_into(
    value: Any, context: ResolutionContext, out: List[str]
) -> None:
    """Append the candidate strings of one Principal value to ``out``."""
    if isinstance(value, list):
        for element in value:
            _principal_into(element, context, out)
        return
    if isinstance(value, dict) and not _is_intrinsic(value):
        for sub_value in value.values():
            _principal_into(sub_value, context, out)
        return
    out.extend(candidate.text for candidate in resolve(value, context).candidates)


def _is_intrinsic(value: Dict[Any, Any]) -> bool:
    """Whether a mapping is an intrinsic function rather than a Principal wrapper."""
    return any(
        isinstance(key, str) and (key == REF or key.startswith("Fn::"))
        for key in value
    )


# ---------------------------------------------------------------------------
# The attachment graph
# ---------------------------------------------------------------------------


def attachments(
    doc: Dict[str, Any], logical_ids: Sequence[str]
) -> Dict[str, List[str]]:
    """Which resources reference each policy-owning resource.

    design.md's ``attached_to``. A Role's permissions only matter in proportion
    to what runs with them, and that is the one piece of context a policy
    document does not contain: ``{"AppExecutionRole": ["AppFunction"]}`` tells
    the Agent that this Role's ``s3:*`` is a Lambda function's authority. Layer 1
    has no use for it -- a wildcard is a wildcard -- which is why it appears in
    the Layer 2 input and not in a Finding.

    Args:
        doc: A parsed Template. Untrusted.
        logical_ids: The logical IDs to report on, normally the policy sites'
            owners.

    Returns:
        One entry per element of ``logical_ids``, in the order given, each
        holding the logical IDs of the *other* resources whose bodies reference
        it, sorted alphabetically. An empty list means nothing in this Template
        references it, which is itself worth seeing: an unattached Role may be
        dead weight, or it may be assumed by something outside the Template.

    Note:
        References are read from ``Ref``, ``Fn::GetAtt``, and ``${Name}``
        substitutions in ``Fn::Sub``, anywhere in a resource body. That covers
        both directions the Template can express an attachment --
        ``AWS::Lambda::Function.Role`` pointing at a Role, and
        ``AWS::IAM::Policy.Roles`` pointing back -- so neither needs a
        per-resource-type table. ``DependsOn`` is not read: it orders
        provisioning and says nothing about who uses whose permissions.
    """
    wanted = set(logical_ids)
    referrers: Dict[str, List[str]] = {name: [] for name in logical_ids}
    for name, body in _resources(doc):
        for target in sorted(_referenced_ids(body) & wanted):
            if target != name:
                referrers[target].append(name)
    return {name: sorted(referrers[name]) for name in referrers}


def _resources(doc: Any) -> List[Tuple[str, Any]]:
    """The Template's resources as ``(logical_id, body)``, in Template order."""
    if not isinstance(doc, dict):
        return []
    resources = doc.get(locate.RESOURCES_KEY)
    if not isinstance(resources, dict):
        return []
    return [(name, body) for name, body in resources.items() if isinstance(name, str)]


def _referenced_ids(value: Any) -> set:
    """Every name a value references through ``Ref``, ``Fn::GetAtt`` or ``Fn::Sub``.

    Names that cannot be logical IDs -- pseudo parameters, which contain ``::``
    -- are excluded. Parameter names are not: telling a parameter from a resource
    would need the ``Parameters`` section, and :func:`attachments` intersects the
    result with the logical IDs it was asked about anyway, so a parameter that
    happens to share a resource's name is the only ambiguity and CloudFormation
    forbids that collision.
    """
    found: set = set()
    _walk_references(value, 0, found)
    return found


def _walk_references(value: Any, depth: int, out: set) -> None:
    """Collect referenced names from ``value``, bounded by :data:`_MAX_WALK_DEPTH`.

    Any mapping that is not one of the three reference functions is descended
    into, which is what makes an ``Fn::If`` need no case of its own: both
    alternatives are walked, and a resource named in either one is referenced
    whichever way the condition resolves at deploy time.
    """
    if depth >= _MAX_WALK_DEPTH:
        return
    if isinstance(value, list):
        for element in value:
            _walk_references(element, depth + 1, out)
        return
    if not isinstance(value, dict):
        return
    for key, sub_value in value.items():
        if key == REF:
            _add_name(sub_value, out)
        elif key == FN_GETATT:
            _add_getatt(sub_value, out)
        elif key == FN_SUB:
            _add_sub(sub_value, depth + 1, out)
        else:
            _walk_references(sub_value, depth + 1, out)


def _add_name(value: Any, out: set) -> None:
    """Record a referenced name, unless it is a pseudo parameter."""
    if isinstance(value, str) and _PSEUDO_PARAMETER_MARKER not in value:
        out.add(value)


def _add_getatt(value: Any, out: set) -> None:
    """Record the logical ID of an ``Fn::GetAtt``, in either argument form."""
    if isinstance(value, str):
        _add_name(value.split(_GETATT_SEPARATOR)[0], out)
    elif isinstance(value, list) and value:
        _add_name(value[0], out)


def _add_sub(value: Any, depth: int, out: set) -> None:
    """Record the names an ``Fn::Sub`` substitutes, from either argument form.

    The long form's second element is a variable map: its keys are local names
    that shadow logical IDs, so they are not references, while its values are
    ordinary expressions that may contain some. ``depth`` keeps accumulating
    through that map, so nesting long-form ``Fn::Sub`` inside itself is bounded
    by :data:`_MAX_WALK_DEPTH` like any other nesting rather than recursing until
    the interpreter stops it.
    """
    text = value[0] if isinstance(value, list) and value else value
    if isinstance(text, str):
        for name in _SUB_REFERENCE.findall(text):
            _add_name(name.split(_GETATT_SEPARATOR)[0], out)
    if isinstance(value, list) and len(value) > 1:
        _walk_references(value[1], depth, out)


def _unique(values: Iterable[str]) -> List[str]:
    """Deduplicate while keeping first-seen order.

    Order comes from the Template rather than from an alphabetical sort so that
    a reader of the Layer 2 JSON sees a policy's actions in the order they were
    written. Either choice is deterministic; this one is also readable.
    """
    seen = set()
    unique: List[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique
