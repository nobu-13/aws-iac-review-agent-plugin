"""Wording of a non-``Confirmed`` Finding (Task 14.3, Requirement 7 AC12).

AC12: a Finding carrying a Confidence other than ``Confirmed`` must be phrased
as a potential risk and must not state that a vulnerability exists. design.md
gives it to Confidence semantics -- ``Confirmed`` may be written assertively,
``Likely`` and ``Contextual`` may not -- and lists AC12 in "上記の property が
対象としない acceptance criteria" as ``EXAMPLE (lint 的検査)`` in this file.

**Why this is a lint here and not a filter in the pipeline.** Tasks 14.1 and
14.2 both correct agent output at run time, and both corrections are decidable:
``Confidence == "Confirmed"`` is a string comparison against a closed set, and
the redaction trigger is a Parameter name lookup or a rule ID membership test.
Either one is right or wrong with no middle case, so acting on it costs nothing.
Phrasing is not decidable. Any check for it is a vocabulary heuristic, and the
two run-time responses available are both worse than the problem:

* dropping the Finding would let a wording heuristic delete a real security
  observation, which is the one outcome steering/security.md's evidence rules
  are meant to prevent -- 14.1 drops only entries that are *unusable*, never
  entries whose content it disagrees with;
* rewriting the text would put generated prose in the report under the
  producer's name, and no substitution table turns an assertion into an
  accurate hedge (which risk, how conditional) without knowing what was meant.

So the enforcement point is the repository, not the run: wording this project
authors is checked in CI, and wording the agent authors is checked against the
same rules so that a prompt or Skill instruction that starts producing
assertive text fails a test rather than shipping. ``agentin`` deliberately keeps
accepting such a Finding; :func:`test_an_assertive_agent_finding_is_accepted_and_flagged`
records that division of labour.

**Where the check lives.** In this test module, as Task 14.3 specifies for the
allowlist and denylist. Not in ``agentin``, which would scope it to agent input
while AC12 is stated about any non-``Confirmed`` Finding; and not next to the
redaction helpers in ``finding``, which would ship a heuristic as library API
that nothing in the pipeline may act on.

**Why the fixed wording is in scope even though it belongs to Confirmed
Findings.** ``category_map.json`` and ``rules/**/_meta.json`` supply
``WhyItMatters`` and ``Recommendation`` for cfn-lint and cfn-guard Findings,
which are always ``Confirmed`` and therefore exempt. They do not stay exempt
after a merge: dedup takes the representative wording from the highest-ranked
Source (deterministic before agent) and then caps ``Confidence`` at ``Likely``
whenever ``Agent Review`` is in the union ([Correction] C-8). The fixed text is
then the wording of a ``Likely`` Finding.
:func:`test_merged_finding_carries_deterministic_wording_at_likely` walks that
path with the real rule-set text.

Two rules, in the two halves AC12 states.

Denylist (no vulnerability claim)
    Applied to every prose field of every non-``Confirmed`` Finding. Targets
    assertions of vulnerability, exploitation, and present-tense open access.
    Deliberately narrow: "may grant", "appears to", "could allow" are how a
    Layer 2 Finding is supposed to read, and a check that flagged them would be
    turned off. Factual consequence -- "exposes the attached instances to the
    entire internet" -- is not a vulnerability claim and stays legal, which is
    what lets the shipped rule-set wording pass unchanged.

Allowlist (phrased as a potential risk)
    Applied to the ``Finding`` field when the wording is agent-authored, that
    is when ``Agent Review`` is the only Source. At least one hedging term must
    be present, so an agent cannot satisfy the denylist by writing a flat
    present-tense claim that names no vulnerability. Not applied to merged
    wording: that text comes from a deterministic Source that did confirm what
    it says, and demanding hedges there would make the report vaguer than its
    evidence.

Not covered: a cfn-lint or cfn-guard *tool* message reaching ``Finding``. That
text is authored by the tool, not by this repository, and no CI check here can
constrain it.

Determinism (Requirement 16 AC11): patterns are compiled once, matched with
``re.IGNORECASE | re.ASCII``, and reported in declaration order. ``re.ASCII``
is what keeps case folding locale-independent -- case-insensitive matching over
the full Unicode table folds characters no ASCII keyword needs.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import pytest

from iacreview import agentin
from iacreview.dedup import deduplicate
from iacreview.finding import (
    AGENT_SOURCE,
    CONFIRMED,
    Evidence,
    Finding,
    Location,
)

# tests/unit/test_finding_wording.py -> tests/unit -> tests -> plugin root
PLUGIN_ROOT: Path = Path(__file__).resolve().parents[2]
CATEGORY_MAP: Path = PLUGIN_ROOT / "iacreview" / "category_map.json"
RULES_DIR: Path = PLUGIN_ROOT / "rules"
META_FILENAME = "_meta.json"

#: Mapping-file keys holding wording that becomes Finding prose. ``notes`` is
#: excluded: it documents the mapping itself and never reaches a report.
PROSE_META_KEYS: Tuple[str, ...] = ("why_it_matters", "recommendation")

#: Finding fields checked against the denylist. ``SuggestedRemediation`` is
#: excluded because it holds a property or policy fragment rather than prose,
#: and ``Evidence[].Excerpt`` because it is verbatim Template text -- neither is
#: the producer making a claim. ``Evidence[].Detail`` is prose and is added by
#: :func:`finding_texts`.
PROSE_FIELDS: Tuple[str, ...] = ("Finding", "WhyItMatters", "Recommendation")

#: Regex flags for every pattern below. ``re.ASCII`` restricts case folding to
#: ASCII, so a match depends only on the keyword and never on the platform's
#: Unicode case tables.
_FLAGS = re.IGNORECASE | re.ASCII

#: Denylist: assertive claims a non-``Confirmed`` Finding may not make. Ordered,
#: so a text tripping two of them reports them in a fixed order.
ASSERTIVE_CLAIMS: Tuple[Tuple[str, str], ...] = (
    ("is_vulnerable", r"\b(?:is|are|was|were)\s+vulnerable\b"),
    (
        "has_a_vulnerability",
        r"\b(?:has|have|had|contains?|introduces?|creates?)\s+"
        r"(?:a|an|the)?\s*(?:critical\s+|serious\s+|known\s+)?(?:security\s+)?"
        r"vulnerabilit(?:y|ies)\b",
    ),
    (
        "there_is_a_vulnerability",
        r"\bthere\s+(?:is|are)\s+(?:a\s+|an\s+)?(?:security\s+)?vulnerabilit(?:y|ies)\b",
    ),
    (
        "is_a_vulnerability",
        r"\b(?:is|are)\s+(?:a|an)\s+(?:critical\s+|serious\s+|known\s+)?"
        r"(?:security\s+)?(?:vulnerability|flaw|hole|breach|backdoor)\b",
    ),
    ("is_exploitable", r"\b(?:is|are)\s+(?:remotely\s+|trivially\s+)?exploitable\b"),
    (
        "is_exploited",
        r"\b(?:is|are|has\s+been|have\s+been)\s+(?:actively\s+)?exploited\b",
    ),
    (
        "attacker_capability",
        r"\battackers?\s+(?:can|will|has|have|is\s+able\s+to|are\s+able\s+to)\b",
    ),
    ("is_compromised", r"\b(?:is|are|will\s+be)\s+compromised\b"),
    ("is_insecure", r"\b(?:is|are)\s+(?:insecure|unsafe)\b"),
    (
        "grants_open_access",
        r"\bgrants?\s+(?:public|unrestricted|unlimited|anonymous|world|"
        r"full\s+administrative)\b",
    ),
    ("allows_anyone", r"\b(?:allows?|enables?|lets?)\s+any(?:one|body)\s+to\b"),
)

#: Allowlist: the hedging vocabulary that phrases an observation as a potential
#: risk. One term anywhere in the ``Finding`` text satisfies the requirement.
HEDGE_TERMS: Tuple[str, ...] = (
    r"may",
    r"might",
    r"could",
    r"appears?\s+to",
    r"seems?\s+to",
    r"potential(?:ly)?",
    r"possibl[ey]",
    r"likely",
    r"risks?",
    r"unless",
    r"depending\s+on",
    r"if",
    r"whether",
    r"unclear",
    r"cannot\s+be\s+determined",
)

_COMPILED_CLAIMS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = tuple(
    (name, re.compile(pattern, _FLAGS)) for name, pattern in ASSERTIVE_CLAIMS
)

_COMPILED_HEDGES: Tuple[Tuple[str, "re.Pattern[str]"], ...] = tuple(
    (term, re.compile(r"\b" + term + r"\b", _FLAGS)) for term in HEDGE_TERMS
)


# ---------------------------------------------------------------------------
# The lint
# ---------------------------------------------------------------------------


def assertive_claims(text: str) -> List[str]:
    """Names of the denylist entries ``text`` trips, in declaration order."""
    return [name for name, pattern in _COMPILED_CLAIMS if pattern.search(text)]


def hedge_terms(text: str) -> List[str]:
    """Allowlist terms present in ``text``, in declaration order."""
    return [term for term, pattern in _COMPILED_HEDGES if pattern.search(text)]


def finding_texts(f: Finding) -> List[Tuple[str, str]]:
    """``(field path, text)`` for every prose field of ``f``."""
    texts = [(field, getattr(f, field)) for field in PROSE_FIELDS]
    texts.extend(
        ("Evidence[{0}].Detail".format(index), entry.Detail)
        for index, entry in enumerate(f.Evidence)
    )
    return texts


def is_agent_authored(f: Finding) -> bool:
    """Whether ``f``'s wording was written by the agent and only by the agent.

    A merged Finding names more than one Source and takes its wording from the
    deterministic one, so the hedging requirement does not apply to it.
    """
    return list(f.Source) == [AGENT_SOURCE]


def wording_violations(f: Finding) -> List[str]:
    """AC12 violations in ``f``, or an empty list.

    A ``Confirmed`` Finding has none by definition: AC12 applies to the other
    two Confidence values, and design.md's Confidence table permits assertive
    wording for a deterministically established fact.
    """
    if f.Confidence == CONFIRMED:
        return []
    violations = [
        "{0}: states that a vulnerability exists ({1})".format(field, claim)
        for field, text in finding_texts(f)
        for claim in assertive_claims(text)
    ]
    if is_agent_authored(f) and not hedge_terms(f.Finding):
        violations.append(
            "Finding: not phrased as a potential risk (no term from the allowlist)"
        )
    return violations


# ---------------------------------------------------------------------------
# Fixed wording corpora
# ---------------------------------------------------------------------------


def _prose_entries(label: str, rules: Dict[str, Any]) -> List[Tuple[str, str]]:
    """``(label, text)`` for each prose key of each rule entry in ``rules``.

    Rule names are sorted so the collected corpus, and therefore the parametrized
    case list, does not depend on the mapping file's key order.
    """
    entries: List[Tuple[str, str]] = []
    for rule_name in sorted(rules):
        rule = rules[rule_name]
        for key in PROSE_META_KEYS:
            if key in rule:
                entries.append(("{0}.{1}.{2}".format(label, rule_name, key), rule[key]))
    return entries


def category_map_texts() -> List[Tuple[str, str]]:
    """Fixed wording in ``iacreview/category_map.json``."""
    document = json.loads(CATEGORY_MAP.read_text(encoding="utf-8"))
    texts: List[Tuple[str, str]] = []
    for section in ("cfnlint", "cfnguard"):
        overrides = document.get(section, {}).get("rule_overrides", {})
        texts.extend(_prose_entries("category_map.{0}".format(section), overrides))
    return texts


def rule_meta_texts() -> List[Tuple[str, str]]:
    """Fixed wording in the ``rules/**/_meta.json`` sidecars."""
    texts: List[Tuple[str, str]] = []
    for meta_path in sorted(RULES_DIR.glob("*/" + META_FILENAME)):
        document = json.loads(meta_path.read_text(encoding="utf-8"))
        label = "{0}/{1}".format(meta_path.parent.name, META_FILENAME)
        texts.extend(_prose_entries(label, document.get("rules", {})))
    return texts


def _cases(texts: Sequence[Tuple[str, str]]) -> Dict[str, Any]:
    """``pytest.mark.parametrize`` kwargs naming each case by its label."""
    return {"argvalues": [text for _, text in texts], "ids": [label for label, _ in texts]}


CATEGORY_MAP_CASES = _cases(category_map_texts())
RULE_META_CASES = _cases(rule_meta_texts())


# ---------------------------------------------------------------------------
# Findings under test
# ---------------------------------------------------------------------------

#: Legal Layer 2 phrasing: hedged, evidence-bound, no vulnerability claim.
HEDGED_FINDING_TEXTS: Tuple[str, ...] = (
    "The role may grant broader S3 access than AppFunction requires.",
    "AppExecutionRole appears to allow s3:* on every bucket in the account.",
    "The bucket policy could allow read access from outside this account.",
    "This trust policy might be assumable by a principal in another account.",
    "The security group possibly exposes port 22 more widely than intended.",
    "Depending on the CIDR supplied at deploy time, ingress may reach 0.0.0.0/0.",
    "There is a potential risk that the KMS key policy is broader than intended.",
    "Whether this is a problem depends on the environment the stack targets.",
)

#: Assertive phrasing AC12 forbids, one per denylist entry it must trip.
ASSERTIVE_FINDING_TEXTS: Tuple[Tuple[str, str], ...] = (
    ("is_vulnerable", "This bucket is vulnerable to unauthorized public reads."),
    ("has_a_vulnerability", "The template has a vulnerability in its IAM role."),
    (
        "there_is_a_vulnerability",
        "There is a vulnerability in the way the trust policy is written.",
    ),
    ("is_a_vulnerability", "This is a critical security flaw in the network design."),
    ("is_exploitable", "The trust policy is exploitable by any AWS account."),
    ("is_exploited", "This misconfiguration is actively exploited in the wild."),
    ("attacker_capability", "An attacker can read every object in the bucket."),
    ("is_compromised", "The database will be compromised once the stack deploys."),
    ("is_insecure", "The network design is insecure."),
    ("grants_open_access", "The role grants public access to all S3 objects."),
    ("allows_anyone", "The policy allows anyone to assume the role."),
)


def agent_entry(**overrides: Any) -> Dict[str, Any]:
    """One valid agent finding, as JSON. Mirrors design.md's Layer 2 output."""
    entry: Dict[str, Any] = {
        "Normalized_Category": "IAM",
        "FindingType": "Security",
        "Severity": "MEDIUM",
        "Confidence": "Likely",
        "Source": [AGENT_SOURCE],
        "Resource": "AppExecutionRole",
        "Location": {
            "File": "templates/app.yaml",
            "TemplatePath": ["Resources", "AppExecutionRole", "Properties"],
        },
        "Finding": HEDGED_FINDING_TEXTS[0],
        "WhyItMatters": "Excess permissions widen the blast radius of a mistake.",
        "Evidence": [
            {
                "Source": AGENT_SOURCE,
                "Detail": "AppExecutionRole is referenced by AppFunction.Properties.Role",
                "Excerpt": 'Action: ["s3:*"]',
            }
        ],
        "Recommendation": "Scope the policy to the actions the function performs.",
        "SuggestedRemediation": None,
    }
    entry.update(overrides)
    return entry


def accepted_agent_finding(**overrides: Any) -> Finding:
    """The Finding ``agentin`` produces for :func:`agent_entry`.

    Going through the boundary rather than constructing a Finding directly is
    what makes this "an Agent Finding ``agentin`` accepted" (Task 14.3) instead
    of a hand-built object that never met the schema.
    """
    findings, errors = agentin.findings_from_payload([agent_entry(**overrides)])
    assert errors == [], errors
    return findings[0]


def deterministic_finding(
    *, resource: str, category: str, text: str, why: str, recommendation: str
) -> Finding:
    """A ``Confirmed`` cfn-guard Finding, for the merge path."""
    return Finding(
        ID=0,
        Normalized_Category=category,
        FindingType="Security",
        Severity="HIGH",
        Confidence=CONFIRMED,
        Source=["cfn-guard"],
        Resource=resource,
        Location=Location(File="templates/app.yaml", TemplatePath=["Resources", resource]),
        Finding=text,
        WhyItMatters=why,
        Evidence=[
            Evidence(
                Source="cfn-guard",
                Detail="Rule security_group_open_ingress reported this resource.",
                RuleId="security_group_open_ingress",
            )
        ],
        Recommendation=recommendation,
        SuggestedRemediation=None,
    )


# ---------------------------------------------------------------------------
# The lint accepts possibility wording and rejects assertive wording
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("text", HEDGED_FINDING_TEXTS)
def test_hedged_agent_wording_passes(text: str) -> None:
    assert wording_violations(accepted_agent_finding(Finding=text)) == []


@pytest.mark.parametrize(
    "claim,text", ASSERTIVE_FINDING_TEXTS, ids=[name for name, _ in ASSERTIVE_FINDING_TEXTS]
)
def test_assertive_agent_wording_is_flagged(claim: str, text: str) -> None:
    violations = wording_violations(accepted_agent_finding(Finding=text))

    assert violations, "assertive wording went undetected: {0!r}".format(text)
    assert any(claim in violation for violation in violations)
    assert all(violation.startswith("Finding:") for violation in violations)


@pytest.mark.parametrize(
    "claim,text", ASSERTIVE_FINDING_TEXTS, ids=[name for name, _ in ASSERTIVE_FINDING_TEXTS]
)
def test_each_denylist_entry_matches_exactly_its_own_case(claim: str, text: str) -> None:
    """Each case trips its own entry, so the ids above stay meaningful.

    Overlap is allowed (``"is a critical security flaw"`` reasonably trips more
    than one reading), but a case that trips *only* another entry would mean the
    entry it is named for is never exercised.
    """
    assert claim in assertive_claims(text)


@pytest.mark.parametrize(
    "field", ["Finding", "WhyItMatters", "Recommendation", "Evidence[0].Detail"]
)
def test_every_prose_field_is_checked(field: str) -> None:
    """A vulnerability claim is a claim wherever the Finding makes it."""
    text = "This bucket is vulnerable to unauthorized public reads."
    if field == "Evidence[0].Detail":
        entry = agent_entry()
        entry["Evidence"][0]["Detail"] = text
        overrides: Dict[str, Any] = {"Evidence": entry["Evidence"]}
    else:
        overrides = {field: text}

    violations = wording_violations(accepted_agent_finding(**overrides))

    expected = "{0}: states that a vulnerability exists (is_vulnerable)".format(field)
    assert expected in violations


def test_excerpt_is_not_linted() -> None:
    """``Excerpt`` is quoted Template text, not the producer's claim."""
    entry = agent_entry()
    entry["Evidence"][0]["Excerpt"] = "Description: this bucket is vulnerable"

    findings, errors = agentin.findings_from_payload([entry])

    assert errors == []
    assert wording_violations(findings[0]) == []


# ---------------------------------------------------------------------------
# The allowlist half: a flat claim naming no vulnerability is still a claim
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "The execution role uses s3:* on every bucket in the account.",
        "AppExecutionRole has more permissions than AppFunction needs.",
        "The bucket policy exposes object data to every principal.",
    ],
)
def test_agent_wording_without_a_hedge_is_flagged(text: str) -> None:
    violations = wording_violations(accepted_agent_finding(Finding=text))

    assert violations == [
        "Finding: not phrased as a potential risk (no term from the allowlist)"
    ]


@pytest.mark.parametrize("confidence", ["Likely", "Contextual"])
def test_both_non_confirmed_confidences_are_linted(confidence: str) -> None:
    finding = accepted_agent_finding(
        Confidence=confidence, Finding="This bucket is vulnerable to public reads."
    )

    assert finding.Confidence == confidence
    assert wording_violations(finding)


def test_a_confirmed_finding_may_be_assertive() -> None:
    """design.md's Confidence table: a confirmed fact may be stated as one."""
    finding = deterministic_finding(
        resource="OpenSecurityGroup",
        category="NetworkSecurity",
        text="An attacker can reach port 22 from any address on the internet.",
        why="The ingress rule is open to 0.0.0.0/0.",
        recommendation="Restrict CidrIp to the ranges that require access.",
    )

    assert finding.Confidence == CONFIRMED
    assert assertive_claims(finding.Finding) == ["attacker_capability"]
    assert wording_violations(finding) == []


# ---------------------------------------------------------------------------
# agentin keeps accepting what this lint rejects
# ---------------------------------------------------------------------------


def test_an_assertive_agent_finding_is_accepted_and_flagged() -> None:
    """The boundary validates structure; wording is a repository lint.

    Locks the decision recorded in the module docstring: an assertive Finding is
    not dropped by ``agentin`` (a wording heuristic must not delete a security
    observation), and is caught here instead.
    """
    text = "An attacker can read every object in the bucket."

    findings, errors = agentin.findings_from_payload([agent_entry(Finding=text)])

    assert errors == []
    assert findings[0].Finding == text
    assert wording_violations(findings[0])


# ---------------------------------------------------------------------------
# Fixed wording: category_map.json and rules/**/_meta.json
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("text", **CATEGORY_MAP_CASES)
def test_category_map_wording_makes_no_vulnerability_claim(text: str) -> None:
    assert assertive_claims(text) == []


@pytest.mark.parametrize("text", **RULE_META_CASES)
def test_rule_meta_wording_makes_no_vulnerability_claim(text: str) -> None:
    assert assertive_claims(text) == []


def test_both_fixed_wording_corpora_are_non_empty() -> None:
    """A corpus that silently became empty would pass every case above.

    The floors are the counts shipped when this task was written; they rise as
    wording is added, and a drop means text stopped being collected rather than
    stopped existing.
    """
    assert len(CATEGORY_MAP_CASES["ids"]) >= 14
    assert len(RULE_META_CASES["ids"]) >= 22
    assert all("why_it_matters" in label or "recommendation" in label
               for label in CATEGORY_MAP_CASES["ids"] + RULE_META_CASES["ids"])


def test_every_rule_directory_contributes_wording() -> None:
    """Each category directory's sidecar is actually read."""
    directories = {label.split("/", 1)[0] for label in RULE_META_CASES["ids"]}

    assert directories == {
        "backup",
        "encryption",
        "iam",
        "logging",
        "public-access",
        "tagging",
    }


def test_merged_finding_carries_deterministic_wording_at_likely() -> None:
    """The path that puts fixed wording on a non-``Confirmed`` Finding.

    dedup takes the representative wording from the deterministic Source and
    caps ``Confidence`` at ``Likely`` because ``Agent Review`` is in the union
    ([Correction] C-8). The fixed text is then subject to AC12, which is why the
    two corpus tests above exist. It passes the denylist, and the hedging half
    is not applied to it: the wording states what cfn-guard confirmed.
    """
    fixed = json.loads((RULES_DIR / "public-access" / META_FILENAME).read_text("utf-8"))
    entry = fixed["rules"]["security_group_open_ingress"]
    deterministic = deterministic_finding(
        resource="OpenSecurityGroup",
        category="NetworkSecurity",
        text="Resource OpenSecurityGroup failed rule security_group_open_ingress.",
        why=entry["why_it_matters"],
        recommendation=entry["recommendation"],
    )
    agent = accepted_agent_finding(
        Resource="OpenSecurityGroup",
        Normalized_Category="NetworkSecurity",
        Finding="Ingress may be reachable from outside the corporate network.",
    )

    merged = deduplicate([deterministic, agent])

    assert len(merged) == 1
    assert merged[0].Confidence == "Likely"
    assert merged[0].Source == ["cfn-guard", AGENT_SOURCE]
    assert merged[0].WhyItMatters == entry["why_it_matters"]
    assert hedge_terms(merged[0].Finding) == []
    assert not is_agent_authored(merged[0])
    assert wording_violations(merged[0]) == []


# ---------------------------------------------------------------------------
# Determinism (Requirement 16 AC11)
# ---------------------------------------------------------------------------


def test_every_pattern_is_ascii_case_folded() -> None:
    """Locale-independent matching: no Unicode case table is consulted."""
    patterns = [pattern for _, pattern in _COMPILED_CLAIMS]
    patterns.extend(pattern for _, pattern in _COMPILED_HEDGES)

    assert patterns
    assert all(pattern.flags & re.ASCII for pattern in patterns)
    assert all(pattern.flags & re.IGNORECASE for pattern in patterns)


@pytest.mark.parametrize("transform", [str.lower, str.upper, str.title])
def test_matching_is_case_insensitive(transform: Any) -> None:
    text = transform("This bucket is vulnerable to unauthorized public reads.")

    assert assertive_claims(text) == ["is_vulnerable"]


def test_claims_are_reported_in_declaration_order() -> None:
    text = (
        "The database is insecure, an attacker can read it, and it will be "
        "compromised."
    )

    assert assertive_claims(text) == [
        "attacker_capability",
        "is_compromised",
        "is_insecure",
    ]


def test_violations_are_ordered_by_field_then_by_pattern() -> None:
    """The whole report is positional: field order, then declaration order."""
    finding = accepted_agent_finding(
        Finding="The role grants public access and is exploitable.",
        WhyItMatters="This is a critical security flaw.",
    )

    violations = wording_violations(finding)

    assert violations == [
        "Finding: states that a vulnerability exists (is_exploitable)",
        "Finding: states that a vulnerability exists (grants_open_access)",
        "WhyItMatters: states that a vulnerability exists (is_a_vulnerability)",
        "Finding: not phrased as a potential risk (no term from the allowlist)",
    ]
    assert violations == wording_violations(finding)
