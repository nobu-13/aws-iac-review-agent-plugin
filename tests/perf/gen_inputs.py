"""Seeded, deterministic input generator for the v1.1 Delta_Tool measurements.

Used by ``measure_m0.py`` (Gate M0) and, later, by the M1 measurement of the
implementation (``tasks.md`` Task 0.4 and Task 16). Not collected by pytest:
the file name does not start with ``test_``.

Every generator is a pure function of its arguments and ``seed``. Nothing here
writes a file; callers decide where text goes. Inputs are built to a requested
size so that a measurement can be repeated at several scales.

Alias inputs are generated as YAML text with anchors. Their logical size is
known in closed form, so a measurement never needs to expand them to find out.
"""

from __future__ import annotations

import copy
import json
import random
from typing import Any, Dict, List, Tuple

#: Change modes for a Template pair.
CHANGE_MODES: Tuple[str, ...] = ("none", "one_percent", "all_leaves")


def _bucket(index: int, rng: random.Random) -> Dict[str, Any]:
    return {
        "Type": "AWS::S3::Bucket",
        "Properties": {
            "BucketName": {"Fn::Sub": "bucket-{0}-${{AWS::AccountId}}".format(index)},
            "Tags": [
                {"Key": "k{0}".format(j), "Value": "v{0}-{1}".format(j, rng.randrange(10 ** 6))}
                for j in range(3)
            ],
            "VersioningConfiguration": {"Status": "Enabled"},
        },
    }


def _document(resources: int, seed: int) -> Dict[str, Any]:
    rng = random.Random(seed)
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Bucket{0:06d}".format(i): _bucket(i, rng) for i in range(resources)},
    }


def _dump(doc: Dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(doc, indent=1)
    import yaml  # PyYAML is a runtime dependency already; imported lazily for JSON-only callers

    return yaml.safe_dump(doc, sort_keys=False)


def _resources_for_size(target_bytes: int, fmt: str, seed: int) -> int:
    probe = len(_dump(_document(200, seed), fmt).encode("utf-8")) / 200.0
    return max(1, int(target_bytes / probe * 0.98))


def _mutate(doc: Dict[str, Any], mode: str, seed: int) -> Dict[str, Any]:
    head = copy.deepcopy(doc)
    if mode == "none":
        return head
    rng = random.Random(seed + 1)
    names = sorted(head["Resources"])
    if mode == "one_percent":
        chosen = names[:: 100] or names[:1]
        for name in chosen:
            head["Resources"][name]["Properties"]["VersioningConfiguration"]["Status"] = "Suspended"
        return head
    for name in names:  # all_leaves: every scalar leaf under Properties changes
        props = head["Resources"][name]["Properties"]
        props["BucketName"]["Fn::Sub"] = props["BucketName"]["Fn::Sub"] + "-x"
        for tag in props["Tags"]:
            tag["Key"] = tag["Key"] + "x"
            tag["Value"] = "w{0}".format(rng.randrange(10 ** 6))
        props["VersioningConfiguration"]["Status"] = "Suspended"
    return head


def template_pair(target_bytes: int, fmt: str, mode: str, seed: int = 11) -> Tuple[str, str, int]:
    """Return ``(base_text, head_text, resources)`` near ``target_bytes`` each."""
    if mode not in CHANGE_MODES:
        raise ValueError(mode)
    resources = _resources_for_size(target_bytes, fmt, seed)
    base = _document(resources, seed)
    return _dump(base, fmt), _dump(_mutate(base, mode, seed), fmt), resources


def alias_fanout_yaml(levels: int, fanout: int) -> Tuple[str, int, int]:
    """YAML whose ``Resources`` holds ``levels`` lists, each ``fanout`` aliases of the previous.

    Returns ``(text, alias_references, logical_nodes)``. The logical node count is
    computed in closed form: list ``l_k`` has ``1 + fanout * size(l_{k-1})`` nodes.
    """
    lines = ["Resources:\n", "  l0: &l0 [{0}]\n".format(", ".join(['"x"'] * fanout))]
    for k in range(1, levels):
        lines.append("  l{0}: &l{0} [{1}]\n".format(k, ", ".join(["*l{0}".format(k - 1)] * fanout)))
    sizes = [1 + fanout]
    for _ in range(1, levels):
        sizes.append(1 + fanout * sizes[-1])
    logical = 1 + 1 + sum(sizes)  # document mapping + Resources mapping + each list tree
    return "".join(lines), fanout * (levels - 1), logical


def alias_reference_heavy_yaml(references: int) -> str:
    """Many alias references to one small anchor (construct cost, not fan-out)."""
    items = ", ".join(["*a"] * references)
    return "Resources:\n  base: &a {{Type: AWS::S3::Bucket}}\n  uses: [{0}]\n".format(items)


def cycle_yaml(kind: str) -> str:
    return {
        "list": "Resources:\n  R: &a [*a]\n",
        "mapping": "Resources: &r\n  R: *r\n",
        "resource": "Resources:\n  R: &a\n    Type: AWS::S3::Bucket\n    Properties: {Loop: *a}\n",
    }[kind]


def nested_list_document(depth: int) -> Dict[str, Any]:
    """A document whose tree depth is exactly ``depth`` (root = 1)."""
    inner: Any = "leaf"
    for _ in range(depth - 3):
        inner = [inner]
    return {"Resources": {"R": inner}}


def shared_fanout_object(levels: int, fanout: int) -> Tuple[Dict[str, Any], int]:
    """The in-memory equivalent of :func:`alias_fanout_yaml`, without parsing."""
    level: List[Any] = ["x"] * fanout
    resources: Dict[str, Any] = {"l0": level}
    sizes = [1 + fanout]
    for k in range(1, levels):
        level = [level] * fanout
        resources["l{0}".format(k)] = level
        sizes.append(1 + fanout * sizes[-1])
    return {"Resources": resources}, 1 + 1 + sum(sizes)


def report_pair(findings: int, evidence_per_finding: int, mode: str, seed: int = 7) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Two valid Review_Reports built with the existing ``report.build_report``.

    ``mode``: ``same`` (head equals base), ``all_new`` (base empty), or
    ``null_groups`` (template-level Findings sharing one Identity_Key in groups of 5).
    """
    from iacreview import report
    from iacreview.finding import Evidence, Finding, Location

    rng = random.Random(seed)

    def one(index: int, resource: Any) -> Finding:
        return Finding(
            ID=0,
            Normalized_Category="DataProtection",
            FindingType="Security",
            Severity="HIGH",
            Confidence="Confirmed",
            Source=["IAM Review"],
            Resource=resource,
            Location=Location(File="t.yaml", Line=None, Column=None,
                              TemplatePath=["Resources", "R{0}".format(index), "Properties", index % 7]),
            Finding="[rule] finding {0}".format(index),
            WhyItMatters="why {0}".format(rng.randrange(10 ** 6)),
            Evidence=[Evidence(Source="IAM Review", Detail="detail {0}".format(j), RuleId="rule_{0}".format(j), Excerpt=None)
                      for j in range(evidence_per_finding)],
            Recommendation="recommendation",
            SuggestedRemediation=None,
        )

    if mode == "null_groups":
        base_findings = [one(i, None) for i in range(findings)]
    else:
        base_findings = [one(i, "R{0:06d}".format(i)) for i in range(findings)]
    meta = report.ReportMeta(files=["t.yaml"], sources_enabled=["IAM Review"], tools=[])
    base = report.build_report(base_findings if mode != "all_new" else [], [], meta)
    head = report.build_report(base_findings, [], meta)
    return base, head


# ---------------------------------------------------------------------------
# M1 additions (tasks.md Task 16). The generators above are unchanged so the
# M0 inputs stay reproducible.
# ---------------------------------------------------------------------------


def change_entry_pair(entries: int, fmt: str, per_resource: int = 200) -> Tuple[str, str, int]:
    """A Template pair whose Semantic Diff has exactly ``entries`` Change_Entries.

    Each Resource holds one list of small integers under ``Properties``; the
    Head adds 1 to every element, so each element is one ``modified`` entry
    with no Qualifier. The last Resource holds the remainder.

    Returns ``(base_text, head_text, resources)``.
    """
    if entries < 1 or per_resource < 1:
        raise ValueError("entries and per_resource must be positive")
    sizes = [per_resource] * (entries // per_resource)
    if entries % per_resource:
        sizes.append(entries % per_resource)

    def doc(offset: int) -> Dict[str, Any]:
        return {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Res{0:06d}".format(i): {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"Items": [j + offset for j in range(size)]},
                }
                for i, size in enumerate(sizes)
            },
        }

    return _dump(doc(0), fmt), _dump(doc(1), fmt), len(sizes)


def _deep_properties(levels: int, leaf_json: str) -> str:
    """JSON text of a Template whose ``Resources.R.Properties`` holds ``levels``
    nested one-key mappings (``"k0"``, ``"k1"``, ...) around ``leaf_json``."""
    if levels < 0:
        raise ValueError("levels must not be negative")
    opening = "".join('{{"k{0}": '.format(n) for n in range(levels))
    closing = "}" * levels
    return ('{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"R": {"Type": "AWS::S3::Bucket", '
            '"Properties": ' + opening + leaf_json + closing + "}}}")


def deep_list_change_pair(elements: int, levels: int) -> Tuple[str, str]:
    """Two JSON Templates (RC Blocker P0, A-1b case 1): a list of ``elements``
    integers below ``levels`` nested mappings under ``Properties``; the Head
    adds 1 to every element, so each element is one ``modified`` Change_Entry
    whose path has ``levels + 4`` items. ``levels=57``, ``elements=200000`` is
    the M1 case (path length 61, each file about 1.49 MB)."""
    if elements < 1:
        raise ValueError("elements must be positive")
    base = json.dumps(list(range(elements)))
    head = json.dumps([n + 1 for n in range(elements)])
    return _deep_properties(levels, base), _deep_properties(levels, head)


def deep_duplicate_key_pair(mappings: int, levels: int) -> str:
    """One JSON Template (RC Blocker P0, A-1b case 2, compared with itself): a
    list of ``mappings`` copies of ``{"a":1,"a":2}`` below ``levels`` nested
    mappings. Each duplicate-key mapping is one uncompared path.
    ``levels=57``, ``mappings=285000`` is the M1 case (about 4.28 MB)."""
    if mappings < 1:
        raise ValueError("mappings must be positive")
    leaf = "[" + ", ".join(['{"a":1,"a":2}'] * mappings) + "]"
    return _deep_properties(levels, leaf)


def report_pair_disjoint(findings: int, evidence_per_finding: int, seed: int = 7) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Two valid Review_Reports with no Identity_Key in common.

    Every Finding is one-sided, so the Finding Delta has ``2 * findings``
    Delta_Entries (``base_only`` and ``head_only``): the largest Delta_Entry
    count a pair of this size can produce.
    """
    from iacreview import report
    from iacreview.finding import Evidence, Finding, Location

    rng = random.Random(seed)

    def one(index: int, resource: str) -> Finding:
        return Finding(
            ID=0,
            Normalized_Category="DataProtection",
            FindingType="Security",
            Severity="HIGH",
            Confidence="Confirmed",
            Source=["IAM Review"],
            Resource=resource,
            Location=Location(File="t.yaml", Line=None, Column=None,
                              TemplatePath=["Resources", resource, "Properties", index % 7]),
            Finding="[rule] finding {0}".format(index),
            WhyItMatters="why {0}".format(rng.randrange(10 ** 6)),
            Evidence=[Evidence(Source="IAM Review", Detail="detail {0}".format(j), RuleId="rule_{0}".format(j), Excerpt=None)
                      for j in range(evidence_per_finding)],
            Recommendation="recommendation",
            SuggestedRemediation=None,
        )

    meta = report.ReportMeta(files=["t.yaml"], sources_enabled=["IAM Review"], tools=[])
    base = report.build_report([one(i, "B{0:06d}".format(i)) for i in range(findings)], [], meta)
    head = report.build_report([one(i, "H{0:06d}".format(i)) for i in range(findings)], [], meta)
    return base, head
