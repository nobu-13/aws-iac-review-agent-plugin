"""Configuration D: the Phase 1 contracts rebuilt from Guard and a small script.

A fair "do it yourself" baseline for the comparison (AC45): what a team could
write in an afternoon with the official tools, git and PyYAML, without the
Phase 1 verifier. Exit 0 accepts the candidate, anything else rejects it.

1. ``git diff --name-only BASE HEAD`` must name the target Template only.
2. Both Templates are loaded with PyYAML (CloudFormation tags kept as data);
   after deleting the allowed properties of the target Resource, everything
   else must be equal.
3. cfn-guard with the hand-written rules (``baseline_d/<scenario>.guard``) and
   cfn-lint on the Head Template must pass.
"""

from __future__ import annotations

import argparse
import copy
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
TARGET = "infra/template.yaml"
ALLOWED = {"sc01": ("OrdersTable", ["BillingMode", "ProvisionedThroughput"]), "sc02": ("IngestRole", ["Policies"])}


class CfnLoader(yaml.SafeLoader):
    pass


def _tag(loader, suffix, node):  # type: ignore[no-untyped-def]
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    return {"!" + suffix: value}


CfnLoader.add_multi_constructor("!", _tag)


def git(repo: str, *args: str) -> str:
    return subprocess.run(["git", "-C", repo, *args], check=True, stdout=subprocess.PIPE).stdout.decode()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--repo", required=True)
    p.add_argument("--base", required=True)
    p.add_argument("--head", required=True)
    p.add_argument("--scenario", required=True, choices=sorted(ALLOWED))
    a = p.parse_args()
    changed = [x for x in git(a.repo, "diff", "--name-only", a.base, a.head).splitlines() if x]
    if changed not in ([], [TARGET]):
        return 1
    base = yaml.load(git(a.repo, "show", a.base + ":" + TARGET), Loader=CfnLoader)
    head_text = git(a.repo, "show", a.head + ":" + TARGET)
    head = yaml.load(head_text, Loader=CfnLoader)
    resource, props = ALLOWED[a.scenario]
    stripped = []
    for doc in (base, head):
        doc = copy.deepcopy(doc)
        for prop in props:
            doc.get("Resources", {}).get(resource, {}).get("Properties", {}).pop(prop, None)
        stripped.append(doc)
    if stripped[0] != stripped[1]:
        return 2
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "head.yaml"
        path.write_text(head_text, encoding="utf-8")
        guard = subprocess.run(["cfn-guard", "validate", "--data", str(path), "--rules", str(HERE / "baseline_d" / (a.scenario + ".guard")), "--show-summary", "none"])
        if guard.returncode != 0:
            return 3
        lint = subprocess.run(["cfn-lint", "--", str(path)], stdout=subprocess.DEVNULL)
        if lint.returncode not in (0, 4, 8, 12):
            return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
