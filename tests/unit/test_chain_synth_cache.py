"""The per-process cache of verification reports in ``chain_synth`` (WP2 CI performance audit, option A).

The cache is a test helper only. These tests pin what makes it safe: the cached bytes equal the generated
bytes, every input that can change the report is in the key, nothing mutable is shared, and no chain
mutant edits anything the cached report is made from (so the mutation tests keep their kill power).
"""

from __future__ import annotations

import dataclasses
import importlib.util
import stat
import sys
from pathlib import Path
from typing import Any, List

import pytest

import chain_synth as cs
from iacreview.remediation import checks

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _fresh_cache() -> None:
    cs.clear_verification_cache()


def test_the_cached_report_equals_the_generated_report(tmp_path: Path) -> None:
    first = cs.build_case(tmp_path / "a", "C02")
    generated = cs.verification_report_bytes(first, cache=False)
    assert cs.verification_cache_stats() == {"calls": 0, "hits": 0, "misses": 0, "bypassed": 0}  # cache=False never touches the cache
    miss = cs.verification_report_bytes(first)
    hit = cs.verification_report_bytes(first)
    assert generated == miss == hit
    assert cs.verification_cache_stats() == {"calls": 2, "hits": 1, "misses": 1, "bypassed": 0}
    second = cs.build_case(tmp_path / "b", "C02")  # another repository directory with the same commits
    assert second.repo != first.repo and (second.base, second.head) == (first.base, first.head)
    assert cs.verification_report_bytes(second) == cs.verification_report_bytes(second, cache=False) == generated
    assert cs.verification_cache_stats() == {"calls": 3, "hits": 2, "misses": 1, "bypassed": 0}


def test_a_blocked_case_is_cached_apart_from_a_verified_one(tmp_path: Path) -> None:
    verified, blocked = cs.build_case(tmp_path / "v", "C02"), cs.build_case(tmp_path / "b", "C05")
    assert cs.verification_cache_key(verified) != cs.verification_cache_key(blocked)
    a, b = cs.verification_report_bytes(verified), cs.verification_report_bytes(blocked)
    assert a != b and b == cs.verification_report_bytes(blocked, cache=False)
    assert cs.verification_cache_stats()["misses"] == 2


def test_a_second_gate_chain_does_not_verify_again(tmp_path: Path) -> None:
    import test_chain_gate as g  # the gate tests build one chain each

    head = g.HEAD
    first = cs.GateChain(tmp_path / "one", [g.R(10, "APPROVED", g.A, g.T(10), head)])
    second = cs.GateChain(tmp_path / "two", [g.R(10, "COMMENTED", g.A, g.T(10), head)])
    assert cs.verification_cache_stats() == {"calls": 2, "hits": 1, "misses": 1, "bypassed": 0}
    assert first.chain.verification == second.chain.verification


def test_a_worktree_preview_is_never_served_from_the_cache(tmp_path: Path) -> None:
    """``head=None`` reads uncommitted files, which commit ids do not name: a stale report would be wrong."""
    setup = cs.build_case(tmp_path / "case", "C02")
    preview = dataclasses.replace(setup, head=None)
    with pytest.raises(ValueError, match="uncommitted"):
        cs.verification_cache_key(preview)
    before = cs.verification_report_bytes(preview)
    template = setup.repo / casegen_target()
    template.write_text(template.read_text(encoding="utf-8") + "\n# uncommitted edit\n", encoding="utf-8")
    after = cs.verification_report_bytes(preview)
    assert before != after  # the uncommitted edit changed the report, and the cache did not hide it
    assert after == cs.verification_report_bytes(preview, cache=False)
    assert cs.verification_cache_stats() == {"calls": 2, "hits": 0, "misses": 0, "bypassed": 2}
    assert cs._VERIFICATION_CACHE == {}  # nothing of the preview was stored
    assert cs.verification_report_bytes(setup) != after  # the committed head is a different report


def casegen_target() -> str:
    return cs.casegen.TARGET


def test_every_input_that_can_change_the_report_is_in_the_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    setup = cs.build_case(tmp_path / "case", "C02")
    base = cs.verification_cache_key(setup)
    assert base == cs.verification_cache_key(setup)  # stable
    assert cs.verification_cache_key(setup, "worktree") != base  # the execution mode
    other = cs.build_case(tmp_path / "other", "C01")
    assert cs.verification_cache_key(other) != base  # commits and contract
    monkeypatch.setenv(checks.TIMEOUT_OVERRIDE_ENV, "7")
    assert cs.verification_cache_key(setup) != base  # the verifier's own environment variable
    monkeypatch.delenv(checks.TIMEOUT_OVERRIDE_ENV)
    assert cs.verification_cache_key(setup) == base
    monkeypatch.setenv("PATH", str(tmp_path / "no-tools"))
    assert cs.verification_cache_key(setup) != base  # PATH, and with it both tools, are gone


def test_a_replaced_tool_binary_gives_another_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    setup = cs.build_case(tmp_path / "case", "C02")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in (checks.CFN_LINT, checks.CFN_GUARD):
        tool = bin_dir / name
        tool.write_text("#!/bin/sh\necho 'fake 0.0.0'\n", encoding="utf-8")
        tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", str(bin_dir))
    before = cs.verification_cache_key(setup)
    assert cs._tool_identity(checks.CFN_LINT)[1] == str((bin_dir / checks.CFN_LINT).resolve())
    (bin_dir / checks.CFN_LINT).write_text("#!/bin/sh\necho 'fake 9.9.9, longer'\n", encoding="utf-8")  # same path, new content
    assert cs.verification_cache_key(setup) != before


def test_a_draft_contract_file_is_keyed_by_its_content(tmp_path: Path) -> None:
    setup = cs.build_case(tmp_path / "case", "C02")
    draft = tmp_path / "draft.yaml"
    draft.write_text("a: 1\n", encoding="utf-8")
    setup.contract_file = draft
    one = cs.verification_cache_key(setup)
    draft.write_text("a: 2\n", encoding="utf-8")
    assert cs.verification_cache_key(setup) != one


def test_nothing_mutable_is_shared(tmp_path: Path) -> None:
    setup = cs.build_case(tmp_path / "case", "C02")
    data = cs.verification_report_bytes(setup)
    assert type(data) is bytes and all(type(v) is bytes for v in cs._VERIFICATION_CACHE.values())
    stats = cs.verification_cache_stats()
    stats["hits"] = 99
    assert cs.verification_cache_stats()["hits"] == 0  # a copy of the counters is returned
    assert cs.verification_report_bytes(setup) == data


def test_no_chain_mutant_edits_what_the_cached_report_is_made_from() -> None:
    """Mutants edit ``iacreview/chain/`` only, so caching ``iacreview.remediation`` output cannot hide a kill."""
    spec = importlib.util.spec_from_file_location("chain_mutants_cache_check", ROOT / "tests" / "mutation" / "chain_mutants.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    edited: List[Any] = sorted({edit[0] for m in module.MUTANTS for edit in m.edits})
    assert edited and all(str(path).startswith("iacreview/chain/") for path in edited), edited
    chain_sources = "".join(p.read_text(encoding="utf-8") for p in (ROOT / "iacreview" / "chain").glob("*.py"))
    # the cached report is made by remediation code that does not import the chain package (no feedback path)
    remediation_sources = "".join(p.read_text(encoding="utf-8") for p in (ROOT / "iacreview" / "remediation").glob("*.py"))
    assert "iacreview.chain" not in remediation_sources and "from iacreview import chain" not in remediation_sources
    assert "verification_report_bytes" not in chain_sources
