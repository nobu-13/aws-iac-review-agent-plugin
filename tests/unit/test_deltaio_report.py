"""Unit tests for :func:`iacreview.deltaio.read_report` (v1.1 Task 5, Design 9-1).

The Report is read with the v1.0 TOCTOU-safe reader (5 MiB, regular files
only), decoded as UTF-8, parsed as JSON that may repeat no key and may hold no
non-finite number, and digested with SHA-256 over the exact bytes read. Schema
checks are not part of this step.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from iacreview import deltaio, template
from iacreview.deltaio import Failure, LoadedReport

REPO_ROOT = Path(__file__).resolve().parents[2]
DELTA_REPORTS = REPO_ROOT / "tests" / "fixtures" / "delta" / "reports"
CANARY = "QzCanaryReportValue5519"


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _read(tmp_path: Path, data: bytes, name: str = "r.json") -> object:
    _write(tmp_path / name, data)
    return deltaio.read_report(name, tmp_path, "base")


def _failure(result: object, code: str) -> Failure:
    assert isinstance(result, Failure), result
    assert result.code == code
    assert result.input == "report"
    return result


def test_reads_parses_and_digests(tmp_path: Path) -> None:
    data = b'{"schema_version": "1.0.0", "findings": [], "n": 1.5}\n'
    result = _read(tmp_path, data)
    assert isinstance(result, LoadedReport)
    assert result.obj == {"schema_version": "1.0.0", "findings": [], "n": 1.5}
    assert result.sha256 == hashlib.sha256(data).hexdigest()
    assert result.size == len(data)


def test_digest_is_over_the_bytes_not_the_value(tmp_path: Path) -> None:
    a = _read(tmp_path, b'{"a": 1}', "a.json")
    b = _read(tmp_path, b'{ "a" : 1 }\n', "b.json")
    assert isinstance(a, LoadedReport) and isinstance(b, LoadedReport)
    assert a.obj == b.obj
    assert a.sha256 != b.sha256


@pytest.mark.parametrize("name", sorted(p.name for p in DELTA_REPORTS.iterdir() if p.is_dir()))
def test_task2_report_fixtures_load(name: str) -> None:
    for side in ("base", "head"):
        relative = "tests/fixtures/delta/reports/{0}/{1}.json".format(name, side)
        result = deltaio.read_report(relative, REPO_ROOT, side)
        assert isinstance(result, LoadedReport), (name, side, result)
        raw = (REPO_ROOT / relative).read_bytes()
        assert result.sha256 == hashlib.sha256(raw).hexdigest()
        assert result.obj == json.loads(raw.decode("utf-8"))


# ---------------------------------------------------------------------------
# size limit (Requirement 14 AC2)
# ---------------------------------------------------------------------------


def test_size_limit_at_and_over(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = b'{"k": "v"}'
    _write(tmp_path / "r.json", data)
    monkeypatch.setattr(template, "MAX_TEMPLATE_BYTES", len(data))
    assert isinstance(deltaio.read_report("r.json", tmp_path, "head"), LoadedReport)
    monkeypatch.setattr(template, "MAX_TEMPLATE_BYTES", len(data) - 1)
    failure = _failure(deltaio.read_report("r.json", tmp_path, "head"), "report_too_large")
    assert failure.error_class == "input_too_large" and failure.exit_code == 3
    assert failure.side == "head"


# ---------------------------------------------------------------------------
# path and file type (Requirement 2 AC1, AC3)
# ---------------------------------------------------------------------------


def test_directory_is_refused(tmp_path: Path) -> None:
    (tmp_path / "d.json").mkdir()
    failure = _failure(deltaio.read_report("d.json", tmp_path, "base"), "path_violation")
    assert failure.exit_code == 7


def test_fifo_is_refused(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("os.mkfifo is not available on this platform")
    os.mkfifo(tmp_path / "p.json")
    _failure(deltaio.read_report("p.json", tmp_path, "base"), "path_violation")


def test_outward_symlink_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "ws"
    root.mkdir()
    outside = _write(tmp_path / "outside.json", b"{}")
    (root / "link.json").symlink_to(outside)
    _failure(deltaio.read_report("link.json", root, "base"), "path_violation")


def test_inward_symlink_is_resolved_and_read(tmp_path: Path) -> None:
    real = _write(tmp_path / "real.json", b'{"a": 1}')
    (tmp_path / "link.json").symlink_to(real)
    result = deltaio.read_report("link.json", tmp_path, "base")
    assert isinstance(result, LoadedReport) and result.obj == {"a": 1}


def test_final_symlink_reaching_the_reader_is_input_not_found(tmp_path: Path) -> None:
    """Design 1-4 / H1 M0-10: kept as input_not_found, not relabelled."""
    real = _write(tmp_path / "real.json", b"{}")
    link = tmp_path / "link.json"
    link.symlink_to(real)
    try:
        template._read_bytes_toctou_safe(link)
    except Exception as exc:  # noqa: BLE001
        assert deltaio._failure_from_error(exc, "head", "report").code == "input_not_found"  # type: ignore[arg-type]
    else:
        pytest.fail("the reader followed a final symlink")


@pytest.mark.parametrize(
    "arg,code",
    [
        ("../x.json", "path_violation"),
        ("/etc/hosts", "path_violation"),
        ("absent.json", "input_not_found"),
        ("x|y.json", "invalid_arguments"),
        ("  ", "invalid_arguments"),
    ],
)
def test_path_failures(tmp_path: Path, arg: str, code: str) -> None:
    _failure(deltaio.read_report(arg, tmp_path, "base"), code)


# ---------------------------------------------------------------------------
# decoding and strict JSON
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data",
    [b'{"a": "\xff\xfe"}', b"\xef\xbb\xbf{}", b"\x00\x01\x02"],
    ids=["invalid_utf8", "bom", "binary"],
)
def test_not_utf8_json_is_a_parse_failure(tmp_path: Path, data: bytes) -> None:
    failure = _failure(_read(tmp_path, data), "report_parse_failure")
    assert failure.error_class == "schema_violation" and failure.exit_code == 4


@pytest.mark.parametrize(
    "data",
    [b'{"a": 1, "a": 2}', b'{"findings": [{"ID": 1, "ID": 2}]}', b'[{"x": {"y": 1, "y": 1}}]'],
    ids=["top_level", "in_a_finding", "deep"],
)
def test_duplicate_keys_are_refused(tmp_path: Path, data: bytes) -> None:
    failure = _failure(_read(tmp_path, data), "report_duplicate_json_key")
    assert failure.error_class == "schema_violation" and failure.exit_code == 4


@pytest.mark.parametrize("literal", [b"NaN", b"Infinity", b"-Infinity", b"1e999", b"-1e999"])
def test_non_finite_numbers_are_refused(tmp_path: Path, literal: bytes) -> None:
    _failure(_read(tmp_path, b'{"n": ' + literal + b"}"), "report_parse_failure")


def test_large_finite_numbers_are_kept(tmp_path: Path) -> None:
    result = _read(tmp_path, b'{"n": 1e308, "i": 123456789012345678901234567890}')
    assert isinstance(result, LoadedReport)
    assert result.obj == {"n": 1e308, "i": 123456789012345678901234567890}


def test_malformed_json_reports_a_position(tmp_path: Path) -> None:
    failure = _failure(_read(tmp_path, b'{\n  "a": 1,\n  "b": \n}'), "report_parse_failure")
    assert failure.line == 4 and failure.column == 1


def test_deep_nesting_is_a_parse_failure_not_a_crash(tmp_path: Path) -> None:
    _failure(_read(tmp_path, b"[" * 200000 + b"]" * 200000), "report_parse_failure")


def test_empty_file_is_a_parse_failure(tmp_path: Path) -> None:
    _failure(_read(tmp_path, b""), "report_parse_failure")


@pytest.mark.parametrize(
    "data",
    [
        b'{"' + CANARY.encode() + b'": }',
        b'{"a": "' + CANARY.encode() + b'", "a": 1}',
        b'{"' + CANARY.encode() + b'": NaN}',
        b'{"x": "' + CANARY.encode() + b'\xff"}',
    ],
)
def test_no_input_text_is_kept(tmp_path: Path, data: bytes) -> None:
    result = _read(tmp_path, data)
    assert isinstance(result, Failure)
    assert CANARY not in repr(result)
    for value in vars(result).values():
        assert value is None or isinstance(value, int) or (isinstance(value, str) and CANARY not in value)


def test_parse_report_bytes_is_pure() -> None:
    data = b'{"a": [1, 2]}'
    first = deltaio.parse_report_bytes(data, "head")
    second = deltaio.parse_report_bytes(data, "head")
    assert isinstance(first, LoadedReport) and isinstance(second, LoadedReport)
    assert first == second
