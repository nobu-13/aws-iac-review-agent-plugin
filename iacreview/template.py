"""Template loading, format detection, and the reviewable predicate.

This module is the only place a Template file turns into a Python document.
Everything downstream (cfn-lint normalization, IAM analysis, the Agent Review
prompt) works from :class:`LoadedTemplate`, so the decisions made here apply to
the whole pipeline.

Format is decided by *content*, not by extension
    ``.yaml``, ``.yml``, ``.json``, ``.template``, and no extension at all are
    all in circulation, and a ``cdk synth`` output redirected by a user may
    carry any of them. Trusting the extension would mean a JSON Template named
    ``template.yaml`` gets parsed by the YAML loader -- which mostly works,
    since JSON is very nearly a YAML subset, and then fails in obscure ways on
    the cases where it does not (duplicate keys, tabs, ``\\/`` escapes). The
    first non-whitespace character is enough to distinguish the two: a
    CloudFormation Template is a mapping, so a JSON one begins with ``{``.

Every failure is an :class:`~iacreview.errors.IacReviewError`
    Requirement 12 AC8 requires malformed input -- invalid syntax, truncated
    files, binary content -- to produce a structured error rather than an
    unhandled exception, and the input is untrusted by definition. So the parse
    step catches broadly and re-raises
    :class:`~iacreview.errors.TemplateParseError`: a bare ``except`` for the
    parser's declared error type would still let a ``RecursionError`` from a
    deeply nested flow sequence escape as a traceback. ``IacReviewError`` itself
    is never swallowed, so a missing PyYAML still reports as
    ``tool_unavailable`` rather than being relabelled a parse failure.

Position information is always present
    :class:`~iacreview.errors.TemplateParseError` carries ``error_type``,
    ``line``, and ``column`` (Requirement 3 AC6). PyYAML supplies a
    ``problem_mark`` and :class:`json.JSONDecodeError` supplies
    ``lineno``/``colno``, but neither is guaranteed for every error, and a
    decode failure has no parser mark at all. When no position can be recovered
    the fields fall back to :data:`DEFAULT_LINE` / :data:`DEFAULT_COLUMN` so
    that consumers never have to handle ``None``.

Nothing in the Template is evaluated
    ``json.loads`` is called without ``object_hook`` / ``parse_constant``, and
    YAML goes through :func:`iacreview.yamlcfn.load_yaml`, whose loader derives
    from ``SafeLoader``. Intrinsic functions are kept as data (``{"Ref": ...}``)
    and never resolved (design.md, Security Design / Template 内容を評価しない).

The read is time-of-check to time-of-use safe. A caller passes a path that
:func:`iacreview.pathguard.resolve_within` already resolved and contained, but
that check and the read used to be separate operations, leaving a window in
which a symlink or the path itself could be swapped between them
(Requirement 17 AC5). :func:`_read_bytes_toctou_safe` closes the window: it opens
the path once with ``O_NOFOLLOW``, then proves via :func:`os.fstat` on that one
descriptor that the file it holds is a *regular* file (Requirement 17 AC6) whose
``(st_dev, st_ino)`` still match the resolved path -- and does the size check on
the same descriptor's ``st_size``. A mismatch or a non-regular file is a
``path_violation``; an unreadable file is still an
:class:`~iacreview.errors.InputNotFoundError`, matching the exit code the failure
mode matrix assigns to that case.

No message built here names an absolute path
    Every failure of this module reaches ``errors[]`` on stdout for at least one
    entry point -- a parse failure and a non-reviewable file are exactly the two
    classes the failure mode matrix asks to appear there -- and Requirement 16
    AC11 makes stdout a function of the input, so an absolute host path in a
    message would make the same review produce different bytes on two machines.
    The path a caller supplies is therefore rendered through
    :func:`iacreview.source.display_path`, and an :class:`OSError` through
    :func:`iacreview.errors.os_error_detail`, which drops the filename CPython
    appends to it.

    The conversion happens *here*, not in the callers, for the reason
    :mod:`iacreview.proc` reduces an executable path to its bare name in one
    place: callers hold the absolute path on purpose -- it is what
    :func:`iacreview.pathguard.resolve_within` returns and what an external tool
    must be given -- so any caller passing it straight in would reintroduce the
    leak, and the next caller written would reintroduce it again.
    :attr:`LoadedTemplate.path` still carries the path as given; only messages
    are rendered.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from iacreview.errors import (
    InputNotFoundError,
    InputTooLargeError,
    NotReviewableError,
    PathContainmentError,
    TemplateParseError,
    os_error_detail,
)
from iacreview.source import display_path
from iacreview.yamlcfn import import_yaml, load_yaml

__all__ = [
    "MAX_TEMPLATE_BYTES",
    "TEMPLATE_FORMATS",
    "RESOURCES_KEY",
    "JSON_START_CHARACTERS",
    "DEFAULT_LINE",
    "DEFAULT_COLUMN",
    "EMPTY_DOCUMENT_ERROR_TYPE",
    "PARSE_POSITION_FORMAT",
    "parse_position_text",
    "LoadedTemplate",
    "detect_format",
    "parse_template_text",
    "is_reviewable",
    "load_template",
]

#: Maximum size, in bytes, of a single Template file the plugin will read
#: (Requirement 17 AC1). 5 MiB: comfortably above CloudFormation's 1 MiB
#: template-body limit, so a legitimate ``cdk synth`` output still loads, while
#: a hostile multi-gigabyte file is refused before a byte is read. This is the
#: single definition of the single-file limit (Requirement 17 AC8); the
#: aggregate limit for a directory target lives in the orchestration layer as
#: ``MAX_AGGREGATE_BYTES``. Documented in ``docs/security-model.md`` (R-8).
MAX_TEMPLATE_BYTES = 5 * 1024 * 1024

#: The two formats Requirement 3 AC4 requires, in a fixed order.
TEMPLATE_FORMATS: Tuple[str, str] = ("yaml", "json")

#: Top-level section that makes a document a reviewable Template.
RESOURCES_KEY = "Resources"

#: First non-whitespace characters that mark a document as JSON.
#:
#: ``[`` is included even though a CloudFormation Template is never a list: a
#: JSON array is unambiguously JSON, and routing it to ``json.loads`` produces
#: "not a reviewable Template" instead of a confusing YAML error.
JSON_START_CHARACTERS = "{["

#: Position reported when the underlying parser gives no usable mark. 1-based,
#: matching how both PyYAML messages and editors count.
DEFAULT_LINE = 1
DEFAULT_COLUMN = 1

#: ``error_type`` used for an input that holds no document at all.
EMPTY_DOCUMENT_ERROR_TYPE = "EmptyDocument"

#: How every parse failure names its error type and its position *inside the
#: message*.
#:
#: Requirement 3 AC6 asks a parse failure to report the error type together with
#: the line and the column, and the failure mode matrix puts a parse failure's
#: ``errors[]`` entry on stdout. The three values live on
#: :class:`~iacreview.errors.TemplateParseError` as attributes and deliberately
#: not as StructuredError keys -- that key set is a fixed output contract
#: (:data:`iacreview.errors.STRUCTURED_ERROR_KEYS`) which report consumers index
#: without existence checks, so widening it for one exception class would change
#: the shape of every other error too. The message is where the report carries
#: them, so this module renders all three into it rather than leaving the caller
#: to remember that it should.
PARSE_POSITION_FORMAT = "{error_type} at line {line}, column {column}"

#: Byte-order mark. Some editors and PowerShell redirections prepend it; it is
#: valid to strip because it carries no document content, and ``json.loads``
#: rejects it outright.
_BOM = "\ufeff"


@dataclass(frozen=True)
class LoadedTemplate:
    """A parsed, reviewable Template together with how it was read.

    Attributes:
        path: Path the document was read from. Kept so that Findings and errors
            can name the file without the caller threading it through.
        doc: The parsed document. Always a mapping with a non-empty
            ``Resources`` mapping, because :func:`load_template` refuses
            anything else.
        fmt: ``"yaml"`` or ``"json"``, one of :data:`TEMPLATE_FORMATS`. Recorded
            because a later Source may need to hand the original file to an
            external tool that cares about the format.

    Frozen: the loaded Template is shared across every review Source, and a
        Source mutating it would make results depend on Source order.
        ``frozen=True`` only protects the attribute bindings, not the contents
        of ``doc``; Sources treat the document as read-only by convention.
    """

    path: Path
    doc: Dict[str, Any]
    fmt: str


# ---------------------------------------------------------------------------
# Reading and format detection
# ---------------------------------------------------------------------------


def _read_bytes_toctou_safe(path: Path) -> bytes:
    """Open, verify, and read ``path`` through a single file descriptor.

    Requirement 17 AC5 asks that the containment check and the read happen
    against the *same* file object, so that a symlink or path swapped between
    :func:`iacreview.pathguard.resolve_within` returning and the read starting
    cannot redirect the read to a file outside the workspace. ``resolve_within``
    ran on ``path`` earlier and confirmed it resolves inside the root; this
    function opens that same path and then proves the descriptor it holds refers
    to the very file that was contained, closing the check/read gap for identity,
    size, and file type at once.

    The sequence, on the one file descriptor:

    1. ``os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)`` --
       ``O_NOFOLLOW`` refuses to open the *final* component if it is a symlink,
       defeating the swap where the resolved regular file is replaced by a link
       to a target outside the root. It behaves identically on macOS and Linux.
       It only guards the last component, so the identity re-check below is the
       primary control and ``O_NOFOLLOW`` is defense-in-depth (design.md, R-2).
       ``O_NONBLOCK`` keeps the open from blocking when the path is a FIFO with
       no writer (a hostile input could hang the review otherwise); it has no
       effect on reading a regular file, which is the only file type that gets
       past the ``S_ISREG`` check below.
    2. ``os.fstat(fd)`` -- read ``st_dev``/``st_ino``, ``st_size``, and
       ``st_mode`` from the *opened* file, not from a second path lookup.
    3. ``stat.S_ISREG(st_mode)`` -- confirm a regular file; a FIFO, device, or
       directory is refused (Requirement 17 AC6).
    4. ``os.stat(path)`` on the already-resolved path and require
       ``(st_dev, st_ino)`` to match the fstat. A mismatch means the name now
       points at a different file than the descriptor holds -- the check/read
       swap -- so the read is refused.
    5. size check against :data:`MAX_TEMPLATE_BYTES` on the fstat ``st_size``,
       before any byte is read, preserving the Requirement 17 AC1 behaviour and
       moving it onto the same descriptor.
    6. read the bytes from the descriptor and close it in ``finally``.

    Non-regular files and identity mismatches are both reported as
    ``path_violation`` (:class:`~iacreview.errors.PathContainmentError`). The
    class already means "the path does not safely refer to a contained regular
    file", which is exactly what a FIFO passed as a template, or a name swapped
    after the containment check, both are; a dedicated ``not_regular_file`` class
    would split one "this path is not a safe input file" outcome across two codes
    without a consumer needing to tell them apart.

    Raises:
        InputNotFoundError: The file is missing or cannot be opened/read.
        InputTooLargeError: The opened file is larger than
            :data:`MAX_TEMPLATE_BYTES` (Requirement 17 AC1); refused before its
            bytes are read.
        PathContainmentError: The opened file is not a regular file
            (Requirement 17 AC6), or its identity does not match the resolved
            path (Requirement 17 AC5). Neither message names an absolute host
            path (Requirement 16 AC11).
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise InputNotFoundError(
            "cannot read input file: {0} ({1})".format(
                display_path(path), os_error_detail(exc)
            )
        ) from exc

    try:
        info = os.fstat(fd)

        if not stat.S_ISREG(info.st_mode):
            raise PathContainmentError(
                "input path is not a regular file and was not read: {0}".format(
                    display_path(path)
                ),
                remediation=(
                    "Provide a regular YAML or JSON Template file. FIFOs, "
                    "devices, and directories are not Templates."
                ),
            )

        try:
            resolved_info = os.stat(path)
        except OSError as exc:
            raise InputNotFoundError(
                "cannot read input file: {0} ({1})".format(
                    display_path(path), os_error_detail(exc)
                )
            ) from exc

        if (info.st_dev, info.st_ino) != (
            resolved_info.st_dev,
            resolved_info.st_ino,
        ):
            raise PathContainmentError(
                "input path changed between the containment check and the "
                "read and was not read: {0}".format(display_path(path)),
                remediation=(
                    "Do not modify or replace the input path while a review "
                    "is running."
                ),
            )

        if info.st_size > MAX_TEMPLATE_BYTES:
            raise InputTooLargeError(
                "input file exceeds the maximum size of {0} bytes and was not "
                "read: {1} ({2} bytes)".format(
                    MAX_TEMPLATE_BYTES, display_path(path), info.st_size
                ),
                remediation=(
                    "Review a CloudFormation Template no larger than {0} "
                    "bytes. A file this large is not a normal Template.".format(
                        MAX_TEMPLATE_BYTES
                    )
                ),
            )

        try:
            return _read_all(fd)
        except OSError as exc:
            raise InputNotFoundError(
                "cannot read input file: {0} ({1})".format(
                    display_path(path), os_error_detail(exc)
                )
            ) from exc
    finally:
        os.close(fd)


def _read_all(fd: int) -> bytes:
    """Read a file descriptor to EOF, returning the bytes read.

    ``os.read`` may return a short read, so it is called in a loop until it
    returns an empty ``bytes`` (EOF). The descriptor is positioned at the start
    because :func:`_read_bytes_toctou_safe` performs no seek after opening.
    """
    chunks = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _read_text(path: Path) -> str:
    """Read ``path`` as UTF-8 text through a TOCTOU-safe descriptor.

    The open/verify/read is delegated to :func:`_read_bytes_toctou_safe`; this
    function only handles the UTF-8 decode, so that the descriptor lifetime and
    the identity checks stay in one place.

    Raises:
        InputNotFoundError: The file is missing, or cannot be opened or read.
            This mirrors the exit code the failure mode matrix assigns to an
            unreadable input (3), rather than reporting it as a parse failure.
        InputTooLargeError: The file is larger than :data:`MAX_TEMPLATE_BYTES`.
            The size is taken from ``os.fstat`` on the opened descriptor and
            checked *before* any byte is read, so an oversized file never enters
            memory (Requirement 17 AC1). The message names the file the way the
            report does, never as an absolute host path (Requirement 16 AC11).
        PathContainmentError: The opened file is not a regular file
            (Requirement 17 AC6), or was swapped after the containment check
            (Requirement 17 AC5).
        TemplateParseError: The bytes are not valid UTF-8, which is what binary
            input looks like at this point. The position is computed from the
            offending byte offset so the report can still point at a location.
    """
    data = _read_bytes_toctou_safe(path)

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        line, column = _position_of_byte_offset(data, exc.start)
        error_type = _error_type_name(exc)
        raise TemplateParseError(
            "input is not valid UTF-8 text and cannot be parsed as a Template: "
            "{0}: {1} (invalid byte at offset {2})".format(
                display_path(path),
                parse_position_text(error_type, (line, column)),
                exc.start,
            ),
            error_type=error_type,
            line=line,
            column=column,
            remediation=(
                "Provide a UTF-8 encoded YAML or JSON CloudFormation Template. "
                "Binary files are not Templates."
            ),
        ) from exc


def _position_of_byte_offset(data: bytes, offset: int) -> Tuple[int, int]:
    """Convert a byte offset into a 1-based ``(line, column)`` pair.

    Counting newline bytes is correct regardless of the encoding of the
    surrounding bytes, which matters because this is used precisely when the
    content failed to decode.
    """
    prefix = data[: max(offset, 0)]
    line = prefix.count(b"\n") + 1
    column = len(prefix) - (prefix.rfind(b"\n") + 1) + 1
    return line, column


def detect_format(text: str) -> str:
    """Return ``"json"`` or ``"yaml"`` based on ``text``'s first content byte.

    Args:
        text: Decoded document text.

    Returns:
        ``"json"`` if the first non-whitespace character is in
        :data:`JSON_START_CHARACTERS`, otherwise ``"yaml"``.

    An empty or whitespace-only string reports ``"yaml"``. The value is not used
    in that case -- :func:`parse_template_text` rejects the document first --
    but returning a member of :data:`TEMPLATE_FORMATS` keeps the function total.
    """
    stripped = text.lstrip(_BOM).lstrip()
    if stripped[:1] in tuple(JSON_START_CHARACTERS):
        return "json"
    return "yaml"


# ---------------------------------------------------------------------------
# Parse error construction
# ---------------------------------------------------------------------------


def _error_type_name(exc: BaseException) -> str:
    """Return a stable, qualified name for the parser error type.

    Qualified with the defining module (``yaml.scanner.ScannerError``,
    ``json.decoder.JSONDecodeError``) because the bare class names are generic
    enough to be ambiguous in a report. Builtins keep their plain name, since
    ``builtins.UnicodeDecodeError`` reads as noise.
    """
    module = getattr(type(exc), "__module__", None)
    name = type(exc).__qualname__
    if not module or module == "builtins":
        return name
    return "{0}.{1}".format(module, name)


def parse_position_text(
    error_type: str, position: Tuple[int, int] = (DEFAULT_LINE, DEFAULT_COLUMN)
) -> str:
    """Render an ``error_type`` and a ``(line, column)`` pair for a message.

    Args:
        error_type: The parser error type, as :func:`_error_type_name` spells it.
        position: 1-based ``(line, column)``.

    Returns:
        :data:`PARSE_POSITION_FORMAT` filled in. One function so that every
        parse failure this module raises reads the same way, whether the position
        came from a parser mark or from the defaults.
    """
    line, column = position
    return PARSE_POSITION_FORMAT.format(
        error_type=error_type, line=line, column=column
    )


def _positive_int(value: object) -> Optional[int]:
    """Return ``value`` as a positive int, or ``None`` if it is not usable.

    Parser marks come from untrusted-input handling paths and are only loosely
    specified, so a non-integer or out-of-range value is treated as "no
    position" rather than propagated into the report. ``bool`` is excluded
    because ``True`` would otherwise pass as line 1.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 1:
        return None
    return value


def _yaml_position(exc: BaseException) -> Tuple[int, int]:
    """Extract a 1-based ``(line, column)`` from a PyYAML error.

    ``problem_mark`` points at the token that could not be handled and is the
    more useful of the two marks; ``context_mark`` points at the construct that
    was being parsed and is used only as a fallback, for the errors that carry
    no problem mark. PyYAML marks are 0-based, hence the ``+ 1``.
    """
    for attribute in ("problem_mark", "context_mark"):
        mark = getattr(exc, attribute, None)
        if mark is None:
            continue
        line = _positive_int(_incremented(getattr(mark, "line", None)))
        column = _positive_int(_incremented(getattr(mark, "column", None)))
        if line is not None or column is not None:
            return (line or DEFAULT_LINE, column or DEFAULT_COLUMN)
    return (DEFAULT_LINE, DEFAULT_COLUMN)


def _incremented(value: object) -> Optional[int]:
    """Convert a 0-based mark component to 1-based, or ``None`` if not an int."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value + 1


def _json_position(exc: BaseException) -> Tuple[int, int]:
    """Extract a 1-based ``(line, column)`` from a JSON decode error.

    ``json.JSONDecodeError.lineno`` and ``colno`` are already 1-based. A plain
    ``ValueError`` raised from inside the decoder carries neither, and falls
    back to the defaults.
    """
    line = _positive_int(getattr(exc, "lineno", None))
    column = _positive_int(getattr(exc, "colno", None))
    return (line or DEFAULT_LINE, column or DEFAULT_COLUMN)


def _parse_error(
    path: Path,
    fmt: str,
    exc: BaseException,
    position: Tuple[int, int],
) -> TemplateParseError:
    """Build the :class:`TemplateParseError` for a failed parse."""
    line, column = position
    error_type = _error_type_name(exc)
    return TemplateParseError(
        "{0} parse error in {1}: {2}: {3}".format(
            fmt.upper(),
            display_path(path),
            parse_position_text(error_type, position),
            exc,
        ),
        error_type=error_type,
        line=line,
        column=column,
        remediation=(
            "Fix the {0} syntax at line {1}, column {2}, then re-run the "
            "review.".format(fmt.upper(), line, column)
        ),
    )


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _parse_json(text: str, path: Path) -> Any:
    """Parse ``text`` as JSON.

    No ``object_hook``, ``object_pairs_hook``, ``parse_float``, or
    ``parse_constant`` is passed: each of those is a callback the document
    content would drive, and the plugin has no reason to let Template content
    select code to run.
    """
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise _parse_error(path, "json", exc, _json_position(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - untrusted input must fail cleanly
        # Reached for failures the decoder does not express as a
        # JSONDecodeError, such as a RecursionError from deeply nested input.
        raise _parse_error(path, "json", exc, (DEFAULT_LINE, DEFAULT_COLUMN)) from exc


def _parse_yaml(text: str, path: Path) -> Any:
    """Parse ``text`` as CloudFormation YAML.

    ``import_yaml`` is called first, outside the ``try``, for two reasons: its
    ``ToolUnavailableError`` / ``ToolVersionError`` must reach the caller
    unchanged rather than be relabelled a parse failure, and ``yaml.YAMLError``
    cannot be named in an ``except`` clause before the module is imported.
    """
    yaml = import_yaml()
    try:
        return load_yaml(text)
    except yaml.YAMLError as exc:
        raise _parse_error(path, "yaml", exc, _yaml_position(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - untrusted input must fail cleanly
        raise _parse_error(path, "yaml", exc, (DEFAULT_LINE, DEFAULT_COLUMN)) from exc


def parse_template_text(text: str, path: Path) -> Tuple[Any, str]:
    """Parse ``text`` and report which format was used.

    Args:
        text: Decoded document text. Untrusted; nothing in it is executed.
        path: Path the text came from, used only in error messages.

    Returns:
        ``(doc, fmt)`` where ``fmt`` is a member of :data:`TEMPLATE_FORMATS`.
        ``doc`` may be any JSON/YAML value, including ``None``; reviewability is
        a separate question answered by :func:`is_reviewable`.

    Raises:
        TemplateParseError: ``text`` holds no document, or it cannot be parsed
            in the detected format.
        ToolUnavailableError: YAML input and PyYAML is not installed.
        ToolVersionError: YAML input and PyYAML is too old.
    """
    if not text.strip().strip(_BOM):
        # An empty file is reported as a parse failure rather than as "not
        # reviewable": there is no document to judge, and the user needs to know
        # the file had no content rather than that it lacked a Resources
        # section.
        raise TemplateParseError(
            "input file is empty and contains no Template document: {0}: "
            "{1}".format(
                display_path(path),
                parse_position_text(EMPTY_DOCUMENT_ERROR_TYPE),
            ),
            error_type=EMPTY_DOCUMENT_ERROR_TYPE,
            line=DEFAULT_LINE,
            column=DEFAULT_COLUMN,
            remediation="Provide a YAML or JSON CloudFormation Template with content.",
        )

    fmt = detect_format(text)
    if fmt == "json":
        return _parse_json(text, path), fmt
    return _parse_yaml(text, path), fmt


# ---------------------------------------------------------------------------
# Reviewability
# ---------------------------------------------------------------------------


def is_reviewable(doc: object) -> bool:
    """Report whether ``doc`` is a reviewable CloudFormation Template.

    Requirement 3 AC1: the document must be a mapping whose top-level
    ``Resources`` is itself a mapping with at least one entry. The emptiness
    check is what keeps a stub file (``Resources: {}``) from being reported as a
    clean review, which would be indistinguishable from a Template that genuinely
    has no findings.

    Args:
        doc: Any parsed document, including ``None`` and scalars.

    Returns:
        ``True`` only for a document that carries at least one resource. Never
        raises, so callers can use it as a plain predicate.
    """
    if not isinstance(doc, dict):
        return False
    resources = doc.get(RESOURCES_KEY)
    return isinstance(resources, dict) and len(resources) > 0


def load_template(path: Path) -> LoadedTemplate:
    """Read, parse, and validate the Template at ``path``.

    Args:
        path: Path to a Template file, already resolved and contained by
            :func:`iacreview.pathguard.resolve_within`.

    Returns:
        A :class:`LoadedTemplate` whose ``doc`` is guaranteed reviewable.

    Raises:
        InputNotFoundError: ``path`` cannot be read.
        InputTooLargeError: ``path`` is larger than :data:`MAX_TEMPLATE_BYTES`;
            the file is refused before its bytes are read (Requirement 17 AC1).
        TemplateParseError: The content is not valid UTF-8, is empty, or fails
            to parse as YAML or JSON. Carries ``error_type``, ``line``, and
            ``column`` (Requirement 3 AC6).
        NotReviewableError: The document parsed but has no non-empty top-level
            ``Resources`` mapping (Requirement 3 AC5). The message names the
            file the way the report does -- workspace-relative, never absolute
            (Requirement 16 AC11).
        ToolUnavailableError: YAML input and PyYAML is not installed.
        ToolVersionError: YAML input and PyYAML is too old.
    """
    text = _read_text(path)
    doc, fmt = parse_template_text(text, path)

    if not is_reviewable(doc):
        raise NotReviewableError(
            "file is not a reviewable CloudFormation Template (no non-empty "
            "top-level {0!r} mapping): {1}".format(
                RESOURCES_KEY, display_path(path)
            ),
            remediation=(
                "Provide a CloudFormation Template whose top-level {0!r} "
                "section declares at least one resource.".format(RESOURCES_KEY)
            ),
        )

    return LoadedTemplate(path=path, doc=doc, fmt=fmt)
