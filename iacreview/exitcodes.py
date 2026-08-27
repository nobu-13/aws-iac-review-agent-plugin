"""Process exit codes for every entry point of the plugin.

Single source of truth for the exit code table defined in design.md
(Error Handling / Exit code). No other module may hardcode a numeric exit
status; import the constants from here instead so the mapping between a failure
class and its exit code stays in one place.

Requirement 16 AC8 requires a distinct exit code for five failure classes
(invalid arguments, input not found, parse failure, tool unavailable, tool
execution failure). The design adds ``PATH_VIOLATION``, ``NO_REVIEWABLE_TEMPLATE``
and ``UNEXPECTED``.

``UNEXPECTED`` is 1 because CPython already returns 1 for an uncaught
exception; reusing 1 for caught bugs keeps the meaning of the value consistent
whether or not the exception reached the interpreter.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

__all__ = [
    "OK",
    "UNEXPECTED",
    "INVALID_ARGUMENTS",
    "INPUT_NOT_FOUND",
    "PARSE_FAILURE",
    "TOOL_UNAVAILABLE",
    "TOOL_EXECUTION_FAILURE",
    "PATH_VIOLATION",
    "NO_REVIEWABLE_TEMPLATE",
    "EXIT_CODES",
]

#: Successful completion. Also used when zero findings were produced: an empty
#: report is a valid review result, not a failure.
OK = 0

#: Unexpected exception (a bug in the plugin or a corrupted installation).
#: The stack trace goes to stderr; stdout stays empty.
UNEXPECTED = 1

#: Argument validation failed: missing argument, unknown flag, or a shell
#: metacharacter detected in a user-supplied value.
INVALID_ARGUMENTS = 2

#: The input file does not exist or cannot be read.
INPUT_NOT_FOUND = 3

#: The input template could not be parsed as YAML or JSON.
PARSE_FAILURE = 4

#: A required external tool is absent from PATH or older than the minimum
#: supported version.
TOOL_UNAVAILABLE = 5

#: An external tool ran but failed: crash, timeout, or unparsable output.
TOOL_EXECUTION_FAILURE = 6

#: A resolved path escapes the workspace root or the plugin root.
PATH_VIOLATION = 7

#: No reviewable template was found (for example, no ``Resources`` mapping).
NO_REVIEWABLE_TEMPLATE = 8

#: Name to value mapping of every exit code above. Read-only so that callers
#: cannot mutate the shared table. Useful for documentation generation and for
#: rendering an exit code back to its symbolic name in diagnostics.
EXIT_CODES: Mapping[str, int] = MappingProxyType(
    {
        "OK": OK,
        "UNEXPECTED": UNEXPECTED,
        "INVALID_ARGUMENTS": INVALID_ARGUMENTS,
        "INPUT_NOT_FOUND": INPUT_NOT_FOUND,
        "PARSE_FAILURE": PARSE_FAILURE,
        "TOOL_UNAVAILABLE": TOOL_UNAVAILABLE,
        "TOOL_EXECUTION_FAILURE": TOOL_EXECUTION_FAILURE,
        "PATH_VIOLATION": PATH_VIOLATION,
        "NO_REVIEWABLE_TEMPLATE": NO_REVIEWABLE_TEMPLATE,
    }
)
