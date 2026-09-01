"""Shared deterministic core for aws-iac-review-agent-plugin.

This package holds every parsing, normalization, deduplication and reporting
routine exactly once. Skill entry points under ``skills/*/scripts/`` insert the
plugin root into ``sys.path`` and import from here, so no logic is duplicated
per Skill.

The package is not distributed on PyPI. The plugin ships as a directory.
"""

__all__ = ["__version__"]

__version__ = "0.9.0"
