"""Benchmark harness for aws-iac-review-agent-plugin.

The harness runs the deterministic review pipeline over ``benchmark/cases/``
and compares the result with each case's Ground_Truth. Agent Findings are never
generated at run time; they are supplied as fixed fixtures so the harness stays
deterministic.
"""
