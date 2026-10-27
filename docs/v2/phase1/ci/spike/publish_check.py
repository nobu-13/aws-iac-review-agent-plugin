#!/usr/bin/env python3
"""SPIKE PROTOTYPE (not deployed): publish the gate's decision as a GitHub App check run.

Runs in the publisher job of ``remediation-gate-app.yml``. It receives only
facts the base workflow produced (the verify job's result and outputs, the
event's head SHA) and a GitHub App installation token minted in the same job.
It never sees the Template, the repository checkout, tool output or the App
private key, and it is not part of the verifier (``iacreview/``).

Inputs (environment, all required):
    GITHUB_API_URL, GITHUB_SERVER_URL, GITHUB_REPOSITORY, GITHUB_RUN_ID,
    GITHUB_RUN_ATTEMPT           set by the runner
    EVENT_HEAD_SHA               github.event.pull_request.head.sha
    VERIFY_JOB_RESULT            needs.verify.result
    VERIFIED_HEAD_SHA            needs.verify.outputs.head_sha
    VERIFY_EXIT_CODE             needs.verify.outputs.exit_code
    PAYLOAD_SHA256               needs.verify.outputs.payload_sha256
    CHECK_NAME                   the required check's name
    APP_TOKEN                    installation token (checks: write only)

Conclusion: ``success`` only when the verify job succeeded, verified exactly
the event's head SHA, reported exit code 0 and a payload digest. Anything
else, including a missing, malformed or inconsistent input, publishes
``failure``. If publishing itself fails the job fails, the required check
stays missing, and the merge stays blocked (fail closed).

Exit codes: 0 published; 2 invalid configuration (nothing published);
3 publish failed.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Dict, Mapping, Optional, Tuple

SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
CHECK_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/-]{0,63}$")
REPO = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")
DIGITS = re.compile(r"^[0-9]{1,20}$")
API = re.compile(r"^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._/-]*)?$")
DECISIONS = {"0": "VERIFIED", "20": "BLOCKED", "21": "UNVERIFIED", "22": "ERROR"}
TIMEOUT_S = 30


class ConfigError(Exception):
    pass


def _need(env: Mapping[str, str], name: str, pattern: "re.Pattern[str]") -> str:
    value = env.get(name, "")
    if not pattern.match(value):
        raise ConfigError(name)
    return value


def decide(env: Mapping[str, str]) -> Tuple[str, str, str]:
    """(conclusion, title, summary) from the verify job's facts. Fails closed."""
    event_head = env.get("EVENT_HEAD_SHA", "")
    verified_head = env.get("VERIFIED_HEAD_SHA", "")
    exit_code = env.get("VERIFY_EXIT_CODE", "")
    digest = env.get("PAYLOAD_SHA256", "")
    result = env.get("VERIFY_JOB_RESULT", "")
    problems = []
    if not SHA.match(event_head):
        problems.append("event head SHA missing or malformed")
    if verified_head != event_head:
        problems.append("the verify job did not verify the event's head SHA")
    if exit_code not in DECISIONS:
        problems.append("verify exit code missing or unknown")
    if not DIGEST.match(digest):
        problems.append("report payload digest missing or malformed")
    decision = DECISIONS.get(exit_code, "none")
    # The job result and the exit code must tell the same story: success with
    # 0, failure with 20 / 21 / 22. A mismatch means the outputs cannot be
    # trusted to describe the run, so it is a problem, not a verdict.
    if decision == "VERIFIED" and result != "success":
        problems.append("verify job result is {0} although the exit code is 0".format(result or "missing"))
    if decision in ("BLOCKED", "UNVERIFIED", "ERROR") and result != "failure":
        problems.append("verify job result is {0} although the exit code is {1}".format(result or "missing", exit_code))
    ok = not problems and decision == "VERIFIED"
    conclusion = "success" if ok else "failure"
    title = "Remediation gate: {0}".format("inconsistent evidence" if problems else decision)
    lines = ["decision: {0}".format(decision), "verify job: {0}".format(result or "missing"),
             "verified head: {0}".format(verified_head if SHA.match(verified_head) else "missing"),
             "payload_sha256: {0}".format(digest if DIGEST.match(digest) else "missing")]
    lines += ["problem: " + p for p in problems]
    lines.append("VERIFIED is not an approval to merge or deploy; runtime behaviour is not verified.")
    return conclusion, title, "\n".join(lines)


def build_request(env: Mapping[str, str]) -> Tuple[str, Dict[str, str], bytes]:
    api = _need(env, "GITHUB_API_URL", API).rstrip("/")
    server = _need(env, "GITHUB_SERVER_URL", API).rstrip("/")
    repo = _need(env, "GITHUB_REPOSITORY", REPO)
    run_id = _need(env, "GITHUB_RUN_ID", DIGITS)
    attempt = _need(env, "GITHUB_RUN_ATTEMPT", DIGITS)
    name = _need(env, "CHECK_NAME", CHECK_NAME)
    token = env.get("APP_TOKEN", "")
    if not token or any(c.isspace() for c in token) or len(token) > 1000:
        raise ConfigError("APP_TOKEN")
    head = _need(env, "EVENT_HEAD_SHA", SHA)
    conclusion, title, summary = decide(env)
    digest = env.get("PAYLOAD_SHA256", "")
    body = {
        "name": name,
        "head_sha": head,
        "status": "completed",
        "conclusion": conclusion,
        # Links the check to the run that decided it; an evidence reader
        # compares this with the run's own log, not only name and app.
        "external_id": "{0}.{1}:{2}".format(run_id, attempt, digest if DIGEST.match(digest) else "none"),
        "details_url": "{0}/{1}/actions/runs/{2}".format(server, repo, run_id),
        "output": {"title": title, "summary": summary},
    }
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
        "User-Agent": "iac-remediation-gate-publisher",
    }
    return "{0}/repos/{1}/check-runs".format(api, repo), headers, json.dumps(body, sort_keys=True).encode("utf-8")


def publish(env: Mapping[str, str], opener: Optional[urllib.request.OpenerDirector] = None) -> int:
    try:
        url, headers, body = build_request(env)
    except ConfigError as exc:
        sys.stderr.write("publisher: invalid or missing {0}; nothing published\n".format(exc))
        return 2
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    open_ = (opener or urllib.request.build_opener(urllib.request.HTTPHandler, urllib.request.HTTPSHandler)).open
    try:
        with open_(request, timeout=TIMEOUT_S) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        sys.stderr.write("publisher: GitHub API returned HTTP {0}; the required check stays missing\n".format(exc.code))
        return 3
    except (urllib.error.URLError, OSError):
        sys.stderr.write("publisher: GitHub API unreachable; the required check stays missing\n")
        return 3
    if status != 201:
        sys.stderr.write("publisher: unexpected HTTP {0}; the required check stays missing\n".format(status))
        return 3
    sys.stdout.write("publisher: check '{0}' published\n".format(json.loads(body)["name"]))
    return 0


if __name__ == "__main__":
    sys.exit(publish(os.environ))
