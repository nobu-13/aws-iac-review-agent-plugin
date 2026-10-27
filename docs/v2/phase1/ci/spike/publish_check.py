#!/usr/bin/env python3
"""SPIKE PROTOTYPE (not deployed): publish the gate's decision as a GitHub App check run.

Runs in the publish job of ``remediation-gate-app.yml``. It never sees the
Template, a repository checkout, tool output or the App private key, and it
is not part of the verifier (``iacreview/``).

What it trusts and what it does not:

* Run context (``GITHUB_*``, ``RUNNER_ENVIRONMENT``, the event payload file):
  set by the runner; a workflow cannot overwrite ``GITHUB_*`` / ``RUNNER_*``.
  Still checked, so that the publisher refuses to run in any context other
  than the base gate: event ``pull_request_target``, workflow file
  ``.github/workflows/remediation-gate.yml`` on the default branch, a PR
  into the default branch of this repository, a GitHub-hosted runner.
  Otherwise nothing is published (exit 2) and the required check stays
  missing.
* Target SHA: the event payload's ``pull_request.head.sha`` only. Never a job
  output, never an environment value from the workflow.
* Verify job outputs: produced by pinned code that reads untrusted bytes, so
  they are evidence, not instructions. ``success`` needs all of: job result
  ``success``, exit code 0, decision ``VERIFIED``, the verified head equal to
  the event head, a 64-hex digest. Any missing, malformed or inconsistent
  value gives ``failure``.
* GitHub's response: checked. The created check must be on the event head,
  carry the requested name, conclusion and external_id, and come from the
  configured App id. Redirects are refused so the token is sent to
  ``GITHUB_API_URL`` only.

Inputs (environment):
    runner     GITHUB_API_URL, GITHUB_SERVER_URL, GITHUB_REPOSITORY,
               GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT, GITHUB_EVENT_NAME,
               GITHUB_EVENT_PATH, GITHUB_REF, GITHUB_WORKFLOW_REF,
               RUNNER_ENVIRONMENT
    workflow   VERIFY_JOB_RESULT (needs.verify.result),
               VERIFY_EXIT_CODE, VERIFY_DECISION, VERIFIED_HEAD_SHA,
               PAYLOAD_SHA256 (needs.verify.outputs.*),
               CHECK_NAME, EXPECTED_APP_ID, APP_TOKEN

Exit codes: 0 published and confirmed; 2 invalid configuration or not the
base gate (nothing published); 3 publish failed (nothing confirmed);
4 GitHub's response does not match the request (treat as not published).
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

# Always used with fullmatch: with re.match, "$" also accepts a trailing "\n".
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
CHECK_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._/-]{0,63}$")
REPO = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")
BRANCH = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
DIGITS = re.compile(r"^[0-9]{1,20}$")
API = re.compile(r"^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._/-]*)?$")
DECISIONS = {"0": "VERIFIED", "20": "BLOCKED", "21": "UNVERIFIED", "22": "ERROR"}
JOB_RESULTS = ("success", "failure", "cancelled", "skipped")
GATE_EVENT = "pull_request_target"
GATE_ACTIONS = ("opened", "synchronize", "reopened")
GATE_WORKFLOW_PATH = ".github/workflows/remediation-gate.yml"
MAX_EVENT_BYTES = 25 * 1024 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
TIMEOUT_S = 30


class ConfigError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: the bearer token must not follow one."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        # None makes urllib raise HTTPError for the 3xx instead of following it.
        return None


def default_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(NoRedirect)


def _need(env: Mapping[str, str], name: str, pattern: "re.Pattern[str]") -> str:
    value = env.get(name, "")
    if not pattern.fullmatch(value):
        raise ConfigError(name)
    return value


def _get(obj: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def gate_context(env: Mapping[str, str]) -> Tuple[str, str]:
    """(repository, event head SHA) if this is the base gate; ConfigError otherwise."""
    repo = _need(env, "GITHUB_REPOSITORY", REPO)
    if env.get("GITHUB_EVENT_NAME") != GATE_EVENT:
        raise ConfigError("GITHUB_EVENT_NAME (not {0})".format(GATE_EVENT))
    if env.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise ConfigError("RUNNER_ENVIRONMENT (not github-hosted)")
    path = Path(env.get("GITHUB_EVENT_PATH", ""))
    try:
        if not env.get("GITHUB_EVENT_PATH") or not path.is_file() or path.stat().st_size > MAX_EVENT_BYTES:
            raise ConfigError("GITHUB_EVENT_PATH")
        event = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        raise ConfigError("GITHUB_EVENT_PATH (unreadable)")
    default = _get(event, "repository", "default_branch")
    if not isinstance(default, str) or not BRANCH.fullmatch(default):
        raise ConfigError("event repository.default_branch")
    if _get(event, "action") not in GATE_ACTIONS:
        raise ConfigError("event action")
    if _get(event, "repository", "full_name") != repo or _get(event, "pull_request", "base", "repo", "full_name") != repo:
        raise ConfigError("event repository")
    if _get(event, "pull_request", "base", "ref") != default:
        raise ConfigError("event base ref (not the default branch)")
    ref = "refs/heads/" + default
    if env.get("GITHUB_REF") != ref:
        raise ConfigError("GITHUB_REF (not the default branch)")
    if env.get("GITHUB_WORKFLOW_REF") != "{0}/{1}@{2}".format(repo, GATE_WORKFLOW_PATH, ref):
        raise ConfigError("GITHUB_WORKFLOW_REF (not the gate on the default branch)")
    head = _get(event, "pull_request", "head", "sha")
    if not isinstance(head, str) or not SHA.fullmatch(head):
        raise ConfigError("event pull_request.head.sha")
    return repo, head


def decide(env: Mapping[str, str], event_head: str) -> Tuple[str, str, str]:
    """(conclusion, title, summary) from the verify job's facts. Fails closed."""
    verified_head = env.get("VERIFIED_HEAD_SHA", "")
    exit_code = env.get("VERIFY_EXIT_CODE", "")
    decision_out = env.get("VERIFY_DECISION", "")
    digest = env.get("PAYLOAD_SHA256", "")
    result = env.get("VERIFY_JOB_RESULT", "")
    problems = []
    if result not in JOB_RESULTS:
        problems.append("verify job result missing or unknown")
        result = ""
    if exit_code not in DECISIONS:
        problems.append("verify exit code missing or unknown")
    decision = DECISIONS.get(exit_code, "none")
    if decision_out != decision:
        problems.append("verify decision does not match its exit code")
    if not DIGEST.fullmatch(digest):
        problems.append("report payload digest missing or malformed")
    if decision == "VERIFIED" and verified_head != event_head:
        problems.append("the verify job did not verify the event's head SHA")
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
             "event head: {0}".format(event_head),
             "verified head: {0}".format(verified_head if SHA.fullmatch(verified_head) else "missing"),
             "payload_sha256: {0}".format(digest if DIGEST.fullmatch(digest) else "missing")]
    lines += ["problem: " + p for p in problems]
    lines.append("VERIFIED is not an approval to merge or deploy; runtime behaviour is not verified.")
    return conclusion, title, "\n".join(lines)


def build_request(env: Mapping[str, str]) -> Tuple[str, Dict[str, str], Dict[str, Any]]:
    api = _need(env, "GITHUB_API_URL", API).rstrip("/")
    server = _need(env, "GITHUB_SERVER_URL", API).rstrip("/")
    run_id = _need(env, "GITHUB_RUN_ID", DIGITS)
    attempt = _need(env, "GITHUB_RUN_ATTEMPT", DIGITS)
    name = _need(env, "CHECK_NAME", CHECK_NAME)
    _need(env, "EXPECTED_APP_ID", DIGITS)
    token = env.get("APP_TOKEN", "")
    if not token or any(c.isspace() for c in token) or len(token) > 1000:
        raise ConfigError("APP_TOKEN")
    repo, head = gate_context(env)
    conclusion, title, summary = decide(env, head)
    digest = env.get("PAYLOAD_SHA256", "")
    body = {
        "name": name,
        "head_sha": head,
        "status": "completed",
        "conclusion": conclusion,
        # Links the check to the run that decided it; an evidence reader
        # compares this with the run's own log and report, not only name and app.
        "external_id": "{0}.{1}:{2}".format(run_id, attempt, digest if DIGEST.fullmatch(digest) else "none"),
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
    return "{0}/repos/{1}/check-runs".format(api, repo), headers, body


def response_problems(created: Any, body: Mapping[str, Any], app_id: str) -> list:
    if not isinstance(created, dict):
        return ["response is not a JSON object"]
    problems = []
    for key in ("name", "head_sha", "conclusion", "external_id"):
        if created.get(key) != body[key]:
            problems.append("response {0} differs from the request".format(key))
    if created.get("status") != "completed":
        problems.append("response status is not completed")
    if str(_get(created, "app", "id")) != app_id:
        problems.append("check was not created by the configured App")
    return problems


def publish(env: Mapping[str, str], opener: Optional[urllib.request.OpenerDirector] = None) -> int:
    try:
        url, headers, body = build_request(env)
    except ConfigError as exc:
        sys.stderr.write("publisher: invalid or missing {0}; nothing published\n".format(exc))
        return 2
    data = json.dumps(body, sort_keys=True).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    open_ = (opener or default_opener()).open
    try:
        with open_(request, timeout=TIMEOUT_S) as response:
            status = response.status
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        sys.stderr.write("publisher: GitHub API returned HTTP {0}; the required check stays missing\n".format(exc.code))
        return 3
    except (urllib.error.URLError, OSError):
        sys.stderr.write("publisher: GitHub API unreachable; the required check stays missing\n")
        return 3
    if status != 201:
        sys.stderr.write("publisher: unexpected HTTP {0}; the required check stays missing\n".format(status))
        return 3
    try:
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("too large")
        created = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        created = None
    problems = response_problems(created, body, env["EXPECTED_APP_ID"])
    if problems:
        for problem in problems:
            sys.stderr.write("publisher: {0}\n".format(problem))
        return 4
    sys.stdout.write("publisher: check '{0}' ({1}) published on {2}\n".format(body["name"], body["conclusion"], body["head_sha"]))
    return 0


if __name__ == "__main__":
    sys.exit(publish(os.environ))
