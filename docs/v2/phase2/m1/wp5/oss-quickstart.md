# Evidence Integrity Foundation — Quickstart (synthetic evidence only)

* Scope: `iacreview/evidence/` (Phase 2 M1). Status: implemented, **not committed**, not released
* What this shows: capture → secret gate → immutable store → integrity validator → verified snapshot →
  evaluator → offline replay → final report, on **synthetic** GitHub answers
* What this does not provide: a connection to GitHub. There is no command that fetches real GitHub data. The
  collector takes a transport function; the only transports in this repository are test fakes. Real capture is
  planned separately (`github-e2e-verification-plan.md`) and needs its own Human approval

Every command below except the `pip install` line was run in a clean copy of the public file set (no `.agents/`,
no `.kiro/`) with the dependencies already installed; the results are in `m1-integration-test-results.md` §4. No
setup time was measured and no third-party installation was tried.

## 1. Requirements

| Item | Needed for | Version used for the recorded run |
| --- | --- | --- |
| Python ≥ 3.9 | everything | 3.9.6 (`/usr/bin/python3` on macOS) |
| Python standard library only | `iacreview.evidence` at run time | — |
| PyYAML ≥ 6.0 | the rest of the plugin (`pyproject.toml` runtime dependency); not imported by `iacreview.evidence` | 6.0.3 |
| pytest ≥ 7 | the tests and the synthetic example | 8.3.4 |
| git | only to obtain the files | — |

No network access, GitHub token, AWS credential or GitHub App key is needed or read.

## 2. Setup

From the repository root:

```sh
python3 -m pip install --user "PyYAML>=6.0" "pytest>=7"   # skip what is already installed
python3 -m pytest -q -p no:cacheprovider tests/unit/test_evidence_*.py
```

The tests that need the private Phase 1 evidence (`.agents/`) are skipped with a `NOT VERIFIED` reason in a
checkout that does not have it. Skipped is not passed.

## 3. Run the pipeline on synthetic evidence

The synthetic answers come from the test helper `tests/unit/evidence_synth.py` (invented ids, SHAs and App id).

```sh
DEMO="$(mktemp -d)"
PYTHONPATH=.:tests/unit python3 - "$DEMO" <<'EOF'
import json, sys
from pathlib import Path
import evidence_synth as syn
work = Path(sys.argv[1])
b = syn.Builder(work)                       # collector (fake transport) + secret gate + store
for gid in ("G1", "G2"):
    b.add_scenario(syn.scenario_spec(gid))
b.add_scenario(syn.scenario_spec("G3", impostor_required=True))
(work / "spec.json").write_text(json.dumps(b.seal(), indent=2), encoding="utf-8")   # seal = one store revision
EOF
python3 -m iacreview.evidence.replay "$DEMO/spec.json" > "$DEMO/result.json"
python3 -m iacreview.evidence.final_report "$DEMO/result.json" > "$DEMO/report.json"
```

`result.json` is the canonical evaluation result; its SHA-256 is the result hash (printed on stderr).
`report.json` is the summary, bound to the result by `result_sha256`.

## 4. Check integrity

The replay validates each group of evidence before it binds it (`validation` in `result.json`). To inspect the
store directly (read-only):

```sh
PYTHONPATH=. python3 - "$DEMO" <<'EOF'
import json, sys
from pathlib import Path
from iacreview.evidence.store import EvidenceStore
work = Path(sys.argv[1]) / "work"
d = EvidenceStore(work / "evidence-store", work).diagnose()
print(json.dumps({"store_valid": d["store_valid"], "unusable": d["unusable_evidence_ids"]}))
EOF
```

`store_valid: true` means every revision's manifest, envelopes and raw files match their recorded SHA-256, the
revision chain is intact and nothing is half-written. It does not mean the content came from GitHub.

## 5. Replay and compare

```sh
python3 -m iacreview.evidence.replay "$DEMO/spec.json" --expect "$DEMO/result.json" > /dev/null; echo "exit $?"
```

| Exit | Meaning |
| --- | --- |
| 0 | the replay reproduced `result.json` byte for byte |
| 2 | the spec is invalid |
| 3 | the store changed after the snapshot was taken (evaluation refused) |
| 4 | not reproduced; stderr names the first difference: `DEFINITION_CHANGED`, `SOURCE_CHANGED`, `SNAPSHOT_CHANGED`, `RESULT_MISMATCH`, `EXPECTED_NOT_CANONICAL` |

Changing one raw file in the store and running the same command gives exit 4 `SNAPSHOT_CHANGED` (the changed
evidence fails validation, is not bound, and the snapshot differs).

## 6. Reading the results

| Status | Meaning |
| --- | --- |
| `PASS` | the rule's condition holds on the bound evidence |
| `FAILED` | the evidence shows the condition is violated. A FAILED part is never offset by another part's PASS |
| `NOT_PROVEN` | the evidence does not decide it: missing, not bound, incomplete, a declared limit, or a rule that is not implemented. Never read as PASS |

* `s7_result`: the Phase 1 §7 composition of one scenario (gate, app_check, required, steal parts)
* `phase2_result`: `s7_result` plus the Phase 2 axes (issuer pinning independent proof, artifact integrity)
* `reason_code` on each criterion says why it is not PASS
* `open_questions` (S7-19): four questions of the plan, each `NOT_RUN`, `RUN_UNSETTLED`, `EVIDENCE_INSUFFICIENT`,
  `LIMIT_DECLARED` or `EVIDENCE_SATISFIED`. With the current evidence roles two of them (Q2, Q3) cannot be answered,
  so S7-19 is NOT_PROVEN
* `evidence_recording` (S7-01) in `report.json`: whether the raw API data of each scenario is in the verified
  store. PASS only if it was evaluated for at least one scenario and PASS for every one; missing roles or unbound
  evidence are NOT_PROVEN
* In `report.json`, `capture_authenticity` and `independent_reproduction` are always `NOT_PROVEN`

## 7. Security considerations

* Read-only. No GitHub, AWS or network call; nothing is deployed, merged or changed outside the given directory
* Every input is untrusted: JSON is parsed strictly, files are opened without following symbolic links, the store
  is written exclusively and never overwritten
* The secret gate refuses a page before it is stored when a secret-shaped value, binary content or an oversized
  body is found; the refusal names the rule, never the value. A clean scan is not a proof that no secret is present
* Do not put real tokens, keys or personal data into synthetic examples

## 8. Known limitations

* No real GitHub capture. Native replay has been shown for synthetic raw only
* `authenticity_verified` is false for every envelope: integrity is proven after capture, origin is not
* S7-19 Q2 (`POST /rulesets` accepting `integration_id`) and Q3 (`user/installations` permissions) have no evidence
  role in a read-only collector
* The synthetic example uses a test helper, not a product command
* The Phase 1 re-evaluation needs the private Phase 1 evidence and is not reproducible from a public checkout
* Full list: `m1-known-limitations.md`
