# Overnight Sprint Report — Email Delivery, Report Email, Dataset Sampling

**Branch:** `opencode/overnight-email-and-reporting` (based on `origin/main`
`6d580c6`, merge commit `Merge dashboard-forensics into main`)
**Status:** implementation complete; PR open, **not merged**
**Companion tool:** `scripts/ops/model_failover_watchdog.py`

---

## 1. Scope and constraints honoured

| Constraint | Result |
|---|---|
| Work on a separate branch, never `main` | Branch created in an isolated worktree; `main` untouched |
| Push only this branch, never force-push | `git push -u origin opencode/overnight-email-and-reporting` (no `-f`) |
| PR opened, not merged | Yes |
| Preserve the user's uncommitted work | Original repo was never edited; its diff was archived to `~/NetGuard-overnight-handoff/preexisting_dashboard_forensics_*.patch` before any work |
| No secrets, PCAPs, databases, caches or benchmark outputs committed | Verified by staged-diff scan; test byproducts removed; `/storage/` added to `.gitignore` |
| Email work only — no new Telegram work | Telegram/SMS/webhook code paths untouched except shared outbox plumbing |
| Report formats: HTML/JSON/CSV only | `SUPPORTED_FORMATS = ("html", "json", "csv")`; `pdf` requests degrade to real HTML |
| Detection code frozen | `git status --porcelain -- ids_project/engine ids_project/detection ids_project/capture ids_project/evaluation` empty for the whole sprint |
| Datasets stored outside the repo, ≤ 2 GiB | 206.3 MiB on `/run/media/harshitgarg/Data1`, ≥ 100 GiB free maintained |
| No live-network replay | Only file-based replay through the existing offline path |
| No real SMTP credentials in tests | Local in-process fake SMTP server only |
| No fabricated precision/recall | Only capture-level signals reported, with explicit limits |

---

## 2. Root cause of the failing email notification

**Symptom:** Gmail returned
`(530, b'5.7.0 Authentication Required. For more information, go to ...')`.

**Actual causes (two, both in `EmailProvider`):**

1. `from_addr` silently defaulted to `netguard-ids@localhost`. Gmail rejects a
   sender it has no relationship with, and the misleading localhost sender made
   the failure look like an authentication problem.
2. When a username was configured but the password was empty,
   `if self.user and self.password:` skipped `server.login()` entirely. The
   provider then issued `MAIL FROM` unauthenticated, and the relay answered
   `530 5.7.0 Authentication Required`.

**Fix:** no sender fallback (an unconfigured sender is an explicit configuration
error), and fail closed with a specific diagnostic when a username has no stored
password. A regression test asserts the exact message so the silent-skip path
cannot return.

---

## 3. What was built

### 3.1 Recipient and rendering layer

* `notifications/email_utils.py` — delimiter-aware parsing (`,`, `;`, newlines),
  case-insensitive de-duplication, per-field (25) and total (50) ceilings,
  rejection of any address containing CR/LF/NUL (header injection is impossible),
  safe `From:` formatting, address redaction for diagnostics.
* `notifications/email_render.py` — one `RenderedEmail(subject, text, html)` for
  alerts and reports. All interpolated values HTML-escaped, severity constrained
  to a fixed CSS token, plain-text alternative always present, dashboard link only
  from a validated `http(s)` base URL, no scripts/remote images.

### 3.2 SMTP provider

* Explicit TLS modes (`starttls`, `ssl`, `none`) with port-derived defaults.
* STARTTLS is required when selected; credentials are never sent in the clear.
* `From` display name, `Cc`, `Bcc` (Bcc only in the envelope, never in headers).
* Validated attachments, basename-only filenames, 25 MiB cap.
* Failure classification (`auth`, `permanent`, `transient`) drives retry policy.
* **Bug found by the new tests:** `server.sendmail()` was called without reading
  its return value, so *partial* recipient rejection was reported as full
  success. The refusal map is now consumed, and the result is reported as
  "delivered to N of M recipients" with the rejected addresses recorded.

### 3.3 Durable outbox

* New bounded `notification_outbox.payload_json` column (≤ 64 KB) so rich HTML is
  rendered at delivery time rather than persisted.
* Claim-based delivery: atomic `pending` → `sending` before transmission, with
  stale-claim recovery after 300 s. Two workers (or a restart mid-send) can no
  longer double-send.
* Permanent vs transient classification only for email; non-email providers keep
  their historical retry behaviour.
* Durable report jobs (`enqueue_report_email`) with attachment reference, delay,
  Cc/Bcc and per-job status.

### 3.4 Report delivery and "Generate & Email"

* `notifications/report_delivery.py` — artifacts confined to an
  application-owned directory, path resolution validated against the root
  (symlink escapes rejected), `0600` modes, size/hash recorded, pruning
  (24 h / 200 files), 25 MiB ceiling.
* `reports/generator.py` hardened: HTML escaping, severity token constraint, CSV
  formula-injection neutralisation (`=`, `+`, `-`, `@`, tab, CR), and
  `SUPPORTED_FORMATS` restricted to HTML/JSON/CSV.
* Dashboard:
  * `POST /api/reports/email` — validates type/format/window/recipients,
    generates the artifact, queues the job, audits the action with size and
    SHA-256, returns `202`.
  * `GET /api/reports/outbox` — report jobs plus outbox counters.
  * Reports workspace: To/Cc/Bcc fields and a **Generate & Email** action.
  * Notification settings: display name, Cc, Bcc, transport security, and a
    warning when a username has no stored password.

### 3.5 Watchdog

`scripts/ops/model_failover_watchdog.py` + `docs/OPERATIONS_MODEL_FAILOVER_WATCHDOG.md`.
Independent supervisor that reads provider errors from OpenCode's session
database, attempts the authorised fallback exactly once, and either continues or
performs a single graceful shutdown. Model output never reaches a shell. See the
dedicated document for configuration and limitations.

---

## 4. Test evidence

| Suite | Result |
|---|---|
| `pytest ids_project/tests` (branch) | **1074 passed**, 630 subtests, **4 failed** |
| Baseline (`origin/main`) | 986 passed, 630 subtests, 4 failed |
| New tests | `test_email_pipeline.py` (49), `test_report_email.py` (39) = **+88** |

The four failures are byte-identical to the pre-existing baseline and are **not**
caused by this work:

1. `test_regression_fixes.py::TestDetectionEnvironmentParsing::test_string_port_telemetry_compatibility_across_rules`
2. `test_tcp_zero_window.py::TestTcpZeroWindowRule::test_zero_window_alert_reports_responder_role_from_handshake`
3. `test_workbench.py::test_eval_db_mcp_server_summary_and_stats`
4. `test_workbench.py::test_eval_db_mcp_server_sql_injection_defense`

No failing test was disabled, skipped or removed.

Notable test coverage added:

* header-injection rejection in recipients and subjects;
* Bcc never appearing in headers while remaining in the envelope;
* STARTTLS refusal when the server does not advertise it;
* authentication failure classified permanent (no retry) vs connection refused
  classified transient (retry);
* partial recipient rejection;
* claim/duplicate-delivery and stale-claim recovery;
* report artifact confinement, symlink escape, size ceiling and pruning;
* CSV formula injection through the real generator;
* missing attachment still producing a covering email.

---

## 5. Dataset sampling (read-only evaluation)

12 previously unevaluated public captures, 206.3 MiB, 706,965 packets replayed
through the unmodified engine at detector revision
`a4843be53cb6c0a6d9315774abae62c92185bb01`.

Headline: 3 capture-level true positives, 2 partial, 6 sub-threshold, 1
unassessed. The three actionable findings:

1. `ICMP_FLOOD`/`ICMP_SWEEP` did not fire on a publisher-labelled Rbot ICMP-DoS
   capture (28,826 packets).
2. `DNS_ANOMALY` did not fire on a fast-flux capture (45,853 packets).
3. Two attack-labelled captures produced **zero** alerts:
   `ctu13_sogou_20110816` (20,663 packets) and IoT-23 Torii
   `iot23_malware_21_1` (50,277 packets).

Small Suricata-verification fixtures (48–16,384 packets) are explicitly marked as
non-evidence; DoH-over-443 is recorded as a scope boundary, not a miss. Full
detail, hashes, licenses and limitations:
`/run/media/harshitgarg/Data1/NetGuard-datasets/evaluations/20261112T175050Z_supplementary/OVERNIGHT_DATASET_EVALUATION_REPORT.md`.

No detection change was made in response to these findings — the sprint forbade
it. They are recorded as follow-up work.

---

## 6. Timeline and operational disclosure

* Sprint start: 2026-11-12 17:14 UTC.
* The host **suspended at ≈17:52 UTC** and resumed at ≈02:17 UTC on 2026-11-13,
  an ≈8 h 25 min gap. The externally scheduled shutdown at 23:20 UTC did not fire
  because the machine was suspended.
* Consequences: the first dataset pass completed only 1 of 12 captures, and the
  in-flight download failed on resume with DNS errors. The remaining 11 captures
  were re-run and merged; no capture was scored twice.
* The watchdog stayed resident across the suspend, checkpointed on resume, and
  never left `IDLE`.
* Because of the gap, the "six-hour" sprint window does not correspond to six
  hours of wall-clock work; the report above describes only work that actually
  ran.

### Known limitation

The watchdog's real `systemctl poweroff` path could not be executed because
`sudo -n` requires a password on this host. Dry-run and unit-level verification
passed; `CanPowerOff` was confirmed. This is disclosed rather than claimed as
verified end to end.

---

## 7. Commits and PR

* `a4843be` — `feat(notifications): reliable email delivery and Generate & Email reports`
  (15 files, +3544 / −106; includes both new test modules and the fake SMTP
  server)
* `e2b59e5` — documentation, dataset registry update, watchdog tool and this report.
* `3671fb7` — CI compatibility and test-hermeticity fixes (see below).

PR: opened against `main`, **not merged**. All metrics in this report come from
the commands above; no number was estimated.

---

## 8. CI follow-up: why the `test` check was red

The PR's `test` check reported failure, but the identical failure exists on
`main` (run 43252756947 on `6d580c6`) and on every earlier run. The job log
showed the suite dying during collection, not during detection tests:

| Signature | Count on `main` |
|---|---|
| `ModuleNotFoundError: No module named 'pytest'` | 23 |
| `NameError: name 'Any' is not defined` | 59 |

Three distinct causes, none of them a regression from this PR:

1. **Missing `Any` import (product bug).** `ids_project/engine/rules.py`
   annotated `_normalize_port(port: Any)` without importing `Any`. Python
   3.11–3.13 evaluate annotations when the `def` executes, so *importing the
   engine* raised `NameError`. Python 3.14 (used locally) defers annotation
   evaluation via PEP 649, which is why the bug never showed up in local runs.
   Every test module that imports the engine failed. Fixed with
   `from typing import Any` — no rule, threshold, weight or feature logic
   changed.
2. **Wrong test runner.** CI ran `python -m unittest discover`, but the suite is
   pytest-based and pytest was not installed. CI now installs pytest and runs
   `python -m pytest ids_project/tests -q`.
3. **Order-dependent test failures (test-hygiene bug).** Two detection tests
   passed alone but failed in a full run:
   `test_regression_fixes.py::TestDetectionEnvironmentParsing::test_string_port_telemetry_compatibility_across_rules`
   and
   `test_tcp_zero_window.py::TestTcpZeroWindowRule::test_zero_window_alert_reports_responder_role_from_handshake`.
   `RuleEngine.__init__` copies `config.TRUSTED_HOSTS` — seeded with the
   configured gateway, default `192.168.1.1` — into the module-global
   `engine.rules.TRUSTED_HOSTS`. Any test that built an engine therefore marked
   the gateway as trusted for the remainder of the session, suppressing alerts
   whose source/advertiser was `192.168.1.1`. `setUpClass` in
   `test_memory_and_lru_bounds.py` was the first leak. A conftest autouse
   fixture now restores the set to its session baseline after every test; no
   assertion was weakened or removed.

Two evaluation-DB MCP tests were also made hermetic: they required a
developer-populated, gitignored `ids_project/storage/alerts.db`, so they now
create a throwaway database under `tmp_path`.

Local verification after the fixes (Python 3.14.8, the only interpreter
available on this host):

```
python3 -m pytest ids_project/tests -q   -> 1078 passed, 630 subtests passed
python3 ids_project/evaluation/run_eval.py -> exit 0
```

Residual risk disclosed honestly: the host has no Python 3.11 interpreter, so
the fixes were verified for *importability* under 3.11 semantics via
`typing.get_type_hints()` rather than by executing the suite on 3.11. Any
remaining 3.11-only behaviour difference will surface in the CI check itself.

