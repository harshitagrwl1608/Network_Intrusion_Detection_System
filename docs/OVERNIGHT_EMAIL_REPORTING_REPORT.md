# Overnight Sprint Report — Email Delivery, Report Email, Dataset Sampling

**Branch:** `opencode/overnight-email-and-reporting` (based on `origin/main`
`6d580c6`, merge commit `Merge dashboard-forensics into main`)
**Status:** implementation complete; PR open, **not merged**

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
| Detection behavior frozen | No rule, threshold, weight, feature-extraction, flow-construction or evaluation-logic changes. One missing `typing.Any` import was added in `engine/rules.py` for Python 3.11 import compatibility. |
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
  stale-claim recovery after 300 s. Two workers cannot claim the same pending row. A crash after SMTP accepts a
  message but before the database records `sent` can still lead to a duplicate
  after stale-claim recovery; delivery is at-least-once across that failure window.
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

---

## 4. Test evidence

| Suite | Result |
|---|---|
| Latest GitHub Actions run (PR head, Python 3.11) | **1058 passed, 15 skipped**, 630 subtests passed |
| Synthetic evaluation (`run_eval.py`) | Completed successfully; 42 labelled scenarios detected, 0 benign false positives |
| New tests | `test_email_pipeline.py` (49), `test_report_email.py` (40) = **+89** |

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

Headline: 2 attack-labelled capture-level signals (Rbot and the Hajime prefix),
1 separate protocol-fixture signal (`oisf_irc`, which is not malware ground truth),
2 partial, 6 sub-threshold and 1 unassessed. These are coarse capture-level
signals, not flow-level true positives. The actionable findings:

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
* Because of the gap, the "six-hour" sprint window does not correspond to six
  hours of wall-clock work; the report above describes only work that actually
  ran.

---

## 7. Commits and PR

* `a4843be` — `feat(notifications): reliable email delivery and Generate & Email reports`
  (15 files, +3544 / −106; includes both new test modules and the fake SMTP
  server)
* `e2b59e5` — documentation, dataset registry update and this report.
* `3671fb7` — CI compatibility and test-hermeticity fixes (see section 8).
* `b9e1d2c` — declare `cryptography`, add dev requirements, make browser tests
  skippable (see section 8).
* `1cab419` — holdout test no longer depends on capinfos/tshark (see section 8).
* Final docs commit — CI green evidence.

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

The first CI run after switching to pytest then exposed two more pre-existing
gaps that `unittest discover` had hidden:

4. **Undeclared runtime dependency.** `storage/crypto.py` imports
   `cryptography` (Fernet/PBKDF2) for credential encryption, but it was absent
   from `ids_project/requirements.txt`, so a clean install could not use the
   encrypted-storage paths either. Declared `cryptography>=42.0.0` and added
   `ids_project/requirements-dev.txt` for test-only packages.
5. **Hard browser dependency.** `test_browser_acceptance.py` imported Selenium
   unconditionally and pinned `/usr/bin/chromium` and `/usr/bin/chromedriver`.
   It now uses `pytest.importorskip("selenium")`, skips the module with an
   explicit reason when no Chrome/Chromium binary exists, and resolves both
   binaries dynamically. It still runs in full on this host (6 passed).

A second missing annotation import was found by static scan of the whole repo
(`scripts/audits/ctu48_1_ground_truth_audit_v3_1.py` used `Tuple` and `Any`
without importing them, which broke three collection modules on 3.11).
Repository-wide scan now reports zero unbound typing names in annotations.

6. **Test depended on optional system tools.**
   `test_enforce_quarantine_permissions` wrote a header-only 24-byte PCAP and
   expected quarantine validation to accept it. That holds only when
   `capinfos`/`tshark` are installed; the pure-Python fallback correctly rejects
   a capture with no packet records, so the test failed on a clean CI runner.
   The test now writes a minimal capture that includes one packet record, which
   both code paths accept. Verified with Wireshark tooling present and with
   `PATH` emptied.

### Final verification

The latest GitHub Actions run for the PR head is run **#148** (`43362164201`).
Its Python 3.11 test job completed successfully:

```
python -m pytest ids_project/tests -q
1058 passed, 15 skipped, 630 subtests passed

python ids_project/evaluation/run_eval.py
exit 0
```

The CI run is the release-gating result. The 15 skipped tests are reported as
skipped by the CI job and are not represented as passing. The workflow completed
with `success`; the pull request is still open pending review and merge.


