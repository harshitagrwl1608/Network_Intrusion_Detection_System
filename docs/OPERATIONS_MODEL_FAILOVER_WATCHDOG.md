# NetGuard IDS — Model Failover Watchdog (Operator Tool)

`scripts/ops/model_failover_watchdog.py` is a **standalone supervisor for long
autonomous sessions**, not part of the IDS runtime. It exists so that a sprint
driven by a free model can survive that model becoming unavailable, and can shut
the host down predictably if no authorised model remains.

It does not import the IDS, does not touch the repository, and does not depend on
the agent's own output. It runs as its own process.

---

## 1. What it guarantees

| Property | Implementation |
|---|---|
| Attempts fallback **exactly once** per failure | `probe.max_attempts = 1`; the attempt is recorded in state before it starts |
| Success → continue | `FALLBACK_ACTIVE`: marker written, session left running |
| Failure → graceful stop | `MODEL_UNAVAILABLE`: marker written, managed processes stopped, then poweroff |
| Model output never executes anything | The probe is a fixed argv list; output is only compared against a token. A shell is never invoked with model text |
| Dry-run | `--dry-run` performs every step except killing processes and powering off |
| No duplicate shutdowns | `shutdown_started` marker + state guard; a second request is a no-op |
| Transient network errors do not power off | `transient` classification is recorded and ignored |
| Checkpoints | Written at startup, every `checkpoint_interval_s` (default 600 s), and on manual request |

---

## 2. Signal source

The authoritative signal is **OpenCode's session database**, not the server log:

```
~/.local/share/opencode/opencode.db   table: session_message
type = 'assistant'  and  data.error is present
```

For each assistant message whose `data.model` matches an authorised model, the
`data.error` object is classified:

| `error.type` / message | Class | Action |
|---|---|---|
| quota / usage-limit / rate-limit / 429 / insufficient_quota | `quota` | fallback attempt |
| `ProviderModelNotFound`, model-not-found | `unavailable` | fallback attempt |
| `aborted` | ignored | none |
| connection refused/reset, DNS failure, timeout, 502/503/504 | `transient` | recorded, no action |
| anything else | `unknown` | recorded, no action |

`db.start_from_now = true` (default) means only errors that occur **after** the
watchdog starts can trigger it, so a historical failure cannot power off a healthy
session.

Log tailing is **disabled by default**. The OpenCode server log records lifecycle
events, not provider API errors; when enabled, a line must be `level=ERROR` or
`level=WARN`, contain a provider-error marker, and mention the primary model.
This prevents unrelated text echoed into a log from triggering a shutdown.

---

## 3. Usage

```bash
# verify behaviour without touching anything
python3 scripts/ops/model_failover_watchdog.py selftest

# inspect state
python3 scripts/ops/model_failover_watchdog.py --config ~/.config/opencode/netguard-watchdog.json status

# write an immediate checkpoint
python3 scripts/ops/model_failover_watchdog.py --config ~/.config/opencode/netguard-watchdog.json checkpoint

# run as a detached supervisor
setsid nohup python3 scripts/ops/model_failover_watchdog.py \
  --config ~/.config/opencode/netguard-watchdog.json run \
  >> ~/.local/state/netguard-watchdog/watchdog.log 2>&1 < /dev/null &

# manual signal (useful for drills)
python3 scripts/ops/model_failover_watchdog.py --dry-run \
  --config ~/.config/opencode/netguard-watchdog.json feed \
  --kind quota --text "free usage limit reached" --model opencode/deepseek-v4.1-flash-free
```

### Configuration

Start from `scripts/ops/netguard-watchdog.example.json`, copy it to
`~/.config/opencode/netguard-watchdog.json`, and set `shutdown.enabled = true`
only if you accept that the machine will power off when the fallback model also
fails.

Important fields:

| Field | Meaning |
|---|---|
| `primary_model` / `fallback_models` / `additional_models` | Authorised free models. Only these can influence the state machine |
| `probe.command` | `null` uses `opencode run --standalone --model <model> --agent plan <prompt>` |
| `probe.agent` | Must stay `plan` (read-only) so a probe cannot modify the repository |
| `db.path` | OpenCode session database |
| `state_dir` | State, markers and checkpoints |
| `shutdown.commands` | Ordered poweroff commands, executed once |
| `shutdown.stop_opencode` | Runs `opencode service stop` before poweroff |

### Markers

| File (under `state_dir`) | Meaning |
|---|---|
| `MODEL_UNAVAILABLE` | Terminal state reached; shutdown sequence executed (or would have been, in dry-run) |
| `SHUTDOWN_STARTED` | Shutdown began; prevents a second sequence |
| `FALLBACK_ACTIVE` | Fallback model answered the probe; session continues |

---

## 4. Verification performed

* `selftest` → **23 checks passed**: successful fallback, failure → unavailable,
  duplicate-shutdown suppression, transient no-op, unclassified inert,
  injection-never-executed, checkpoint validity, database-signal tests (primary
  quota error triggers exactly one fallback; non-authorised model ignored;
  aborted/error-free messages ignored; transient error ignored), and
  log-chatter immunity.
* Live fallback probe verified once:
  `opencode run --standalone --model opencode/minimax-m3.1-flash-free --agent plan
  "Reply with exactly: NETGUARD_PROBE_OK"` → `NETGUARD_PROBE_OK`.
* The daemon ran for the duration of the sprint in `dry_run=False` with
  `shutdown.enabled = true`, checkpointing every 10 minutes, and remained in
  `IDLE` with no false trigger.

### Known limitation

`sudo -n` on this host requires a password, so the actual
`systemctl poweroff --no-block` invocation was **not** executed end to end. The
poweroff path is exercised in dry-run and by unit-level checks, and the host's
`CanPowerOff` capability was confirmed (`busctl … CanPowerOff → yes`). An operator
who needs a guaranteed unattended shutdown should grant passwordless
`systemctl poweroff` to the account, or run the watchdog under a systemd unit with
`CAP_SYS_BOOT`.
