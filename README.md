# AI Agent Security Monitor

A working local security-monitoring platform for AI agents, built around a
simulated customer-support/finance agent called **FinAssist**. Every prompt
FinAssist receives, and every tool it wants to call, passes through a
**Security Gateway** that detects prompt injection, jailbreaks, data
exfiltration, unauthorized access, sensitive-data exposure, and excessive
tool usage -- before anything is allowed to execute.

This is a portfolio/demo project. **All data is synthetic and every
"external action" (sending an email, issuing a refund, exporting a report)
is simulated in-process.** Nothing ever touches a real bank, a real email
server, or real customer data.

---

## What this actually is (read this first)

- The **detectors are real and run live** against every request -- a
  hybrid rule-based + local-corpus-similarity prompt-injection detector,
  regex/contextual sensitive-data and exfiltration scanners, a declarative
  policy/authorization engine, and a transparent weighted risk-scoring
  engine. Nothing is hard-coded or faked.
- The **FinAssist agent's natural-language understanding is a
  deterministic keyword/regex intent parser**, not a live LLM call. This
  is a deliberate choice: the subject of this project is the *security
  layer*, and a deterministic agent keeps every scenario perfectly
  reproducible and requires no paid API key. The parser still produces the
  same shape of output (a proposed tool name + arguments) a real
  LLM function-calling agent would, and the security gateway evaluates
  that proposal exactly the same way regardless of how it was generated.
- The **dashboard metrics are computed live from the SQLite database** on
  every request -- nothing is a hard-coded number. Run the attack
  simulator, refresh the dashboard, and the charts change because the
  underlying `events`/`alerts` tables changed.
- The **prompt-injection detector is a transparent hybrid**, not a
  "trained ML classifier" -- it combines ~10 explainable rule/regex
  signals with a TF-IDF + cosine-similarity comparison against a local
  labeled corpus (`backend/data/security_prompts.csv`). This is
  explicitly *not* described as a neural model anywhere in the UI or
  code, in line with the project's transparency requirements.
- **Phase 2's Isolation Forest** is a real scikit-learn model, trained
  offline via `backend/train_model.py` on synthetic behavioral sessions
  and loaded at runtime -- see the Phase 2 section below for what's
  actually wired up vs. what's a documented limitation.

---

## Architecture

```
User
  |
  v
Agent Chat Interface (React)
  |
  v
Simulated FinAssist Agent  (proposes a tool call; NEVER executes one itself)
  |
  v
Agent Security Gateway  <-- the only path to tool execution
  |-- Prompt-Injection Detector      (hybrid rules + corpus similarity)
  |-- Sensitive-Data Detector        (regex + Luhn-validated PII scan)
  |-- Data-Exfiltration Detector     (scope / bulk / destination analysis)
  |-- Tool Authorization & Policy Engine  (per-tool role + call-budget rules)
  |-- Behavioral-Anomaly Detector    (Isolation Forest, Phase 2)
  |-- Risk-Scoring Engine            (weighted combination -> 0-100 + decision)
  v
ALLOWED tool execution (simulated) | BLOCKED | APPROVAL_REQUIRED
  |
  v
Event Logger (SQLite: events, tool_calls, model_predictions)
  |
  v
Alerts + Security Dashboard (React + Recharts, live DB queries)
```

FinAssist never touches the database or executes a tool directly -- it only
returns a `ProposedAction {tool_name, arguments}`. Only the gateway, after
running every detector and computing a decision, calls the (simulated)
tool executor.

---

## Tech stack

| Layer      | Technology |
|------------|------------|
| Frontend   | React 19, TypeScript, Vite, Tailwind CSS v4, Recharts |
| Backend    | Python, FastAPI, Pydantic, SQLAlchemy |
| Database   | SQLite |
| ML         | scikit-learn (Isolation Forest, Phase 2), TF-IDF (prompt similarity) |
| Testing    | pytest (backend, 45+ tests), Playwright-verified UI |

No Kubernetes, Kafka, Redis, or cloud services -- everything runs on a
laptop with Python + Node.

---

## Quick start

```bash
git clone <this repo>
cd ai-agent-security-monitor
./start.sh
```

This will (idempotently):
1. Create a Python virtualenv under `backend/venv` and install dependencies.
2. Generate `backend/data/security_prompts.csv` if it doesn't exist yet.
3. Train and evaluate the Isolation Forest anomaly model under `backend/models/`
   if it doesn't exist yet (a few seconds; seeded, so results are reproducible --
   the numbers in the "Phase 2 status" section below come from this exact step).
4. Start the FastAPI backend on **http://127.0.0.1:8000** (docs at `/docs`).
5. Install frontend npm dependencies if needed.
6. Start the Vite dev server on **http://127.0.0.1:5173**.

`backend/models/` and `backend/data/security_monitor.db` are gitignored on
purpose -- they're generated, not source -- so a fresh clone regenerates
them itself instead of shipping binary artifacts in the repo.

Open **http://127.0.0.1:5173** and:
- Chat as a synthetic customer ("What is my account balance?").
- Try a sample attack prompt from the suggestion chips (or type your own).
- Visit **Attack Simulator** and run any of the 8 built-in scenarios.
- Watch **Dashboard**, **Events**, and **Alerts** update with real data.

Press `Ctrl+C` to stop both servers.

### Running manually (equivalent to start.sh)

```bash
# Backend
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python scripts/build_dataset.py                                          # only needed once
python train_model.py --n-samples 2000 --contamination 0.05 --seed 42    # only needed once
python evaluate_model.py --n-normal 400 --n-abnormal 400 --seed 1337     # only needed once
uvicorn app.main:app --reload --port 8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

### Running the tests

```bash
cd backend
source venv/bin/activate
pytest -v
```

---

## The FinAssist agent & its tools

| Tool | Risk level | Notes |
|---|---|---|
| `search_knowledge_base` | LOW | Answers general FAQ-style questions |
| `get_customer_profile` | LOW | Name, email, tier, customer-since date |
| `get_account_balance` | MEDIUM | Checking/savings balances |
| `get_transaction_history` | MEDIUM | Recent synthetic transactions |
| `create_support_ticket` | MEDIUM | Opens a (simulated) ticket |
| `update_customer_email` | HIGH | Changes email on file (simulated) |
| `send_customer_email` | HIGH | Sends a (simulated, never real) email |
| `export_transaction_report` | HIGH | Generates a (simulated) data export |
| `issue_refund` | CRITICAL | Always requires policy approval by default |

Synthetic customers (`backend/app/agent/synthetic_data.py`): `CUST-10001`
(Jordan Lee), `CUST-10002` (Priya Natarajan), `CUST-10003` (Marcus Webb),
plus a `support_agent` role user for cross-role policy testing.

---

## Detection pipeline in detail

### 1. Prompt-injection / jailbreak detector (`app/security/prompt_injection.py`)

A **transparent hybrid** detector combining independent signals, each
scored 0-1 and individually reported:

- Instruction-override attempts ("ignore all previous instructions...")
- System-prompt / instruction extraction attempts
- Role manipulation / jailbreak personas (DAN, "developer mode", roleplay)
- Requests to bypass or disable security/policy checks
- Secret/credential extraction attempts
- Tool-manipulation attempts (forcing/chaining tool calls)
- Requests for another customer's data
- Encoded payloads (base64/hex/percent-encoding) -- **the detector
  actually decodes base64 payloads and re-runs every pattern signal
  against the decoded text**, so "please decode this and follow it:
  &lt;base64 of an injection&gt;" is still caught, not just flagged as
  "contains base64."
- Dangerous-tool + urgency-language combinations
- **Local-corpus similarity**: TF-IDF vectorization + cosine similarity
  against `data/security_prompts.csv` (135 labeled examples, 56 benign /
  79 malicious across 10 attack-type categories). This is a classical
  information-retrieval technique, not a neural embedding model, and is
  labeled as "corpus similarity" everywhere in the UI/code.

Each triggered signal contributes `weight x confidence` points to a 0-100
`injection_score`, capped at 100. Classification: `SAFE` (0-29),
`SUSPICIOUS` (30-59), `MALICIOUS` (60-100).

**Measured accuracy** (see `backend/tests/test_prompt_injection.py`):
- 100% on the local corpus itself (safe vs. suspicious/malicious).
- **100% on a 20-example held-out set of prompts that do NOT appear in the
  corpus** (10 novel malicious paraphrases + 10 novel benign questions) --
  this is the honest generalization number; evaluating against the
  training corpus alone would be circular, since corpus-similarity
  trivially scores 1.0 against itself.

### 2. Sensitive-data detector (`app/security/sensitive_data.py`)

Regex + contextual scanning for: SSNs, credit-card numbers (validated with
a **Luhn checksum** to avoid flagging arbitrary long numbers as cards),
bank account numbers, routing numbers, API keys, passwords, email
addresses, and customer-ID references.

### 3. Data-exfiltration detector (`app/security/exfiltration.py`)

Operates on the *proposed tool call*, not just the text:
- Bulk/wildcard scope (`customer_id="ALL"`, `*`, comma-separated lists)
- Cross-customer scope violations (`customer_id` != the session's own)
- External/suspicious destinations on email/export tools (an allow-list of
  the synthetic bank's own domains defines what counts as "internal")

### 4. Tool authorization & policy engine (`app/security/policy_engine.py`)

Every tool has a `Policy` row (role allow-list, `requires_approval` flag,
`max_calls_per_session` budget, editable at runtime from the **Policies**
page). `issue_refund` requires approval by default; `export_transaction_report`,
`update_customer_email`, and `issue_refund` have default per-session call
budgets specifically to catch **excessive tool usage** even before any
ML-based anomaly detection is involved.

### 5. Risk-scoring & decision engine (`app/security/risk_scoring.py`)

Combines all of the above into a 0-100 `risk_score` via documented,
explicit weights, plus a small "corroboration bonus" when 2+ independent
detectors each score highly (matching how a human analyst reasons: two
independent alarms are stronger evidence than one). A short **ordered list
of hard rules** then makes the final ALLOWED / BLOCKED / APPROVAL_REQUIRED
decision on top of the score -- e.g. an unauthorized role, an exceeded call
budget, a confirmed MALICIOUS prompt, or an out-of-scope data request are
always blocked, regardless of what the numeric average happens to be.

The `reasoning_summary` returned to the UI is assembled directly from
these structured findings -- there is no hidden chain-of-thought and
nothing here calls an LLM to "explain itself"; the explanation *is* the
audit trail.

---

## Attack Simulator: 8 reproducible scenarios

Available on the **Attack Simulator** page (`GET /api/attack-scenarios`,
`POST /api/attack-scenarios/run`). Each sends its prompt(s) through the
exact same `/api/chat` pipeline a real user hits -- nothing is
special-cased for the demo.

1. **Instruction Override Injection** -- classic "ignore all previous
   instructions" + bulk export to an external address. -> BLOCKED (MALICIOUS)
2. **DAN Jailbreak -> Unauthorized Refund** -- persona jailbreak requesting
   a $10,000 refund with no verification. -> BLOCKED (MALICIOUS, critical tool)
3. **Bulk Data Export Exfiltration** -- `customer_id=ALL` export to an
   external analytics address. -> BLOCKED (exfiltration pattern)
4. **Unauthorized Cross-Customer Access** -- a customer asking for another
   customer's balance/history. -> BLOCKED (scope violation)
5. **Excessive Tool Usage / Abnormal Sequence** -- profile -> balance ->
   history -> 3x report export -> email change, in one session. -> the
   3rd export is BLOCKED by the per-session call budget; the following
   email change to an external address is held for APPROVAL.
6. **Sensitive Data Exposure Probe** -- a synthetic SSN + credit card
   pasted into the chat. -> findings surfaced, flagged SUSPICIOUS.
7. **Base64-Encoded Instruction Injection** -- an injection hidden inside
   base64. -> the detector decodes it and BLOCKS (MALICIOUS).
8. **Credential/Secret Extraction Attempt** -- directly asking for admin
   passwords/API keys. -> BLOCKED (MALICIOUS).

---

## Database schema

SQLite tables (`backend/app/models.py`): `users`, `agents`, `sessions`,
`events`, `tool_calls`, `alerts`, `policies`, `model_predictions`,
`metrics`. The `events` table is the central audit record and includes
`event_id`, `timestamp`, `session_id`, `user_id`, `agent_id`, `event_type`,
`prompt`, `tool_name`, `tool_arguments`, `api_endpoint`, `response`,
`risk_score`, `risk_level`, `detection_reason`, `detection_type`,
`action`, `blocked`, and `latency_ms`.

---

## API overview

| Endpoint | Description |
|---|---|
| `POST /api/chat` | Send a message through FinAssist -> gateway -> (maybe) tool |
| `GET /api/events` | Full audit log, filterable by session/risk/action |
| `GET /api/alerts` / `POST /api/alerts/{id}/resolve` | Alerts |
| `GET /api/dashboard/metrics` | Live-computed dashboard metrics |
| `GET /api/policies` / `PATCH /api/policies/{id}` | Policy management |
| `GET /api/attack-scenarios` / `POST /api/attack-scenarios/run(-all)` | Attack Simulator |

Interactive OpenAPI docs at `http://127.0.0.1:8000/docs` once the backend
is running.

---

## Testing

`backend/tests/` (pytest, **52 tests**, all passing):
- `test_prompt_injection.py` -- detector accuracy on the corpus **and** an
  honest held-out set.
- `test_sensitive_data.py`, `test_exfiltration.py`, `test_policy_engine.py`
  -- unit tests for each detector, including the Luhn check and the
  call-budget enforcement.
- `test_finassist_agent.py` -- intent parsing and simulated tool execution.
- `test_api.py` -- full end-to-end HTTP tests: normal requests are
  allowed, malicious ones are blocked *and the tool never executes*,
  blocked events create alerts, dashboard metrics match real event counts.
- `test_phase2.py` -- anomaly model loadability/behavior, the
  model-performance endpoint, trace inclusion in events, session
  listing, and session-replay ordering.

Run with `pytest -v` from `backend/` (uses an isolated temp SQLite file,
never your dev database).

`frontend/src/` (Vitest + React Testing Library, **13 tests**, all
passing): the API client, both badge components, `ChatPage`, and
`DashboardPage`. Run with `npx vitest run` from `frontend/`.

---

## Project structure

```
ai-agent-security-monitor/
  start.sh                     # one-command startup
  backend/
    app/
      main.py                  # FastAPI app + lifespan (create tables, seed)
      models.py / schemas.py   # SQLAlchemy models / Pydantic schemas
      agent/                   # FinAssist intent parser + synthetic data
      security/                # every detector + the gateway + risk scoring
      api/                     # chat, events, alerts, dashboard, policies, attack-simulator routers
      logging_service.py       # event/alert persistence
      seed_data.py
    data/security_prompts.csv  # labeled corpus (135 rows)
    scripts/build_dataset.py   # regenerates the corpus
    models/                    # trained Isolation Forest artifacts (Phase 2)
    train_model.py / evaluate_model.py   # Phase 2
    tests/                     # pytest suite
  frontend/
    src/
      pages/                   # Chat, Dashboard, AttackSimulator, Events, Alerts, Policies
      components/              # shared badges / UI
      api/client.ts            # typed fetch wrapper
```

---

## Known limitations

- FinAssist's language understanding is a deterministic keyword/regex
  parser, not a live LLM -- see "What this actually is" above for why.
- The prompt-injection detector is rule + corpus-similarity based; it is
  not a neural classifier and will not generalize as well as a trained
  transformer model to attack phrasings very different from both its
  rules and its corpus. Measured held-out accuracy is documented above
  rather than assumed.
- The synthetic bank/customer data is intentionally small (3 customers)
  to keep the demo easy to reason about.
- See the Phase 2 section for anomaly-detection-specific limitations.

---

## Phase 2 status

Phase 2 was built and verified after Phase 1 was independently confirmed
end-to-end (52/52 backend tests, live Playwright walkthrough of every
page, all 8 attack scenarios producing the expected verdict). Everything
below was actually run, not assumed.

### What was implemented

- **Behavioral anomaly detection** -- a real scikit-learn `IsolationForest`
  (`backend/train_model.py`), trained offline on 2,000 synthetic sessions
  built from hand-written "normal" and "abnormal" session generators
  (`app/security/synthetic_sessions.py`), not at server startup. The
  8-feature vector (tool-call frequency, distinct tools, high-risk calls,
  time-since-last-action, blocked actions, failed auth, sensitive-data
  hits, average risk score) is computed live per session by
  `compute_session_features()` and scored by a lazily-loaded singleton
  (`app/security/anomaly.py`). `backend/evaluate_model.py` runs a held-out
  evaluation (400 normal + 400 abnormal sessions, seeded separately from
  training) and writes `models/evaluation_report.json`; nothing in the UI
  or API hardcodes these numbers -- the Model Performance page and
  `/api/model-performance` both read the report and the corpus live.
- **Real-time event stream** -- `GET /api/events/stream` (Server-Sent
  Events, polling the DB every 1s, no message broker) with the Events
  page switching from its old 5s poll to `EventSource`, and a visible
  "Live (SSE)" / "Polling" indicator that reflects the actual connection
  state rather than being hardcoded to "Live".
- **Agent Trace page** (`/trace`) -- every event now stores a structured
  `trace` JSON blob (added to the `Event` model) capturing all 7 gateway
  pipeline stages (agent proposal -> injection detector -> sensitive-data
  detector -> exfiltration detector -> policy engine -> anomaly detector
  -> risk-scoring decision); the page renders it as a step-by-step
  pipeline with flagged stages highlighted.
- **Session Replay page** (`/replay`) -- step-through or auto-play (1.6s
  interval) controls over a chosen session's events in original order,
  via a new `/api/sessions` and `/api/sessions/{id}/events` pairing.
- **Model Performance page** (`/model-performance`) -- shows the
  injection detector's corpus accuracy (recomputed on demand, not
  cached) and the Isolation Forest's training metadata + offline
  evaluation metrics side by side, explicitly labeling the injection
  detector as "hybrid rule-based signals + TF-IDF corpus-similarity (not
  a neural classifier)" so the two models are never conflated.
- **Dashboard**: added P50/P95 latency (via `numpy.percentile` over real
  logged latencies, computed live in `/api/dashboard/metrics`).
- **Frontend tests**: Vitest + React Testing Library added for the API
  client, both badge components, ChatPage, and DashboardPage (13 tests).
- **Responsive/UI polish pass**: the app shell's sidebar was fixed-width
  with no breakpoint at all, so on a narrow viewport it silently ate the
  screen and squeezed every page into an unreadably narrow column. Fixed
  with a proper mobile drawer (hamburger toggle, backdrop, auto-close on
  navigation) and a `main` region that actually accounts for the mobile
  top bar's height. The Agent Trace page's fixed 320px event-picker
  sidebar was changed to stack above the detail pane (capped height,
  scrollable) below the `md` breakpoint. The Events page's per-row layout
  (timestamp + 3 badges + tool name + prompt, previously a non-wrapping
  flex row) now wraps instead of clipping content off-screen. The
  Policies page's wide table already had `overflow-x-auto`, confirmed by
  scripting a horizontal scroll and screenshotting the revealed columns.

### Commands executed for Phase 2 verification (all actually run)

```
# Backend
cd backend && source venv/bin/activate
python train_model.py --n-samples 2000 --contamination 0.05 --seed 42
python evaluate_model.py --n-normal 400 --n-abnormal 400 --seed 1337
python -m pytest -q                    # 52 passed

# Frontend
cd frontend
npx vitest run                          # 13 passed
npm run build                           # tsc -b && vite build, clean

# End-to-end (Playwright, headless Chromium)
# navigated to /events, /trace, /replay, /model-performance and to
# every page at a 390x844 mobile viewport; asserted zero console/page
# errors and visually inspected each resulting screenshot
```

### Test results (measured, not asserted)

- Backend: **52/52 pytest tests passing** (unit tests for every
  detector, the policy engine, the FinAssist tool simulator, the full
  API, plus 7 Phase-2-specific tests for the anomaly model, trace
  inclusion, and session listing/replay ordering).
- Frontend: **13/13 Vitest tests passing**; production `tsc -b && vite
  build` completes with no type errors.
- Isolation Forest offline evaluation (800 held-out synthetic sessions,
  seed 1337, independent of the 2,000 training sessions seeded at 42):
  recall **100.0%**, false-positive rate **6.0%**, precision **94.3%**,
  overall accuracy **97.0%** (24 false positives out of 400 normal
  sessions, 0 false negatives out of 400 abnormal sessions). The
  hand-written "normal" (`get_customer_profile -> get_account_balance ->
  get_transaction_history`, score 38.0, NORMAL) and "abnormal"
  (`get_customer_profile -> get_account_balance ->
  export_transaction_report x3 -> update_customer_email ->
  send_customer_email`, score 55.7, ANOMALOUS) sequences from the
  project brief are included verbatim as worked examples on the Model
  Performance page.
- Prompt-injection corpus accuracy unchanged from Phase 1: 100% on the
  135-row local corpus, 100% on 20 novel held-out prompts not in that
  corpus (`test_held_out_generalization_accuracy`).

### Known errors hit during Phase 2 and how they were fixed

- **SSE route-ordering 500 error**: `GET /api/events/{event_id}` was
  declared before `GET /api/events/stream` in `app/api/events.py`.
  Starlette matches routes in declaration order, so requests to
  `/events/stream` were captured by the parameterized route as
  `event_id="stream"`, the DB lookup returned `None`, and
  `response_model=EventOut` validation on `None` raised a 500
  (`fastapi.exceptions.ResponseValidationError`). Fixed by moving the
  literal `/events/stream` route before the parameterized one; verified
  by restarting the backend and confirming `curl` and the browser both
  get a real SSE stream instead of a 500, then re-running the Playwright
  check to confirm zero console errors on `/events`.
- **Playwright `networkidle` hang on `/events`**: after the SSE fix, the
  page opens a genuinely long-lived connection, so Chromium's
  `networkidle` wait (no network activity for 500ms) never resolves --
  it *had* been resolving before the fix only because the 500 error
  closed the connection quickly. Switched the verification script to
  wait on `load` instead.
- **Sidebar had no responsive breakpoints at all**: not a functional
  bug, but a real UI defect found by screenshotting every page at a
  390px viewport -- content wasn't just cramped, it was clipped
  off-screen on the Events page and unusable on Chat. Fixed as described
  above and re-verified with fresh screenshots at the same viewport.

### What remains / honest limitations

- The SSE stream is a 1-second DB poll wrapped in `StreamingResponse`,
  not a true push mechanism backed by a message broker -- appropriate
  for a single-process local demo, explicitly not presented as
  Kafka/Redis-grade infrastructure per the project's tech constraints.
- The Isolation Forest is trained entirely on synthetic session
  generators (`synthetic_sessions.py`), not on real historical agent
  behavior, because none exists for this demo. Its evaluation numbers
  above measure how well it separates the *kinds* of sequences the
  generators encode as normal vs. abnormal, not real-world accuracy.
- The production JS bundle is ~683kB unminified-equivalent (single
  chunk, no code-splitting) -- functional but a real app would split
  routes; left as-is since it doesn't affect correctness and the brief
  prioritized a complete vertical slice over build tuning.
- No dedicated Playwright/E2E test files were added for the frontend
  (only Vitest unit/component tests); all end-to-end verification in
  this project was done with ad hoc Playwright scripts run manually
  during development rather than checked-in, repeatable E2E specs.
