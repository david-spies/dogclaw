# DogClaw — Development Guide

> Complete reference for architecture, internals, contribution workflow, and extending the platform.

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Architecture Deep Dive](#architecture-deep-dive)
3. [Backend Internals](#backend-internals)
4. [Data Pipeline](#data-pipeline)
5. [Rules Engine](#rules-engine)
6. [AI Agent System](#ai-agent-system)
7. [WebSocket Protocol](#websocket-protocol)
8. [Database Schema](#database-schema)
9. [Adding a New Integration](#adding-a-new-integration)
10. [Writing Detection Rules](#writing-detection-rules)
11. [Testing](#testing)
12. [Performance Tuning](#performance-tuning)
13. [Security Hardening](#security-hardening)
14. [Contributing](#contributing)

---

## Project Structure

```
dogclaw/
├── server.py                  # Main FastAPI backend — entry point
├── requirements.txt           # Python dependencies
├── dogclaw.html               # Single-file browser UI
├── config/
│   ├── settings.yaml          # Global configuration
│   ├── integrations/          # Per-integration YAML configs
│   │   ├── aws.yaml
│   │   ├── kubernetes.yaml
│   │   ├── github.yaml
│   │   └── ...
│   └── rules/                 # Detection rule definitions
│       ├── iam.yaml
│       ├── network.yaml
│       ├── container.yaml
│       └── sigma/             # Imported SIGMA rules
├── core/
│   ├── ingest/
│   │   ├── __init__.py
│   │   ├── metrics.py         # StatsD / Prometheus scrape ingest
│   │   ├── logs.py            # Syslog / Fluent Bit / JSON log ingest
│   │   ├── traces.py          # OpenTelemetry trace receiver
│   │   └── events.py          # Security event normalization
│   ├── pipeline/
│   │   ├── normalizer.py      # ECS field normalization
│   │   ├── enricher.py        # GeoIP, threat intel, asset lookup
│   │   ├── correlator.py      # Multi-event correlation engine
│   │   └── deduplicator.py    # Alert deduplication / flap prevention
│   ├── rules/
│   │   ├── engine.py          # Rule evaluation loop
│   │   ├── sigma.py           # SIGMA rule parser & compiler
│   │   └── loader.py          # Hot-reload rule YAML files
│   ├── ai/
│   │   ├── agent.py           # DogClaw AI orchestrator
│   │   ├── watchclaw.py       # Anomaly detection (statistical + ML)
│   │   ├── pr_review.py       # GitHub PR security analysis
│   │   └── attack_path.py     # Attack path graph reconstruction
│   ├── storage/
│   │   ├── db.py              # SQLAlchemy ORM + TimescaleDB helpers
│   │   ├── models.py          # ORM model definitions
│   │   └── queries.py         # Common query patterns
│   ├── response/
│   │   ├── actions.py         # Response action executors
│   │   ├── playbooks.py       # Automated playbook runner
│   │   └── notifications.py   # Slack, PagerDuty, email dispatch
│   └── ws/
│       ├── hub.py             # WebSocket connection manager
│       └── broadcaster.py     # Fan-out to subscribed clients
├── integrations/
│   ├── aws/
│   │   ├── cloudtrail.py
│   │   ├── guardduty.py
│   │   └── cloudwatch.py
│   ├── kubernetes/
│   │   ├── events.py
│   │   ├── metrics.py
│   │   └── runtime.py
│   ├── github/
│   │   └── webhooks.py
│   ├── okta/
│   │   └── system_log.py
│   └── ...
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
└── scripts/
    ├── install_agent.sh       # DogClaw agent bootstrap
    ├── migrate_db.py          # Database migrations
    └── seed_rules.py          # Load default rule set
```

---

## Architecture Deep Dive

### Event Flow

Every piece of data entering DogClaw follows this path:

```
External Source
      │
      ▼
  [Ingest Layer]          Normalizes to ECS (Elastic Common Schema)
      │                   Assigns source type, timestamps, host context
      ▼
  [Enrichment]            Adds GeoIP, threat intel lookups, asset metadata,
      │                   user context, cloud account mapping
      ▼
  [Correlation Engine]    Matches multi-event patterns across time windows
      │                   Builds event chains (e.g., login → policy change → exfil)
      ▼
  [Rules Engine]          Evaluates all active detection rules
      │                   Emits signals with severity, MITRE tags, confidence
      ▼
  [Deduplication]         Suppresses duplicate alerts within flap window
      │                   Groups related alerts into investigations
      ▼
  [Storage]               Persists events, signals, metrics to TimescaleDB
      │
      ▼
  [WebSocket Broadcast]   Pushes real-time updates to connected browser clients
      │
      ▼
  [AI Analysis]           WatchClaw scores anomaly probability
      │                   DogClaw Agent pre-triages critical signals
      ▼
  [Response Engine]       Executes automated playbooks if configured
      │                   Sends notifications to Slack / PagerDuty / email
```

### Component Responsibilities

**FastAPI Application (`server.py`)** — HTTP REST API and WebSocket server. Handles authentication, routing, static file serving, and health checks. Single process; uses asyncio throughout for non-blocking I/O.

**Ingest Layer (`core/ingest/`)** — Protocol-specific receivers. Each module handles one input type (StatsD UDP, syslog TCP/UDP, OTLP gRPC, JSON HTTP POST, WebHook). All output a normalized `Event` object.

**Correlation Engine (`core/pipeline/correlator.py`)** — Maintains a sliding time-window index of recent events keyed by entity (IP, user, host, container). When a new event arrives it queries the index for co-occurring events and builds chains that match registered correlation patterns.

**Rules Engine (`core/rules/engine.py`)** — Evaluates each incoming normalized event against all loaded rules. Rules are expressed as YAML with CEL (Common Expression Language) conditions. Supports threshold rules, sequence rules, and statistical anomaly rules. Supports hot-reload without restart.

**WatchClaw (`core/ai/watchclaw.py`)** — Runs periodic baseline models for each metric series and event rate series. Uses seasonal decomposition + Z-score for numeric metrics and DBSCAN clustering for behavioral patterns. Emits anomaly signals when observations diverge from baseline.

**DogClaw AI Agent (`core/ai/agent.py`)** — Orchestrates calls to an LLM (configurable: local Ollama, OpenAI, Anthropic) for natural language investigation, triage summaries, and PR review. Injects relevant observability context into prompts automatically.

**Response Engine (`core/response/`)** — Executes discrete response actions (revoke IAM key, isolate container, block IP at WAF) and chains them into playbooks triggered by signal conditions.

---

## Backend Internals

### FastAPI App Initialization (`server.py`)

The backend starts with lifespan context management:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await db.connect()
    await rules_engine.load_rules()
    await integrations_manager.start_all()
    await ws_hub.start()
    asyncio.create_task(watchclaw.run_loop())
    yield
    # Shutdown
    await integrations_manager.stop_all()
    await db.disconnect()
```

### Authentication

DogClaw uses JWT tokens by default. All API routes except `/health` and `/ws` require a valid Bearer token. Token signing key is set in `config/settings.yaml`. For single-user local deployments, authentication can be disabled.

```yaml
# config/settings.yaml
auth:
  enabled: true
  jwt_secret: "change-me-in-production"
  token_expiry_hours: 24
  single_user_mode: false
```

### Rate Limiting

Ingest endpoints are rate-limited per source IP to prevent accidental flooding. The default is 100,000 events/minute per source, configurable per integration.

---

## Data Pipeline

### Normalization

All events are normalized to a subset of Elastic Common Schema (ECS). Key fields:

| Field | Type | Description |
|-------|------|-------------|
| `@timestamp` | ISO8601 | Event time |
| `event.kind` | string | `event`, `alert`, `metric`, `state` |
| `event.category` | string[] | `authentication`, `network`, `process`, `file`, `iam` |
| `event.action` | string | Specific action (e.g., `user-login`, `policy-attached`) |
| `event.outcome` | string | `success`, `failure`, `unknown` |
| `source.ip` | IP | Originating IP |
| `source.geo` | object | GeoIP result |
| `user.name` | string | Acting principal |
| `host.name` | string | Target host |
| `cloud.provider` | string | `aws`, `gcp`, `azure` |
| `threat.indicator` | object | Matched threat intel |
| `rule.name` | string | Triggering rule (if alert) |
| `rule.reference` | string | MITRE ATT&CK ID |

### Enrichment Pipeline

Each event passes through the enrichment chain in order:

1. **GeoIP** — MaxMind GeoLite2 database lookup on `source.ip` and `destination.ip`
2. **Threat Intelligence** — Check against loaded IOC feeds (Abuse IPDB, AlienVault OTX, custom STIX feeds)
3. **Asset Context** — Look up host metadata (owner, environment, criticality) from asset inventory
4. **Identity Context** — Resolve user identity details from identity provider cache
5. **Cloud Context** — Map cloud account IDs to human-readable account names/environments
6. **Vulnerability Context** — Tag events involving known-vulnerable software versions

---

## Rules Engine

### Rule YAML Format

```yaml
# config/rules/iam_escalation.yaml
id: dogclaw-iam-001
name: "High-Privilege IAM Policy Attached from Suspicious Source"
severity: critical
enabled: true
mitre:
  tactic: "Privilege Escalation"
  technique: "T1098"
  subtechnique: "T1098.001"
description: >
  Detects when AdministratorAccess or similarly high-privilege IAM policies
  are attached to any principal from an IP flagged as suspicious.

# Match conditions (CEL expressions)
conditions:
  - field: event.action
    op: eq
    value: "AttachUserPolicy"
  - field: aws.policy_arn
    op: contains
    value: "AdministratorAccess"
  - field: threat.indicator.type
    op: in
    value: ["tor-exit", "residential-proxy", "known-bad-ip"]

# Optional: correlation — this rule fires only if these events
# also occurred within the time window for the same principal
correlate:
  window_minutes: 30
  min_match: 1
  any_of:
    - event.action: "CreateAccessKey"
    - event.action: "CreateLoginProfile"

# Actions on match
response:
  notify:
    - slack: "#security-alerts"
    - pagerduty: severity_critical
  auto_actions:
    - type: create_investigation
      title: "IAM Privilege Escalation — {user.name}"
```

### SIGMA Rule Import

```bash
python scripts/seed_rules.py --sigma ./rules/sigma/
```

SIGMA rules are automatically compiled to DogClaw's native format. Field mappings for CloudTrail, Syslog, and Windows Event Log are pre-configured.

---

## AI Agent System

### Context Assembly

When a user asks DogClaw AI a question, the agent automatically assembles context:

```python
async def build_context(query: str, investigation_id: str = None) -> dict:
    ctx = {}
    ctx["recent_alerts"] = await db.get_recent_alerts(limit=20)
    ctx["active_investigations"] = await db.get_open_investigations()
    ctx["host_health"] = await metrics_store.get_host_summary()
    if investigation_id:
        ctx["investigation"] = await db.get_investigation_detail(investigation_id)
        ctx["related_events"] = await db.get_correlated_events(investigation_id)
    return ctx
```

### LLM Configuration

```yaml
# config/settings.yaml
ai:
  provider: "anthropic"        # anthropic | openai | ollama | disabled
  model: "claude-sonnet-4-20250514"
  api_key: "${ANTHROPIC_API_KEY}"
  max_tokens: 2048
  temperature: 0.1             # Low temp for security analysis
  context_limit_events: 50     # Max events injected into context
  pr_review:
    chunk_size_lines: 200      # Analyze PRs in 200-line chunks
    max_chunks: 20
```

### WatchClaw Anomaly Detection

WatchClaw runs two detection strategies in parallel:

**Metric Anomaly** — For each numeric time series (CPU, error rate, request rate, etc.), maintains a 7-day rolling baseline using seasonal decomposition. Flags values beyond 3σ from the expected range.

**Behavioral Anomaly** — Builds baseline behavior profiles per entity (user, service account, container) across 30-day windows. Uses DBSCAN to detect unusual patterns in event sequences (time-of-day, geographic patterns, API call sequences).

---

## WebSocket Protocol

The browser connects to `ws://localhost:8000/ws?token=<jwt>`.

### Message Types (Server → Client)

```json
// New threat event
{"type": "threat_event", "payload": {...event...}}

// Metric update
{"type": "metric_update", "payload": {"host": "app-01", "metrics": {...}}}

// Investigation update
{"type": "investigation_update", "payload": {"id": "INV-...", "status": "open"}}

// AI agent response
{"type": "ai_response", "payload": {"conversation_id": "...", "message": "..."}}

// System health
{"type": "system_health", "payload": {"agents_online": 248, "events_per_sec": 14200}}
```

### Message Types (Client → Server)

```json
// Subscribe to a specific feed
{"type": "subscribe", "feed": "threats", "filters": {"severity": ["critical", "high"]}}

// AI query
{"type": "ai_query", "conversation_id": "...", "message": "What changed in the last hour?"}

// Execute response action
{"type": "response_action", "action": "revoke_credentials", "target": "svc-deploy-prod"}
```

---

## Database Schema

DogClaw uses SQLite by default for single-machine deployments, with optional TimescaleDB for production scale.

### Core Tables

```sql
-- Normalized security/observability events
CREATE TABLE events (
    id          BIGSERIAL PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL,
    kind        VARCHAR(32),
    category    TEXT[],
    action      VARCHAR(128),
    outcome     VARCHAR(32),
    source_ip   INET,
    user_name   VARCHAR(256),
    host_name   VARCHAR(256),
    severity    VARCHAR(16),
    raw         JSONB,
    enriched    JSONB,
    INDEX (timestamp DESC),
    INDEX (source_ip),
    INDEX (user_name)
);

-- SIEM signals (rule matches)
CREATE TABLE signals (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL,
    rule_id         VARCHAR(64),
    rule_name       TEXT,
    severity        VARCHAR(16),
    mitre_technique VARCHAR(32),
    entity          VARCHAR(256),
    event_ids       BIGINT[],
    investigation_id BIGINT REFERENCES investigations(id),
    status          VARCHAR(32) DEFAULT 'open'
);

-- Investigation cases
CREATE TABLE investigations (
    id          BIGSERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW(),
    title       TEXT,
    severity    VARCHAR(16),
    status      VARCHAR(32) DEFAULT 'open',
    assignee    VARCHAR(128),
    timeline    JSONB DEFAULT '[]',
    ai_summary  TEXT,
    tags        TEXT[]
);

-- Time-series metrics (hypertable if TimescaleDB)
CREATE TABLE metrics (
    time        TIMESTAMPTZ NOT NULL,
    host        VARCHAR(256),
    metric_name VARCHAR(128),
    value       DOUBLE PRECISION,
    tags        JSONB
);
```

---

## Adding a New Integration

1. Create `integrations/<name>/<name>.py`
2. Implement the `BaseIntegration` interface:

```python
from core.ingest.base import BaseIntegration, Event

class MyIntegration(BaseIntegration):
    name = "my-service"

    async def start(self):
        """Start polling or listening."""
        pass

    async def stop(self):
        """Clean up."""
        pass

    def normalize(self, raw: dict) -> Event:
        """Convert raw payload to normalized Event."""
        return Event(
            timestamp=raw["time"],
            action=raw["eventName"],
            source_ip=raw.get("sourceIPAddress"),
            raw=raw
        )
```

3. Register in `config/integrations/my-service.yaml`:

```yaml
name: my-service
enabled: true
type: webhook          # webhook | polling | streaming
endpoint: /ingest/my-service
poll_interval_seconds: 60
auth:
  type: bearer_token
  token: "${MY_SERVICE_TOKEN}"
```

4. Add field mappings to `core/pipeline/normalizer.py`
5. Add unit tests in `tests/unit/integrations/test_my_service.py`

---

## Writing Detection Rules

Rules are hot-reloaded from `config/rules/`. Create a YAML file, and the rules engine picks it up within 5 seconds.

See the [Rules Engine section](#rules-engine) for the full YAML schema. Key tips:

- Use `correlate` to reduce false positives by requiring multiple supporting events
- Set `auto_actions` only for rules with very high confidence
- Tag every rule with a MITRE ATT&CK technique for investigation context
- Use `severity: info` for rules that should feed WatchClaw context without paging anyone

---

## Testing

```bash
# Unit tests
pytest tests/unit/ -v

# Integration tests (requires Docker for dependencies)
docker-compose -f tests/docker-compose.yml up -d
pytest tests/integration/ -v

# Load test the ingest API
locust -f tests/load/locustfile.py --host=http://localhost:8000

# Rule evaluation tests
pytest tests/unit/rules/ -v --tb=short
```

### Fixture Events

`tests/fixtures/` contains sample events in ECS format for each integration. Use these to test rule conditions without live infrastructure.

---

## Performance Tuning

### Event Throughput

Default configuration handles ~50,000 events/second on a 4-core machine. For higher throughput:

```yaml
# config/settings.yaml
pipeline:
  ingest_workers: 8          # Parallel ingest coroutines
  enrichment_batch_size: 500 # Events per enrichment batch
  rules_eval_workers: 4      # Parallel rule evaluation threads
  db_write_batch_size: 1000  # Events per DB write batch
  db_write_interval_ms: 500  # Max time before flushing write batch
```

### Memory Management

The correlation engine keeps a rolling window of recent events in memory. Tune the window to balance detection quality vs. memory usage:

```yaml
correlation:
  window_minutes: 30         # Default: 30-minute correlation window
  max_entities: 100000       # Max unique entities tracked in memory
  entity_ttl_minutes: 60     # Evict inactive entities after 60 minutes
```

---

## Security Hardening

For production single-machine deployments:

1. **Enable TLS** — Configure `ssl_certfile` and `ssl_keyfile` in `settings.yaml`
2. **Change JWT secret** — Use a 256-bit random value
3. **Restrict network** — Bind to `127.0.0.1` and use a reverse proxy (nginx) for external access
4. **Rotate API keys** — Store all integration secrets in environment variables or a secrets manager
5. **Enable audit logging** — All API actions are logged to `audit.log` when `audit.enabled: true`
6. **Database encryption** — Enable SQLite WAL mode and file-level encryption for the data directory

---

## Contributing

1. Fork the repository and create a feature branch
2. Follow the project coding style (Black, isort, mypy strict)
3. Add tests for new functionality (target >80% coverage)
4. Update relevant documentation files
5. Open a Pull Request — DogClaw AI will automatically scan it for security issues

### Commit Convention

```
feat(rules): add SIGMA rule import for Windows Event Log
fix(ingest): handle malformed syslog timestamps
docs(quickstart): add GCP integration steps
test(correlation): add fixtures for IAM escalation chain
```
