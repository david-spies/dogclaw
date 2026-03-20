# DogClaw — Technology Stack Reference

> Complete inventory of every technology, library, and protocol used in DogClaw, with rationale for each choice.

---

## Overview

DogClaw is designed around three constraints: **runs from a single machine**, **serves the UI from a browser**, and **stays lightweight enough to not require Kubernetes to run itself**. Every technology choice reflects these constraints.

---

## Backend

### Runtime & Framework

| Technology | Version | Role | Why |
|---|---|---|---|
| **Python** | 3.11+ | Primary backend language | Excellent async support, rich data/ML ecosystem, fast prototyping |
| **FastAPI** | 0.111+ | HTTP & WebSocket server | Async-native, auto OpenAPI docs, excellent performance for Python |
| **Uvicorn** | 0.30+ | ASGI server | Low-overhead, asyncio-native, production-grade for single-machine |
| **asyncio** | stdlib | Concurrency primitive | Non-blocking I/O throughout; no threads needed for I/O-bound work |

### Data Storage

| Technology | Version | Role | Why |
|---|---|---|---|
| **SQLite** | 3.45+ | Default embedded DB | Zero external dependencies, WAL mode handles concurrent reads/writes well up to ~100k events/day |
| **TimescaleDB** | 2.x (optional) | Production time-series DB | PostgreSQL-compatible, hypertable compression, automatic data retention policies |
| **SQLAlchemy** | 2.x | ORM | Async support, works with both SQLite and TimescaleDB via same model definitions |
| **Redis** | 7.x (optional) | In-memory cache & pub/sub | Correlation window cache, WebSocket fan-out for multi-worker deployments |

### Message & Event Pipeline

| Technology | Version | Role | Why |
|---|---|---|---|
| **asyncio Queues** | stdlib | Internal event queues | Zero dependencies, sufficient for single-machine throughput |
| **Pydantic** | 2.x | Data validation & models | Fast validation of incoming events, auto-generates JSON schemas |
| **structlog** | 24.x | Structured logging | JSON log output, context binding, integrates with the log ingest pipeline itself |

### AI & Machine Learning

| Technology | Version | Role | Why |
|---|---|---|---|
| **Anthropic SDK** | 0.28+ | DogClaw AI agent LLM | Claude models for investigation, PR review, triage summarization |
| **OpenAI SDK** | 1.x (optional) | Alternative LLM provider | Switchable via config |
| **Ollama** | latest (optional) | Local LLM inference | Air-gapped environments; run models locally |
| **scikit-learn** | 1.5+ | WatchClaw anomaly detection | IsolationForest, DBSCAN for behavioral clustering |
| **statsmodels** | 0.14+ | Time-series baselines | Seasonal decomposition for metric anomaly detection |
| **numpy / pandas** | latest | Numerical processing | Feature engineering for ML models, metric aggregation |

### Security & Network

| Technology | Version | Role | Why |
|---|---|---|---|
| **python-jose** | 3.x | JWT auth | Industry-standard token validation |
| **passlib** | 1.7+ | Password hashing | bcrypt for user credential storage |
| **geoip2** | 4.x | GeoIP enrichment | MaxMind GeoLite2 database lookups |
| **aiohttp** | 3.x | Async HTTP client | Polling integrations (CloudTrail, Okta, GitHub) |
| **websockets** | 12.x | WebSocket client lib | Outbound WebSocket connections to streaming sources |
| **cryptography** | 42.x | Encryption primitives | TLS cert handling, secret encryption at rest |

### Parsing & Protocol Support

| Technology | Version | Role | Why |
|---|---|---|---|
| **opentelemetry-sdk** | 1.x | OTLP trace receiver | Vendor-neutral trace and metric ingest from any OTEL-instrumented service |
| **sigma-cli** | 0.x | SIGMA rule import | Parse and compile community detection rules |
| **PyYAML** | 6.x | Rule & config parsing | Human-readable rule and integration definitions |
| **python-dateutil** | 2.x | Timestamp normalization | Handle dozens of timestamp formats from different log sources |
| **maxminddb** | 2.x | GeoIP DB reader | Offline IP-to-geo lookups without external API calls |

---

## Frontend

### UI Architecture

The entire UI is a **single HTML file** (`dogclaw.html`) with no build step, no npm, and no framework dependencies fetched at runtime. This is an intentional architectural choice — the UI loads instantly from the local server and works offline.

| Technology | Role | Why |
|---|---|---|
| **Vanilla JavaScript (ES2022)** | UI logic, WebSocket client, chart rendering | Zero dependencies, instant load, no build pipeline |
| **Canvas API** | Sparklines, network topology map, threat activity chart | Native browser API, hardware-accelerated, no library needed for simple charts |
| **CSS Custom Properties** | Theming system | Runtime theme switching without JS, consistent design tokens |
| **CSS Grid & Flexbox** | Layout | Modern, performant layout without any CSS framework |
| **WebSocket API** | Real-time event streaming from backend | Native browser API, bidirectional, low overhead |
| **Google Fonts** (optional) | Typography — Syne, JetBrains Mono, Space Mono | Loaded from CDN at startup; falls back gracefully if offline |

### Design System

| Choice | Value |
|---|---|
| Primary font | Syne (display headings) |
| Monospace font | JetBrains Mono (code, data, UI labels) |
| UI font | Space Mono (navigation, badges) |
| Color system | Dark theme with CSS custom properties |
| Primary accent | `#00e5ff` (cyan) |
| Danger | `#ef4444` (red) |
| Warning | `#f97316` (orange) |
| Success | `#10b981` (green) |

---

## Protocols & Data Formats

### Ingest Protocols

| Protocol | Transport | Used For |
|---|---|---|
| **StatsD** | UDP 8125 | Application metrics (counters, gauges, timers) |
| **Prometheus Remote Write** | HTTP POST | Infrastructure metrics from node_exporter, kube-state-metrics |
| **OTLP** | gRPC 4317 / HTTP 4318 | OpenTelemetry traces, metrics, logs |
| **Syslog** | UDP/TCP 514 | Host OS logs, network device logs |
| **Fluent Bit / Fluentd** | HTTP POST | Container log forwarding |
| **HTTP Webhook** | HTTPS POST | GitHub, AWS, Okta, PagerDuty event push |
| **WebSocket** | WSS | Real-time streaming from compatible sources |
| **Kafka Consumer** | TCP | High-volume log and event streams |

### Data Formats

| Format | Used For |
|---|---|
| **ECS (Elastic Common Schema)** | Internal normalized event format |
| **OCSF (Open Cybersecurity Schema Framework)** | Security event normalization |
| **SIGMA** | Community detection rule import |
| **STIX 2.1** | Threat intelligence indicator format |
| **OpenTelemetry Protocol (OTLP)** | Traces, metrics, logs from instrumented apps |
| **JSON / NDJSON** | REST API payloads, log streaming |
| **YAML** | Rules, integration configs, playbooks |
| **Prometheus exposition format** | Metric scraping |

---

## External Integrations

### Cloud Providers

| Provider | SDK | Data Sources |
|---|---|---|
| **AWS** | boto3 | CloudTrail, GuardDuty, CloudWatch, S3 access logs, VPC Flow Logs, Lambda logs, Config |
| **GCP** | google-cloud-logging | Cloud Logging, Pub/Sub, Security Command Center, Cloud Audit Logs |
| **Azure** | azure-monitor-query | Monitor, Activity Log, Entra ID (AAD) Sign-ins, Defender for Cloud |

### Identity Providers

| Provider | Method |
|---|---|
| **Okta** | System Log API (polling + event hooks) |
| **Auth0** | Log streaming webhook |
| **Azure AD / Entra ID** | Microsoft Graph API |
| **AWS IAM** | CloudTrail + IAM Access Analyzer |

### Container Orchestration

| Technology | Method | Data |
|---|---|---|
| **Kubernetes** | kube-apiserver events, metrics-server | Pod events, node health, resource utilization |
| **Docker** | Docker Engine API + containerd | Container stats, image scan results |
| **AWS ECS** | CloudWatch + ECS API | Task health, service metrics |

### Notification & Response

| Service | SDK / Protocol | Used For |
|---|---|---|
| **Slack** | Slack Bolt SDK | Alert notifications, investigation updates |
| **PagerDuty** | Events API v2 | On-call escalation for critical signals |
| **OpsGenie** | REST API | Alert routing |
| **SMTP** | smtplib | Email notifications |
| **Jira** | REST API | Auto-create tickets from investigations |
| **GitHub** | REST API + webhooks | PR security scanning, issue creation |

---

## Infrastructure (Single Machine)

### Process Model

```
systemd / launchd / supervisor
└── uvicorn server:app --host 0.0.0.0 --port 8000 --workers 1
    ├── FastAPI HTTP/WebSocket
    ├── asyncio background tasks
    │   ├── Integration pollers (one task per integration)
    │   ├── WatchClaw anomaly loop (every 60s)
    │   ├── Rules hot-reload watcher (inotify)
    │   └── DB write batcher (flush every 500ms)
    └── SQLite database (WAL mode)
```

### System Requirements

| Resource | Minimum | Recommended |
|---|---|---|
| CPU | 2 cores | 4 cores |
| RAM | 2 GB | 8 GB |
| Disk | 20 GB | 100 GB (for 90-day log retention) |
| OS | Linux (Ubuntu 22.04+), macOS 13+ | Ubuntu 22.04 LTS |
| Python | 3.11 | 3.12 |
| Network | 100 Mbps | 1 Gbps (high-volume ingest) |

### Optional Sidecar Services

These are optional — DogClaw runs without them, but they enhance throughput and durability:

| Service | Purpose | When to add |
|---|---|---|
| **Redis 7** | Correlation window cache, WS fan-out | >10k events/sec or multi-browser clients |
| **TimescaleDB** | Production-grade metric retention | >100k events/day or >90 day retention needed |
| **Nginx** | TLS termination, reverse proxy | Any internet-facing deployment |
| **Fluent Bit** | Log collection agent | Running on monitored hosts |
| **Prometheus** | Metric scraping from hosts | Infrastructure metric collection |

---

## Development Tooling

| Tool | Purpose |
|---|---|
| **Black** | Python code formatting |
| **isort** | Import sorting |
| **mypy** | Static type checking (strict mode) |
| **ruff** | Fast linting |
| **pytest + pytest-asyncio** | Test framework |
| **pytest-cov** | Coverage reporting |
| **locust** | Load testing the ingest API |
| **pre-commit** | Git hook automation |
| **docker-compose** | Integration test dependencies |
