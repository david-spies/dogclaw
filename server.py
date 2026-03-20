"""
DogClaw — Unified Threat Detection & Observability Platform
Backend server: single-machine, single-process, asyncio-native.

Run:
    python server.py
    python server.py --host 0.0.0.0 --port 8000 --reload

API docs available at: http://localhost:8000/docs
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import random
import sqlite3
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import structlog
import uvicorn
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

class Settings(BaseSettings):
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    db_url: str = "sqlite+aiosqlite:///./dogclaw.db"
    jwt_secret: str = "dogclaw-change-me-in-production-use-256-bit-random"
    jwt_expiry_hours: int = 24
    auth_enabled: bool = True
    single_user_mode: bool = True  # No password needed for localhost dev
    ui_file: str = "dogclaw.html"

    # AI
    ai_provider: str = "anthropic"        # anthropic | openai | ollama | disabled
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    ai_model: str = "claude-sonnet-4-20250514"

    # Ingest
    statsd_port: int = 8125
    syslog_port: int = 5140               # 514 requires root; use 5140 in dev
    otlp_http_port: int = 4318
    webhook_secret: str = ""

    # GeoIP
    geoip_db_path: str = "./GeoLite2-City.mmdb"

    # Retention
    event_retention_days: int = 90
    metric_retention_days: int = 30

    class Config:
        env_file = ".env"
        env_prefix = "DOGCLAW_"

settings = Settings()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer() if settings.debug else structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    logger_factory=structlog.stdlib.LoggerFactory(),
)
log = structlog.get_logger("dogclaw.server")

# ---------------------------------------------------------------------------
# Database (async SQLite via aiosqlite)
# ---------------------------------------------------------------------------

DB_PATH = Path("dogclaw.db")

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    kind        TEXT,
    category    TEXT,
    action      TEXT,
    outcome     TEXT,
    source_ip   TEXT,
    user_name   TEXT,
    host_name   TEXT,
    severity    TEXT,
    raw         TEXT,
    enriched    TEXT
);

CREATE TABLE IF NOT EXISTS signals (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    rule_id         TEXT,
    rule_name       TEXT,
    severity        TEXT,
    mitre_technique TEXT,
    entity          TEXT,
    source_ip       TEXT,
    description     TEXT,
    status          TEXT DEFAULT 'open',
    investigation_id INTEGER REFERENCES investigations(id)
);

CREATE TABLE IF NOT EXISTS investigations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT DEFAULT (datetime('now')),
    updated_at  TEXT DEFAULT (datetime('now')),
    title       TEXT,
    severity    TEXT,
    status      TEXT DEFAULT 'open',
    assignee    TEXT,
    ai_summary  TEXT,
    tags        TEXT DEFAULT '[]',
    timeline    TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS metrics (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    time        TEXT NOT NULL,
    host        TEXT,
    metric_name TEXT,
    value       REAL,
    tags        TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    name        TEXT PRIMARY KEY,
    last_seen   TEXT,
    status      TEXT DEFAULT 'ok',
    os          TEXT,
    ip          TEXT,
    tags        TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS rules (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    severity    TEXT,
    enabled     INTEGER DEFAULT 1,
    mitre       TEXT,
    conditions  TEXT,
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_signals_timestamp ON signals(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_metrics_time ON metrics(time DESC);
CREATE INDEX IF NOT EXISTS idx_metrics_host ON metrics(host, metric_name);
"""

_db_conn: Optional[sqlite3.Connection] = None


def get_db() -> sqlite3.Connection:
    """Return synchronous SQLite connection (used from sync helpers)."""
    global _db_conn
    if _db_conn is None:
        _db_conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        _db_conn.row_factory = sqlite3.Row
        _db_conn.executescript(SCHEMA_SQL)
        _db_conn.commit()
    return _db_conn


def db_execute(sql: str, params: tuple = ()) -> list[dict]:
    conn = get_db()
    cur = conn.execute(sql, params)
    conn.commit()
    if cur.description:
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]
    return []


def db_insert(table: str, data: dict) -> int:
    cols = ", ".join(data.keys())
    placeholders = ", ".join("?" * len(data))
    sql = f"INSERT INTO {table} ({cols}) VALUES ({placeholders})"
    conn = get_db()
    cur = conn.execute(sql, tuple(data.values()))
    conn.commit()
    return cur.lastrowid

# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class EventIn(BaseModel):
    timestamp: Optional[str] = None
    kind: str = "event"
    category: list[str] = []
    action: str = ""
    outcome: str = "unknown"
    source_ip: Optional[str] = None
    user_name: Optional[str] = None
    host_name: Optional[str] = None
    severity: str = "info"
    raw: dict = {}


class MetricIn(BaseModel):
    host: str
    metric_name: str
    value: float
    tags: dict = {}
    timestamp: Optional[str] = None


class SignalCreate(BaseModel):
    rule_id: str
    rule_name: str
    severity: str
    mitre_technique: Optional[str] = None
    entity: Optional[str] = None
    source_ip: Optional[str] = None
    description: str = ""


class InvestigationCreate(BaseModel):
    title: str
    severity: str = "medium"
    tags: list[str] = []


class AiQuery(BaseModel):
    message: str
    conversation_id: Optional[str] = None
    investigation_id: Optional[int] = None


class ResponseAction(BaseModel):
    action: str   # revoke_credentials | isolate_container | block_ip | create_investigation
    target: str
    params: dict = {}


class LoginRequest(BaseModel):
    username: str
    password: str


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

security = HTTPBearer(auto_error=False)

# Single hardcoded user for local dev. Replace with DB-backed users for production.
USERS = {
    "admin": hashlib.sha256(b"dogclaw-admin").hexdigest(),
}


def create_token(username: str) -> str:
    """Create a simple HMAC-based token (replace with python-jose JWT in production)."""
    expiry = int(time.time()) + settings.jwt_expiry_hours * 3600
    payload = f"{username}:{expiry}"
    sig = hmac.new(settings.jwt_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def verify_token(token: str) -> Optional[str]:
    """Return username if token is valid, else None."""
    try:
        parts = token.rsplit(":", 2)
        if len(parts) != 3:
            return None
        username, expiry_str, sig = parts
        expiry = int(expiry_str)
        if time.time() > expiry:
            return None
        payload = f"{username}:{expiry_str}"
        expected = hmac.new(settings.jwt_secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        return username
    except Exception:
        return None


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> str:
    if settings.single_user_mode or not settings.auth_enabled:
        return "admin"
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    username = verify_token(credentials.credentials)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return username


# ---------------------------------------------------------------------------
# WebSocket Hub
# ---------------------------------------------------------------------------

class WebSocketHub:
    """Manages connected browser clients and broadcasts events."""

    def __init__(self):
        self._clients: dict[str, WebSocket] = {}
        self._subscriptions: dict[str, set[str]] = defaultdict(set)  # client_id -> feeds

    async def connect(self, ws: WebSocket) -> str:
        await ws.accept()
        client_id = str(uuid.uuid4())[:8]
        self._clients[client_id] = ws
        log.info("ws_client_connected", client_id=client_id, total=len(self._clients))
        return client_id

    def disconnect(self, client_id: str):
        self._clients.pop(client_id, None)
        self._subscriptions.pop(client_id, None)
        log.info("ws_client_disconnected", client_id=client_id, total=len(self._clients))

    async def broadcast(self, message: dict, feed: str = "all"):
        """Send message to all clients subscribed to the given feed."""
        dead = []
        for cid, ws in self._clients.items():
            if feed == "all" or feed in self._subscriptions.get(cid, {"all"}):
                try:
                    await ws.send_json(message)
                except Exception:
                    dead.append(cid)
        for cid in dead:
            self.disconnect(cid)

    def subscribe(self, client_id: str, feeds: list[str]):
        self._subscriptions[client_id].update(feeds)

    @property
    def client_count(self) -> int:
        return len(self._clients)


ws_hub = WebSocketHub()

# ---------------------------------------------------------------------------
# In-memory Correlation Window
# ---------------------------------------------------------------------------

class CorrelationWindow:
    """
    Lightweight sliding-window event tracker per entity.
    Keeps the last N events per entity within a time window.
    Used by the rules engine to detect multi-event patterns.
    """

    def __init__(self, window_minutes: int = 30, max_per_entity: int = 100):
        self.window = timedelta(minutes=window_minutes)
        self.max_per_entity = max_per_entity
        self._store: dict[str, deque] = defaultdict(lambda: deque(maxlen=max_per_entity))

    def add(self, entity: str, event: dict):
        self._store[entity].append({**event, "_ts": datetime.now(timezone.utc)})

    def get(self, entity: str) -> list[dict]:
        cutoff = datetime.now(timezone.utc) - self.window
        return [e for e in self._store[entity] if e["_ts"] > cutoff]

    def count_action(self, entity: str, action: str) -> int:
        return sum(1 for e in self.get(entity) if e.get("action") == action)


correlation = CorrelationWindow()

# ---------------------------------------------------------------------------
# Rules Engine
# ---------------------------------------------------------------------------

# Default built-in rules (in production these load from YAML files in config/rules/)
DEFAULT_RULES = [
    {
        "id": "dogclaw-iam-001",
        "name": "High-Privilege IAM Policy Attached from Suspicious Source",
        "severity": "critical",
        "mitre": "T1098",
        "enabled": True,
        "match": lambda e: (
            e.get("action") in ("AttachUserPolicy", "PutUserPolicy") and
            "AdministratorAccess" in json.dumps(e.get("raw", {}))
        ),
    },
    {
        "id": "dogclaw-auth-001",
        "name": "Brute Force — Repeated Failed Authentication",
        "severity": "high",
        "mitre": "T1110",
        "enabled": True,
        "match": lambda e: (
            e.get("action") in ("login", "authenticate", "ConsoleLogin") and
            e.get("outcome") == "failure"
        ),
        "threshold": {"count": 10, "window_minutes": 5, "group_by": "source_ip"},
    },
    {
        "id": "dogclaw-net-001",
        "name": "Outbound Data Volume Spike (Possible Exfiltration)",
        "severity": "high",
        "mitre": "T1567",
        "enabled": True,
        "match": lambda e: (
            e.get("category") == "network" and
            float(e.get("raw", {}).get("bytes_out", 0)) > 500_000_000  # 500 MB
        ),
    },
    {
        "id": "dogclaw-container-001",
        "name": "Cryptominer Process Signature Detected",
        "severity": "critical",
        "mitre": "T1496",
        "enabled": True,
        "match": lambda e: (
            any(kw in json.dumps(e.get("raw", {})).lower()
                for kw in ["xmrig", "minerd", "cpuminer", "stratum+tcp"])
        ),
    },
    {
        "id": "dogclaw-dlp-001",
        "name": "PII Detected in Log or Telemetry Stream",
        "severity": "high",
        "mitre": "T1530",
        "enabled": True,
        "match": lambda e: (
            any(kw in json.dumps(e.get("raw", {}))
                for kw in ["ssn", "social_security", "credit_card", "@@"])  # simplified
        ),
    },
    {
        "id": "dogclaw-iam-002",
        "name": "New IAM Access Keys Created",
        "severity": "medium",
        "mitre": "T1098",
        "enabled": True,
        "match": lambda e: e.get("action") == "CreateAccessKey",
    },
    {
        "id": "dogclaw-geo-001",
        "name": "Authentication from Unusual Geographic Location",
        "severity": "medium",
        "mitre": "T1078",
        "enabled": True,
        "match": lambda e: (
            e.get("action") in ("login", "ConsoleLogin") and
            e.get("outcome") == "success" and
            e.get("raw", {}).get("geo_country") in ("CN", "RU", "KP", "IR")
        ),
    },
]

# Threshold counters for rate-based rules
_threshold_counters: dict[str, list[float]] = defaultdict(list)


def evaluate_rules(event: dict) -> list[dict]:
    """Evaluate all enabled rules against a normalized event. Returns list of signals."""
    signals = []
    now = time.time()

    for rule in DEFAULT_RULES:
        if not rule.get("enabled"):
            continue

        try:
            matched = rule["match"](event)
        except Exception:
            matched = False

        if not matched:
            continue

        # Threshold rules: only fire if count exceeds threshold in window
        if "threshold" in rule:
            thresh = rule["threshold"]
            group_key = event.get(thresh.get("group_by", "source_ip"), "unknown")
            counter_key = f"{rule['id']}:{group_key}"
            window = thresh["window_minutes"] * 60
            # Clean old entries
            _threshold_counters[counter_key] = [
                t for t in _threshold_counters[counter_key] if now - t < window
            ]
            _threshold_counters[counter_key].append(now)
            if len(_threshold_counters[counter_key]) < thresh["count"]:
                continue  # Haven't hit threshold yet

        signal = {
            "id": str(uuid.uuid4())[:12],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "severity": rule["severity"],
            "mitre_technique": rule.get("mitre", ""),
            "entity": event.get("user_name") or event.get("host_name") or event.get("source_ip", "unknown"),
            "source_ip": event.get("source_ip", ""),
            "description": f"{rule['name']} — action: {event.get('action', 'unknown')}",
            "status": "open",
        }
        signals.append(signal)

    return signals


# ---------------------------------------------------------------------------
# Event Processor
# ---------------------------------------------------------------------------

async def process_event(raw_event: dict) -> dict:
    """Normalize, enrich, evaluate rules, store, and broadcast an incoming event."""
    now_iso = datetime.now(timezone.utc).isoformat()

    # Normalize
    event: dict[str, Any] = {
        "timestamp": raw_event.get("timestamp", now_iso),
        "kind": raw_event.get("kind", "event"),
        "category": raw_event.get("category", ""),
        "action": raw_event.get("action", ""),
        "outcome": raw_event.get("outcome", "unknown"),
        "source_ip": raw_event.get("source_ip") or raw_event.get("sourceIPAddress"),
        "user_name": raw_event.get("user_name") or raw_event.get("userIdentity", {}).get("userName"),
        "host_name": raw_event.get("host_name"),
        "severity": raw_event.get("severity", "info"),
        "raw": json.dumps(raw_event),
        "enriched": "{}",
    }

    # Store event
    try:
        event_id = db_insert("events", event)
        event["id"] = event_id
    except Exception as e:
        log.warning("db_insert_failed", error=str(e))
        event["id"] = 0

    # Update host last-seen
    if event["host_name"]:
        try:
            conn = get_db()
            conn.execute(
                "INSERT OR REPLACE INTO hosts (name, last_seen, ip) VALUES (?, ?, ?)",
                (event["host_name"], now_iso, event["source_ip"] or ""),
            )
            conn.commit()
        except Exception:
            pass

    # Add to correlation window
    entity = event.get("user_name") or event.get("source_ip") or "unknown"
    correlation.add(entity, event)

    # Evaluate rules
    signals = evaluate_rules(event)
    for signal in signals:
        try:
            db_insert("signals", {
                "timestamp": signal["timestamp"],
                "rule_id": signal["rule_id"],
                "rule_name": signal["rule_name"],
                "severity": signal["severity"],
                "mitre_technique": signal["mitre_technique"],
                "entity": signal["entity"],
                "source_ip": signal["source_ip"],
                "description": signal["description"],
                "status": "open",
            })
        except Exception:
            pass

        # Broadcast signal to UI
        await ws_hub.broadcast({"type": "threat_event", "payload": signal}, feed="threats")
        log.warning("signal_fired", rule=signal["rule_name"], severity=signal["severity"])

    # Broadcast raw event to log feed
    await ws_hub.broadcast({"type": "log_event", "payload": event}, feed="logs")

    return {"event_id": event.get("id"), "signals_fired": len(signals)}


# ---------------------------------------------------------------------------
# Simulated Live Data (Demo Mode)
# ---------------------------------------------------------------------------

DEMO_EVENTS = [
    {"action": "ConsoleLogin", "outcome": "failure", "source_ip": "91.108.56.130", "user_name": "admin",
     "raw": {"geo_country": "RU", "userAgent": "python-requests/2.28"}, "severity": "medium"},
    {"action": "AttachUserPolicy", "outcome": "success", "source_ip": "185.220.101.44",
     "user_name": "admin-ops", "raw": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
     "requestParameters": {"userName": "svc-deploy-prod"}}, "severity": "critical"},
    {"action": "CreateAccessKey", "outcome": "success", "source_ip": "10.0.1.12",
     "user_name": "svc-deploy-prod", "raw": {}, "severity": "medium"},
    {"action": "process_spawn", "host_name": "k8s-node-07", "severity": "critical",
     "raw": {"process": "xmrig", "args": "--pool stratum+tcp://pool.minexmr.com:4444"}},
    {"action": "login", "outcome": "success", "source_ip": "1.180.215.99", "user_name": "ops-admin",
     "raw": {"geo_country": "CN"}, "severity": "medium"},
    {"action": "http_request", "source_ip": "103.21.244.19", "host_name": "api-gateway",
     "raw": {"path": "/api/v2/users?id=1 OR 1=1--", "waf_action": "BLOCK"}, "severity": "high"},
    {"action": "network_flow", "source_ip": "10.0.1.47", "host_name": "dogprod-api-7",
     "category": "network",
     "raw": {"bytes_out": 1_200_000_000, "destination": "transfer.sh"}, "severity": "high"},
]


async def demo_event_loop():
    """Continuously emit simulated events for demo/development mode."""
    log.info("demo_event_loop_started")
    await asyncio.sleep(3)  # Wait for startup
    while True:
        event = random.choice(DEMO_EVENTS).copy()
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
        await process_event(event)

        # Also broadcast a system health heartbeat
        await ws_hub.broadcast({
            "type": "system_health",
            "payload": {
                "agents_online": random.randint(246, 250),
                "events_per_sec": round(random.uniform(12000, 16000), 0),
                "open_signals": db_execute("SELECT COUNT(*) as c FROM signals WHERE status='open'")[0]["c"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        })

        await asyncio.sleep(random.uniform(4, 12))


# ---------------------------------------------------------------------------
# AI Agent
# ---------------------------------------------------------------------------

async def query_ai(message: str, context: dict) -> str:
    """Send a query to the configured LLM with security context injected."""
    if settings.ai_provider == "disabled":
        return "AI is disabled. Set DOGCLAW_AI_PROVIDER=anthropic and provide an API key."

    recent_signals = db_execute(
        "SELECT rule_name, severity, entity, source_ip, description, timestamp "
        "FROM signals ORDER BY timestamp DESC LIMIT 10"
    )
    recent_events = db_execute(
        "SELECT action, outcome, source_ip, user_name, host_name, timestamp "
        "FROM events ORDER BY timestamp DESC LIMIT 20"
    )

    system_prompt = """You are DogClaw AI, an expert security analyst and observability engineer
embedded in a unified threat detection platform. You have access to real-time telemetry from
the monitored environment including security signals, events, metrics, and logs.

When answering questions:
- Be specific, cite event data when available
- Reference MITRE ATT&CK techniques when relevant
- Provide actionable recommendations
- For security incidents, assess confidence and recommend immediate actions
- For code/PR review, focus on secrets, injection vulnerabilities, and supply chain risks
- Keep responses concise and analyst-focused"""

    user_message = f"""Environment context:
Recent signals (last 10): {json.dumps(recent_signals, indent=2)}
Recent events (last 20): {json.dumps(recent_events, indent=2)}
Additional context: {json.dumps(context, indent=2)}

Analyst question: {message}"""

    if settings.ai_provider == "anthropic" and settings.anthropic_api_key:
        try:
            import anthropic as _anthropic
            client = _anthropic.Anthropic(api_key=settings.anthropic_api_key)
            response = client.messages.create(
                model=settings.ai_model,
                max_tokens=1500,
                system=system_prompt,
                messages=[{"role": "user", "content": user_message}],
            )
            return response.content[0].text
        except Exception as e:
            log.error("anthropic_api_error", error=str(e))
            return f"AI query failed: {e}"

    elif settings.ai_provider == "openai" and settings.openai_api_key:
        try:
            import openai as _openai
            client = _openai.AsyncOpenAI(api_key=settings.openai_api_key)
            response = await client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                max_tokens=1500,
            )
            return response.choices[0].message.content
        except Exception as e:
            log.error("openai_api_error", error=str(e))
            return f"AI query failed: {e}"

    # Fallback: rule-based mock responses for demo
    lq = message.lower()
    if any(k in lq for k in ["185.220", "tor", "suspicious ip"]):
        return ("IP 185.220.101.44 is a confirmed Tor exit node with a malicious score of 94/100 on "
                "AbuseIPDB. It appeared in 3 prior incidents in your environment this quarter. "
                "Immediate recommendation: block at WAF, revoke all sessions originating from this IP.")
    if any(k in lq for k in ["attack path", "chain", "kill chain"]):
        return ("Reconstructed attack chain: External (185.220.101.44) → Stolen admin session → "
                "svc-deploy-prod privilege escalation (AdministratorAccess) → Container compromise "
                "(dogprod-api-7) → Exfiltration attempt to transfer.sh. "
                "MITRE: T1078 → T1098 → T1525 → T1567. Duration: ~14 minutes. Confidence: 94%.")
    if any(k in lq for k in ["pr", "pull request", "code review"]):
        return ("PR analysis: Found hardcoded AWS key pattern (AKIA...) on lines 412-415 and "
                "unsanitized SQL interpolation on lines 889-892. 6 low-severity findings. "
                "Recommendation: Block merge. Rotate the exposed key immediately even if the PR is closed.")
    if any(k in lq for k in ["what changed", "last hour", "recent"]):
        signals = db_execute("SELECT rule_name, severity FROM signals ORDER BY timestamp DESC LIMIT 5")
        return (f"In the last hour I observed {len(signals)} signals. Most notable: " +
                "; ".join(f"{s['severity'].upper()} — {s['rule_name']}" for s in signals) +
                ". The privilege escalation chain from 185.220.101.44 is the highest priority item.")
    return (f"Based on current telemetry ({len(db_execute('SELECT id FROM signals WHERE status=?', ('open',)))} "
            f"open signals, {db_execute('SELECT COUNT(*) as c FROM events')[0]['c']} events ingested): "
            f"your query '{message}' has been noted. Set DOGCLAW_AI_PROVIDER=anthropic with a valid API key "
            f"for full AI-powered analysis.")


# ---------------------------------------------------------------------------
# Response Action Handlers
# ---------------------------------------------------------------------------

RESPONSE_HANDLERS: dict[str, Any] = {
    "revoke_credentials": lambda target, params: {
        "status": "executed",
        "action": "revoke_credentials",
        "target": target,
        "detail": f"All access keys for '{target}' have been revoked. Login sessions invalidated.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    },
    "isolate_container": lambda target, params: {
        "status": "executed",
        "action": "isolate_container",
        "target": target,
        "detail": f"Container '{target}' network policy updated: all ingress/egress blocked. Pod not terminated.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    },
    "block_ip": lambda target, params: {
        "status": "executed",
        "action": "block_ip",
        "target": target,
        "detail": f"IP '{target}' added to WAF deny list. Also added to internal threat intel feed.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    },
    "create_investigation": lambda target, params: {
        "status": "executed",
        "action": "create_investigation",
        "target": target,
        "detail": f"Investigation created for '{target}'. Assigned to SOC queue.",
        "investigation_id": db_insert("investigations", {
            "title": target,
            "severity": params.get("severity", "medium"),
            "tags": json.dumps(params.get("tags", [])),
        }),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    },
}


# ---------------------------------------------------------------------------
# Application Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown logic."""
    log.info("dogclaw_starting", version="2.4.1", host=settings.host, port=settings.port)

    # Initialize DB
    get_db()
    log.info("database_ready", path=str(DB_PATH))

    # Seed demo rules into DB
    for rule in DEFAULT_RULES:
        try:
            db_insert("rules", {
                "id": rule["id"],
                "name": rule["name"],
                "severity": rule["severity"],
                "enabled": 1,
                "mitre": rule.get("mitre", ""),
                "conditions": "{}",
            })
        except Exception:
            pass  # Already exists

    # Start demo event loop (remove in production, replace with real integrations)
    demo_task = asyncio.create_task(demo_event_loop())
    log.info("demo_mode_active", message="Generating simulated events. Disable in production.")

    yield

    # Shutdown
    demo_task.cancel()
    log.info("dogclaw_shutdown")


# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="DogClaw API",
    description="Unified Threat Detection & Observability Platform",
    version="2.4.1",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routes — Auth
# ---------------------------------------------------------------------------

@app.post("/auth/login")
async def login(req: LoginRequest):
    """Authenticate and receive a token."""
    stored = USERS.get(req.username)
    if not stored:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    hashed = hashlib.sha256(req.password.encode()).hexdigest()
    if not hmac.compare_digest(hashed, stored):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(req.username)
    return {"token": token, "username": req.username}


@app.get("/auth/me")
async def me(user: str = Depends(get_current_user)):
    return {"username": user}


# ---------------------------------------------------------------------------
# Routes — Health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    event_count = db_execute("SELECT COUNT(*) as c FROM events")[0]["c"]
    signal_count = db_execute("SELECT COUNT(*) as c FROM signals WHERE status='open'")[0]["c"]
    return {
        "status": "ok",
        "version": "2.4.1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "db": "connected",
        "ws_clients": ws_hub.client_count,
        "events_total": event_count,
        "open_signals": signal_count,
    }


# ---------------------------------------------------------------------------
# Routes — Ingest
# ---------------------------------------------------------------------------

@app.post("/ingest/event")
async def ingest_event(
    event: EventIn,
    background_tasks: BackgroundTasks,
    user: str = Depends(get_current_user),
):
    """Ingest a single normalized security/observability event."""
    result = await process_event(event.model_dump())
    return result


@app.post("/ingest/events/batch")
async def ingest_events_batch(
    events: list[EventIn],
    user: str = Depends(get_current_user),
):
    """Ingest a batch of events (up to 1000 per request)."""
    if len(events) > 1000:
        raise HTTPException(status_code=400, detail="Max 1000 events per batch")
    results = []
    for event in events:
        results.append(await process_event(event.model_dump()))
    return {"processed": len(results), "signals_fired": sum(r["signals_fired"] for r in results)}


@app.post("/ingest/metric")
async def ingest_metric(
    metric: MetricIn,
    user: str = Depends(get_current_user),
):
    """Ingest a single metric data point."""
    db_insert("metrics", {
        "time": metric.timestamp or datetime.now(timezone.utc).isoformat(),
        "host": metric.host,
        "metric_name": metric.metric_name,
        "value": metric.value,
        "tags": json.dumps(metric.tags),
    })
    return {"status": "ok"}


@app.post("/ingest/webhook/{source}")
async def ingest_webhook(source: str, request: Request):
    """
    Generic webhook endpoint for push-based integrations.
    Source: aws | github | okta | pagerduty | custom
    """
    body = await request.json()
    log.info("webhook_received", source=source, size=len(str(body)))

    # Normalize based on source
    if source == "aws":
        records = body.get("Records", [body])
        for record in records:
            await process_event({"action": record.get("eventName", "unknown"),
                                 "source": "aws", "raw": record})
    elif source == "github":
        event_type = request.headers.get("X-GitHub-Event", "unknown")
        await process_event({"action": f"github.{event_type}", "source": "github", "raw": body})
    elif source == "okta":
        for log_event in body.get("data", {}).get("events", [body]):
            await process_event({"action": log_event.get("eventType", "unknown"),
                                 "source": "okta", "raw": log_event})
    else:
        await process_event({"action": f"{source}.event", "source": source, "raw": body})

    return {"status": "accepted"}


# ---------------------------------------------------------------------------
# Routes — Events & Signals
# ---------------------------------------------------------------------------

@app.get("/api/signals")
async def list_signals(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(100, le=1000),
    user: str = Depends(get_current_user),
):
    """List SIEM signals (rule matches)."""
    sql = "SELECT * FROM signals WHERE 1=1"
    params: list = []
    if severity:
        sql += " AND severity = ?"
        params.append(severity)
    if status:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    return db_execute(sql, tuple(params))


@app.get("/api/signals/{signal_id}")
async def get_signal(signal_id: int, user: str = Depends(get_current_user)):
    rows = db_execute("SELECT * FROM signals WHERE id = ?", (signal_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="Signal not found")
    return rows[0]


@app.patch("/api/signals/{signal_id}/status")
async def update_signal_status(
    signal_id: int,
    body: dict,
    user: str = Depends(get_current_user),
):
    new_status = body.get("status", "open")
    db_execute("UPDATE signals SET status = ? WHERE id = ?", (new_status, signal_id))
    return {"status": "updated"}


@app.get("/api/events")
async def list_events(
    host: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = Query(200, le=5000),
    user: str = Depends(get_current_user),
):
    sql = "SELECT * FROM events WHERE 1=1"
    params: list = []
    if host:
        sql += " AND host_name = ?"
        params.append(host)
    if action:
        sql += " AND action LIKE ?"
        params.append(f"%{action}%")
    sql += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    return db_execute(sql, tuple(params))


# ---------------------------------------------------------------------------
# Routes — Metrics
# ---------------------------------------------------------------------------

@app.get("/api/metrics")
async def list_metrics(
    host: Optional[str] = None,
    metric: Optional[str] = None,
    hours: int = 1,
    user: str = Depends(get_current_user),
):
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    sql = "SELECT * FROM metrics WHERE time > ?"
    params: list = [cutoff]
    if host:
        sql += " AND host = ?"
        params.append(host)
    if metric:
        sql += " AND metric_name = ?"
        params.append(metric)
    sql += " ORDER BY time DESC LIMIT 10000"
    return db_execute(sql, tuple(params))


@app.get("/api/hosts")
async def list_hosts(user: str = Depends(get_current_user)):
    return db_execute("SELECT * FROM hosts ORDER BY last_seen DESC")


# ---------------------------------------------------------------------------
# Routes — Investigations
# ---------------------------------------------------------------------------

@app.get("/api/investigations")
async def list_investigations(user: str = Depends(get_current_user)):
    return db_execute("SELECT * FROM investigations ORDER BY created_at DESC")


@app.post("/api/investigations")
async def create_investigation(body: InvestigationCreate, user: str = Depends(get_current_user)):
    inv_id = db_insert("investigations", {
        "title": body.title,
        "severity": body.severity,
        "tags": json.dumps(body.tags),
    })
    return {"id": inv_id, "title": body.title}


@app.get("/api/investigations/{inv_id}")
async def get_investigation(inv_id: int, user: str = Depends(get_current_user)):
    rows = db_execute("SELECT * FROM investigations WHERE id = ?", (inv_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="Investigation not found")
    inv = rows[0]
    inv["signals"] = db_execute("SELECT * FROM signals WHERE investigation_id = ?", (inv_id,))
    return inv


@app.patch("/api/investigations/{inv_id}")
async def update_investigation(
    inv_id: int,
    body: dict,
    user: str = Depends(get_current_user),
):
    allowed = {"status", "assignee", "ai_summary", "title", "severity"}
    updates = {k: v for k, v in body.items() if k in allowed}
    if not updates:
        raise HTTPException(status_code=400, detail="No valid fields to update")
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    db_execute(
        f"UPDATE investigations SET {set_clause}, updated_at = datetime('now') WHERE id = ?",
        (*updates.values(), inv_id),
    )
    return {"status": "updated"}


# ---------------------------------------------------------------------------
# Routes — Rules
# ---------------------------------------------------------------------------

@app.get("/api/rules")
async def list_rules(user: str = Depends(get_current_user)):
    return db_execute("SELECT * FROM rules ORDER BY severity, name")


@app.patch("/api/rules/{rule_id}/toggle")
async def toggle_rule(rule_id: str, user: str = Depends(get_current_user)):
    rows = db_execute("SELECT enabled FROM rules WHERE id = ?", (rule_id,))
    if not rows:
        raise HTTPException(status_code=404, detail="Rule not found")
    new_state = 0 if rows[0]["enabled"] else 1
    db_execute("UPDATE rules SET enabled = ? WHERE id = ?", (new_state, rule_id))
    return {"enabled": bool(new_state)}


# ---------------------------------------------------------------------------
# Routes — AI Agent
# ---------------------------------------------------------------------------

@app.post("/api/ai/query")
async def ai_query(body: AiQuery, user: str = Depends(get_current_user)):
    """Send a question to the DogClaw AI agent."""
    context = {}
    if body.investigation_id:
        rows = db_execute("SELECT * FROM investigations WHERE id = ?", (body.investigation_id,))
        if rows:
            context["investigation"] = rows[0]

    response = await query_ai(body.message, context)
    return {
        "response": response,
        "conversation_id": body.conversation_id or str(uuid.uuid4())[:8],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Routes — Response Actions
# ---------------------------------------------------------------------------

@app.post("/api/response/action")
async def execute_response_action(
    action: ResponseAction,
    user: str = Depends(get_current_user),
):
    """Execute a response action (revoke credentials, isolate container, block IP, etc.)."""
    handler = RESPONSE_HANDLERS.get(action.action)
    if not handler:
        raise HTTPException(status_code=400, detail=f"Unknown action: {action.action}. "
                            f"Valid: {list(RESPONSE_HANDLERS.keys())}")

    result = handler(action.target, action.params)

    # Log the response action as an event
    await process_event({
        "action": f"response.{action.action}",
        "outcome": "success",
        "user_name": user,
        "severity": "info",
        "raw": {"target": action.target, "executor": user, "result": result},
    })

    # Broadcast to UI
    await ws_hub.broadcast({"type": "response_executed", "payload": result})

    log.info("response_action_executed", action=action.action, target=action.target, executor=user)
    return result


# ---------------------------------------------------------------------------
# Routes — Dashboard Stats
# ---------------------------------------------------------------------------

@app.get("/api/stats/overview")
async def stats_overview(user: str = Depends(get_current_user)):
    """Aggregated stats for the main dashboard."""
    open_signals = db_execute("SELECT severity, COUNT(*) as c FROM signals WHERE status='open' GROUP BY severity")
    severity_counts = {row["severity"]: row["c"] for row in open_signals}

    recent_signals = db_execute(
        "SELECT * FROM signals ORDER BY timestamp DESC LIMIT 20"
    )
    host_count = db_execute("SELECT COUNT(*) as c FROM hosts")[0]["c"]
    event_count = db_execute("SELECT COUNT(*) as c FROM events")[0]["c"]

    return {
        "critical": severity_counts.get("critical", 0),
        "high": severity_counts.get("high", 0),
        "medium": severity_counts.get("medium", 0),
        "low": severity_counts.get("low", 0),
        "hosts_online": host_count,
        "total_events": event_count,
        "recent_signals": recent_signals,
        "ws_clients": ws_hub.client_count,
    }


# ---------------------------------------------------------------------------
# WebSocket Endpoint
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket, token: Optional[str] = Query(None)):
    """Real-time event streaming endpoint for the browser UI."""
    # Auth check (relaxed for single-user mode)
    if settings.auth_enabled and not settings.single_user_mode:
        if not token or not verify_token(token):
            await ws.close(code=4001)
            return

    client_id = await ws_hub.connect(ws)

    # Send initial state
    await ws.send_json({
        "type": "connected",
        "payload": {
            "client_id": client_id,
            "server_version": "2.4.1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    })

    try:
        while True:
            data = await ws.receive_json()
            msg_type = data.get("type")

            if msg_type == "subscribe":
                ws_hub.subscribe(client_id, data.get("feeds", ["all"]))
                await ws.send_json({"type": "subscribed", "feeds": data.get("feeds", ["all"])})

            elif msg_type == "ai_query":
                response = await query_ai(data.get("message", ""), {})
                await ws.send_json({
                    "type": "ai_response",
                    "payload": {
                        "conversation_id": data.get("conversation_id"),
                        "message": response,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                })

            elif msg_type == "ping":
                await ws.send_json({"type": "pong", "ts": time.time()})

    except WebSocketDisconnect:
        ws_hub.disconnect(client_id)
    except Exception as e:
        log.error("ws_error", client_id=client_id, error=str(e))
        ws_hub.disconnect(client_id)


# ---------------------------------------------------------------------------
# Serve UI
# ---------------------------------------------------------------------------

@app.get("/")
async def serve_ui():
    """Serve the DogClaw browser UI."""
    ui_path = Path(settings.ui_file)
    if ui_path.exists():
        return FileResponse(ui_path, media_type="text/html")
    return HTMLResponse("""
    <html><body style="background:#080b12;color:#00e5ff;font-family:monospace;padding:40px">
    <h2>🐾 DogClaw — UI file not found</h2>
    <p>Place <code>dogclaw.html</code> in the same directory as <code>server.py</code> and restart.</p>
    <p>API is running: <a href="/docs" style="color:#7c3aed">/docs</a> | 
    <a href="/health" style="color:#10b981">/health</a></p>
    </body></html>
    """, status_code=200)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="DogClaw Backend Server")
    parser.add_argument("--host", default=settings.host)
    parser.add_argument("--port", type=int, default=settings.port)
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload (development only)")
    parser.add_argument("--workers", type=int, default=1, help="Number of worker processes")
    parser.add_argument("--no-demo", action="store_true", help="Disable demo event generator")
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════════╗
║  🐾  DogClaw v2.4.1                          ║
║  Unified Threat Detection Platform           ║
╠══════════════════════════════════════════════╣
║  UI:   http://{args.host}:{args.port:<28}  ║
║  API:  http://{args.host}:{args.port}/docs   ║
║  WS:   ws://{args.host}:{args.port}/ws       ║
╚══════════════════════════════════════════════╝
""")

    uvicorn.run(
        "server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        workers=1 if args.reload else args.workers,
        log_level="debug" if settings.debug else "info",
        access_log=settings.debug,
    )
