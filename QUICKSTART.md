# DogClaw — Quickstart Guide

> **Get from zero to a running threat detection platform in under 20 minutes.** This guide covers installation, agent setup, and connecting every supported service.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [First Launch](#first-launch)
4. [Install the DogClaw Agent on Monitored Hosts](#install-the-dogclaw-agent-on-monitored-hosts)
5. [Connecting AWS](#connecting-aws)
6. [Connecting Kubernetes](#connecting-kubernetes)
7. [Connecting GitHub (PR Security Scanning)](#connecting-github)
8. [Connecting Okta](#connecting-okta)
9. [Connecting Azure AD / Entra ID](#connecting-azure-ad)
10. [Connecting GCP](#connecting-gcp)
11. [Connecting Docker](#connecting-docker)
12. [Connecting Databases](#connecting-databases)
13. [Connecting Application Traces (OpenTelemetry)](#connecting-opentelemetry)
14. [Connecting Logs (Fluent Bit / Syslog)](#connecting-logs)
15. [Connecting Network Monitoring](#connecting-network-monitoring)
16. [Setting Up Notifications (Slack / PagerDuty)](#setting-up-notifications)
17. [Enabling AI (DogClaw Agent)](#enabling-ai)
18. [Configuring Detection Rules](#configuring-detection-rules)
19. [Verifying Everything Works](#verifying-everything-works)
20. [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before you begin, make sure the machine running DogClaw has:

- **Python 3.11 or higher** — `python3 --version`
- **pip** — `pip3 --version`
- **4 GB RAM minimum** (8 GB recommended)
- **20 GB free disk** (for event and metric storage)
- **Outbound internet access** (for cloud integrations and GeoIP updates)
- **Inbound ports open** (configurable): `8000` (UI/API), `8125/udp` (StatsD), `5140` (Syslog), `4318` (OTLP)

Optional but recommended for production:
- **nginx** for TLS termination
- **systemd** for process management

---

## Installation

### Step 1 — Clone the Repository

```bash
git clone https://github.com/your-org/dogclaw.git
cd dogclaw
```

### Step 2 — Create a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate          # macOS / Linux
# .venv\Scripts\activate           # Windows
```

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

> **Note:** The first install may take 2–3 minutes. Core dependencies (FastAPI, SQLAlchemy, scikit-learn) are the largest packages.

### Step 4 — Configure Environment

Copy the example environment file and edit it:

```bash
cp .env.example .env
```

Open `.env` in your editor. At minimum, set:

```bash
# .env

# Server
DOGCLAW_HOST=0.0.0.0
DOGCLAW_PORT=8000
DOGCLAW_JWT_SECRET=<generate with: python3 -c "import secrets; print(secrets.token_hex(32))">

# AI (optional but recommended — see Step 17)
DOGCLAW_AI_PROVIDER=anthropic
DOGCLAW_ANTHROPIC_API_KEY=sk-ant-...

# Single-user mode (no login required for localhost)
DOGCLAW_SINGLE_USER_MODE=true
DOGCLAW_AUTH_ENABLED=true
```

### Step 5 — Download GeoIP Database (Optional but Recommended)

GeoIP enrichment adds geographic context to IP addresses in alerts. This requires a free MaxMind account.

1. Register at https://www.maxmind.com/en/geolite2/signup
2. Download **GeoLite2-City.mmdb**
3. Place it in the project root: `./GeoLite2-City.mmdb`

```bash
# Or use the download script (requires MAXMIND_LICENSE_KEY in .env)
python scripts/download_geoip.py
```

---

## First Launch

```bash
python server.py
```

You should see:

```
╔══════════════════════════════════════════════╗
║  🐾  DogClaw v2.4.1                          ║
║  Unified Threat Detection Platform           ║
╠══════════════════════════════════════════════╣
║  UI:   http://0.0.0.0:8000                   ║
║  API:  http://0.0.0.0:8000/docs              ║
║  WS:   ws://0.0.0.0:8000/ws                  ║
╚══════════════════════════════════════════════╝
```

Open **http://localhost:8000** in your browser. You'll see the DogClaw UI with live simulated events (demo mode). Demo mode generates realistic security events so you can explore the interface before connecting real data sources.

**To run as a background service (Linux):**

```bash
# Create systemd service
sudo tee /etc/systemd/system/dogclaw.service > /dev/null <<EOF
[Unit]
Description=DogClaw Threat Detection Platform
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/.venv/bin/python server.py
Restart=on-failure
RestartSec=5
EnvironmentFile=$(pwd)/.env

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable dogclaw
sudo systemctl start dogclaw
sudo systemctl status dogclaw
```

---

## Install the DogClaw Agent on Monitored Hosts

The DogClaw agent runs on each host you want to monitor. It collects metrics, forwards logs, and watches for process/file anomalies. It reports back to your DogClaw server over HTTP.

### Linux / macOS (One-line Install)

Run this on every host you want to monitor. Replace `DOGCLAW_SERVER` with the IP or hostname of your DogClaw machine.

```bash
export DOGCLAW_SERVER=http://<your-dogclaw-ip>:8000
export DOGCLAW_TOKEN=<your-api-token>   # Get from DogClaw UI → Settings → API Tokens
curl -sSL https://raw.githubusercontent.com/your-org/dogclaw/main/scripts/install_agent.sh | bash
```

The agent installs to `/opt/dogclaw-agent/` and registers itself as a systemd service.

### What the Agent Collects

| Category | Data | Interval |
|---|---|---|
| System Metrics | CPU, memory, disk, network I/O | Every 15s |
| Process List | Running processes, new/exited processes | Every 30s |
| File Integrity | Hash-monitored paths (configurable) | On change |
| Syslog | `/var/log/syslog`, `/var/log/auth.log` | Real-time tail |
| Docker Stats | Container CPU, memory, network | Every 15s (if Docker present) |

### Agent Configuration

After install, edit `/opt/dogclaw-agent/config.yaml`:

```yaml
server: http://<dogclaw-ip>:8000
token: <your-api-token>
host_tags:
  env: production
  team: platform
  region: us-east-1

# Paths to monitor for file integrity changes
file_watch:
  - /etc/passwd
  - /etc/sudoers
  - /etc/ssh/sshd_config
  - /root/.ssh/authorized_keys

# Processes to always alert on if seen
process_deny_list:
  - xmrig
  - minerd
  - ncat
  - mimikatz

# Log files to forward
log_files:
  - path: /var/log/nginx/access.log
    type: nginx_access
  - path: /var/log/nginx/error.log
    type: nginx_error
  - path: /var/log/app/*.log
    type: json
```

Restart the agent after changes: `sudo systemctl restart dogclaw-agent`

### Verify Agent Connection

In the DogClaw UI, go to **Overview → System Status → Agent Health**. Your new host should appear under **Host Health** within 30 seconds of the agent starting.

---

## Connecting AWS

DogClaw ingests from CloudTrail (API audit logs), GuardDuty (threat findings), CloudWatch (metrics and logs), and VPC Flow Logs.

### Step 1 — Create an IAM User for DogClaw

In the AWS Console → IAM → Users → Create User:

- Username: `dogclaw-reader`
- Permissions: Attach these managed policies:
  - `CloudWatchReadOnlyAccess`
  - `AWSCloudTrailReadOnlyAccess`

Add this inline policy for GuardDuty and Config:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "guardduty:ListFindings",
        "guardduty:GetFindings",
        "guardduty:ListDetectors",
        "config:DescribeConfigRules",
        "config:GetComplianceDetailsByConfigRule",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": "*"
    }
  ]
}
```

Create an access key and note the **Access Key ID** and **Secret Access Key**.

### Step 2 — Configure AWS Integration

Add to your `.env` file:

```bash
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1
DOGCLAW_AWS_CLOUDTRAIL_ENABLED=true
DOGCLAW_AWS_GUARDDUTY_ENABLED=true
DOGCLAW_AWS_CLOUDWATCH_ENABLED=true
DOGCLAW_AWS_POLL_INTERVAL_SECONDS=60
```

Or edit `config/integrations/aws.yaml`:

```yaml
cloudtrail:
  enabled: true
  regions:
    - us-east-1
    - us-west-2
  s3_bucket: ""              # Leave empty to use direct API polling
  poll_interval_seconds: 60

guardduty:
  enabled: true
  regions:
    - us-east-1
  poll_interval_seconds: 60

cloudwatch:
  enabled: true
  namespaces:
    - AWS/EC2
    - AWS/Lambda
    - AWS/RDS
    - AWS/ELB

vpc_flow_logs:
  enabled: false             # Set true and provide S3 bucket or CloudWatch log group
  log_group: "/aws/vpc/flowlogs"
```

### Step 3 — Set Up CloudTrail (if not already enabled)

In AWS Console → CloudTrail → Create Trail:
- Trail name: `dogclaw-audit`
- Apply to all regions: Yes
- Log file validation: Enabled
- S3 bucket: Create new or use existing

### Step 4 — (Optional) Push CloudTrail to DogClaw via SNS

For real-time instead of polling, set up an SNS topic to forward CloudTrail events:

1. Create SNS Topic: `dogclaw-cloudtrail-events`
2. Subscribe: HTTP endpoint `http://<dogclaw-ip>:8000/ingest/webhook/aws`
3. In CloudTrail → Edit trail → SNS notification → Select your topic

### Verify

In DogClaw UI → Log Analysis, filter by source `aws`. You should see CloudTrail events within 1-2 minutes.

---

## Connecting Kubernetes

DogClaw monitors Kubernetes cluster events, pod health, resource utilization, and container image vulnerabilities.

### Step 1 — Create RBAC Permissions

Apply this to your cluster:

```yaml
# dogclaw-k8s-rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: dogclaw
  namespace: monitoring
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: dogclaw-reader
rules:
  - apiGroups: [""]
    resources: ["pods", "nodes", "events", "namespaces", "services", "endpoints"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets", "daemonsets", "statefulsets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["metrics.k8s.io"]
    resources: ["pods", "nodes"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dogclaw-reader-binding
subjects:
  - kind: ServiceAccount
    name: dogclaw
    namespace: monitoring
roleRef:
  kind: ClusterRole
  name: dogclaw-reader
  apiGroup: rbac.authorization.k8s.io
```

```bash
kubectl apply -f dogclaw-k8s-rbac.yaml
```

### Step 2 — Get the Service Account Token

```bash
# Kubernetes 1.24+
kubectl create token dogclaw -n monitoring --duration=8760h > k8s-token.txt

# Store in .env
echo "DOGCLAW_K8S_TOKEN=$(cat k8s-token.txt)" >> .env
echo "DOGCLAW_K8S_API_URL=https://<your-cluster-api-server>" >> .env
```

### Step 3 — Deploy Fluent Bit for Log Forwarding

Deploy Fluent Bit as a DaemonSet to forward container logs to DogClaw:

```yaml
# fluent-bit-dogclaw.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
  namespace: monitoring
data:
  fluent-bit.conf: |
    [SERVICE]
        Flush 5

    [INPUT]
        Name              tail
        Path              /var/log/containers/*.log
        Parser            docker
        Tag               k8s.*

    [OUTPUT]
        Name              http
        Match             *
        Host              <dogclaw-ip>
        Port              8000
        URI               /ingest/webhook/kubernetes
        Format            json
        tls               off
```

```bash
kubectl apply -f fluent-bit-dogclaw.yaml
```

### Step 4 — Configure Kubernetes Integration

```yaml
# config/integrations/kubernetes.yaml
enabled: true
api_url: "https://<cluster-api-server>"
token_file: "./k8s-token.txt"   # or set DOGCLAW_K8S_TOKEN env var
verify_ssl: true
namespaces:
  - default
  - production
  - staging
poll_interval_seconds: 30
watch_events: true               # Real-time event streaming
```

### Verify

Go to DogClaw UI → Observability → Containers. Pod names and statuses should populate within 1 minute.

---

## Connecting GitHub

DogClaw scans pull requests for secrets, injection vulnerabilities, and supply chain risks using the DogClaw AI agent.

### Step 1 — Create a GitHub Webhook

In your GitHub repository (or organization):
1. Go to **Settings → Webhooks → Add webhook**
2. Payload URL: `http://<dogclaw-ip>:8000/ingest/webhook/github`
3. Content type: `application/json`
4. Secret: Generate one and add to `.env` as `DOGCLAW_WEBHOOK_SECRET=<secret>`
5. Select events:
   - ✅ Pull requests
   - ✅ Push
   - ✅ Workflow runs
   - ✅ Security advisory

### Step 2 — Create a GitHub Personal Access Token

1. GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens
2. Repository access: Select repositories to monitor
3. Permissions:
   - `pull_requests`: Read
   - `contents`: Read
   - `security_events`: Read
4. Copy the token

```bash
echo "DOGCLAW_GITHUB_TOKEN=github_pat_..." >> .env
echo "DOGCLAW_GITHUB_ORGS=your-org-name" >> .env
```

### Step 3 — Configure PR Review

```yaml
# config/integrations/github.yaml
enabled: true
token: "${DOGCLAW_GITHUB_TOKEN}"
orgs:
  - your-org-name
pr_review:
  enabled: true
  chunk_size_lines: 200          # Analyze in 200-line chunks for accuracy
  block_on_critical: false       # Set true to post blocking status check
  post_comments: true            # Post findings as PR review comments
  secret_patterns:
    - AKIA[A-Z0-9]{16}           # AWS Access Key
    - "-----BEGIN.*PRIVATE KEY"
    - "password\s*=\s*['\"][^'\"]{8,}"
```

### Verify

Open a pull request in a monitored repository. Within 30 seconds, DogClaw should post a review comment (if `post_comments: true`) and the PR should appear in DogClaw UI → AI → Recent PRs Reviewed.

---

## Connecting Okta

Okta's System Log provides authentication events, user lifecycle changes, and policy modifications.

### Step 1 — Create an Okta API Token

1. Okta Admin Console → Security → API → Tokens → Create Token
2. Name: `DogClaw Integration`
3. Copy the token immediately (shown only once)

```bash
echo "DOGCLAW_OKTA_DOMAIN=your-org.okta.com" >> .env
echo "DOGCLAW_OKTA_TOKEN=00B..." >> .env
```

### Step 2 — Configure Okta Integration

```yaml
# config/integrations/okta.yaml
enabled: true
domain: "${DOGCLAW_OKTA_DOMAIN}"
token: "${DOGCLAW_OKTA_TOKEN}"
poll_interval_seconds: 60

# Event types to ingest (leave empty for all)
event_filter:
  - user.session.start
  - user.session.end
  - user.authentication.auth_via_mfa
  - user.authentication.sso
  - user.account.lock
  - group.user_membership.add
  - policy.evaluate_sign_on
  - application.user_membership.add
```

### Step 3 — (Optional) Configure Event Hooks for Real-Time

Instead of polling, configure Okta to push events in real-time:

1. Okta Admin → Workflow → Event Hooks → Create Event Hook
2. Name: `DogClaw Live Feed`
3. URL: `http://<dogclaw-ip>:8000/ingest/webhook/okta`
4. Authentication: Header `Authorization: Bearer <your-dogclaw-api-token>`
5. Subscribe to events: Select all authentication and IAM events

### Verify

Log in to Okta from any device. The `user.session.start` event should appear in DogClaw UI → Log Analysis within 60 seconds (polling) or immediately (event hook).

---

## Connecting Azure AD

Azure Entra ID provides sign-in logs, audit logs, and identity risk events.

### Step 1 — Register an Application in Azure

1. Azure Portal → Azure Active Directory → App registrations → New registration
2. Name: `DogClaw`
3. Supported account types: Single tenant
4. After creation, note the **Application (client) ID** and **Directory (tenant) ID**

### Step 2 — Create a Client Secret

App registration → Certificates & secrets → New client secret
- Description: `dogclaw-secret`
- Expiry: 24 months

Copy the secret value.

### Step 3 — Assign API Permissions

App registration → API permissions → Add a permission → Microsoft Graph:
- `AuditLog.Read.All` (Application)
- `IdentityRiskEvent.Read.All` (Application)
- `Directory.Read.All` (Application)

Click **Grant admin consent**.

```bash
echo "DOGCLAW_AZURE_TENANT_ID=<tenant-id>" >> .env
echo "DOGCLAW_AZURE_CLIENT_ID=<client-id>" >> .env
echo "DOGCLAW_AZURE_CLIENT_SECRET=<secret>" >> .env
```

### Step 4 — Configure Azure Integration

```yaml
# config/integrations/azure.yaml
enabled: true
tenant_id: "${DOGCLAW_AZURE_TENANT_ID}"
client_id: "${DOGCLAW_AZURE_CLIENT_ID}"
client_secret: "${DOGCLAW_AZURE_CLIENT_SECRET}"
poll_interval_seconds: 300       # Graph API rate limits; don't set below 60

sources:
  sign_in_logs: true
  audit_logs: true
  risk_detections: true          # Requires Azure AD P2 license
  risky_users: true              # Requires Azure AD P2 license
```

---

## Connecting GCP

### Step 1 — Create a Service Account

```bash
# In your GCP project
gcloud iam service-accounts create dogclaw-reader \
  --display-name="DogClaw Log Reader"

gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:dogclaw-reader@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/logging.viewer"

gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:dogclaw-reader@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/securitycenter.findingsViewer"

# Download key
gcloud iam service-accounts keys create dogclaw-gcp-key.json \
  --iam-account=dogclaw-reader@YOUR_PROJECT_ID.iam.gserviceaccount.com
```

```bash
echo "DOGCLAW_GCP_PROJECT_ID=your-project" >> .env
echo "DOGCLAW_GCP_CREDENTIALS_FILE=./dogclaw-gcp-key.json" >> .env
```

### Step 2 — Configure GCP Log Sink (Real-Time Push)

```bash
# Create Pub/Sub topic
gcloud pubsub topics create dogclaw-logs

# Create log sink
gcloud logging sinks create dogclaw-sink \
  pubsub.googleapis.com/projects/YOUR_PROJECT_ID/topics/dogclaw-logs \
  --log-filter='severity>=WARNING'

# Create subscription with push to DogClaw
gcloud pubsub subscriptions create dogclaw-push-sub \
  --topic=dogclaw-logs \
  --push-endpoint=http://<dogclaw-ip>:8000/ingest/webhook/gcp \
  --ack-deadline=60
```

---

## Connecting Docker

If you're running containers without Kubernetes, DogClaw can monitor Docker directly.

### Step 1 — Enable Docker API Access

The DogClaw server needs access to the Docker socket. If running DogClaw on the same host as Docker:

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER
newgrp docker

# Verify Docker API access
docker ps
```

### Step 2 — Configure Docker Integration

```yaml
# config/integrations/docker.yaml
enabled: true
socket: "unix:///var/run/docker.sock"
poll_interval_seconds: 15

monitoring:
  container_stats: true      # CPU, memory, network per container
  events: true               # Container start, stop, die events
  log_forwarding: true       # Forward container stdout/stderr
  image_scan: false          # Enable if Trivy is installed

# Alert if these images are deployed
image_deny_list:
  - "*:latest"               # Alert on latest tag (no version pinning)
  - "*/*/xmrig:*"
```

---

## Connecting Databases

DogClaw monitors query performance and detects anomalous query patterns.

### PostgreSQL

```bash
# Enable pg_stat_statements extension on your DB
psql -U postgres -c "CREATE EXTENSION IF NOT EXISTS pg_stat_statements;"

# Create read-only monitoring user
psql -U postgres -c "
CREATE USER dogclaw_monitor WITH PASSWORD '<secure-password>';
GRANT pg_monitor TO dogclaw_monitor;
GRANT SELECT ON pg_stat_statements TO dogclaw_monitor;
"
```

```bash
echo "DOGCLAW_POSTGRES_DSN=postgresql://dogclaw_monitor:<password>@localhost:5432/postgres" >> .env
```

### MySQL / MariaDB

```sql
CREATE USER 'dogclaw'@'%' IDENTIFIED BY '<password>';
GRANT SELECT, PROCESS, REPLICATION CLIENT ON *.* TO 'dogclaw'@'%';
FLUSH PRIVILEGES;
```

```bash
echo "DOGCLAW_MYSQL_DSN=mysql://dogclaw:<password>@localhost:3306/performance_schema" >> .env
```

---

## Connecting OpenTelemetry

Any application instrumented with OpenTelemetry can send traces, metrics, and logs directly to DogClaw's OTLP endpoint.

### OTLP Endpoint

| Protocol | Address | Data |
|---|---|---|
| HTTP (JSON/Protobuf) | `http://<dogclaw-ip>:4318` | Traces, metrics, logs |
| gRPC | `grpc://<dogclaw-ip>:4317` | Traces, metrics, logs |

### Python Application

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace.export import BatchSpanProcessor

provider = TracerProvider()
exporter = OTLPSpanExporter(endpoint="http://<dogclaw-ip>:4318/v1/traces")
provider.add_span_processor(BatchSpanProcessor(exporter))
trace.set_tracer_provider(provider)
```

### Node.js Application

```javascript
const { NodeSDK } = require('@opentelemetry/sdk-node');
const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-http');

const sdk = new NodeSDK({
  traceExporter: new OTLPTraceExporter({
    url: 'http://<dogclaw-ip>:4318/v1/traces',
  }),
});
sdk.start();
```

### Via Environment Variables (Any Language)

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://<dogclaw-ip>:4318
export OTEL_SERVICE_NAME=my-service
export OTEL_RESOURCE_ATTRIBUTES=env=production,team=backend
```

---

## Connecting Logs

### Fluent Bit (Recommended — Works with Any Log Source)

Install Fluent Bit on each host that generates logs:

```bash
curl https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh
```

Configure `/etc/fluent-bit/fluent-bit.conf`:

```ini
[SERVICE]
    Flush       5
    Daemon      Off

[INPUT]
    Name        tail
    Path        /var/log/syslog
    Tag         syslog

[INPUT]
    Name        tail
    Path        /var/log/nginx/access.log
    Tag         nginx.access
    Parser      nginx

[INPUT]
    Name        tail
    Path        /var/log/app/*.log
    Tag         app.log
    Multiline   On

[OUTPUT]
    Name        http
    Match       *
    Host        <dogclaw-ip>
    Port        8000
    URI         /ingest/webhook/fluentbit
    Format      json
    json_date_key  timestamp
    json_date_format iso8601
```

```bash
sudo systemctl enable fluent-bit
sudo systemctl start fluent-bit
```

### Syslog (UDP/TCP)

Configure your hosts, routers, or firewalls to forward syslog to:
- UDP: `<dogclaw-ip>:5140`
- TCP: `<dogclaw-ip>:5140`

Linux rsyslog example (`/etc/rsyslog.d/50-dogclaw.conf`):
```
*.* @@<dogclaw-ip>:5140    # TCP (double @)
# *.* @<dogclaw-ip>:5140   # UDP (single @)
```

```bash
sudo systemctl restart rsyslog
```

---

## Connecting Network Monitoring

DogClaw visualizes network flows and detects anomalous traffic patterns.

### VPC Flow Logs (AWS)

Enable in your AWS VPC:

1. VPC Console → Your VPC → Flow Logs → Create
2. Filter: All
3. Destination: CloudWatch Logs, log group `/aws/vpc/flowlogs`
4. Ensure the CloudWatch integration is configured (see AWS section above)

### pfSense / OPNsense

In your firewall → System → Logging → Remote:
- Remote syslog server: `<dogclaw-ip>:5140`
- Log firewall events: ✅

### Zeek (Deep Packet Inspection)

Install Zeek on a network tap or mirror port host, then configure it to forward JSON logs to DogClaw:

```bash
# /etc/zeek/site/dogclaw.zeek
@load base/frameworks/logging

hook Log::log_stream_policy(rec: Log::Info, id: Log::ID)
{
    # Forward to DogClaw via the json-streaming log format
}
```

Configure Fluent Bit on the Zeek host to forward `/var/log/zeek/current/*.log` to DogClaw (see Fluent Bit section above).

### SNMP (Network Devices)

```yaml
# config/integrations/snmp.yaml
enabled: true
poll_interval_seconds: 60
targets:
  - host: 192.168.1.1
    version: "2c"
    community: "public"
    oids:
      - "1.3.6.1.2.1.2.2.1.10"   # ifInOctets
      - "1.3.6.1.2.1.2.2.1.16"   # ifOutOctets
```

---

## Setting Up Notifications

### Slack

1. Go to https://api.slack.com/apps → Create New App → From scratch
2. App name: `DogClaw`, workspace: yours
3. OAuth & Permissions → Bot Token Scopes: `chat:write`, `channels:read`
4. Install to workspace, copy the **Bot User OAuth Token**

```bash
echo "DOGCLAW_SLACK_TOKEN=xoxb-..." >> .env
echo "DOGCLAW_SLACK_CHANNEL=#security-alerts" >> .env
```

Test it:
```bash
curl -X POST http://localhost:8000/api/response/action \
  -H "Content-Type: application/json" \
  -d '{"action": "test_notification", "target": "slack"}'
```

### PagerDuty

1. PagerDuty → Services → Add Service → DogClaw
2. Integration type: **Events API v2**
3. Copy the **Integration Key**

```bash
echo "DOGCLAW_PAGERDUTY_KEY=..." >> .env
```

Configure routing in `config/notifications.yaml`:

```yaml
pagerduty:
  enabled: true
  routing_key: "${DOGCLAW_PAGERDUTY_KEY}"
  # Only page for critical signals
  severity_filter:
    - critical

slack:
  enabled: true
  token: "${DOGCLAW_SLACK_TOKEN}"
  routes:
    - channel: "#security-critical"
      severity: [critical]
    - channel: "#security-alerts"
      severity: [high, medium]
    - channel: "#ops-monitoring"
      severity: [low, info]
      categories: [infrastructure]
```

---

## Enabling AI

### Anthropic (Claude) — Recommended

```bash
echo "DOGCLAW_AI_PROVIDER=anthropic" >> .env
echo "DOGCLAW_ANTHROPIC_API_KEY=sk-ant-api03-..." >> .env
```

The DogClaw AI Agent automatically gets security context (recent signals, events, host state) injected into every query. No additional configuration needed.

### OpenAI (GPT-4)

```bash
echo "DOGCLAW_AI_PROVIDER=openai" >> .env
echo "DOGCLAW_OPENAI_API_KEY=sk-..." >> .env
```

### Ollama (Local — Air-Gapped / No API Key)

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a security-capable model
ollama pull llama3.1:8b
# or for better analysis quality:
ollama pull llama3.1:70b

echo "DOGCLAW_AI_PROVIDER=ollama" >> .env
echo "DOGCLAW_OLLAMA_BASE_URL=http://localhost:11434" >> .env
echo "DOGCLAW_AI_MODEL=llama3.1:8b" >> .env
```

### Testing the AI Agent

Open the DogClaw UI → **DogClaw AI** tab. Type:

```
What are the highest severity events in the last hour?
```

You should get a contextualized response based on your actual ingested data.

---

## Configuring Detection Rules

### Enable/Disable Built-in Rules

In the UI: **Rules** tab → toggle any rule on or off.

Via API:
```bash
curl -X PATCH http://localhost:8000/api/rules/dogclaw-iam-001/toggle \
  -H "Authorization: Bearer <token>"
```

### Add a Custom Rule

Create `config/rules/my-custom-rule.yaml`:

```yaml
id: custom-001
name: "Production Database Access Outside Business Hours"
severity: high
enabled: true
mitre: "T1078"
description: >
  Alert when production databases are accessed between 11pm and 6am UTC.

conditions:
  - field: event.category
    op: contains
    value: "database"
  - field: host_name
    op: regex
    value: "db-prod-.*"

time_conditions:
  hours_outside: [23, 0, 1, 2, 3, 4, 5]  # 11pm - 6am UTC
```

Rules are hot-reloaded — no restart needed.

### Import SIGMA Rules

```bash
# Import a community SIGMA ruleset
pip install sigma-cli
sigma convert -t dogclaw \
  https://github.com/SigmaHQ/sigma/tree/master/rules/cloud/aws/ \
  -o config/rules/sigma/

# DogClaw auto-loads rules from config/rules/ on startup and file change
```

---

## Verifying Everything Works

Use this checklist after setup:

### Health Check

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "ok",
  "version": "2.4.1",
  "db": "connected",
  "ws_clients": 1,
  "events_total": 847,
  "open_signals": 3
}
```

### Send a Test Event

```bash
curl -X POST http://localhost:8000/ingest/event \
  -H "Content-Type: application/json" \
  -d '{
    "action": "AttachUserPolicy",
    "outcome": "success",
    "source_ip": "185.220.101.44",
    "user_name": "test-user",
    "severity": "critical",
    "raw": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
  }'
```

You should see a CRITICAL signal appear in the UI's threat feed within 1 second.

### Integration Verification

| Integration | How to Verify |
|---|---|
| AWS CloudTrail | Perform any API action in AWS, check Log Analysis within 2 min |
| Kubernetes | `kubectl delete pod test-pod`, check Threat Feed for event |
| GitHub | Open a test PR, check AI → Recent PRs Reviewed |
| Okta | Log in to Okta, check Log Analysis for `user.session.start` |
| Fluent Bit | Append a line to a watched log file, check Log Analysis |
| DogClaw Agent | Watch host appear in Overview → Host Health within 30s |

---

## Troubleshooting

### Server Won't Start

```bash
# Check Python version
python3 --version   # Must be 3.11+

# Check for port conflicts
lsof -i :8000
lsof -i :8125

# Check for import errors
python3 -c "import fastapi, uvicorn, sqlalchemy, pydantic_settings"
```

### UI Loads But No Data

1. Open browser dev tools → Console — look for WebSocket errors
2. Check server logs for errors: `journalctl -u dogclaw -f`
3. Confirm WebSocket: `wscat -c ws://localhost:8000/ws` (install: `npm install -g wscat`)

### Events Not Triggering Alerts

```bash
# List active rules
curl http://localhost:8000/api/rules | python3 -m json.tool

# Check rule is enabled
curl http://localhost:8000/api/rules/dogclaw-iam-001

# Tail server logs for rule evaluation
python server.py --debug 2>&1 | grep "signal_fired\|rule_"
```

### AWS Integration Not Working

```bash
# Verify credentials
aws sts get-caller-identity

# Check CloudTrail is enabled
aws cloudtrail describe-trails

# Test DogClaw can reach CloudTrail API
python3 -c "import boto3; ct = boto3.client('cloudtrail'); print(ct.describe_trails())"
```

### Fluent Bit Not Forwarding Logs

```bash
# Check Fluent Bit is running
sudo systemctl status fluent-bit

# Test connectivity to DogClaw
curl -X POST http://<dogclaw-ip>:8000/ingest/webhook/fluentbit \
  -H "Content-Type: application/json" \
  -d '{"log": "test message", "host": "test-host"}'

# Check Fluent Bit logs
journalctl -u fluent-bit -f
```

### High Memory Usage

If DogClaw is using too much RAM, reduce the correlation window:

```bash
echo "DOGCLAW_CORRELATION_WINDOW_MINUTES=10" >> .env
echo "DOGCLAW_MAX_CORRELATION_ENTITIES=50000" >> .env
```

Then restart: `sudo systemctl restart dogclaw`

---

## Next Steps

Once you have DogClaw running and connected to your stack:

1. **Tune detection rules** — Review the default rules and adjust thresholds to match your environment's baseline.
2. **Build custom dashboards** — The Overview tab is configurable; add widgets for metrics most relevant to your team.
3. **Set up response playbooks** — In `config/playbooks/`, define automated response chains for high-confidence signals.
4. **Enable scheduled reports** — Configure weekly security summary emails in `config/notifications.yaml`.
5. **Integrate your ticketing system** — Connect Jira or ServiceNow so investigations auto-create tickets.
6. **Review the DEVELOPMENT.md** — For extending DogClaw with new integrations or custom detection logic.

**Support:** Open an issue at github.com/your-org/dogclaw or join #dogclaw-users in your organization's Slack.
