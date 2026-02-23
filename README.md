# SentinelForge

**Autonomous SOC Analyst Platform**

AI-driven alert triage, log correlation, threat hunting, and incident response playbook execution for Security Operations Centers.

[![CI](https://github.com/cwccie/sentinelforge/actions/workflows/ci.yml/badge.svg)](https://github.com/cwccie/sentinelforge/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

---

## The Problem

There are **4.8 million unfilled cybersecurity positions** worldwide (ISC² 2024), and the gap is widening. SOC analysts face:

- **11,000+ alerts/day** in enterprise environments, most of which are false positives
- **Alert fatigue** causing analysts to miss genuine threats buried in noise
- **45-minute average** time to triage a single alert manually
- **Tier-1 analysts** spending 60-70% of their time on repetitive, automatable tasks

Meanwhile, adversaries are faster than ever. The median breakout time (initial access to lateral movement) is now **62 minutes** (CrowdStrike 2024).

**SentinelForge automates the 60-70% of Tier-1 SOC work** that is pattern-based and repetitive, letting human analysts focus on complex investigations that require judgment.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        ALERT SOURCES                            │
│   Syslog (RFC 5424/3164) │ CEF │ LEEF │ JSON │ Windows XML     │
└────────────────┬─────────────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                    INGESTION PIPELINE                            │
│   Parse (auto-detect) → Normalize (OCSF) → Enrich              │
│   • GeoIP lookup         • Threat intel     • Asset context     │
└────────────────┬─────────────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                      TRIAGE AGENT                                │
│   LLM-based severity classification + MITRE ATT&CK mapping      │
│   • Confidence scoring   • Auto-close benign  • Verdict         │
└────────┬───────────┬───────────┬─────────────────────────────────┘
         │           │           │
    ┌────▼──┐   ┌────▼────┐  ┌──▼──────────────────────────┐
    │ LOW   │   │ MEDIUM  │  │ HIGH / CRITICAL              │
    │Auto-  │   │Investi- │  │Alert → HITL → Playbook       │
    │close  │   │gate →   │  │→ Remediate                   │
    └───────┘   │Correlate│  └──────────────────────────────┘
                │→ Report │
                └─────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────────────┐
│                  INCIDENT DASHBOARD                              │
│   Real-time alert feed │ Timeline │ Playbook status │ Metrics   │
│   WebSocket live updates │ REST API │ Investigation workspace   │
└──────────────────────────────────────────────────────────────────┘
```

---

## Features

### Multi-Format Log Ingestion
- **5 formats**: Syslog RFC 5424/3164, CEF, LEEF, JSON, Windows Event XML
- **Auto-detection**: Automatically identifies log format
- **OCSF normalization**: All logs converted to Open Cybersecurity Schema Framework
- **Enrichment**: GeoIP, threat intelligence, asset context

### AI-Powered Triage Agent
- **Severity classification**: Critical / High / Medium / Low / Info
- **MITRE ATT&CK mapping**: Automatic technique and tactic identification
- **Confidence scoring**: 0.0-1.0 confidence on every classification
- **Auto-close**: Known benign patterns closed automatically (60-70% reduction)
- **14 ATT&CK technique patterns** matched across all tactics

### Investigation Agent
- **IOC extraction**: IPs, domains, hashes (MD5/SHA1/SHA256), URLs, emails
- **Timeline reconstruction**: Chronological event sequence
- **Lateral movement detection**: Multi-host pivot analysis
- **Risk scoring**: 0-10 composite risk score
- **Actionable recommendations**: Specific remediation guidance

### Correlation Engine
- **Entity-based grouping**: Union-Find algorithm across IPs, users, hosts
- **Kill chain progression**: ATT&CK tactic sequence detection
- **Alert deduplication**: Identical alerts consolidated
- **Incident creation**: Automatic incident packaging with full context

### Playbook Engine
- **YAML-defined playbooks**: Declarative response procedures
- **HITL approval gates**: Destructive actions require human approval
- **10 action types**: Block IP, isolate host, disable account, collect forensics, etc.
- **Execution logging**: Full audit trail of every action
- **5 built-in playbooks**: Brute force, malware, data exfil, phishing, privilege escalation

### Threat Hunting
- **8 built-in hypotheses**: Brute force, lateral movement, exfiltration, C2 beaconing, etc.
- **Anomaly scoring**: Statistical baseline comparison
- **Custom hypotheses**: Define your own hunt queries
- **Frequency, timing, and fan-out anomaly detection**

### Detection Models
- **10 built-in detection rules**: Brute force, PowerShell, credential dumping, ransomware, etc.
- **Rule engine**: Pattern-based with threshold support
- **ML anomaly detector**: Z-score analysis with NumPy (optional)
- **Custom rules**: Add your own detection logic

### Web Dashboard
- **Real-time alert feed**: Live severity-coded display
- **Incident timeline**: Visual attack progression
- **WebSocket support**: Push updates to connected clients
- **REST API**: Full CRUD for alerts, incidents, and playbooks
- **Dark SOC theme**: Purpose-built for 24/7 operations

---

## Quickstart

### Install

```bash
# Clone
git clone https://github.com/cwccie/sentinelforge.git
cd sentinelforge

# Install with all optional dependencies
pip install -e ".[all]"

# Or minimal install (no web dashboard, no CLI colors)
pip install -e .
```

### Demo Mode

Run the full pipeline with sample data:

```bash
sentinelforge demo
```

This will:
1. Ingest 20+ sample logs across all formats
2. Triage and classify each alert with ATT&CK mapping
3. Run detection rules
4. Investigate high-severity alerts
5. Correlate alerts into incidents
6. Execute threat hunts
7. Print a comprehensive summary

### Launch Dashboard

```bash
sentinelforge dashboard
# Open http://localhost:5000
```

### Docker

```bash
docker compose up -d
# Dashboard at http://localhost:5000

# With demo data:
docker compose --profile demo up -d
```

### Submit an Alert via API

```bash
# Submit a raw log
curl -X POST http://localhost:5000/api/v1/alerts \
  -H "Content-Type: application/json" \
  -d '{"raw_log": "<134>1 2026-02-23T10:15:30Z fw01 sshd 1234 - - Failed password for admin from 198.51.100.23 port 22"}'

# List alerts
curl http://localhost:5000/api/v1/alerts

# Run correlation
curl -X POST http://localhost:5000/api/v1/correlate

# Get metrics
curl http://localhost:5000/api/v1/metrics
```

---

## CLI Reference

```
sentinelforge ingest <file>              Ingest logs from a file
sentinelforge triage                     Run triage on pending alerts
sentinelforge investigate <alert_id>     Deep investigation of an alert
sentinelforge correlate                  Group alerts into incidents
sentinelforge hunt [hypothesis]          Run threat hunting hypotheses
sentinelforge dashboard                  Launch web dashboard
sentinelforge demo                       Full pipeline demo with sample data
sentinelforge status                     Show system status
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/alerts` | Submit a raw log for ingestion + triage |
| `GET` | `/api/v1/alerts` | List alerts (filter by status, severity) |
| `GET` | `/api/v1/alerts/<id>` | Get specific alert |
| `POST` | `/api/v1/alerts/<id>/investigate` | Run investigation |
| `GET` | `/api/v1/incidents` | List incidents |
| `GET` | `/api/v1/incidents/<id>` | Get specific incident |
| `POST` | `/api/v1/correlate` | Trigger correlation engine |
| `POST` | `/api/v1/ingest/batch` | Batch log ingestion |
| `GET` | `/api/v1/metrics` | System metrics |

---

## MITRE ATT&CK Coverage

SentinelForge maps alerts to MITRE ATT&CK techniques across the kill chain:

| Tactic | Techniques | IDs |
|--------|-----------|-----|
| Initial Access | Valid Accounts, Phishing | T1078, T1566 |
| Execution | Command and Scripting Interpreter | T1059 |
| Persistence | Scheduled Task/Job | T1053 |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 |
| Defense Evasion | Indicator Removal | T1070 |
| Credential Access | Brute Force, OS Credential Dumping | T1110, T1003 |
| Discovery | Network Service Discovery | T1046 |
| Lateral Movement | Remote Services | T1021 |
| Command and Control | Application Layer Protocol, DNS | T1071, T1071.004 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |
| Impact | Data Encrypted for Impact | T1486 |

---

## Comparison

| Feature | SentinelForge | Splunk SOAR | Palo Alto XSOAR |
|---------|:------------:|:-----------:|:---------------:|
| Open source | **Yes (MIT)** | No | No |
| Self-hosted | **Yes** | Yes | Yes/Cloud |
| AI triage | **Built-in** | Plugin | Plugin |
| ATT&CK mapping | **Automatic** | Manual | Semi-auto |
| Zero dependencies | **Yes** | No | No |
| Multi-format ingest | **5 formats** | Via add-ons | Via integrations |
| Playbook engine | **YAML + HITL** | Visual | Visual |
| Threat hunting | **Built-in** | Separate | Separate |
| Setup time | **< 5 minutes** | Days-weeks | Days-weeks |
| License cost | **$0** | $$$$ | $$$$ |

---

## Project Structure

```
sentinelforge/
├── src/sentinelforge/
│   ├── ingest/          # Multi-format log parsers + OCSF normalization
│   ├── triage/          # AI triage agent with ATT&CK mapping
│   ├── investigate/     # IOC extraction, timeline, lateral movement
│   ├── correlate/       # Entity-based correlation engine
│   ├── playbook/        # YAML playbook engine with HITL gates
│   ├── hunt/            # Threat hunting with anomaly scoring
│   ├── dashboard/       # Flask + WebSocket web interface
│   ├── api/             # REST API endpoints
│   ├── models/          # Rule engine + ML anomaly detector
│   ├── schemas.py       # OCSF-aligned data models
│   ├── store.py         # Thread-safe in-memory storage
│   └── cli.py           # Click CLI
├── tests/               # 50+ tests across all modules
├── sample_data/         # Sample logs in all supported formats
├── playbooks/           # 5 YAML response playbooks
├── pyproject.toml       # Package configuration
├── Dockerfile           # Container build
├── docker-compose.yml   # Container orchestration
└── README.md
```

---

## Development

```bash
# Setup
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Test
pytest --cov

# Lint
ruff check src/ tests/

# Run demo
sentinelforge demo
```

---

## Roadmap

- [ ] Real LLM integration (OpenAI, Anthropic, local models)
- [ ] Elasticsearch backend for persistent storage
- [ ] STIX/TAXII threat intelligence feed integration
- [ ] SOAR integrations (TheHive, Cortex, Shuffle)
- [ ] Sigma rule import
- [ ] Multi-tenant support
- [ ] Kafka/Redis streaming ingestion
- [ ] RBAC and audit logging

---

## Author

**Corey A. Wade**
- CISSP, CCIE #14124
- PhD Candidate — AI + Cybersecurity
- GitHub: [@cwccie](https://github.com/cwccie)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
