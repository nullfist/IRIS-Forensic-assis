# IRIS – Incident Reconstruction & Intelligence System

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?logo=fastapi)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)
![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178C6?logo=typescript)
![Neo4j](https://img.shields.io/badge/Neo4j-5.20-008CC1?logo=neo4j)
![Tests](https://img.shields.io/badge/Tests-32%20passing-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Docker](https://img.shields.io/badge/Docker-Compose%20%2B%20K8s-2496ED?logo=docker)
![Cases](https://img.shields.io/badge/Case%20Management-Autopsy%20Style-blueviolet)

> **See the attack. Tell the story. Stop the threat.**

> **IRIS doesn't just detect attacks. It reconstructs them into explainable stories in seconds.**

IRIS is a production-ready Digital Forensics and Incident Response (DFIR) platform built for enterprise SOC and incident response teams. Drop any digital evidence file — Sysmon logs, Windows Event Logs, PCAP metadata, XML exports, CSV logs, disk images, or memory dumps — and IRIS automatically detects the file type, normalizes every event into a canonical schema, extracts entities, builds an attack graph, reconstructs a chronological timeline, runs 30+ detection rules plus ML anomaly scoring, and presents analysts with fully explainable, MITRE ATT&CK-mapped alerts.

Unlike traditional SIEMs that surface raw alerts, IRIS goes further: it **identifies the attack origin automatically**, **narrates the full kill chain as a human-readable story**, and **makes hidden event relationships explicit** — so analysts understand not just *what* happened, but *how* and *why*.


---

## 🚀 Quick Start

### Windows (one click)
```bat
start-iris.bat
```
This builds all containers, waits for health checks, loads the demo attack scenario, and opens your browser automatically.

### Any OS (Docker)
```bash
git clone https://github.com/your-org/IRIS-Forensic-assis.git
cd IRIS-Forensic-assis
docker-compose up -d
```

| Service | URL | Credentials |
|---|---|---|
| Analyst Console (Frontend) | http://localhost:3000 | — |
| Backend API | http://localhost:8000 | — |
| Interactive API Docs | http://localhost:8000/docs | — |
| Neo4j Browser | http://localhost:7474 | neo4j / irispassword |
| Prometheus | http://localhost:9090 | — |
| Grafana | http://localhost:3001 | admin / admin |

### Load the demo attack scenario
```bash
# PowerShell
$records = Get-Content 'data\scenarios\phishing_to_exfiltration.jsonl' |
  Where-Object { $_.Trim() -ne '' } | ForEach-Object { $_ | ConvertFrom-Json }
$payload = @{
  investigation_id = 'demo-attack-001'
  enrich_graph     = $true
  artifacts        = @(@{ source = 'sysmon'; artifact_name = 'demo.jsonl'; records = $records })
} | ConvertTo-Json -Depth 20 -Compress
Invoke-RestMethod -Uri 'http://localhost:8000/api/v1/ingest' -Method POST -ContentType 'application/json' -Body $payload
```

Or just drag-and-drop any evidence file onto the **Evidence Ingestion** panel in the UI — IRIS auto-detects the format.


---

## 📋 Table of Contents

1. [What's New](#-whats-new)
2. [Case Management](#-case-management)
3. [Core Features](#-core-features)
4. [Evidence Ingestion — File Upload](#-evidence-ingestion--file-upload)
5. [Detection Engine](#-detection-engine)
6. [Architecture](#-architecture)
7. [Data Flow](#-data-flow)
8. [Technology Stack](#-technology-stack)
9. [Project Structure](#-project-structure)
10. [Installation](#-installation)
11. [Running Tests](#-running-tests)
12. [API Reference](#-api-reference)
13. [Detection Rules](#-detection-rules)
14. [Frontend UI Guide](#-frontend-ui-guide)
15. [Deployment](#-deployment)
16. [Monitoring](#-monitoring)
17. [Demo Guide](#-demo-guide)
18. [Security](#-security)
19. [Contributing](#-contributing)
20. [License](#-license)
21. [Support](#-support)


---

## ✨ What's New

### Case Management — Autopsy-Style Workflow (v0.3.0)

#### 🗂️ 1. Cases Home Screen
IRIS now opens to a **case list page** instead of jumping straight into the workbench:
- Every investigation is a named case with type, priority, status, examiner, and organization
- Live event and alert counts per case update as evidence is ingested
- Sort, filter, and delete cases from the table
- URL: `http://localhost:3000/cases`

#### 📄 2. New Case Form
Click **+ New Case** to open a structured creation form:
- Case name, description, type (Incident / Forensic / Threat Hunt), priority (Critical / High / Medium / Low)
- Examiner name and organization
- Free-form tags for categorization
- On submit → case is created and you go straight into the workbench
- URL: `http://localhost:3000/cases/new`

#### 🔍 3. Case-Scoped Workbench
Each case has its own dedicated workbench at `/cases/:caseId`:
- Header shows case name, type, priority, and examiner
- **← Cases** button returns to the case list
- All evidence uploaded inside a case is scoped to that case's `investigation_id`
- Switching cases switches all panels automatically

#### 🛠️ 4. Raw PCAP Support
IRIS now parses **raw binary `.pcap` files** directly — no conversion needed:
- Pure Python struct-based parser — no scapy dependency
- Reads PCAP global header, walks every packet, extracts IPv4 TCP/UDP 5-tuples
- Aggregates packets into flows with src/dst IP, ports, protocol, bytes
- Supports little-endian (`d4 c3 b2 a1`) and big-endian (`a1 b2 c3 d4`) PCAP
- PCAPNG detected and returns a conversion hint

#### 🛠️ 5. PCAP Metadata JSON Wrapper Fix
JSON files with a `{"flows": [...]}` wrapper (like `lateral_movement_metadata.json`) now parse correctly:
- Detector unwraps `flows`, `records`, `events`, `data`, `packets` keys automatically
- No longer misclassified as Sysmon

---

### Intelligence Upgrades (v0.2.0)

#### 🧨 1. Root Cause Detection — Attack Origin Identified
IRIS now automatically identifies the most likely attack entry point from ingested events:
- Scores every event against phase order, parent process indicators, encoded command lines, and temporal position
- Returns the entry event, confidence score (0–100%), human-readable reasoning, and a full attack chain
- The entry node is **automatically highlighted in orange** on the attack graph
- API: `GET /api/v1/analysis/root-cause`
- Example output: *"Attack likely started at 'Process Create on WKSTN-07: WINWORD.EXE' (confidence 91%). Parent process is winword.exe — typical phishing delivery vector. Encoded/obfuscated command line detected."*

#### 🧨 2. Story Mode — One-Click Attack Narrative
Click **📖 Explain Attack** in the workbench header to generate a full narrative:
- Each MITRE ATT&CK phase becomes a numbered chapter with a headline, narrative paragraph, key events, and linked alerts
- Chapters are collapsible — expand any phase to see the detail
- Summary paragraph covers total events, affected users, hosts, and critical alerts
- API: `GET /api/v1/analysis/story`

#### 🧨 3. Correlation Intelligence — Hidden Relationships Made Explicit
IRIS now surfaces 5 types of hidden event connections with plain-English reasoning:
- **Cross-host user activity** — same account on multiple hosts → credential reuse or lateral movement
- **Process chain links** — parent→child via ProcessGuid → direct execution lineage
- **Shared C2/destination** — multiple events to same IP/domain → beaconing or exfiltration
- **Shared malware hash** — same file hash on multiple hosts → malware propagation
- **Temporal activity bursts** — ≥4 events on same host within 60 seconds → automated execution
- API: `GET /api/v1/analysis/correlation-intel`

#### 🧨 4. Attack Graph — WOW Moment
- **Orange double-border node** marks the automatically detected attack origin
- **Red highlighted path** shows the attack progression through the graph
- **▶ Animate path** button pulses each node in sequence to show the attacker's movement
- Nodes not on the attack path dim to 20% opacity so the path stands out immediately
- Entry node and path auto-populate from root cause analysis on every data load

#### 🧨 5. Competitive Edge
> *"IRIS doesn't just detect attacks. It reconstructs them into explainable stories in seconds."*

Where SIEMs give you a list of alerts, IRIS gives you a story. Where other tools show you nodes, IRIS shows you the attacker's path. Every detection comes with a reasoning chain, a confidence score, and three specific next steps — no black box, no guesswork.

---

### File Upload & Auto-Detection (v0.1.1)
- **Drag-and-drop evidence ingestion** — drop any file onto the UI, IRIS detects the format automatically
- **Supported formats**: `.jsonl`, `.json`, `.evtx` (JSON export), `.xml` (wevtutil), `.csv`, `.pcap`/`.pcapng` metadata, `.e01`, `.dd`, `.img`, `.vmdk` (disk images), `.dmp`/`.mem` (memory dumps), `.log`, `.txt`
- **Auto investigation ID** — each upload gets a UUID investigation ID; the UI adopts it automatically so all panels refresh to show the new data
- **Progress bar** per file with detected type label and upload status

### Bug Fixes (v0.1.1)
| # | Bug | Fix |
|---|---|---|
| 1 | `normalize()` required `investigation_id` — broke all tests | Made optional with default |
| 2 | `SysmonParser` stole EVTX records by matching `EventID` alone | Now requires Sysmon channel or `ProcessGuid` |
| 3 | YAML rule files used `yaml.safe_load` on multi-document `---` files | Switched to `yaml.safe_load_all` |
| 4 | All regex `value:` fields in YAML rules used double-quotes with `\.` | Converted to single-quoted strings |
| 5 | `attack_tactics` lists contained `{Technique: T1003.001}` dicts | `DetectionService` now filters to strings only |
| 6 | `PcapMetadataParser` didn't accept `bytes_out`/`bytes_in` field names | Added field aliases |
| 7 | `ExplanationResponse` field mismatch (`confidence_summary` vs `confidence_explanation`) | Both fields now populated |
| 8 | `Alert` schema missing `description` field the frontend expected | Added as alias for `summary` |
| 9 | `GraphResponse` `total_nodes`/`total_edges` hardcoded | Auto-computed in `model_post_init` |
| 10 | `TimelineEntry` missing `event_id` and `source` fields | Added |
| 11 | `TimelinePhaseGroup` `started_at`/`ended_at` vs `start_time`/`end_time` mismatch | Both populated |
| 12 | `IngestRequest`/`IngestArtifact` required fields broke JSON ingestion | Made optional with defaults |
| 13 | Graph/Timeline API endpoints required `investigation_id` — broke initial load | Made optional |
| 14 | `fetchEvents` returned wrong type (`NormalizedEvent[]` vs `EventListResponse`) | Fixed |
| 15 | `vite.config.ts` missing `@vitejs/plugin-react` — JSX broken in build | Added plugin |
| 16 | Nginx had no SPA fallback — 404 on direct URL access | Added `nginx.conf` with `try_files` |
| 17 | Test data had duplicate `event_id` timestamps | Fixed with `time.sleep` between events |
| 18 | `risk_score` range assertion was `<= 1.0` but scale is 0–100 | Fixed to `<= 100.0` |


---

## 🗂️ Case Management

IRIS uses an **Autopsy-style case management flow** — every investigation starts as a named case before you enter the workbench.

### The Flow

```
http://localhost:3000
        │
        ▼
  Cases Home Screen
  ┌────────────────────────────────────────────────────────────────┐
  │  🔍 IRIS                                  [+ New Case]  │
  ├────────────────────────────────────────────────────────────────┤
  │  4 Cases │ 2 Open │ 1 In Progress │ 1 Critical           │
  ├────────────────────────────────────────────────────────────────┤
  │  Case Name         │ Type    │ Priority │ Status  │ Events │
  │  Phishing Jan 25   │ Incident│ Critical │ Open    │  47    │
  │  Threat Hunt Q1    │ Hunt    │ Medium   │ In Prog │  12    │
  └────────────────────────────────────────────────────────────────┘
        │                              │
   Click case                    Click + New Case
        │                              │
        ▼                              ▼
  Incident Workbench          New Case Form
  (scoped to that case)       ┌──────────────────────────────┐
                              │ Case Name *                  │
                              │ Description                  │
                              │ Type: Incident/Forensic/Hunt │
                              │ Priority: Critical/High/Med  │
                              │ Examiner + Organization      │
                              │ Tags                         │
                              │ [Create Case & Open →]       │
                              └──────────────────────────────┘
```

### Case Fields

| Field | Options | Description |
|---|---|---|
| Name | free text | Required. Identifies the investigation |
| Description | free text | Brief scope summary |
| Case Type | `incident` / `forensic` / `threat_hunt` | Classification |
| Priority | `critical` / `high` / `medium` / `low` | Urgency level |
| Examiner | free text | Analyst conducting the investigation |
| Organization | free text | Team or company |
| Tags | free text list | Labels for filtering |
| Status | `open` / `in_progress` / `closed` | Lifecycle state |

### Case API

```bash
# List all cases
GET /api/v1/cases

# Create a case
POST /api/v1/cases
{ "name": "Phishing Jan 2025", "priority": "critical", "case_type": "incident", "examiner": "John Smith" }

# Get a specific case (with live event/alert counts)
GET /api/v1/cases/{case_id}

# Update case status
PATCH /api/v1/cases/{case_id}/status?status=in_progress

# Delete a case
DELETE /api/v1/cases/{case_id}
```

### Routes

| URL | Page |
|---|---|
| `/cases` | Cases home — list all investigations |
| `/cases/new` | New case form |
| `/cases/:caseId` | Incident workbench scoped to that case |


---

## 🎯 Core Features

### Ingestion & Normalization
- **Multi-source ingestion** — Sysmon JSON/JSONL, Windows EVTX (JSON export), PCAP flow metadata, XML event logs, CSV, generic text logs, disk image manifests, memory dump manifests
- **File upload endpoint** — `POST /api/v1/ingest/upload` accepts any evidence file up to 200 MB, auto-detects format, runs the full pipeline
- **Canonical event schema** — every source normalized to `NormalizedEvent` with process, network, file, registry, and authentication contexts
- **Parser provenance** — every event records which parser produced it, timestamp fidelity, and source file reference

### Entity Extraction
Automatically extracts and deduplicates 9 entity types from every event:

| Entity | Example |
|---|---|
| `host` | `WKSTN-07`, `APP-02.corp.local` |
| `user` | `CORP\jdoe`, `svc_backup` |
| `process` | `powershell.exe` (with PID, GUID, command line) |
| `ip` | `185.199.110.153` |
| `domain` | `cdn.update-support.com` |
| `file` | `C:\ProgramData\stage\adsvc.exe` |
| `registry_key` | `HKLM\SOFTWARE\...\Run\Malware` |
| `service` | `TempUpdater` |
| `task` | `\Microsoft\Windows\...` |

### Attack Graph
- **Neo4j-backed** entity relationship graph with graceful in-memory fallback when Neo4j is unavailable
- **BFS attack path traversal** — find shortest path between any two entities up to configurable depth
- **Node sizing by risk score**, border color by severity, shape by entity type
- **Click-to-pivot** — select any node to see linked events, relationships, and quick-filter buttons

### Timeline Reconstruction
- **Chronological ordering** across all sources by UTC timestamp
- **MITRE ATT&CK phase grouping** — Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → Exfiltration → Impact
- **Replay slider** — step through the attack event by event; past events dim, current event highlights
- **Phase inference** — events without explicit phase are classified by event type and content heuristics

### Detection & Intelligence
- **30 built-in YAML rules** across 3 families (process chains, credential access, lateral movement)
- **Isolation Forest ML** anomaly scoring — 6-feature matrix per event, normalized 0–1 score
- **Multi-factor risk scoring** — severity weight + phase weight + confidence + host criticality + anomaly score → 0–100 scale
- **Alert deduplication** — same family + same event set → keep highest risk score only
- **Explainability engine** — every alert gets a reasoning chain, confidence summary, ATT&CK tactics, and 3 next-step recommendations

### Root Cause Detection
- **Automatic attack origin identification** — scores every event against phase order, parent process signals, encoded command lines, and temporal position
- **Confidence score** — 0–100% with plain-English reasoning: *"Attack likely started at WINWORD.EXE → PowerShell (confidence: 91%)"*
- **Attack chain** — ordered list of key events from entry point to final action
- **Graph integration** — entry node auto-highlighted in orange on the attack graph

### Story Mode
- **One-click attack narrative** — click “Explain Attack” to generate a full kill-chain story
- **Phase chapters** — each MITRE ATT&CK phase becomes a collapsible chapter with headline, narrative paragraph, key events, and linked alerts
- **Executive summary** — covers total events, affected users, hosts, and critical alerts in plain English
- **Presentation-ready** — designed to be shown directly to stakeholders and judges

### Correlation Intelligence
- **Cross-host user activity** — same account on multiple hosts → credential reuse or lateral movement
- **Process chain links** — parent→child via ProcessGuid → direct execution lineage
- **Shared C2/destination** — multiple events to same IP/domain → beaconing or exfiltration
- **Shared malware hash** — same file hash on multiple hosts → malware propagation
- **Temporal activity bursts** — ≥4 events on same host within 60 seconds → automated execution
- Every link includes a confidence score and plain-English explanation


---

## 📂 Evidence Ingestion — File Upload

IRIS accepts any digital evidence file. You do not need to know the format in advance — the system detects it automatically.

### How it works

```
File dropped / uploaded
        │
        ▼
FileTypeDetector
  ├── Extension map (.jsonl → sysmon, .xml → xml, .e01 → disk_image …)
  ├── Content sniffing (magic bytes for EVTX, PCAP, XML)
  └── JSON field sniffing (EventID + ProcessGuid → sysmon, src_ip + dst_ip → pcap)
        │
        ▼
EvidenceFileParser
  ├── JSONL / JSON array  → list of dicts
  ├── XML (wevtutil)      → System block + EventData extracted
  ├── CSV                 → DictReader rows
  ├── PCAP metadata JSON  → flow records
  ├── Disk image (binary) → manifest record with guidance
  ├── Memory dump         → manifest record with guidance
  └── Generic .log/.txt   → one record per line
        │
        ▼
NormalizationService → DetectionService → GraphService
        │
        ▼
Investigation ID returned to frontend → all panels refresh
```

### Supported file types

| Extension | Detected As | Parser |
|---|---|---|
| `.jsonl`, `.json` | Sysmon or EVTX (sniffed) | `SysmonParser` / `EvtxJsonParser` |
| `.evtx` | EVTX JSON export | `EvtxJsonParser` |
| `.xml` | Windows XML event log | XML parser (wevtutil format) |
| `.csv` | CSV log | CSV DictReader |
| `.pcap`, `.pcapng` | Raw binary PCAP / PCAPNG | Pure-Python struct parser — extracts TCP/UDP flows, no scapy needed |
| `.log`, `.txt` | Generic log | Line-by-line parser |
| `.e01`, `.dd`, `.img`, `.vmdk`, `.raw` | Disk image | Manifest record + Autopsy/Volatility guidance |
| `.dmp`, `.mem` | Memory dump | Manifest record + Volatility guidance |

### Binary EVTX files
Raw `.evtx` binary files need to be exported first:
```bash
# Windows built-in
wevtutil qe Security /lf:true /f:xml > security_events.xml

# Python (cross-platform)
pip install python-evtx
evtxdump.py Security.evtx > security_events.jsonl
```
Then upload the `.xml` or `.jsonl` output directly to IRIS.

### Upload via UI
1. Open http://localhost:3000
2. The **Evidence Ingestion** panel is at the top of the workbench
3. Drag files onto the drop zone or click to browse
4. Each file shows its detected type and size
5. Click **Analyse All** — IRIS processes all queued files and refreshes every panel

### Upload via API
```bash
curl -X POST http://localhost:8000/api/v1/ingest/upload \
  -F "file=@sysmon_attack_chain.jsonl" \
  -F "investigation_id=inv-001"
```
Response:
```json
{
  "job_id": "3f8a1c2d-...",
  "investigation_id": "inv-001",
  "status": "completed",
  "artifact_count": 1,
  "message": "[SYSMON] sysmon_attack_chain.jsonl → Ingestion completed with 47 normalized events."
}
```


---

## 🔍 Detection Engine

IRIS runs three detection layers in sequence for every ingestion job.

### Layer 1 — Correlation
`CorrelationService` groups raw events before rule evaluation:

- **Process chains** — links parent→child events via `ProcessGuid`/`ParentProcessGuid`, builds full execution trees
- **Credential dumping indicators** — scans all events for LSASS, sekurlsa, minidump, comsvcs.dll, procdump keywords
- **Lateral movement groups** — clusters events by host where `dst_port` is 445, 135, 139, 5985, or 5986

### Layer 2 — Rule Engine
`RuleLoader` reads all `detection/rules/*.yml` files using `yaml.safe_load_all` (multi-document YAML). Each rule document has:

```yaml
rule_id: PROC-008
name: PowerShell Download Cradle
family: suspicious_process_chain
severity: critical
confidence: 0.94
phase: execution
attack_tactics:
  - Execution
  - Defense Evasion
match_any:
  - powershell
  - pwsh
conditions:
  - field: process.command_line
    operator: regex
    value: '(?i)(iex|invoke-expression|invoke-webrequest|wget|curl|downloadfile|downloadstring).*http'
```

`match_any` terms are checked against a haystack of `title + description + process.image + process.command_line + raw_data`. If any term matches, the full conditions list is evaluated.

### Layer 3 — ML Anomaly Detection
`AnomalyDetector` uses scikit-learn `IsolationForest` with a 6-feature matrix per event:

| Feature | Description |
|---|---|
| `severity_rank` | INFO=0, LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4 |
| `category_flag` | 1.0 if network event, else 0.0 |
| `command_length` | Length of process command line |
| `network_bytes` | `bytes_sent + bytes_received` |
| `entity_count` | Number of extracted entities |
| `distinctiveness` | 1 / category frequency (rare categories score higher) |

Scores are min-max normalized to 0–1. Events with fewer than 4 samples use a heuristic fallback scorer.

### Risk Scoring
`RiskScoringService` combines all signals into a 0–100 risk score:

```
risk_score = severity_weight        (10–90)
           + phase_weight           (8–30, exfiltration highest)
           + confidence × 20        (0–20)
           + host_criticality × 8   (4–16)
           + anomaly_score × 12     (0–12)
           capped at 100
```

### Alert Deduplication
Alerts with the same `(family, sorted_event_ids)` key are deduplicated — only the highest risk score survives. Final list is sorted by `risk_score DESC`.

### Explainability
`ReasoningEngine.explain_alert()` produces:
- **Reasoning chain** — detection family match + per-event detail (command line, destination IP) + prioritization rationale
- **Confidence summary** — evidence count, event count, phase context
- **Next steps** — 3 family-specific investigative actions (credential, lateral movement, or generic)
- **ATT&CK tactics** — from rule definition or inferred from phase


---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          IRIS Analyst Console (React 18)                      │
│                                                                                │
│  ┌─────────────────┐  ┌──────────────────┐  ┌────────────┐  ┌─────────────┐  │
│  │ EvidenceUploader│  │  AttackGraph     │  │ Timeline   │  │ AlertPanel  │  │
│  │ (drag-drop any  │  │  (Cytoscape.js)  │  │ Viewer     │  │ +Explanation│  │
│  │  evidence file) │  │                  │  │ (replay)   │  │ Panel       │  │
│  └────────┬────────┘  └────────┬─────────┘  └─────┬──────┘  └──────┬──────┘  │
│           │                   │                   │                │          │
│           └───────────────────┴───────────────────┴────────────────┘          │
│                                       │ REST / multipart                       │
│                              TanStack Query + Zustand                          │
└───────────────────────────────────────┼────────────────────────────────────────┘
                                        │
                    ┌───────────────────▼────────────────────┐
                    │           FastAPI Backend               │
                    │                                         │
                    │  POST /ingest          GET /events      │
                    │  POST /ingest/upload   GET /graph       │
                    │  GET  /ingest/jobs/:id GET /timeline    │
                    │                        GET /alerts      │
                    │                        GET /alerts/:id/ │
                    │                            explanation  │
                    │                                         │
                    │  ┌──────────────────────────────────┐   │
                    │  │         Service Pipeline          │   │
                    │  │                                   │   │
                    │  │  FileTypeDetector                 │   │
                    │  │       ↓                           │   │
                    │  │  EvidenceFileParser               │   │
                    │  │       ↓                           │   │
                    │  │  NormalizationService             │   │
                    │  │  (SysmonParser / EvtxJsonParser / │   │
                    │  │   PcapMetadataParser / XmlParser) │   │
                    │  │       ↓                           │   │
                    │  │  EntityExtractionService          │   │
                    │  │       ↓                           │   │
                    │  │  CorrelationService               │   │
                    │  │       ↓                           │   │
                    │  │  DetectionService                 │   │
                    │  │  (RuleLoader + AnomalyDetector +  │   │
                    │  │   RiskScoringService)             │   │
                    │  │       ↓                           │   │
                    │  │  GraphService → Neo4jGraphClient  │   │
                    │  │       ↓                           │   │
                    │  │  TimelineService                  │   │
                    │  │       ↓                           │   │
                    │  │  ReasoningEngine                  │   │
                    │  └──────────────────────────────────┘   │
                    └───────────────────┬────────────────────┘
                                        │
              ┌─────────────────────────┼──────────────────────────┐
              │                         │                          │
    ┌─────────▼──────────┐   ┌──────────▼──────────┐   ┌──────────▼──────────┐
    │     PostgreSQL 16   │   │      Neo4j 5.20      │   │      Redis 7        │
    │  (events, alerts,   │   │  (entity graph,      │   │  (cache, sessions)  │
    │   jobs — via        │   │   attack paths,      │   │                     │
    │   MemoryStore now,  │   │   OBSERVED_IN rels)  │   │                     │
    │   SQLAlchemy ready) │   │   graceful fallback  │   │                     │
    └────────────────────┘   └─────────────────────┘   └─────────────────────┘
```


---

## 🔄 Data Flow

Every piece of evidence — whether submitted via the UI file uploader, the JSON ingest API, or the demo loader — follows the same pipeline:

```
Step 1  INGESTION
        User uploads file or POSTs JSON records
        → IngestionService.submit_ingestion() creates a job record

Step 2  TYPE DETECTION  (file upload path only)
        FileTypeDetector checks extension + magic bytes + JSON field sniffing
        → EventSource enum assigned (sysmon / evtx / pcap / xml / csv / disk_image / memory_dump / generic)

Step 3  PARSING
        Source-specific parser selected by NormalizationService._select_parser()
        SysmonParser     → EventID 1 (process), 3 (network), 11 (file), 13 (registry)
        EvtxJsonParser   → EventID 4624 (logon), 4697 (service), 4698 (task), 4103/4104 (PowerShell)
        PcapMetadataParser → flow records with src/dst IP, ports, bytes
        XmlParser        → wevtutil XML export, System + EventData blocks
        CsvParser        → DictReader rows
        → list[NormalizedEvent]

Step 4  ENTITY EXTRACTION
        EntityExtractionService.extract_entities() runs on every NormalizedEvent
        → Deduplicates entities by entity_id across host / user / process / ip / domain / file / registry / service / task

Step 5  STORAGE
        MemoryStore.add_events() stores normalized events keyed by investigation_id

Step 6  CORRELATION
        CorrelationService builds process chains (GUID linking), credential indicators, lateral movement groups

Step 7  DETECTION
        RuleLoader loads all detection/rules/*.yml (yaml.safe_load_all)
        AnomalyDetector scores every event with IsolationForest
        DetectionService.build_alerts() merges rule hits + anomaly scores → Alert objects
        RiskScoringService.score_alert() assigns 0–100 risk score
        Deduplication removes duplicate (family, event_ids) pairs

Step 8  GRAPH ENRICHMENT  (if enrich_graph=true)
        GraphService.build_graph() projects entities as nodes, event relationships as edges
        Neo4jGraphClient.upsert_events() writes to Neo4j (graceful fallback to in-memory)

Step 9  TIMELINE
        TimelineService.build_timeline() sorts events by UTC timestamp
        detect_phases() groups into MITRE ATT&CK phase blocks with start/end times

Step 10 EXPLANATION  (on demand)
        ReasoningEngine.explain_alert() generates reasoning chain + next steps per alert
        Returned by GET /api/v1/alerts/{alert_id}/explanation
```


---

## 🛠️ Technology Stack

### Backend — Python 3.11
| Package | Version | Purpose |
|---|---|---|
| `fastapi` | ≥0.111 | Async REST API framework |
| `uvicorn[standard]` | ≥0.30 | ASGI server |
| `pydantic` v2 | ≥2.7 | Schema validation and serialization |
| `pydantic-settings` | ≥2.2 | Environment-based configuration |
| `python-multipart` | ≥0.0.9 | Multipart file upload support |
| `sqlalchemy` | ≥2.0 | ORM (PostgreSQL, schema-ready) |
| `psycopg2-binary` | ≥2.9 | PostgreSQL driver |
| `neo4j` | ≥5.20 | Neo4j Bolt driver |
| `redis` | ≥5.0 | Redis client |
| `scikit-learn` | ≥1.4 | IsolationForest anomaly detection |
| `numpy` | ≥1.26 | Feature matrix construction |
| `python-dateutil` | ≥2.9 | Timestamp parsing (all formats) |
| `PyYAML` | ≥6.0 | Detection rule loading |
| `httpx` | ≥0.27 | Async HTTP client |
| `aiofiles` | ≥23.2 | Async file I/O |
| `pytest` + `pytest-asyncio` | ≥8.2 | Test framework (32 tests) |

### Frontend — TypeScript / React 18
| Package | Version | Purpose |
|---|---|---|
| `react` + `react-dom` | ^18.3 | UI framework |
| `typescript` | ^5.5 | Type safety |
| `vite` + `@vitejs/plugin-react` | ^5.3 / ^4.3 | Build tooling + JSX transform |
| `cytoscape` + `react-cytoscapejs` | ^3.29 / ^2.0 | Attack graph visualization |
| `@tanstack/react-query` | ^5.51 | Server state management + caching |
| `zustand` | ^4.5 | Client state (filters, selected node/alert) |
| `axios` | ^1.7 | HTTP client with upload progress |
| `dayjs` | ^1.11 | Timestamp formatting |
| `clsx` | ^2.1 | Conditional CSS class names |
| `react-router-dom` | ^6.24 | SPA routing |

### Infrastructure
| Component | Image | Purpose |
|---|---|---|
| PostgreSQL | `postgres:16-alpine` | Primary event storage |
| Neo4j Enterprise | `neo4j:5.20-enterprise` | Entity graph + attack paths |
| Redis | `redis:7-alpine` | Cache and session store |
| Nginx | `nginx:1.27-alpine` | Frontend static serving + API proxy + SPA routing |
| Prometheus | `prom/prometheus` | Metrics collection |
| Grafana | `grafana/grafana` | Metrics dashboards |


---

## 📁 Project Structure

```
IRIS-Forensic-assis/
│
├── backend/
│   ├── app/
│   │   ├── api/v1/
│   │   │   ├── cases.py           # GET/POST/PATCH/DELETE /cases
│   │   │   ├── ingest.py          # POST /ingest  +  POST /ingest/upload  +  GET /ingest/jobs/:id
│   │   │   ├── events.py          # GET /events  (filterable)
│   │   │   ├── graph.py           # GET /graph  +  POST /graph/attack-paths
│   │   │   ├── timeline.py        # GET /timeline  +  GET /timeline/replay
│   │   │   ├── alerts.py          # GET /alerts  +  GET /alerts/:id/explanation
│   │   │   ├── analysis.py        # GET /analysis/root-cause + /story + /correlation-intel
│   │   │   └── router.py          # Mounts all routers under /api/v1
│   │   ├── core/
│   │   │   ├── config.py          # Pydantic-settings (env vars)
│   │   │   └── logging.py         # Structured JSON logger
│   │   ├── detection/
│   │   │   ├── anomaly_detector.py  # IsolationForest scorer
│   │   │   └── rule_loader.py       # yaml.safe_load_all multi-doc YAML loader
│   │   ├── explainability/
│   │   │   └── reasoning_engine.py  # Per-alert reasoning chain + next steps
│   │   ├── graph/
│   │   │   ├── graph_service.py     # Build graph, BFS attack paths
│   │   │   └── neo4j_client.py      # Neo4j Bolt driver (graceful fallback)
│   │   ├── models/
│   │   │   └── enums.py             # EventSource, AttackPhase, SeverityLevel, EntityType …
│   │   ├── parsers/
│   │   │   ├── base.py              # Abstract BaseParser
│   │   │   ├── sysmon_parser.py     # EventID 1/3/11/13
│   │   │   ├── evtx_parser.py       # EventID 4624/4697/4698/4103/4104
│   │   │   ├── pcap_parser.py       # Flow metadata JSON
│   │   │   └── file_upload_parser.py  # Auto-detect + parse any evidence file
│   │   ├── repository/
│   │   │   └── memory_store.py      # Thread-safe in-memory store (SQLAlchemy-ready)
│   │   ├── schemas/
│   │   │   ├── base.py              # IRISBaseModel, InvestigationScopedModel
│   │   │   ├── events.py            # NormalizedEvent, ProcessContext, NetworkContext …
│   │   │   ├── alerts.py            # Alert, AlertEvidence, ExplanationResponse
│   │   │   ├── graph.py             # GraphNode, GraphEdge, GraphResponse, AttackPath
│   │   │   ├── timeline.py          # TimelineEntry, TimelinePhaseGroup, ReplayFrame
│   │   │   └── ingestion.py         # IngestRequest, IngestArtifact, IngestJobResponse
│   │   ├── services/
│   │   │   ├── ingestion_service.py      # Orchestrates full pipeline per job
│   │   │   ├── normalization_service.py  # Parser selection + entity extraction
│   │   │   ├── entity_extraction_service.py
│   │   │   ├── correlation_service.py    # Process chains, cred indicators, lat-move groups
│   │   │   ├── detection_service.py      # Rules + anomaly + alert building
│   │   │   ├── risk_scoring_service.py   # 0–100 risk score
│   │   │   ├── timeline_service.py       # Ordering, phase grouping, replay
│   │   │   ├── root_cause_service.py     # Attack origin detection + confidence scoring
│   │   │   ├── story_mode_service.py     # Phase-by-phase attack narrative generator
│   │   │   └── correlation_intelligence_service.py  # Hidden relationship detection
│   │   ├── bootstrap.py             # ServiceContainer + FastAPI dependency providers
│   │   └── main.py                  # FastAPI app + CORS + lifespan
│   ├── Dockerfile
│   └── requirements.txt
│
├── frontend/
│   └── src/
│       ├── api/
│       │   └── client.ts            # axios client + uploadEvidenceFile()
│       ├── components/
│       │   ├── upload/
│       │   │   └── EvidenceUploader.tsx   # Drag-drop file upload panel
│       │   ├── analysis/
│       │   │   ├── RootCausePanel.tsx      # Attack origin + confidence bar + chain
│       │   │   ├── StoryModePanel.tsx      # Collapsible phase chapters narrative
│       │   │   └── CorrelationIntelPanel.tsx # Hidden relationship cards
│       │   ├── graph/
│       │   │   ├── AttackGraph.tsx         # Cytoscape.js graph + path animation
│       │   │   └── NodeDetailsDrawer.tsx   # Slide-in entity detail panel
│       │   ├── timeline/
│       │   │   └── TimelineViewer.tsx      # Phase groups + replay slider
│       │   ├── alerts/
│       │   │   └── AlertPanel.tsx          # Prioritized alert list
│       │   ├── explanations/
│       │   │   └── ExplanationPanel.tsx    # Reasoning + ATT&CK + next steps
│       │   └── filters/
│       │       └── InvestigationFilters.tsx  # Investigation ID + time/host/user/severity/source
│       ├── pages/
│       │   ├── CasesPage.tsx               # Cases home — list all investigations
│       │   ├── NewCasePage.tsx             # New case creation form
│       │   └── IncidentWorkbench.tsx       # Main workbench scoped to a case
│       ├── store/
│       │   └── investigationStore.ts       # Zustand (filters, selectedNode, selectedAlert, investigationId, entryEntityId, attackPathIds, storyModeOpen)
│       ├── styles/
│       │   ├── app.css                     # Full dark-theme design system
│       │   └── cytoscape.css               # Graph canvas overrides
│       └── types/
│           └── api.ts                      # All TypeScript interfaces
│
├── detection/
│   └── rules/
│       ├── process_chains.yml      # PROC-001 … PROC-010
│       ├── credential_access.yml   # CRE-001 … CRE-010
│       └── lateral_movement.yml    # LAT-001 … LAT-010
│
├── graph/
│   ├── cypher/
│   │   ├── upserts.cypher          # MERGE queries for entity/event nodes
│   │   └── traversals.cypher       # Attack path + neighbour queries
│   └── schema/
│       └── neo4j_schema.md         # Node labels, relationship types, indexes
│
├── data/
│   ├── sample_logs/
│   │   ├── sysmon_attack_chain.jsonl      # 47-event phishing→exfil Sysmon scenario
│   │   └── evtx_process_events.jsonl      # EVTX security + PowerShell events
│   ├── pcaps/
│   │   └── lateral_movement_metadata.json # SMB/RPC/WinRM/HTTPS flow metadata
│   └── scenarios/
│       ├── phishing_to_exfiltration.jsonl  # Full combined scenario
│       └── phishing_to_exfiltration.md     # Scenario narrative + expected detections
│
├── tests/
│   ├── unit/
│   │   ├── test_sysmon_parser.py      # 17 tests — parser correctness
│   │   ├── test_normalization.py      # 2 tests — multi-source normalization
│   │   ├── test_detection_rules.py    # 2 tests — rule engine + alert families
│   │   └── test_detection_service.py  # 13 tests — detection, anomaly, risk, dedup
│   ├── integration/
│   │   └── test_ingest_to_graph.py    # End-to-end ingest → graph pipeline
│   └── e2e/
│       └── test_demo_scenario.py      # Full phishing→exfil scenario
│
├── k8s/
│   └── iris-deployment.yaml    # Deployments, StatefulSets, Services, Secrets, Namespace
│
├── configs/
│   ├── development/backend.env
│   ├── observability/prometheus.yml
│   └── production/backend.env.example
│
├── conftest.py              # sys.path fix for pytest
├── pytest.ini               # Test discovery config
├── docker-compose.yml       # Full stack (backend + frontend + postgres + neo4j + redis)
├── start-iris.bat           # Windows one-click launcher
├── stop-iris.bat            # Windows one-click stopper
└── WINDOWS-SETUP.md         # Windows-specific setup notes
```


---

## 📦 Installation

### Prerequisites
- Docker Desktop ≥ 4.x (includes Docker Compose v2)
- 8 GB RAM minimum (16 GB recommended for Neo4j + ML)
- 20 GB free disk space
- Port availability: 3000, 8000, 5432, 7474, 7687, 6379, 9090, 3001

### Option A — Docker Compose (recommended)

```bash
# 1. Clone
git clone https://github.com/your-org/IRIS-Forensic-assis.git
cd IRIS-Forensic-assis

# 2. Start everything
docker-compose up -d

# 3. Verify backend is healthy
curl http://localhost:8000/health
# {"status":"ok","environment":"production"}

# 4. Open the analyst console
open http://localhost:3000        # macOS
start http://localhost:3000       # Windows
xdg-open http://localhost:3000    # Linux
```

### Option B — Windows one-click

```bat
start-iris.bat
```

Automatically: checks Docker, stops old containers, builds images, waits for health, loads demo data, opens browser.

### Option C — Local development (no Docker)

**Backend**
```bash
cd IRIS-Forensic-assis

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS/Linux

# Install dependencies
pip install -r backend/requirements.txt

# Set environment (edit as needed)
copy configs\development\backend.env .env   # Windows
cp configs/development/backend.env .env     # macOS/Linux

# Run backend (Neo4j/Redis optional — graceful fallback)
uvicorn backend.app.main:app --reload --port 8000
```

**Frontend**
```bash
cd frontend
npm install
npm run dev
# Dev server: http://localhost:5173 (proxies /api → localhost:8000)
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_DSN` | `postgresql://iris:iris@localhost:5432/iris` | PostgreSQL connection string |
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j Bolt URI |
| `NEO4J_USER` | `neo4j` | Neo4j username |
| `NEO4J_PASSWORD` | `irispassword` | Neo4j password |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL |
| `LOG_LEVEL` | `INFO` | Logging level |
| `ENVIRONMENT` | `development` | Environment name |
| `MAX_UPLOAD_SIZE_MB` | `100` | Max file upload size |
| `ENABLE_GRAPH_WRITES` | `true` | Write entities to Neo4j |


---

## 🧪 Running Tests

All 32 unit tests pass. Run them locally without Docker:

```bash
# Install deps (if not already done)
pip install -r backend/requirements.txt

# Run all unit tests
pytest tests/unit/ -v

# Run a specific test file
pytest tests/unit/test_sysmon_parser.py -v
pytest tests/unit/test_detection_service.py -v

# Run with coverage report
pytest tests/unit/ --cov=backend/app --cov-report=term-missing

# Run inside Docker
docker-compose exec iris-backend pytest tests/unit/ -v
```

### Test Coverage by File

| File | Tests | What's covered |
|---|---|---|
| `test_sysmon_parser.py` | 17 | Process/network/file/registry parsing, timestamp formats, hash parsing, entity extraction, phase classification |
| `test_normalization.py` | 2 | Multi-source normalization (Sysmon + EVTX + PCAP), field name correctness |
| `test_detection_rules.py` | 2 | Rule engine alert families, evidence presence |
| `test_detection_service.py` | 13 | Office→PowerShell chain, credential dumping, lateral movement, alert building, anomaly scoring, process chain correlation, deduplication, risk scoring, empty input, severity/phase normalization |

### Current Test Results
```
32 passed in 3.47s
```


---

## 📡 API Reference

Full interactive docs at **http://localhost:8000/docs** (Swagger UI).

### Cases

#### `GET /api/v1/cases`
List all cases with live event and alert counts.
```json
{
  "items": [
    {
      "case_id": "fbedc9c3-...",
      "investigation_id": "case-fbedc9c3",
      "name": "Phishing Attack Jan 2025",
      "case_type": "incident",
      "priority": "critical",
      "status": "open",
      "examiner": "John Smith",
      "event_count": 47,
      "alert_count": 5,
      "created_at": "2025-01-12T08:00:00Z"
    }
  ],
  "total": 1
}
```

#### `POST /api/v1/cases`
Create a new case. Returns the case with its auto-generated `investigation_id`.
```json
{
  "name": "Phishing Attack Jan 2025",
  "description": "Finance user opened malicious document",
  "case_type": "incident",
  "priority": "critical",
  "examiner": "John Smith",
  "organization": "ACME Corp SOC",
  "tags": ["phishing", "lateral-movement"]
}
```

#### `GET /api/v1/cases/{case_id}`
Get a specific case with live event and alert counts.

#### `PATCH /api/v1/cases/{case_id}/status?status=in_progress`
Update case status. Valid values: `open`, `in_progress`, `closed`.

#### `DELETE /api/v1/cases/{case_id}`
Delete a case. Returns `{ "deleted": "case_id" }`.

---

### Ingestion

#### `POST /api/v1/ingest`
Submit pre-parsed records as JSON.
```json
{
  "investigation_id": "inv-001",
  "enrich_graph": true,
  "artifacts": [
    {
      "source": "sysmon",
      "artifact_name": "events.jsonl",
      "records": [ { "EventID": 1, "UtcTime": "...", ... } ]
    }
  ]
}
```
Response: `IngestJobResponse` with `job_id`, `investigation_id`, `status`, `message`.

#### `POST /api/v1/ingest/upload`
Upload any evidence file — format auto-detected.
```bash
curl -X POST http://localhost:8000/api/v1/ingest/upload \
  -F "file=@evidence.jsonl" \
  -F "investigation_id=inv-001"
```
- Max file size: 200 MB
- Returns `422` if format cannot be parsed
- Returns `413` if file exceeds size limit
- `investigation_id` is optional — auto-generated UUID if omitted

#### `GET /api/v1/ingest/jobs/{job_id}`
Poll ingestion job status.
```json
{
  "job_id": "3f8a...",
  "status": "completed",
  "processed_artifacts": 1,
  "normalized_events": 47,
  "generated_alerts": 5
}
```

---

### Events

#### `GET /api/v1/events`
List normalized events with optional filters.

| Query param | Type | Description |
|---|---|---|
| `investigation_id` | string | Filter by investigation |
| `source` | enum | `sysmon`, `evtx`, `pcap`, `xml`, `csv`, `generic` |
| `host` | string | Exact host match |
| `user` | string | Exact user match |
| `severity` | enum | `info`, `low`, `medium`, `high`, `critical` |
| `start_time` | ISO 8601 | Events after this time |
| `end_time` | ISO 8601 | Events before this time |

Response: `{ "items": [...], "total": 47 }`

---

### Graph

#### `GET /api/v1/graph`
Get entity relationship graph. Accepts same filters as `/events`.
```json
{
  "investigation_id": "inv-001",
  "nodes": [ { "id": "host:wkstn-07", "label": "WKSTN-07", "type": "host", "risk_score": 72.4 } ],
  "edges": [ { "id": "...", "source": "user:corp\\jdoe", "target": "host:wkstn-07", "relationship": "process_create" } ],
  "total_nodes": 14,
  "total_edges": 23
}
```

#### `POST /api/v1/graph/attack-paths`
Find shortest paths between two entities.
```json
{
  "source_entity_id": "host:wkstn-07",
  "target_entity_id": "host:app-02",
  "investigation_id": "inv-001",
  "max_depth": 5
}
```

---

### Timeline

#### `GET /api/v1/timeline`
Get full timeline with MITRE ATT&CK phase grouping.
```json
{
  "investigation_id": "inv-001",
  "entries": [ { "event_id": "...", "timestamp": "...", "phase": "execution", "title": "...", "severity": "high" } ],
  "phases": [ { "phase": "execution", "start_time": "...", "end_time": "...", "event_count": 8, "entries": [...] } ],
  "total": 47
}
```

#### `GET /api/v1/timeline/replay?investigation_id=inv-001&position=10`
Get replay frame at a specific position (0-indexed).

---

### Alerts

#### `GET /api/v1/alerts`
List alerts. Filterable by `investigation_id`, `severity`, `phase`, `status`, `host`, `user`.
```json
{
  "items": [
    {
      "alert_id": "...",
      "title": "Suspicious Office child process chain",
      "severity": "high",
      "phase": "execution",
      "confidence": 0.88,
      "risk_score": 84.2,
      "tactics": ["Execution", "Defense Evasion"],
      "evidence": [...]
    }
  ],
  "total": 5
}
```

#### `GET /api/v1/alerts/{alert_id}/explanation`
Get full explainability output for an alert.
```json
{
  "alert_id": "...",
  "summary": "Office-spawned scripting or LOLBin execution...",
  "reasoning_chain": [
    { "title": "Detection family matched", "detail": "..." },
    { "title": "Process Create", "detail": "Command line: powershell.exe -enc ..." }
  ],
  "attack_tactics": ["Execution", "Defense Evasion"],
  "confidence_summary": "Confidence 0.88 is supported by 3 evidence items...",
  "next_steps": [
    "Validate the full parent-child process chain...",
    "Review neighboring events on the timeline...",
    "Collect host artifacts..."
  ]
}
```

#### `GET /api/v1/health`
```json
{ "status": "ok", "environment": "production" }
```

---

### Analysis

#### `GET /api/v1/analysis/root-cause`
Identify the most likely attack origin event.

| Query param | Type | Description |
|---|---|---|
| `investigation_id` | string | Filter to a specific investigation |

```json
{
  "found": true,
  "event_id": "a3f8...",
  "title": "Process Create on WKSTN-07: WINWORD.EXE",
  "timestamp": "2025-01-12T08:14:21Z",
  "host": "WKSTN-07",
  "user": "CORP\\jdoe",
  "confidence": 0.91,
  "reasoning": "Attack likely started at 'Process Create on WKSTN-07: WINWORD.EXE' (confidence 91%). Parent process is winword.exe — typical phishing delivery vector. Encoded/obfuscated command line detected.",
  "attack_chain": [
    "[08:14:21] Process Create on WKSTN-07: WINWORD.EXE",
    "[08:14:27] Network Connect on WKSTN-07: powershell.exe (exfiltration)",
    "[08:18:42] Process Create on WKSTN-07: procdump64.exe (credential_access)"
  ],
  "entry_entity_id": "process:{GUID-PARENT}"
}
```

#### `GET /api/v1/analysis/story`
Generate a human-readable attack narrative grouped by MITRE ATT&CK phase.

```json
{
  "investigation_id": "inv-001",
  "title": "Attack Story — 4 phases detected",
  "summary": "This investigation covers 47 events across 4 attack phases: Execution, Credential Theft, Lateral Movement, Exfiltration. Primary account involved: CORP\\jdoe. Affected hosts: WKSTN-07, APP-02, DB-01.",
  "chapters": [
    {
      "step": 1,
      "phase": "execution",
      "headline": "Malicious code executed via WINWORD.EXE",
      "narrative": "Malicious code was executed on the compromised system. Command observed: \"powershell.exe -enc ZQBjAGgAbwAgAHQAZQBzAHQ=…\"",
      "events": [...],
      "alerts": ["Suspicious Office child process chain"],
      "timestamp_start": "2025-01-12T08:14:21Z",
      "timestamp_end": "2025-01-12T08:18:00Z"
    }
  ],
  "total_chapters": 4
}
```

#### `GET /api/v1/analysis/correlation-intel`
Expose hidden event relationships with explicit human-readable reasoning.

```json
{
  "links": [
    {
      "link_id": "link-0001",
      "event_ids": ["a3f8...", "b2c1..."],
      "reason": "Account 'CORP\\jdoe' was active on 3 hosts: WKSTN-07, APP-02, DB-01. This pattern indicates credential reuse or lateral movement.",
      "link_type": "user_across_hosts",
      "shared_attributes": { "user": "CORP\\jdoe", "hosts": ["WKSTN-07", "APP-02", "DB-01"] },
      "confidence": 0.85
    }
  ],
  "total_links": 5,
  "summary": "Found 5 correlation link(s) across 47 events: 1 cross-host user activity | 3 process chain link(s) | 1 shared C2/exfil destination(s)."
}
```


---

## 🎯 Detection Rules

30 built-in rules across 3 YAML files in `detection/rules/`. All rules use single-quoted regex values (YAML-safe) and multi-document `---` format.

### Process Chain Detections (`process_chains.yml`)

| Rule ID | Name | Severity | Confidence | MITRE |
|---|---|---|---|---|
| PROC-001 | Suspicious Office to PowerShell Chain | Critical | 0.92 | T1059.001 |
| PROC-002 | Office to Command Prompt Chain | High | 0.88 | T1059.003 |
| PROC-003 | Office to Script Host Chain | High | 0.85 | T1059.005 |
| PROC-004 | Suspicious Rundll32 Execution | High | 0.80 | T1218.011 |
| PROC-005 | Regsvr32 Scriptlet Execution (Squiblydoo) | High | 0.87 | T1218.010 |
| PROC-006 | MsBuild Code Compilation | High | 0.83 | T1127 |
| PROC-007 | InstallUtil Code Execution | High | 0.84 | T1218.004 |
| PROC-008 | PowerShell Download Cradle | Critical | 0.94 | T1059.001 |
| PROC-009 | CertUtil Download Activity | Medium | 0.78 | T1105 |
| PROC-010 | Bitsadmin Download Activity | Medium | 0.76 | T1105 |

### Credential Access Detections (`credential_access.yml`)

| Rule ID | Name | Severity | Confidence | MITRE |
|---|---|---|---|---|
| CRE-001 | LSASS Memory Access Detected | Critical | 0.95 | T1003.001 |
| CRE-002 | Mimikatz Execution Detected | Critical | 0.97 | T1003.001 |
| CRE-003 | ProDump LSASS Dump | Critical | 0.93 | T1003.001 |
| CRE-004 | Comsvcs.dll MiniDump | Critical | 0.94 | T1003.001 |
| CRE-005 | SAM/SECURITY Hive Access | High | 0.88 | T1003.002 |
| CRE-006 | NTDS.dit Access on Domain Controller | Critical | 0.96 | T1003.003 |
| CRE-007 | DCSync Credential Dumping | Critical | 0.91 | T1003.006 |
| CRE-008 | Kerberoasting Attack Detected | High | 0.85 | T1558.003 |
| CRE-009 | AS-REP Roasting Attack | High | 0.83 | T1558.004 |
| CRE-010 | Credential Enumeration Activity | Medium | 0.75 | T1555 |

### Lateral Movement Detections (`lateral_movement.yml`)

| Rule ID | Name | Severity | Confidence | MITRE |
|---|---|---|---|---|
| LAT-001 | PsExec Remote Execution | High | 0.89 | T1021.002 |
| LAT-002 | SMB Admin Share Access | High | 0.82 | T1021.002 |
| LAT-003 | WMI Remote Execution | High | 0.86 | T1047 |
| LAT-004 | WinRM Remote Execution | High | 0.84 | T1021.006 |
| LAT-005 | RDP Lateral Movement | Medium | 0.75 | T1021.001 |
| LAT-006 | Remote Service Creation | High | 0.87 | T1021 |
| LAT-007 | Remote Scheduled Task Creation | High | 0.85 | T1053.005 |
| LAT-008 | Pass-the-Hash Attack | Critical | 0.90 | T1550.002 |
| LAT-009 | Overpass-the-Hash Attack | Critical | 0.88 | T1550.002 |
| LAT-010 | Anomalous SMB Connection Pattern | Medium | 0.72 | T1021.002 |

### Adding Custom Rules
Create a new `.yml` file in `detection/rules/` using the same multi-document format:
```yaml
---
rule_id: CUSTOM-001
name: My Custom Rule
family: custom_detection
severity: high
confidence: 0.85
phase: execution
attack_tactics:
  - Execution
match_any:
  - suspicious_term
conditions:
  - field: process.command_line
    operator: regex
    value: '(?i)(your_pattern_here)'
```
Rules are loaded automatically on the next ingestion — no restart required.


---

## 🖥️ Frontend UI Guide

The analyst console is a single-page React app at **http://localhost:3000**. All panels update reactively when filters change or new evidence is uploaded.

### Cases Home Screen (landing page)
- **URL**: `http://localhost:3000/cases`
- Table showing all cases with: name, type, priority, status, examiner, event count, alert count, created date
- Stats bar at top: total cases, open, in progress, critical
- Click any row to open that case's workbench
- Click **+ New Case** to create a new investigation
- Click 🗑 on any row to delete a case (with confirmation)

### New Case Form
- **URL**: `http://localhost:3000/cases/new`
- **Case Details**: name (required), description
- **Classification**: type (Incident / Forensic / Threat Hunt), priority (Critical / High / Medium / Low)
- **Examiner Info**: examiner name, organization
- **Tags**: free-form labels, add with Enter key
- Click **Create Case & Open Workbench →** to create and enter the workbench immediately
- Side panel shows "What happens next" and supported evidence types

### Incident Workbench (case-scoped)
- **URL**: `http://localhost:3000/cases/:caseId`
- Header shows: **← Cases** button, case name, type, priority, examiner
- All evidence uploaded is scoped to that case's `investigation_id`
- Switching cases (via ← Cases button) switches all panels automatically

### Evidence Ingestion Panel (top of workbench)
- **Drag-and-drop** any evidence file or click to browse
- Each queued file shows: filename, detected type (e.g. "Sysmon / JSON Lines"), file size
- Click **Analyse All** to process all pending files
- On completion, the investigation ID is adopted and all panels refresh automatically
- Upload status per file: uploading (progress bar) → done (green badge) → error (red badge)

### Investigation Filters (below upload)
| Field | Purpose |
|---|---|
| Investigation ID | Switch between investigations; auto-set after upload |
| Time start / end | Narrow all panels to a time window |
| User | Filter to a specific user account |
| Host | Filter to a specific hostname |
| Severity | Show only events/alerts at or above a severity level |
| Source | Filter by data source (Sysmon, EVTX, PCAP, etc.) |
| Replay mode | Toggle timeline replay slider on/off |

### Attack Graph (center-left)
- **Node shapes by entity type**: rectangle=host, ellipse=user, hexagon=process, diamond=file, V-shape=IP, tag=domain
- **Node size** scales with risk score (larger = higher risk)
- **Border color**: red=critical, orange=high, default=low/medium
- **Click any node** to open the Entity Detail drawer (right side)
- **Zoom**: mouse wheel (sensitivity 0.12), pinch on touch
- **Layout**: COSE force-directed, re-runs when data changes

### Entity Detail Drawer (slides in from right)
- Risk score, severity, attack phase, relationship count
- All entity properties (PID, command line, IP, port, etc.)
- **Quick Pivots**: "Pivot to host" / "Pivot to user" — sets the filter and refreshes all panels
- **Linked Events**: up to 12 events directly connected to this entity

### Timeline Replay (center-left, below graph)
- Events grouped by MITRE ATT&CK phase with start/end timestamps
- Each entry shows: time, title, severity badge, summary, source, host, user
- **Replay slider**: drag to step through events; entries after the current position dim to 45% opacity; current entry gets a blue left-border highlight
- Replay mode must be enabled in filters to activate the slider

### Alert Panel (right sidebar, top)
- Sorted by risk score descending
- Each card shows: severity badge, phase pill, title, description, confidence %, status, evidence count, timestamp
- **Click a card** to select it and load its explanation below

### Explanation Panel (right sidebar, bottom)
- Appears when an alert is selected
- **Reasoning Chain**: numbered steps explaining why the alert fired
- **ATT&CK Tactics**: clickable tactic tags
- **Confidence Summary**: evidence count, event count, phase context
- **Next Steps**: 3 specific investigative actions tailored to the alert family

### Attack Origin Panel (below filters)
- Shows the automatically detected entry point with orange badge
- Confidence bar (0–100%) with gradient fill
- Plain-English reasoning: *"Parent process is winword.exe — typical phishing delivery vector"*
- Ordered attack chain from entry point to final action
- The corresponding graph node is highlighted in orange automatically

### Story Mode Panel (full-width, toggled by 📖 Explain Attack)
- Click **📖 Explain Attack** in the workbench header to open/close
- Numbered chapters, one per MITRE ATT&CK phase detected
- Each chapter: phase pill, headline, expand/collapse toggle, timestamp
- Expanded chapter shows: narrative paragraph, triggered alerts, key events with timestamps
- Executive summary at the top covers all phases, affected users, hosts, critical alerts

### Correlation Intelligence Panel (below timeline)
- Shows hidden event relationships with type icon, confidence badge, plain-English reason
- Link types: 👤 Cross-host user, 🔗 Process chain, 🌐 Shared C2, 🦠 Shared hash, ⚡ Activity burst
- Each card shows the event IDs involved (truncated) and a confidence score
- High confidence (≥85%) shown in green, medium (70–84%) in amber


---

## 🚀 Deployment

### Docker Compose — Development / Small Scale

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f iris-backend
docker-compose logs -f iris-frontend

# Stop and remove containers (keep data volumes)
docker-compose down

# Stop and wipe all data
docker-compose down -v
```

Services started:
- `iris-backend` — FastAPI on port 8000, health check every 30s
- `iris-frontend` — Nginx serving React build on port 3000, proxies `/api` to backend
- `postgres` — PostgreSQL 16 on port 5432
- `neo4j` — Neo4j 5.20 Enterprise on ports 7474 (HTTP) and 7687 (Bolt)
- `redis` — Redis 7 on port 6379

### Kubernetes — Production

```bash
# Create namespace, secrets, and all workloads
kubectl apply -f k8s/iris-deployment.yaml

# Check status
kubectl get pods -n iris
kubectl get services -n iris

# Access frontend (LoadBalancer)
kubectl get svc iris-frontend-service -n iris

# Port-forward for local access
kubectl port-forward svc/iris-frontend-service 3000:80 -n iris
kubectl port-forward svc/iris-backend-service 8000:80 -n iris
```

K8s manifest includes:
- `iris-backend` Deployment — 3 replicas, 512Mi/1Gi memory, liveness + readiness probes
- `iris-frontend` Deployment — 2 replicas, 256Mi/512Mi memory
- `postgres` StatefulSet — 1 replica, 20Gi PVC
- `neo4j` StatefulSet — 1 replica, 50Gi data + 10Gi logs + 5Gi import + 1Gi plugins PVCs
- `redis` Deployment — 1 replica, 5Gi PVC
- `iris-secrets` Secret — all credentials
- `iris` Namespace

### Production Checklist
- [ ] Change all default passwords in `k8s/iris-deployment.yaml` secrets
- [ ] Enable TLS on the Nginx ingress
- [ ] Set `ENVIRONMENT=production` and `LOG_LEVEL=WARNING`
- [ ] Configure persistent volume storage class for your cloud provider
- [ ] Set up external PostgreSQL and Redis for high availability
- [ ] Enable Neo4j Enterprise clustering for graph HA
- [ ] Configure Prometheus scrape targets and Grafana data source


---

## 📊 Monitoring

IRIS ships with Prometheus and Grafana pre-configured.

| Service | URL | Credentials |
|---|---|---|
| Prometheus | http://localhost:9090 | — |
| Grafana | http://localhost:3001 | admin / admin |

### Prometheus config
`configs/observability/prometheus.yml` scrapes the backend `/metrics` endpoint every 15 seconds.

### Key metrics to watch
| Metric | What it tells you |
|---|---|
| `http_requests_total` | API request volume by endpoint and status code |
| `http_request_duration_seconds` | API latency percentiles |
| `iris_events_ingested_total` | Total normalized events processed |
| `iris_alerts_generated_total` | Total alerts generated |
| `iris_graph_nodes_total` | Entity graph size |
| `neo4j_bolt_connections_active` | Active Neo4j connections |
| `process_resident_memory_bytes` | Backend memory usage |

### Health endpoint
```bash
curl http://localhost:8000/health
# {"status":"ok","environment":"production"}
```


---

## 🎬 Demo Guide

Full script in [DEMO.md](./DEMO.md). Summary below.

### The scenario
A finance-themed phishing document (`Q1_Benefits_Update.docm`) is opened by `CORP\jdoe` on `WKSTN-07`. The attack progresses through 6 phases over ~12 minutes:

```
09:14  WINWORD.EXE → powershell.exe (encoded download cradle)
09:14  PowerShell → cdn.update-support.com (C2 beacon)
09:15  Payload dropped: C:\ProgramData\stage\adsvc.exe
09:18  procdump64.exe -ma lsass.exe → credential dump
09:19  Registry Run key persistence added
09:25  sc.exe \\APP-02 create TempUpdater (lateral movement)
09:26  schtasks.exe /create /s DB-01 (second host)
09:33  finance_q1.zip → storage.sync-preview.net (exfiltration, 8.2 MB)
```

### Expected detections
- `suspicious_process_chain` — WINWORD → PowerShell (PROC-001, confidence 0.92)
- `credential_dumping` — procdump64 + lsass (CRE-003, confidence 0.93)
- `lateral_movement` — SMB/RPC to APP-02, WinRM to DB-01 (LAT-001/LAT-006)
- ML anomaly score elevated on the exfiltration flow event

### 5-minute demo flow
1. **Start** — `start-iris.bat` or `docker-compose up -d`
2. **Cases page** — open http://localhost:3000, you land on the cases list
3. **New Case** — click **+ New Case**, fill in name "Phishing Demo", type Incident, priority Critical, click **Create Case & Open Workbench →**
4. **Upload** — drag `data/scenarios/phishing_to_exfiltration.jsonl` onto the Evidence Ingestion panel, click **Analyse All**
5. **Attack Origin** — the orange panel shows WINWORD.EXE as entry point at 91% confidence
6. **Graph** — orange node = attack origin, red path = attacker's route, click **▶ Animate path**
7. **Story** — click **📖 Explain Attack**, expand each chapter to read the narrative
8. **Alerts** — click "Credential dumping indicators" → read reasoning chain + next steps
9. **Timeline** — enable replay, drag slider to 09:18 → watch credential access phase highlight
10. **Back** — click **← Cases** to return to the case list, see event/alert counts updated

### Troubleshooting
```bash
# Containers not starting
docker-compose ps
docker-compose logs iris-backend

# No data appearing after upload
curl http://localhost:8000/api/v1/events
# Should return {"items":[...],"total":N}

# Reset everything
docker-compose down -v && docker-compose up -d
```


---

## 🔒 Security

### Current state (development)
- CORS is open (`allow_origins=["*"]`) — restrict in production
- No authentication on API endpoints — add JWT middleware before exposing externally
- Default credentials in `docker-compose.yml` and `k8s/iris-deployment.yaml` — change before production

### Hardening checklist
- [ ] Add JWT authentication middleware to FastAPI
- [ ] Restrict CORS to your frontend domain
- [ ] Change all default passwords (PostgreSQL, Neo4j, Grafana)
- [ ] Enable TLS on Nginx (see `configs/production/ssl/`)
- [ ] Set `NEO4J_dbms_security_procedures_unrestricted` to only required procedures
- [ ] Enable PostgreSQL SSL
- [ ] Use Kubernetes Secrets from a secrets manager (AWS Secrets Manager, Vault)
- [ ] Enable audit logging for all data access

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes following the guidelines below
4. Run tests: `pytest tests/unit/ -v` — all 32 must pass
5. Commit: `git commit -m 'feat: add your feature'`
6. Push: `git push origin feature/your-feature`
7. Open a Pull Request

### Development guidelines
- **Python**: follow PEP 8, use type hints everywhere, keep functions small
- **TypeScript**: strict mode, no `any` unless unavoidable
- **Tests**: add unit tests for any new parser, service, or detection rule
- **YAML rules**: use single-quoted regex values, multi-document `---` format
- **Schemas**: add `model_post_init` for any field that needs a computed default
- **Parsers**: extend `BaseParser`, implement `can_parse()` and `parse_records()`

### Adding a new evidence source
1. Add the new `EventSource` enum value in `backend/app/models/enums.py`
2. Create `backend/app/parsers/your_parser.py` extending `BaseParser`
3. Register it in `NormalizationService.__init__()` parsers list
4. Add extension mapping in `FileTypeDetector.EXTENSION_SOURCE_MAP`
5. Add a unit test in `tests/unit/test_normalization.py`

---

## 📄 License

MIT License — see [LICENSE](./LICENSE) for full text.

---

## 📧 Support

- **API Docs**: http://localhost:8000/docs (when running)
- **Demo Guide**: [DEMO.md](./DEMO.md)
- **Architecture**: [ARCHITECTURE.md](./ARCHITECTURE.md)
- **Windows Setup**: [WINDOWS-SETUP.md](./WINDOWS-SETUP.md)
- **Issues**: https://github.com/your-org/IRIS-Forensic-assis/issues
- **Email**: security@iris-dfir.example.com

---

## 🙏 Acknowledgments

- [MITRE ATT&CK](https://attack.mitre.org/) — threat taxonomy and technique IDs
- [Sysinternals Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) — endpoint telemetry
- [Neo4j](https://neo4j.com/) — graph database
- [FastAPI](https://fastapi.tiangolo.com/) — Python web framework
- [Cytoscape.js](https://js.cytoscape.org/) — graph visualization
- [scikit-learn](https://scikit-learn.org/) — IsolationForest anomaly detection

---

*IRIS – See the attack. Tell the story. Stop the threat.*
