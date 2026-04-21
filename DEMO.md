# IRIS Demo Guide
## Incident Reconstruction & Intelligence System

This document provides a step-by-step guide for demonstrating IRIS to stakeholders, judges, or potential customers.

---

## Demo Overview

**Duration:** 5-7 minutes  
**Audience:** Security analysts, SOC managers, CISOs, technical judges  
**Goal:** Demonstrate end-to-end incident investigation from raw telemetry to actionable intelligence

---

## Pre-Demo Setup

### 1. Start the IRIS Platform

```bash
# Clone and navigate to the project
cd IRIS-Forensic-assis

# Start all services with Docker Compose
docker-compose up -d

# Wait for services to be ready (check health)
curl http://localhost:8000/health
# Expected: {"status": "ok", "environment": "development"}
```

### 2. Access the Platform

- **Frontend:** http://localhost:3000
- **Backend API:** http://localhost:8000
- **API Documentation:** http://localhost:8000/docs
- **Neo4j Browser:** http://localhost:7474 (neo4j / irispassword)

### 3. Load Sample Data

```bash
# Load the phishing-to-exfiltration attack scenario
curl -X POST http://localhost:8000/api/v1/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "investigation_id": "demo-attack-001",
    "enrich_graph": true,
    "artifacts": [
      {
        "source": "sysmon",
        "artifact_name": "phishing_to_exfiltration.jsonl",
        "records": [PASTE_CONTENT_OF_JSONL_FILE]
      }
    ]
  }'
```

---

## Demo Script

### Act 1: The Alert (1 minute)

**Narrator:** *"It's 9:30 AM on a Monday. Your SOC has just received an alert about suspicious activity on a workstation. Let's see what IRIS reveals."*

**Actions:**
1. Open the IRIS dashboard at http://localhost:3000
2. Point to the **Alerts Panel** on the right
3. Click on the highest severity alert: *"Suspicious Office to PowerShell Chain"*

**What to Say:**
- "Notice the alert shows a **critical severity** detection"
- "The system has identified a suspicious process chain: WINWORD → PowerShell"
- "This is a classic indicator of a malicious document exploiting Office macros"

---

### Act 2: The Attack Graph (2 minutes)

**Narrator:** *"Let's visualize the attack. The graph shows how entities relate to each other."*

**Actions:**
1. Point to the **Attack Graph** in the center
2. Hover over different node types to show the legend:
   - Blue rectangle = Host
   - Green ellipse = User
   - Purple hexagon = Process
   - Orange diamond = File
   - Pink V-shape = IP address
3. Click on the `stage.exe` node to see details

**What to Say:**
- "Each shape represents a different entity type"
- "The size indicates risk score — larger means higher risk"
- "The border color shows severity — red for critical, orange for high"
- "Click any node to see full context and related events"

**Key Observations to Highlight:**
1. WINWORD spawned PowerShell (suspicious)
2. PowerShell downloaded and executed stage.exe
3. stage.exe connected to external C2 server (112.254.134.100)
4. stage.exe accessed LSASS (credential dumping)
5. Connections to FILESERVER-01 and SERVER-DC-01 (lateral movement)

---

### Act 3: The Timeline (2 minutes)

**Narrator:** *"Now let's see the attack unfold chronologically. IRIS automatically segments events into attack phases."*

**Actions:**
1. Scroll to the **Timeline Replay** section
2. Point out the phase groupings:
   - **Execution** — Initial code execution
   - **Credential Access** — LSASS dump
   - **Lateral Movement** — SMB connections to other hosts
   - **Exfiltration** — Data transfer to external server
3. Use the replay slider to step through events

**What to Say:**
- "IRIS automatically categorizes events into MITRE ATT&CK phases"
- "The timeline shows the complete attack narrative from start to finish"
- "Use the replay slider to step through the attack second by second"
- "This helps analysts understand the attacker's methodology and intent"

**Key Timeline Moments:**
1. `09:23:45` — Malicious document opened
2. `09:23:47` — PowerShell download cradle executed
3. `09:23:50` — Malware payload (stage.exe) executed
4. `09:25:15` — LSASS memory dumped via comsvcs.dll
5. `09:28:32` — SMB connections to file server and DC
6. `09:35:12` — Data exfiltrated to external server

---

### Act 4: Alert Explanation (1.5 minutes)

**Narrator:** *"Every alert in IRIS comes with a detailed explanation. Let's see what the system recommends."*

**Actions:**
1. Click on an alert in the Alerts panel
2. View the **Explanation Panel** on the right
3. Scroll through the explanation sections

**What to Say:**
- "The explanation provides the full context of why this alert was triggered"
- "It maps to MITRE ATT&CK techniques for standardized reporting"
- "The evidence chain shows exactly which events triggered the detection"
- "Recommended actions help analysts respond quickly"
- "Next investigative pivots suggest where to look next"

---

### Act 5: Graph Traversal (Optional, 1 minute)

**Narrator:** *"Let's use the graph to find all systems affected by this attack."*

**Actions:**
1. Right-click on the `WORKSTATION-01` node
2. Select "Find connected hosts"
3. Show the traversal results highlighting FILESERVER-01 and SERVER-DC-01

**What to Say:**
- "Graph traversals help identify the blast radius of an attack"
- "We can instantly see which systems the attacker touched"
- "This is invaluable for containment and remediation decisions"

---

## Key Selling Points to Emphasize

### 1. Speed of Investigation
- "What would take hours of manual log review is accomplished in seconds"
- "The graph automatically connects related events across multiple data sources"

### 2. Explainability
- "Every detection comes with a clear explanation — no black box AI"
- "Analysts can see exactly why an alert was generated"

### 3. Attack Narrative Reconstruction
- "IRIS doesn't just show alerts — it tells the story of the attack"
- "Phase detection helps understand attacker methodology"

### 4. Graph-Based Analysis
- "Entity relationships are visualized, making complex attacks easy to understand"
- "Pivoting from any entity reveals the full context"

### 5. MITRE ATT&CK Alignment
- "All detections map to standard ATT&CK techniques"
- "This enables standardized reporting and threat intelligence sharing"

---

## Technical Highlights

### Data Pipeline
- Multi-source ingestion (Sysmon, EVTX, PCAP)
- Real-time normalization and entity extraction
- Graph-based correlation for relationship discovery

### Detection Engine
- Rule-based detections for known TTPs
- Anomaly detection using Isolation Forest ML
- Risk scoring with multiple factors

### Scalability
- Designed for millions of events
- Distributed processing architecture
- Efficient graph traversals with Neo4j

---

## Common Questions & Answers

**Q: How does IRIS compare to SIEM solutions?**  
A: IRIS complements SIEMs by focusing on deep investigation and graph-based analysis. While SIEMs excel at log aggregation, IRIS excels at connecting the dots.

**Q: Can IRIS integrate with existing tools?**  
A: Yes, IRIS has a REST API and can ingest data from any source that produces structured logs.

**Q: What data sources does IRIS support?**  
A: Currently Sysmon, Windows Event Logs (EVTX), and PCAP. The architecture supports adding custom parsers.

**Q: Is IRIS suitable for small teams?**  
A: Yes, IRIS scales from single-server deployments to enterprise clusters.

**Q: How accurate are the detections?**  
A: Rule-based detections have high precision. ML anomaly detection is tuned to minimize false positives while catching novel attacks.

---

## Post-Demo Next Steps

1. **Try it yourself:** Provide access to the demo environment
2. **Custom scenarios:** Offer to load customer-specific data
3. **Integration discussion:** Discuss how IRIS fits into existing security stack
4. **Deployment options:** Review on-prem, cloud, or hybrid deployment

---

## Troubleshooting

### If the demo doesn't load:
```bash
# Check all containers are running
docker-compose ps

# View logs for errors
docker-compose logs iris-backend
docker-compose logs iris-frontend
```

### If data isn't appearing:
```bash
# Verify the ingestion API is working
curl http://localhost:8000/api/v1/events?investigation_id=demo-attack-001

# Check Neo4j connectivity
curl http://localhost:7474
```

### Reset the demo:
```bash
# Stop all services and remove data
docker-compose down -v

# Restart fresh
docker-compose up -d

# Reload sample data