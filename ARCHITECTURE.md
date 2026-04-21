# IRIS – Incident Reconstruction & Intelligence System
## Complete System Architecture & Technical Specification

## 1. System Overview

IRIS is a production-grade DFIR (Digital Forensics and Incident Response) platform designed for enterprise SOC and incident response teams. It ingests heterogeneous forensic telemetry from multiple sources, normalizes events into a canonical format, correlates them into attack narratives, builds entity relationship graphs, scores risk, and presents analysts with timeline-driven incident reconstruction and explainable detections.

### 1.1 Design Principles

1. **Explainability First**: Every detection must have a traceable evidence chain
2. **Scalability**: Handle millions of events across distributed deployments
3. **Modularity**: Pluggable parsers, detectors, and enrichment pipelines
4. **Auditability**: Full provenance tracking from raw artifact to alert
5. **Performance**: Sub-second query response for interactive investigation

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PRESENTATION LAYER                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    React Analyst Console                             │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │   │
│  │  │ Attack Graph│  │   Timeline  │  │    Alerts   │  │ Explanation │ │   │
│  │  │ (Cytoscape) │  │   Viewer    │  │    Panel    │  │    Panel    │ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ REST API / WebSocket (future)
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            API LAYER                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    FastAPI Application                               │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐        │   │
│  │  │  /ingest  │  │  /events  │  │  /graph   │  │ /timeline │        │   │
│  │  └───────────┘  └───────────┘  └───────────┘  └───────────┘        │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐                       │   │
│  │  │  /alerts  │  │  /search  │  │   /cases  │                       │   │
│  │  └───────────┘  └───────────┘  └───────────┘                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ Service Layer
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SERVICE LAYER                                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │   Ingestion     │  │   Normalization │  │    Entity       │             │
│  │   Service       │  │     Service     │  │  Extraction     │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │   Correlation   │  │    Detection    │  │     Risk        │             │
│  │   Service       │  │     Service     │  │   Scoring       │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │    Timeline     │  │     Graph       │  │   Explainability│             │
│  │    Service      │  │     Service     │  │     Engine      │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ Data Access
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DATA LAYER                                           │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐             │
│  │   PostgreSQL    │  │      Neo4j      │  │      Redis      │             │
│  │  (Events/Jobs)  │  │  (Entity Graph) │  │  (Cache/Queue)  │             │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Data Flow (End-to-End)

### 3.1 Ingestion Pipeline

```
1. RAW TELEMETRY INGESTION
   ├── File Upload (Sysmon JSON, EVTX export, PCAP)
   ├── Streaming Events (EDR connectors, SIEM forwarders)
   └── API Submission (external tool integration)
           │
           ▼
2. VALIDATION & DEDUPLICATION
   ├── Schema validation
   ├── Timestamp sanity checks
   ├── Duplicate detection (hash-based)
   └── Artifact metadata extraction
           │
           ▼
3. PARSER ROUTING
   ├── Sysmon Parser → Canonical Events
   ├── EVTX JSON Parser → Canonical Events
   ├── PCAP Parser → Network Events
   └── Custom Parser Plugin → Canonical Events
           │
           ▼
4. NORMALIZATION
   ├── Field mapping to canonical schema
   ├── Timestamp normalization (UTC)
   ├── Confidence scoring
   └── Parser provenance recording
           │
           ▼
5. ENTITY EXTRACTION
   ├── Hosts (from Computer/Hostname fields)
   ├── Users (from User/TargetUser fields)
   ├── Processes (from ProcessGuid/Image/CommandLine)
   ├── Files (from paths, hashes)
   ├── Network (IPs, domains, ports)
   └── Registry keys
           │
           ▼
6. CORRELATION
   ├── Process parent-child linking
   ├── Cross-host user session tracking
   ├── Network flow correlation
   └── Incident clustering
           │
           ▼
7. DETECTION ENGINE
   ├── Rule-based matching (TTP patterns)
   ├── Anomaly detection (ML models)
   ├── Behavioral clustering
   └── Alert generation
           │
           ▼
8. GRAPH PERSISTENCE
   ├── Node upserts (entities)
   ├── Edge creation (relationships)
   ├── Timeline-indexed edges
   └── Attack path materialization
           │
           ▼
9. EXPLAINABILITY
   ├── Evidence chain assembly
   ├── ATT&CK mapping
   ├── Natural language generation
   └── Analyst recommendations
```

### 3.2 Query Flow

```
ANALYST QUERY
      │
      ▼
API LAYER (authentication, rate limiting)
      │
      ▼
SERVICE LAYER (business logic, caching)
      │
      ├──► PostgreSQL (event search, filtering)
      ├──► Neo4j (graph traversals, path finding)
      └──► Redis (cached results, session state)
      │
      ▼
RESPONSE ASSEMBLY
      │
      ├── Event enrichment
      ├── Graph projection
      ├── Timeline reconstruction
      └── Alert correlation
      │
      ▼
JSON RESPONSE TO CLIENT
```

---

## 4. Component Specifications

### 4.1 Ingestion Service

**Responsibilities:**
- Accept multi-format telemetry (files, streams, API)
- Validate payload integrity and schema
- Generate job tracking IDs
- Route to appropriate parsers
- Handle partial failures gracefully

**API Endpoints:**
```
POST /api/v1/ingest
  - Accepts: IngestRequest with artifacts array
  - Returns: IngestJobResponse with job_id

GET /api/v1/ingest/jobs/{job_id}
  - Returns: IngestJobStatusResponse with current status
```

**Data Model:**
```python
class IngestRequest:
    investigation_id: str
    artifacts: list[IngestArtifact]
    enrich_graph: bool = True

class IngestArtifact:
    source: EventSource  # sysmon, evtx, pcap
    artifact_name: str
    records: list[dict]  # parsed JSON records
```

### 4.2 Parser Modules

#### Sysmon Parser
- **Input**: Sysmon JSON export (EventID 1, 3, 11, 13, 15, 17, 19, 21, 22, 23, 24, 25, 26, 27, 28, 29)
- **Output**: NormalizedEvent with ProcessContext, NetworkContext, FileContext, RegistryContext
- **Key Mappings**:
  - EventID 1 → Process Create
  - EventID 3 → Network Connect
  - EventID 11 → File Create
  - EventID 13 → Registry Set
  - EventID 22 → DNS Query

#### EVTX Parser
- **Input**: Windows Event Log JSON export
- **Output**: NormalizedEvent with appropriate context
- **Key Mappings**:
  - Security 4624 → Authentication (Logon)
  - Security 4625 → Authentication (Failed Logon)
  - Security 4648 → Credential Use (RunAs)
  - Security 4672 → Special Privileges
  - Security 4688 → Process Creation
  - Security 4698 → Scheduled Task Creation

#### PCAP Parser
- **Input**: PCAP file or network flow metadata
- **Output**: Network events with connection details
- **Extraction**:
  - TCP/UDP flows (src/dst IP, ports, bytes)
  - DNS queries and responses
  - HTTP/HTTPS metadata (SNI, URLs)
  - TLS certificate metadata

### 4.3 Entity Extraction Service

**Extracted Entity Types:**
```python
class EntityType:
    HOST = "host"           # Computer systems
    USER = "user"           # User accounts
    PROCESS = "process"     # Running processes
    FILE = "file"           # File system objects
    IP = "ip"               # IP addresses
    DOMAIN = "domain"       # DNS domains
    SERVICE = "service"     # Windows services
    TASK = "task"           # Scheduled tasks
    REGISTRY_KEY = "registry_key"  # Registry entries
    ALERT = "alert"         # Detection alerts
```

**Entity Resolution:**
- Stable ID generation: `{entity_type}:{normalized_key}`
- Alias tracking for pivoting
- Risk score propagation

### 4.4 Correlation Engine

**Correlation Strategies:**

1. **Process Chain Correlation**
   - Link parent-child processes via ProcessGuid
   - Build execution trees
   - Detect suspicious process spawning patterns

2. **Cross-Host Correlation**
   - Track user sessions across multiple hosts
   - Identify lateral movement patterns
   - Correlate network connections with process activity

3. **Temporal Correlation**
   - Group events within time windows
   - Detect burst patterns
   - Identify attack phases

4. **Incident Clustering**
   - Group related alerts into incidents
   - Calculate incident severity
   - Track attack progression

### 4.5 Detection Engine

#### Rule-Based Detections

**Rule Format (YAML):**
```yaml
rule_id: PROC-001
name: Suspicious PowerShell Download
description: Detects PowerShell downloading content from external sources
tactic: execution
technique: T1059.001
severity: high
conditions:
  - field: process.image
    operator: contains
    value: powershell
  - field: process.command_line
    operator: regex
    value: "(?i)(downloadstring|invoke-webrequest|wget|curl).*http"
window: 5m
threshold: 1
```

**Detection Categories:**

1. **Process Chain Detections**
   - Suspicious parent-child relationships
   - Living-off-the-land binary (LOLBin) usage
   - Process injection indicators

2. **Credential Access Detections**
   - LSASS access patterns
   - Credential dumping tools (Mimikatz, ProDump)
   - Pass-the-hash indicators

3. **Lateral Movement Detections**
   - SMB/PsExec usage patterns
   - WMI remote execution
   - RDP/WinRM anomalous connections

4. **Exfiltration Detections**
   - Large outbound data transfers
   - DNS tunneling patterns
   - Cloud storage uploads

#### Anomaly Detection

**Models:**
- Isolation Forest for outlier detection
- Statistical baselines for user/host behavior
- Time-series anomaly detection for event volumes

### 4.6 Graph Engine

#### Neo4j Schema

**Node Labels:**
```cypher
(:Host {host_id, name, os, domain, risk_score, first_seen, last_seen})
(:User {user_id, name, domain, risk_score, first_seen, last_seen})
(:Process {process_id, image, pid, command_line, host, risk_score})
(:File {file_id, path, hash, size, host, risk_score})
(:IP {ip_id, address, type, risk_score, first_seen, last_seen})
(:Domain {domain_id, name, risk_score, first_seen, last_seen})
(:Alert {alert_id, rule_id, severity, status, created_at})
```

**Relationship Types:**
```cypher
(:Process)-[:RUNS_ON]->(:Host)
(:Process)-[:RUN_AS]->(:User)
(:Process)-[:SPAWNED]->(:Process)
(:Process)-[:CONNECTED_TO]->(:IP)
(:Process)-[:CONNECTED_TO]->(:Domain)
(:Process)-[:ACCESSED]->(:File)
(:Process)-[:MODIFIED]->(:RegistryKey)
(:User)-[:LOGGED_INTO]->(:Host)
(:User)-[:USED]->(:Process)
(:Host)-[:COMMUNICATED_WITH]->(:Host)
(:Alert)-[:RELATED_TO]->(:Process)
(:Alert)-[:AFFECTS]->(:Host)
(:Alert)-[:INVOLVES]->(:User)
```

**Key Traversals:**
```cypher
// Find all processes spawned by a suspicious process
MATCH (p:Process {process_id: $id})-[:SPAWNED*]->(child:Process)
RETURN child

// Find attack paths between two hosts
MATCH path = shortestPath(
  (h1:Host {name: $source})-[*]-(h2:Host {name: $target})
)
RETURN path

// Find all alerts affecting a user
MATCH (a:Alert)-[:INVOLVES]->(u:User {user_id: $user_id})
RETURN a ORDER BY a.created_at DESC
```

### 4.7 Timeline Engine

**Phase Detection:**
```python
class AttackPhase:
    INITIAL_ACCESS = "initial_access"        # Phishing, drive-by
    EXECUTION = "execution"                  # Code execution
    PERSISTENCE = "persistence"              # Autostart, scheduled tasks
    PRIVILEGE_ESCALATION = "privilege_escalation"  # UAC bypass, token impersonation
    DEFENSE_EVASION = "defense_evasion"      # Timestomping, obfuscation
    CREDENTIAL_ACCESS = "credential_access"  # LSASS dump, credential theft
    DISCOVERY = "discovery"                  # Network scanning, system info
    LATERAL_MOVEMENT = "lateral_movement"    # SMB, PsExec, WMI
    COLLECTION = "collection"                # Data staging
    EXFILTRATION = "exfiltration"            # Data transfer out
    IMPACT = "impact"                        # Encryption, destruction
```

**Timeline Entry Structure:**
```python
class TimelineEntry:
    timestamp: datetime
    phase: AttackPhase
    event_ids: list[str]
    summary: str
    severity: SeverityLevel
    affected_entities: list[EntityRef]
```

### 4.8 Explainability Engine

**Explanation Template:**
```
ALERT: {rule_name}
SEVERITY: {severity}
ATT&CK: {tactic} / {technique}

WHAT HAPPENED:
{natural_language_description}

EVIDENCE CHAIN:
1. {timestamp} - {event_description}
2. {timestamp} - {event_description}
...

IMPACTED ASSETS:
- Hosts: {affected_hosts}
- Users: {affected_users}
- Processes: {suspicious_processes}

RECOMMENDED ACTIONS:
1. {action}
2. {action}
...

NEXT INVESTIGATIVE PIVOTS:
- Examine {entity} for additional context
- Check {host} for related activity
- Review {time_window} for similar patterns
```

---

## 5. API Specification

### 5.1 Ingestion Endpoints

```
POST /api/v1/ingest
  Request: IngestRequest
  Response: IngestJobResponse (202 Accepted)

GET /api/v1/ingest/jobs/{job_id}
  Response: IngestJobStatusResponse
```

### 5.2 Event Endpoints

```
GET /api/v1/events
  Query Params: investigation_id, host, user, severity, source, time_start, time_end, limit, offset
  Response: EventListResponse

GET /api/v1/events/{event_id}
  Response: NormalizedEvent
```

### 5.3 Graph Endpoints

```
GET /api/v1/graph
  Query Params: investigation_id, host, user, depth, node_types, edge_types
  Response: GraphResponse { nodes, edges }

GET /api/v1/graph/nodes/{node_id}
  Response: GraphNode with relationships

GET /api/v1/graph/traverse
  Query Params: start_node_id, relationship_type, max_depth
  Response: TraversalResponse { paths, visited_nodes }
```

### 5.4 Timeline Endpoints

```
GET /api/v1/timeline
  Query Params: investigation_id, phase, severity, time_start, time_end
  Response: TimelineResponse { entries }

GET /api/v1/timeline/phases
  Query Params: investigation_id
  Response: PhaseSummaryResponse
```

### 5.5 Alert Endpoints

```
GET /api/v1/alerts
  Query Params: investigation_id, status, severity, rule_id, time_start, time_end
  Response: AlertListResponse

GET /api/v1/alerts/{alert_id}
  Response: AlertResponse

GET /api/v1/alerts/{alert_id}/explanation
  Response: ExplanationResponse

PATCH /api/v1/alerts/{alert_id}
  Request: UpdateAlertRequest { status, notes }
  Response: AlertResponse
```

---

## 6. Technology Stack Justification

### Backend
- **FastAPI**: Async-capable, auto OpenAPI docs, Pydantic validation, high performance
- **PostgreSQL**: ACID compliance, full-text search, JSON support, mature ecosystem
- **Neo4j**: Native graph storage, Cypher query language, efficient traversals
- **Redis**: In-memory caching, pub/sub, simple queue capabilities
- **Pydantic v2**: Type-safe data validation, serialization

### Frontend
- **React 18**: Concurrent rendering, Suspense, mature ecosystem
- **TypeScript**: Type safety, better IDE support, fewer runtime errors
- **Vite**: Fast HMR, optimized builds
- **Cytoscape.js**: Purpose-built for graph visualization
- **TanStack Query**: Server state management, caching, background updates
- **Zustand**: Lightweight state management

### ML/Analytics
- **scikit-learn**: Isolation Forest, clustering, statistical models
- **numpy**: Efficient numerical operations

---

## 7. Scalability Considerations

### Horizontal Scaling
- Stateless API servers behind load balancer
- Redis cluster for distributed caching
- Neo4j causal clustering for read scaling
- PostgreSQL read replicas

### Data Partitioning
- Events partitioned by investigation_id
- Graph partitioned by host clusters
- Time-based indexing for timeline queries

### Performance Optimizations
- Connection pooling for all databases
- Query result caching with TTL
- Batch operations for graph writes
- Async I/O throughout

---

## 8. Failure Handling

### Ingestion Failures
- Partial artifact processing with error reporting
- Dead-letter queue for failed parses
- Retry with exponential backoff

### Graph Write Failures
- Idempotent upsert operations
- Event storage decoupled from graph writes
- Background graph rebuild jobs

### API Failures
- Graceful degradation (return available data)
- Circuit breaker pattern for external services
- Comprehensive error responses with correlation IDs

---

## 9. Security Considerations

### Authentication & Authorization
- JWT-based authentication
- Role-based access control (analyst, admin, readonly)
- Investigation-level permissions

### Data Protection
- Encryption at rest (database, files)
- TLS for all network communication
- Audit logging for all data access

### Input Validation
- Schema validation on all inputs
- File type verification
- Size limits and rate limiting