export type EventSource = 'sysmon' | 'evtx' | 'pcap' | 'cloud' | 'manual' | string;
export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical' | 'informational' | string;
export type AttackPhase =
  | 'initial_access'
  | 'execution'
  | 'persistence'
  | 'privilege_escalation'
  | 'defense_evasion'
  | 'credential_access'
  | 'discovery'
  | 'lateral_movement'
  | 'collection'
  | 'command_and_control'
  | 'exfiltration'
  | 'impact'
  | string;
export type AlertStatus = 'new' | 'triaged' | 'investigating' | 'resolved' | 'closed' | string;
export type EntityType = 'host' | 'user' | 'process' | 'file' | 'ip' | 'domain' | 'registry' | string;

export interface EntityRef {
  entity_id: string;
  entity_type: EntityType;
  name: string;
  value?: string;
  risk_score?: number;
  attributes?: Record<string, unknown>;
}

export interface ProcessContext {
  process_guid?: string;
  pid?: number;
  parent_pid?: number;
  image?: string;
  command_line?: string;
  parent_image?: string;
  parent_command_line?: string;
  integrity_level?: string;
  hashes?: Record<string, string>;
}

export interface NetworkContext {
  src_ip?: string;
  src_port?: number;
  dst_ip?: string;
  dst_port?: number;
  protocol?: string;
  direction?: string;
  domain?: string;
  sni?: string;
  bytes_in?: number;
  bytes_out?: number;
}

export interface FileContext {
  path?: string;
  sha256?: string;
  md5?: string;
  operation?: string;
}

export interface RegistryContext {
  key_path?: string;
  value_name?: string;
  value_data?: string;
  operation?: string;
}

export interface NormalizedEvent {
  event_id: string;
  investigation_id?: string;
  timestamp: string;
  source: EventSource;
  category?: string;
  event_type: string;
  severity: SeverityLevel;
  phase?: AttackPhase;
  title: string;
  summary?: string;
  host?: string;
  user?: string;
  process?: ProcessContext;
  network?: NetworkContext;
  file?: FileContext;
  registry?: RegistryContext;
  entities: EntityRef[];
  evidence?: string[];
  confidence?: number;
  parser?: string;
  raw_ref?: string;
  metadata?: Record<string, unknown>;
}

export interface GraphNode {
  id: string;
  label: string;
  type: EntityType;
  risk_score?: number;
  severity?: SeverityLevel;
  phase?: AttackPhase;
  properties?: Record<string, unknown>;
  linked_event_ids?: string[];
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  severity?: SeverityLevel;
  weight?: number;
  properties?: Record<string, unknown>;
}

export interface GraphResponse {
  investigation_id?: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  summary?: {
    node_count: number;
    edge_count: number;
    high_risk_nodes: number;
  };
}

export interface AttackPathRequest {
  source_entity_id: string;
  target_entity_id: string;
}

export interface TimelineEntry {
  event_id: string;
  timestamp: string;
  title: string;
  summary?: string;
  phase: AttackPhase;
  severity: SeverityLevel;
  source: EventSource;
  host?: string;
  user?: string;
  entity_ids?: string[];
  confidence?: number;
}

export interface TimelinePhaseGroup {
  phase: AttackPhase;
  start_time: string;
  end_time: string;
  event_count: number;
  entries: TimelineEntry[];
}

export interface TimelineReplayResponse {
  investigation_id?: string;
  generated_at?: string;
  phases: TimelinePhaseGroup[];
  entries: TimelineEntry[];
}

export interface AlertEvidence {
  event_id?: string;
  entity_id?: string;
  summary: string;
  source?: EventSource;
  timestamp?: string;
}

export interface Alert {
  alert_id: string;
  title: string;
  description?: string;
  severity: SeverityLevel;
  phase: AttackPhase;
  confidence: number;
  status: AlertStatus;
  source: string;
  evidence: AlertEvidence[];
  created_at: string;
  updated_at?: string;
  investigation_id?: string;
  risk_score?: number;
  tags?: string[];
}

export interface AlertListResponse {
  items: Alert[];
  total: number;
}

export interface EventListResponse {
  items: NormalizedEvent[];
  total: number;
}

export interface ExplanationResponse {
  alert_id: string;
  summary: string;
  reasoning_chain: Array<{ title: string; detail: string; supporting_event_ids?: string[] } | string>;
  attack_tactics: string[];
  confidence_summary?: string;
  confidence_explanation?: string;
  next_steps: string[];
  supporting_event_ids?: string[];
}

export interface IngestArtifact {
  artifact_type?: string;
  source: EventSource;
  artifact_name?: string;
  records: Record<string, unknown>[];
  filename?: string;
}

export interface IngestRequest {
  investigation_id?: string;
  artifacts: IngestArtifact[];
  enrich_graph?: boolean;
}

export interface IngestJobResponse {
  job_id: string;
  investigation_id?: string;
  status: string;
  submitted_at?: string;
  artifact_count?: number;
  message?: string;
}

export interface InvestigationFilters {
  time_start?: string;
  time_end?: string;
  user?: string;
  host?: string;
  severity?: SeverityLevel | '';
  source?: EventSource | '';
  replayEnabled: boolean;
}

export interface GraphQueryParams {
  investigation_id?: string;
  host?: string;
  user?: string;
  severity?: string;
  source?: string;
  time_start?: string;
  time_end?: string;
}

export interface TimelineQueryParams extends GraphQueryParams {}

export interface EventQueryParams extends GraphQueryParams {}

// ── Analysis API types ────────────────────────────────────────────────

export interface RootCauseResponse {
  found: boolean;
  message?: string;
  event_id?: string;
  title?: string;
  timestamp?: string;
  host?: string;
  user?: string;
  confidence?: number;
  reasoning?: string;
  attack_chain?: string[];
  entry_entity_id?: string;
}

export interface StoryChapter {
  step: number;
  phase: AttackPhase;
  headline: string;
  narrative: string;
  events: Array<{
    event_id: string;
    title: string;
    timestamp: string;
    host?: string;
    user?: string;
    severity: SeverityLevel;
  }>;
  alerts: string[];
  timestamp_start: string;
  timestamp_end: string;
}

export interface StoryModeResponse {
  investigation_id: string;
  title: string;
  summary: string;
  chapters: StoryChapter[];
  total_chapters: number;
}

export interface CorrelationLink {
  link_id: string;
  event_ids: string[];
  reason: string;
  link_type: string;
  shared_attributes: Record<string, unknown>;
  confidence: number;
}

export interface CorrelationIntelResponse {
  links: CorrelationLink[];
  total_links: number;
  summary: string;
}

// ── Case Management types ─────────────────────────────────────────────

export type CaseType     = 'incident' | 'forensic' | 'threat_hunt';
export type CasePriority = 'low' | 'medium' | 'high' | 'critical';
export type CaseStatus   = 'open' | 'in_progress' | 'closed';

export interface Case {
  case_id: string;
  investigation_id: string;
  name: string;
  description?: string;
  examiner?: string;
  organization?: string;
  case_type: CaseType;
  priority: CasePriority;
  status: CaseStatus;
  tags: string[];
  created_at: string;
  updated_at: string;
  event_count: number;
  alert_count: number;
}

export interface CaseCreate {
  name: string;
  description?: string;
  examiner?: string;
  organization?: string;
  case_type?: CaseType;
  priority?: CasePriority;
  tags?: string[];
}

export interface CaseListResponse {
  items: Case[];
  total: number;
}
