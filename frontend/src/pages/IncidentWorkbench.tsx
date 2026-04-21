import { useEffect, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate, useParams } from 'react-router-dom';
import {
  fetchAlerts, fetchCase, fetchEvents,
  fetchGraph, fetchRootCause, fetchTimeline
} from '../api/client';
import AlertPanel from '../components/alerts/AlertPanel';
import CorrelationIntelPanel from '../components/analysis/CorrelationIntelPanel';
import RootCausePanel from '../components/analysis/RootCausePanel';
import StoryModePanel from '../components/analysis/StoryModePanel';
import EvidenceUploader from '../components/upload/EvidenceUploader';
import ExplanationPanel from '../components/explanations/ExplanationPanel';
import InvestigationFilters from '../components/filters/InvestigationFilters';
import AttackGraph from '../components/graph/AttackGraph';
import NodeDetailsDrawer from '../components/graph/NodeDetailsDrawer';
import TimelineViewer from '../components/timeline/TimelineViewer';
import { useInvestigationStore } from '../store/investigationStore';

export default function IncidentWorkbench() {
  const { caseId } = useParams<{ caseId: string }>();
  const navigate = useNavigate();
  const filters          = useInvestigationStore((s) => s.filters);
  const investigationId  = useInvestigationStore((s) => s.investigationId);
  const storyModeOpen    = useInvestigationStore((s) => s.storyModeOpen);
  const toggleStoryMode  = useInvestigationStore((s) => s.toggleStoryMode);
  const setEntryEntityId = useInvestigationStore((s) => s.setEntryEntityId);
  const setAttackPathIds = useInvestigationStore((s) => s.setAttackPathIds);
  const clearAttackPath  = useInvestigationStore((s) => s.clearAttackPath);
  const setInvestigationId = useInvestigationStore((s) => s.setInvestigationId);

  // Load case and adopt its investigation_id
  const caseQuery = useQuery({
    queryKey: ['case', caseId],
    queryFn: () => fetchCase(caseId!),
    enabled: !!caseId,
  });

  useEffect(() => {
    if (caseQuery.data?.investigation_id) {
      setInvestigationId(caseQuery.data.investigation_id);
    }
  }, [caseQuery.data, setInvestigationId]);

  const queryFilters = useMemo(() => ({
    investigation_id: investigationId,
    host:       filters.host       || undefined,
    user:       filters.user       || undefined,
    severity:   filters.severity   || undefined,
    source:     filters.source     || undefined,
    start_time: filters.time_start || undefined,
    end_time:   filters.time_end   || undefined
  }), [filters, investigationId]);

  const eventsQuery  = useQuery({ queryKey: ['events',  queryFilters], queryFn: () => fetchEvents(queryFilters) });
  const graphQuery   = useQuery({ queryKey: ['graph',   queryFilters], queryFn: () => fetchGraph(queryFilters),   enabled: !!investigationId });
  const timelineQuery = useQuery({ queryKey: ['timeline', queryFilters], queryFn: () => fetchTimeline(queryFilters), enabled: !!investigationId });
  const alertsQuery  = useQuery({ queryKey: ['alerts',  queryFilters], queryFn: () => fetchAlerts(queryFilters) });
  const rootCauseQuery = useQuery({ queryKey: ['root-cause', investigationId], queryFn: () => fetchRootCause(investigationId), enabled: !!investigationId });

  // Auto-highlight entry node whenever root cause resolves
  useEffect(() => {
    if (rootCauseQuery.data?.found && rootCauseQuery.data.entry_entity_id) {
      setEntryEntityId(rootCauseQuery.data.entry_entity_id);
      // Build attack path from attack_chain event titles mapped to graph node IDs
      if (graphQuery.data && rootCauseQuery.data.attack_chain) {
        const pathIds = graphQuery.data.nodes
          .filter((n) => n.type === 'process' || n.type === 'host')
          .slice(0, 8)
          .map((n) => n.id);
        setAttackPathIds(pathIds);
      }
    }
  }, [rootCauseQuery.data, graphQuery.data, setEntryEntityId, setAttackPathIds]);

  const eventItems = eventsQuery.data?.items ?? [];

  return (
    <div className="workbench">
      {/* ── Header ── */}
      <header className="workbench__header">
        <div className="workbench__header-left">
          <button
            className="button button--ghost workbench__back"
            onClick={() => navigate('/cases')}
            type="button"
          >
            ← Cases
          </button>
          <div>
            <p className="eyebrow">IRIS DFIR Platform</p>
            <h1>{caseQuery.data?.name ?? 'Incident Workbench'}</h1>
            {caseQuery.data && (
              <p className="workbench__case-meta">
                {caseQuery.data.case_type.replace('_', ' ')} &nbsp;·&nbsp;
                <span className={`cases-priority priority--${caseQuery.data.priority}`}>
                  {caseQuery.data.priority}
                </span>
                {caseQuery.data.examiner && (
                  <> &nbsp;·&nbsp; {caseQuery.data.examiner}</>
                )}
              </p>
            )}
            <p className="workbench__pitch">
              IRIS doesn't just detect attacks — it reconstructs them into explainable stories in seconds.
            </p>
          </div>
        </div>
        <div className="workbench__header-right">
          <div className="workbench__stats">
            <div className="stat-tile">
              <span className="stat-tile__label">Events</span>
              <strong>{eventsQuery.data?.total ?? 0}</strong>
            </div>
            <div className="stat-tile">
              <span className="stat-tile__label">Entities</span>
              <strong>{graphQuery.data?.nodes.length ?? 0}</strong>
            </div>
            <div className="stat-tile">
              <span className="stat-tile__label">Alerts</span>
              <strong>{alertsQuery.data?.total ?? 0}</strong>
            </div>
          </div>
          <div className="workbench__actions">
            <button
              className="button button--story"
              onClick={toggleStoryMode}
              type="button"
            >
              {storyModeOpen ? '✕ Close Story' : '📖 Explain Attack'}
            </button>
            <button
              className="button button--ghost"
              onClick={clearAttackPath}
              type="button"
            >
              Clear highlights
            </button>
          </div>
        </div>
      </header>

      {/* ── Story Mode (full-width when open) ── */}
      {storyModeOpen && (
        <section className="panel story-panel">
          <div className="panel__header">
            <div>
              <h2>Attack Story</h2>
              <p>One-click narrative reconstruction — phase by phase, event by event.</p>
            </div>
          </div>
          <StoryModePanel />
        </section>
      )}

      {/* ── Evidence Upload ── */}
      <section className="workbench__upload panel">
        <div className="panel__header">
          <div>
            <h2>Evidence Ingestion</h2>
            <p>Drop any digital evidence file — EVTX, Sysmon JSON, PCAP metadata, XML, CSV, disk image manifest.</p>
          </div>
        </div>
        <EvidenceUploader investigationId={investigationId} />
      </section>

      {/* ── Filters ── */}
      <section className="workbench__filters panel">
        <InvestigationFilters />
      </section>

      {/* ── Main grid ── */}
      <section className="workbench__main">
        <div className="workbench__primary">

          {/* Root Cause */}
          <div className="panel root-cause-panel">
            <div className="panel__header">
              <div>
                <h2>Attack Origin</h2>
                <p>Automatically identified entry point with confidence score and reasoning.</p>
              </div>
            </div>
            <RootCausePanel />
          </div>

          {/* Attack Graph */}
          <div className="panel graph-panel">
            <div className="panel__header">
              <div>
                <h2>Attack Graph</h2>
                <p>Entity relationships, process chains, and infrastructure pivots. Orange node = attack origin.</p>
              </div>
              <span className="panel__meta">
                {graphQuery.isLoading ? 'Building graph…' : `${graphQuery.data?.edges.length ?? 0} relationships`}
              </span>
            </div>
            <AttackGraph graph={graphQuery.data} loading={graphQuery.isLoading} />
          </div>

          {/* Timeline */}
          <div className="panel timeline-panel">
            <div className="panel__header">
              <div>
                <h2>Timeline Replay</h2>
                <p>Chronological reconstruction with attack-phase grouping.</p>
              </div>
              <span className="panel__meta">
                {timelineQuery.isLoading ? 'Loading…' : `${timelineQuery.data?.entries.length ?? 0} entries`}
              </span>
            </div>
            <TimelineViewer timeline={timelineQuery.data} loading={timelineQuery.isLoading} />
          </div>

          {/* Correlation Intelligence */}
          <div className="panel corr-panel">
            <div className="panel__header">
              <div>
                <h2>Correlation Intelligence</h2>
                <p>Hidden event relationships made explicit — same user, same C2, same malware hash.</p>
              </div>
            </div>
            <CorrelationIntelPanel />
          </div>

        </div>

        {/* ── Sidebar ── */}
        <aside className="workbench__sidebar">
          <div className="panel alerts-panel">
            <div className="panel__header">
              <div><h2>Alerts</h2><p>Detections prioritized for analyst review.</p></div>
            </div>
            <AlertPanel alerts={alertsQuery.data?.items ?? []} loading={alertsQuery.isLoading} />
          </div>

          <div className="panel explanation-panel">
            <div className="panel__header">
              <div><h2>Alert Explanation</h2><p>Reasoning, ATT&amp;CK mapping, and next investigative steps.</p></div>
            </div>
            <ExplanationPanel />
          </div>
        </aside>
      </section>

      <NodeDetailsDrawer graph={graphQuery.data} events={eventItems} />
    </div>
  );
}
