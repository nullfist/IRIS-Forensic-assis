import dayjs from 'dayjs';
import clsx from 'clsx';
import type { GraphResponse, NormalizedEvent } from '../../types/api';
import { useInvestigationStore } from '../../store/investigationStore';

interface NodeDetailsDrawerProps {
  graph?: GraphResponse;
  events: NormalizedEvent[];
}

export default function NodeDetailsDrawer({ graph, events }: NodeDetailsDrawerProps) {
  const selectedNode = useInvestigationStore((state) => state.selectedNode);
  const panelState = useInvestigationStore((state) => state.panelState);
  const setSelectedNode = useInvestigationStore((state) => state.setSelectedNode);
  const updateFilters = useInvestigationStore((state) => state.updateFilters);

  if (!panelState.nodeDrawerOpen || !selectedNode) {
    return null;
  }

  const linkedEventIds = new Set(selectedNode.linked_event_ids ?? []);
  const linkedEvents = events.filter(
    (event) =>
      linkedEventIds.has(event.event_id) ||
      event.entities.some((entity) => entity.entity_id === selectedNode.id)
  );

  const relatedEdges = graph?.edges.filter(
    (edge) => edge.source === selectedNode.id || edge.target === selectedNode.id
  );

  return (
    <aside className={clsx('drawer', { 'drawer--open': panelState.nodeDrawerOpen })}>
      <div className="drawer__header">
        <div>
          <p className="eyebrow">Entity Detail</p>
          <h3>{selectedNode.label}</h3>
          <p className="drawer__subtitle">{selectedNode.type}</p>
        </div>
        <button className="button button--ghost" onClick={() => setSelectedNode(null)} type="button">
          Close
        </button>
      </div>

      <div className="drawer__section">
        <h4>Attributes</h4>
        <dl className="detail-grid">
          <div>
            <dt>Risk score</dt>
            <dd>{selectedNode.risk_score ?? 'n/a'}</dd>
          </div>
          <div>
            <dt>Severity</dt>
            <dd>{selectedNode.severity ?? 'n/a'}</dd>
          </div>
          <div>
            <dt>Attack phase</dt>
            <dd>{selectedNode.phase ?? 'n/a'}</dd>
          </div>
          <div>
            <dt>Relationships</dt>
            <dd>{relatedEdges?.length ?? 0}</dd>
          </div>
        </dl>
      </div>

      {selectedNode.properties && Object.keys(selectedNode.properties).length > 0 ? (
        <div className="drawer__section">
          <h4>Entity Properties</h4>
          <ul className="kv-list">
            {Object.entries(selectedNode.properties).map(([key, value]) => (
              <li key={key}>
                <span>{key}</span>
                <strong>{String(value)}</strong>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="drawer__section">
        <h4>Quick Pivots</h4>
        <div className="drawer__actions">
          <button
            className="button"
            onClick={() => updateFilters({ host: selectedNode.type === 'host' ? selectedNode.label : '' })}
            type="button"
          >
            Pivot to host
          </button>
          <button
            className="button"
            onClick={() => updateFilters({ user: selectedNode.type === 'user' ? selectedNode.label : '' })}
            type="button"
          >
            Pivot to user
          </button>
        </div>
      </div>

      <div className="drawer__section">
        <h4>Linked Events</h4>
        {linkedEvents.length === 0 ? (
          <p className="empty-state">No directly linked events found for this entity.</p>
        ) : (
          <ul className="event-list">
            {linkedEvents.slice(0, 12).map((event) => (
              <li key={event.event_id} className="event-list__item">
                <div>
                  <strong>{event.title}</strong>
                  <p>{event.summary ?? event.event_type}</p>
                </div>
                <div className="event-list__meta">
                  <span>{dayjs(event.timestamp).format('MMM D HH:mm:ss')}</span>
                  <span>{event.source}</span>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </aside>
  );
}