import dayjs from 'dayjs';
import clsx from 'clsx';
import type { Alert } from '../../types/api';
import { useInvestigationStore } from '../../store/investigationStore';

interface AlertPanelProps {
  alerts: Alert[];
  loading?: boolean;
}

export default function AlertPanel({ alerts, loading }: AlertPanelProps) {
  const selectedAlert = useInvestigationStore((state) => state.selectedAlert);
  const setSelectedAlert = useInvestigationStore((state) => state.setSelectedAlert);

  if (loading) {
    return <div className="alerts-state">Evaluating detections…</div>;
  }

  if (alerts.length === 0) {
    return <div className="alerts-state">No alerts are currently in scope.</div>;
  }

  return (
    <div className="alerts-list">
      {alerts.map((alert) => (
        <button
          key={alert.alert_id}
          className={clsx('alert-card', {
            'alert-card--active': selectedAlert?.alert_id === alert.alert_id
          })}
          onClick={() => setSelectedAlert(alert)}
          type="button"
        >
          <div className="alert-card__top">
            <span className={`severity severity--${alert.severity}`}>{alert.severity}</span>
            <span className="phase-pill">{alert.phase.replace(/_/g, ' ')}</span>
          </div>
          <strong className="alert-card__title">{alert.title}</strong>
          <p className="alert-card__description">{alert.description ?? 'No description provided.'}</p>
          <div className="alert-card__meta">
            <span>Confidence {Math.round((alert.confidence ?? 0) * 100)}%</span>
            <span>Status {alert.status}</span>
          </div>
          <div className="alert-card__meta">
            <span>Evidence {alert.evidence.length}</span>
            <span>{dayjs(alert.created_at).format('MMM D HH:mm')}</span>
          </div>
        </button>
      ))}
    </div>
  );
}