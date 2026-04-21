import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import dayjs from 'dayjs';
import clsx from 'clsx';
import { fetchCases, deleteCase } from '../api/client';
import type { Case } from '../types/api';

const PRIORITY_COLORS: Record<string, string> = {
  critical: 'priority--critical',
  high:     'priority--high',
  medium:   'priority--medium',
  low:      'priority--low',
};

const STATUS_LABELS: Record<string, string> = {
  open:        '🟢 Open',
  in_progress: '🟡 In Progress',
  closed:      '⚫ Closed',
};

const TYPE_ICONS: Record<string, string> = {
  incident:    '🚨',
  forensic:    '🔬',
  threat_hunt: '🎯',
};

export default function CasesPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ['cases'],
    queryFn: fetchCases,
  });

  const deleteMutation = useMutation({
    mutationFn: deleteCase,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['cases'] }),
  });

  const openCase = (c: Case) => {
    navigate(`/cases/${c.case_id}`, { state: { case: c } });
  };

  return (
    <div className="cases-page">
      {/* Header */}
      <header className="cases-header">
        <div className="cases-header__brand">
          <div className="cases-header__logo">🔍</div>
          <div>
            <h1>IRIS</h1>
            <p className="eyebrow">Incident Reconstruction &amp; Intelligence System</p>
          </div>
        </div>
        <button
          className="button button--primary"
          onClick={() => navigate('/cases/new')}
          type="button"
        >
          + New Case
        </button>
      </header>

      {/* Stats bar */}
      <div className="cases-stats">
        <div className="cases-stat">
          <span>{data?.total ?? 0}</span>
          <label>Total Cases</label>
        </div>
        <div className="cases-stat">
          <span>{data?.items.filter(c => c.status === 'open').length ?? 0}</span>
          <label>Open</label>
        </div>
        <div className="cases-stat">
          <span>{data?.items.filter(c => c.status === 'in_progress').length ?? 0}</span>
          <label>In Progress</label>
        </div>
        <div className="cases-stat">
          <span>{data?.items.filter(c => c.priority === 'critical').length ?? 0}</span>
          <label>Critical</label>
        </div>
      </div>

      {/* Case list */}
      <main className="cases-list-container">
        {isLoading && (
          <div className="cases-empty">Loading cases…</div>
        )}

        {!isLoading && (!data || data.total === 0) && (
          <div className="cases-empty">
            <div className="cases-empty__icon">📂</div>
            <h2>No cases yet</h2>
            <p>Create your first case to start an investigation.</p>
            <button
              className="button button--primary"
              onClick={() => navigate('/cases/new')}
              type="button"
            >
              + Create New Case
            </button>
          </div>
        )}

        {data && data.total > 0 && (
          <table className="cases-table">
            <thead>
              <tr>
                <th>Case</th>
                <th>Type</th>
                <th>Priority</th>
                <th>Status</th>
                <th>Examiner</th>
                <th>Events</th>
                <th>Alerts</th>
                <th>Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((c) => (
                <tr
                  key={c.case_id}
                  className="cases-table__row"
                  onClick={() => openCase(c)}
                >
                  <td className="cases-table__name">
                    <strong>{c.name}</strong>
                    {c.description && (
                      <p className="cases-table__desc">{c.description}</p>
                    )}
                    {c.tags.length > 0 && (
                      <div className="cases-table__tags">
                        {c.tags.map(t => (
                          <span key={t} className="tag">{t}</span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td>
                    <span className="cases-type">
                      {TYPE_ICONS[c.case_type] ?? '📁'} {c.case_type.replace('_', ' ')}
                    </span>
                  </td>
                  <td>
                    <span className={clsx('cases-priority', PRIORITY_COLORS[c.priority])}>
                      {c.priority}
                    </span>
                  </td>
                  <td>{STATUS_LABELS[c.status] ?? c.status}</td>
                  <td className="cases-table__examiner">{c.examiner || '—'}</td>
                  <td className="cases-table__num">{c.event_count}</td>
                  <td className="cases-table__num">{c.alert_count}</td>
                  <td className="cases-table__date">
                    {dayjs(c.created_at).format('MMM D YYYY')}
                    <br />
                    <span>{dayjs(c.created_at).format('HH:mm')}</span>
                  </td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <button
                      className="button button--ghost cases-table__delete"
                      onClick={() => {
                        if (confirm(`Delete case "${c.name}"?`)) {
                          deleteMutation.mutate(c.case_id);
                        }
                      }}
                      type="button"
                      title="Delete case"
                    >
                      🗑
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </main>
    </div>
  );
}
