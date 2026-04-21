import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { fetchCorrelationIntel } from '../../api/client';
import { useInvestigationStore } from '../../store/investigationStore';

const LINK_TYPE_LABELS: Record<string, { icon: string; label: string }> = {
  user_across_hosts:  { icon: '👤', label: 'Cross-host user' },
  process_chain:      { icon: '🔗', label: 'Process chain' },
  shared_destination: { icon: '🌐', label: 'Shared C2/destination' },
  shared_file_hash:   { icon: '🦠', label: 'Shared malware hash' },
  temporal_burst:     { icon: '⚡', label: 'Activity burst' },
};

export default function CorrelationIntelPanel() {
  const investigationId = useInvestigationStore((s) => s.investigationId);

  const { data, isLoading } = useQuery({
    queryKey: ['correlation-intel', investigationId],
    queryFn: () => fetchCorrelationIntel(investigationId),
    enabled: !!investigationId
  });

  if (isLoading) return <div className="analysis-state">Analyzing correlations…</div>;

  if (!data || data.total_links === 0) {
    return (
      <div className="analysis-state">
        {data?.summary ?? 'Ingest evidence to surface hidden correlations.'}
      </div>
    );
  }

  return (
    <div className="corr-intel">
      <p className="corr-intel__summary">{data.summary}</p>

      <ul className="corr-intel__list">
        {data.links.map((link) => {
          const meta = LINK_TYPE_LABELS[link.link_type] ?? { icon: '🔍', label: link.link_type };
          const pct = Math.round(link.confidence * 100);
          return (
            <li key={link.link_id} className="corr-intel__item">
              <div className="corr-intel__item-header">
                <span className="corr-intel__icon">{meta.icon}</span>
                <span className="corr-intel__type">{meta.label}</span>
                <span className={clsx('corr-intel__conf', {
                  'corr-intel__conf--high': pct >= 85,
                  'corr-intel__conf--med': pct >= 70 && pct < 85,
                })}>
                  {pct}% confidence
                </span>
              </div>
              <p className="corr-intel__reason">{link.reason}</p>
              <div className="corr-intel__events">
                {link.event_ids.slice(0, 4).map((id) => (
                  <code key={id} className="corr-intel__event-id">{id.slice(0, 8)}…</code>
                ))}
                {link.event_ids.length > 4 && (
                  <span className="corr-intel__more">+{link.event_ids.length - 4} more</span>
                )}
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
