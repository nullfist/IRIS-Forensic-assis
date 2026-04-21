import { useQuery } from '@tanstack/react-query';
import dayjs from 'dayjs';
import { fetchRootCause } from '../../api/client';
import { useInvestigationStore } from '../../store/investigationStore';

export default function RootCausePanel() {
  const investigationId = useInvestigationStore((s) => s.investigationId);

  const { data, isLoading } = useQuery({
    queryKey: ['root-cause', investigationId],
    queryFn: () => fetchRootCause(investigationId),
    enabled: !!investigationId
  });

  if (isLoading) return <div className="analysis-state">Identifying attack origin…</div>;

  if (!data || !data.found) {
    return (
      <div className="analysis-state">
        {data?.message ?? 'Ingest evidence to identify the attack origin.'}
      </div>
    );
  }

  const pct = Math.round((data.confidence ?? 0) * 100);

  return (
    <div className="root-cause">
      <div className="root-cause__origin">
        <span className="root-cause__badge">⚡ Attack Origin Identified</span>
        <h3 className="root-cause__title">{data.title}</h3>
        <div className="root-cause__meta">
          {data.timestamp && <span>{dayjs(data.timestamp).format('MMM D HH:mm:ss')}</span>}
          {data.host && <span>{data.host}</span>}
          {data.user && <span>{data.user}</span>}
        </div>
        <div className="root-cause__confidence">
          <span>Confidence</span>
          <div className="root-cause__bar">
            <div className="root-cause__bar-fill" style={{ width: `${pct}%` }} />
          </div>
          <strong>{pct}%</strong>
        </div>
      </div>

      {data.reasoning && (
        <p className="root-cause__reasoning">{data.reasoning}</p>
      )}

      {data.attack_chain && data.attack_chain.length > 0 && (
        <div className="root-cause__chain">
          <h4>Attack Chain</h4>
          <ol className="root-cause__chain-list">
            {data.attack_chain.map((step, i) => (
              <li key={i}>{step}</li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}
