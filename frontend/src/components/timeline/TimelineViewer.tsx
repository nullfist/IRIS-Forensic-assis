import dayjs from 'dayjs';
import clsx from 'clsx';
import type { TimelineReplayResponse } from '../../types/api';
import { useInvestigationStore } from '../../store/investigationStore';

interface TimelineViewerProps {
  timeline?: TimelineReplayResponse;
  loading?: boolean;
}

export default function TimelineViewer({ timeline, loading }: TimelineViewerProps) {
  const replayEnabled = useInvestigationStore((state) => state.filters.replayEnabled);
  const replayPosition = useInvestigationStore((state) => state.replayPosition);
  const setReplayPosition = useInvestigationStore((state) => state.setReplayPosition);

  if (loading) {
    return <div className="timeline-state">Loading ordered event stream…</div>;
  }

  if (!timeline || timeline.entries.length === 0) {
    return <div className="timeline-state">No timeline entries available for the active scope.</div>;
  }

  const clampedReplay = Math.min(replayPosition, Math.max(timeline.entries.length - 1, 0));

  return (
    <div className="timeline">
      <div className="timeline__toolbar">
        <div>
          <strong>Replay position</strong>
          <p>
            {replayEnabled
              ? `${clampedReplay + 1} / ${timeline.entries.length} events`
              : 'Replay disabled — showing full timeline context.'}
          </p>
        </div>
        <input
          disabled={!replayEnabled}
          max={Math.max(timeline.entries.length - 1, 0)}
          min={0}
          onChange={(event) => setReplayPosition(Number(event.target.value))}
          type="range"
          value={clampedReplay}
        />
      </div>

      <div className="timeline__phases">
        {timeline.phases.map((phase, phaseIndex) => (
          <section key={`${phase.phase}-${phaseIndex}`} className="phase-block">
            <div className="phase-block__header">
              <div>
                <span className="phase-pill">{phase.phase.replace(/_/g, ' ')}</span>
                <h3>{phase.event_count} events</h3>
              </div>
              <p>
                {dayjs(phase.start_time).format('MMM D HH:mm:ss')} — {dayjs(phase.end_time).format('MMM D HH:mm:ss')}
              </p>
            </div>

            <ul className="timeline__entries">
              {phase.entries.map((entry) => {
                const entryIndex = timeline.entries.findIndex((timelineEntry) => timelineEntry.event_id === entry.event_id);
                const active = replayEnabled && entryIndex === clampedReplay;
                const muted = replayEnabled && entryIndex > clampedReplay;

                return (
                  <li
                    key={entry.event_id}
                    className={clsx('timeline-entry', {
                      'timeline-entry--active': active,
                      'timeline-entry--muted': muted
                    })}
                  >
                    <div className="timeline-entry__time">{dayjs(entry.timestamp).format('HH:mm:ss')}</div>
                    <div className="timeline-entry__body">
                      <div className="timeline-entry__headline">
                        <strong>{entry.title}</strong>
                        <span className={`severity severity--${entry.severity}`}>{entry.severity}</span>
                      </div>
                      <p>{entry.summary ?? 'No summary provided.'}</p>
                      <div className="timeline-entry__meta">
                        <span>{entry.source}</span>
                        {entry.host ? <span>{entry.host}</span> : null}
                        {entry.user ? <span>{entry.user}</span> : null}
                      </div>
                    </div>
                  </li>
                );
              })}
            </ul>
          </section>
        ))}
      </div>
    </div>
  );
}