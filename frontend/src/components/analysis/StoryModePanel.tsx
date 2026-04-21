import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import dayjs from 'dayjs';
import clsx from 'clsx';
import { fetchStory } from '../../api/client';
import { useInvestigationStore } from '../../store/investigationStore';

export default function StoryModePanel() {
  const investigationId = useInvestigationStore((s) => s.investigationId);
  const [activeStep, setActiveStep] = useState<number | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ['story', investigationId],
    queryFn: () => fetchStory(investigationId),
    enabled: !!investigationId
  });

  if (isLoading) return <div className="analysis-state">Generating attack story…</div>;

  if (!data || data.total_chapters === 0) {
    return (
      <div className="analysis-state">
        Ingest evidence to generate the attack narrative.
      </div>
    );
  }

  return (
    <div className="story">
      <div className="story__summary">
        <strong>{data.title}</strong>
        <p>{data.summary}</p>
      </div>

      <div className="story__chapters">
        {data.chapters.map((chapter) => {
          const isOpen = activeStep === chapter.step;
          return (
            <div
              key={chapter.step}
              className={clsx('story__chapter', { 'story__chapter--open': isOpen })}
            >
              <button
                className="story__chapter-header"
                onClick={() => setActiveStep(isOpen ? null : chapter.step)}
                type="button"
              >
                <span className="story__step-num">{chapter.step}</span>
                <div className="story__chapter-info">
                  <span className="phase-pill">{chapter.phase.replace(/_/g, ' ')}</span>
                  <strong>{chapter.headline}</strong>
                </div>
                <span className="story__chapter-time">
                  {dayjs(chapter.timestamp_start).format('HH:mm:ss')}
                </span>
                <span className="story__chevron">{isOpen ? '▲' : '▼'}</span>
              </button>

              {isOpen && (
                <div className="story__chapter-body">
                  <p className="story__narrative">{chapter.narrative}</p>

                  {chapter.alerts.length > 0 && (
                    <div className="story__alerts">
                      <span className="story__alerts-label">🚨 Alerts triggered:</span>
                      {chapter.alerts.map((a) => (
                        <span key={a} className="tag">{a}</span>
                      ))}
                    </div>
                  )}

                  {chapter.events.length > 0 && (
                    <ul className="story__events">
                      {chapter.events.map((ev) => (
                        <li key={ev.event_id} className="story__event">
                          <span className="story__event-time">
                            {dayjs(ev.timestamp).format('HH:mm:ss')}
                          </span>
                          <span className="story__event-title">{ev.title}</span>
                          <span className={`severity severity--${ev.severity}`}>{ev.severity}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
