import type { ChangeEvent } from 'react';
import clsx from 'clsx';
import { useInvestigationStore } from '../../store/investigationStore';
import type { InvestigationFilters as InvestigationFiltersState } from '../../types/api';

export default function InvestigationFilters() {
  const filters = useInvestigationStore((state) => state.filters);
  const updateFilters = useInvestigationStore((state) => state.updateFilters);
  const resetFilters = useInvestigationStore((state) => state.resetFilters);
  const investigationId = useInvestigationStore((state) => state.investigationId);
  const setInvestigationId = useInvestigationStore((state) => state.setInvestigationId);

  const handleInput = (event: ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, type, value } = event.target;
    const checked = 'checked' in event.target ? event.target.checked : undefined;
    updateFilters({ [name]: type === 'checkbox' ? checked : value } as Partial<InvestigationFiltersState>);
  };

  return (
    <div className="filters">
      <div className="panel__header">
        <div>
          <h2>Investigation Filters</h2>
          <p>Constrain the current view across graph, timeline, and detection results.</p>
        </div>
        <button className="button button--ghost" onClick={resetFilters} type="button">Reset</button>
      </div>

      <div className="filters__grid">
        <label className="field">
          <span>Investigation ID</span>
          <input
            name="investigation_id"
            placeholder="auto-assigned on upload"
            value={investigationId}
            onChange={(e) => setInvestigationId(e.target.value)}
          />
        </label>
        <label className="field">
          <span>Time start</span>
          <input name="time_start" type="datetime-local" value={filters.time_start ?? ''} onChange={handleInput} />
        </label>

        <label className="field">
          <span>Time end</span>
          <input name="time_end" type="datetime-local" value={filters.time_end ?? ''} onChange={handleInput} />
        </label>

        <label className="field">
          <span>User</span>
          <input name="user" placeholder="alice, svc_backup" value={filters.user ?? ''} onChange={handleInput} />
        </label>

        <label className="field">
          <span>Host</span>
          <input name="host" placeholder="WKSTN-07" value={filters.host ?? ''} onChange={handleInput} />
        </label>

        <label className="field">
          <span>Severity</span>
          <select name="severity" value={filters.severity ?? ''} onChange={handleInput}>
            <option value="">All severities</option>
            <option value="informational">Informational</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </label>

        <label className="field">
          <span>Source</span>
          <select name="source" value={filters.source ?? ''} onChange={handleInput}>
            <option value="">All sources</option>
            <option value="sysmon">Sysmon</option>
            <option value="evtx">Windows Event Log</option>
            <option value="pcap">PCAP / Flow Metadata</option>
            <option value="manual">Manual / Analyst Input</option>
          </select>
        </label>

        <label className={clsx('field', 'field--toggle')}>
          <span>Replay mode</span>
          <div className="toggle">
            <input
              checked={filters.replayEnabled}
              id="replayEnabled"
              name="replayEnabled"
              onChange={handleInput}
              type="checkbox"
            />
            <label htmlFor="replayEnabled">
              {filters.replayEnabled ? 'Timeline playback enabled' : 'Timeline playback disabled'}
            </label>
          </div>
        </label>
      </div>
    </div>
  );
}