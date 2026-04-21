import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { createCase } from '../api/client';
import type { CaseCreate, CaseType, CasePriority } from '../types/api';

export default function NewCasePage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [form, setForm] = useState<CaseCreate>({
    name: '',
    description: '',
    examiner: '',
    organization: '',
    case_type: 'incident',
    priority: 'medium',
    tags: [],
  });
  const [tagInput, setTagInput] = useState('');
  const [error, setError] = useState('');

  const mutation = useMutation({
    mutationFn: createCase,
    onSuccess: (newCase) => {
      queryClient.invalidateQueries({ queryKey: ['cases'] });
      // Go straight into the workbench for this case
      navigate(`/cases/${newCase.case_id}`);
    },
    onError: () => setError('Failed to create case. Please try again.'),
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim()) {
      setError('Case name is required.');
      return;
    }
    setError('');
    mutation.mutate(form);
  };

  const addTag = () => {
    const t = tagInput.trim();
    if (t && !form.tags?.includes(t)) {
      setForm((f) => ({ ...f, tags: [...(f.tags ?? []), t] }));
    }
    setTagInput('');
  };

  const removeTag = (tag: string) =>
    setForm((f) => ({ ...f, tags: f.tags?.filter((t) => t !== tag) ?? [] }));

  return (
    <div className="new-case-page">
      <header className="new-case-header">
        <button
          className="button button--ghost"
          onClick={() => navigate('/cases')}
          type="button"
        >
          ← Back to Cases
        </button>
        <div>
          <p className="eyebrow">IRIS DFIR Platform</p>
          <h1>New Case</h1>
        </div>
      </header>

      <div className="new-case-body">
        <form className="new-case-form panel" onSubmit={handleSubmit}>

          {/* Section 1 — Case Identity */}
          <div className="new-case-section">
            <h2>Case Details</h2>
            <p>Basic information about this investigation.</p>

            <div className="new-case-grid">
              <label className="field new-case-field--full">
                <span>Case Name <span className="required">*</span></span>
                <input
                  autoFocus
                  placeholder="e.g. Phishing Attack — Finance Dept Jan 2025"
                  value={form.name}
                  onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                />
              </label>

              <label className="field new-case-field--full">
                <span>Description</span>
                <textarea
                  className="new-case-textarea"
                  placeholder="Brief summary of the incident or investigation scope…"
                  value={form.description}
                  onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
                  rows={3}
                />
              </label>
            </div>
          </div>

          {/* Section 2 — Classification */}
          <div className="new-case-section">
            <h2>Classification</h2>
            <p>Set the case type and priority level.</p>

            <div className="new-case-grid">
              <label className="field">
                <span>Case Type</span>
                <select
                  value={form.case_type}
                  onChange={(e) => setForm((f) => ({ ...f, case_type: e.target.value as CaseType }))}
                >
                  <option value="incident">🚨 Incident Response</option>
                  <option value="forensic">🔬 Digital Forensics</option>
                  <option value="threat_hunt">🎯 Threat Hunt</option>
                </select>
              </label>

              <label className="field">
                <span>Priority</span>
                <select
                  value={form.priority}
                  onChange={(e) => setForm((f) => ({ ...f, priority: e.target.value as CasePriority }))}
                >
                  <option value="critical">🔴 Critical</option>
                  <option value="high">🟠 High</option>
                  <option value="medium">🟡 Medium</option>
                  <option value="low">🟢 Low</option>
                </select>
              </label>
            </div>
          </div>

          {/* Section 3 — Examiner */}
          <div className="new-case-section">
            <h2>Examiner Information</h2>
            <p>Who is conducting this investigation.</p>

            <div className="new-case-grid">
              <label className="field">
                <span>Examiner Name</span>
                <input
                  placeholder="e.g. John Smith"
                  value={form.examiner}
                  onChange={(e) => setForm((f) => ({ ...f, examiner: e.target.value }))}
                />
              </label>

              <label className="field">
                <span>Organization</span>
                <input
                  placeholder="e.g. ACME Corp SOC"
                  value={form.organization}
                  onChange={(e) => setForm((f) => ({ ...f, organization: e.target.value }))}
                />
              </label>
            </div>
          </div>

          {/* Section 4 — Tags */}
          <div className="new-case-section">
            <h2>Tags</h2>
            <p>Optional labels for filtering and categorization.</p>

            <div className="new-case-tag-input">
              <input
                placeholder="Add a tag and press Enter"
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addTag(); } }}
              />
              <button className="button" onClick={addTag} type="button">Add</button>
            </div>

            {(form.tags ?? []).length > 0 && (
              <div className="new-case-tags">
                {form.tags?.map((tag) => (
                  <span key={tag} className="new-case-tag">
                    {tag}
                    <button onClick={() => removeTag(tag)} type="button">✕</button>
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Error */}
          {error && <p className="new-case-error">{error}</p>}

          {/* Actions */}
          <div className="new-case-actions">
            <button
              className="button button--ghost"
              onClick={() => navigate('/cases')}
              type="button"
            >
              Cancel
            </button>
            <button
              className="button button--primary"
              type="submit"
              disabled={mutation.isPending}
            >
              {mutation.isPending ? 'Creating…' : 'Create Case & Open Workbench →'}
            </button>
          </div>

        </form>

        {/* Side info panel */}
        <div className="new-case-info">
          <div className="new-case-info-card">
            <h3>What happens next?</h3>
            <ol>
              <li>Case is created with a unique Investigation ID</li>
              <li>You enter the Incident Workbench</li>
              <li>Drop evidence files — EVTX, Sysmon, PCAP, XML, CSV</li>
              <li>IRIS auto-detects format and runs full analysis</li>
              <li>Attack graph, timeline, and alerts populate automatically</li>
            </ol>
          </div>

          <div className="new-case-info-card">
            <h3>Supported Evidence</h3>
            <ul>
              <li>📋 Sysmon JSON / JSONL</li>
              <li>📋 Windows Event Log (EVTX export)</li>
              <li>🌐 PCAP / PCAPNG (raw or metadata)</li>
              <li>📄 XML Event Log (wevtutil)</li>
              <li>📊 CSV Logs</li>
              <li>💾 Disk Images (E01, DD, IMG)</li>
              <li>🧠 Memory Dumps (DMP, MEM)</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
