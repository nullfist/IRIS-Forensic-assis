import { useCallback, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { uploadEvidenceFile } from '../../api/client';
import { useInvestigationStore } from '../../store/investigationStore';

interface FileEntry {
  file: File;
  status: 'pending' | 'uploading' | 'done' | 'error';
  progress: number;
  message: string;
  detectedType: string;
}

const EXTENSION_MAP: Record<string, string> = {
  evtx: 'Windows Event Log (EVTX)',
  jsonl: 'Sysmon / JSON Lines',
  json: 'JSON Evidence',
  pcap: 'Packet Capture (PCAP)',
  pcapng: 'Packet Capture (PCAPNG)',
  xml: 'XML Event Log',
  csv: 'CSV Log',
  log: 'Generic Log',
  txt: 'Text Log',
  e01: 'Disk Image (E01)',
  dd: 'Raw Disk Image',
  img: 'Disk Image',
  vmdk: 'VM Disk Image',
  raw: 'Raw Memory / Disk',
  dmp: 'Memory Dump',
  mem: 'Memory Dump',
  zip: 'Archive (ZIP)',
  gz: 'Archive (GZ)',
};

function detectType(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase() ?? '';
  return EXTENSION_MAP[ext] ?? `Unknown (${ext || 'no extension'})`;
}

export default function EvidenceUploader({ investigationId }: { investigationId: string }) {
  const [entries, setEntries] = useState<FileEntry[]>([]);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const queryClient = useQueryClient();
  const setInvestigationId = useInvestigationStore((s) => s.setInvestigationId);

  const addFiles = useCallback((files: FileList | File[]) => {
    const newEntries: FileEntry[] = Array.from(files).map((f) => ({
      file: f,
      status: 'pending',
      progress: 0,
      message: '',
      detectedType: detectType(f.name)
    }));
    setEntries((prev) => [...prev, ...newEntries]);
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      if (e.dataTransfer.files.length) addFiles(e.dataTransfer.files);
    },
    [addFiles]
  );

  const uploadAll = async () => {
    const pending = entries.filter((e) => e.status === 'pending');
    if (!pending.length) return;

    for (const entry of pending) {
      setEntries((prev) =>
        prev.map((e) => (e.file === entry.file ? { ...e, status: 'uploading' } : e))
      );
      try {
        const result = await uploadEvidenceFile(entry.file, investigationId, (pct) => {
          setEntries((prev) =>
            prev.map((e) => (e.file === entry.file ? { ...e, progress: pct } : e))
          );
        });
        // If backend assigned a new investigation_id, adopt it
        if (result.investigation_id && result.investigation_id !== investigationId) {
          setInvestigationId(result.investigation_id);
        }
        setEntries((prev) =>
          prev.map((e) =>
            e.file === entry.file
              ? { ...e, status: 'done', progress: 100, message: `Job ${result.job_id} — ${result.status}` }
              : e
          )
        );
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : 'Upload failed';
        setEntries((prev) =>
          prev.map((e) => (e.file === entry.file ? { ...e, status: 'error', message: msg } : e))
        );
      }
    }
    // Refresh all panels after uploads complete
    await queryClient.invalidateQueries();
  };

  const removeEntry = (file: File) =>
    setEntries((prev) => prev.filter((e) => e.file !== file));

  const hasPending = entries.some((e) => e.status === 'pending');

  return (
    <div className="uploader">
      <div
        className={`uploader__dropzone${dragging ? ' uploader__dropzone--active' : ''}`}
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => inputRef.current?.click()}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => e.key === 'Enter' && inputRef.current?.click()}
      >
        <input
          ref={inputRef}
          type="file"
          multiple
          style={{ display: 'none' }}
          onChange={(e) => e.target.files && addFiles(e.target.files)}
          accept=".evtx,.jsonl,.json,.pcap,.pcapng,.xml,.csv,.log,.txt,.e01,.dd,.img,.vmdk,.raw,.dmp,.mem,.zip,.gz"
        />
        <div className="uploader__icon">📂</div>
        <p><strong>Drop evidence files here</strong> or click to browse</p>
        <p className="uploader__hint">
          Supports: EVTX · Sysmon JSONL · PCAP · XML · CSV · Disk Images (E01/DD/IMG) · Memory Dumps · Archives
        </p>
      </div>

      {entries.length > 0 && (
        <div className="uploader__queue">
          <div className="uploader__queue-header">
            <span>{entries.length} file{entries.length !== 1 ? 's' : ''} queued</span>
            {hasPending && (
              <button className="button" onClick={uploadAll} type="button">
                Analyse All
              </button>
            )}
          </div>
          <ul className="uploader__list">
            {entries.map((entry) => (
              <li key={entry.file.name + entry.file.size} className={`uploader__item uploader__item--${entry.status}`}>
                <div className="uploader__item-info">
                  <strong>{entry.file.name}</strong>
                  <span className="uploader__type">{entry.detectedType}</span>
                  <span className="uploader__size">{(entry.file.size / 1024).toFixed(1)} KB</span>
                </div>
                <div className="uploader__item-status">
                  {entry.status === 'uploading' && (
                    <div className="uploader__progress">
                      <div className="uploader__progress-bar" style={{ width: `${entry.progress}%` }} />
                    </div>
                  )}
                  {entry.status === 'done' && <span className="uploader__badge uploader__badge--done">✓ {entry.message}</span>}
                  {entry.status === 'error' && <span className="uploader__badge uploader__badge--error">✗ {entry.message}</span>}
                  {entry.status === 'pending' && (
                    <button
                      className="button button--ghost uploader__remove"
                      onClick={() => removeEntry(entry.file)}
                      type="button"
                    >
                      ✕
                    </button>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
