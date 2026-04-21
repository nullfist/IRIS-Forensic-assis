import axios from 'axios';
import type {
  AlertListResponse,
  CorrelationIntelResponse,
  EventListResponse,
  EventQueryParams,
  ExplanationResponse,
  GraphQueryParams,
  GraphResponse,
  IngestJobResponse,
  IngestRequest,
  RootCauseResponse,
  StoryModeResponse,
  TimelineQueryParams,
  TimelineReplayResponse
} from '../types/api';

const apiClient = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' }
});

function compactParams(params?: Record<string, unknown>) {
  if (!params) return undefined;
  return Object.fromEntries(
    Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== '')
  );
}

export async function fetchEvents(params?: EventQueryParams) {
  const { data } = await apiClient.get<EventListResponse>('/events', {
    params: compactParams(params as Record<string, unknown>)
  });
  return data;
}

export async function fetchGraph(params?: GraphQueryParams) {
  const { data } = await apiClient.get<GraphResponse>('/graph', {
    params: compactParams(params as Record<string, unknown>)
  });
  return data;
}

export async function fetchTimeline(params?: TimelineQueryParams) {
  const { data } = await apiClient.get<TimelineReplayResponse>('/timeline', {
    params: compactParams(params as Record<string, unknown>)
  });
  return data;
}

export async function fetchAlerts(params?: GraphQueryParams) {
  const { data } = await apiClient.get<AlertListResponse>('/alerts', {
    params: compactParams(params as Record<string, unknown>)
  });
  return data;
}

export async function fetchExplanation(alertId: string) {
  const { data } = await apiClient.get<ExplanationResponse>(`/alerts/${alertId}/explanation`);
  return data;
}

export async function submitIngest(payload: IngestRequest) {
  const { data } = await apiClient.post<IngestJobResponse>('/ingest', payload);
  return data;
}

export async function uploadEvidenceFile(
  file: File,
  investigationId: string,
  onProgress?: (pct: number) => void
) {
  const form = new FormData();
  form.append('file', file);
  form.append('investigation_id', investigationId);
  const { data } = await apiClient.post<IngestJobResponse>('/ingest/upload', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: (e) => {
      if (onProgress && e.total) onProgress(Math.round((e.loaded * 100) / e.total));
    }
  });
  return data;
}

export { apiClient };

export async function fetchRootCause(investigationId?: string) {
  const { data } = await apiClient.get<RootCauseResponse>('/analysis/root-cause', {
    params: compactParams({ investigation_id: investigationId })
  });
  return data;
}

export async function fetchStory(investigationId?: string) {
  const { data } = await apiClient.get<StoryModeResponse>('/analysis/story', {
    params: compactParams({ investigation_id: investigationId })
  });
  return data;
}

export async function fetchCorrelationIntel(investigationId?: string) {
  const { data } = await apiClient.get<CorrelationIntelResponse>('/analysis/correlation-intel', {
    params: compactParams({ investigation_id: investigationId })
  });
  return data;
}

export async function fetchCases() {
  const { data } = await apiClient.get<import('../types/api').CaseListResponse>('/cases');
  return data;
}

export async function fetchCase(caseId: string) {
  const { data } = await apiClient.get<import('../types/api').Case>(`/cases/${caseId}`);
  return data;
}

export async function createCase(payload: import('../types/api').CaseCreate) {
  const { data } = await apiClient.post<import('../types/api').Case>('/cases', payload);
  return data;
}

export async function updateCaseStatus(caseId: string, status: string) {
  const { data } = await apiClient.patch<import('../types/api').Case>(
    `/cases/${caseId}/status?status=${status}`
  );
  return data;
}

export async function deleteCase(caseId: string) {
  await apiClient.delete(`/cases/${caseId}`);
}
