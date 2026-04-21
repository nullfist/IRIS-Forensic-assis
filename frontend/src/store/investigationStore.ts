import { create } from 'zustand';
import type { Alert, GraphNode, InvestigationFilters } from '../types/api';

interface PanelState {
  nodeDrawerOpen: boolean;
  alertsExpanded: boolean;
  explanationExpanded: boolean;
}

interface InvestigationStore {
  selectedNode: GraphNode | null;
  selectedAlert: Alert | null;
  filters: InvestigationFilters;
  investigationId: string;
  replayPosition: number;
  panelState: PanelState;
  // Attack graph intelligence
  entryEntityId: string;        // root-cause entry node to highlight
  attackPathIds: string[];      // ordered node IDs forming the attack path
  storyModeOpen: boolean;       // whether story mode panel is expanded
  setSelectedNode: (node: GraphNode | null) => void;
  setSelectedAlert: (alert: Alert | null) => void;
  updateFilters: (updates: Partial<InvestigationFilters>) => void;
  resetFilters: () => void;
  setReplayPosition: (position: number) => void;
  setPanelState: (updates: Partial<PanelState>) => void;
  setInvestigationId: (id: string) => void;
  setEntryEntityId: (id: string) => void;
  setAttackPathIds: (ids: string[]) => void;
  clearAttackPath: () => void;
  toggleStoryMode: () => void;
}

const defaultFilters: InvestigationFilters = {
  time_start: '',
  time_end: '',
  user: '',
  host: '',
  severity: '',
  source: '',
  replayEnabled: false
};

export const useInvestigationStore = create<InvestigationStore>((set) => ({
  selectedNode: null,
  selectedAlert: null,
  filters: defaultFilters,
  investigationId: 'default-investigation',
  replayPosition: 0,
  entryEntityId: '',
  attackPathIds: [],
  storyModeOpen: false,
  panelState: {
    nodeDrawerOpen: false,
    alertsExpanded: true,
    explanationExpanded: true
  },
  setSelectedNode: (node) =>
    set(() => ({
      selectedNode: node,
      panelState: { nodeDrawerOpen: !!node, alertsExpanded: true, explanationExpanded: true }
    })),
  setSelectedAlert: (alert) => set(() => ({ selectedAlert: alert })),
  updateFilters: (updates) =>
    set((state) => ({ filters: { ...state.filters, ...updates } })),
  resetFilters: () => set(() => ({ filters: defaultFilters, replayPosition: 0 })),
  setReplayPosition: (position) => set(() => ({ replayPosition: position })),
  setPanelState: (updates) =>
    set((state) => ({ panelState: { ...state.panelState, ...updates } })),
  setInvestigationId: (id) => set(() => ({ investigationId: id })),
  setEntryEntityId: (id) => set(() => ({ entryEntityId: id })),
  setAttackPathIds: (ids) => set(() => ({ attackPathIds: ids })),
  clearAttackPath: () => set(() => ({ attackPathIds: [], entryEntityId: '' })),
  toggleStoryMode: () => set((state) => ({ storyModeOpen: !state.storyModeOpen }))
}));
