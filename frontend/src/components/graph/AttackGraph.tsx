import { memo, useCallback, useEffect, useMemo, useRef } from 'react';
import CytoscapeComponent from 'react-cytoscapejs';
import type { Core, ElementDefinition } from 'cytoscape';
import type { GraphResponse } from '../../types/api';
import { useInvestigationStore } from '../../store/investigationStore';

interface AttackGraphProps {
  graph?: GraphResponse;
  loading?: boolean;
}

const stylesheet = [
  {
    selector: 'node',
    style: {
      label: 'data(label)',
      color: '#d7e0ea',
      'font-size': 11,
      'text-wrap': 'wrap',
      'text-max-width': 96,
      'background-color': '#4f7cff',
      width: 'mapData(risk, 0, 100, 28, 60)',
      height: 'mapData(risk, 0, 100, 28, 60)',
      'border-width': 1.5,
      'border-color': '#9db3c8',
      'transition-property': 'background-color, border-color, border-width, width, height',
      'transition-duration': '300ms'
    }
  },
  {
    selector: 'edge',
    style: {
      width: 'mapData(weight, 0, 10, 1, 5)',
      'line-color': '#3d5268',
      'curve-style': 'bezier',
      'target-arrow-shape': 'triangle',
      'target-arrow-color': '#3d5268',
      opacity: 0.8,
      'transition-property': 'line-color, opacity, width',
      'transition-duration': '300ms'
    }
  },
  // Entity type shapes
  { selector: 'node[type = "host"]',    style: { shape: 'round-rectangle', 'background-color': '#4f7cff' } },
  { selector: 'node[type = "user"]',    style: { shape: 'ellipse',         'background-color': '#1ca58a' } },
  { selector: 'node[type = "process"]', style: { shape: 'hexagon',         'background-color': '#9c6cff' } },
  { selector: 'node[type = "file"]',    style: { shape: 'diamond',         'background-color': '#d08732' } },
  { selector: 'node[type = "ip"]',      style: { shape: 'vee',             'background-color': '#ef5b8d' } },
  { selector: 'node[type = "domain"]',  style: { shape: 'tag',             'background-color': '#c056ff' } },
  // Severity borders
  { selector: 'node[severity = "critical"]', style: { 'border-color': '#ff4d6d', 'border-width': 3 } },
  { selector: 'node[severity = "high"]',     style: { 'border-color': '#ff8a3d', 'border-width': 2.5 } },
  // Selected node
  {
    selector: '.selected',
    style: {
      'overlay-color': '#83e0ff',
      'overlay-opacity': 0.18,
      'overlay-padding': 8,
      'border-color': '#83e0ff',
      'border-width': 3
    }
  },
  // Attack path highlight
  {
    selector: '.attack-path-node',
    style: {
      'border-color': '#ff4d6d',
      'border-width': 4,
      'background-color': '#ff1a3c',
      'z-index': 10
    }
  },
  {
    selector: '.attack-path-edge',
    style: {
      'line-color': '#ff4d6d',
      'target-arrow-color': '#ff4d6d',
      width: 4,
      opacity: 1,
      'z-index': 10
    }
  },
  // Entry node (attack origin)
  {
    selector: '.entry-node',
    style: {
      'border-color': '#ffb454',
      'border-width': 5,
      'border-style': 'double',
      'background-color': '#ff8a00',
      'z-index': 20,
      label: 'data(label)',
      'font-weight': 'bold'
    }
  },
  // Dimmed nodes (not on attack path)
  {
    selector: '.dimmed',
    style: { opacity: 0.2 }
  }
] as const;

function AttackGraph({ graph, loading }: AttackGraphProps) {
  const cyRef = useRef<Core | null>(null);
  const graphRef = useRef(graph);
  const animFrameRef = useRef<number | null>(null);

  const selectedNode   = useInvestigationStore((s) => s.selectedNode);
  const setSelectedNode = useInvestigationStore((s) => s.setSelectedNode);
  const entryEntityId  = useInvestigationStore((s) => s.entryEntityId);
  const attackPathIds  = useInvestigationStore((s) => s.attackPathIds);

  const elements = useMemo<ElementDefinition[]>(() => {
    if (!graph) return [];
    return [
      ...graph.nodes.map((node) => ({
        data: {
          id: node.id,
          label: node.label,
          type: node.type,
          risk: node.risk_score ?? 20,
          severity: node.severity ?? 'low'
        }
      })),
      ...graph.edges.map((edge) => ({
        data: {
          id: edge.id,
          source: edge.source,
          target: edge.target,
          label: edge.relationship,
          weight: edge.weight ?? 1,
          severity: edge.severity ?? 'low'
        }
      }))
    ];
  }, [graph]);

  useEffect(() => { graphRef.current = graph; }, [graph]);

  // Apply selected class
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.nodes().removeClass('selected');
    if (selectedNode) cy.$id(selectedNode.id).addClass('selected');
  }, [selectedNode]);

  // Apply entry node + attack path highlights
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.elements().removeClass('attack-path-node attack-path-edge entry-node dimmed');

    const hasPath = attackPathIds.length > 0;
    const hasEntry = !!entryEntityId;

    if (!hasPath && !hasEntry) return;

    if (hasPath) {
      const pathSet = new Set(attackPathIds);
      cy.nodes().forEach((n) => {
        if (pathSet.has(n.id())) n.addClass('attack-path-node');
        else n.addClass('dimmed');
      });
      cy.edges().forEach((e) => {
        if (pathSet.has(e.source().id()) && pathSet.has(e.target().id())) {
          e.addClass('attack-path-edge');
        } else {
          e.addClass('dimmed');
        }
      });
    }

    if (hasEntry) {
      cy.$id(entryEntityId).removeClass('dimmed attack-path-node').addClass('entry-node');
    }
  }, [entryEntityId, attackPathIds]);

  // Layout on element change
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.layout({ name: 'cose', animate: false, padding: 24, nodeRepulsion: 320000 }).run();
    cy.fit(undefined, 40);
  }, [elements]);

  // Animate attack path traversal — pulse each path node in sequence
  const animateAttackPath = useCallback(() => {
    const cy = cyRef.current;
    if (!cy || attackPathIds.length === 0) return;
    if (animFrameRef.current) clearTimeout(animFrameRef.current);

    attackPathIds.forEach((nodeId, idx) => {
      animFrameRef.current = window.setTimeout(() => {
        const node = cy.$id(nodeId);
        if (!node.length) return;
        node.animate(
          { style: { 'border-width': 8, 'border-color': '#ff4d6d' } },
          { duration: 300, complete: () => {
            node.animate({ style: { 'border-width': 4 } }, { duration: 200 });
          }}
        );
      }, idx * 350);
    });
  }, [attackPathIds]);

  const bindCy = (cy: Core) => {
    if (cyRef.current === cy) return;
    cyRef.current = cy;
    cy.off('tap', 'node');
    cy.on('tap', 'node', (event) => {
      const id = event.target.id();
      const node = graphRef.current?.nodes.find((n) => n.id === id) ?? null;
      setSelectedNode(node);
    });
  };

  if (loading) return <div className="graph-state">Building graph view…</div>;
  if (!graph || graph.nodes.length === 0) {
    return <div className="graph-state">No graph data available for the active filters.</div>;
  }

  return (
    <div className="graph-shell">
      <CytoscapeComponent
        className="graph-canvas"
        cy={bindCy}
        elements={elements}
        layout={{ name: 'cose', animate: false, padding: 24, nodeRepulsion: 320000 }}
        minZoom={0.35}
        maxZoom={2.2}
        stylesheet={stylesheet as never}
        wheelSensitivity={0.12}
      />
      <div className="graph-legend">
        <span className="graph-legend__item">
          <span className="graph-legend__dot graph-legend__dot--entry" /> Attack origin
        </span>
        <span className="graph-legend__item">
          <span className="graph-legend__dot graph-legend__dot--path" /> Attack path
        </span>
        <span className="graph-legend__item">Nodes sized by risk score</span>
        {attackPathIds.length > 0 && (
          <button className="button button--ghost graph-legend__animate" onClick={animateAttackPath} type="button">
            ▶ Animate path
          </button>
        )}
      </div>
    </div>
  );
}

export default memo(AttackGraph);
