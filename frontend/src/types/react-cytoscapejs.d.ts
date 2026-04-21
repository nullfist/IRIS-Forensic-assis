declare module 'react-cytoscapejs' {
  import { ComponentType } from 'react';
  import { Core, ElementDefinition, Stylesheet } from 'cytoscape';

  interface CytoscapeComponentProps {
    cy?: (cy: Core) => void;
    elements: ElementDefinition[];
    layout?: Record<string, unknown>;
    stylesheet?: Stylesheet[];
    minZoom?: number;
    maxZoom?: number;
    wheelSensitivity?: number;
    className?: string;
  }

  const CytoscapeComponent: ComponentType<CytoscapeComponentProps>;
  export default CytoscapeComponent;
}