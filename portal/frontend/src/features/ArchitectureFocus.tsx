import {useMemo, useState} from 'react';
import {Icon} from '../components/ui';
import './architecture-focus.css';

interface Resource {
  id: string;
  name?: string;
  kind?: string;
  type?: string;
  namespace?: string;
  label?: string;
  provenance?: string;
}

interface Relationship {
  id: string;
  source: string;
  target: string;
  label?: string;
  classification?: string;
  provenance?: string;
}

const workloads = new Set(['Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet', 'Job', 'CronJob', 'Pod', 'ComposeService']);
const kind = (node: Resource) => node.kind || node.type || 'Resource';
const name = (node: Resource) => node.name || node.label || node.id;
const optionLabel = (node: Resource) => [node.namespace, kind(node), name(node)].filter(Boolean).join(' / ');
const evidenceLabel = (value: string) => value.toLowerCase().replaceAll('_', ' ');
type SelectEvidence = (item: Resource | Relationship) => void;

function ResourceButton({node, onSelect}: {node: Resource; onSelect: SelectEvidence}) {
  return <button type="button" className="arch-resource" onClick={() => onSelect(node)} aria-label={node.label || name(node)}>
    <span className="arch-kind">{kind(node)}</span>
    <strong>{name(node)}</strong>
    {node.namespace && <span className="arch-namespace">{node.namespace}</span>}
  </button>;
}

interface Connection {edge: Relationship; neighbor: Resource}

function Connections({items, incoming, onSelect}: {items: Connection[]; incoming?: boolean; onSelect: SelectEvidence}) {
  const [expanded, setExpanded] = useState(false);
  const title = incoming ? 'Incoming relationships' : 'Outgoing relationships';
  const limit = 3;
  const neighbors = useMemo(() => {
    const grouped = new Map<string, {neighbor: Resource; edges: Relationship[]}>();
    for (const {neighbor, edge} of items) {
      const existing = grouped.get(neighbor.id);
      if (existing) existing.edges.push(edge);
      else grouped.set(neighbor.id, {neighbor, edges: [edge]});
    }
    return [...grouped.values()].sort((a, b) => optionLabel(a.neighbor).localeCompare(optionLabel(b.neighbor)));
  }, [items]);
  const visible = expanded ? neighbors : neighbors.slice(0, limit);
  return <section className={'arch-connections ' + (incoming ? 'arch-incoming' : 'arch-outgoing')} aria-label={title}>
    <h3>{title} <span>{items.length}</span></h3>
    {items.length === 0 && <p className="arch-no-links">None recorded</p>}
    <ul>{visible.map(({edges, neighbor}) => <li key={neighbor.id}>
      <ResourceButton node={neighbor} onSelect={onSelect}/>
      {edges.map(edge => <button key={edge.id} type="button" className="arch-relation" onClick={() => onSelect(edge)}
        aria-label={`Relationship ${edge.label || 'details'}: ${neighbor.label || name(neighbor)}`}>
        <span>{edge.label || 'Relationship'}</span>
        {edge.classification && <small>{evidenceLabel(edge.classification)}</small>}
      </button>)}
    </li>)}</ul>
    {neighbors.length > limit && <button type="button" className="arch-more" aria-expanded={expanded} onClick={() => setExpanded(!expanded)}>
      {expanded ? 'Show fewer' : `Show ${neighbors.length - limit} more`}
    </button>}
  </section>;
}

export function ArchitectureFocus({nodes, edges, focusId, onFocus, onSelect}: {
  nodes: Map<string, Resource>; edges: Relationship[]; focusId: string;
  onFocus: (id: string) => void; onSelect: SelectEvidence;
}) {
  const index = useMemo(() => {
    const incoming = new Map<string, Connection[]>(), outgoing = new Map<string, Connection[]>();
    for (const edge of edges) {
      const source = nodes.get(edge.source), target = nodes.get(edge.target);
      if (!source || !target) continue;
      if (!outgoing.has(source.id)) outgoing.set(source.id, []);
      if (!incoming.has(target.id)) incoming.set(target.id, []);
      outgoing.get(source.id)!.push({edge, neighbor: target});
      incoming.get(target.id)!.push({edge, neighbor: source});
    }
    const sorted = [...nodes.values()].sort((a, b) => optionLabel(a).localeCompare(optionLabel(b)) || a.id.localeCompare(b.id));
    const groups = [sorted.filter(node => workloads.has(kind(node))), sorted.filter(node => !workloads.has(kind(node)))];
    const candidates = groups[0].length ? groups[0] : groups[1];
    const degree = (node: Resource) => (incoming.get(node.id)?.length || 0) + (outgoing.get(node.id)?.length || 0);
    const initial = candidates.reduce<Resource | undefined>((best, node) => !best || degree(node) > degree(best) ? node : best, undefined);
    return {incoming, outgoing, groups, initial};
  }, [nodes, edges]);
  const focus = nodes.get(focusId) || index.initial;
  if (!focus) return <p className="arch-no-resources">No resources are available in this evidence.</p>;
  return <div className="arch-focus">
    <label className="arch-picker">Focus resource
      <select value={focus.id} onChange={event => onFocus(event.target.value)}>
        {index.groups.map((group, i) => group.length > 0 && <optgroup key={i} label={i ? 'Other resources' : 'Workloads'}>
          {group.map(node => <option key={node.id} value={node.id}>{optionLabel(node)}</option>)}
        </optgroup>)}
      </select>
    </label>
    <div className="arch-map" aria-label="Focused resource diagram">
      <Connections key={'in-' + focus.id} items={index.incoming.get(focus.id) || []} incoming onSelect={onSelect}/>
      <section className="arch-center" aria-label="Focused resource">
        <span className="arch-focus-icon"><Icon name={workloads.has(kind(focus)) ? 'server' : 'layers'}/></span>
        <ResourceButton node={focus} onSelect={onSelect}/>
        {focus.provenance && <span className="arch-provenance">{evidenceLabel(focus.provenance)}</span>}
      </section>
      <Connections key={'out-' + focus.id} items={index.outgoing.get(focus.id) || []} onSelect={onSelect}/>
    </div>
  </div>;
}
