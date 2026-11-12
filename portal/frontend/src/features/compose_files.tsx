import {useEffect, useRef, useState} from 'react';
import {requestJson} from '../api';
import './compose_files.css';

interface MissingVariable {name: string; required: boolean; sources: string[]; services: string[]}
interface Inspection {files: string[]; default_files: string[]; missing_variables: MissingVariable[]}
interface InspectionInput {files: File[]; order: string | undefined; immediate: boolean}
interface InspectionState {input: InspectionInput; profiles: string; result: Inspection | null; error: string}

export function ComposeFiles({initialOrder = '', profiles = '', onStateChange}: {
  initialOrder?: string; profiles?: string; onStateChange: (message: string) => void;
}) {
  const [input, setInput] = useState<InspectionInput>({files: [], order: initialOrder, immediate: false});
  const [inspection, setInspection] = useState<InspectionState | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [knownVariables, setKnownVariables] = useState<Record<string, MissingVariable>>({});
  const valuesRef = useRef(values);
  const completed = useRef<InspectionState | null>(null);
  const busy = !!input.files.length && (inspection?.input !== input || inspection.profiles !== profiles);
  const candidates = inspection?.result?.files ?? null;
  const missing = inspection?.result?.missing_variables || [];
  const error = busy ? '' : inspection?.error || '';
  const order = input.order || '';
  const selected = order.split(/\r?\n/).map(name => name.trim()).filter(Boolean);
  const validation = busy ? 'Wait for Compose file inspection to finish.' : error
    || (candidates !== null && !candidates.length ? 'No Compose documents were found in these files.' : '')
    || (candidates?.length && !selected.length ? 'Choose at least one Compose document and its merge order.' : '')
    || (new Set(selected).size !== selected.length ? 'Select each Compose document only once.' : '')
    || (candidates && selected.some(name => !candidates.includes(name)) ? 'Select paths from the detected Compose documents.' : '');
  useEffect(() => { onStateChange(validation); }, [validation, onStateChange]);

  useEffect(() => {
    if (!input.files.length || (completed.current?.input === input && completed.current.profiles === profiles)) return;
    const controller = new AbortController();
    const timeout = setTimeout(async () => {
      let result: Inspection | null = null;
      let error = '';
      try {
        const body = new FormData();
        input.files.forEach(file => body.append('compose_uploads', file));
        if (input.order !== undefined) body.set('compose_files', input.order);
        body.set('compose_profiles', profiles);
        body.set('compose_variables', JSON.stringify(valuesRef.current));
        result = await requestJson<Inspection>('/api/public/compose/files', {
          method: 'POST', body, signal: controller.signal,
        });
      } catch (reason) {
        error = reason instanceof Error ? reason.message : 'Unable to inspect Compose files. Retry inspection.';
      }
      if (controller.signal.aborted) return;
      const nextInput = {...input, immediate: false, order: input.order ?? (result ? result.default_files.join('\n') : undefined)};
      const nextInspection = {input: nextInput, profiles, result: result || completed.current?.result || null, error};
      completed.current = nextInspection;
      setInput(nextInput);
      setInspection(nextInspection);
      if (result) setKnownVariables(previous => ({...previous, ...Object.fromEntries((result.missing_variables || []).map(variable => [variable.name, variable]))}));
    }, input.immediate ? 0 : 250);
    return () => { clearTimeout(timeout); controller.abort(); };
  }, [input, profiles]);

  function upload(files: File[]) {
    valuesRef.current = {};
    completed.current = null;
    setValues({}); setKnownVariables({}); setInspection(null);
    setInput({files, order: undefined, immediate: true});
  }
  function changeOrder(order: string) {
    setInput(previous => ({...previous, order, immediate: false}));
  }
  function recheck() { setInput(previous => ({...previous, immediate: true})); }
  function setValue(name: string, value: string | undefined) {
    const next = value === undefined ? {...valuesRef.current} : {...valuesRef.current, [name]: value};
    if (value === undefined) delete next[name];
    valuesRef.current = next;
    setValues(next);
  }
  function move(name: string, position: string) {
    const next = selected.filter(item => item !== name);
    if (position) next.splice(Number(position) - 1, 0, name);
    changeOrder(next.join('\n'));
  }
  const variables = [...missing, ...Object.keys(values).filter(name => !missing.some(variable => variable.name === name))
    .map(name => Object.hasOwn(knownVariables, name) ? knownVariables[name] : {name, required: false, sources: [], services: []})];

  return <>
    <label htmlFor="compose-uploads">Docker Compose files and companions <span className="muted">(optional; any filename, or ZIP / TAR bundles including gzip, bzip2 and xz)</span></label>
    <input id="compose-uploads" name="compose_uploads" type="file" multiple onChange={event => upload(Array.from(event.target.files || []))} aria-describedby="compose-help" />
    <small id="compose-help" className="muted">Files are inspected when selected. Bundles preserve folders and companion files. Preview discovers services and images without scanning.</small>
    {busy && <p role="status">Inspecting Compose documents and variables…</p>}
    {error && <p role="alert">{error} <button type="button" onClick={recheck}>Retry inspection</button></p>}
    {candidates !== null && <fieldset className="compose-file-picker">
      <legend>Detected Compose documents ({candidates.length})</legend>
      <p className="muted">Choose Skip or a merge position: 1 is the base, followed by overrides. Changing a position moves the file and renumbers the others.</p>
      {candidates.map((name, index) => <div key={name}>
        <label htmlFor={`compose-order-${index}`}>{name}</label>
        <select id={`compose-order-${index}`} value={selected.includes(name) ? String(selected.indexOf(name) + 1) : ''} onChange={event => move(name, event.target.value)}>
          <option value="">Skip</option>
          {candidates.map((_, position) => <option key={position} value={position + 1}>{position + 1}{position === 0 ? ' (base)' : ''}</option>)}
        </select>
      </div>)}
      {validation && <p role="status">{validation}</p>}
    </fieldset>}
    <label htmlFor="compose-files">Compose file order <span className="muted">(relative paths, one per line, base first then overrides)</span></label>
    <textarea id="compose-files" name="compose_files" rows={3} value={order} onChange={event => changeOrder(event.target.value)} placeholder={'compose.yaml\ncompose.production.yaml'} aria-describedby="compose-order-help" />
    <small id="compose-order-help" className="muted">Dropdown selections fill this order. You can also edit it directly. Documents are identified by their contents, including Compose.txt and compose.main.yaml(2).</small>
    <input type="hidden" name="compose_variables" value={JSON.stringify(values)} />
    {candidates !== null && !!candidates.length && <fieldset className="compose-variables">
      <legend>Compose variables</legend>
      <p className="muted">Values used in image references must resolve to identify images. Runtime-only values may be left blank. Enter values and scan directly, or recheck to discover variables used by nested expressions.</p>
      {!busy && !selected.length && <p>Choose at least one Compose document to check its variables.</p>}
      {!busy && !!selected.length && !variables.length && <p>No missing variables were found for the selected files and profiles.</p>}
      {variables.map((variable, index) => {
        const provided = Object.hasOwn(values, variable.name);
        return <div className="compose-variable" key={variable.name}>
          <label htmlFor={`compose-variable-${index}`}>{variable.name}</label>
          <small id={`compose-variable-details-${index}`} className="muted">
            {variable.required && 'Required by a Compose expression. '}
            {!!variable.sources.length && `Files: ${variable.sources.join(', ')}. `}
            {!!variable.services.length && `Services: ${variable.services.join(', ')}. `}
            {provided && !missing.some(item => item.name === variable.name) && 'Provided value retained.'}
          </small>
          <input id={`compose-variable-${index}`} type="password" autoComplete="off" maxLength={8192} value={provided ? values[variable.name] : ''}
            onChange={event => setValue(variable.name, event.target.value || undefined)} aria-describedby={`compose-variable-details-${index}`} />
          <label className="compose-variable-empty"><input type="checkbox" checked={provided && values[variable.name] === ''}
            onChange={event => setValue(variable.name, event.target.checked ? '' : undefined)} />Use an empty value for {variable.name}</label>
        </div>;
      })}
      <button type="button" className="secondary-button" onClick={recheck} disabled={busy}>Recheck variables</button>
      <small className="muted">Untouched blank fields are omitted. Supplied values are retained across rechecks and cleared when uploads change. Values are not saved to browser storage.</small>
    </fieldset>}
  </>;
}
