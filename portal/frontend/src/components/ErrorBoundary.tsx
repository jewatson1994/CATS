import {Component, type ReactNode} from 'react';
import {ErrorDetails} from './ErrorDetails';
import {localDiagnostic} from '../diagnostics';

export class ErrorBoundary extends Component<{children: ReactNode}, {failed: boolean}> {
  state = {failed: false};
  static getDerivedStateFromError() {return {failed: true};}
  render() {
    if (this.state.failed) return <section className="panel padded" role="alert">
      <h1>Unable to display this page</h1><ErrorDetails diagnostic={{...localDiagnostic('The browser could not display this page.', 0, 'render page', 'UI_RENDER_FAILED'), category: 'frontend', resolution: ['Reload the page. If the problem continues, share this report with an administrator.']}}/>
      <button onClick={() => window.location.reload()}>Reload page</button>
    </section>;
    return this.props.children;
  }
}
