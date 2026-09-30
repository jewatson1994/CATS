import {Component, type ReactNode} from 'react';

export class ErrorBoundary extends Component<{children: ReactNode}, {failed: boolean}> {
  state = {failed: false};
  static getDerivedStateFromError() {return {failed: true};}
  render() {
    if (this.state.failed) return <section className="panel padded" role="alert">
      <h1>Unable to display this page</h1><p>Your saved data has not been changed.</p>
      <button onClick={() => window.location.reload()}>Reload page</button>
    </section>;
    return this.props.children;
  }
}
