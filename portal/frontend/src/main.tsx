import {createRoot} from 'react-dom/client';
import {App, preparePage, readBootstrap} from './App';
import {ErrorBoundary} from './components/ErrorBoundary';
// Design-system layer: bundled after /static/app.css so it is the final presentation layer.
import './styles/design-system.css';

const root = document.getElementById('root');
if (!root) throw new Error('CATS root element is missing.');
const initial = readBootstrap();
// A lazily split page renders as soon as its chunk is here, without the
// Suspense fallback and React's throttled reveal; other chunks load on idle.
const start = () => createRoot(root).render(<ErrorBoundary><App initial={initial}/></ErrorBoundary>);
void preparePage(initial).then(start, start);
