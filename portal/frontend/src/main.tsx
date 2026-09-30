import {createRoot} from 'react-dom/client';
import {App, readBootstrap} from './App';
import {ErrorBoundary} from './components/ErrorBoundary';

const root = document.getElementById('root');
if (!root) throw new Error('CATS root element is missing.');
createRoot(root).render(<ErrorBoundary><App initial={readBootstrap()}/></ErrorBoundary>);
