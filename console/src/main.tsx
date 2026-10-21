import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import { savedTheme, ThemeProvider } from './Theme';
import '@xyflow/react/dist/style.css';
import './style.css';
import './theme.css';

document.documentElement.dataset.theme = savedTheme();
createRoot(document.getElementById('root')!).render(<StrictMode><ThemeProvider><App /></ThemeProvider></StrictMode>);
