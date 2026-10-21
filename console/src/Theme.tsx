import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';

export const themes = [
  { id: 'indigo', name: '蓝紫', accent: '#4f46e5', secondary: '#8b5cf6', nav: '#15233f', canvas: '#f8faff', soft: '#e0e7ff', series: ['#6366f1', '#8b5cf6', '#38bdf8', '#fbbf24', '#34d399', '#94a3b8', '#c7d2fe'] },
  { id: 'forest', name: '青绿', accent: '#0f766e', secondary: '#3782a2', nav: '#183b32', canvas: '#f6faf8', soft: '#d5eee5', series: ['#0f766e', '#3782a2', '#6bbba4', '#d9ab50', '#94a3b8', '#829da3', '#d1e8df'] },
  { id: 'sand', name: '暖砂', accent: '#a85d24', secondary: '#b68a54', nav: '#352b24', canvas: '#fcfaf6', soft: '#f4e5d2', series: ['#a85d24', '#b68a54', '#cfb383', '#78978d', '#9b8cab', '#a2a5a4', '#e8dccc'] },
] as const;
type ThemeId = typeof themes[number]['id'];
const storageKey = 'traceshield-color-theme';
export function savedTheme(): ThemeId {
  try { return themes.find(theme => theme.id === window.localStorage.getItem(storageKey))?.id ?? 'indigo'; }
  catch { return 'indigo'; }
}
const ThemeContext = createContext({ theme: 'indigo' as ThemeId, palette: themes[0] as typeof themes[number], setTheme: (_id: ThemeId) => {} });
export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<ThemeId>(savedTheme);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { window.localStorage.setItem(storageKey, theme); } catch { /* 禁用存储时仍允许本页切换。 */ }
  }, [theme]);
  useEffect(() => {
    const sync = (event: StorageEvent) => { if (event.key === storageKey) setTheme(savedTheme()); };
    window.addEventListener('storage', sync);
    return () => window.removeEventListener('storage', sync);
  }, []);
  const palette = themes.find(item => item.id === theme) ?? themes[0];
  return <ThemeContext value={{ theme, palette, setTheme }}>{children}</ThemeContext>;
}
export const useTheme = () => useContext(ThemeContext);
export function ThemeSwitcher() {
  const { theme, setTheme, palette } = useTheme();
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null), trigger = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!open) return;
    const outside = (event: MouseEvent) => { if (!root.current?.contains(event.target as Node)) setOpen(false); };
    const escape = (event: KeyboardEvent) => { if (event.key === 'Escape') { setOpen(false); trigger.current?.focus(); } };
    document.addEventListener('mousedown', outside); document.addEventListener('keydown', escape);
    return () => { document.removeEventListener('mousedown', outside); document.removeEventListener('keydown', escape); };
  }, [open]);
  return <div className="theme-switcher" ref={root}><button ref={trigger} className="theme-trigger" aria-label="选择界面配色" aria-haspopup="dialog" aria-expanded={open} title={`界面配色：${palette.name}`} onClick={() => setOpen(value => !value)}><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true"><path d="M12 3a9 9 0 1 0 0 18h1.4a2 2 0 0 0 1.4-3.4 1.5 1.5 0 0 1 1.1-2.6H18a3 3 0 0 0 3-3 9 9 0 0 0-9-9Z" /><circle cx="7.5" cy="10" r=".8" /><circle cx="11" cy="6.8" r=".8" /><circle cx="16" cy="8.5" r=".8" /></svg><span>配色</span><i style={{ background: palette.accent }} /></button>{open && <div className="theme-menu" role="dialog" aria-label="界面配色"><p>界面配色</p><div role="group" aria-label="配色方案">{themes.map(item => <button key={item.id} data-theme-choice={item.id} aria-pressed={theme === item.id} onClick={() => { setTheme(item.id); setOpen(false); trigger.current?.focus(); }}><span className="theme-preview" style={{ background: `linear-gradient(110deg, ${item.nav} 40%, ${item.accent} 40%, ${item.soft})` }} /><span>{item.name}</span>{theme === item.id && <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><path d="m5 12 4 4L19 6" /></svg>}</button>)}</div></div>}</div>;
}
