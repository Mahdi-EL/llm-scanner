import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';

const NAV_COMMANDS = [
  { id:'nav-dash',         icon:'⊞', label:'Go to Dashboard',    sub:'Home',                   path:'/' },
  { id:'nav-scan',         icon:'⚡', label:'New Security Scan',  sub:'Launch a scan',          path:'/new-scan' },
  { id:'nav-reports',      icon:'📄', label:'Reports',            sub:'All scan reports',       path:'/reports' },
  { id:'nav-targets',      icon:'🔌', label:'Targets and CI',     sub:'Saved targets, schedules, CI', path:'/targets' },
  { id:'nav-analytics',    icon:'📊', label:'Analytics',          sub:'Trends & insights',      path:'/analytics' },
  { id:'nav-threat-intel', icon:'🛡', label:'Attack library',    sub:'Categories and custom attacks',   path:'/threat-intel' },
  { id:'nav-settings',     icon:'⚙', label:'Settings',           sub:'Account & security',     path:'/settings' },
  { id:'nav-pricing',      icon:'💎', label:'Pricing Plans',      sub:'Upgrade plan',           path:'/pricing' },
];

export default function CommandPalette({ open, onClose, recentScans = [] }) {
  const [query,    setQuery]    = useState('');
  const [selected, setSelected] = useState(0);
  const inputRef  = useRef(null);
  const navigate  = useNavigate();

  useEffect(() => {
    if (open) {
      setQuery('');
      setSelected(0);
      setTimeout(() => inputRef.current?.focus(), 40);
    }
  }, [open]);

  const q = query.toLowerCase();

  const { groups, totalItems } = useMemo(() => {
    const filteredNav = NAV_COMMANDS.filter(c =>
      !q || c.label.toLowerCase().includes(q) || c.sub.toLowerCase().includes(q)
    );
    const filteredScans = recentScans
      .filter(s => s.status === 'complete' && (!q || s.target_name.toLowerCase().includes(q)))
      .slice(0, 5)
      .map(s => ({
        id   : s.scan_id,
        icon : '🛡️',
        label: s.target_name,
        sub  : `Score: ${s.summary?.security_score ?? '—'} · ${new Date(s.created_at).toLocaleDateString()}`,
        path : `/results/${s.scan_id}`,
      }));
    const g = [];
    let off = 0;
    if (filteredNav.length)   { g.push({ label:'Navigate',     items:filteredNav,   offset:off }); off += filteredNav.length; }
    if (filteredScans.length) { g.push({ label:'Recent Scans', items:filteredScans, offset:off }); off += filteredScans.length; }
    return { groups:g, totalItems:off };
  }, [q, recentScans]);

  const handleSelect = useCallback((item) => {
    onClose();
    if (item.path) navigate(item.path);
  }, [navigate, onClose]);

  useEffect(() => {
    if (!open) return;
    const handler = e => {
      if (e.key === 'Escape')    { onClose(); return; }
      if (e.key === 'ArrowDown') { e.preventDefault(); setSelected(s => Math.min(s + 1, totalItems - 1)); }
      if (e.key === 'ArrowUp')   { e.preventDefault(); setSelected(s => Math.max(s - 1, 0)); }
      if (e.key === 'Enter') {
        let flat = 0;
        for (const g of groups) {
          for (const item of g.items) {
            if (flat === selected) { handleSelect(item); return; }
            flat++;
          }
        }
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open, totalItems, selected, handleSelect, onClose, groups]);

  if (!open) return null;

  return (
    <div className="cmd-backdrop" onClick={onClose}>
      <div className="cmd-modal" onClick={e => e.stopPropagation()}>

        {/* Search */}
        <div className="cmd-search-row">
          <svg className="cmd-search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
          </svg>
          <input
            ref={inputRef}
            className="cmd-input"
            placeholder="Search pages, scans…"
            value={query}
            onChange={e => { setQuery(e.target.value); setSelected(0); }}
          />
          <button className="cmd-esc" onClick={onClose}>Esc</button>
        </div>

        {/* Results */}
        <div className="cmd-results">
          {totalItems === 0 ? (
            <div className="cmd-empty">No results for "{query}"</div>
          ) : (
            groups.map(g => (
              <div key={g.label}>
                <div className="cmd-section-label">{g.label}</div>
                {g.items.map((item, i) => {
                  const idx = g.offset + i;
                  const sel = idx === selected;
                  return (
                    <div
                      key={item.id}
                      className={`cmd-item${sel ? ' selected' : ''}`}
                      onClick={() => handleSelect(item)}
                      onMouseEnter={() => setSelected(idx)}
                    >
                      <div className="cmd-item-icon">
                        <span style={{ fontSize:'13px' }}>{item.icon}</span>
                      </div>
                      <div style={{ flex:1, minWidth:0 }}>
                        <div className="cmd-item-label">{item.label}</div>
                        {item.sub && <div className="cmd-item-sub">{item.sub}</div>}
                      </div>
                      <svg className="cmd-item-arrow" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="9 18 15 12 9 6"/>
                      </svg>
                    </div>
                  );
                })}
              </div>
            ))
          )}
        </div>

        {/* Footer */}
        <div className="cmd-footer">
          <span className="cmd-hint"><kbd className="cmd-kbd">↑↓</kbd> navigate</span>
          <span className="cmd-hint"><kbd className="cmd-kbd">↵</kbd> open</span>
          <span className="cmd-hint"><kbd className="cmd-kbd">Esc</kbd> close</span>
          <span style={{ marginLeft:'auto' }}>
            <kbd className="cmd-kbd">⌘K</kbd>
          </span>
        </div>

      </div>
    </div>
  );
}
