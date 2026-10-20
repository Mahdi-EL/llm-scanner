import React, { useState, useRef, useEffect, useCallback } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { scansAPI } from '../services/api';
import { relTime } from '../utils/format';

const PAGE_TITLES = {
  '/'             : { title:'Dashboard',    icon:'⊞' },
  '/new-scan'     : { title:'New Scan',     icon:'⚡' },
  '/reports'      : { title:'Reports',      icon:'📄' },
  '/targets'      : { title:'Targets and CI', icon:'🔌' },
  '/analytics'    : { title:'Analytics',    icon:'📊' },
  '/threat-intel' : { title:'Attack library', icon:'🛡' },
  '/settings'     : { title:'Settings',     icon:'⚙' },
  '/pricing'      : { title:'Pricing',      icon:'💎' },
};

// Notifications come from the user's own recent scans. What has been read is
// remembered per browser (a convenience only; nothing breaks without it).
// Per account, so another account signing in on this browser starts with its own state.
const READ_KEY   = id => `notifs_read_until:${id}`;
const HIDDEN_KEY = id => `notifs_hidden:${id}`;
const OPENED_KEY = id => `notifs_opened:${id}`;

function storageGet(key, fallback) {
  try { const v = localStorage.getItem(key); return v == null ? fallback : JSON.parse(v); } catch { return fallback; }
}
function storageSet(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* private mode */ }
}

function toNotification(scan) {
  const s = scan.summary || {};
  const when = scan.completed_at || scan.created_at;
  if (scan.status === 'complete') {
    return {
      id: scan.scan_id, when,
      type: s.critical ? 'critical' : s.high ? 'warning' : 'success',
      title: `Scan complete: ${scan.target_name}`,
      body: `Score ${s.security_score ?? 0}/100, grade ${s.grade || '?'} · ${s.critical || 0} critical, ${s.high || 0} high`,
    };
  }
  if (scan.status === 'failed' || scan.status === 'cancelled') {
    return {
      id: scan.scan_id, when, type: 'warning',
      title: `Scan ${scan.status}: ${scan.target_name}`,
      body: scan.error_message || 'The scan stopped before it finished.',
    };
  }
  return null;
}

const TYPE_COLOR = {
  critical : '#dc2626',
  warning  : '#ea580c',
  success  : '#16a34a',
  info     : '#2563eb',
};

export default function TopBar({ onOpenCmd, onOpenNav }) {
  const location  = useLocation();
  const navigate  = useNavigate();
  const { user }  = useAuth();
  const [notifOpen, setNotifOpen] = useState(false);
  const [items,     setItems]     = useState([]);
  const uid = user?.id || 'anon';
  const [readUntil, setReadUntil] = useState(() => storageGet(READ_KEY(uid), ''));
  const [hidden,    setHidden]    = useState(() => storageGet(HIDDEN_KEY(uid), []));
  const [opened,    setOpened]    = useState(() => storageGet(OPENED_KEY(uid), []));
  useEffect(() => {
    setReadUntil(storageGet(READ_KEY(uid), ''));
    setHidden(storageGet(HIDDEN_KEY(uid), []));
    setOpened(storageGet(OPENED_KEY(uid), []));
  }, [uid]);
  const panelRef  = useRef(null);

  const load = useCallback(() => {
    scansAPI.list({ limit: 10 })
      .then(r => setItems(r.data.scans.map(toNotification).filter(Boolean)))
      .catch(() => {});
  }, []);
  useEffect(() => { load(); }, [load, location.pathname]);

  const notifs = items
    .filter(n => !hidden.includes(n.id))
    .map(n => ({ ...n, time: relTime(n.when), read: opened.includes(n.id) || (!!readUntil && n.when <= readUntil) }));
  const unread = notifs.filter(n => !n.read).length;

  useEffect(() => {
    if (!notifOpen) return;
    const handler = e => { if (!panelRef.current?.contains(e.target)) setNotifOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [notifOpen]);

  const markAllRead  = () => {
    const latest = items.reduce((m, n) => (n.when > m ? n.when : m), '');
    setReadUntil(latest); storageSet(READ_KEY(uid), latest);
  };
  const dismiss      = id  => { const next = [...hidden, id].slice(-200); setHidden(next); storageSet(HIDDEN_KEY(uid), next); };
  const open         = n   => {
    if (!opened.includes(n.id)) { const next = [...opened, n.id].slice(-200); setOpened(next); storageSet(OPENED_KEY(uid), next); }
    setNotifOpen(false); navigate(`/results/${n.id}`);
  };

  const page    = PAGE_TITLES[location.pathname]
    || (location.pathname.startsWith('/results/') ? { title:'Scan results', icon:'📄' } : { title:'LLMScanner', icon:'🔐' });
  const initial = (user?.username || 'U')[0].toUpperCase();

  return (
    <header className="topbar">

      {/* ── Left: page identity ─────────────── */}
      <div className="topbar-left">
        <button className="topbar-menu-btn" onClick={onOpenNav} aria-label="Open menu">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/>
          </svg>
        </button>
        <span className="topbar-page-icon">{page.icon}</span>
        <span className="topbar-page-title">{page.title}</span>
        {user?.workspace && (
          <span style={{ fontSize:'12px', color:'var(--t3)', marginLeft:'10px', whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis' }}
            title="The team workspace you're working in. Switch in the sidebar.">
            in {user.workspace.name} · {user.workspace.role}
          </span>
        )}
      </div>

      {/* ── Right: actions ──────────────────── */}
      <div className="topbar-right">

        {/* Search shortcut */}
        <button className="topbar-cmd-btn" onClick={onOpenCmd}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
          </svg>
          <span className="topbar-cmd-label">Search</span>
          <kbd className="topbar-kbd">⌘K</kbd>
        </button>

        {/* New Scan quick button */}
        <button className="topbar-new-scan-btn" onClick={() => navigate('/new-scan')}>
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
            <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
          </svg>
          New Scan
        </button>

        {/* Notification bell */}
        <div style={{ position:'relative' }} ref={panelRef}>
          <button
            className={`topbar-icon-btn${notifOpen ? ' active' : ''}`}
            onClick={() => { if (!notifOpen) load(); setNotifOpen(o => !o); }}
            title="Notifications"
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
              <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
            </svg>
            {unread > 0 && <span className="topbar-badge">{unread > 9 ? '9+' : unread}</span>}
          </button>

          {notifOpen && (
            <div className="notif-panel">
              <div className="notif-header">
                <span className="notif-title">Notifications</span>
                <div style={{ display:'flex', gap:'8px', alignItems:'center' }}>
                  {unread > 0 && (
                    <span style={{ background:'rgba(37,99,235,0.15)', color:'var(--blue)', border:'1px solid rgba(37,99,235,0.25)', padding:'1px 8px', borderRadius:'10px', fontSize:'10px', fontWeight:'700' }}>
                      {unread} new
                    </span>
                  )}
                  {unread > 0 && (
                    <button className="notif-mark-read" onClick={markAllRead}>Mark all read</button>
                  )}
                </div>
              </div>

              <div className="notif-list">
                {notifs.length === 0 ? (
                  <div className="notif-empty">
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" style={{ color:'var(--t3)', marginBottom:'8px' }}>
                      <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
                      <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
                    </svg>
                    <div>No finished scans yet.</div>
                  </div>
                ) : notifs.map(n => (
                  <div key={n.id} className={`notif-item${n.read ? '' : ' unread'}`}>
                    <div className="notif-dot" style={{ background: TYPE_COLOR[n.type] || 'var(--blue)' }} />
                    <div style={{ flex:1, minWidth:0, cursor:'pointer' }} onClick={() => open(n)}>
                      <div className="notif-item-title">{n.title}</div>
                      <div className="notif-item-body">{n.body}</div>
                      <div className="notif-item-time">{n.time}</div>
                    </div>
                    <button className="notif-dismiss" onClick={() => dismiss(n.id)} title="Dismiss">
                      <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                        <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                      </svg>
                    </button>
                  </div>
                ))}
              </div>

              {notifs.length > 0 && (
                <div className="notif-footer">
                  <button className="notif-clear-all" onClick={() => notifs.forEach(n => dismiss(n.id))}>Clear all</button>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Avatar → settings */}
        <button className="topbar-avatar" onClick={() => navigate('/settings')} title="Account settings">
          {initial}
        </button>
      </div>
    </header>
  );
}
