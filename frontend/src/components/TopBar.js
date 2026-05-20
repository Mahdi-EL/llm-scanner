import React, { useState, useRef, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const PAGE_TITLES = {
  '/'             : { title:'Dashboard',    icon:'⊞' },
  '/new-scan'     : { title:'New Scan',     icon:'⚡' },
  '/reports'      : { title:'Reports',      icon:'📄' },
  '/integrations' : { title:'Integrations', icon:'🔌' },
  '/analytics'    : { title:'Analytics',    icon:'📊' },
  '/threat-intel' : { title:'Threat Intel', icon:'🛡' },
  '/settings'     : { title:'Settings',     icon:'⚙' },
  '/pricing'      : { title:'Pricing',      icon:'💎' },
};

const INIT_NOTIFS = [
  { id:1, type:'critical', title:'Prompt injection detected',  body:'gpt-4o endpoint exposed system prompt via role-play vector',         time:'3m ago',  read:false },
  { id:2, type:'warning',  title:'High severity finding',      body:'Jailbreak template (DAN) succeeded on claude-3-haiku',               time:'42m ago', read:false },
  { id:3, type:'success',  title:'Scan completed',             body:'openai.example.com scored 76/100 — 12 findings',                    time:'1h ago',  read:false },
  { id:4, type:'info',     title:'Attack library updated',     body:'1 010 prompts across 21 categories now active',                     time:'2h ago',  read:true  },
  { id:5, type:'success',  title:'Weekly digest ready',        body:'3 scans this week · avg score 68 · 2 critical findings',            time:'1d ago',  read:true  },
];

const TYPE_COLOR = {
  critical : '#f87171',
  warning  : '#fb923c',
  success  : '#4ade80',
  info     : '#4a8af4',
};

export default function TopBar({ onOpenCmd }) {
  const location  = useLocation();
  const navigate  = useNavigate();
  const { user }  = useAuth();
  const [notifOpen, setNotifOpen] = useState(false);
  const [notifs,    setNotifs]    = useState(INIT_NOTIFS);
  const panelRef  = useRef(null);

  const unread = notifs.filter(n => !n.read).length;

  useEffect(() => {
    if (!notifOpen) return;
    const handler = e => { if (!panelRef.current?.contains(e.target)) setNotifOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [notifOpen]);

  const markAllRead  = () => setNotifs(ns => ns.map(n => ({ ...n, read:true })));
  const dismiss      = id  => setNotifs(ns => ns.filter(n => n.id !== id));

  const page    = PAGE_TITLES[location.pathname] || { title:'LLMScanner', icon:'🔐' };
  const initial = (user?.username || 'U')[0].toUpperCase();

  return (
    <div className="topbar">

      {/* ── Left: page identity ─────────────── */}
      <div className="topbar-left">
        <span className="topbar-page-icon">{page.icon}</span>
        <span className="topbar-page-title">{page.title}</span>
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
            onClick={() => { setNotifOpen(o => !o); if (!notifOpen && unread > 0) {} }}
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
                    <span style={{ background:'rgba(74,138,244,0.15)', color:'var(--blue)', border:'1px solid rgba(74,138,244,0.25)', padding:'1px 8px', borderRadius:'10px', fontSize:'10px', fontWeight:'700' }}>
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
                    <div>All caught up!</div>
                  </div>
                ) : notifs.map(n => (
                  <div key={n.id} className={`notif-item${n.read ? '' : ' unread'}`}>
                    <div className="notif-dot" style={{ background: TYPE_COLOR[n.type] || 'var(--blue)' }} />
                    <div style={{ flex:1, minWidth:0 }}>
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
                  <button className="notif-clear-all" onClick={() => setNotifs([])}>Clear all</button>
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
    </div>
  );
}
