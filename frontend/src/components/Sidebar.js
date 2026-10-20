import React, { useEffect, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import Logo from './Logo';

const IcoDashboard = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/>
    <rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>
  </svg>
);
const IcoScan = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    <line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
  </svg>
);
const IcoPricing = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/>
    <line x1="7" y1="7" x2="7.01" y2="7"/>
  </svg>
);
const IcoSignOut = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
    <polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>
  </svg>
);
const IcoPlus = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
    <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
  </svg>
);
const IcoReports = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
    <polyline points="14 2 14 8 20 8"/>
    <line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>
    <polyline points="10 9 9 9 8 9"/>
  </svg>
);
const IcoIntegrations = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/>
    <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
    <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
  </svg>
);
const IcoSettings = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="3"/>
    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
  </svg>
);
const IcoAnalytics = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/>
    <line x1="6" y1="20" x2="6" y2="14"/><line x1="2" y1="20" x2="22" y2="20"/>
  </svg>
);
const IcoThreatIntel = () => (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    <polyline points="9 12 11 14 15 10"/>
  </svg>
);
const IcoChevronLeft = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
    <polyline points="15 18 9 12 15 6"/>
  </svg>
);
const IcoChevronRight = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
    <polyline points="9 18 15 12 9 6"/>
  </svg>
);

const NAV_MAIN = [
  { path:'/',              icon:<IcoDashboard />,    label:'Dashboard' },
  { path:'/new-scan',      icon:<IcoScan />,         label:'New Scan' },
  { path:'/reports',       icon:<IcoReports />,      label:'Reports' },
  { path:'/targets',       icon:<IcoIntegrations />, label:'Targets & CI' },
  { path:'/analytics',     icon:<IcoAnalytics />,    label:'Analytics' },
  { path:'/threat-intel',  icon:<IcoThreatIntel />,  label:'Attack library' },
];

const NAV_BOTTOM = [
  { path:'/pricing',  icon:<IcoPricing />,  label:'Pricing' },
  { path:'/settings', icon:<IcoSettings />, label:'Settings' },
];

const PLAN_STYLE = {
  free      : { bg:'rgba(17,24,39,0.06)',  color:'#545b68', border:'rgba(17,24,39,0.1)' },
  pro       : { bg:'rgba(37,99,235,0.15)',   color:'#1d4ed8',               border:'rgba(37,99,235,0.3)' },
  enterprise: { bg:'rgba(34,197,94,0.12)',    color:'#166534',               border:'rgba(34,197,94,0.3)' },
};

export default function Sidebar({ mobileOpen = false, onClose }) {
  const location  = useLocation();
  const navigate  = useNavigate();
  const { user, logout, switchWorkspace } = useAuth();
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem('sidebar_collapsed') === '1'
  );

  const toggle = () => {
    setCollapsed(c => {
      const next = !c;
      localStorage.setItem('sidebar_collapsed', next ? '1' : '0');
      return next;
    });
  };

  useEffect(() => {
    if (!mobileOpen) return undefined;
    const onKey = e => { if (e.key === 'Escape') onClose?.(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [mobileOpen, onClose]);

  const isActive = path =>
    path === '/' ? location.pathname === '/' : location.pathname.startsWith(path);

  const ps      = PLAN_STYLE[user?.plan] || PLAN_STYLE.free;
  const initial = (user?.username || 'U')[0].toUpperCase();
  const isFree  = !user?.plan || user.plan === 'free';

  return (
    <>
    {mobileOpen && <div className="sidebar-backdrop" onClick={onClose} />}
    <aside className={`sidebar${collapsed && !mobileOpen ? ' collapsed' : ''}${mobileOpen ? ' mobile-open' : ''}`}>

      {/* ── Logo ──────────────────────────── */}
      <Link to="/" className="sidebar-logo" style={{ textDecoration:'none' }}>
        <div className="sidebar-logo-icon"><Logo size={26} /></div>
        <span className="sidebar-logo-text">
          LLM<span style={{ color:'var(--blue)' }}>Scanner</span>
        </span>
      </Link>

      {/* ── New Scan quick button ─────────── */}
      <div style={{ padding:'10px 10px 0' }}>
        <button
          onClick={() => navigate('/new-scan')}
          className="sidebar-new-scan"
          style={{
            display:'flex', alignItems:'center', justifyContent:'center', gap:'7px',
            width:'100%', padding:'9px',
            background:'var(--blue)', color:'#fff',
            border:'1px solid rgba(37,99,235,0.5)',
            borderRadius:'7px', font:'600 13px/1 inherit',
            cursor:'pointer',
            boxShadow:'0 2px 12px rgba(37,99,235,0.25), inset 0 1px 0 rgba(17,24,39,0.1)',
            transition:'background 0.15s, box-shadow 0.15s, transform 0.12s',
          }}
          onMouseEnter={e => { e.currentTarget.style.background='#1d4ed8'; e.currentTarget.style.transform='translateY(-1px)'; }}
          onMouseLeave={e => { e.currentTarget.style.background='var(--blue)'; e.currentTarget.style.transform='none'; }}
        >
          <IcoPlus />
          <span className="sidebar-new-scan-text">New Scan</span>
        </button>
      </div>

      {/* ── Nav ───────────────────────────── */}
      <nav className="sidebar-nav">
        <div className="sidebar-section-label">Menu</div>
        {NAV_MAIN.map(item => (
          <Link
            key={item.path}
            to={item.path}
            className={`sidebar-link${isActive(item.path) ? ' active' : ''}`}
            aria-current={isActive(item.path) ? 'page' : undefined}
          >
            <span className="sidebar-link-icon">{item.icon}</span>
            <span className="sidebar-link-label">{item.label}</span>
          </Link>
        ))}

        <div className="sidebar-section-label" style={{ marginTop:'12px' }}>Account</div>
        {NAV_BOTTOM.map(item => (
          <Link
            key={item.path}
            to={item.path}
            className={`sidebar-link${isActive(item.path) ? ' active' : ''}`}
            aria-current={isActive(item.path) ? 'page' : undefined}
          >
            <span className="sidebar-link-icon">{item.icon}</span>
            <span className="sidebar-link-label">{item.label}</span>
          </Link>
        ))}
      </nav>

      {/* ── Upgrade CTA (free users only) ── */}
      {isFree && (
        <div className="sidebar-upgrade">
          <div className="sidebar-upgrade-label">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><polyline points="17 11 12 6 7 11"/><polyline points="17 18 12 13 7 18"/></svg>
            Upgrade
          </div>
          <div className="sidebar-upgrade-title">Unlock Pro features</div>
          <div className="sidebar-upgrade-sub">200 scans a month, scheduled scans and regression alerts.</div>
          <Link to="/pricing" className="sidebar-upgrade-cta">View Plans →</Link>
        </div>
      )}

      {/* ── Collapse button ────────────────── */}
      <div style={{ padding:'0 10px 4px' }}>
        <button className="sidebar-collapse-btn" onClick={toggle} title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} aria-expanded={!collapsed}>
          {collapsed ? <IcoChevronRight /> : <IcoChevronLeft />}
        </button>
      </div>

      {/* ── User block ────────────────────── */}
      <div className="sidebar-bottom">
        <div className="sidebar-user-block">
          <div className="sidebar-avatar">{initial}</div>
          <div className="sidebar-user-meta">
            <div className="sidebar-user-name">{user?.username}</div>
            <span style={{
              background:ps.bg, color:ps.color,
              border:`1px solid ${ps.border}`,
              padding:'1px 7px', borderRadius:'8px',
              fontSize:'9px', fontWeight:'700',
              letterSpacing:'0.7px', textTransform:'uppercase',
              display:'inline-block', marginTop:'2px',
            }}>
              {user?.plan || 'free'}
            </span>
          </div>
        </div>
        {user?.workspaces?.length > 1 && (
          <label className="sidebar-workspace" style={{ display:'block', padding:'8px 2px 0', fontSize:'11px', color:'var(--t3)' }}>
            Workspace
            <select value={user.workspace?.id || user.id} onChange={e => switchWorkspace(e.target.value)}
              style={{ display:'block', width:'100%', marginTop:'4px', fontSize:'12px' }}>
              {user.workspaces.map(w => (
                <option key={w.id} value={w.id}>{w.name}{w.role !== 'owner' ? ` (${w.role})` : ''}</option>
              ))}
            </select>
          </label>
        )}
        <button className="sidebar-sign-out" onClick={() => { logout(); navigate('/login'); }}>
          <IcoSignOut /> <span>Sign out</span>
        </button>
      </div>
    </aside>
    </>
  );
}
