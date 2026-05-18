import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const s = {
  nav: {
    background    : 'rgba(13, 17, 23, 0.85)',
    backdropFilter: 'blur(12px)',
    borderBottom  : '1px solid rgba(255,255,255,0.07)',
    padding       : '0 32px',
    display       : 'flex',
    alignItems    : 'center',
    justifyContent: 'space-between',
    height        : '64px',
    position      : 'sticky',
    top           : 0,
    zIndex        : 100,
  },
  logo: {
    display       : 'flex',
    alignItems    : 'center',
    gap           : '10px',
    textDecoration: 'none',
  },
  logoIcon: {
    width         : '32px',
    height        : '32px',
    background    : 'linear-gradient(135deg, #6366f1, #a78bfa)',
    borderRadius  : '9px',
    display       : 'flex',
    alignItems    : 'center',
    justifyContent: 'center',
    fontSize      : '14px',
    flexShrink    : 0,
  },
  logoText: {
    fontSize  : '16px',
    fontWeight: '700',
    color     : '#fff',
    letterSpacing: '-0.3px',
  },
  link: {
    color         : '#64748b',
    textDecoration: 'none',
    fontSize      : '13px',
    fontWeight    : '500',
    transition    : 'color 0.2s',
    padding       : '4px 0',
  },
  activeLink: {
    color: '#6366f1',
  },
  versionBadge: {
    background  : 'rgba(99,102,241,0.1)',
    color       : '#6366f1',
    border      : '1px solid rgba(99,102,241,0.2)',
    padding     : '2px 8px',
    borderRadius: '20px',
    fontSize    : '10px',
    fontWeight  : '700',
    letterSpacing: '0.3px',
  },
};

const PLAN_COLORS = {
  free      : { background: 'rgba(100,116,139,0.12)', color: '#94a3b8',  border: '1px solid rgba(100,116,139,0.2)' },
  pro       : { background: 'rgba(99,102,241,0.12)',  color: '#818cf8',  border: '1px solid rgba(99,102,241,0.2)' },
  enterprise: { background: 'rgba(34,197,94,0.12)',   color: '#4ade80',  border: '1px solid rgba(34,197,94,0.2)' },
};

function Navbar({ darkMode, toggleDarkMode }) {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);

  const isActive  = path => location.pathname === path;
  const planColor = PLAN_COLORS[user?.plan] || PLAN_COLORS.free;

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <nav style={s.nav}>
      {/* Logo */}
      <Link to="/" style={s.logo}>
        <span style={s.logoIcon}>🔐</span>
        <span style={s.logoText}>LLM Scanner</span>
      </Link>

      {/* Nav links */}
      <div style={{ display: 'flex', gap: '28px', alignItems: 'center' }}>
        {user && (
          <>
            <Link to="/"         style={{ ...s.link, ...(isActive('/')         ? s.activeLink : {}) }}>Dashboard</Link>
            <Link to="/new-scan" style={{ ...s.link, ...(isActive('/new-scan') ? s.activeLink : {}) }}>New Scan</Link>
          </>
        )}
        <Link to="/pricing" style={{ ...s.link, ...(isActive('/pricing') ? s.activeLink : {}) }}>Pricing</Link>
      </div>

      {/* Right side */}
      <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
        <button className="theme-toggle" onClick={toggleDarkMode}>
          {darkMode ? '☀' : '🌙'}
        </button>

        {user ? (
          <div style={{ position: 'relative' }}>
            <button
              onClick={() => setMenuOpen(o => !o)}
              style={{
                background  : 'rgba(30,35,50,0.8)',
                border      : '1px solid rgba(255,255,255,0.08)',
                borderRadius: '9px',
                padding     : '6px 12px',
                color       : '#e2e8f0',
                cursor      : 'pointer',
                fontSize    : '13px',
                fontFamily  : 'inherit',
                fontWeight  : '500',
                display     : 'flex',
                gap         : '8px',
                alignItems  : 'center',
                transition  : 'border-color 0.2s',
              }}
            >
              <span style={{
                ...planColor,
                padding     : '1px 8px',
                borderRadius: '10px',
                fontSize    : '10px',
                fontWeight  : '700',
                letterSpacing: '0.3px',
                textTransform: 'uppercase',
              }}>
                {user.plan || 'free'}
              </span>
              <span>{user.username}</span>
              <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
                <path d="M2 4l3 3 3-3" stroke="#64748b" strokeWidth="1.5" strokeLinecap="round"/>
              </svg>
            </button>

            {menuOpen && (
              <>
                <div
                  style={{ position: 'fixed', inset: 0, zIndex: 150 }}
                  onClick={() => setMenuOpen(false)}
                />
                <div style={{
                  position    : 'absolute',
                  right       : 0,
                  top         : '48px',
                  background  : '#0d1117',
                  border      : '1px solid rgba(255,255,255,0.1)',
                  borderRadius: '12px',
                  padding     : '8px',
                  minWidth    : '200px',
                  zIndex      : 200,
                  boxShadow   : '0 8px 40px rgba(0,0,0,0.5)',
                }}>
                  <div style={{
                    padding     : '8px 12px',
                    color       : '#64748b',
                    fontSize    : '12px',
                    borderBottom: '1px solid rgba(255,255,255,0.07)',
                    marginBottom: '6px',
                  }}>
                    {user.email || user.username}
                  </div>
                  <Link
                    to="/pricing"
                    onClick={() => setMenuOpen(false)}
                    style={{
                      display     : 'block',
                      padding     : '8px 12px',
                      color       : '#e2e8f0',
                      fontSize    : '13px',
                      fontWeight  : '500',
                      textDecoration: 'none',
                      borderRadius: '7px',
                      transition  : 'background 0.15s',
                    }}
                    onMouseEnter={e => e.target.style.background = 'rgba(255,255,255,0.05)'}
                    onMouseLeave={e => e.target.style.background = 'transparent'}
                  >
                    ↑ Upgrade Plan
                  </Link>
                  <button
                    onClick={handleLogout}
                    style={{
                      display     : 'block',
                      width       : '100%',
                      padding     : '8px 12px',
                      color       : '#ef4444',
                      fontSize    : '13px',
                      fontWeight  : '500',
                      fontFamily  : 'inherit',
                      background  : 'none',
                      border      : 'none',
                      cursor      : 'pointer',
                      textAlign   : 'left',
                      borderRadius: '7px',
                      transition  : 'background 0.15s',
                    }}
                    onMouseEnter={e => e.currentTarget.style.background = 'rgba(239,68,68,0.08)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'none'}
                  >
                    Sign Out
                  </button>
                </div>
              </>
            )}
          </div>
        ) : (
          <div style={{ display: 'flex', gap: '8px' }}>
            <Link
              to="/login"
              style={{
                ...s.link,
                padding     : '6px 14px',
                border      : '1px solid rgba(255,255,255,0.08)',
                borderRadius: '8px',
                color       : '#94a3b8',
              }}
            >
              Sign In
            </Link>
            <Link
              to="/register"
              style={{
                padding     : '6px 14px',
                background  : 'linear-gradient(135deg, #6366f1, #818cf8)',
                borderRadius: '8px',
                color       : 'white',
                textDecoration: 'none',
                fontSize    : '13px',
                fontWeight  : '600',
                boxShadow   : '0 2px 10px rgba(99,102,241,0.3)',
              }}
            >
              Sign Up
            </Link>
          </div>
        )}

        <span style={s.versionBadge}>v2.0</span>
      </div>
    </nav>
  );
}

export default Navbar;
