import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const s = {
  nav: {
    background    : '#1a1d27',
    borderBottom  : '1px solid #2a2d3a',
    padding       : '0 30px',
    display       : 'flex',
    alignItems    : 'center',
    justifyContent: 'space-between',
    height        : '64px',
  },
  logo: {
    fontSize      : '20px',
    fontWeight    : '700',
    color         : 'white',
    textDecoration: 'none',
  },
  link: {
    color         : '#888888',
    textDecoration: 'none',
    fontSize      : '14px',
    fontWeight    : '500',
    transition    : 'color 0.2s',
  },
  activeLink: { color: '#2E75B6' },
  badge: {
    background  : '#2E75B622',
    color       : '#2E75B6',
    padding     : '2px 8px',
    borderRadius: '10px',
    fontSize    : '11px',
  },
  planBadge: {
    padding     : '2px 10px',
    borderRadius: '10px',
    fontSize    : '11px',
    fontWeight  : '600',
  },
};

const PLAN_COLORS = {
  free      : { background: '#1e2340', color: '#64748b' },
  pro       : { background: '#1e3a5f', color: '#3b82f6' },
  enterprise: { background: '#1a2e1a', color: '#22c55e' },
};

function Navbar({ darkMode, toggleDarkMode }) {
  const location     = useLocation();
  const navigate     = useNavigate();
  const { user, logout } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);

  const isActive = path => location.pathname === path;
  const planColor = PLAN_COLORS[user?.plan] || PLAN_COLORS.free;

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <nav style={s.nav}>
      <Link to="/" style={s.logo}>🔐 LLM Scanner</Link>

      <div style={{ display: 'flex', gap: '24px', alignItems: 'center' }}>
        {user && (
          <>
            <Link to="/"        style={{ ...s.link, ...(isActive('/')         ? s.activeLink : {}) }}>Dashboard</Link>
            <Link to="/new-scan"style={{ ...s.link, ...(isActive('/new-scan') ? s.activeLink : {}) }}>New Scan</Link>
          </>
        )}
        <Link to="/pricing" style={{ ...s.link, ...(isActive('/pricing') ? s.activeLink : {}) }}>Pricing</Link>
      </div>

      <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
        <button className="theme-toggle" onClick={toggleDarkMode}>
          {darkMode ? '☀️ Light' : '🌙 Dark'}
        </button>

        {user ? (
          <div style={{ position: 'relative' }}>
            <button
              onClick={() => setMenuOpen(o => !o)}
              style={{
                background  : '#111320',
                border      : '1px solid #2a2d3a',
                borderRadius: '8px',
                padding     : '6px 14px',
                color       : 'white',
                cursor      : 'pointer',
                fontSize    : '13px',
                display     : 'flex',
                gap         : '8px',
                alignItems  : 'center',
              }}
            >
              <span style={{ ...s.planBadge, ...planColor }}>{user.plan || 'free'}</span>
              {user.username}
              <span style={{ color: '#64748b', fontSize: '10px' }}>▼</span>
            </button>

            {menuOpen && (
              <div style={{
                position  : 'absolute',
                right     : 0,
                top       : '44px',
                background: '#111320',
                border    : '1px solid #2a2d3a',
                borderRadius: '10px',
                padding   : '8px',
                minWidth  : '160px',
                zIndex    : 200,
              }}>
                <div style={{ padding: '8px 12px', color: '#64748b', fontSize: '12px', borderBottom: '1px solid #2a2d3a', marginBottom: '8px' }}>
                  {user.email || user.username}
                </div>
                <Link
                  to="/pricing"
                  onClick={() => setMenuOpen(false)}
                  style={{ display: 'block', padding: '8px 12px', color: '#e2e8f0', fontSize: '13px', textDecoration: 'none', borderRadius: '6px' }}
                >
                  Upgrade Plan
                </Link>
                <button
                  onClick={handleLogout}
                  style={{
                    display: 'block', width: '100%', padding: '8px 12px',
                    color: '#ef4444', fontSize: '13px', background: 'none',
                    border: 'none', cursor: 'pointer', textAlign: 'left', borderRadius: '6px',
                  }}
                >
                  Sign Out
                </button>
              </div>
            )}
          </div>
        ) : (
          <div style={{ display: 'flex', gap: '8px' }}>
            <Link to="/login"    style={{ ...s.link, padding: '6px 14px', border: '1px solid #2a2d3a', borderRadius: '8px' }}>Sign In</Link>
            <Link to="/register" style={{ ...s.link, ...s.activeLink, padding: '6px 14px', background: '#2E75B622', borderRadius: '8px' }}>Sign Up</Link>
          </div>
        )}

        <span style={s.badge}>v2.0.0</span>
      </div>
    </nav>
  );
}

export default Navbar;
