import React from 'react';
import { Link, useLocation } from 'react-router-dom';

const styles = {
  nav: {
    background: '#1a1d27',
    borderBottom: '1px solid #2a2d3a',
    padding: '0 30px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    height: '64px',
  },
  logo: {
    fontSize: '20px',
    fontWeight: '700',
    color: 'white',
    textDecoration: 'none',
  },
  links: {
    display: 'flex',
    gap: '24px',
  },
  link: {
    color: '#888888',
    textDecoration: 'none',
    fontSize: '14px',
    fontWeight: '500',
    transition: 'color 0.2s',
  },
  activeLink: {
    color: '#2E75B6',
  },
  badge: {
    background: '#2E75B622',
    color: '#2E75B6',
    padding: '2px 8px',
    borderRadius: '10px',
    fontSize: '11px',
    marginLeft: '8px',
  }
};

function Navbar() {
  const location = useLocation();

  const isActive = (path) => location.pathname === path;

  return (
    <nav style={styles.nav}>
      <Link to="/" style={styles.logo}>
        🔐 LLM Scanner
      </Link>

      <div style={styles.links}>
        <Link to="/"        style={{...styles.link, ...(isActive('/') ? styles.activeLink : {})}}>
           Dashboard
        </Link>
        <Link to="/new-scan" style={{...styles.link, ...(isActive('/new-scan') ? styles.activeLink : {})}}>
            New Scan
        </Link>
        <Link to="/pricing"  style={{...styles.link, ...(isActive('/pricing') ? styles.activeLink : {})}}>
          Pricing
        </Link>
      </div>
      <div>
        <span style={styles.badge}>v1.0.0</span>
      </div>
    </nav>
  );
}

export default Navbar;