import React, { useState, useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import Logo from './Logo';

const PLAN = {
  free      : { bg:'rgba(17,24,39,0.05)',  color:'#545b68', border:'1px solid rgba(17,24,39,0.10)' },
  pro       : { bg:'rgba(37,99,235,0.10)', color:'#2563eb', border:'1px solid rgba(37,99,235,0.28)' },
  enterprise: { bg:'rgba(22,163,74,0.10)', color:'#16a34a', border:'1px solid rgba(22,163,74,0.28)' },
};

export default function Navbar() {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [menu, setMenu]       = useState(false);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 12);
    window.addEventListener('scroll', onScroll);
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const active = path => location.pathname === path;
  const plan   = PLAN[user?.plan] || PLAN.free;
  const handleLogout = () => { logout(); navigate('/login'); };

  // Light glass navbar — clean SaaS (Linear/Vercel/Stripe).
  const onLanding = location.pathname === '/landing';
  const ink       = '#14161c';
  const inkMuted  = '#545b68';
  const accent    = '#2563eb';

  const link = (path) => ({
    fontSize    : '13px',
    fontWeight  : active(path) ? '700' : '500',
    color       : active(path) ? ink : inkMuted,
    textDecoration: 'none',
    transition  : 'color 0.15s',
    letterSpacing: '0.1px',
    padding     : '4px 0',
    borderBottom: active(path) ? `1.5px solid ${accent}` : '1.5px solid transparent',
  });

  return (
    <nav className="site-nav" style={{
      height       : '60px',
      position     : 'sticky',
      top          : 0,
      zIndex       : 200,
      display      : 'flex',
      alignItems   : 'center',
      justifyContent:'space-between',
      padding      : '0 56px',
      background   : scrolled ? 'rgba(255,255,255,0.85)' : 'rgba(255,255,255,0.6)',
      backdropFilter: 'blur(22px) saturate(1.4)',
      WebkitBackdropFilter: 'blur(22px) saturate(1.4)',
      borderBottom : `1px solid ${scrolled ? 'rgba(17,24,39,0.10)' : 'transparent'}`,
      transition   : 'background 0.3s, border-color 0.3s',
    }}>

      {/* Logo */}
      <Link to={user ? '/' : '/landing'} style={{ display:'flex', alignItems:'center', gap:'10px', textDecoration:'none', flexShrink:0 }}>
        <Logo size={28} />
        <span style={{ fontSize:'14px', fontWeight:'800', color:ink, letterSpacing:'-0.3px' }}>
          LLM<span style={{ color:accent }}>Scanner</span>
        </span>
      </Link>

      {/* Nav links */}
      <div className="site-nav-links" style={{ display:'flex', gap:'32px', alignItems:'center' }}>
        {user ? (
          <>
            <Link to="/"         style={link('/')}>Dashboard</Link>
            <Link to="/new-scan" style={link('/new-scan')}>New Scan</Link>
            <Link to="/pricing"  style={link('/pricing')}>Pricing</Link>
          </>
        ) : (
          <>
            <Link to="/landing" style={link('/landing')}>Product</Link>
            <Link to="/pricing" style={link('/pricing')}>Pricing</Link>
          </>
        )}
      </div>

      {/* Right */}
      <div style={{ display:'flex', gap:'10px', alignItems:'center', flexShrink:0 }}>
        {user ? (
          <div style={{ position:'relative' }}>
            <button
              onClick={() => setMenu(o => !o)}
              style={{
                display     : 'flex',
                alignItems  : 'center',
                gap         : '8px',
                background  : 'rgba(17,24,39,0.04)',
                border      : '1px solid rgba(17,24,39,0.10)',
                borderRadius: '7px',
                padding     : '6px 12px',
                color       : '#545b68',
                cursor      : 'pointer',
                fontSize    : '13px',
                fontFamily  : 'inherit',
                fontWeight  : '500',
                transition  : 'background 0.15s, border-color 0.15s',
              }}
            >
              <span style={{ ...plan, padding:'1px 8px', borderRadius:'10px', fontSize:'10px', fontWeight:'700', letterSpacing:'0.5px', textTransform:'uppercase' }}>
                {user.plan || 'free'}
              </span>
              <span style={{ color:ink, fontWeight:600 }}>{user.username}</span>
              <svg width="10" height="6" viewBox="0 0 10 6" fill="none">
                <path d="M1 1l4 4 4-4" stroke="rgba(17,24,39,0.4)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </button>

            {menu && (
              <>
                <div style={{ position:'fixed', inset:0, zIndex:190 }} onClick={() => setMenu(false)} />
                <div style={{
                  position    : 'absolute',
                  right       : 0,
                  top         : '48px',
                  background  : '#ffffff',
                  border      : '1px solid rgba(17,24,39,0.10)',
                  borderRadius: '10px',
                  padding     : '6px',
                  minWidth    : '210px',
                  zIndex      : 210,
                  boxShadow   : '0 12px 40px rgba(16,24,40,0.14), 0 0 0 1px rgba(17,24,39,0.05)',
                }}>
                  <div style={{ padding:'9px 12px 10px', borderBottom:'1px solid rgba(17,24,39,0.07)', marginBottom:'4px' }}>
                    <div style={{ fontSize:'11px', color:'var(--t3)', marginBottom:'1px', textTransform:'uppercase', letterSpacing:'0.5px' }}>Signed in as</div>
                    <div style={{ fontSize:'13px', color:'#14161c', fontWeight:'600' }}>{user.email || user.username}</div>
                  </div>
                  {[
                    { label:'Upgrade Plan', to:'/pricing' },
                  ].map(item => (
                    <Link key={item.label} to={item.to} onClick={() => setMenu(false)}
                      style={{ display:'block', padding:'8px 12px', color:'#545b68', fontSize:'13px', fontWeight:'500', borderRadius:'6px', transition:'background 0.12s' }}
                      onMouseEnter={e => e.target.style.background='rgba(17,24,39,0.05)'}
                      onMouseLeave={e => e.target.style.background='transparent'}
                    >{item.label}</Link>
                  ))}
                  <div style={{ borderTop:'1px solid rgba(17,24,39,0.07)', marginTop:'4px', paddingTop:'4px' }}>
                    <button
                      onClick={handleLogout}
                      style={{ display:'block', width:'100%', padding:'8px 12px', color:'#dc2626', fontSize:'13px', fontWeight:'500', fontFamily:'inherit', background:'none', border:'none', cursor:'pointer', textAlign:'left', borderRadius:'6px', transition:'background 0.12s' }}
                      onMouseEnter={e => e.currentTarget.style.background='rgba(220,38,38,0.08)'}
                      onMouseLeave={e => e.currentTarget.style.background='none'}
                    >Sign Out</button>
                  </div>
                </div>
              </>
            )}
          </div>
        ) : (
          <div style={{ display:'flex', gap:'8px' }}>
            <Link to="/login" style={{
              padding:'7px 16px',
              border:'1.5px solid rgba(17,24,39,0.16)',
              borderRadius:onLanding ? '999px' : '6px',
              color:'#545b68',
              fontSize:'13px', fontWeight:'600',
              transition:'color 0.15s, border-color 0.15s',
            }}>Sign In</Link>
            <Link to="/register" style={{
              padding:'7px 18px',
              background:'linear-gradient(135deg,#2563eb,#6366f1)',
              border:'none',
              borderRadius:onLanding ? '999px' : '6px',
              color:'#fff',
              fontSize:'13px', fontWeight:'700',
              boxShadow:'0 4px 18px -4px rgba(37,99,235,0.55)',
              transition:'opacity 0.15s, box-shadow 0.15s',
            }}>Get Started →</Link>
          </div>
        )}
      </div>
    </nav>
  );
}
