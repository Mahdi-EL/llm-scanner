import React, { useState, useEffect } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const PLAN = {
  free      : { bg:'rgba(255,255,255,0.06)', color:'rgba(255,255,255,0.4)', border:'1px solid rgba(255,255,255,0.08)' },
  pro       : { bg:'rgba(74,138,244,0.15)',  color:'#93c5fd',              border:'1px solid rgba(74,138,244,0.3)' },
  enterprise: { bg:'rgba(34,197,94,0.12)',   color:'#86efac',              border:'1px solid rgba(34,197,94,0.25)' },
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

  const link = (path) => ({
    fontSize    : '13px',
    fontWeight  : active(path) ? '600' : '400',
    color       : active(path) ? '#ffffff' : 'rgba(255,255,255,0.42)',
    textDecoration: 'none',
    transition  : 'color 0.15s',
    letterSpacing: '0.1px',
    padding     : '4px 0',
    borderBottom: active(path) ? '1px solid rgba(74,138,244,0.7)' : '1px solid transparent',
  });

  return (
    <nav style={{
      height       : '60px',
      position     : 'sticky',
      top          : 0,
      zIndex       : 200,
      display      : 'flex',
      alignItems   : 'center',
      justifyContent:'space-between',
      padding      : '0 56px',
      background   : scrolled ? 'rgba(7,7,10,0.85)' : 'rgba(7,7,10,0.6)',
      backdropFilter: 'blur(20px)',
      WebkitBackdropFilter: 'blur(20px)',
      borderBottom : `1px solid ${scrolled ? 'rgba(255,255,255,0.07)' : 'transparent'}`,
      transition   : 'background 0.3s, border-color 0.3s',
    }}>

      {/* Logo */}
      <Link to={user ? '/' : '/landing'} style={{ display:'flex', alignItems:'center', gap:'10px', textDecoration:'none', flexShrink:0 }}>
        <div style={{
          width:'30px', height:'30px',
          border:'1px solid rgba(74,138,244,0.3)',
          borderRadius:'7px',
          background:'rgba(74,138,244,0.1)',
          display:'flex', alignItems:'center', justifyContent:'center',
          fontSize:'13px',
        }}>🔐</div>
        <span style={{ fontSize:'14px', fontWeight:'800', color:'#fff', letterSpacing:'-0.3px' }}>
          LLM<span style={{ color:'rgba(74,138,244,0.9)' }}>Scanner</span>
        </span>
      </Link>

      {/* Nav links */}
      <div style={{ display:'flex', gap:'32px', alignItems:'center' }}>
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
                background  : 'rgba(255,255,255,0.05)',
                border      : '1px solid rgba(255,255,255,0.09)',
                borderRadius: '7px',
                padding     : '6px 12px',
                color       : 'rgba(255,255,255,0.75)',
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
              <span>{user.username}</span>
              <svg width="10" height="6" viewBox="0 0 10 6" fill="none">
                <path d="M1 1l4 4 4-4" stroke="rgba(255,255,255,0.25)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </button>

            {menu && (
              <>
                <div style={{ position:'fixed', inset:0, zIndex:190 }} onClick={() => setMenu(false)} />
                <div style={{
                  position    : 'absolute',
                  right       : 0,
                  top         : '48px',
                  background  : '#0e0e12',
                  border      : '1px solid rgba(255,255,255,0.09)',
                  borderRadius: '10px',
                  padding     : '6px',
                  minWidth    : '210px',
                  zIndex      : 210,
                  boxShadow   : '0 8px 40px rgba(0,0,0,0.7), 0 0 0 1px rgba(255,255,255,0.04)',
                }}>
                  <div style={{ padding:'9px 12px 10px', borderBottom:'1px solid rgba(255,255,255,0.06)', marginBottom:'4px' }}>
                    <div style={{ fontSize:'11px', color:'rgba(255,255,255,0.25)', marginBottom:'1px', textTransform:'uppercase', letterSpacing:'0.5px' }}>Signed in as</div>
                    <div style={{ fontSize:'13px', color:'rgba(255,255,255,0.6)', fontWeight:'500' }}>{user.email || user.username}</div>
                  </div>
                  {[
                    { label:'Upgrade Plan', to:'/pricing' },
                  ].map(item => (
                    <Link key={item.label} to={item.to} onClick={() => setMenu(false)}
                      style={{ display:'block', padding:'8px 12px', color:'rgba(255,255,255,0.65)', fontSize:'13px', fontWeight:'500', borderRadius:'6px', transition:'background 0.12s' }}
                      onMouseEnter={e => e.target.style.background='rgba(255,255,255,0.06)'}
                      onMouseLeave={e => e.target.style.background='transparent'}
                    >{item.label}</Link>
                  ))}
                  <div style={{ borderTop:'1px solid rgba(255,255,255,0.06)', marginTop:'4px', paddingTop:'4px' }}>
                    <button
                      onClick={handleLogout}
                      style={{ display:'block', width:'100%', padding:'8px 12px', color:'#f87171', fontSize:'13px', fontWeight:'500', fontFamily:'inherit', background:'none', border:'none', cursor:'pointer', textAlign:'left', borderRadius:'6px', transition:'background 0.12s' }}
                      onMouseEnter={e => e.currentTarget.style.background='rgba(240,68,56,0.08)'}
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
              padding:'7px 16px', border:'1px solid rgba(255,255,255,0.1)',
              borderRadius:'6px', color:'rgba(255,255,255,0.5)',
              fontSize:'13px', fontWeight:'500',
              transition:'color 0.15s, border-color 0.15s',
            }}>Sign In</Link>
            <Link to="/register" style={{
              padding:'7px 18px',
              background:'linear-gradient(135deg,#4a8af4,#9b6ef3)',
              borderRadius:'6px', color:'#fff',
              fontSize:'13px', fontWeight:'700',
              boxShadow:'0 2px 12px rgba(74,138,244,0.3)',
              transition:'opacity 0.15s, box-shadow 0.15s',
            }}>Get Started →</Link>
          </div>
        )}
      </div>
    </nav>
  );
}
