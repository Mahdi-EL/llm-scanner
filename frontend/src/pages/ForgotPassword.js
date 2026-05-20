import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { authAPI } from '../services/api';

export default function ForgotPassword() {
  const [email,   setEmail]   = useState('');
  const [sent,    setSent]    = useState(false);
  const [loading, setLoading] = useState(false);

  const submit = async e => {
    e.preventDefault();
    setLoading(true);
    try { await authAPI.forgotPassword(email); }
    finally { setSent(true); setLoading(false); }
  };

  return (
    <div style={{
      minHeight  : 'calc(100vh - 60px)',
      display    : 'flex',
      alignItems : 'center',
      justifyContent:'center',
      background : 'var(--bg)',
      padding    : '48px 24px',
    }}>
      <div style={{
        background  : 'var(--s1)',
        border      : '1px solid var(--b1)',
        borderRadius: '16px',
        padding     : '48px',
        width       : '100%',
        maxWidth    : '420px',
        boxShadow   : 'var(--sh-lg)',
        position    : 'relative',
        overflow    : 'hidden',
      }}>
        <div style={{ position:'absolute', top:0, left:0, right:0, height:'1px', background:'linear-gradient(90deg,transparent,rgba(255,255,255,0.07),transparent)' }} />

        <div style={{ textAlign:'center', marginBottom:'36px' }}>
          <div style={{
            width:'52px', height:'52px',
            background:'var(--blue-soft)',
            border:'1px solid rgba(74,138,244,0.25)',
            borderRadius:'14px',
            display:'flex', alignItems:'center', justifyContent:'center',
            fontSize:'22px', margin:'0 auto 20px',
          }}>🔑</div>
          <h1 style={{ fontSize:'22px', fontWeight:'800', letterSpacing:'-0.5px', marginBottom:'6px' }}>Reset your password</h1>
          <p style={{ fontSize:'14px', color:'var(--t2)' }}>Enter your email and we'll send a reset link</p>
        </div>

        {sent ? (
          <div style={{
            background:'var(--green-soft)', border:'1px solid rgba(34,197,94,0.25)',
            borderRadius:'10px', padding:'20px', textAlign:'center',
          }}>
            <div style={{ fontSize:'24px', marginBottom:'10px' }}>📬</div>
            <div style={{ fontSize:'14px', color:'#4ade80', fontWeight:'600', marginBottom:'6px' }}>Check your inbox</div>
            <div style={{ fontSize:'13px', color:'var(--t2)', lineHeight:'1.5' }}>
              If that email is registered, a reset link has been sent.
            </div>
          </div>
        ) : (
          <form onSubmit={submit}>
            <div className="form-group">
              <label>Email address</label>
              <input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="you@example.com" />
            </div>
            <button type="submit" className="btn-primary" disabled={loading}
              style={{ width:'100%', padding:'13px', fontSize:'14px', justifyContent:'center', borderRadius:'8px' }}>
              {loading ? <><span className="spinner" /> &nbsp;Sending…</> : 'Send Reset Link →'}
            </button>
          </form>
        )}

        <div className="auth-divider" style={{ marginTop:'28px' }}>
          <Link to="/login">← Back to Sign In</Link>
        </div>
      </div>
    </div>
  );
}
