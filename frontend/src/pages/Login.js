import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const SCAN_ATTACKS = [
  { name:'Prompt Injection', val:24, color:'#f87171' },
  { name:'Jailbreak',        val:18, color:'#fb923c' },
  { name:'Data Exfiltration',val:15, color:'#facc15' },
  { name:'Policy Bypass',    val:12, color:'#4ade80' },
];

export default function Login() {
  const { login }  = useAuth();
  const navigate   = useNavigate();
  const [form, setForm]       = useState({ username:'', password:'' });
  const [error, setError]     = useState('');
  const [loading, setLoading] = useState(false);
  const [showPwd, setShowPwd] = useState(false);

  const handle = e => setForm({ ...form, [e.target.name]: e.target.value });

  const submit = async e => {
    e.preventDefault();
    setError(''); setLoading(true);
    try {
      await login(form.username, form.password);
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.detail || 'Invalid credentials. Please try again.');
    } finally { setLoading(false); }
  };

  return (
    <div className="auth-page">

      {/* ── Left panel ────────────────────────── */}
      <div className="auth-left">
        <div className="auth-left-bg" />
        <div className="auth-left-grid" />
        <div className="auth-left-content">

          <div className="auth-left-logo">
            <div className="auth-left-logo-icon">🔐</div>
            <span className="auth-left-logo-text">LLMScanner</span>
          </div>

          <div>
            <h2 className="auth-left-headline">
              AI Security<br /><span>You Can Trust.</span>
            </h2>
            <p style={{ fontSize:'14px', color:'rgba(255,255,255,0.35)', lineHeight:'1.6', marginTop:'16px', maxWidth:'340px' }}>
              Every scan fires 1000+ adversarial prompts across 21 attack categories and generates a full security report automatically.
            </p>
          </div>

          {/* Live scan preview */}
          <div className="auth-scan-card">
            <div className="auth-scan-header">
              <div className="auth-scan-dot" style={{ background:'#ef4444' }} />
              <div className="auth-scan-dot" style={{ background:'#f59e0b' }} />
              <div className="auth-scan-dot" style={{ background:'#22c55e' }} />
              <span className="auth-scan-title">Scan Complete — E-commerce AI</span>
              <span style={{ padding:'2px 8px', borderRadius:'10px', background:'rgba(34,197,94,0.12)', border:'1px solid rgba(34,197,94,0.25)', fontSize:'10px', fontWeight:'700', color:'#4ade80' }}>
                Done
              </span>
            </div>
            <div className="auth-scan-body">
              <div>
                <div className="auth-scan-prog-label">Security score</div>
                <div style={{ display:'flex', alignItems:'center', gap:'10px' }}>
                  <div style={{ flex:1, height:'3px', borderRadius:'2px', background:'var(--s3)', overflow:'hidden' }}>
                    <div style={{ height:'100%', width:'72%', background:'linear-gradient(90deg,var(--green),#22d3ee)', borderRadius:'2px' }} />
                  </div>
                  <span style={{ fontSize:'14px', fontWeight:'800', color:'var(--green)', letterSpacing:'-0.3px' }}>72 / 100</span>
                </div>
              </div>
              <div className="auth-scan-attacks">
                {SCAN_ATTACKS.map(a => (
                  <div key={a.name} className="auth-scan-attack-row">
                    <span className="auth-scan-attack-name">{a.name}</span>
                    <span className="auth-scan-attack-val" style={{ color:a.color }}>{a.val} findings</span>
                  </div>
                ))}
              </div>
              <div style={{ display:'flex', gap:'6px' }}>
                {[
                  { n:3, label:'Critical', c:'#f87171', bg:'rgba(240,68,56,0.1)' },
                  { n:7, label:'High',     c:'#fb923c', bg:'rgba(251,146,60,0.08)' },
                  { n:14,label:'Medium',   c:'#facc15', bg:'rgba(250,204,21,0.08)' },
                ].map(s => (
                  <div key={s.label} style={{ flex:1, background:s.bg, border:`1px solid ${s.c}20`, borderRadius:'6px', padding:'8px 10px' }}>
                    <div style={{ fontSize:'16px', fontWeight:'800', color:s.c, letterSpacing:'-0.3px' }}>{s.n}</div>
                    <div style={{ fontSize:'9px', color:'rgba(255,255,255,0.25)', textTransform:'uppercase', letterSpacing:'0.5px', marginTop:'1px' }}>{s.label}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="auth-left-features">
            {[
              'Automated prompt injection & jailbreak testing',
              'Professional PDF reports with severity scoring',
              'Works with OpenAI, Groq, and custom APIs',
              'Full results in under 15 minutes per scan',
            ].map(f => (
              <div key={f} className="auth-left-feat">
                <div className="auth-left-feat-dot" />
                <span className="auth-left-feat-text">{f}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Right form panel ────────────────── */}
      <div className="auth-right">
        <h1 className="auth-right-title">Welcome back</h1>
        <p className="auth-right-sub">Sign in to your security dashboard</p>

        {error && <div className="alert-error">{error}</div>}

        <form onSubmit={submit} autoComplete="on">
          <div className="form-group">
            <label>Username</label>
            <input name="username" autoComplete="username"
              value={form.username} onChange={handle} placeholder="admin" />
          </div>
          <div className="form-group">
            <label>Password</label>
            <div style={{ position:'relative' }}>
              <input name="password" type={showPwd ? 'text' : 'password'}
                autoComplete="current-password"
                value={form.password} onChange={handle} placeholder="••••••••"
                style={{ paddingRight:'44px' }} />
              <button type="button"
                onClick={() => setShowPwd(v => !v)}
                style={{ position:'absolute', right:'12px', top:'50%', transform:'translateY(-50%)', background:'none', border:'none', color:'var(--t3)', cursor:'pointer', padding:'2px', display:'flex', alignItems:'center' }}>
                {showPwd ? (
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
                ) : (
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                )}
              </button>
            </div>
          </div>

          <div style={{ textAlign:'right', marginBottom:'20px', marginTop:'-8px' }}>
            <Link to="/forgot-password" style={{ fontSize:'12px', color:'rgba(255,255,255,0.25)', transition:'color 0.15s' }}
              onMouseEnter={e => e.target.style.color='rgba(255,255,255,0.55)'}
              onMouseLeave={e => e.target.style.color='rgba(255,255,255,0.25)'}>
              Forgot password?
            </Link>
          </div>

          <button type="submit" className="btn-primary" disabled={loading}
            style={{ width:'100%', padding:'13px', fontSize:'14px', justifyContent:'center', borderRadius:'8px' }}>
            {loading
              ? <><span className="spinner" style={{ borderTopColor:'#fff' }} />&nbsp; Signing in…</>
              : 'Sign In →'
            }
          </button>
        </form>

        <div className="auth-divider" style={{ marginTop:'28px' }}>
          No account?{' '}<Link to="/register">Create one free</Link>
        </div>
      </div>
    </div>
  );
}
