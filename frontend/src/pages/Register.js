import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import Logo from '../components/Logo';
import { errorMessage } from '../services/api';

/* ── Password strength meter ─────────────────────────────── */
function PasswordStrength({ pwd }) {
  const checks = {
    length : pwd.length >= 8,
    upper  : /[A-Z]/.test(pwd),
    number : /[0-9]/.test(pwd),
    special: /[^A-Za-z0-9]/.test(pwd),
  };
  const score = Object.values(checks).filter(Boolean).length;
  const SEG_COLORS = ['', '#b91c1c', '#92400e', '#15803d', '#15803d'];
  const LABELS     = ['', 'Weak', 'Fair', 'Good', 'Strong'];
  if (!pwd) return null;

  return (
    <div style={{ marginTop:'-8px', marginBottom:'18px' }}>
      <div style={{ display:'flex', alignItems:'center', gap:'4px', marginBottom:'8px' }}>
        <div className="pwd-track" style={{ flex:1 }}>
          {[0,1,2,3].map(i => (
            <div key={i} className="pwd-seg"
              style={{ background: i < score ? SEG_COLORS[score] : undefined }} />
          ))}
        </div>
        {score > 0 && (
          <span style={{ fontSize:'11px', fontWeight:'700', color:SEG_COLORS[score], minWidth:'36px', textAlign:'right' }}>
            {LABELS[score]}
          </span>
        )}
      </div>
      <div className="pwd-checks">
        {[
          ['8+ chars', checks.length],
          ['Uppercase', checks.upper],
          ['Number',   checks.number],
          ['Symbol',   checks.special],
        ].map(([label, ok]) => (
          <div key={label} className={`pwd-check${ok ? ' ok' : ''}`}>
            <div className="pwd-check-mark">{ok ? '✓' : ''}</div>
            {label}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Left panel live scan preview ────────────────────────── */
const SCAN_ATTACKS = [
  { name:'Instruction override', val:24, color:'#b91c1c' },
  { name:'Jailbreak templates',  val:18, color:'#c2410c' },
  { name:'Data exfiltration',    val:15, color:'#92400e' },
  { name:'Prompt extraction',    val:12, color:'#15803d' },
];

/* ── Main ─────────────────────────────────────────────────── */
export default function Register() {
  const { register } = useAuth();
  const navigate     = useNavigate();
  const [form, setForm] = useState({ username:'', email:'', password:'', confirm:'' });
  const [error, setError]   = useState('');
  const [loading, setLoading] = useState(false);

  const handle = e => setForm({ ...form, [e.target.name]: e.target.value });

  const submit = async e => {
    e.preventDefault();
    setError('');
    if (form.password !== form.confirm) { setError('Passwords do not match.'); return; }
    if (form.password.length < 8)       { setError('Password must be at least 8 characters.'); return; }
    setLoading(true);
    try {
      await register(form.username, form.email, form.password);
      navigate('/');
    } catch (err) {
      setError(errorMessage(err, 'Registration failed. Please try again.'));
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
            <div className="auth-left-logo-icon"><Logo size={26} /></div>
            <span className="auth-left-logo-text">LLMScanner</span>
          </div>

          <div>
            <h2 className="auth-left-headline">
              Start Securing<br /><span>Your AI Today.</span>
            </h2>
            <p style={{ fontSize:'14px', color:'var(--t3)', lineHeight:'1.6', marginTop:'16px', maxWidth:'340px' }}>
              Free plan, no credit card. Your first full security report on the same day.
            </p>
          </div>

          {/* Live scan preview card */}
          <div className="auth-scan-card">
            <div className="auth-scan-header">
              <div className="auth-scan-dot" style={{ background:'#ef4444' }} />
              <div className="auth-scan-dot" style={{ background:'#f59e0b' }} />
              <div className="auth-scan-dot" style={{ background:'#22c55e' }} />
              <span className="auth-scan-title">Example scan — banking chatbot</span>
              <span style={{ display:'flex', alignItems:'center', gap:'5px' }}>
                <span style={{ width:'5px', height:'5px', borderRadius:'50%', background:'var(--blue)', animation:'pulse-glow 1.8s ease-in-out infinite' }} />
                <span style={{ fontSize:'10px', color:'#1d4ed8', fontWeight:'700' }}>Running</span>
              </span>
            </div>
            <div className="auth-scan-body">
              <div>
                <div className="auth-scan-prog-label">820 / 1,090 prompts tested</div>
                <div className="auth-scan-prog-track">
                  <div className="auth-scan-prog-fill" />
                </div>
              </div>
              <div className="auth-scan-attacks">
                {SCAN_ATTACKS.map(a => (
                  <div key={a.name} className="auth-scan-attack-row">
                    <span className="auth-scan-attack-name">{a.name}</span>
                    <span className="auth-scan-attack-val" style={{ color:a.color }}>{a.val}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="auth-left-features">
            {[
              '1,000+ attack prompts across 22 vulnerability categories',
              'Free plan — no credit card required to start',
              'PDF, HTML, Markdown and JSON reports',
              'Works with any OpenAI-compatible API or your own REST endpoint',
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
        <div style={{ display:'flex', alignItems:'center', gap:'8px', marginBottom:'6px' }}>
          <div style={{ width:'6px', height:'6px', borderRadius:'50%', background:'var(--green)', boxShadow:'0 0 6px var(--green)' }} />
          <span style={{ fontSize:'11px', fontWeight:'600', color:'#15803d', letterSpacing:'0.3px' }}>Free plan — no credit card needed</span>
        </div>
        <h1 className="auth-right-title">Create account</h1>
        <p className="auth-right-sub">Start scanning AI applications for free</p>

        {error && <div className="alert-error">{error}</div>}

        <form onSubmit={submit} autoComplete="on">
          <div className="form-group">
            <label htmlFor="reg-username">Username</label>
            <input id="reg-username" name="username" autoComplete="username"
              value={form.username} onChange={handle} placeholder="johndoe" />
          </div>
          <div className="form-group">
            <label htmlFor="reg-email-address">Email address</label>
            <input id="reg-email-address" name="email" type="email" autoComplete="email"
              value={form.email} onChange={handle} placeholder="you@company.com" />
          </div>
          <div className="form-group">
            <label htmlFor="reg-password">Password</label>
            <input id="reg-password" name="password" type="password" autoComplete="new-password"
              value={form.password} onChange={handle} placeholder="Min. 8 characters" />
          </div>
          <PasswordStrength pwd={form.password} />
          <div className="form-group">
            <label htmlFor="reg-confirm-password">Confirm password</label>
            <input id="reg-confirm-password" name="confirm" type="password" autoComplete="new-password"
              value={form.confirm} onChange={handle} placeholder="••••••••"
              style={{ borderColor: form.confirm && form.confirm !== form.password ? 'rgba(240,68,56,0.5)' : undefined }} />
          </div>

          <button type="submit" className="btn-primary" disabled={loading}
            style={{ width:'100%', padding:'13px', fontSize:'14px', justifyContent:'center', borderRadius:'8px', marginTop:'4px' }}>
            {loading
              ? <><span className="spinner" style={{ borderTopColor:'#fff' }} />&nbsp; Creating account…</>
              : 'Create Account →'
            }
          </button>
        </form>

        <div className="auth-divider" style={{ marginTop:'28px' }}>
          Already have an account?{' '}<Link to="/login">Sign in</Link>
        </div>
      </div>
    </div>
  );
}
