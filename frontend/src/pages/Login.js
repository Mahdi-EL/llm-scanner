import React, { useState } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import { fmtNum, safeNext } from '../utils/format';
import { useLibrary } from '../utils/hooks';
import { useAuth } from '../context/AuthContext';
import Logo from '../components/Logo';
import { errorMessage } from '../services/api';

const SCAN_ATTACKS = [
  { name:'Prompt Injection',  val:24, accent:'#dc2626' },
  { name:'Jailbreak',         val:18, accent:'#ea580c' },
  { name:'Data Exfiltration', val:15, accent:'#ca8a04' },
  { name:'Policy Bypass',     val:12, accent:'#16a34a' },
];

/* lib: the attack library's counts (useLibrary), null until they load */
const TRUST = lib => [
  ...(lib ? [{ value: fmtNum(lib.attacks), label:'Attack prompts' },
             { value: String(lib.categories), label:'Attack categories' }] : []),
  { value:'OWASP', label:'LLM Top 10 mapped' },
];

const IcoEyeOff = () => (
  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
);
const IcoEye = () => (
  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
);

export default function Login() {
  const { login }  = useAuth();
  const navigate   = useNavigate();
  const [form, setForm]       = useState({ username:'', password:'' });
  const [error, setError]     = useState('');
  const [loading, setLoading] = useState(false);
  const [showPwd, setShowPwd] = useState(false);
  const [params] = useSearchParams();
  const lib = useLibrary();

  const handle = e => setForm({ ...form, [e.target.name]: e.target.value });

  const submit = async e => {
    e.preventDefault();
    setError(''); setLoading(true);
    try {
      await login(form.username, form.password);
      navigate(safeNext(params.get('next')), { replace: true });
    } catch (err) {
      setError(errorMessage(err, 'Invalid credentials. Please try again.'));
    } finally { setLoading(false); }
  };

  return (
    <div className="pw-auth">

      {/* ═══════════ LEFT · branded showcase ═══════════ */}
      <aside className="pw-aside">
        <Link to="/landing" className="pw-brand">
          <Logo size={28} />
          <span>LLM<b>Scanner</b></span>
        </Link>

        <div className="pw-aside-mid">
          <h2 className="pw-aside-title">Security testing for your AI, on autopilot.</h2>
          <p className="pw-aside-sub">
            Fire {lib ? `${fmtNum(lib.attacks)} adversarial prompts across ${lib.categories} attack categories`
              : 'adversarial prompts from every attack category'} and get a full security report in minutes.
          </p>

          {/* Product card */}
          <div className="pw-card">
            <div className="pw-card-head">
              <span className="pw-card-title">Scan complete — E-commerce AI</span>
              <span className="pw-pill-done">Done</span>
            </div>
            <div className="pw-card-body">
              <div className="pw-score">
                <span className="pw-score-label">Security score</span>
                <div className="pw-score-row">
                  <div className="pw-score-track"><div className="pw-score-fill" style={{ width:'72%' }} /></div>
                  <span className="pw-score-num">72<i>/100</i></span>
                </div>
              </div>
              <div className="pw-attacks">
                {SCAN_ATTACKS.map(a => (
                  <div key={a.name} className="pw-attack">
                    <span className="pw-attack-dot" style={{ background:a.accent }} />
                    <span className="pw-attack-name">{a.name}</span>
                    <span className="pw-attack-val">{a.val} findings</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="pw-trust">
          {TRUST(lib).map(t => (
            <div key={t.label} className="pw-trust-item">
              <strong>{t.value}</strong>
              <span>{t.label}</span>
            </div>
          ))}
        </div>
      </aside>

      {/* ═══════════ RIGHT · sign-in form ═══════════ */}
      <div className="pw-main">
        <div className="pw-form">
          <Link to="/landing" className="pw-brand pw-brand-mobile">
            <Logo size={26} />
            <span>LLM<b>Scanner</b></span>
          </Link>

          <h1 className="pw-title">Sign in</h1>
          <p className="pw-subtitle">Welcome back — sign in to your security dashboard.</p>

          {error && <div className="pw-error" role="alert">{error}</div>}

          <form onSubmit={submit} autoComplete="on">
            <div className="pw-field">
              <label htmlFor="pw-user">Username or email</label>
              <input id="pw-user" name="username" autoComplete="username"
                value={form.username} onChange={handle} placeholder="you@company.com or your username" />
            </div>

            <div className="pw-field">
              <div className="pw-field-top">
                <label htmlFor="pw-pass">Password</label>
                <Link to="/forgot-password" className="pw-forgot">Forgot password?</Link>
              </div>
              <div className="pw-input-wrap">
                <input id="pw-pass" name="password" type={showPwd ? 'text' : 'password'}
                  autoComplete="current-password"
                  value={form.password} onChange={handle} placeholder="Enter your password" />
                <button type="button" className="pw-eye"
                  onClick={() => setShowPwd(v => !v)}
                  aria-label={showPwd ? 'Hide password' : 'Show password'}>
                  {showPwd ? <IcoEyeOff /> : <IcoEye />}
                </button>
              </div>
            </div>

            <button type="submit" className="pw-submit" disabled={loading}>
              {loading
                ? <><span className="spinner" style={{ borderColor:'rgba(17,24,39,0.4)', borderTopColor:'#fff' }} />&nbsp;&nbsp;Signing in…</>
                : 'Sign in'
              }
            </button>
          </form>

          <p className="pw-switch">
            Don't have an account? <Link to="/register">Create one free</Link>
          </p>

          <div className="pw-secure">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            Encrypted connection · passwords stored with bcrypt
          </div>
        </div>
      </div>
    </div>
  );
}
