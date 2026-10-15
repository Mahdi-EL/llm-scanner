import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import { authAPI } from '../services/api';
import Logo from '../components/Logo';

export default function ResetPassword() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const token    = params.get('token') || '';

  const [form,    setForm]    = useState({ password: '', confirm: '' });
  const [loading, setLoading] = useState(false);
  const [done,    setDone]    = useState(false);
  const [error,   setError]   = useState('');

  useEffect(() => {
    if (!token) setError('Invalid or missing reset token.');
  }, [token]);

  const submit = async e => {
    e.preventDefault();
    setError('');
    if (form.password.length < 8) { setError('Password must be at least 8 characters.'); return; }
    if (form.password !== form.confirm) { setError('Passwords do not match.'); return; }
    setLoading(true);
    try {
      await authAPI.resetPassword(token, form.password);
      setDone(true);
      setTimeout(() => navigate('/login'), 2500);
    } catch (err) {
      setError(err.response?.data?.detail || 'Reset link is invalid or has expired.');
    } finally { setLoading(false); }
  };

  return (
    <div style={{
      minHeight:'calc(100vh - 60px)', display:'flex', alignItems:'center',
      justifyContent:'center', background:'var(--bg)', padding:'48px 24px',
    }}>
      <div style={{
        background:'var(--s1)', border:'1px solid var(--b1)', borderRadius:'16px',
        padding:'48px', width:'100%', maxWidth:'420px',
        boxShadow:'var(--sh-lg)', position:'relative', overflow:'hidden',
      }}>
        <div style={{ position:'absolute', top:0, left:0, right:0, height:'1px', background:'linear-gradient(90deg,transparent,rgba(17,24,39,0.07),transparent)' }} />

        <div style={{ textAlign:'center', marginBottom:'36px' }}>
          <div style={{
            width:'52px', height:'52px', background:'var(--blue-soft)',
            border:'1px solid rgba(37,99,235,0.25)', borderRadius:'14px',
            display:'flex', alignItems:'center', justifyContent:'center',
            margin:'0 auto 20px',
          }}><Logo size={28} /></div>
          <h1 style={{ fontSize:'22px', fontWeight:'800', letterSpacing:'-0.5px', marginBottom:'6px' }}>Set new password</h1>
          <p style={{ fontSize:'14px', color:'var(--t2)' }}>Choose a strong password for your account</p>
        </div>

        {done ? (
          <div style={{ background:'var(--green-soft)', border:'1px solid rgba(34,197,94,0.25)', borderRadius:'10px', padding:'20px', textAlign:'center' }}>
            <div style={{ fontSize:'24px', marginBottom:'10px' }}>✅</div>
            <div style={{ fontSize:'14px', color:'#16a34a', fontWeight:'600', marginBottom:'6px' }}>Password updated!</div>
            <div style={{ fontSize:'13px', color:'var(--t2)' }}>Redirecting to sign in…</div>
          </div>
        ) : (
          <>
            {error && <div className="alert-error" style={{ marginBottom:'20px' }}>{error}</div>}
            {!error && (
              <form onSubmit={submit}>
                <div className="form-group">
                  <label>New Password</label>
                  <input type="password" placeholder="Min. 8 characters"
                    value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} />
                </div>
                <div className="form-group">
                  <label>Confirm Password</label>
                  <input type="password" placeholder="••••••••"
                    value={form.confirm} onChange={e => setForm(f => ({ ...f, confirm: e.target.value }))}
                    style={{ borderColor: form.confirm && form.confirm !== form.password ? 'rgba(240,68,56,0.5)' : undefined }} />
                </div>
                <button type="submit" className="btn-primary" disabled={loading || !token}
                  style={{ width:'100%', padding:'13px', fontSize:'14px', justifyContent:'center', borderRadius:'8px' }}>
                  {loading ? <><span className="spinner" style={{ borderTopColor:'#fff' }} />&nbsp; Updating…</> : 'Set New Password →'}
                </button>
              </form>
            )}
          </>
        )}

        <div className="auth-divider" style={{ marginTop:'28px' }}>
          <Link to="/login">← Back to Sign In</Link>
        </div>
      </div>
    </div>
  );
}
