import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

function Login() {
  const { login }    = useAuth();
  const navigate     = useNavigate();
  const [form, setForm]     = useState({ username: '', password: '' });
  const [error, setError]   = useState('');
  const [loading, setLoading] = useState(false);

  const handle = e => setForm({ ...form, [e.target.name]: e.target.value });

  const submit = async e => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(form.username, form.password);
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', justifyContent: 'center', paddingTop: '80px' }}>
      <div className="card" style={{ width: '100%', maxWidth: '400px' }}>
        <h1 className="page-title" style={{ marginBottom: '4px' }}>Sign In</h1>
        <p className="page-subtitle" style={{ marginBottom: '28px' }}>
          Access your LLM Scanner dashboard
        </p>

        {error && (
          <div style={{
            background: '#2d0f0f', border: '1px solid #7f1d1d',
            borderRadius: '8px', padding: '12px 16px',
            color: '#fca5a5', fontSize: '14px', marginBottom: '20px'
          }}>
            {error}
          </div>
        )}

        <form onSubmit={submit}>
          <div className="form-group">
            <label>Username</label>
            <input
              name="username" autoComplete="username"
              value={form.username} onChange={handle}
              placeholder="admin"
            />
          </div>
          <div className="form-group">
            <label>Password</label>
            <input
              name="password" type="password" autoComplete="current-password"
              value={form.password} onChange={handle}
              placeholder="••••••••"
            />
          </div>

          <button
            type="submit" className="btn-primary"
            disabled={loading}
            style={{ width: '100%', padding: '12px', fontSize: '15px', marginBottom: '16px' }}
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>

        <div style={{ textAlign: 'center', color: '#64748b', fontSize: '14px' }}>
          No account?{' '}
          <Link to="/register" style={{ color: '#3b82f6', textDecoration: 'none' }}>
            Create one
          </Link>
          {'  ·  '}
          <Link to="/forgot-password" style={{ color: '#3b82f6', textDecoration: 'none' }}>
            Forgot password
          </Link>
        </div>
      </div>
    </div>
  );
}

export default Login;
