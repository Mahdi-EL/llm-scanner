import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

function Register() {
  const { register } = useAuth();
  const navigate     = useNavigate();
  const [form, setForm]     = useState({ username: '', email: '', password: '', confirm: '' });
  const [error, setError]   = useState('');
  const [loading, setLoading] = useState(false);

  const handle = e => setForm({ ...form, [e.target.name]: e.target.value });

  const submit = async e => {
    e.preventDefault();
    setError('');
    if (form.password !== form.confirm) {
      setError('Passwords do not match');
      return;
    }
    if (form.password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    setLoading(true);
    try {
      await register(form.username, form.email, form.password);
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.detail || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', justifyContent: 'center', paddingTop: '80px' }}>
      <div className="card" style={{ width: '100%', maxWidth: '420px' }}>
        <h1 className="page-title" style={{ marginBottom: '4px' }}>Create Account</h1>
        <p className="page-subtitle" style={{ marginBottom: '28px' }}>
          Start scanning AI applications for free
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
              placeholder="johndoe"
            />
          </div>
          <div className="form-group">
            <label>Email</label>
            <input
              name="email" type="email" autoComplete="email"
              value={form.email} onChange={handle}
              placeholder="you@example.com"
            />
          </div>
          <div className="form-group">
            <label>Password</label>
            <input
              name="password" type="password" autoComplete="new-password"
              value={form.password} onChange={handle}
              placeholder="At least 8 characters"
            />
          </div>
          <div className="form-group">
            <label>Confirm Password</label>
            <input
              name="confirm" type="password" autoComplete="new-password"
              value={form.confirm} onChange={handle}
              placeholder="••••••••"
            />
          </div>

          <button
            type="submit" className="btn-primary"
            disabled={loading}
            style={{ width: '100%', padding: '12px', fontSize: '15px', marginBottom: '16px' }}
          >
            {loading ? 'Creating account...' : 'Create Account'}
          </button>
        </form>

        <div style={{ textAlign: 'center', color: '#64748b', fontSize: '14px' }}>
          Already have an account?{' '}
          <Link to="/login" style={{ color: '#3b82f6', textDecoration: 'none' }}>
            Sign in
          </Link>
        </div>
      </div>
    </div>
  );
}

export default Register;
