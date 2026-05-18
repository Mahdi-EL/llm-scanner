import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { authAPI } from '../services/api';

function ForgotPassword() {
  const [email,   setEmail]   = useState('');
  const [sent,    setSent]    = useState(false);
  const [loading, setLoading] = useState(false);

  const submit = async e => {
    e.preventDefault();
    setLoading(true);
    try {
      await authAPI.forgotPassword(email);
    } finally {
      setSent(true);
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-card">
        <Link to="/" className="auth-logo">
          <span className="auth-logo-icon">🔐</span>
          <span className="auth-logo-text">LLM Scanner</span>
        </Link>

        <h1 className="page-title" style={{ marginBottom: '4px' }}>Reset password</h1>
        <p className="page-subtitle" style={{ marginBottom: '28px' }}>
          We'll send a reset link to your email
        </p>

        {sent ? (
          <div className="alert-success" style={{ textAlign: 'center' }}>
            If that email is registered, a reset link has been sent.
          </div>
        ) : (
          <form onSubmit={submit}>
            <div className="form-group">
              <label>Email</label>
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="you@example.com"
              />
            </div>
            <button
              type="submit"
              className="btn-primary"
              disabled={loading}
              style={{ width: '100%', padding: '12px', fontSize: '15px', marginBottom: '20px' }}
            >
              {loading ? 'Sending…' : 'Send Reset Link'}
            </button>
          </form>
        )}

        <div className="auth-divider" style={{ marginTop: '16px' }}>
          <Link to="/login">← Back to Sign In</Link>
        </div>
      </div>
    </div>
  );
}

export default ForgotPassword;
