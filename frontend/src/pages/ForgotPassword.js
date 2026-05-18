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
    <div style={{ display: 'flex', justifyContent: 'center', paddingTop: '80px' }}>
      <div className="card" style={{ width: '100%', maxWidth: '400px' }}>
        <h1 className="page-title" style={{ marginBottom: '4px' }}>Reset Password</h1>
        <p className="page-subtitle" style={{ marginBottom: '28px' }}>
          We'll send a reset link to your email
        </p>

        {sent ? (
          <div style={{
            background: '#052e16', border: '1px solid #166534',
            borderRadius: '8px', padding: '16px',
            color: '#86efac', fontSize: '14px', textAlign: 'center'
          }}>
            If that email is registered, a reset link has been sent.
          </div>
        ) : (
          <form onSubmit={submit}>
            <div className="form-group">
              <label>Email</label>
              <input
                type="email" value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="you@example.com"
              />
            </div>
            <button
              type="submit" className="btn-primary"
              disabled={loading}
              style={{ width: '100%', padding: '12px', fontSize: '15px', marginBottom: '16px' }}
            >
              {loading ? 'Sending...' : 'Send Reset Link'}
            </button>
          </form>
        )}

        <div style={{ textAlign: 'center', color: '#64748b', fontSize: '14px', marginTop: '16px' }}>
          <Link to="/login" style={{ color: '#3b82f6', textDecoration: 'none' }}>
            Back to Sign In
          </Link>
        </div>
      </div>
    </div>
  );
}

export default ForgotPassword;
