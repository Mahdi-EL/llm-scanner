import React, { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { authAPI, errorMessage } from '../services/api';
import { useAuth } from '../context/AuthContext';
import CenterCard from '../components/CenterCard';

export default function VerifyEmail() {
  const [params] = useSearchParams();
  const { user, refreshUser } = useAuth();
  const [state, setState] = useState({ status: 'working', message: '' });
  const token = params.get('token');

  useEffect(() => {
    if (!token) { setState({ status: 'error', message: 'This link is missing its token.' }); return; }
    authAPI.verifyEmail(token)
      .then(() => { setState({ status: 'done' }); if (user) refreshUser(); })
      .catch(e => setState({ status: 'error', message: errorMessage(e, 'This link is invalid or has expired.') }));
  }, [token]); // eslint-disable-line react-hooks/exhaustive-deps

  if (state.status === 'working') return <CenterCard title="Confirming your email…" />;
  if (state.status === 'done') return (
    <CenterCard title="Email confirmed" subtitle="Thanks. Your account is fully set up.">
      <Link to="/" className="btn-primary" style={{ display:'inline-flex' }}>Continue</Link>
    </CenterCard>
  );
  return (
    <CenterCard title="Couldn’t confirm your email" subtitle={state.message}>
      <Link to={user ? '/settings' : '/login'} className="btn-outline" style={{ display:'inline-flex' }}>
        {user ? 'Send a new link from Settings' : 'Sign in to send a new link'}
      </Link>
    </CenterCard>
  );
}
