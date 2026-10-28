import React, { useEffect, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { authAPI, errorMessage, PENDING_INVITE_KEY } from '../services/api';
import { useAuth } from '../context/AuthContext';
import CenterCard from '../components/CenterCard';

export default function VerifyEmail() {
  const [params] = useSearchParams();
  const { user, refreshUser } = useAuth();
  const [state, setState] = useState({ status: 'working', message: '' });
  const token = params.get('token');
  const sent = useRef(null);          // a token works once: never send it twice (React may re-run effects)

  useEffect(() => {
    if (!token) { setState({ status: 'error', message: 'This link is missing its token.' }); return; }
    if (sent.current === token) return;
    sent.current = token;
    authAPI.verifyEmail(token)
      .then(() => { setState({ status: 'done' }); if (user) refreshUser(); })
      .catch(e => setState({ status: 'error', message: errorMessage(e, 'This link is invalid or has expired.') }));
  }, [token]); // eslint-disable-line react-hooks/exhaustive-deps

  if (state.status === 'working') return <CenterCard title="Confirming your email…" />;
  const invite = state.status === 'done' && localStorage.getItem(PENDING_INVITE_KEY);
  if (state.status === 'done') return (
    <CenterCard title="Email confirmed"
      subtitle={invite ? 'Thanks. You can now join the workspace you were invited to.' : 'Thanks. Your account is fully set up.'}>
      {invite ? (
        <div style={{ display:'flex', gap:'8px', justifyContent:'center', flexWrap:'wrap' }}>
          <Link to={`/invite?token=${encodeURIComponent(invite)}`} className="btn-primary" style={{ display:'inline-flex' }}>Continue to your invite</Link>
          <Link to="/" className="btn-outline" style={{ display:'inline-flex' }}>Go to the dashboard</Link>
        </div>
      ) : (
        <Link to="/" className="btn-primary" style={{ display:'inline-flex' }}>Continue</Link>
      )}
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
