import React, { useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { teamAPI, errorMessage, WORKSPACE_KEY } from '../services/api';
import { useAuth } from '../context/AuthContext';
import CenterCard from '../components/CenterCard';

/* Opened from a team invite link: sign in with the invited address, then join. */
export default function InviteAccept() {
  const [params] = useSearchParams();
  const token = params.get('token') || '';
  const { user, loading } = useAuth();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const here = `/invite?token=${encodeURIComponent(token)}`;

  if (!token) return <CenterCard title="This invite link is incomplete" subtitle="Ask whoever invited you for a new link." />;
  if (loading) return <CenterCard title="Loading…" />;
  if (!user) return (
    <CenterCard title="You’re invited to a workspace"
      subtitle="Sign in, or create an account, with the email address the invite was sent to. You’ll come back here to join.">
      <div style={{ display:'flex', gap:'8px', justifyContent:'center', flexWrap:'wrap' }}>
        <Link to={`/login?next=${encodeURIComponent(here)}`} className="btn-primary" style={{ display:'inline-flex' }}>Sign in</Link>
        <Link to={`/register?next=${encodeURIComponent(here)}`} className="btn-outline" style={{ display:'inline-flex' }}>Create an account</Link>
      </div>
    </CenterCard>
  );

  const join = async () => {
    setBusy(true); setError('');
    try {
      const { data } = await teamAPI.accept(token);
      localStorage.setItem(WORKSPACE_KEY, data.workspace.id);
      window.location.assign('/');
    } catch (e) {
      setError(errorMessage(e, 'Couldn’t join the workspace.'));
      setBusy(false);
    }
  };
  return (
    <CenterCard title="Join this workspace?" subtitle={`You’re signed in as ${user.email || user.username}. The invite has to be for this address.`}>
      <button className="btn-primary" onClick={join} disabled={busy}>{busy ? 'Joining…' : 'Join the workspace'}</button>
      {error && <div className="alert-error" role="alert" style={{ marginTop:'14px' }}>{error}</div>}
    </CenterCard>
  );
}
