import React, { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { authAPI, teamAPI, errorMessage, setWorkspace, PENDING_INVITE_KEY } from '../services/api';
import { useAuth } from '../context/AuthContext';
import CenterCard from '../components/CenterCard';

/* Opened from a team invite link: sign in with the invited address, then join. */
export default function InviteAccept() {
  const [params] = useSearchParams();
  const token = params.get('token') || '';
  const { user, loading, logout } = useAuth();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [otherAccount, setOtherAccount] = useState(false);    // signed in with an address the invite isn't for
  const [sent, setSent] = useState(false);
  // someone who must confirm their address first: the confirmation page links back to this invite
  useEffect(() => {
    if (token && user && !user.email_verified) localStorage.setItem(PENDING_INVITE_KEY, token);
  }, [token, user]);
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

  // An invite proves nothing about an address nobody has confirmed, so the API asks for that first
  if (!user.email_verified) {
    const resend = async () => {
      setBusy(true); setError('');
      try { await authAPI.resendVerification(); setSent(true); }
      catch (e) { setError(errorMessage(e, 'Couldn’t send the email.')); }
      finally { setBusy(false); }
    };
    return (
      <CenterCard title="Confirm your email address first"
        subtitle={`Open the confirmation link we sent to ${user.email}, then open this invite link again to join.`}>
        <button className="btn-primary" onClick={resend} disabled={busy || sent}>{sent ? 'Sent: check your inbox' : busy ? 'Sending…' : 'Send the link again'}</button>
        {error && <div className="alert-error" role="alert" style={{ marginTop:'14px' }}>{error}</div>}
      </CenterCard>
    );
  }

  const join = async () => {
    setBusy(true); setError('');
    try {
      const { data } = await teamAPI.accept(token);
      localStorage.removeItem(PENDING_INVITE_KEY);
      setWorkspace(data.workspace.id);
      window.location.assign('/');
    } catch (e) {
      setError(errorMessage(e, 'Couldn’t join the workspace.'));
      setOtherAccount(e.response?.status === 403 && /invite is for/i.test(e.response?.data?.detail || ''));
      setBusy(false);
    }
  };
  // signing out leaves this page on the invite, which then offers to sign in with the right address
  const switchAccount = async () => { await logout(); setError(''); setOtherAccount(false); };
  return (
    <CenterCard title="Join this workspace?" subtitle={`You’re signed in as ${user.email || user.username}. The invite has to be for this address.`}>
      <button className="btn-primary" onClick={join} disabled={busy}>{busy ? 'Joining…' : 'Join the workspace'}</button>
      {error && <div className="alert-error" role="alert" style={{ marginTop:'14px' }}>{error}</div>}
      {otherAccount && (
        <button className="btn-outline" style={{ marginTop:'12px' }} onClick={switchAccount}>Sign out and use that address</button>
      )}
    </CenterCard>
  );
}
