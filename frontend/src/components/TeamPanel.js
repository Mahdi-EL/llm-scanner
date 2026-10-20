import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { teamAPI, errorMessage } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import { shortDate } from '../utils/format';

const ROLES = [
  ['viewer', 'Viewer: reads scans and reports'],
  ['member', 'Member: also runs and changes scans, targets and schedules'],
  ['admin',  'Admin: also manages keys, the webhook, branding and the team'],
];

/* The people in the current workspace: invite, change roles, remove, or leave. */
export default function TeamPanel() {
  const { user, role, switchWorkspace } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();
  const [team, setTeam] = useState(null);
  const [failed, setFailed] = useState(false);
  const [email, setEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('member');
  const [created, setCreated] = useState(null);
  const [busy, setBusy] = useState('');
  const admin = role === 'owner' || role === 'admin';

  const load = useCallback(() => teamAPI.get()
    .then(r => { setTeam(r.data); setFailed(false); })
    .catch(() => setFailed(true)), []);
  useEffect(() => { load(); }, [load]);

  const run = async (name, fn) => {
    setBusy(name);
    try { await fn(); } catch (e) { toast(errorMessage(e), 'error', 6000); } finally { setBusy(''); }
  };
  const invite = e => {
    e.preventDefault();
    run('invite', async () => {
      const { data } = await teamAPI.invite(email.trim(), inviteRole);
      setCreated(data); setEmail(''); load();
    });
  };
  const changeRole = (id, r) => run(`role-${id}`, async () => { await teamAPI.setRole(id, r); load(); });
  const removeMember = m => run(`rm-${m.user_id}`, async () => {
    if (!window.confirm(`Remove ${m.username} from this workspace?`)) return;
    await teamAPI.remove(m.user_id); load();
  });
  const revoke = i => run(`inv-${i.id}`, async () => { await teamAPI.revokeInvite(i.id); load(); });
  const leave = () => run('leave', async () => {
    if (!window.confirm('Leave this workspace? You will need a new invite to come back.')) return;
    await teamAPI.remove(user.id);
    switchWorkspace(user.id);
  });

  if (failed) return <div style={{ padding:'16px 20px', fontSize:'13px', color:'#b42318' }} role="alert">Couldn’t load the team. <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={load}>Retry</button></div>;
  if (!team) return <div style={{ padding:'16px 20px', fontSize:'13px', color:'var(--t3)' }}>Loading…</div>;
  const { seats } = team;
  const full = seats.limit != null && seats.used >= seats.limit;
  return (
    <div>
      <div style={{ padding:'14px 20px 4px', fontSize:'12px', color:'var(--t3)' }}>
        {seats.limit == null ? `${seats.used} people · no seat limit` : `${seats.used} of ${seats.limit} seat${seats.limit !== 1 ? 's' : ''} used`}
        {team.role !== 'owner' && <> · you are {team.role === 'admin' ? 'an' : 'a'} {team.role}</>}
      </div>
      {team.members.map(m => (
        <div key={m.user_id} style={{ display:'flex', alignItems:'center', gap:'10px', padding:'10px 20px', borderBottom:'1px solid var(--b1)', flexWrap:'wrap' }}>
          <div style={{ flex:'1 1 200px', minWidth:0 }}>
            <div style={{ fontSize:'13px', fontWeight:600 }}>{m.username}{m.user_id === user.id ? ' (you)' : ''}</div>
            <div style={{ fontSize:'12px', color:'var(--t3)', overflow:'hidden', textOverflow:'ellipsis' }}>{m.email}</div>
          </div>
          {m.role === 'owner' || !admin ? (
            <span style={{ fontSize:'12px', color:'var(--t2)', textTransform:'capitalize' }}>{m.role}</span>
          ) : (
            <select aria-label={`Role of ${m.username}`} value={m.role} disabled={!!busy}
              onChange={e => changeRole(m.user_id, e.target.value)} style={{ fontSize:'12px' }}>
              {ROLES.map(([r]) => <option key={r} value={r}>{r[0].toUpperCase() + r.slice(1)}</option>)}
            </select>
          )}
          {admin && m.role !== 'owner' && m.user_id !== user.id && (
            <button className="btn-ghost" style={{ fontSize:'12px', color:'#b42318' }} disabled={!!busy} onClick={() => removeMember(m)}>Remove</button>
          )}
        </div>
      ))}
      {team.invites.map(i => (
        <div key={i.id} style={{ display:'flex', alignItems:'center', gap:'10px', padding:'10px 20px', borderBottom:'1px solid var(--b1)', flexWrap:'wrap' }}>
          <div style={{ flex:'1 1 200px', minWidth:0, fontSize:'13px' }}>
            {i.email} <span style={{ color:'var(--t3)', fontSize:'12px' }}>invited as {i.role} · expires {shortDate(i.expires_at)}</span>
          </div>
          <button className="btn-ghost" style={{ fontSize:'12px' }} disabled={!!busy} onClick={() => revoke(i)}>Revoke</button>
        </div>
      ))}
      {created && (
        <div role="status" style={{ margin:'12px 20px 0', padding:'12px 14px', border:'1px solid var(--b1)', borderRadius:'8px', fontSize:'13px' }}>
          {created.emailed ? `We emailed ${created.email} an invite. ` : `Send ${created.email} this link (it works once, for that address, for 7 days): `}
          <code style={{ wordBreak:'break-all' }}>{created.link}</code>{' '}
          <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={() => { navigator.clipboard?.writeText(created.link); toast('Copied.', 'success', 1500); }}>Copy</button>
        </div>
      )}
      {admin && (seats.limit === 1 ? (
        <div style={{ padding:'14px 20px', fontSize:'13px', color:'var(--t3)' }}>
          Team members are part of the paid plans. <a href="/pricing" onClick={e => { e.preventDefault(); navigate('/pricing'); }}>See plans</a>
        </div>
      ) : (
        <form onSubmit={invite} style={{ display:'flex', gap:'8px', padding:'14px 20px', flexWrap:'wrap' }}>
          <input type="email" aria-label="Email to invite" value={email} onChange={e => setEmail(e.target.value)} required
            placeholder="colleague@company.com" disabled={full} style={{ flex:'1 1 220px', minWidth:0 }} />
          <select aria-label="Role for the invite" value={inviteRole} onChange={e => setInviteRole(e.target.value)} disabled={full} style={{ fontSize:'12px' }}>
            {ROLES.map(([r, label]) => <option key={r} value={r}>{label}</option>)}
          </select>
          <button type="submit" className="btn-primary" style={{ fontSize:'12px' }} disabled={full || busy === 'invite'}>Invite</button>
          {full && <span style={{ fontSize:'12px', color:'var(--t3)', flexBasis:'100%' }}>Every seat is taken: remove someone or upgrade the plan.</span>}
        </form>
      ))}
      {team.role !== 'owner' && (
        <div style={{ padding:'0 20px 16px' }}>
          <button className="btn-ghost" style={{ fontSize:'12px', color:'#b42318' }} disabled={!!busy} onClick={leave}>Leave this workspace</button>
        </div>
      )}
    </div>
  );
}
