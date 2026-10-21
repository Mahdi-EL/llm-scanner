import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { teamAPI, errorMessage } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import { useConfirm } from '../context/ConfirmContext';
import { shortDate } from '../utils/format';

const ROLES = [
  ['viewer', 'Viewer: reads scans and reports'],
  ['member', 'Member: also runs and changes scans, targets and schedules'],
  ['admin',  'Admin: also manages keys, the webhook, branding and the team'],
];

/* The people in the current workspace: invite, change roles, remove, or leave. */
export default function TeamPanel() {
  const { user, role, switchWorkspace, refreshUser } = useAuth();
  const toast = useToast();
  const confirm = useConfirm();
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
    if (!(await confirm({ title: `Remove ${m.username}?`, confirmLabel: 'Remove',
      body: 'They lose access to this workspace right away, and API keys they created here stop working.' }))) return;
    await teamAPI.remove(m.user_id); load();
  });
  const revoke = i => run(`inv-${i.id}`, async () => { await teamAPI.revokeInvite(i.id); load(); });
  const leave = () => run('leave', async () => {
    if (!(await confirm({ title: 'Leave this workspace?', confirmLabel: 'Leave',
      body: 'You’ll need a new invite to come back, and API keys you created here stop working.' }))) return;
    await teamAPI.remove(user.id);
    switchWorkspace(user.id);
  });
  const leaveOther = w => run(`leave-${w.id}`, async () => {
    if (!(await confirm({ title: `Leave ${w.name}?`, confirmLabel: 'Leave',
      body: 'You’ll need a new invite to come back, and API keys you created there stop working.' }))) return;
    await teamAPI.leave(w.id, user.id);
    await refreshUser();
    toast(`You left ${w.name}.`, 'success');
  });
  const others = (user?.workspaces || []).filter(w => w.id !== user.id);

  if (failed) return <div style={{ padding:'16px 20px', fontSize:'13px', color:'#b42318' }} role="alert">Couldn’t load the team. <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={load}>Retry</button></div>;
  if (!team) return <div style={{ padding:'16px 20px', fontSize:'13px', color:'var(--t3)' }}>Loading…</div>;
  const { seats } = team;
  const full = seats.limit != null && seats.used >= seats.limit;
  const unseated = team.members.filter(m => m.seat === false).length;
  return (
    <div>
      <div style={{ padding:'14px 20px 4px', fontSize:'12px', color:'var(--t3)' }}>
        {seats.limit == null ? `${seats.used} people · no seat limit`
          : seats.used > seats.limit ? `${seats.used} people, ${seats.limit} seat${seats.limit !== 1 ? 's' : ''}`
          : `${seats.used} of ${seats.limit} seat${seats.limit !== 1 ? 's' : ''} used`}
        {team.role !== 'owner' && <> · you are {team.role === 'admin' ? 'an' : 'a'} {team.role}</>}
      </div>
      {unseated > 0 && (
        <div role="status" style={{ margin:'8px 20px', padding:'10px 12px', border:'1px solid rgba(161,92,7,0.35)', borderRadius:'8px', fontSize:'12px', color:'#a15c07' }}>
          The plan has fewer seats than people, so {unseated} {unseated === 1 ? 'person' : 'people'} can’t open this workspace
          (the latest to join). Upgrade the plan or remove someone to give them a seat.
        </div>
      )}
      {team.members.map(m => (
        <div key={m.user_id} style={{ display:'flex', alignItems:'center', gap:'10px', padding:'10px 20px', borderBottom:'1px solid var(--b1)', flexWrap:'wrap' }}>
          <div style={{ flex:'1 1 200px', minWidth:0 }}>
            <div style={{ fontSize:'13px', fontWeight:600 }}>
              {m.username}{m.user_id === user.id ? ' (you)' : ''}
              {m.seat === false && <span style={{ marginLeft:'8px', fontSize:'11px', fontWeight:600, color:'#a15c07' }}>no seat</span>}
            </div>
            <div style={{ fontSize:'12px', color:'var(--t3)', overflow:'hidden', textOverflow:'ellipsis' }}>{m.email}</div>
          </div>
          {m.role === 'owner' || !admin || m.user_id === user.id ? (
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
      {team.role === 'owner' && others.length > 0 && (
        <div style={{ padding:'6px 20px 16px', borderTop:'1px solid var(--b1)' }}>
          <div style={{ fontSize:'12px', fontWeight:600, color:'var(--t2)', margin:'10px 0 6px' }}>Other workspaces you’re in</div>
          {others.map(w => (
            <div key={w.id} style={{ display:'flex', alignItems:'center', gap:'10px', padding:'6px 0', flexWrap:'wrap', fontSize:'13px' }}>
              <span style={{ flex:'1 1 200px', minWidth:0 }}>
                {w.name} <span style={{ color:'var(--t3)', fontSize:'12px' }}>
                  {w.active === false ? 'paused: its plan has no seat for you' : w.role}</span>
              </span>
              {w.active !== false && <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={() => switchWorkspace(w.id)}>Open</button>}
              <button className="btn-ghost" style={{ fontSize:'12px', color:'#b42318' }} disabled={!!busy} onClick={() => leaveOther(w)}>Leave</button>
            </div>
          ))}
        </div>
      )}
      {team.role !== 'owner' && (
        <div style={{ padding:'0 20px 16px' }}>
          <button className="btn-ghost" style={{ fontSize:'12px', color:'#b42318' }} disabled={!!busy} onClick={leave}>Leave this workspace</button>
        </div>
      )}
    </div>
  );
}
