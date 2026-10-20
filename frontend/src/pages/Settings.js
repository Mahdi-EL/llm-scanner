import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import { authAPI, keysAPI, webhookAPI, plansAPI, saveBlob, errorMessage } from '../services/api';
import { relTime } from '../utils/format';

function Section({ title, desc, children, danger }) {
  return (
    <section style={{ marginBottom:'28px' }}>
      <div style={{ marginBottom:'12px' }}>
        <h2 style={{ fontSize:'15px', fontWeight:'700', color: danger ? '#b42318' : 'var(--t1)', marginBottom:'2px' }}>{title}</h2>
        {desc && <p style={{ fontSize:'12px', color:'var(--t3)', margin:0 }}>{desc}</p>}
      </div>
      <div style={{ background:'var(--s1)', border:`1px solid ${danger ? 'rgba(180,35,24,0.3)' : 'var(--b1)'}`, borderRadius:'10px', overflow:'hidden' }}>
        {children}
      </div>
    </section>
  );
}

function Row({ label, desc, children, last }) {
  return (
    <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', padding:'16px 20px', gap:'24px', borderBottom: last ? 'none' : '1px solid var(--b1)', flexWrap:'wrap' }}>
      <div style={{ flex:1, minWidth:'200px' }}>
        <div style={{ fontSize:'13px', fontWeight:'600', color:'var(--t1)', marginBottom:'2px' }}>{label}</div>
        {desc && <div style={{ fontSize:'12px', color:'var(--t3)' }}>{desc}</div>}
      </div>
      <div style={{ flexShrink:0 }}>{children}</div>
    </div>
  );
}

function SecretBox({ value, onDone, note }) {
  const toast = useToast();
  return (
    <div style={{ padding:'14px 20px', background:'var(--s2)', borderBottom:'1px solid var(--b1)' }}>
      <div style={{ fontSize:'12px', color:'#a15c07', marginBottom:'8px' }}>{note}</div>
      <div style={{ display:'flex', gap:'8px' }}>
        <code style={{ flex:1, fontSize:'12px', padding:'9px 12px', border:'1px solid var(--b1)', borderRadius:'6px', overflowX:'auto', whiteSpace:'nowrap' }}>{value}</code>
        <button className="btn-outline" style={{ fontSize:'12px' }} onClick={() => { navigator.clipboard?.writeText(value); toast('Copied.', 'success', 1500); }}>Copy</button>
        <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={onDone}>Done</button>
      </div>
    </div>
  );
}

export default function Settings() {
  const { user, logout, refreshUser, saveTokens } = useAuth();
  const navigate = useNavigate();
  const toast    = useToast();
  const [params, setParams] = useSearchParams();

  const [pwForm, setPwForm]     = useState({ current:'', next:'', confirm:'' });
  const [pwLoading, setPwLoading] = useState(false);
  const [keys, setKeys]         = useState([]);
  const [keysError, setKeysError] = useState(false);
  const [keyName, setKeyName]   = useState('');
  const [newKey, setNewKey]     = useState(null);
  const [webhookUrl, setWebhookUrl] = useState('');
  const [newSecret, setNewSecret]   = useState(null);
  const [deletePw, setDeletePw] = useState('');
  const [busy, setBusy]         = useState('');

  const loadKeys = useCallback(() => keysAPI.list()
    .then(r => { setKeys(r.data.keys); setKeysError(false); })
    .catch(() => setKeysError(true)), []);

  useEffect(() => { loadKeys(); }, [loadKeys]);
  useEffect(() => { setWebhookUrl(user?.webhook_url || ''); }, [user?.webhook_url]);
  useEffect(() => {
    const payment = params.get('payment');
    if (payment === 'success' || payment === 'updated') {
      toast(payment === 'success' ? 'Payment received. Your plan updates in a few seconds.'
                                  : 'Plan changed. The difference is prorated on your next invoice; your plan updates in a few seconds.',
            'success', 6000);
      setParams({}, { replace: true });
      setTimeout(refreshUser, 3000);
    }
  }, [params, setParams, toast, refreshUser]);

  const run = async (name, fn) => {
    setBusy(name);
    try { await fn(); } catch (e) { toast(errorMessage(e), 'error', 5000); } finally { setBusy(''); }
  };

  const savePassword = async () => {
    if (!pwForm.current) { toast('Enter your current password.', 'error'); return; }
    if (pwForm.next.length < 8) { toast('New password must be at least 8 characters.', 'error'); return; }
    if (pwForm.next !== pwForm.confirm) { toast('Passwords do not match.', 'error'); return; }
    setPwLoading(true);
    try {
      const { data } = await authAPI.changePassword(pwForm.current, pwForm.next);
      saveTokens(data);    // other sessions are signed out; this one gets fresh tokens
      toast('Password updated. Other devices have been signed out.', 'success');
      setPwForm({ current:'', next:'', confirm:'' });
    } catch (e) {
      toast(errorMessage(e, 'Failed to update password.'), 'error');
    } finally {
      setPwLoading(false);
    }
  };

  const createKey = () => run('key', async () => {
    const { data } = await keysAPI.create(keyName.trim() || 'API key');
    setNewKey(data.key); setKeyName(''); loadKeys();
  });

  const revokeKey = id => run(`revoke-${id}`, async () => {
    if (!window.confirm('Revoke this key? Anything using it stops working immediately.')) return;
    await keysAPI.revoke(id); loadKeys(); toast('Key revoked.', 'success');
  });

  const saveWebhook = () => run('webhook', async () => {
    const { data } = await webhookAPI.set(webhookUrl.trim());
    if (data.secret) setNewSecret(data.secret);
    await refreshUser();
    toast(webhookUrl.trim() ? 'Webhook saved.' : 'Webhook removed.', 'success');
  });

  const rotateSecret = () => run('rotate', async () => {
    if (!window.confirm('Create a new signing secret? The old one stops working.')) return;
    const { data } = await webhookAPI.rotate();
    setNewSecret(data.secret); await refreshUser();
  });

  const testWebhook = () => run('test', async () => {
    const { data } = await webhookAPI.test();
    toast(data.delivered ? 'Test event delivered.' : 'Your endpoint didn’t answer with a 2xx status.', data.delivered ? 'success' : 'warning');
  });

  const openPortal = () => run('portal', async () => {
    const { data } = await plansAPI.portal();
    window.location.assign(data.url);
  });

  const resendVerification = () => run('verify', async () => {
    await authAPI.resendVerification(); toast('Confirmation email sent.', 'success');
  });

  const signOutEverywhere = () => run('signout', async () => {
    await authAPI.logoutEverywhere();
    await logout();
    navigate('/login');
  });

  const exportData = () => run('export', async () => {
    const { data } = await authAPI.exportData();
    saveBlob(new Blob([JSON.stringify(data, null, 2)], { type:'application/json' }), 'llm-scanner-export.json');
  });

  const deleteAccount = () => run('delete', async () => {
    if (!deletePw) { toast('Enter your password to confirm.', 'error'); return; }
    if (!window.confirm('Delete your account, every scan and every report? This can’t be undone.')) return;
    await authAPI.deleteAccount(deletePw);
    await logout();
    navigate('/');
  });

  const usage = user?.scan_limit == null ? 'Unlimited scans' : `${user?.scans_this_month ?? 0} of ${user?.scan_limit} scans used this month`;

  return (
    <div style={{ maxWidth:'720px' }}>
      <div style={{ marginBottom:'28px' }}>
        <h1 className="page-title">Settings</h1>
        <p className="page-subtitle" style={{ marginBottom:0 }}>Your account, access keys, notifications and data</p>
      </div>

      <Section title="Account">
        <Row label="Username"><span style={{ fontSize:'13px', fontFamily:'monospace' }}>{user?.username}</span></Row>
        <Row label="Email" desc={user?.email_verified ? 'Confirmed' : 'Not confirmed yet'} last>
          <div style={{ display:'flex', gap:'10px', alignItems:'center' }}>
            <span style={{ fontSize:'13px' }}>{user?.email}</span>
            {!user?.email_verified && (
              <button className="btn-ghost" style={{ fontSize:'12px' }} disabled={busy==='verify'} onClick={resendVerification}>Resend confirmation</button>
            )}
          </div>
        </Row>
      </Section>

      <Section title="Plan and usage">
        <Row label={`${(user?.plan || 'free').replace(/^./, c => c.toUpperCase())} plan`} desc={usage} last>
          <div style={{ display:'flex', gap:'8px' }}>
            {user?.has_billing && <button className="btn-outline" style={{ fontSize:'12px' }} disabled={busy==='portal'} onClick={openPortal}>Manage billing</button>}
            <button className="btn-primary" style={{ fontSize:'12px' }} onClick={() => navigate('/pricing')}>
              {user?.plan === 'free' ? 'Upgrade' : 'Change plan'}
            </button>
          </div>
        </Row>
      </Section>

      <Section title="Password" desc="Changing it signs you out on every other device.">
        <form onSubmit={e => { e.preventDefault(); savePassword(); }} style={{ padding:'20px', display:'grid', gap:'12px' }}>
          {/* lets password managers file the new password under the right account */}
          <input type="text" name="username" autoComplete="username" value={user?.username || ''} readOnly hidden />
          <div className="form-group" style={{ marginBottom:0 }}>
            <label htmlFor="set-current-password">Current password</label>
            <input id="set-current-password" type="password" autoComplete="current-password" value={pwForm.current} onChange={e => setPwForm(p => ({ ...p, current:e.target.value }))} />
          </div>
          <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(200px, 1fr))', gap:'12px', alignItems:'end' }}>
            <div className="form-group" style={{ marginBottom:0 }}>
              <label htmlFor="set-new-password">New password</label>
              <input id="set-new-password" type="password" autoComplete="new-password" placeholder="8 to 72 characters" value={pwForm.next} onChange={e => setPwForm(p => ({ ...p, next:e.target.value }))} />
            </div>
            <div className="form-group" style={{ marginBottom:0 }}>
              <label htmlFor="set-confirm-new-password">Confirm new password</label>
              <input id="set-confirm-new-password" type="password" autoComplete="new-password" value={pwForm.confirm} onChange={e => setPwForm(p => ({ ...p, confirm:e.target.value }))}
                style={{ borderColor: pwForm.confirm && pwForm.next !== pwForm.confirm ? '#b42318' : '' }} />
            </div>
          </div>
          <div><button type="submit" className="btn-primary" style={{ fontSize:'13px' }} disabled={pwLoading}>{pwLoading ? 'Updating…' : 'Update password'}</button></div>
        </form>
      </Section>

      <Section title="API keys" desc="For CI pipelines, the SDK and the VS Code extension. Send the key in an X-API-Key header.">
        {newKey && <SecretBox value={newKey} onDone={() => setNewKey(null)} note="Copy this key now. For your safety we only store its hash, so it won’t be shown again." />}
        <div style={{ display:'flex', gap:'8px', padding:'16px 20px', borderBottom:'1px solid var(--b1)', flexWrap:'wrap' }}>
          <input aria-label="API key name" value={keyName} onChange={e => setKeyName(e.target.value)} maxLength={60} placeholder="Key name, e.g. GitHub Actions" style={{ flex:'1 1 200px', minWidth:0 }} />
          <button className="btn-primary" style={{ fontSize:'12px' }} disabled={busy==='key'} onClick={createKey}>Create key</button>
        </div>
        {keysError ? (
          <div role="alert" style={{ padding:'16px 20px', fontSize:'13px', color:'#b42318' }}>
            Couldn’t load your keys. <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={loadKeys}>Retry</button>
          </div>
        ) : keys.length === 0 ? (
          <div style={{ padding:'16px 20px', fontSize:'13px', color:'var(--t3)' }}>No keys yet.</div>
        ) : keys.map((k, i) => (
          <Row key={k.id} last={i === keys.length - 1} label={k.name}
            desc={`${k.prefix}… · created ${relTime(k.created_at)}${k.last_used_at ? ` · last used ${relTime(k.last_used_at)}` : ' · never used'}`}>
            {k.revoked ? <span style={{ fontSize:'12px', color:'var(--t3)' }}>Revoked</span>
              : <button className="btn-ghost" style={{ fontSize:'12px', color:'#b42318' }} onClick={() => revokeKey(k.id)}>Revoke</button>}
          </Row>
        ))}
      </Section>

      <Section title="Webhook" desc="We POST scan.completed, scan.failed and scan.regression events to this URL, signed with HMAC-SHA256 (X-LLMScanner-Signature).">
        {newSecret && <SecretBox value={newSecret} onDone={() => setNewSecret(null)} note="This is your signing secret. Use it to verify that events come from us. It won’t be shown again." />}
        <div style={{ display:'flex', gap:'8px', padding:'16px 20px', flexWrap:'wrap' }}>
          <input aria-label="Webhook URL" value={webhookUrl} onChange={e => setWebhookUrl(e.target.value)} maxLength={2048} placeholder="https://hooks.example.com/llm-scanner" style={{ flex:1, minWidth:'240px' }} />
          <button className="btn-primary" style={{ fontSize:'12px' }} disabled={busy==='webhook'} onClick={saveWebhook}>Save</button>
          {user?.webhook_url && <button className="btn-outline" style={{ fontSize:'12px' }} disabled={busy==='test'} onClick={testWebhook}>Send test</button>}
          {user?.has_webhook_secret && <button className="btn-ghost" style={{ fontSize:'12px' }} disabled={busy==='rotate'} onClick={rotateSecret}>New secret</button>}
        </div>
      </Section>

      <Section title="Sessions and data">
        <Row label="Sign out everywhere" desc="Ends every session on every device, including this one.">
          <button className="btn-outline" style={{ fontSize:'12px' }} disabled={busy==='signout'} onClick={signOutEverywhere}>Sign out everywhere</button>
        </Row>
        <Row label="Export your data" desc="Your profile, scans, findings, saved targets and settings as JSON." last>
          <button className="btn-outline" style={{ fontSize:'12px' }} disabled={busy==='export'} onClick={exportData}>{busy==='export' ? 'Preparing…' : 'Download export'}</button>
        </Row>
      </Section>

      <Section title="Delete account" desc="Deletes your account, every scan and every report, and cancels any subscription. This can’t be undone." danger>
        <form onSubmit={e => { e.preventDefault(); deleteAccount(); }} style={{ display:'flex', gap:'8px', padding:'16px 20px', flexWrap:'wrap' }}>
          <input aria-label="Your password, to confirm deletion" type="password" autoComplete="current-password" value={deletePw} onChange={e => setDeletePw(e.target.value)} placeholder="Your password" style={{ flex:1, minWidth:'200px' }} />
          <button type="submit" disabled={busy==='delete'}
            style={{ padding:'8px 16px', fontSize:'12px', fontWeight:'600', background:'rgba(180,35,24,0.08)', border:'1px solid rgba(180,35,24,0.4)', color:'#b42318', borderRadius:'6px', cursor:'pointer' }}>
            {busy==='delete' ? 'Deleting…' : 'Delete my account'}
          </button>
        </form>
      </Section>
    </div>
  );
}
