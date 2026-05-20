import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import api from '../services/api';

function Section({ title, desc, children }) {
  return (
    <div style={{ marginBottom:'28px' }}>
      <div style={{ marginBottom:'16px' }}>
        <div style={{ fontSize:'14px', fontWeight:'700', color:'var(--t1)', marginBottom:'4px' }}>{title}</div>
        {desc && <div style={{ fontSize:'12px', color:'var(--t3)' }}>{desc}</div>}
      </div>
      <div style={{ background:'var(--s1)', border:'1px solid var(--b1)', borderRadius:'12px', overflow:'hidden', position:'relative' }}>
        <div style={{ position:'absolute', top:0, left:0, right:0, height:'1px', background:'linear-gradient(90deg,transparent,rgba(255,255,255,0.06),transparent)' }} />
        {children}
      </div>
    </div>
  );
}

function Row({ label, desc, children, last }) {
  return (
    <div style={{
      display:'flex', alignItems:'center', justifyContent:'space-between',
      padding:'18px 22px', gap:'24px',
      borderBottom: last ? 'none' : '1px solid var(--b1)',
    }}>
      <div style={{ flex:1 }}>
        <div style={{ fontSize:'13px', fontWeight:'600', color:'var(--t1)', marginBottom:'2px' }}>{label}</div>
        {desc && <div style={{ fontSize:'12px', color:'var(--t3)' }}>{desc}</div>}
      </div>
      <div style={{ flexShrink:0 }}>{children}</div>
    </div>
  );
}

function Toggle({ value, onChange }) {
  return (
    <button
      onClick={() => onChange(!value)}
      style={{
        width:'40px', height:'22px', borderRadius:'11px', border:'none', cursor:'pointer',
        background: value ? 'var(--blue)' : 'var(--s4)',
        position:'relative', transition:'background 0.2s', flexShrink:0,
      }}
    >
      <div style={{
        position:'absolute', top:'3px',
        left: value ? '21px' : '3px',
        width:'16px', height:'16px',
        borderRadius:'50%', background:'#fff',
        transition:'left 0.2s',
        boxShadow:'0 1px 3px rgba(0,0,0,0.4)',
      }} />
    </button>
  );
}

const PLAN_STYLE = {
  free      : { bg:'rgba(255,255,255,0.06)',  color:'rgba(255,255,255,0.5)', border:'rgba(255,255,255,0.12)' },
  pro       : { bg:'rgba(74,138,244,0.15)',   color:'#93c5fd',              border:'rgba(74,138,244,0.3)' },
  enterprise: { bg:'rgba(34,197,94,0.12)',    color:'#86efac',              border:'rgba(34,197,94,0.3)' },
};

export default function Settings() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const toast    = useToast();

  const [notifications, setNotifications] = useState({
    scanComplete : true,
    weeklyDigest : false,
    criticalAlerts: true,
    marketingEmails: false,
  });
  const [theme,     setTheme]     = useState('dark');
  const [language,  setLanguage]  = useState('en');
  const [pwForm,    setPwForm]    = useState({ current:'', next:'', confirm:'' });
  const [apiKey,    setApiKey]    = useState('sk-llms-xxxx-xxxx-xxxx-xxxxxxxx');
  const [keyCopied, setKeyCopied] = useState(false);

  const ps      = PLAN_STYLE[user?.plan] || PLAN_STYLE.free;
  const initial = (user?.username || 'U')[0].toUpperCase();

  const copyKey = () => {
    navigator.clipboard.writeText(apiKey);
    setKeyCopied(true);
    setTimeout(() => setKeyCopied(false), 2000);
    toast('API key copied to clipboard.', 'success');
  };

  const regenerateKey = () => {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    const rand  = n => Array.from({ length:n }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
    setApiKey(`sk-llms-${rand(4)}-${rand(4)}-${rand(4)}-${rand(8)}`);
    toast('New API key generated. Save it — it won\'t be shown again.', 'warning', 5000);
  };

  const [pwLoading, setPwLoading] = useState(false);

  const savePassword = async () => {
    if (!pwForm.current) { toast('Enter your current password.', 'error'); return; }
    if (pwForm.next.length < 8) { toast('New password must be at least 8 characters.', 'error'); return; }
    if (pwForm.next !== pwForm.confirm) { toast('Passwords do not match.', 'error'); return; }
    setPwLoading(true);
    try {
      await api.put('/auth/password', { current_password: pwForm.current, new_password: pwForm.next });
      toast('Password updated successfully.', 'success');
      setPwForm({ current:'', next:'', confirm:'' });
    } catch (e) {
      toast(e.response?.data?.detail || 'Failed to update password.', 'error');
    } finally {
      setPwLoading(false);
    }
  };

  const deleteAccount = () => {
    toast('Account deletion requires confirmation from support. Email support@llmscanner.io.', 'warning', 6000);
  };

  return (
    <div style={{ maxWidth:'680px' }}>

      {/* Header */}
      <div style={{ marginBottom:'32px' }}>
        <h1 className="page-title">Settings</h1>
        <p className="page-subtitle" style={{ marginBottom:0 }}>Manage your account, security, and preferences</p>
      </div>

      {/* ── Profile ─────────────────────────────── */}
      <Section title="Profile" desc="Your account information and plan status">
        <div style={{ padding:'22px', display:'flex', alignItems:'center', gap:'18px', borderBottom:'1px solid var(--b1)' }}>
          <div style={{
            width:'56px', height:'56px', borderRadius:'14px', flexShrink:0,
            background:'linear-gradient(135deg, var(--blue), var(--purple))',
            display:'flex', alignItems:'center', justifyContent:'center',
            fontSize:'22px', fontWeight:'800', color:'#fff',
          }}>
            {initial}
          </div>
          <div style={{ flex:1 }}>
            <div style={{ fontSize:'16px', fontWeight:'700', color:'var(--t1)', marginBottom:'4px' }}>{user?.username}</div>
            <div style={{ fontSize:'13px', color:'var(--t3)', marginBottom:'6px' }}>{user?.email || 'No email set'}</div>
            <span style={{ background:ps.bg, color:ps.color, border:`1px solid ${ps.border}`, padding:'2px 10px', borderRadius:'10px', fontSize:'10px', fontWeight:'700', letterSpacing:'0.7px', textTransform:'uppercase' }}>
              {user?.plan || 'free'} plan
            </span>
          </div>
          <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={() => navigate('/pricing')}>
            {user?.plan === 'free' ? 'Upgrade Plan →' : 'Manage Plan'}
          </button>
        </div>

        <Row label="Username" desc="Used to log in to your account">
          <div style={{ display:'flex', alignItems:'center', gap:'10px' }}>
            <span style={{ fontSize:'13px', color:'var(--t2)', fontFamily:'monospace' }}>{user?.username}</span>
            <button className="btn-ghost" style={{ fontSize:'11px', padding:'4px 10px' }} onClick={() => toast('Username change coming soon.', 'info')}>Edit</button>
          </div>
        </Row>
        <Row label="Email address" desc="For notifications and account recovery" last>
          <div style={{ display:'flex', alignItems:'center', gap:'10px' }}>
            <span style={{ fontSize:'13px', color:'var(--t2)' }}>{user?.email || '—'}</span>
            <button className="btn-ghost" style={{ fontSize:'11px', padding:'4px 10px' }} onClick={() => toast('Email change coming soon.', 'info')}>Edit</button>
          </div>
        </Row>
      </Section>

      {/* ── Security / Password ──────────────────── */}
      <Section title="Security" desc="Change your password and manage authentication">
        <div style={{ padding:'22px' }}>
          <div style={{ display:'flex', flexDirection:'column', gap:'14px' }}>
            <div className="form-group" style={{ marginBottom:0 }}>
              <label>Current Password</label>
              <input type="password" placeholder="••••••••" value={pwForm.current} onChange={e => setPwForm(p => ({ ...p, current:e.target.value }))} />
            </div>
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:'12px' }}>
              <div className="form-group" style={{ marginBottom:0 }}>
                <label>New Password</label>
                <input type="password" placeholder="8+ characters" value={pwForm.next} onChange={e => setPwForm(p => ({ ...p, next:e.target.value }))} />
              </div>
              <div className="form-group" style={{ marginBottom:0 }}>
                <label>Confirm New Password</label>
                <input type="password" placeholder="Repeat password" value={pwForm.confirm} onChange={e => setPwForm(p => ({ ...p, confirm:e.target.value }))}
                  style={{ borderColor: pwForm.confirm && pwForm.next !== pwForm.confirm ? '#f87171' : '' }} />
              </div>
            </div>
            <div>
              <button className="btn-primary" style={{ fontSize:'13px', padding:'9px 20px' }} onClick={savePassword} disabled={pwLoading}>
                {pwLoading ? 'Updating…' : 'Update Password'}
              </button>
            </div>
          </div>
        </div>
      </Section>

      {/* ── API Key ──────────────────────────────── */}
      <Section title="API Access" desc="Use your API key to access LLMScanner programmatically">
        <div style={{ padding:'22px', borderBottom:'1px solid var(--b1)' }}>
          <div style={{ fontSize:'12px', color:'var(--t3)', marginBottom:'10px' }}>Your API Key</div>
          <div style={{ display:'flex', gap:'8px', alignItems:'center' }}>
            <div style={{
              flex:1, background:'var(--s3)', border:'1px solid var(--b1)', borderRadius:'8px',
              padding:'10px 14px', fontFamily:'monospace', fontSize:'13px', color:'var(--t2)',
              overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap',
            }}>
              {apiKey}
            </div>
            <button className="btn-ghost" style={{ fontSize:'12px', padding:'8px 14px', flexShrink:0 }} onClick={copyKey}>
              {keyCopied ? '✓ Copied' : 'Copy'}
            </button>
            <button className="btn-ghost" style={{ fontSize:'12px', padding:'8px 14px', flexShrink:0, color:'#f87171' }} onClick={regenerateKey}>
              Regenerate
            </button>
          </div>
        </div>
        <Row label="API access" desc="Available on Pro and Enterprise plans" last>
          <span style={{
            fontSize:'11px', fontWeight:'700', padding:'3px 10px', borderRadius:'10px',
            ...(user?.plan !== 'free'
              ? { background:'rgba(74,222,128,0.1)', color:'#4ade80', border:'1px solid rgba(74,222,128,0.25)' }
              : { background:'rgba(255,255,255,0.06)', color:'var(--t3)', border:'1px solid var(--b1)' }),
          }}>
            {user?.plan !== 'free' ? 'Enabled' : 'Upgrade to use'}
          </span>
        </Row>
      </Section>

      {/* ── Notifications ────────────────────────── */}
      <Section title="Notifications" desc="Choose what emails and alerts you receive">
        {[
          { key:'scanComplete',    label:'Scan complete',      desc:'Receive an email when a scan finishes.' },
          { key:'criticalAlerts',  label:'Critical findings',  desc:'Immediate alert when critical vulnerabilities are found.' },
          { key:'weeklyDigest',    label:'Weekly digest',      desc:'A weekly summary of your scanning activity.' },
          { key:'marketingEmails', label:'Product updates',    desc:'News about new features and improvements.', last:true },
        ].map(n => (
          <Row key={n.key} label={n.label} desc={n.desc} last={n.last}>
            <Toggle value={notifications[n.key]} onChange={v => { setNotifications(p => ({ ...p, [n.key]:v })); toast(`${n.label} ${v ? 'enabled' : 'disabled'}.`, 'info', 2000); }} />
          </Row>
        ))}
      </Section>

      {/* ── Preferences ──────────────────────────── */}
      <Section title="Preferences" desc="Appearance and regional settings">
        <Row label="Theme" desc="Interface color scheme">
          <div style={{ display:'flex', gap:'6px' }}>
            {['dark','light','system'].map(t => (
              <button key={t} onClick={() => { setTheme(t); toast(`Theme set to ${t}. Full theme switching coming soon.`, 'info'); }}
                style={{ padding:'5px 12px', fontSize:'12px', fontWeight:'600', borderRadius:'7px', border:'1px solid', cursor:'pointer', textTransform:'capitalize',
                  background: theme === t ? 'var(--blue-soft)' : 'var(--s3)',
                  borderColor: theme === t ? 'rgba(74,138,244,0.4)' : 'var(--b1)',
                  color: theme === t ? 'var(--blue)' : 'var(--t3)',
                }}>
                {t}
              </button>
            ))}
          </div>
        </Row>
        <Row label="Language" desc="Interface language" last>
          <select value={language} onChange={e => setLanguage(e.target.value)}
            style={{ background:'var(--s3)', border:'1px solid var(--b2)', color:'var(--t1)', borderRadius:'7px', padding:'6px 10px', fontSize:'13px', fontFamily:'inherit', cursor:'pointer' }}>
            <option value="en">English</option>
            <option value="fr">Français</option>
            <option value="es">Español</option>
            <option value="de">Deutsch</option>
            <option value="ar">العربية</option>
          </select>
        </Row>
      </Section>

      {/* ── Danger zone ──────────────────────────── */}
      <div style={{ marginBottom:'28px' }}>
        <div style={{ marginBottom:'16px' }}>
          <div style={{ fontSize:'14px', fontWeight:'700', color:'#f87171', marginBottom:'4px' }}>Danger Zone</div>
          <div style={{ fontSize:'12px', color:'var(--t3)' }}>Irreversible actions — proceed with caution</div>
        </div>
        <div style={{ background:'rgba(240,68,56,0.05)', border:'1px solid rgba(240,68,56,0.2)', borderRadius:'12px', overflow:'hidden' }}>
          <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', padding:'18px 22px', borderBottom:'1px solid rgba(240,68,56,0.15)' }}>
            <div>
              <div style={{ fontSize:'13px', fontWeight:'600', color:'var(--t1)', marginBottom:'2px' }}>Sign out of all devices</div>
              <div style={{ fontSize:'12px', color:'var(--t3)' }}>Revoke all active sessions immediately.</div>
            </div>
            <button className="btn-outline" style={{ fontSize:'12px', padding:'6px 16px', borderColor:'rgba(240,68,56,0.4)', color:'#f87171' }}
              onClick={() => { logout(); navigate('/login'); }}>
              Sign Out All
            </button>
          </div>
          <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', padding:'18px 22px' }}>
            <div>
              <div style={{ fontSize:'13px', fontWeight:'600', color:'#f87171', marginBottom:'2px' }}>Delete account</div>
              <div style={{ fontSize:'12px', color:'var(--t3)' }}>Permanently delete your account and all scan data.</div>
            </div>
            <button onClick={deleteAccount}
              style={{ padding:'6px 16px', fontSize:'12px', fontWeight:'600', background:'rgba(240,68,56,0.1)', border:'1px solid rgba(240,68,56,0.35)', color:'#f87171', borderRadius:'8px', cursor:'pointer', transition:'all 0.15s' }}
              onMouseEnter={e => e.currentTarget.style.background='rgba(240,68,56,0.2)'}
              onMouseLeave={e => e.currentTarget.style.background='rgba(240,68,56,0.1)'}>
              Delete Account
            </button>
          </div>
        </div>
      </div>

    </div>
  );
}
