import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { scansAPI } from '../services/api';
import { useToast } from '../context/ToastContext';

const TARGET_TYPES = [
  {
    id     : 'simulation',
    icon   : '🧪',
    label  : 'Simulation',
    desc   : 'Safe sandbox — no live API needed. Perfect for development & testing.',
    tag    : 'Recommended',
    color  : 'var(--blue)',
    features: ['No API key required', 'Instant setup', 'Banking bot preset'],
  },
  {
    id     : 'groq',
    icon   : '⚡',
    label  : 'Groq',
    desc   : 'Ultra-fast inference with Llama, Mixtral and Gemma models.',
    color  : '#f97316',
    features: ['Llama 3 / Mixtral', 'gsk_ API key', 'Sub-second latency'],
  },
  {
    id     : 'openai_compatible',
    icon   : '🤖',
    label  : 'OpenAI API',
    desc   : 'GPT-4o, GPT-3.5-turbo or any OpenAI-compatible endpoint.',
    color  : '#10a37f',
    features: ['GPT-4o / GPT-3.5', 'Custom base URL', 'sk- API key'],
  },
  {
    id     : 'custom_rest',
    icon   : '🔌',
    label  : 'Custom REST',
    desc   : 'Any HTTP endpoint that accepts a chat-style JSON request body.',
    color  : 'var(--purple)',
    features: ['Any JSON API', 'Bearer token auth', 'Full flexibility'],
  },
];

const ATTACK_CATEGORIES = [
  { label:'Prompt Injection',       sev:'critical', icon:'💉' },
  { label:'Jailbreaks',             sev:'critical', icon:'🔓' },
  { label:'System Prompt Leakage',  sev:'high',     icon:'🕵️' },
  { label:'Data Exfiltration',      sev:'high',     icon:'📤' },
  { label:'Authority Impersonation',sev:'high',     icon:'👤' },
  { label:'Role Confusion',         sev:'high',     icon:'🎭' },
  { label:'Logical Paradoxes',      sev:'medium',   icon:'♾️' },
  { label:'Context Manipulation',   sev:'medium',   icon:'🌀' },
  { label:'Encoding Attacks',       sev:'medium',   icon:'🔐' },
  { label:'Token Smuggling',        sev:'medium',   icon:'📦' },
  { label:'Multi-turn Exploits',    sev:'medium',   icon:'🔄' },
  { label:'+ 10 more categories',   sev:'low',      icon:'⋯' },
];

const SEV_COLOR = { critical:'#f87171', high:'#fb923c', medium:'#facc15', low:'var(--t3)' };

const STEPS = [
  { num:1, label:'Name Target' },
  { num:2, label:'Select Type' },
  { num:3, label:'Configure'   },
];

function StepProgress({ filled }) {
  return (
    <div className="step-progress" style={{ marginBottom:'24px' }}>
      {STEPS.map((s, i) => {
        const done   = filled > i;
        const active = filled === i;
        return (
          <React.Fragment key={s.num}>
            <div className={`step-item${done ? ' is-done' : active ? ' is-active' : ''}`}>
              <div className="step-num">{done ? (
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>
              ) : s.num}</div>
              <div className="step-label">{s.label}</div>
            </div>
            {i < STEPS.length - 1 && (
              <div style={{ flex:1, height:'1px', background: done ? 'var(--blue)' : 'var(--b1)', transition:'background 0.3s' }} />
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}

function SectionCard({ step, title, subtitle, children }) {
  return (
    <div style={{
      background:'var(--s1)', border:'1px solid var(--b1)', borderRadius:'14px',
      padding:'24px', marginBottom:'12px', position:'relative', overflow:'hidden',
    }}>
      <div style={{ position:'absolute', top:0, left:0, right:0, height:'1px', background:'linear-gradient(90deg,transparent,rgba(255,255,255,0.06),transparent)' }} />
      <div style={{ display:'flex', alignItems:'center', gap:'10px', marginBottom:'20px' }}>
        <div style={{
          width:'26px', height:'26px', background:'var(--blue-soft)', border:'1px solid rgba(74,138,244,0.25)',
          borderRadius:'7px', display:'flex', alignItems:'center', justifyContent:'center',
          fontSize:'11px', fontWeight:'800', color:'var(--blue)', flexShrink:0,
        }}>{step}</div>
        <div>
          <div style={{ fontSize:'14px', fontWeight:'700', color:'var(--t1)' }}>{title}</div>
          <div style={{ fontSize:'12px', color:'var(--t3)', marginTop:'1px' }}>{subtitle}</div>
        </div>
      </div>
      {children}
    </div>
  );
}

export default function NewScan() {
  const navigate = useNavigate();
  const toast    = useToast();
  const [loading, setLoading] = useState(false);
  const [form, setForm] = useState({
    target_name  : '',
    target_type  : 'simulation',
    system_prompt: '',
    api_url      : '',
    api_key      : '',
  });

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const filledSteps = form.target_name.trim() ? 2 : 0;

  const handleSubmit = async () => {
    if (!form.target_name.trim()) { toast('Please enter a target name.', 'error'); return; }
    setLoading(true);
    try {
      const res = await scansAPI.start({
        target_name  : form.target_name,
        target_type  : form.target_type,
        system_prompt: form.system_prompt || null,
        api_url      : form.api_url       || null,
        api_key      : form.api_key       || null,
      });
      toast('Scan started successfully!', 'success');
      navigate(`/results/${res.data.scan_id}`);
    } catch {
      toast('Failed to start scan. Make sure the API is running.', 'error');
      setLoading(false);
    }
  };

  const needsURL = form.target_type === 'openai_compatible' || form.target_type === 'custom_rest';
  const needsKey = form.target_type !== 'simulation';

  return (
    <div style={{ maxWidth:'700px' }}>

      {/* Header */}
      <div style={{ marginBottom:'28px' }}>
        <h1 className="page-title">New Security Scan</h1>
        <p className="page-subtitle" style={{ marginBottom:0 }}>
          Configure a target and launch a full adversarial assessment against your AI
        </p>
      </div>

      <StepProgress filled={filledSteps} />

      {/* Step 1: Name */}
      <SectionCard step={1} title="Name your target" subtitle="Give a descriptive name for this AI application">
        <div className="form-group" style={{ marginBottom:0 }}>
          <label>Target Name</label>
          <input
            value={form.target_name}
            onChange={e => set('target_name', e.target.value)}
            placeholder="e.g. Banking AI Chatbot, Customer Support Bot, HR Assistant…"
            style={{ fontSize:'14px' }}
            autoFocus
          />
        </div>
      </SectionCard>

      {/* Step 2: Type */}
      <SectionCard step={2} title="Select target type" subtitle="Choose how to connect to your AI application">
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:'10px' }}>
          {TARGET_TYPES.map(t => {
            const active = form.target_type === t.id;
            return (
              <button key={t.id} onClick={() => set('target_type', t.id)} style={{
                padding:'16px', background: active ? `${t.color}10` : 'var(--s2)',
                border:`1px solid ${active ? `${t.color}55` : 'var(--b1)'}`,
                borderRadius:'10px', cursor:'pointer', textAlign:'left',
                position:'relative', transition:'all 0.15s',
              }}
                onMouseEnter={e => { if (!active) e.currentTarget.style.borderColor = 'var(--b2)'; }}
                onMouseLeave={e => { if (!active) e.currentTarget.style.borderColor = 'var(--b1)'; }}
              >
                {t.tag && (
                  <span style={{ position:'absolute', top:'9px', right:'9px', fontSize:'9px', fontWeight:'700', textTransform:'uppercase', letterSpacing:'0.5px', color:'var(--blue)', background:'var(--blue-soft)', border:'1px solid rgba(74,138,244,0.2)', borderRadius:'10px', padding:'2px 7px' }}>
                    {t.tag}
                  </span>
                )}
                {active && (
                  <div style={{ position:'absolute', top:'10px', left:'10px', width:'7px', height:'7px', borderRadius:'50%', background:t.color, boxShadow:`0 0 6px ${t.color}80` }} />
                )}
                <div style={{ fontSize:'20px', marginBottom:'8px', marginTop: active ? '2px' : '0' }}>{t.icon}</div>
                <div style={{ fontSize:'13px', fontWeight:'700', color: active ? t.color : 'var(--t1)', marginBottom:'4px' }}>{t.label}</div>
                <div style={{ fontSize:'11px', color:'var(--t3)', lineHeight:'1.4', marginBottom:'10px' }}>{t.desc}</div>
                <div style={{ display:'flex', flexDirection:'column', gap:'3px' }}>
                  {t.features.map(f => (
                    <div key={f} style={{ display:'flex', alignItems:'center', gap:'5px', fontSize:'11px', color: active ? 'var(--t2)' : 'var(--t3)' }}>
                      <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke={active ? t.color : 'var(--t3)'} strokeWidth="3" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>
                      {f}
                    </div>
                  ))}
                </div>
              </button>
            );
          })}
        </div>
      </SectionCard>

      {/* Step 3: Config */}
      <SectionCard step={3} title={needsURL ? 'API configuration' : 'System prompt (optional)'} subtitle={needsURL ? 'Enter your endpoint URL and credentials' : 'Customize the behavior of your simulated AI'}>

        {form.target_type === 'simulation' && (
          <div className="form-group" style={{ marginBottom:0 }}>
            <label>Custom System Prompt</label>
            <textarea
              value={form.system_prompt}
              onChange={e => set('system_prompt', e.target.value)}
              placeholder="Leave empty to use the default banking chatbot simulation…&#10;&#10;Example: You are a helpful customer service assistant for Acme Corp. You have access to order history and can process refunds..."
              style={{ minHeight:'100px' }}
            />
          </div>
        )}

        {needsURL && (
          <div className="form-group">
            <label>API Endpoint URL *</label>
            <input value={form.api_url} onChange={e => set('api_url', e.target.value)} placeholder="https://api.yourapp.com/v1/chat/completions" />
          </div>
        )}

        {needsKey && !needsURL && form.target_type === 'groq' && (
          <div className="form-group" style={{ marginBottom:0 }}>
            <label>Groq API Key</label>
            <input value={form.api_key} onChange={e => set('api_key', e.target.value)} placeholder="gsk_…" type="password" />
          </div>
        )}

        {needsKey && needsURL && (
          <div className="form-group" style={{ marginBottom:0 }}>
            <label>API Key / Bearer Token {form.target_type === 'custom_rest' ? '(optional)' : ''}</label>
            <input value={form.api_key} onChange={e => set('api_key', e.target.value)} placeholder={form.target_type === 'openai_compatible' ? 'sk-…' : 'Bearer token or API key'} type="password" />
          </div>
        )}
      </SectionCard>

      {/* Attack preview */}
      <div style={{
        background:'var(--s1)', border:'1px solid var(--b1)', borderRadius:'14px',
        padding:'20px 24px', marginBottom:'16px', position:'relative', overflow:'hidden',
      }}>
        <div style={{ position:'absolute', top:0, left:0, right:0, height:'1px', background:'linear-gradient(90deg,transparent,rgba(255,255,255,0.06),transparent)' }} />
        <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:'16px' }}>
          <div>
            <div style={{ fontSize:'13px', fontWeight:'700', color:'var(--t1)' }}>Attack Coverage</div>
            <div style={{ fontSize:'12px', color:'var(--t3)', marginTop:'2px' }}>1,010+ prompts across 21 categories</div>
          </div>
          <div style={{ display:'flex', gap:'16px', fontSize:'12px' }}>
            {[['#f87171','Critical'],['#fb923c','High'],['#facc15','Medium']].map(([c,l]) => (
              <div key={l} style={{ display:'flex', alignItems:'center', gap:'5px', color:'var(--t3)' }}>
                <div style={{ width:'8px', height:'8px', borderRadius:'2px', background:c }} />
                {l}
              </div>
            ))}
          </div>
        </div>
        <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:'6px' }}>
          {ATTACK_CATEGORIES.map(cat => (
            <div key={cat.label} style={{
              display:'flex', alignItems:'center', gap:'7px',
              padding:'7px 10px', background:'var(--s2)', borderRadius:'8px',
              border:`1px solid ${SEV_COLOR[cat.sev]}20`,
            }}>
              <span style={{ fontSize:'13px' }}>{cat.icon}</span>
              <span style={{ fontSize:'11px', color:cat.sev === 'low' ? 'var(--t3)' : 'var(--t2)', fontWeight: cat.sev !== 'low' ? '600' : '400' }}>
                {cat.label}
              </span>
              <div style={{ marginLeft:'auto', width:'6px', height:'6px', borderRadius:'50%', background:SEV_COLOR[cat.sev], flexShrink:0 }} />
            </div>
          ))}
        </div>
        <div style={{ marginTop:'14px', display:'flex', gap:'24px', fontSize:'12px', color:'var(--t3)' }}>
          <span>⏱ Est. time: <strong style={{ color:'var(--t2)' }}>15–25 min</strong></span>
          <span>🛡 Categories: <strong style={{ color:'var(--t2)' }}>21</strong></span>
          <span>📝 Prompts: <strong style={{ color:'var(--t2)' }}>1,010+</strong></span>
          <span>📄 PDF report included</span>
        </div>
      </div>

      {/* Launch button */}
      <button
        className="btn-primary"
        onClick={handleSubmit}
        disabled={loading || !form.target_name.trim()}
        style={{ width:'100%', padding:'15px', fontSize:'15px', justifyContent:'center', borderRadius:'10px', letterSpacing:'0.2px', position:'relative', overflow:'hidden' }}
      >
        {loading ? (
          <><span className="spinner" style={{ borderTopColor:'#fff' }} />&nbsp; Starting scan…</>
        ) : (
          <>
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>
            &nbsp; Launch Security Scan
            {form.target_name.trim() && (
              <span style={{ marginLeft:'8px', opacity:0.7, fontSize:'13px' }}>→ {form.target_name}</span>
            )}
          </>
        )}
      </button>

      <p style={{ fontSize:'11px', color:'var(--t3)', textAlign:'center', marginTop:'12px', lineHeight:'1.5' }}>
        By launching you agree that this is an authorized security test. API keys are never stored on our servers.
      </p>
    </div>
  );
}
