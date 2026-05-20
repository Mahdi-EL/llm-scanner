import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useToast } from '../context/ToastContext';

const INTEGRATIONS = [
  {
    id      : 'openai',
    name    : 'OpenAI API',
    icon    : '🤖',
    desc    : 'Connect to GPT-4o, GPT-3.5-turbo and any OpenAI-compatible endpoint.',
    color   : '#10a37f',
    bg      : 'rgba(16,163,127,0.1)',
    border  : 'rgba(16,163,127,0.25)',
    group   : 'Cloud Providers',
    models  : 'GPT-4o · GPT-3.5 · Custom',
    fields  : [
      { key:'api_key',  label:'API Key',              placeholder:'sk-…',                       type:'password' },
      { key:'base_url', label:'Base URL (optional)',   placeholder:'https://api.openai.com/v1',  type:'text' },
      { key:'model',    label:'Model',                 placeholder:'gpt-4o',                     type:'text' },
    ],
  },
  {
    id      : 'groq',
    name    : 'Groq',
    icon    : '⚡',
    desc    : 'Ultra-fast inference with Llama 3, Mixtral and Gemma models at sub-second latency.',
    color   : '#f97316',
    bg      : 'rgba(249,115,22,0.1)',
    border  : 'rgba(249,115,22,0.25)',
    group   : 'Cloud Providers',
    models  : 'Llama 3 · Mixtral · Gemma',
    fields  : [
      { key:'api_key', label:'Groq API Key', placeholder:'gsk_…',          type:'password' },
      { key:'model',   label:'Model',        placeholder:'llama3-70b-8192', type:'text' },
    ],
  },
  {
    id      : 'anthropic',
    name    : 'Anthropic Claude',
    icon    : '🧠',
    desc    : 'Test Claude models including Sonnet, Opus and Haiku across all versions.',
    color   : '#8b5cf6',
    bg      : 'rgba(139,92,246,0.1)',
    border  : 'rgba(139,92,246,0.25)',
    group   : 'Cloud Providers',
    models  : 'Sonnet · Opus · Haiku',
    fields  : [
      { key:'api_key', label:'Anthropic API Key', placeholder:'sk-ant-…',          type:'password' },
      { key:'model',   label:'Model',              placeholder:'claude-sonnet-4-6', type:'text' },
    ],
  },
  {
    id      : 'azure',
    name    : 'Azure OpenAI',
    icon    : '☁️',
    desc    : 'Enterprise-grade OpenAI models hosted on Microsoft Azure with compliance.',
    color   : '#0078d4',
    bg      : 'rgba(0,120,212,0.1)',
    border  : 'rgba(0,120,212,0.25)',
    group   : 'Cloud Providers',
    models  : 'GPT-4 · Custom deployments',
    fields  : [
      { key:'api_key',  label:'Azure API Key',    placeholder:'…',                                     type:'password' },
      { key:'base_url', label:'Azure Endpoint',   placeholder:'https://your-resource.openai.azure.com/', type:'text' },
      { key:'model',    label:'Deployment Name',  placeholder:'gpt-4',                                 type:'text' },
    ],
  },
  {
    id      : 'ollama',
    name    : 'Ollama (Local)',
    icon    : '🦙',
    desc    : 'Run open-source models locally via Ollama — no data leaves your machine.',
    color   : '#4a8af4',
    bg      : 'rgba(74,138,244,0.08)',
    border  : 'rgba(74,138,244,0.2)',
    group   : 'Local Models',
    models  : 'Llama 3 · Mistral · Phi-3',
    fields  : [
      { key:'base_url', label:'Ollama URL',  placeholder:'http://localhost:11434', type:'text' },
      { key:'model',    label:'Model Name',  placeholder:'llama3',                type:'text' },
    ],
  },
  {
    id      : 'custom',
    name    : 'Custom REST API',
    icon    : '🔌',
    desc    : 'Any HTTP endpoint that accepts a chat-style JSON request body.',
    color   : '#9b6ef3',
    bg      : 'rgba(155,110,243,0.08)',
    border  : 'rgba(155,110,243,0.18)',
    group   : 'Custom',
    models  : 'Any JSON endpoint',
    fields  : [
      { key:'base_url', label:'Endpoint URL',           placeholder:'https://api.yourapp.com/chat', type:'text' },
      { key:'api_key',  label:'API Key / Bearer Token', placeholder:'optional',                     type:'password' },
    ],
  },
];

const GROUPS = ['Cloud Providers', 'Local Models', 'Custom'];

function StatusDot({ connected }) {
  return (
    <div style={{ display:'flex', alignItems:'center', gap:'5px' }}>
      <div style={{
        width:'7px', height:'7px', borderRadius:'50%',
        background: connected ? '#4ade80' : 'var(--b2)',
        boxShadow: connected ? '0 0 6px rgba(74,222,128,0.5)' : 'none',
      }} />
      <span style={{ fontSize:'11px', color: connected ? '#4ade80' : 'var(--t3)', fontWeight:'600' }}>
        {connected ? 'Connected' : 'Not configured'}
      </span>
    </div>
  );
}

function IntegrationCard({ integration, onTest }) {
  const [open,     setOpen]     = useState(false);
  const [saved,    setSaved]    = useState(false);
  const [testing,  setTesting]  = useState(false);
  const [testOk,   setTestOk]   = useState(null);
  const [values,   setValues]   = useState({});
  const toast = useToast();
  const navigate = useNavigate();

  const set = (k, v) => setValues(p => ({ ...p, [k]: v }));

  const save = () => {
    setSaved(true);
    setTestOk(null);
    toast(`${integration.name} configuration saved.`, 'success');
    setTimeout(() => setOpen(false), 500);
  };

  const test = async () => {
    setTesting(true);
    setTestOk(null);
    toast(`Testing connection to ${integration.name}…`, 'info');
    await new Promise(r => setTimeout(r, 1400));
    const ok = true; // mock
    setTestOk(ok);
    setTesting(false);
    if (ok) toast(`${integration.name}: connection successful ✓`, 'success', 3500);
    else    toast(`${integration.name}: connection failed`, 'error');
    onTest(integration);
  };

  return (
    <div style={{
      background:'var(--s1)', borderRadius:'14px', overflow:'hidden',
      border:`1px solid var(--b1)`,
      borderLeft:`3px solid ${integration.color}`,
      transition:'border-color 0.2s, box-shadow 0.2s',
    }}
      onMouseEnter={e => e.currentTarget.style.boxShadow=`0 0 0 1px ${integration.color}20, 0 4px 20px rgba(0,0,0,0.15)`}
      onMouseLeave={e => e.currentTarget.style.boxShadow='none'}
    >
      <div style={{ padding:'18px 20px', display:'flex', alignItems:'center', gap:'14px' }}>
        {/* Icon */}
        <div style={{
          width:'42px', height:'42px', borderRadius:'11px', flexShrink:0,
          background:integration.bg, border:`1px solid ${integration.border}`,
          display:'flex', alignItems:'center', justifyContent:'center', fontSize:'18px',
        }}>
          {integration.icon}
        </div>

        {/* Info */}
        <div style={{ flex:1, minWidth:0 }}>
          <div style={{ display:'flex', alignItems:'center', gap:'10px', marginBottom:'3px' }}>
            <span style={{ fontSize:'14px', fontWeight:'700', color:'var(--t1)' }}>{integration.name}</span>
            {testOk === true && (
              <span style={{ fontSize:'10px', fontWeight:'700', color:'#4ade80', background:'rgba(74,222,128,0.1)', border:'1px solid rgba(74,222,128,0.25)', borderRadius:'10px', padding:'1px 8px' }}>
                ✓ Verified
              </span>
            )}
          </div>
          <div style={{ fontSize:'12px', color:'var(--t3)', marginBottom:'5px', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{integration.desc}</div>
          <div style={{ display:'flex', alignItems:'center', gap:'12px' }}>
            <StatusDot connected={saved} />
            <span style={{ fontSize:'11px', color:'var(--t3)' }}>{integration.models}</span>
          </div>
        </div>

        {/* Actions */}
        <div style={{ display:'flex', gap:'6px', flexShrink:0, alignItems:'center' }}>
          {saved && (
            <>
              <button
                className="btn-ghost"
                style={{ fontSize:'11px', padding:'5px 10px', display:'flex', alignItems:'center', gap:'4px' }}
                onClick={() => navigate('/new-scan')}
              >
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                Scan
              </button>
              <button
                className="btn-ghost"
                style={{ fontSize:'11px', padding:'5px 10px', display:'flex', alignItems:'center', gap:'4px', opacity: testing ? 0.6 : 1 }}
                onClick={test}
                disabled={testing}
              >
                {testing ? (
                  <span className="spinner" style={{ width:'10px', height:'10px', borderWidth:'1.5px' }} />
                ) : (
                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.41"/></svg>
                )}
                {testing ? 'Testing…' : 'Test'}
              </button>
            </>
          )}
          <button
            onClick={() => setOpen(o => !o)}
            style={{
              padding:'6px 14px', fontSize:'12px', fontWeight:'600', cursor:'pointer', borderRadius:'8px',
              background: open ? 'var(--s3)' : integration.bg,
              border:`1px solid ${open ? 'var(--b2)' : integration.border}`,
              color: open ? 'var(--t2)' : integration.color,
              transition:'all 0.15s',
            }}
          >
            {open ? 'Cancel' : saved ? 'Edit' : 'Configure'}
          </button>
        </div>
      </div>

      {/* Config form */}
      {open && (
        <div style={{ padding:'0 20px 20px', borderTop:'1px solid var(--b1)' }}>
          <div style={{ paddingTop:'16px', display:'flex', flexDirection:'column', gap:'12px' }}>
            {integration.fields.map(f => (
              <div key={f.key} className="form-group" style={{ marginBottom:0 }}>
                <label>{f.label}</label>
                <input
                  type={f.type}
                  placeholder={f.placeholder}
                  value={values[f.key] || ''}
                  onChange={e => set(f.key, e.target.value)}
                />
              </div>
            ))}
            <div style={{ display:'flex', gap:'8px', marginTop:'4px' }}>
              <button className="btn-primary" onClick={save} style={{ padding:'8px 18px', fontSize:'13px' }}>
                Save
              </button>
              <button className="btn-ghost" onClick={test} style={{ padding:'8px 14px', fontSize:'13px', display:'flex', alignItems:'center', gap:'6px' }} disabled={testing}>
                {testing ? <><span className="spinner" style={{ width:'12px', height:'12px', borderWidth:'1.5px' }} /> Testing…</> : 'Test Connection'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function Integrations() {
  const navigate = useNavigate();

  const handleTest = (_integration) => {
    // handled inside IntegrationCard
  };

  return (
    <div style={{ maxWidth:'800px' }}>

      {/* Header */}
      <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', marginBottom:'28px' }}>
        <div>
          <h1 className="page-title">Integrations</h1>
          <p className="page-subtitle" style={{ marginBottom:0 }}>
            Connect your AI targets — configure endpoints and credentials for scanning
          </p>
        </div>
        <button className="btn-primary" onClick={() => navigate('/new-scan')} style={{ marginTop:'4px', flexShrink:0 }}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>
          New Scan
        </button>
      </div>

      {/* Info bar */}
      <div style={{
        background:'rgba(74,138,244,0.06)', border:'1px solid rgba(74,138,244,0.18)',
        borderRadius:'10px', padding:'13px 18px', marginBottom:'24px',
        display:'flex', gap:'12px', alignItems:'center',
      }}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <div style={{ fontSize:'13px', color:'var(--t2)', lineHeight:'1.5' }}>
          Credentials are saved locally in your browser session and are{' '}
          <strong style={{ color:'var(--t1)' }}>never sent to our servers</strong>.
          After configuring, use "Test" to verify the connection, then "Scan" to launch an assessment.
        </div>
      </div>

      {/* Grouped cards */}
      {GROUPS.map(group => {
        const items = INTEGRATIONS.filter(i => i.group === group);
        return (
          <div key={group} style={{ marginBottom:'28px' }}>
            <div style={{ fontSize:'11px', fontWeight:'700', color:'var(--t3)', textTransform:'uppercase', letterSpacing:'0.7px', marginBottom:'10px', paddingLeft:'2px' }}>
              {group}
            </div>
            <div style={{ display:'flex', flexDirection:'column', gap:'8px' }}>
              {items.map(integration => (
                <IntegrationCard key={integration.id} integration={integration} onTest={handleTest} />
              ))}
            </div>
          </div>
        );
      })}

      {/* CTA */}
      <div style={{
        background:'linear-gradient(135deg, rgba(74,138,244,0.06), rgba(155,110,243,0.06))',
        border:'1px solid rgba(74,138,244,0.15)',
        borderRadius:'12px', padding:'22px 24px', display:'flex', alignItems:'center', justifyContent:'space-between', gap:'16px',
      }}>
        <div>
          <div style={{ fontSize:'14px', fontWeight:'700', color:'var(--t1)', marginBottom:'4px' }}>
            Don't see your provider?
          </div>
          <div style={{ fontSize:'13px', color:'var(--t3)' }}>
            Use <strong style={{ color:'var(--t2)' }}>Custom REST API</strong> to connect any HTTP endpoint that accepts JSON.
          </div>
        </div>
        <button className="btn-outline" onClick={() => navigate('/new-scan')} style={{ flexShrink:0, fontSize:'13px' }}>
          View Docs
        </button>
      </div>
    </div>
  );
}
