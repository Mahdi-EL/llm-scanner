import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { targetsAPI, schedulesAPI, scansAPI, API_URL, errorMessage } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import { relTime, shortDate, TARGET_TYPES } from '../utils/format';
import FirewallPanel from '../components/FirewallPanel';

const TYPES = TARGET_TYPES;

const EMPTY = { name:'', target_type:'openai_compatible', api_url:'', api_key:'', model:'', system_prompt:'', input_field:'', output_field:'' };

function TargetForm({ onSaved, onCancel }) {
  const toast = useToast();
  const [form, setForm] = useState(EMPTY);
  const [saving, setSaving] = useState(false);
  const [test, setTest] = useState(null);
  const set = (k, v) => { setForm(f => ({ ...f, [k]: v })); setTest(null); };
  const needsURL = form.target_type === 'openai_compatible' || form.target_type === 'custom_rest';
  const body = () => Object.fromEntries(Object.entries(form).filter(([, v]) => v && String(v).trim()));

  const runTest = async () => {
    setTest({ pending: true });
    try { const { data } = await scansAPI.testTarget({ ...body(), name: undefined }); setTest(data); }
    catch (e) { setTest({ ok:false, error: errorMessage(e) }); }
  };

  const save = async () => {
    if (!form.name.trim()) { toast('Give the target a name.', 'error'); return; }
    if (needsURL && !form.api_url.trim()) { toast('Enter the API URL.', 'error'); return; }
    setSaving(true);
    try { const { data } = await targetsAPI.create(body()); onSaved(data); }
    catch (e) { toast(errorMessage(e), 'error'); }
    finally { setSaving(false); }
  };

  return (
    <div style={{ padding:'20px', borderBottom:'1px solid var(--b1)', display:'grid', gap:'12px' }}>
      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:'12px' }}>
        <div className="form-group" style={{ marginBottom:0 }}>
          <label htmlFor="tg-name">Name *</label>
          <input id="tg-name" value={form.name} onChange={e => set('name', e.target.value)} maxLength={120} placeholder="Support bot (prod)" />
        </div>
        <div className="form-group" style={{ marginBottom:0 }}>
          <label htmlFor="tg-type">Type</label>
          <select id="tg-type" value={form.target_type} onChange={e => set('target_type', e.target.value)}>
            {Object.entries(TYPES).map(([id, label]) => <option key={id} value={id}>{label}</option>)}
          </select>
        </div>
      </div>
      {needsURL && (
        <div className="form-group" style={{ marginBottom:0 }}>
          <label htmlFor="tg-api-url">API URL *</label>
          <input id="tg-api-url" value={form.api_url} onChange={e => set('api_url', e.target.value)} placeholder="https://api.openai.com/v1" />
        </div>
      )}
      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:'12px' }}>
        {form.target_type !== 'simulation' && (
          <div className="form-group" style={{ marginBottom:0 }}>
            <label htmlFor="tg-api-key">API key</label>
            <input id="tg-api-key" type="password" autoComplete="off" value={form.api_key} onChange={e => set('api_key', e.target.value)} placeholder="Stored encrypted" />
          </div>
        )}
        {form.target_type !== 'custom_rest' ? (
          <div className="form-group" style={{ marginBottom:0 }}>
            <label htmlFor="tg-model">Model</label>
            <input id="tg-model" value={form.model} onChange={e => set('model', e.target.value)} placeholder={form.target_type === 'openai_compatible' ? 'gpt-4o-mini' : 'Server default'} />
          </div>
        ) : (
          <div className="form-group" style={{ marginBottom:0 }}>
            <label htmlFor="tg-input-field">Request / response fields</label>
            <div style={{ display:'flex', gap:'6px' }}>
              <input id="tg-input-field" value={form.input_field} onChange={e => set('input_field', e.target.value)} placeholder="message" />
              <input aria-label="Response field" value={form.output_field} onChange={e => set('output_field', e.target.value)} placeholder="response" />
            </div>
          </div>
        )}
      </div>
      <div className="form-group" style={{ marginBottom:0 }}>
        <label htmlFor="tg-system-prompt">System prompt (optional)</label>
        <textarea id="tg-system-prompt" value={form.system_prompt} onChange={e => set('system_prompt', e.target.value)} style={{ minHeight:'70px' }}
          placeholder={form.target_type === 'simulation' || form.target_type === 'groq' ? 'The prompt to test' : 'Improves leak detection'} />
      </div>
      <div style={{ display:'flex', gap:'8px', alignItems:'center', flexWrap:'wrap' }}>
        <button className="btn-primary" style={{ fontSize:'12px' }} disabled={saving} onClick={save}>{saving ? 'Saving…' : 'Save target'}</button>
        <button className="btn-outline" style={{ fontSize:'12px' }} disabled={test?.pending} onClick={runTest}>{test?.pending ? 'Testing…' : 'Test connection'}</button>
        <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={onCancel}>Cancel</button>
        {test && !test.pending && (
          <span style={{ fontSize:'12px', color: test.ok ? '#16a34a' : '#b42318' }}>
            {test.ok ? `Connected in ${test.latency_ms} ms` : test.error}
          </span>
        )}
      </div>
    </div>
  );
}

function ScheduleControl({ target, schedule, paid, onChange }) {
  const toast = useToast();
  const navigate = useNavigate();
  if (!paid) {
    return <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={() => navigate('/pricing')}>Schedules: Pro plan</button>;
  }
  const create = async frequency => {
    try { await schedulesAPI.create({ target_id: target.id, frequency, alert_drop: 5 }); onChange(); toast(`Scheduled ${frequency}.`, 'success'); }
    catch (e) { toast(errorMessage(e), 'error'); }
  };
  if (!schedule) {
    return (
      <select aria-label={`Schedule scans of ${target.name}`} defaultValue="" onChange={e => e.target.value && create(e.target.value)} style={{ fontSize:'12px' }}>
        <option value="" disabled>Schedule…</option>
        <option value="daily">Every day</option>
        <option value="weekly">Every week</option>
      </select>
    );
  }
  const toggle = async () => {
    try { await schedulesAPI.update(schedule.id, { enabled: !schedule.enabled }); onChange(); }
    catch (e) { toast(errorMessage(e), 'error'); }
  };
  const remove = async () => {
    try { await schedulesAPI.remove(schedule.id); onChange(); }
    catch (e) { toast(errorMessage(e), 'error'); }
  };
  return (
    <span style={{ fontSize:'12px', color:'var(--t3)', display:'inline-flex', gap:'8px', alignItems:'center' }}>
      {schedule.enabled ? `${schedule.frequency}, next ${shortDate(schedule.next_run_at)}` : 'paused'}
      <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={toggle}>{schedule.enabled ? 'Pause' : 'Resume'}</button>
      <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={remove}>Remove</button>
    </span>
  );
}

function Snippet({ title, code }) {
  const toast = useToast();
  return (
    <div style={{ marginBottom:'14px' }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:'6px' }}>
        <span style={{ fontSize:'13px', fontWeight:'600' }}>{title}</span>
        <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={() => { navigator.clipboard?.writeText(code); toast('Copied.', 'success', 1500); }}>Copy</button>
      </div>
      <pre className="finding-pre" style={{ maxHeight:'none', whiteSpace:'pre', wordBreak:'normal', overflowX:'auto' }}>{code}</pre>
    </div>
  );
}

export default function Targets() {
  const { user } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();
  const [targets, setTargets]     = useState([]);
  const [schedules, setSchedules] = useState([]);
  const [adding, setAdding]       = useState(false);
  const [loading, setLoading]     = useState(true);
  const paid = user?.plan && user.plan !== 'free';

  const load = useCallback(async () => {
    try {
      const [t, s] = await Promise.all([targetsAPI.list(), schedulesAPI.list()]);
      setTargets(t.data.targets); setSchedules(s.data.schedules);
    } catch (e) { toast(errorMessage(e), 'error'); }
    finally { setLoading(false); }
  }, [toast]);

  useEffect(() => { load(); }, [load]);

  const scanNow = async target => {
    try {
      const { data } = await scansAPI.start({ target_name: target.name, target_id: target.id });
      navigate(`/results/${data.scan_id}`);
    } catch (e) { toast(errorMessage(e), 'error', 6000); }
  };

  const remove = async target => {
    if (!window.confirm(`Delete "${target.name}"? Its schedule is removed too; past scans stay.`)) return;
    try { await targetsAPI.remove(target.id); load(); }
    catch (e) { toast(errorMessage(e), 'error'); }
  };

  const curl = `curl -X POST ${API_URL}/scan \\
  -H "X-API-Key: $LLMSCANNER_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"target_name": "Support bot", "target_type": "openai_compatible",
       "api_url": "https://api.openai.com/v1", "api_key": "'"$OPENAI_API_KEY"'",
       "model": "gpt-4o-mini", "categories": ["extraction", "direct_override"]}'`;
  const python = `pip install llmscanner

from llmscanner import Client
client = Client(api_key="llmsk_...", base_url="${API_URL}")
scan = client.scan("Support bot", target_type="openai_compatible",
                   api_url="https://api.openai.com/v1", api_key="sk-...", model="gpt-4o-mini")
report = client.wait(scan.scan_id)
print(report.security_score, report.grade)`;
  const action = `# .github/workflows/llm-security.yml
name: LLM security scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Mahdi-EL/llm-scanner/.github/actions/scan@main
        with:
          api-key: \${{ secrets.LLMSCANNER_API_KEY }}
          api-url: ${API_URL}
          target-name: Support bot
          target-type: openai_compatible
          target-url: https://api.openai.com/v1
          target-key: \${{ secrets.OPENAI_API_KEY }}
          model: gpt-4o-mini
          fail-on: high`;

  return (
    <div style={{ maxWidth:'860px' }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:'24px', gap:'16px' }}>
        <div>
          <h1 className="page-title">Targets and CI</h1>
          <p className="page-subtitle" style={{ marginBottom:0 }}>Save the AI apps you test, re-scan them in one click, schedule scans, and run them from CI.</p>
        </div>
        {!adding && <button className="btn-primary" onClick={() => setAdding(true)}>Add target</button>}
      </div>

      <div style={{ background:'var(--s1)', border:'1px solid var(--b1)', borderRadius:'10px', overflow:'hidden', marginBottom:'28px' }}>
        {adding && <TargetForm onCancel={() => setAdding(false)} onSaved={() => { setAdding(false); load(); toast('Target saved.', 'success'); }} />}
        {loading ? (
          <div style={{ padding:'20px', fontSize:'13px', color:'var(--t3)' }}>Loading…</div>
        ) : targets.length === 0 && !adding ? (
          <div style={{ padding:'28px 20px', fontSize:'13px', color:'var(--t3)' }}>No saved targets yet. Add one, or tick “Save this target” when you start a scan.</div>
        ) : targets.map(t => {
          const schedule = schedules.find(s => s.target_id === t.id);
          return (
            <div key={t.id} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', gap:'16px', padding:'14px 20px', borderBottom:'1px solid var(--b1)', flexWrap:'wrap' }}>
              <div style={{ minWidth:'220px', flex:1 }}>
                <div style={{ fontSize:'14px', fontWeight:'600' }}>{t.name}</div>
                <div style={{ fontSize:'12px', color:'var(--t3)' }}>
                  {TYPES[t.config.target_type] || t.config.target_type}
                  {t.config.model ? ` · ${t.config.model}` : ''}
                  {t.config.api_url ? ` · ${t.config.api_url}` : ''}
                  {t.has_key ? ' · key saved' : ''} · updated {relTime(t.updated_at)}
                </div>
              </div>
              <div style={{ display:'flex', gap:'8px', alignItems:'center', flexWrap:'wrap' }}>
                <ScheduleControl target={t} schedule={schedule} paid={paid} onChange={load} />
                <button className="btn-outline" style={{ fontSize:'12px' }} onClick={() => scanNow(t)}>Scan now</button>
                <button className="btn-ghost" style={{ fontSize:'12px', color:'#b42318' }} onClick={() => remove(t)}>Delete</button>
              </div>
            </div>
          );
        })}
      </div>

      <h2 style={{ fontSize:'15px', fontWeight:'700', marginBottom:'4px' }}>Run scans from code and CI</h2>
      <p style={{ fontSize:'12px', color:'var(--t3)', marginBottom:'14px' }}>
        Create an API key in <a href="/settings" onClick={e => { e.preventDefault(); navigate('/settings'); }}>Settings</a>, then use any of these.
      </p>
      <Snippet title="curl" code={curl} />
      <Snippet title="Python SDK" code={python} />
      <Snippet title="GitHub Actions" code={action} />

      <FirewallPanel Snippet={Snippet} />
    </div>
  );
}
