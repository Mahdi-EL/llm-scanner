import React, { useCallback, useEffect, useState } from 'react';
import LoadError from '../components/LoadError';
import { useNavigate } from 'react-router-dom';
import { targetsAPI, schedulesAPI, scansAPI, gatewayAPI, API_URL, errorMessage } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import { useConfirm } from '../context/ConfirmContext';
import { relTime, shortDate, TARGET_TYPES } from '../utils/format';
import FirewallPanel from '../components/FirewallPanel';

const TYPES = TARGET_TYPES;

const EMPTY = { name:'', target_type:'openai_compatible', api_url:'', api_key:'', model:'', system_prompt:'', input_field:'', output_field:'' };
const EDITABLE = ['name', 'target_type', 'api_url', 'model', 'system_prompt', 'input_field', 'output_field'];
const URL_TYPES = ['openai_compatible', 'custom_rest'];
const sameURL = (a, b) => (a || '').trim().replace(/\/+$/, '') === (b || '').trim().replace(/\/+$/, '');

/* Adds a target, or with `target` changes a saved one (its key is never shown: leave the field empty to keep it). */
function TargetForm({ target, onSaved, onCancel }) {
  const toast = useToast();
  const initial = target
    ? { ...EMPTY, ...Object.fromEntries(EDITABLE.map(k => [k, String((k === 'name' ? target.name : target.config[k]) ?? '')])) }
    : EMPTY;
  const [form, setForm] = useState(initial);
  const [clearKey, setClearKey] = useState(false);
  const [saving, setSaving] = useState(false);
  const [test, setTest] = useState(null);
  const set = (k, v) => { setForm(f => ({ ...f, [k]: v })); setTest(null); };
  const needsURL = URL_TYPES.includes(form.target_type);
  const body = () => Object.fromEntries(Object.entries(form).filter(([, v]) => v && String(v).trim()));
  // the API sends a saved key only to the address (and kind of target) it was saved for
  const savedType = target?.config.target_type;
  const keyFollows = form.target_type === 'simulation' || (sameURL(form.api_url, target?.config.api_url)
    && (form.target_type === savedType || (URL_TYPES.includes(form.target_type) && URL_TYPES.includes(savedType))));
  const keyNeeded = !!target?.has_key && !clearKey && !form.api_key.trim() && !keyFollows;

  const runTest = async () => {
    setTest({ pending: true });
    try {
      const { data } = await scansAPI.testTarget({ ...body(), name: undefined, ...(target && !clearKey ? { target_id: target.id } : {}) });
      setTest(data);
    } catch (e) { setTest({ ok:false, error: errorMessage(e) }); }
  };

  const save = async () => {
    if (!form.name.trim()) { toast('Give the target a name.', 'error'); return; }
    if (needsURL && !form.api_url.trim()) { toast('Enter the API URL.', 'error'); return; }
    if (form.target_type === 'groq' && !form.api_key.trim() && !(target?.has_key && !clearKey && keyFollows)) {
      toast('Enter your Groq API key: a Groq target runs on your own key.', 'error'); return;
    }
    setSaving(true);
    try {
      if (target) {
        const changes = Object.fromEntries(EDITABLE.filter(k => form[k].trim() !== initial[k].trim()).map(k => [k, form[k].trim()]));
        if (form.api_key.trim()) changes.api_key = form.api_key.trim();
        if (clearKey) changes.clear_api_key = true;
        const { data } = Object.keys(changes).length ? await targetsAPI.update(target.id, changes) : { data: target };
        onSaved(data);
      } else {
        const { data } = await targetsAPI.create(body());
        onSaved(data);
      }
    }
    catch (e) { toast(errorMessage(e), 'error'); }
    finally { setSaving(false); }
  };

  return (
    <div style={{ padding:'20px', borderBottom:'1px solid var(--b1)', display:'grid', gap:'12px' }}>
      <div className="tg-form-row">
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
      <div className="tg-form-row">
        {form.target_type !== 'simulation' && (
          <div className="form-group" style={{ marginBottom:0 }}>
            <label htmlFor="tg-api-key">API key</label>
            <input id="tg-api-key" type="password" autoComplete="off" value={form.api_key} onChange={e => set('api_key', e.target.value)}
              placeholder={target?.has_key && !clearKey ? 'Saved: leave empty to keep it' : 'Stored encrypted'} disabled={clearKey}
              aria-describedby={keyNeeded ? 'tg-key-needed' : undefined} />
            {keyNeeded && (
              <div id="tg-key-needed" style={{ fontSize:'12px', color:'#a15c07', marginTop:'4px' }}>
                Enter the key again: a saved key only goes to the address it was saved for.
              </div>
            )}
            {target?.has_key && (
              <label className="check-label">
                <input type="checkbox" checked={clearKey} onChange={e => { setClearKey(e.target.checked); setTest(null); }} /> Remove the saved key
              </label>
            )}
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
          placeholder={form.target_type === 'custom_rest' ? 'Improves leak detection'
            : form.target_type === 'openai_compatible' ? 'Sent as the system message with every attack' : 'The prompt to test'} />
      </div>
      <div style={{ display:'flex', gap:'8px', alignItems:'center', flexWrap:'wrap' }}>
        <button className="btn-primary" style={{ fontSize:'12px' }} disabled={saving || keyNeeded} onClick={save}>
          {saving ? 'Saving…' : target ? 'Save changes' : 'Save target'}
        </button>
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

function ScheduleControl({ target, schedule, paid, onChange, readOnly }) {
  const toast = useToast();
  const navigate = useNavigate();
  const remove = async () => {
    try { await schedulesAPI.remove(schedule.id); onChange(); }
    catch (e) { toast(errorMessage(e), 'error'); }
  };
  // a schedule kept from a paid plan doesn't run on Free; it starts again after an upgrade
  const onHold = schedule && schedule.enabled && !paid;
  if (readOnly) {
    return schedule ? <span style={{ fontSize:'12px', color:'var(--t3)' }}>
      {onHold ? `${schedule.frequency} schedule on hold: needs a paid plan`
        : schedule.enabled ? `Scanned ${schedule.frequency}, next ${shortDate(schedule.next_run_at)}` : 'Schedule paused'}</span> : null;
  }
  if (!paid) {
    if (!schedule) return <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={() => navigate('/pricing')}>Schedules: Pro plan</button>;
    return (
      <span style={{ fontSize:'12px', color:'var(--t3)', display:'inline-flex', gap:'8px', alignItems:'center', flexWrap:'wrap' }}>
        {onHold ? `${schedule.frequency} schedule on hold: needs a paid plan` : 'paused'}
        <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={() => navigate('/pricing')}>See plans</button>
        <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={remove} aria-label={`Remove the schedule of ${target.name}`}>Unschedule</button>
      </span>
    );
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
  return (
    <span style={{ fontSize:'12px', color:'var(--t3)', display:'inline-flex', gap:'8px', alignItems:'center' }}>
      {schedule.enabled ? `${schedule.frequency}, next ${shortDate(schedule.next_run_at)}` : 'paused'}
      <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={toggle}>{schedule.enabled ? 'Pause' : 'Resume'}</button>
      <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={remove} aria-label={`Remove the schedule of ${target.name}`}>Unschedule</button>
    </span>
  );
}

const GATEWAY_TYPES = ['openai_compatible', 'groq'];

/* The firewall gateway for one saved target: where to point an OpenAI client, and what it caught. */
function GatewayPanel({ target }) {
  const [stats, setStats] = useState(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    gatewayAPI.stats(target.id).then(r => setStats(r.data)).catch(() => setFailed(true));
  }, [target.id]);
  const base = `${API_URL}/gateway/${target.id}/v1`;
  const python = `import os
from openai import OpenAI

client = OpenAI(
    base_url="${base}",
    api_key=os.environ["LLMSCANNER_API_KEY"],  # your model key stays with this saved target
)`;
  const node = `import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "${base}",
  apiKey: process.env.LLMSCANNER_API_KEY,
});`;
  return (
    <div style={{ padding:'4px 20px 18px', borderBottom:'1px solid var(--b1)', background:'var(--s2)' }}>
      <p style={{ fontSize:'13px', color:'var(--t2)', lineHeight:1.6, margin:'12px 0' }}>
        Send this app's chat requests through the AI firewall: change only the base URL and the API key of your
        OpenAI client. Injections are blocked before they reach the model (the caller gets a refusal), and leaked
        secrets or system-prompt text are removed from replies and from the arguments of tool calls. Each request
        uses your daily firewall checks;
        the <code>X-LLMScanner-Input</code> and <code>X-LLMScanner-Output</code> response headers say what happened.
      </p>
      <div style={{ fontSize:'12px', color:'var(--t3)', marginBottom:'12px' }}>
        {failed ? 'Couldn’t load the gateway stats.' : !stats ? 'Loading stats…' : stats.requests === 0
          ? 'No requests in the last 7 days.'
          : `Last 7 days: ${stats.requests} request${stats.requests === 1 ? '' : 's'} · ${stats.blocked_inputs} blocked · `
            + `${stats.flagged_inputs} flagged · ${stats.blocked_outputs} ${stats.blocked_outputs === 1 ? 'reply' : 'replies'} cleaned · `
            + `${stats.unscreened} unscreened (allowance used up) · ${stats.avg_latency_ms} ms on average`}
      </div>
      <Snippet title="Python" code={python} />
      <Snippet title="Node.js" code={node} />
    </div>
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
      {/* scrolls sideways on phones: focusable so keyboard users can scroll it too */}
      <pre className="finding-pre" tabIndex={0} aria-label={`${title} example`} style={{ maxHeight:'none', whiteSpace:'pre', wordBreak:'normal', overflowX:'auto' }}>{code}</pre>
    </div>
  );
}

export default function Targets() {
  const { user, canEdit } = useAuth();
  const toast = useToast();
  const confirm = useConfirm();
  const navigate = useNavigate();
  const [targets, setTargets]     = useState([]);
  const [schedules, setSchedules] = useState([]);
  const [adding, setAdding]       = useState(false);
  const [loading, setLoading]     = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [gatewayOpen, setGatewayOpen] = useState(null);
  const [editing, setEditing] = useState(null);
  const paid = user?.plan && user.plan !== 'free';

  const load = useCallback(async () => {
    try {
      const [t, s] = await Promise.all([targetsAPI.list(), schedulesAPI.list()]);
      setTargets(t.data.targets); setSchedules(s.data.schedules);
      setLoadError(false);
    } catch { setLoadError(true); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const scanNow = async target => {
    try {
      const { data } = await scansAPI.start({ target_name: target.name, target_id: target.id });
      navigate(`/results/${data.scan_id}`);
    } catch (e) { toast(errorMessage(e), 'error', 6000); }
  };

  const remove = async target => {
    if (!(await confirm({ title: `Delete “${target.name}”?`, confirmLabel: 'Delete target',
      body: 'Its schedule is removed too; past scans stay.' }))) return;
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

  if (loadError) return <LoadError title="Targets and CI" what="your saved targets" onRetry={load} />;

  return (
    <div style={{ maxWidth:'860px' }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:'24px', gap:'16px' }}>
        <div>
          <h1 className="page-title">Targets and CI</h1>
          <p className="page-subtitle" style={{ marginBottom:0 }}>Save the AI apps you test, re-scan them in one click, schedule scans, and run them from CI.</p>
        </div>
        {!adding && canEdit && <button className="btn-primary" onClick={() => setAdding(true)}>Add target</button>}
      </div>

      <div style={{ background:'var(--s1)', border:'1px solid var(--b1)', borderRadius:'10px', overflow:'hidden', marginBottom:'28px' }}>
        {adding && <TargetForm onCancel={() => setAdding(false)} onSaved={() => { setAdding(false); load(); toast('Target saved.', 'success'); }} />}
        {loading ? (
          <div style={{ padding:'20px', fontSize:'13px', color:'var(--t3)' }}>Loading…</div>
        ) : targets.length === 0 && !adding ? (
          <div style={{ padding:'28px 20px', fontSize:'13px', color:'var(--t3)' }}>{canEdit ? 'No saved targets yet. Add one, or tick “Save this target” when you start a scan.' : 'This workspace has no saved targets yet.'}</div>
        ) : targets.map(t => {
          const schedule = schedules.find(s => s.target_id === t.id);
          const gatewayable = GATEWAY_TYPES.includes(t.config.target_type);
          return (
            <React.Fragment key={t.id}>
            <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', gap:'16px', padding:'14px 20px', borderBottom:'1px solid var(--b1)', flexWrap:'wrap' }}>
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
                <ScheduleControl target={t} schedule={schedule} paid={paid} onChange={load} readOnly={!canEdit} />
                {canEdit && <button className="btn-outline" style={{ fontSize:'12px' }} onClick={() => scanNow(t)}>Scan now</button>}
                {canEdit && (
                  <button className="btn-outline" style={{ fontSize:'12px' }} aria-expanded={editing === t.id}
                    onClick={() => setEditing(open => (open === t.id ? null : t.id))}>Edit</button>
                )}
                {gatewayable && (
                  <button className="btn-outline" style={{ fontSize:'12px' }} aria-expanded={gatewayOpen === t.id}
                    onClick={() => setGatewayOpen(open => (open === t.id ? null : t.id))}>Gateway</button>
                )}
                {canEdit && <button className="btn-ghost" style={{ fontSize:'12px', color:'#b42318' }} onClick={() => remove(t)}>Delete</button>}
              </div>
            </div>
            {editing === t.id && (
              <TargetForm key={`edit-${t.id}-${t.updated_at}`} target={t} onCancel={() => setEditing(null)}
                onSaved={() => { setEditing(null); load(); toast('Target updated.', 'success'); }} />
            )}
            {gatewayOpen === t.id && <GatewayPanel target={t} />}
            </React.Fragment>
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
