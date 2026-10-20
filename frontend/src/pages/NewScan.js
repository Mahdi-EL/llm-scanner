import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { scansAPI, targetsAPI, promptsAPI, errorMessage } from '../services/api';
import { useToast } from '../context/ToastContext';
import { useAuth } from '../context/AuthContext';
import { fmtNum, typeLabel } from '../utils/format';

const TARGET_TYPES = [
  { id:'simulation', label:'Simulation', tag:'No key needed',
    desc:'We run a Groq model with your system prompt (or a banking demo prompt) and attack it.',
    defaultModel:'' },
  { id:'groq', label:'Groq',
    desc:'Your own Groq model, with your key and your system prompt.',
    defaultModel:'' },
  { id:'openai_compatible', label:'OpenAI-compatible API',
    desc:'OpenAI, Azure OpenAI, Together, Groq’s OpenAI endpoint, or any /chat/completions API.',
    defaultModel:'gpt-4o-mini' },
  { id:'custom_rest', label:'Custom REST endpoint',
    desc:'Any HTTP endpoint that takes a JSON message and returns a JSON reply.',
    defaultModel:'' },
];

const EMPTY = {
  target_name:'', target_type:'simulation', system_prompt:'', api_url:'', api_key:'',
  model:'', baseline_question:'', input_field:'', output_field:'',
};

function Section({ title, subtitle, children }) {
  return (
    <section style={{ background:'var(--s1)', border:'1px solid var(--b1)', borderRadius:'10px', padding:'22px 24px', marginBottom:'12px' }}>
      <h2 style={{ fontSize:'15px', fontWeight:'700', marginBottom:'2px' }}>{title}</h2>
      {subtitle && <p style={{ fontSize:'12px', color:'var(--t3)', marginBottom:'16px' }}>{subtitle}</p>}
      {children}
    </section>
  );
}

export default function NewScan() {
  const navigate = useNavigate();
  const toast    = useToast();
  const { user } = useAuth();
  const [params] = useSearchParams();
  const [form, setForm]         = useState(EMPTY);
  const [loading, setLoading]   = useState(false);
  const [testing, setTesting]   = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [categories, setCategories] = useState([]);
  const [catsError, setCatsError] = useState(false);
  const [chosen, setChosen]     = useState(null);        // null = all categories
  const [targets, setTargets]   = useState([]);
  const [targetId, setTargetId] = useState(params.get('target') || '');
  const [saveTarget, setSaveTarget] = useState(false);
  const [customCount, setCustomCount] = useState(0);
  const [includeCustom, setIncludeCustom] = useState(true);
  const fullAllowed = user?.full_scans !== false;
  const [quick, setQuick] = useState(!fullAllowed);
  useEffect(() => { if (!fullAllowed) setQuick(true); }, [fullAllowed]);
  const [models, setModels] = useState({ default_target: '', groq: [] });
  const savedOnce = useRef(null);   // {key, id} of a target saved by an earlier attempt that then failed

  const loadCategories = () => scansAPI.categories()
    .then(r => { setCategories(r.data.categories); setCatsError(false); })
    .catch(() => setCatsError(true));

  useEffect(() => {
    loadCategories();
    targetsAPI.list().then(r => setTargets(r.data.targets)).catch(() => {});
    promptsAPI.list().then(r => setCustomCount(r.data.prompts.length)).catch(() => {});
    scansAPI.models().then(r => setModels(r.data)).catch(() => {});
  }, []);

  const set = (k, v) => { setForm(f => ({ ...f, [k]: v })); setTestResult(null); };
  const type = TARGET_TYPES.find(t => t.id === form.target_type);
  const needsURL = form.target_type === 'openai_compatible' || form.target_type === 'custom_rest';
  const savedTarget = targets.find(t => t.id === targetId);

  useEffect(() => {
    if (savedTarget && !form.target_name) setForm(f => ({ ...f, target_name: savedTarget.name }));
  }, [savedTarget]); // eslint-disable-line react-hooks/exhaustive-deps

  const attackCount = useMemo(() => {
    const pool = chosen ? categories.filter(c => chosen.includes(c.id)) : categories;
    return pool.reduce((n, c) => n + (quick ? (c.quick_attacks ?? c.attacks) : c.attacks), 0)
      + (includeCustom ? customCount : 0);
  }, [categories, chosen, includeCustom, customCount, quick]);
  const quickTotal = categories.reduce((n, c) => n + (c.quick_attacks ?? 0), 0);
  const fullTotal  = categories.reduce((n, c) => n + c.attacks, 0);

  const payload = () => {
    const out = { target_type: form.target_type };
    ['system_prompt','api_url','api_key','model','baseline_question','input_field','output_field']
      .forEach(k => { if (form[k]?.trim()) out[k] = form[k].trim(); });
    return out;
  };

  const validate = () => {
    if (!form.target_name.trim()) return 'Give the target a name.';
    if (chosen && chosen.length === 0) return 'Pick at least one attack category.';
    if (savedTarget) return null;
    if (needsURL && !form.api_url.trim()) return 'Enter the API URL.';
    if (needsURL && !/^https?:\/\//i.test(form.api_url.trim())) return 'The URL must start with http:// or https://';
    if (form.target_type === 'groq' && !form.api_key.trim()) return 'Enter your Groq API key.';
    return null;
  };

  const testConnection = async () => {
    const problem = needsURL && !form.api_url.trim() ? 'Enter the API URL first.' : null;
    if (problem) { toast(problem, 'error'); return; }
    setTesting(true); setTestResult(null);
    try { const { data } = await scansAPI.testTarget(payload()); setTestResult(data); }
    catch (e) { setTestResult({ ok:false, error: errorMessage(e) }); }
    finally { setTesting(false); }
  };

  const handleSubmit = async () => {
    const problem = validate();
    if (problem) { toast(problem, 'error'); return; }
    setLoading(true);
    try {
      let useTarget = savedTarget ? targetId : null;     // ?target= may name a target deleted since
      if (!useTarget && saveTarget) {
        const config = { name: form.target_name.trim(), ...payload() };
        const key = JSON.stringify(config);
        if (savedOnce.current?.key !== key) {
          const { data } = await targetsAPI.create(config);
          savedOnce.current = { key, id: data.id };
        }
        useTarget = savedOnce.current.id;
      }
      const body = useTarget
        ? { target_name: form.target_name.trim(), target_id: useTarget }
        : { target_name: form.target_name.trim(), ...payload() };
      if (chosen) body.categories = chosen;
      body.include_custom_prompts = includeCustom;
      body.quick = quick;
      const res = await scansAPI.start(body);
      toast('Scan queued.', 'success');
      navigate(`/results/${res.data.scan_id}`);
    } catch (e) {
      toast(errorMessage(e, 'Failed to start the scan.'), 'error', 6000);
      setLoading(false);
    }
  };

  const toggleCategory = id => {
    setChosen(c => {
      const current = c || categories.map(x => x.id);
      return current.includes(id) ? current.filter(x => x !== id) : [...current, id];
    });
  };

  const quota = user?.scan_limit == null ? null : `${user.scans_this_month ?? 0} of ${user.scan_limit} scans used this month`;
  const outOfScans = user?.scan_limit != null && (user.scans_this_month ?? 0) >= user.scan_limit;

  return (
    <div style={{ maxWidth:'720px' }}>
      <div style={{ marginBottom:'24px' }}>
        <h1 className="page-title">New security scan</h1>
        <p className="page-subtitle" style={{ marginBottom:0 }}>
          Point the scanner at an AI application and fire {attackCount ? fmtNum(attackCount) : 'its'} adversarial prompts at it.
          {quota && <span style={{ color:'var(--t3)' }}> · {quota}</span>}
        </p>
      </div>

      {outOfScans && (
        <div className="alert-error" role="status" style={{ marginBottom:'20px' }}>
          You’ve used all {user.scan_limit} scans of your plan this month. <Link to="/pricing">See plans</Link> to run more,
          or wait until the 1st.
        </div>
      )}

      {targets.length > 0 && (
        <Section title="Saved target" subtitle="Re-scan a target you saved before, with its stored settings and key.">
          <div className="form-group" style={{ marginBottom:0 }}>
            <select aria-label="Saved target" value={targetId} onChange={e => { setTargetId(e.target.value); setTestResult(null); }} style={{ width:'100%' }}>
              <option value="">— Configure a new target below —</option>
              {targets.map(t => <option key={t.id} value={t.id}>{t.name} ({typeLabel(t.config.target_type)})</option>)}
            </select>
          </div>
        </Section>
      )}

      <Section title="Name" subtitle="Shown in reports and used to compare scans of the same target.">
        <div className="form-group" style={{ marginBottom:0 }}>
          <input value={form.target_name} onChange={e => set('target_name', e.target.value)} maxLength={120}
            placeholder="e.g. Support chatbot (production)" autoFocus aria-label="Target name" />
        </div>
      </Section>

      {!savedTarget && (
        <>
          <Section title="Target type">
            <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(220px, 1fr))', gap:'10px' }}>
              {TARGET_TYPES.map(t => {
                const active = form.target_type === t.id;
                return (
                  <button key={t.id} type="button" onClick={() => set('target_type', t.id)} aria-pressed={active}
                    style={{ padding:'14px 16px', textAlign:'left', cursor:'pointer', borderRadius:'8px', fontFamily:'inherit',
                             background: active ? 'var(--s2)' : 'transparent',
                             border: `1px solid ${active ? 'var(--t1)' : 'var(--b1)'}` }}>
                    <div style={{ display:'flex', justifyContent:'space-between', gap:'8px' }}>
                      <span style={{ fontSize:'13px', fontWeight:'700', color:'var(--t1)' }}>{t.label}</span>
                      {t.tag && <span style={{ fontSize:'10px', color:'var(--t3)' }}>{t.tag}</span>}
                    </div>
                    <div style={{ fontSize:'12px', color:'var(--t3)', lineHeight:1.45, marginTop:'4px' }}>{t.desc}</div>
                  </button>
                );
              })}
            </div>
          </Section>

          <Section title="Connection" subtitle={needsURL ? 'Where to send attacks and how to authenticate.' : 'What the simulated assistant is told.'}>
            {needsURL && (
              <div className="form-group">
                <label htmlFor="ns-api-url">API URL *</label>
                <input id="ns-api-url" value={form.api_url} onChange={e => set('api_url', e.target.value)} maxLength={2048}
                  placeholder={form.target_type === 'openai_compatible' ? 'https://api.openai.com/v1' : 'https://api.yourapp.com/chat'} />
              </div>
            )}
            {form.target_type !== 'simulation' && (
              <div className="form-group">
                <label htmlFor="ns-api-key">{form.target_type === 'groq' ? 'Groq API key *' : `API key or bearer token${form.target_type === 'custom_rest' ? ' (optional)' : ''}`}</label>
                <input id="ns-api-key" type="password" autoComplete="off" value={form.api_key} onChange={e => set('api_key', e.target.value)} maxLength={1000}
                  placeholder={form.target_type === 'groq' ? 'gsk_…' : 'sk-… or token'} />
              </div>
            )}
            {form.target_type !== 'custom_rest' && (
              <div className="form-group">
                <label htmlFor="ns-model">Model</label>
                <input id="ns-model" value={form.model} onChange={e => set('model', e.target.value)} maxLength={100}
                  list={form.target_type === 'openai_compatible' ? undefined : 'groq-models'}
                  placeholder={`Default: ${type.defaultModel || models.default_target || 'chosen by the server'}`} />
                <datalist id="groq-models">{models.groq.map(m => <option key={m} value={m} />)}</datalist>
              </div>
            )}
            {form.target_type === 'custom_rest' && (
              <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(220px, 1fr))', gap:'10px' }}>
                <div className="form-group">
                  <label htmlFor="ns-request-field">Request field</label>
                  <input id="ns-request-field" value={form.input_field} onChange={e => set('input_field', e.target.value)} placeholder="message" />
                </div>
                <div className="form-group">
                  <label htmlFor="ns-response-field">Response field</label>
                  <input id="ns-response-field" value={form.output_field} onChange={e => set('output_field', e.target.value)} placeholder="response" />
                </div>
              </div>
            )}
            <div className="form-group">
              <label htmlFor="ns-system-prompt">{form.target_type === 'custom_rest'
                ? 'Your system prompt (optional, improves leak detection)' : 'System prompt to test (optional)'}</label>
              <textarea id="ns-system-prompt" value={form.system_prompt} onChange={e => set('system_prompt', e.target.value)} maxLength={20000}
                style={{ minHeight:'90px' }}
                placeholder={form.target_type === 'simulation'
                  ? 'Leave empty to use the demo banking assistant.'
                  : form.target_type === 'openai_compatible'
                    ? 'Sent as the system message with every attack. Leave empty if your endpoint adds its own prompt.'
                    : 'If you paste it, any reply that repeats it word for word is flagged.'} />
            </div>
            <div className="form-group" style={{ marginBottom:'12px' }}>
              <label htmlFor="ns-baseline">Baseline question (optional)</label>
              <input id="ns-baseline" value={form.baseline_question} onChange={e => set('baseline_question', e.target.value)} maxLength={1000}
                placeholder="A normal question for this app. Default: “Hi! What can you help me with?”" />
            </div>
            <div style={{ display:'flex', alignItems:'center', gap:'12px', flexWrap:'wrap' }}>
              <button type="button" className="btn-outline" onClick={testConnection} disabled={testing}>
                {testing ? 'Testing…' : 'Test connection'}
              </button>
              {testResult && (testResult.ok
                ? <span style={{ fontSize:'12px', color:'#16a34a' }}>Connected in {testResult.latency_ms} ms. Reply: “{testResult.reply_preview?.slice(0, 90)}”</span>
                : <span style={{ fontSize:'12px', color:'#b42318' }}>{testResult.error}</span>)}
            </div>
            <label style={{ display:'flex', gap:'8px', alignItems:'center', fontSize:'13px', marginTop:'14px' }}>
              <input type="checkbox" checked={saveTarget} onChange={e => setSaveTarget(e.target.checked)} />
              Save this target for one-click re-scans and schedules (its key is stored encrypted)
            </label>
          </Section>
        </>
      )}

      <Section title="Depth" subtitle="A quick scan samples every category, from basic to advanced attacks. Run a full scan before you ship.">
        <div role="group" aria-label="Scan depth" style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(220px, 1fr))', gap:'10px' }}>
          {[
            { id:true,  label:'Quick scan', desc:`About ${quickTotal ? fmtNum(quickTotal) : '110'} attacks, 5 per category. Done in a few minutes.` },
            { id:false, label:'Full scan',  desc:`All ${fullTotal ? fmtNum(fullTotal) : '1,090'} attacks.`, locked: !fullAllowed },
          ].map(o => {
            const active = quick === o.id;
            return (
              <button key={o.label} type="button" aria-pressed={active} disabled={o.locked}
                onClick={() => setQuick(o.id)}
                style={{ padding:'14px 16px', textAlign:'left', cursor: o.locked ? 'not-allowed' : 'pointer', borderRadius:'8px', fontFamily:'inherit',
                         opacity: o.locked ? 0.6 : 1, background: active ? 'var(--s2)' : 'transparent',
                         border: `1px solid ${active ? 'var(--t1)' : 'var(--b1)'}` }}>
                <div style={{ fontSize:'13px', fontWeight:'700', color:'var(--t1)' }}>{o.label}</div>
                <div style={{ fontSize:'12px', color:'var(--t3)', lineHeight:1.45, marginTop:'4px' }}>{o.desc}</div>
                {o.locked && <div style={{ fontSize:'12px', marginTop:'6px' }}>Included in paid plans. <Link to="/pricing">See plans</Link></div>}
              </button>
            );
          })}
        </div>
      </Section>

      <Section title="Attack categories" subtitle={chosen ? `${chosen.length} of ${categories.length} categories selected` : (categories.length ? `All ${categories.length} categories` : 'All categories')}>
        <div style={{ display:'flex', gap:'8px', marginBottom:'10px' }}>
          <button type="button" className="btn-ghost" style={{ fontSize:'12px' }} onClick={() => setChosen(null)}>Select all</button>
          <button type="button" className="btn-ghost" style={{ fontSize:'12px' }} onClick={() => setChosen([])}>Clear</button>
        </div>
        {catsError && (
          <div role="alert" style={{ fontSize:'13px', color:'#b42318', marginBottom:'10px' }}>
            Couldn’t load the attack categories. <button type="button" className="btn-ghost" style={{ fontSize:'12px' }} onClick={loadCategories}>Retry</button>
          </div>
        )}
        <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(210px, 1fr))', gap:'6px' }}>
          {categories.map(c => {
            const on = !chosen || chosen.includes(c.id);
            return (
              <label key={c.id} title={c.tests} style={{ display:'flex', gap:'8px', alignItems:'flex-start', fontSize:'12px', padding:'7px 9px', border:'1px solid var(--b1)', borderRadius:'6px', cursor:'pointer' }}>
                <input type="checkbox" checked={on} onChange={() => toggleCategory(c.id)} style={{ marginTop:'2px' }} />
                <span>
                  <span style={{ display:'block', color:'var(--t1)' }}>{c.title}</span>
                  <span style={{ color:'var(--t3)' }}>{c.attacks} attacks · {c.owasp[0]?.split(' ')[0]}</span>
                </span>
              </label>
            );
          })}
        </div>
        {customCount > 0 && (
          <label style={{ display:'flex', gap:'8px', alignItems:'center', fontSize:'13px', marginTop:'12px' }}>
            <input type="checkbox" checked={includeCustom} onChange={e => setIncludeCustom(e.target.checked)} />
            Include my {customCount} custom attack prompt{customCount !== 1 ? 's' : ''}
          </label>
        )}
      </Section>

      <button className="btn-primary" onClick={handleSubmit} disabled={loading || outOfScans}
        style={{ width:'100%', padding:'14px', fontSize:'15px', justifyContent:'center', borderRadius:'8px' }}>
        {loading ? 'Starting scan…' : `Launch scan${attackCount ? ` · ${fmtNum(attackCount)} attacks` : ''}`}
      </button>

      <p style={{ fontSize:'11px', color:'var(--t3)', textAlign:'center', marginTop:'12px', lineHeight:1.6 }}>
        Only scan applications you own or are authorized to test. Your target’s API key is stored encrypted while the scan runs
        and deleted when it ends, unless you save the target. Attack replies are kept with your scan until you delete it.
      </p>
    </div>
  );
}
