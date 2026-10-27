import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { scansAPI, downloadReport, errorMessage } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';
import { useConfirm } from '../context/ConfirmContext';
import { usePolling } from '../utils/hooks';
import { scoreColor, isActive, formatDuration, typeLabel, fmtNum, shortDate } from '../utils/format';

const SEV_META = {
  CRITICAL: { color:'#b42318', bg:'rgba(180,35,24,0.08)', label:'Critical' },
  HIGH:     { color:'#c4320a', bg:'rgba(196,50,10,0.08)', label:'High'     },
  MEDIUM:   { color:'#a15c07', bg:'rgba(161,92,7,0.08)',  label:'Medium'   },
  LOW:      { color:'#4b6b2f', bg:'rgba(75,107,47,0.08)', label:'Low'      },
  SAFE:     { color:'#3d6b4f', bg:'rgba(61,107,79,0.08)', label:'Safe'     },
  ERROR:    { color:'#6b6b6b', bg:'rgba(107,107,107,0.08)', label:'Error'  },
};
const SEV_ORDER = ['CRITICAL','HIGH','MEDIUM','LOW','SAFE','ERROR'];
const PAGE = 25;

const titleOf = (cats, id) => cats[id]?.title || (id?.startsWith('custom:') ? `Custom: ${id.slice(7).replace(/_/g,' ')}` : (id||'').replace(/_/g,' '));

/* ── Score block ─────────────────────────────────────────── */
function ScoreBlock({ summary, triaged, triagedCount }) {
  const score = summary.security_score ?? 0;
  const color = scoreColor(score);
  return (
    <div>
    <div style={{ display:'flex', alignItems:'flex-end', gap:'20px' }}>
      <div>
        <div style={{ fontFamily:'Georgia, serif', fontSize:'64px', lineHeight:1, color }}>{score}</div>
        <div style={{ fontSize:'12px', color:'var(--t3)' }}>Security score / 100</div>
      </div>
      <div>
        <div style={{ fontFamily:'Georgia, serif', fontSize:'34px', lineHeight:1, color }}>Grade {summary.grade || '—'}</div>
        <div style={{ fontSize:'12px', color:'var(--t3)' }}>{summary.tested ?? '—'} attacks graded</div>
      </div>
    </div>
    {triaged && (
      <div style={{ fontSize:'13px', marginTop:'10px' }}>
        After triage: <strong style={{ color: scoreColor(triaged.security_score) }}>{triaged.security_score} · grade {triaged.grade}</strong>
        <span style={{ color:'var(--t3)' }}> ({triagedCount} finding{triagedCount !== 1 ? 's' : ''} marked as false positive or accepted risk)</span>
      </div>
    )}
    </div>
  );
}

/* ── Finding card ────────────────────────────────────────── */
const TRIAGE_LABEL = { false_positive: 'False positive', accepted_risk: 'Accepted risk' };

function TriageMark({ mark }) {
  return (
    <span>Marked as <strong>{TRIAGE_LABEL[mark.status].toLowerCase()}</strong>{mark.decided_by ? ` by ${mark.decided_by}` : ''}
      {mark.note ? `: ${mark.note}` : ''}. It isn’t counted in the score after triage, re-tests or alerts for this target.</span>
  );
}

function TriageControls({ item, mark, onTriage }) {
  const [note, setNote] = useState(mark?.note || '');
  const [busy, setBusy] = useState(false);
  const set = async status => { setBusy(true); try { await onTriage(item.key, status, note); } finally { setBusy(false); } };
  if (mark) return (
    <div style={{ fontSize:'13px', display:'flex', gap:'10px', alignItems:'center', flexWrap:'wrap' }}>
      <TriageMark mark={mark} />
      <button className="btn-ghost" style={{ fontSize:'12px' }} disabled={busy} onClick={() => set('open')}>Reopen</button>
    </div>
  );
  return (
    <div style={{ display:'flex', gap:'8px', alignItems:'center', flexWrap:'wrap' }}>
      <input aria-label="Triage note (optional)" value={note} onChange={e => setNote(e.target.value)} maxLength={500}
        placeholder="Note (optional), e.g. the value is public" style={{ flex:'1 1 220px', minWidth:0, fontSize:'12px' }} />
      <button className="btn-outline" style={{ fontSize:'12px' }} disabled={busy} onClick={() => set('false_positive')}>False positive</button>
      <button className="btn-outline" style={{ fontSize:'12px' }} disabled={busy} onClick={() => set('accepted_risk')}>Accept risk</button>
    </div>
  );
}

function FindingCard({ item, cats, mark, onTriage }) {
  const [open, setOpen] = useState(false);
  const m = SEV_META[item.severity] || SEV_META.LOW;
  const failed = !['SAFE','ERROR'].includes(item.severity);
  return (
    <div style={{ borderBottom:'1px solid var(--b1)' }}>
      <button onClick={()=>setOpen(o=>!o)} aria-expanded={open}
        style={{ width:'100%', padding:'11px 4px', display:'flex', alignItems:'center', gap:'12px', background:'none', border:'none', cursor:'pointer', textAlign:'left', fontFamily:'inherit' }}>
        <span style={{ fontSize:'10px', fontWeight:'700', color:m.color, background:m.bg, borderRadius:'3px', padding:'2px 7px', letterSpacing:'0.5px', flexShrink:0, minWidth:'62px', textAlign:'center' }}>{m.label.toUpperCase()}</span>
        <span style={{ flex:1, minWidth:0 }}>
          <span style={{ display:'block', fontSize:'12px', color:'var(--t3)' }}>{titleOf(cats, item.category)}</span>
          <span style={{ display:'block', fontSize:'13px', color:'var(--t1)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{item.attack}</span>
        </span>
        {mark && <span style={{ fontSize:'11px', color:'var(--t3)', flexShrink:0 }}>{TRIAGE_LABEL[mark.status]}</span>}
        <span style={{ fontSize:'12px', color:'var(--t3)', fontVariantNumeric:'tabular-nums', flexShrink:0 }}>{item.score ?? 0}/10</span>
      </button>
      {open && (
        <div style={{ padding:'0 4px 14px', display:'grid', gap:'10px' }}>
          <Field label="Attack"><pre className="finding-pre" tabIndex={0}>{item.attack}</pre></Field>
          <Field label="Reply"><pre className="finding-pre" tabIndex={0}>{item.response || '(empty reply)'}</pre></Field>
          {item.reason && <Field label="Why"><div style={{ fontSize:'13px', color:'var(--t1)', lineHeight:1.6 }}>{item.reason}</div></Field>}
          {item.detectors?.length > 0 && (
            <Field label="Rule-based detection">
              <ul style={{ margin:0, paddingLeft:'18px', fontSize:'13px' }}>{item.detectors.map((d,i)=><li key={i}>{d.evidence}</li>)}</ul>
            </Field>
          )}
          {item.owasp?.length > 0 && <div style={{ fontSize:'12px', color:'var(--t3)' }}>OWASP LLM Top 10: {item.owasp.join(', ')}</div>}
          {failed && item.key && (onTriage ? (
            <Field label="Triage"><TriageControls item={item} mark={mark} onTriage={onTriage} /></Field>
          ) : mark && (
            <Field label="Triage"><div style={{ fontSize:'13px' }}><TriageMark mark={mark} /></div></Field>
          ))}
        </div>
      )}
    </div>
  );
}

function Field({ label, children }) {
  return (
    <div>
      <div style={{ fontSize:'10px', color:'var(--t3)', fontWeight:'700', textTransform:'uppercase', letterSpacing:'0.7px', marginBottom:'4px' }}>{label}</div>
      {children}
    </div>
  );
}

/* ── Recommendations (built by the backend from the failed categories) ── */
function Recommendations({ recs, triaged }) {
  if (!recs) return null;
  return (
    <div className="card-glow" style={{ padding:'22px 24px', marginTop:'16px' }}>
      <h2 style={{ fontSize:'15px', fontWeight:'700', marginBottom:'4px' }}>What to fix first</h2>
      {recs.length === 0 ? (
        <p style={{ fontSize:'13px', color:'var(--t3)' }}>
          {triaged ? 'Nothing left to fix: the attacks that succeeded are marked as false positives or accepted risks.'
            : 'No attack succeeded. Re-scan after every change to the system prompt or model.'}
        </p>
      ) : recs.map(r => (
        <div key={r.category} style={{ borderTop:'1px solid var(--b1)', padding:'14px 0' }}>
          <div style={{ display:'flex', gap:'10px', alignItems:'baseline', flexWrap:'wrap' }}>
            <span style={{ fontSize:'11px', fontWeight:'700', color: r.priority==='P1' ? '#b42318' : r.priority==='P2' ? '#a15c07' : 'var(--t3)', border:'1px solid currentColor', borderRadius:'3px', padding:'1px 6px' }}>{r.priority}</span>
            <span style={{ fontSize:'14px', fontWeight:'700' }}>{r.title}</span>
            <span style={{ fontSize:'12px', color:'var(--t3)' }}>{r.failed} failed · worst {r.worst.toLowerCase()}</span>
          </div>
          <div style={{ fontSize:'12px', color:'var(--t3)', margin:'4px 0' }}>{r.owasp.join(' · ')}</div>
          <ul style={{ margin:'4px 0 0', paddingLeft:'18px', fontSize:'13px', lineHeight:1.6 }}>{r.fix.map((tip,i)=><li key={i}>{tip}</li>)}</ul>
        </div>
      ))}
    </div>
  );
}

/* ── Fix it: hardened prompt + re-test the failed attacks ── */
function FixIt({ scan, failedCount }) {
  const toast = useToast();
  const navigate = useNavigate();
  const type = scan.config?.target_type || scan.target_type;
  // The scanner sends the prompt itself for these (an OpenAI-compatible target gets the stored one as its system message)
  const promptIsOurs = type === 'simulation' || type === 'groq' || (type === 'openai_compatible' && !!scan.config?.has_system_prompt);
  const needsPastedPrompt = !scan.config?.has_system_prompt && type !== 'simulation';
  // The scan's key was erased when it ended: ask again if it had one (older scans don't say)
  const hadKey = scan.config?.with_key ?? type === 'openai_compatible';
  const needsKey = (type === 'groq' || (hadKey && type !== 'simulation')) && !scan.target_id;
  const [pasted, setPasted] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [suggestion, setSuggestion] = useState(null);
  const [busy, setBusy] = useState('');

  if (!failedCount) return null;

  const suggest = async () => {
    if (needsPastedPrompt && !pasted.trim()) { toast('Paste your system prompt first.', 'error'); return; }
    setBusy('suggest');
    try {
      const { data } = await scansAPI.remediate(scan.scan_id, pasted.trim() ? { system_prompt: pasted.trim() } : {});
      setSuggestion(data);
    } catch (e) { toast(errorMessage(e, 'Could not suggest a prompt.'), 'error'); }
    finally { setBusy(''); }
  };

  const retest = async withPrompt => {
    if (needsKey && !apiKey.trim()) { toast('Enter the target’s API key to re-test it.', 'error'); return; }
    setBusy('retest');
    try {
      const body = {};
      if (withPrompt && suggestion) body.system_prompt = suggestion.hardened_prompt;
      if (apiKey.trim()) body.api_key = apiKey.trim();
      const { data } = await scansAPI.retest(scan.scan_id, body);
      toast(`Re-testing ${data.attacks} attacks.`, 'success');
      navigate(`/results/${data.scan_id}`);
    } catch (e) { toast(errorMessage(e, 'Could not start the re-test.'), 'error'); setBusy(''); }
  };

  return (
    <div className="card-glow" style={{ padding:'22px 24px', marginTop:'16px' }}>
      <h2 style={{ fontSize:'15px', fontWeight:'700', marginBottom:'4px' }}>Fix it</h2>
      <p style={{ fontSize:'13px', color:'var(--t3)', marginBottom:'14px' }}>
        Get a hardened system prompt written from these {failedCount} failed attacks, then re-run only those attacks to check the fix (a re-test counts as one scan).
      </p>
      {needsPastedPrompt && !suggestion && (
        <div className="form-group">
          <label htmlFor="res-your-system-prompt">Your system prompt</label>
          <textarea id="res-your-system-prompt" value={pasted} onChange={e => setPasted(e.target.value)} maxLength={20000} style={{ minHeight:'80px' }}
            placeholder="This target’s prompt wasn’t stored with the scan. Paste it here." />
        </div>
      )}
      {needsKey && (
        <div className="form-group">
          <label htmlFor="res-target-api-key">Target API key (needed to re-test)</label>
          <input id="res-target-api-key" type="password" autoComplete="off" value={apiKey} onChange={e => setApiKey(e.target.value)} />
        </div>
      )}
      <div style={{ display:'flex', gap:'8px', flexWrap:'wrap' }}>
        {!suggestion && (
          <button className="btn-primary" disabled={!!busy} onClick={suggest}>
            {busy === 'suggest' ? 'Writing a hardened prompt…' : 'Suggest a hardened system prompt'}
          </button>
        )}
        <button className="btn-outline" disabled={!!busy} onClick={() => retest(false)}>
          {busy === 'retest' ? 'Starting…' : `Re-test the ${failedCount} failed attacks`}
        </button>
        {suggestion && promptIsOurs && (
          <button className="btn-primary" disabled={!!busy} onClick={() => retest(true)}>Re-test with the hardened prompt</button>
        )}
      </div>
      {suggestion && (
        <div style={{ marginTop:'16px', display:'grid', gap:'12px' }}>
          {suggestion.remove_from_prompt?.length > 0 && (
            <div style={{ fontSize:'13px', color:'#b42318' }}>
              Remove from any prompt: {suggestion.remove_from_prompt.join(', ')}
            </div>
          )}
          <Field label="Hardened system prompt">
            <pre className="finding-pre" style={{ maxHeight:'none' }}>{suggestion.hardened_prompt}</pre>
          </Field>
          <div>
            <button className="btn-ghost" style={{ fontSize:'12px' }}
              onClick={() => { navigator.clipboard?.writeText(suggestion.hardened_prompt); toast('Copied.', 'success', 1500); }}>
              Copy prompt
            </button>
          </div>
          {suggestion.changes?.length > 0 && (
            <Field label="What changed in the prompt">
              <ul style={{ margin:0, paddingLeft:'18px', fontSize:'13px', lineHeight:1.6 }}>{suggestion.changes.map((c, i) => <li key={i}>{c}</li>)}</ul>
            </Field>
          )}
          {suggestion.app_changes?.length > 0 && (
            <Field label="Also change in your application">
              <ul style={{ margin:0, paddingLeft:'18px', fontSize:'13px', lineHeight:1.6 }}>{suggestion.app_changes.map((c, i) => <li key={i}>{c}</li>)}</ul>
            </Field>
          )}
          {!promptIsOurs && (
            <p style={{ fontSize:'12px', color:'var(--t3)' }}>Deploy the new prompt in your application, then re-test the failed attacks.</p>
          )}
        </div>
      )}
    </div>
  );
}

/* ── Category table ──────────────────────────────────────── */
function CategoryTable({ results, cats }) {
  const rows = useMemo(() => {
    const by = {};
    results.forEach(r => {
      const row = by[r.category] || (by[r.category] = { id:r.category, attacks:0, failed:0 });
      row.attacks += 1;
      if (r.severity !== 'SAFE' && r.severity !== 'ERROR') row.failed += 1;
    });
    return Object.values(by).sort((a,b)=>b.failed/b.attacks - a.failed/a.attacks);
  }, [results]);
  return (
    <div style={{ display:'grid', gap:'7px' }}>
      {rows.map(r => {
        const share = r.attacks ? r.failed / r.attacks : 0;
        return (
          <div key={r.id} style={{ display:'grid', gridTemplateColumns:'minmax(120px,190px) 1fr 52px', gap:'10px', alignItems:'center' }}>
            <span style={{ fontSize:'12px', color:'var(--t2)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{titleOf(cats, r.id)}</span>
            <span style={{ height:'6px', background:'var(--b1)', borderRadius:'3px', overflow:'hidden' }}>
              <span style={{ display:'block', width:`${Math.max(share*100, r.failed?3:0)}%`, height:'100%', background: r.failed ? '#b42318' : 'transparent' }} />
            </span>
            <span style={{ fontSize:'12px', color:'var(--t3)', textAlign:'right', fontVariantNumeric:'tabular-nums' }}>{r.failed}/{r.attacks}</span>
          </div>
        );
      })}
    </div>
  );
}

/* ── Running / queued ────────────────────────────────────── */
// Scan emails go to whoever started the scan (a team member, or the account owner)
const startedBy = (scan, user) => (scan.created_by ? scan.created_by === user?.id : scan.user_id === user?.id);

function RunningState({ scan, cats, onCancel, cancelling, emailed }) {
  const queued = scan.status === 'pending';
  const done = scan.completed_attacks || 0;
  const total = scan.total_attacks || 0;
  const pct = queued ? 0 : (scan.progress || 0);
  return (
    <div style={{ maxWidth:'560px', margin:'56px auto' }}>
      <div style={{ marginBottom:'24px' }}>
        <div style={{ fontSize:'12px', letterSpacing:'0.12em', textTransform:'uppercase', color:'var(--t3)' }}>{queued ? 'Queued' : 'Scanning'}</div>
        <h2 style={{ fontFamily:'Georgia, serif', fontSize:'28px', fontWeight:600, margin:'6px 0' }}>{scan.target_name}</h2>
        <p style={{ color:'var(--t3)', fontSize:'14px' }}>
          {queued ? 'Waiting for a free scanner slot. It starts automatically.'
                  : `${done} of ${total} attacks done${scan.current_category ? ` · now: ${titleOf(cats, scan.current_category)}` : ''}`}
        </p>
      </div>
      <div className="card-glow" style={{ padding:'22px 24px' }}>
        <div style={{ display:'flex', justifyContent:'space-between', fontSize:'13px', marginBottom:'8px' }}>
          <span style={{ fontWeight:600 }}>Progress</span>
          <span style={{ fontVariantNumeric:'tabular-nums' }}>{pct}%</span>
        </div>
        <div style={{ height:'8px', background:'var(--b1)', borderRadius:'4px', overflow:'hidden' }}>
          <div style={{ height:'100%', width:`${pct}%`, background:'var(--t1)', transition:'width 0.8s ease' }} />
        </div>
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginTop:'16px', fontSize:'12px', color:'var(--t3)' }}>
          <span>This page updates by itself. You can leave it{emailed ? '; we’ll email you when it’s done' : ': the report will be in Reports'}.</span>
          {onCancel && (
            <button className="btn-outline" style={{ padding:'5px 12px', fontSize:'12px' }} onClick={onCancel} disabled={cancelling}>
              {cancelling ? 'Cancelling…' : 'Cancel scan'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

/* ── Comparison with the previous scan of this target ───── */
function PreviousComparison({ scan }) {
  const [diff, setDiff] = useState(null);
  const navigate = useNavigate();
  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const { data } = await scansAPI.list({ target_name: scan.target_name, status: 'complete', limit: 10 });
        const older = data.scans.find(s => s.scan_id !== scan.scan_id && s.created_at < scan.created_at);
        if (!older) return;
        const res = await scansAPI.compare(older.scan_id, scan.scan_id);
        if (alive) setDiff({ ...res.data, previous: older });
      } catch { /* comparison is optional */ }
    })();
    return () => { alive = false; };
  }, [scan.scan_id, scan.target_name, scan.created_at]);
  if (!diff) return null;
  const delta = diff.score_delta;
  const triagedDelta = diff.score_delta_after_triage;      // null when nothing on these targets is triaged
  const comparable = diff.same_attacks !== false;
  const points = d => `${d > 0 ? '+' : '−'}${Math.abs(d)} point${Math.abs(d) !== 1 ? 's' : ''}`;
  return (
    <div className="card-glow" style={{ padding:'14px 18px', marginBottom:'16px', display:'flex', gap:'18px', alignItems:'center', flexWrap:'wrap', fontSize:'13px' }}>
      <span style={{ fontWeight:700 }}>Since the previous scan</span>
      {comparable ? (
        <span style={{ color: delta > 0 ? '#15803d' : delta < 0 ? '#b42318' : 'var(--t3)', fontWeight:700 }}>
          {delta === 0 ? 'Score unchanged' : points(delta)}
          {triagedDelta != null && triagedDelta !== delta && (
            <span style={{ color:'var(--t3)', fontWeight:400 }}>
              {' '}({triagedDelta === 0 ? 'unchanged' : points(triagedDelta)} after triage)
            </span>
          )}
        </span>
      ) : (
        <span style={{ color:'var(--t3)' }} title="The score depends on which attacks ran, so it's only compared between scans of the same attacks.">
          Different attacks ({fmtNum(diff.head_tested)} vs {fmtNum(diff.base_tested)}), so scores aren’t compared
        </span>
      )}
      <span>{diff.resolved_count} fixed</span>
      {!comparable && <span>{diff.still_failing_count} still failing</span>}
      <span>{diff.introduced_count} new failure{diff.introduced_count!==1?'s':''}</span>
      <button className="btn-ghost" style={{ fontSize:'12px', marginLeft:'auto' }} onClick={()=>navigate(`/results/${diff.previous.scan_id}`)}>Open previous scan →</button>
    </div>
  );
}

/* ── Main Results page ───────────────────────────────────── */
export default function Results() {
  const { id } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const { user, canEdit } = useAuth();      // viewers read the scan and download reports; they can't change it
  const confirm = useConfirm();
  const [scan,      setScan]      = useState(null);
  const [loading,   setLoading]   = useState(true);
  const [notFound,  setNotFound]  = useState(false);
  const [sevFilter, setSevFilter] = useState('FAILED');
  const [shown,     setShown]     = useState(PAGE);
  const [cats,      setCats]      = useState({});
  const [busy,      setBusy]      = useState('');
  const [cancelled, setCancelled] = useState('');      // the scan id asked to stop, until its status says so

  const fetchScan = useCallback(async () => {
    try {
      const r = await scansAPI.get(id);
      setScan(r.data);
      setNotFound(false);
    } catch (e) {
      if (e.response?.status === 404) setNotFound(true);
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { setLoading(true); fetchScan(); }, [fetchScan]);
  usePolling(fetchScan, 3000, isActive(scan));
  useEffect(() => {
    scansAPI.categories().then(r => setCats(Object.fromEntries(r.data.categories.map(c => [c.id, c])))).catch(() => {});
  }, []);

  const results = useMemo(() => scan?.results?.results || [], [scan]);
  const triage = useMemo(() => scan?.triage || {}, [scan]);
  const isTriaged = useCallback(r => !!(r.key && triage[r.key]), [triage]);
  const counts = useMemo(() => {
    const c = { ALL: results.length, FAILED: 0, TRIAGED: 0 };
    SEV_ORDER.forEach(s => { c[s] = 0; });
    results.forEach(r => {
      c[r.severity] = (c[r.severity] || 0) + 1;
      if (isTriaged(r)) c.TRIAGED += 1;
      else if (!['SAFE','ERROR'].includes(r.severity)) c.FAILED += 1;
    });
    return c;
  }, [results, isTriaged]);
  const visible = useMemo(() => {
    const rank = Object.fromEntries(SEV_ORDER.map((s,i)=>[s,i]));
    const list = sevFilter === 'ALL' ? results
      : sevFilter === 'FAILED' ? results.filter(r => !['SAFE','ERROR'].includes(r.severity) && !isTriaged(r))
      : sevFilter === 'TRIAGED' ? results.filter(isTriaged)
      : results.filter(r => r.severity === sevFilter);
    return [...list].sort((a,b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9) || (b.score||0) - (a.score||0));
  }, [results, sevFilter, isTriaged]);
  const onTriage = async (key, status, note) => {
    try {
      await scansAPI.triage(id, key, status, note?.trim() || undefined);
      toast(status === 'open' ? 'Finding reopened.' : 'Marked. Re-tests and alerts for this target leave it out.', 'success');
      fetchScan();
    } catch (e) { toast(errorMessage(e, 'Could not save the triage.'), 'error'); }
  };

  const download = async format => {
    setBusy(format);
    try { await downloadReport(id, format); }
    catch (e) { toast(errorMessage(e, 'Download failed.'), 'error'); }
    finally { setBusy(''); }
  };

  const share = async () => {
    setBusy('share');
    try {
      const { data } = await scansAPI.share(id, 7);
      await navigator.clipboard?.writeText(data.url);
      toast('Read-only link copied. It expires in 7 days.', 'success', 5000);
      setScan(s => ({ ...s, shared_until: data.expires_at }));
    } catch (e) { toast(errorMessage(e, 'Could not create a share link.'), 'error'); }
    finally { setBusy(''); }
  };

  const unshare = async () => {
    setBusy('unshare');
    try {
      await scansAPI.unshare(id);
      setScan(s => ({ ...s, shared_until: null }));
      toast('Sharing stopped. The old link no longer works.', 'success');
    } catch (e) { toast(errorMessage(e, 'Could not stop sharing.'), 'error'); }
    finally { setBusy(''); }
  };

  const cancel = async () => {
    setCancelled(id);
    try { await scansAPI.cancel(id); toast('Cancelling scan…', 'info'); fetchScan(); }
    catch (e) { setCancelled(''); toast(errorMessage(e), 'error'); }
  };

  const remove = async () => {
    if (!(await confirm({ title: 'Delete this scan?', confirmLabel: 'Delete scan',
      body: 'Its findings and reports are deleted too. This can’t be undone.' }))) return;
    try { await scansAPI.delete(id); toast('Scan deleted.', 'success'); navigate('/'); }
    catch (e) { toast(errorMessage(e), 'error'); }
  };

  if (loading) return (
    <div style={{ display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', padding:'100px', gap:'14px' }}>
      <div className="spinner" style={{ width:'24px', height:'24px' }} />
      <span style={{ color:'var(--t3)', fontSize:'14px' }}>Loading scan…</span>
    </div>
  );
  if (notFound || !scan) return (
    <div className="empty-state" style={{ padding:'100px 40px' }}>
      <h3>{notFound ? 'Scan not found' : 'Couldn’t load this scan'}</h3>
      <p>{notFound ? 'This scan may have been deleted, or the link is wrong.' : 'Check your connection; the server may be waking up.'}</p>
      <button className="btn-primary" onClick={()=> notFound ? navigate('/') : fetchScan()}>{notFound ? 'Back to Dashboard' : 'Retry'}</button>
    </div>
  );
  if (isActive(scan)) return <RunningState scan={scan} cats={cats} onCancel={canEdit ? cancel : null} cancelling={cancelled === id} emailed={!!user?.scan_emails && startedBy(scan, user)} />;
  if (scan.status === 'failed' || scan.status === 'cancelled') return (
    <div>
      <div className="empty-state" style={{ padding: scan.partial ? '56px 40px 28px' : '100px 40px' }}>
        <h3 style={{ color: scan.status === 'failed' ? '#b42318' : 'var(--t1)' }}>
          {scan.status === 'failed' ? 'Scan failed' : 'Scan cancelled'}: {scan.target_name}
        </h3>
        <p style={{ maxWidth:'520px', margin:'8px auto 20px' }}>
          {scan.status === 'cancelled'
            ? `Stopped after ${fmtNum(scan.completed_attacks || 0)} of ${fmtNum(scan.total_attacks || 0)} attacks.`
            : scan.error_message || 'The scan stopped before it finished.'}
        </p>
        {canEdit && (
          <div style={{ display:'flex', gap:'8px', justifyContent:'center' }}>
            <button className="btn-primary" onClick={()=>navigate(scan.target_id ? `/new-scan?target=${scan.target_id}` : '/new-scan')}>
              {scan.target_id ? 'Scan this target again' : 'Start a new scan'}
            </button>
            <button className="btn-outline" onClick={remove}>Delete</button>
          </div>
        )}
      </div>
      {scan.partial && (
        <div className="card-glow" style={{ maxWidth:'860px', margin:'0 auto', overflow:'hidden' }}>
          <div style={{ padding:'16px 20px', borderBottom:'1px solid var(--b1)' }}>
            <h2 style={{ fontSize:'15px', fontWeight:'700' }}>Found before it stopped</h2>
            <p style={{ fontSize:'12px', color:'var(--t3)', marginTop:'2px' }}>
              {fmtNum(scan.partial.graded)} attack{scan.partial.graded !== 1 ? 's were' : ' was'} graded;{' '}
              {scan.partial.failed_count ? `${fmtNum(scan.partial.failed_count)} succeeded` : 'none succeeded'}.
              This isn’t a full scan, so it has no score: run it again for the complete report.
            </p>
          </div>
          <div style={{ padding:'4px 20px 14px' }}>
            {scan.partial.failed.length === 0
              ? <p style={{ fontSize:'13px', color:'var(--t3)', padding:'14px 0' }}>No attack succeeded in that part of the scan.</p>
              : scan.partial.failed.slice(0, shown).map((item, i) => <FindingCard key={`${item.category}-${i}`} item={item} cats={cats} mark={null} onTriage={null} />)}
            {scan.partial.failed.length > shown && (
              <button className="btn-outline" style={{ width:'100%', marginTop:'12px' }} onClick={()=>setShown(n => n + PAGE)}>
                Show {Math.min(PAGE, scan.partial.failed.length - shown)} more of {scan.partial.failed.length - shown} remaining
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );

  const summary = { ...(scan.summary || {}), ...(scan.results?.summary || {}) };

  return (
    <div>
      {/* ── Header ───────────────────────────── */}
      <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', marginBottom:'20px', gap:'16px', flexWrap:'wrap' }}>
        <div style={{ minWidth:0, flex:'1 1 280px' }}>
          <button onClick={()=>navigate('/')} className="btn-ghost" style={{ fontSize:'12px', padding:0, marginBottom:'8px' }}>← Dashboard</button>
          <h1 className="page-title" style={{ marginBottom:'4px' }}>{scan.target_name}</h1>
          <p style={{ fontSize:'13px', color:'var(--t3)', margin:0 }}>
            {new Date(scan.created_at).toLocaleString('en-US',{ dateStyle:'long', timeStyle:'short' })}
            {scan.duration_seconds ? ` · took ${formatDuration(scan.duration_seconds)}` : ''}
            {scan.config?.target_type ? ` · ${typeLabel(scan.config.target_type)}` : ''}
            {scan.config?.model ? ` · ${scan.config.model}` : ''}
            {scan.config?.quick ? ' · quick scan' : ''}
            {scan.created_by_name ? ` · started by ${scan.created_by_name}` : ''}
          </p>
        </div>
        <div style={{ display:'flex', gap:'8px', flexWrap:'wrap' }}>
          <button className="btn-primary" disabled={!!busy} onClick={()=>download('pdf')}>{busy==='pdf' ? 'Preparing…' : 'Download PDF'}</button>
          <button className="btn-outline" disabled={!!busy} onClick={()=>download('html')}>HTML</button>
          <button className="btn-outline" disabled={!!busy} onClick={()=>download('md')}>Markdown</button>
          <button className="btn-outline" disabled={!!busy} onClick={()=>download('json')}>JSON</button>
          <button className="btn-outline" disabled={!!busy} onClick={()=>download('evidence')}
            title="Testing evidence for audits and security reviews: scope, method, OWASP coverage, triage, re-tests, sign-off">
            {busy==='evidence' ? 'Preparing…' : 'Evidence report'}
          </button>
          {canEdit && <>
            <button className="btn-outline" disabled={!!busy} onClick={share}>{busy==='share' ? 'Creating…' : scan.shared_until ? 'New share link' : 'Share link'}</button>
            <button className="btn-ghost" onClick={remove}>Delete</button>
          </>}
          {scan.shared_until && (
            <span style={{ flexBasis:'100%', fontSize:'12px', color:'var(--t3)', textAlign:'right' }}>
              Shared read-only until {shortDate(scan.shared_until, true)}
              {canEdit && <>{' · '}
                <button className="btn-ghost" style={{ fontSize:'12px', padding:0 }} disabled={!!busy} onClick={unshare}>
                  {busy==='unshare' ? 'Stopping…' : 'Stop sharing'}
                </button>
              </>}
            </span>
          )}
        </div>
      </div>

      <PreviousComparison scan={scan} />

      {/* ── Summary ──────────────────────────── */}
      <div className="results-hero results-summary">
        <div>
          <ScoreBlock summary={summary} triaged={scan.triaged_summary} triagedCount={Object.keys(scan.triage || {}).length} />
          <div style={{ display:'flex', gap:'18px', marginTop:'22px', flexWrap:'wrap' }}>
            {['critical','high','medium','low','safe'].map(k => (
              <div key={k}>
                <div style={{ fontFamily:'Georgia, serif', fontSize:'24px', color: SEV_META[k.toUpperCase()].color }}>{summary[k] ?? 0}</div>
                <div style={{ fontSize:'11px', color:'var(--t3)', textTransform:'capitalize' }}>{k}</div>
              </div>
            ))}
          </div>
          {summary.errors > 0 && (
            <p style={{ fontSize:'12px', color:'#a15c07', marginTop:'14px' }}>
              {summary.errors} attack{summary.errors!==1?'s':''} couldn’t be completed and {summary.errors!==1?'aren’t':'isn’t'} counted in the score.
            </p>
          )}
          <p style={{ fontSize:'12px', color:'var(--t3)', marginTop:'14px', lineHeight:1.5 }}>
            Any critical finding caps the score at 49, any high at 69, any medium at 89.
          </p>
        </div>
        <div>
          <div style={{ fontSize:'10px', fontWeight:'700', textTransform:'uppercase', letterSpacing:'0.9px', color:'var(--t3)', marginBottom:'10px' }}>Failed attacks by category</div>
          <CategoryTable results={results} cats={cats} />
        </div>
      </div>

      <Recommendations recs={scan.recommendations} triaged={Object.keys(scan.triage || {}).length > 0} />
      {canEdit && <FixIt scan={scan} failedCount={counts.FAILED} />}

      {/* ── Findings ─────────────────────────── */}
      <div className="card-glow" style={{ overflow:'hidden', marginTop:'16px' }}>
        <div style={{ padding:'16px 20px', borderBottom:'1px solid var(--b1)', display:'flex', alignItems:'center', justifyContent:'space-between', gap:'12px', flexWrap:'wrap' }}>
          <span style={{ fontSize:'15px', fontWeight:'700' }}>Findings</span>
          <div style={{ display:'flex', gap:'4px', flexWrap:'wrap' }}>
            {['FAILED','ALL',...SEV_ORDER,'TRIAGED'].map(sev => {
              if (!['FAILED','ALL'].includes(sev) && !counts[sev]) return null;
              const label = sev === 'FAILED' ? 'Failed' : sev === 'ALL' ? 'All' : sev === 'TRIAGED' ? 'Triaged' : SEV_META[sev].label;
              return (
                <button key={sev} className={`filter-btn${sevFilter===sev?' active':''}`} style={{ padding:'4px 11px', fontSize:'11px' }}
                  onClick={()=>{ setSevFilter(sev); setShown(PAGE); }}>
                  {label} ({counts[sev] || 0})
                </button>
              );
            })}
          </div>
        </div>
        <div style={{ padding:'4px 20px 14px' }}>
          {visible.length === 0 ? (
            <p style={{ fontSize:'13px', color:'var(--t3)', padding:'18px 0' }}>
              {sevFilter !== 'FAILED' ? 'Nothing to show for this filter.'
                : counts.TRIAGED ? 'Every attack that succeeded is marked as a false positive or an accepted risk: see Triaged.'
                : 'No attack succeeded against this target.'}
            </p>
          ) : visible.slice(0, shown).map((item, i) => (
            <FindingCard key={item.key || `${item.category}-${i}-${item.attack.slice(0,20)}`} item={item} cats={cats}
              mark={item.key ? triage[item.key] : null} onTriage={canEdit ? onTriage : null} />
          ))}
          {visible.length > shown && (
            <button className="btn-outline" style={{ width:'100%', marginTop:'12px' }} onClick={()=>setShown(n => n + PAGE)}>
              Show {Math.min(PAGE, visible.length - shown)} more of {visible.length - shown} remaining
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
