import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { scansAPI, API_URL } from '../services/api';

const SEV_META = {
  CRITICAL: { color:'#dc2626', bg:'rgba(248,113,113,0.12)', border:'rgba(248,113,113,0.25)', label:'Critical' },
  HIGH:     { color:'#ea580c', bg:'rgba(251,146,60,0.12)',  border:'rgba(251,146,60,0.25)',  label:'High'     },
  MEDIUM:   { color:'#b45309', bg:'rgba(250,204,21,0.10)',  border:'rgba(250,204,21,0.25)',  label:'Medium'   },
  LOW:      { color:'#16a34a', bg:'rgba(74,222,128,0.10)',  border:'rgba(74,222,128,0.25)',  label:'Low'      },
};
const SEV_ORDER = ['CRITICAL','HIGH','MEDIUM','LOW'];

/* ── Animated SVG score ring ─────────────────────────────── */
function ScoreRing({ score }) {
  const R = 54, CIRC = 2 * Math.PI * R;
  const color = score >= 70 ? '#16a34a' : score >= 40 ? '#b45309' : '#dc2626';
  const label = score >= 85 ? 'Excellent' : score >= 70 ? 'Low Risk' : score >= 40 ? 'Moderate' : 'High Risk';
  return (
    <div style={{ position:'relative', width:'148px', height:'148px', flexShrink:0 }}>
      {/* Outer glow ring */}
      <div style={{ position:'absolute', inset:'-6px', borderRadius:'50%', background:`radial-gradient(circle, ${color}15 0%, transparent 70%)`, pointerEvents:'none' }} />
      <svg width="148" height="148" viewBox="0 0 148 148" style={{ transform:'rotate(-90deg)' }}>
        <circle cx="74" cy="74" r={R} fill="none" stroke="rgba(17,24,39,0.04)" strokeWidth="10" />
        <circle cx="74" cy="74" r={R} fill="none" stroke="rgba(17,24,39,0.06)" strokeWidth="10"
          strokeDasharray={`${(score/100)*CIRC} ${CIRC}`} style={{ transition:'none' }} />
        <circle cx="74" cy="74" r={R} fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={`${(score/100)*CIRC} ${CIRC}`}
          style={{ transition:'stroke-dasharray 1.6s cubic-bezier(.4,0,.2,1)', filter:`drop-shadow(0 0 14px ${color}70)` }} />
      </svg>
      <div style={{ position:'absolute', inset:0, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', gap:'2px' }}>
        <span style={{ fontSize:'38px', fontWeight:'900', letterSpacing:'-2.5px', lineHeight:1, color }}>{score}</span>
        <span style={{ fontSize:'9px', color:'var(--t3)', fontWeight:'700', textTransform:'uppercase', letterSpacing:'1px' }}>/ 100</span>
        <span style={{ fontSize:'10px', fontWeight:'700', color, letterSpacing:'0.2px', marginTop:'2px' }}>{label}</span>
      </div>
    </div>
  );
}

/* ── Mini score bar ──────────────────────────────────────── */
function SevBadge({ sev, count }) {
  const m = SEV_META[sev];
  if (!m || !count) return null;
  return (
    <div style={{ background:m.bg, border:`1px solid ${m.border}`, borderRadius:'10px', padding:'8px 14px', textAlign:'center', minWidth:'56px' }}>
      <div style={{ fontSize:'18px', fontWeight:'900', color:m.color, letterSpacing:'-0.5px', lineHeight:1 }}>{count}</div>
      <div style={{ fontSize:'9px', color:m.color, opacity:0.7, textTransform:'uppercase', letterSpacing:'0.5px', marginTop:'3px' }}>{m.label}</div>
    </div>
  );
}

/* ── Category breakdown chart ────────────────────────────── */
function CategoryChart({ results }) {
  const counts = {};
  results.forEach(r => {
    const c = (r.category||'unknown').replace(/_/g,' ');
    counts[c] = (counts[c]||0)+1;
  });
  const sorted = Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,8);
  const max = sorted[0]?.[1] || 1;
  const COLORS = ['#dc2626','#ea580c','#b45309','#16a34a','#2563eb','#6366f1','#2dd4bf','#e879f9'];
  return (
    <div style={{ display:'flex', flexDirection:'column', gap:'8px' }}>
      {sorted.map(([cat,cnt],i)=>(
        <div key={cat} style={{ display:'flex', alignItems:'center', gap:'10px' }}>
          <div style={{ width:'8px', height:'8px', borderRadius:'2px', background:COLORS[i%8], flexShrink:0 }} />
          <div style={{ fontSize:'11px', color:'var(--t2)', fontWeight:'500', width:'130px', flexShrink:0, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', textTransform:'capitalize' }}>{cat}</div>
          <div style={{ flex:1, height:'4px', background:'rgba(17,24,39,0.05)', borderRadius:'2px', overflow:'hidden' }}>
            <div style={{ width:`${(cnt/max)*100}%`, height:'100%', background:COLORS[i%8], borderRadius:'2px', transition:'width 0.8s cubic-bezier(.4,0,.2,1)', boxShadow:`0 0 6px ${COLORS[i%8]}60` }} />
          </div>
          <div style={{ fontSize:'12px', fontWeight:'700', color:'var(--t2)', width:'22px', textAlign:'right', flexShrink:0 }}>{cnt}</div>
        </div>
      ))}
    </div>
  );
}

/* ── Finding card ────────────────────────────────────────── */
function FindingCard({ item, index }) {
  const [open, setOpen] = useState(index === 0);
  const m = SEV_META[item.severity] || SEV_META.LOW;
  const score = item.score ?? 0;
  return (
    <div style={{
      background:'var(--s2)', borderRadius:'10px', overflow:'hidden',
      border:`1px solid var(--b1)`,
      borderLeft:`3px solid ${m.color}`,
      transition:'border-color 0.2s, box-shadow 0.2s',
    }}
      onMouseEnter={e=>e.currentTarget.style.boxShadow=`0 0 0 1px ${m.color}20, 0 4px 16px rgba(0,0,0,0.3)`}
      onMouseLeave={e=>e.currentTarget.style.boxShadow='none'}
    >
      <button onClick={()=>setOpen(o=>!o)} style={{ width:'100%', padding:'12px 14px 12px 16px', display:'flex', alignItems:'center', gap:'12px', background:'none', border:'none', cursor:'pointer', textAlign:'left' }}>
        <div style={{ flex:1, minWidth:0 }}>
          <div style={{ display:'flex', alignItems:'center', gap:'8px', marginBottom:'3px' }}>
            <span style={{ fontSize:'10px', fontWeight:'700', color:m.color, background:m.bg, border:`1px solid ${m.border}`, borderRadius:'4px', padding:'1px 7px', textTransform:'uppercase', letterSpacing:'0.5px', flexShrink:0 }}>
              {m.label}
            </span>
            <span style={{ fontSize:'11px', color:'var(--t3)', fontWeight:'600', textTransform:'uppercase', letterSpacing:'0.5px', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
              {item.category?.replace(/_/g,' ')}
            </span>
          </div>
          <div style={{ fontSize:'13px', color:'var(--t1)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
            {item.attack?.substring(0,110)}{item.attack?.length > 110 ? '…' : ''}
          </div>
        </div>
        <div style={{ display:'flex', alignItems:'center', gap:'8px', flexShrink:0 }}>
          <div style={{ display:'flex', alignItems:'center', gap:'4px' }}>
            <div style={{ width:'32px', height:'3px', background:'rgba(17,24,39,0.07)', borderRadius:'2px', overflow:'hidden' }}>
              <div style={{ width:`${score*10}%`, height:'100%', background:m.color, borderRadius:'2px' }} />
            </div>
            <span style={{ fontSize:'11px', fontWeight:'800', color:m.color }}>{score}/10</span>
          </div>
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none" style={{ transform:open?'rotate(180deg)':'none', transition:'transform 0.2s', color:'var(--t3)', flexShrink:0 }}>
            <path d="M2 4l4 4 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
          </svg>
        </div>
      </button>

      {open && (
        <div style={{ padding:'0 14px 14px 16px', borderTop:'1px solid var(--b1)' }}>
          <div style={{ paddingTop:'12px', display:'flex', flexDirection:'column', gap:'10px' }}>
            <div>
              <div style={{ fontSize:'10px', color:'var(--t3)', fontWeight:'700', textTransform:'uppercase', letterSpacing:'0.7px', marginBottom:'5px', display:'flex', alignItems:'center', gap:'6px' }}>
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
                Attack Prompt
              </div>
              <div style={{ fontSize:'12px', color:'var(--t2)', fontFamily:'monospace', background:'var(--s3)', border:`1px solid var(--b1)`, borderRadius:'7px', padding:'10px 14px', lineHeight:'1.65', wordBreak:'break-word', whiteSpace:'pre-wrap' }}>
                {item.attack}
              </div>
            </div>
            {item.reason && (
              <div>
                <div style={{ fontSize:'10px', color:'var(--t3)', fontWeight:'700', textTransform:'uppercase', letterSpacing:'0.7px', marginBottom:'5px', display:'flex', alignItems:'center', gap:'6px' }}>
                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                  Analysis
                </div>
                <div style={{ fontSize:'13px', color:'var(--t1)', lineHeight:'1.7', background:'var(--s3)', borderRadius:'7px', padding:'10px 14px', border:`1px solid ${m.color}20` }}>
                  {item.reason}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Recommendations ─────────────────────────────────────── */
function Recommendations({ score, summary }) {
  const recs = [];
  if ((summary.critical||0)>0)
    recs.push({ icon:'🚨', priority:'P1', title:'Patch critical prompt injections', body:'Your AI can be fully hijacked. Add strict output validation and input sanitization before any production use.', color:'#dc2626' });
  if ((summary.high||0)>0)
    recs.push({ icon:'⚠️', priority:'P2', title:'Harden against role-play bypasses', body:'High-severity findings stem from weak persona anchoring. Use layered instructions and deny-list known jailbreak phrases.', color:'#ea580c' });
  if (score < 70)
    recs.push({ icon:'🔐', priority:'P2', title:'Add output classifiers', body:'Deploy a secondary LLM or regex classifier to evaluate responses before serving to end users.', color:'#b45309' });
  recs.push({ icon:'📅', priority:'P3', title:'Schedule regular re-scans', body:'AI models drift over time. Re-scan monthly or after every model update to catch regressions.', color:'var(--blue)' });
  if (score>=85)
    recs.push({ icon:'✅', priority:'P3', title:'Maintain excellent posture', body:'Strong resistance detected. Continue with automated weekly scans and red-team exercises.', color:'#16a34a' });
  return (
    <div className="card-glow" style={{ padding:'22px 24px', marginTop:'20px' }}>
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:'16px' }}>
        <div style={{ fontSize:'14px', fontWeight:'700', color:'var(--t1)', letterSpacing:'-0.2px' }}>Recommendations</div>
        <span style={{ fontSize:'11px', color:'var(--t3)' }}>{recs.length} action{recs.length!==1?'s':''}</span>
      </div>
      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:'10px' }}>
        {recs.slice(0,4).map((r,i)=>(
          <div key={i} style={{ background:'var(--s2)', border:`1px solid var(--b1)`, borderRadius:'12px', padding:'14px 16px', display:'flex', gap:'12px', alignItems:'flex-start', position:'relative', overflow:'hidden', transition:'border-color 0.2s' }}
            onMouseEnter={e=>e.currentTarget.style.borderColor='var(--b2)'}
            onMouseLeave={e=>e.currentTarget.style.borderColor='var(--b1)'}
          >
            <div style={{ position:'absolute', top:0, left:0, right:0, height:'2px', background:`linear-gradient(90deg,${r.color}70,transparent)` }} />
            <div style={{ fontSize:'17px', flexShrink:0, marginTop:'1px' }}>{r.icon}</div>
            <div style={{ minWidth:0 }}>
              <div style={{ display:'flex', alignItems:'center', gap:'6px', marginBottom:'4px' }}>
                <span style={{ fontSize:'9px', fontWeight:'800', color:r.color, background:`${r.color}18`, border:`1px solid ${r.color}30`, borderRadius:'4px', padding:'1px 6px', letterSpacing:'0.3px' }}>{r.priority}</span>
                <span style={{ fontSize:'12px', fontWeight:'700', color:'var(--t1)' }}>{r.title}</span>
              </div>
              <div style={{ fontSize:'12px', color:'var(--t3)', lineHeight:'1.55' }}>{r.body}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Running state ───────────────────────────────────────── */
function RunningState({ scan }) {
  const [dots, setDots] = useState(1);
  const [prog, setProg] = useState(0);
  useEffect(() => {
    const t1 = setInterval(()=>setDots(d=>d%3+1), 600);
    const t2 = setInterval(()=>setProg(p=>Math.min(p+0.35, 88)), 900);
    return ()=>{ clearInterval(t1); clearInterval(t2); };
  }, []);
  const STAGES = [
    { label:'Prompt Injection',       color:'#dc2626', pct:Math.min(prog*1.1,100) },
    { label:'Jailbreak Templates',    color:'#ea580c', pct:Math.min(prog,100) },
    { label:'Data Exfiltration',      color:'var(--blue)', pct:Math.min(prog*0.8,100) },
    { label:'Authority Impersonation',color:'#b45309', pct:Math.min(prog*0.6,100) },
    { label:'System Prompt Spoofing', color:'var(--purple)', pct:Math.min(prog*0.4,100) },
    { label:'Context Manipulation',   color:'#2dd4bf', pct:Math.min(prog*0.25,100) },
  ];
  return (
    <div style={{ maxWidth:'520px', margin:'56px auto' }}>
      <div style={{ textAlign:'center', marginBottom:'32px' }}>
        <div style={{ width:'72px', height:'72px', margin:'0 auto 20px', borderRadius:'20px', background:'linear-gradient(135deg,rgba(37,99,235,0.15),rgba(155,110,243,0.15))', border:'1px solid rgba(37,99,235,0.25)', display:'flex', alignItems:'center', justifyContent:'center', fontSize:'32px', boxShadow:'0 0 40px rgba(37,99,235,0.12), 0 0 0 8px rgba(37,99,235,0.04)' }}>🛡</div>
        <h2 style={{ fontSize:'22px', fontWeight:'800', letterSpacing:'-0.5px', marginBottom:'6px' }}>Scan in Progress</h2>
        <p style={{ color:'var(--t2)', fontSize:'14px', marginBottom:'3px' }}>Target: <strong style={{ color:'var(--t1)' }}>{scan.target_name}</strong></p>
        <p style={{ color:'var(--t3)', fontSize:'13px' }}>Firing 1 000+ adversarial prompts{'.'.repeat(dots)}</p>
      </div>

      <div className="card-glow" style={{ padding:'22px 24px' }}>
        <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:'16px' }}>
          <div style={{ fontSize:'11px', fontWeight:'700', textTransform:'uppercase', letterSpacing:'0.9px', color:'var(--t3)' }}>Attack Progress</div>
          <div style={{ display:'flex', alignItems:'center', gap:'6px', fontSize:'11px', color:'var(--blue)' }}>
            <span className="pulse-dot" style={{ margin:0 }} />
            Live
          </div>
        </div>
        {STAGES.map(s=>(
          <div key={s.label} style={{ marginBottom:'10px' }}>
            <div style={{ display:'flex', justifyContent:'space-between', marginBottom:'4px' }}>
              <span style={{ fontSize:'12px', color:'var(--t2)', fontWeight:'500' }}>{s.label}</span>
              <span style={{ fontSize:'11px', color:'var(--t3)', fontVariantNumeric:'tabular-nums' }}>{Math.round(s.pct)}%</span>
            </div>
            <div style={{ height:'3px', background:'rgba(17,24,39,0.05)', borderRadius:'2px', overflow:'hidden' }}>
              <div style={{ height:'100%', width:`${s.pct}%`, background:s.color, borderRadius:'2px', boxShadow:`0 0 8px ${s.color}50`, transition:'width 0.9s ease' }} />
            </div>
          </div>
        ))}
        <div style={{ marginTop:'16px', paddingTop:'14px', borderTop:'1px solid var(--b1)', display:'flex', justifyContent:'space-between', fontSize:'12px', color:'var(--t3)' }}>
          <span>⏱ Est. time: 10–25 min</span>
          <span>🔄 Page refreshes automatically</span>
        </div>
      </div>
    </div>
  );
}

/* ── Main Results page ───────────────────────────────────── */
export default function Results() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan,      setScan]      = useState(null);
  const [loading,   setLoading]   = useState(true);
  const [copied,    setCopied]    = useState(false);
  const [sevFilter, setSevFilter] = useState('ALL');
  const scanStatusRef = useRef(null);

  const fetchScan = async () => {
    try {
      const r = await scansAPI.get(id);
      setScan(r.data);
      scanStatusRef.current = r.data?.status;
    }
    catch {} finally { setLoading(false); }
  };

  useEffect(() => {
    fetchScan();
    const t = setInterval(() => {
      const s = scanStatusRef.current;
      if (s !== 'complete' && s !== 'failed') fetchScan();
    }, 3000);
    return () => clearInterval(t);
  }, [id]); // eslint-disable-line

  const copyLink = () => {
    navigator.clipboard.writeText(window.location.href);
    setCopied(true);
    setTimeout(()=>setCopied(false), 2400);
  };

  const _results   = useMemo(()=> scan?.results?.results || [], [scan]);
  const filteredResults = useMemo(()=>
    sevFilter==='ALL' ? _results : _results.filter(r=>r.severity===sevFilter),
  [_results, sevFilter]);
  const sevCounts  = useMemo(()=>{
    const c = { ALL:_results.length, CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 };
    _results.forEach(r=>{ if(c[r.severity]!==undefined) c[r.severity]++; });
    return c;
  }, [_results]);

  if (loading) return (
    <div style={{ display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', padding:'100px', gap:'14px' }}>
      <div className="spinner" style={{ width:'24px', height:'24px' }} />
      <span style={{ color:'var(--t3)', fontSize:'14px' }}>Loading scan results…</span>
    </div>
  );
  if (!scan) return (
    <div className="empty-state" style={{ padding:'100px 40px' }}>
      <div className="empty-state-icon">🔍</div>
      <h3>Scan not found</h3>
      <p>This scan may have been deleted or the ID is invalid.</p>
      <button className="btn-primary" onClick={()=>navigate('/')}>Back to Dashboard</button>
    </div>
  );
  if (scan.status==='running'||scan.status==='pending') return <RunningState scan={scan} />;
  if (scan.status==='failed') return (
    <div className="empty-state" style={{ padding:'100px 40px' }}>
      <div className="empty-state-icon">❌</div>
      <h3 style={{ color:'#dc2626' }}>Scan Failed</h3>
      <p>{scan.error||'An error occurred during the scan.'}</p>
      <button className="btn-primary" onClick={()=>navigate('/')}>Back to Dashboard</button>
    </div>
  );

  const summary      = scan.results?.summary || {};
  const score        = summary.security_score || 0;
  const results      = _results;
  const totalFindings = (summary.critical||0)+(summary.high||0)+(summary.medium||0)+(summary.low||0);
  const riskColor    = score>=70 ? '#16a34a' : score>=40 ? '#b45309' : '#dc2626';
  const riskDesc     = score>=85
    ? 'Excellent security posture. Strong resistance to all tested attack vectors.'
    : score>=70 ? 'Good resistance to adversarial attacks. A few findings need review before production.'
    : score>=40 ? 'Several vulnerabilities detected. Prioritize critical and high findings immediately.'
    : 'Critical vulnerabilities found. Highly susceptible to adversarial exploitation. Immediate remediation required.';

  return (
    <div>

      {/* ── Breadcrumb + actions ─────────────── */}
      <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', marginBottom:'22px', gap:'16px' }}>
        <div>
          <button onClick={()=>navigate('/')}
            style={{ display:'inline-flex', alignItems:'center', gap:'5px', background:'none', border:'none', cursor:'pointer', color:'var(--t3)', fontSize:'12px', fontWeight:'600', textTransform:'uppercase', letterSpacing:'0.5px', marginBottom:'8px', padding:0, transition:'color 0.15s' }}
            onMouseEnter={e=>e.currentTarget.style.color='var(--t1)'}
            onMouseLeave={e=>e.currentTarget.style.color='var(--t3)'}
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><polyline points="15 18 9 12 15 6"/></svg>
            Dashboard
          </button>
          <h1 className="page-title" style={{ marginBottom:'4px' }}>{scan.target_name}</h1>
          <p style={{ fontSize:'13px', color:'var(--t3)', marginBottom:0, display:'flex', alignItems:'center', gap:'8px' }}>
            {new Date(scan.created_at).toLocaleDateString('en-US',{weekday:'long',year:'numeric',month:'long',day:'numeric'})}
            <span style={{ color:'var(--b3)' }}>·</span>
            <span style={{ fontFamily:'monospace', fontSize:'11px', color:'var(--t3)' }}>{scan.scan_id?.slice(0,12)}…</span>
          </p>
        </div>
        <div style={{ display:'flex', gap:'8px', marginTop:'30px', flexShrink:0 }}>
          <button onClick={copyLink} style={{ display:'inline-flex', alignItems:'center', gap:'6px', padding:'8px 14px', background:'var(--s2)', border:'1px solid var(--b2)', borderRadius:'8px', color:'var(--t2)', fontSize:'13px', fontWeight:'600', cursor:'pointer', fontFamily:'inherit', transition:'all 0.15s' }}
            onMouseEnter={e=>{e.currentTarget.style.color='var(--t1)';e.currentTarget.style.borderColor='var(--b3)';}}
            onMouseLeave={e=>{e.currentTarget.style.color='var(--t2)';e.currentTarget.style.borderColor='var(--b2)';}}
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
            {copied ? '✓ Copied!' : 'Copy Link'}
          </button>
          <button className="btn-primary" onClick={()=>window.open(`${API_URL}/download/${id}`,'_blank')}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            Download PDF
          </button>
        </div>
      </div>

      {/* ── Hero card ────────────────────────── */}
      <div className="results-hero" style={{ marginBottom:'16px' }}>
        {/* Score color accent bar */}
        <div style={{ height:'3px', background:`linear-gradient(90deg, ${riskColor}80, ${riskColor}20, transparent)` }} />

        <div style={{ display:'grid', gridTemplateColumns:'200px 1fr', gap:0 }}>
          {/* Left: ring + severity chips */}
          <div style={{ display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', gap:'16px', padding:'32px 20px', borderRight:'1px solid var(--b1)' }}>
            <ScoreRing score={score} />
            <div style={{ display:'flex', gap:'6px', flexWrap:'wrap', justifyContent:'center' }}>
              {SEV_ORDER.map(k=><SevBadge key={k} sev={k} count={summary[k.toLowerCase()]} />)}
            </div>
          </div>

          {/* Right: summary + chart */}
          <div style={{ padding:'28px 32px' }}>
            <div style={{ marginBottom:'20px' }}>
              <div style={{ fontSize:'10px', fontWeight:'700', textTransform:'uppercase', letterSpacing:'0.9px', color:'var(--t3)', marginBottom:'8px' }}>Security Assessment Summary</div>
              <p style={{ fontSize:'14px', color:'var(--t2)', lineHeight:'1.7', marginBottom:'16px', maxWidth:'500px' }}>{riskDesc}</p>

              {/* Metrics strip */}
              <div style={{ display:'flex', gap:'28px', flexWrap:'wrap' }}>
                {[
                  { label:'Prompts Fired',  val:'1 000+', mono:false },
                  { label:'Total Findings', val:totalFindings, mono:false },
                  { label:'Categories Hit', val:[...new Set(results.map(r=>r.category))].length||'0', mono:false },
                  { label:'Scan ID',        val:scan.scan_id?.slice(0,8)+'…', mono:true },
                ].map(m=>(
                  <div key={m.label}>
                    <div style={{ fontSize:m.mono?'12px':'20px', fontWeight:'900', letterSpacing:m.mono?'0':'-0.8px', color:'var(--t1)', fontFamily:m.mono?'monospace':'inherit', lineHeight:1, marginBottom:'4px' }}>{m.val}</div>
                    <div style={{ fontSize:'10px', color:'var(--t3)', textTransform:'uppercase', letterSpacing:'0.6px', fontWeight:'600' }}>{m.label}</div>
                  </div>
                ))}
              </div>
            </div>

            {results.length > 0 && (
              <div style={{ borderTop:'1px solid var(--b1)', paddingTop:'16px' }}>
                <div style={{ fontSize:'10px', fontWeight:'700', textTransform:'uppercase', letterSpacing:'0.9px', color:'var(--t3)', marginBottom:'10px' }}>Findings by Category</div>
                <CategoryChart results={results} />
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Findings ─────────────────────────── */}
      {results.length > 0 && (
        <div className="card-glow" style={{ overflow:'hidden', marginBottom:'4px' }}>
          {/* Header + filters */}
          <div style={{ padding:'16px 20px', borderBottom:'1px solid var(--b1)', display:'flex', alignItems:'center', justifyContent:'space-between', gap:'12px', flexWrap:'wrap' }}>
            <div>
              <span style={{ fontSize:'14px', fontWeight:'700', color:'var(--t1)' }}>All Findings</span>
              <span style={{ fontSize:'12px', color:'var(--t3)', marginLeft:'8px' }}>({totalFindings})</span>
            </div>
            <div style={{ display:'flex', gap:'4px', flexWrap:'wrap' }}>
              {['ALL',...SEV_ORDER].map(sev=>{
                const cnt = sevCounts[sev];
                if (cnt===0 && sev!=='ALL') return null;
                const active = sevFilter===sev;
                const m = SEV_META[sev];
                return (
                  <button key={sev}
                    onClick={()=>setSevFilter(sev)}
                    style={{
                      padding:'5px 11px', borderRadius:'20px', fontSize:'11px', fontWeight:'700',
                      cursor:'pointer', fontFamily:'inherit', letterSpacing:'0.3px',
                      transition:'all 0.12s', border:'1px solid',
                      borderColor: active && m ? m.border : 'var(--b1)',
                      background:  active && m ? m.bg : 'transparent',
                      color:       active && m ? m.color : active ? 'var(--blue)' : 'var(--t3)',
                    }}
                  >
                    {sev==='ALL' ? `All (${cnt})` : `${sev[0]+sev.slice(1).toLowerCase()} (${cnt})`}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Findings list */}
          <div style={{ padding:'14px' }}>
            {(sevFilter==='ALL' ? SEV_ORDER : [sevFilter]).map(sev=>{
              const items = filteredResults.filter(r=>r.severity===sev);
              if (!items.length) return null;
              const m = SEV_META[sev];
              return (
                <div key={sev} style={{ marginBottom:'18px' }}>
                  {sevFilter==='ALL' && (
                    <div style={{ display:'flex', alignItems:'center', gap:'10px', marginBottom:'8px', paddingLeft:'2px' }}>
                      <div style={{ width:'7px', height:'7px', borderRadius:'50%', background:m.color, boxShadow:`0 0 6px ${m.color}80` }} />
                      <span style={{ fontSize:'12px', fontWeight:'700', color:m.color }}>{m.label}</span>
                      <span style={{ fontSize:'12px', color:'var(--t3)' }}>{items.length} finding{items.length!==1?'s':''}</span>
                    </div>
                  )}
                  <div style={{ display:'flex', flexDirection:'column', gap:'5px' }}>
                    {items.slice(0,8).map((item,i)=><FindingCard key={i} item={item} index={i} />)}
                    {items.length>8 && (
                      <button style={{ width:'100%', padding:'12px', background:'var(--s2)', border:'1px solid var(--b1)', borderRadius:'8px', cursor:'pointer', color:'var(--t3)', fontSize:'13px', fontFamily:'inherit', transition:'all 0.15s' }}
                        onClick={()=>window.open(`${API_URL}/download/${id}`,'_blank')}
                        onMouseEnter={e=>{e.currentTarget.style.borderColor='var(--b2)';e.currentTarget.style.color='var(--t1)';}}
                        onMouseLeave={e=>{e.currentTarget.style.borderColor='var(--b1)';e.currentTarget.style.color='var(--t3)';}}
                      >
                        +{items.length-8} more findings — <span style={{ color:'var(--blue)', fontWeight:'600' }}>download the full PDF report →</span>
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {results.length === 0 && (
        <div className="card-glow" style={{ padding:'48px', textAlign:'center' }}>
          <div style={{ fontSize:'32px', marginBottom:'12px' }}>🎉</div>
          <div style={{ fontSize:'17px', fontWeight:'700', color:'#16a34a', marginBottom:'6px' }}>No Vulnerabilities Found</div>
          <div style={{ fontSize:'14px', color:'var(--t3)' }}>Your AI application passed all adversarial tests with zero findings.</div>
        </div>
      )}

      {/* ── Recommendations ──────────────────── */}
      <Recommendations score={score} summary={summary} />

    </div>
  );
}
