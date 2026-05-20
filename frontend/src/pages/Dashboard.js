import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { scansAPI } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';

const PER_PAGE = 8;

const greetHour = () => {
  const h = new Date().getHours();
  if (h < 12) return 'Good morning';
  if (h < 18) return 'Good afternoon';
  return 'Good evening';
};

function relTime(dateStr) {
  const diff = Date.now() - new Date(dateStr).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 7) return `${d}d ago`;
  return new Date(dateStr).toLocaleDateString('en-US', { month:'short', day:'numeric' });
}

/* ── Animated counter ──────────────────────────────────── */
function AnimatedNum({ value }) {
  const [n, setN] = useState(0);
  const prev = useRef(0);
  useEffect(() => {
    const from = prev.current, to = value;
    prev.current = value;
    if (from === to) return;
    const dur = 700, t0 = performance.now();
    const tick = now => {
      const p = Math.min((now - t0) / dur, 1);
      setN(Math.round(from + (to - from) * (1 - Math.pow(1 - p, 3))));
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [value]);
  return <>{n}</>;
}

/* ── Mini sparkline ────────────────────────────────────── */
function Spark({ data, color = 'var(--blue)', height = 32 }) {
  if (data.length < 2) return <div style={{ height }} />;
  const W = 100, H = height;
  const min = Math.min(...data), max = Math.max(...data);
  const toX = i => (i / (data.length - 1)) * W;
  const toY = v => H - 2 - ((v - min) / (max - min || 1)) * (H - 4);
  const pts = data.map((v, i) => [toX(i), toY(v)]);
  const line = pts.map((p, i) => {
    if (i === 0) return `M${p[0].toFixed(1)},${p[1].toFixed(1)}`;
    const prev = pts[i - 1];
    const cx = ((prev[0] + p[0]) / 2).toFixed(1);
    return `C${cx},${prev[1].toFixed(1)} ${cx},${p[1].toFixed(1)} ${p[0].toFixed(1)},${p[1].toFixed(1)}`;
  }).join(' ');
  const area = `${line} L${W},${H} L0,${H} Z`;
  const uid = color.replace(/[^a-z0-9]/gi, '');
  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
      <defs>
        <linearGradient id={`sg-${uid}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={area} fill={`url(#sg-${uid})`} />
      <path d={line} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/* ── Gauge ─────────────────────────────────────────────── */
function PostureGauge({ score }) {
  const R = 38, CX = 54, CY = 52;
  const toRad = deg => (deg * Math.PI) / 180;
  const toXY  = deg => [CX + R * Math.cos(toRad(deg)), CY + R * Math.sin(toRad(deg))];
  const arc   = (a1, a2) => {
    const [x1,y1] = toXY(a1), [x2,y2] = toXY(a2);
    return `M${x1.toFixed(2)},${y1.toFixed(2)} A${R},${R} 0 ${Math.abs(a2-a1)>180?1:0} 1 ${x2.toFixed(2)},${y2.toFixed(2)}`;
  };
  if (score == null) return (
    <div style={{ textAlign:'center', padding:'8px 0' }}>
      <div style={{ fontSize:'26px', fontWeight:'900', color:'var(--t3)' }}>—</div>
      <div style={{ fontSize:'11px', color:'var(--t3)' }}>No data yet</div>
    </div>
  );
  const pct = score / 100;
  const color = score>=70 ? '#4ade80' : score>=40 ? '#facc15' : '#f87171';
  const label = score>=85 ? 'Secure' : score>=70 ? 'Low Risk' : score>=40 ? 'Moderate' : 'High Risk';
  const needle = -180 + 180 * pct;
  const [nx, ny] = toXY(needle);
  return (
    <div style={{ display:'flex', flexDirection:'column', alignItems:'center' }}>
      <svg viewBox="0 0 108 60" style={{ width:'100%', maxWidth:'160px', overflow:'visible' }}>
        <path d={arc(-180, 0)} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="9" strokeLinecap="round" />
        {score > 0 && <path d={arc(-180, needle)} fill="none" stroke={color} strokeWidth="9" strokeLinecap="round"
          style={{ filter:`drop-shadow(0 0 6px ${color}70)`, transition:'all 1.2s cubic-bezier(.4,0,.2,1)' }} />}
        <circle cx={nx.toFixed(2)} cy={ny.toFixed(2)} r="5.5" fill={color} stroke="var(--s1)" strokeWidth="2.5"
          style={{ filter:`drop-shadow(0 0 5px ${color})` }} />
        <text x={CX} y={CY+2} textAnchor="middle" fill={color} fontSize="16" fontWeight="900" fontFamily="Inter,sans-serif" style={{ letterSpacing:'-0.5px' }}>{score}</text>
      </svg>
      <div style={{ fontSize:'11px', fontWeight:'700', color, letterSpacing:'0.3px', marginTop:'3px' }}>{label}</div>
    </div>
  );
}

/* ── Score pill ────────────────────────────────────────── */
function ScorePill({ score }) {
  if (score == null) return <span style={{ color:'var(--t3)', fontSize:'12px' }}>—</span>;
  const color = score>=70 ? '#4ade80' : score>=40 ? '#facc15' : '#f87171';
  return (
    <div style={{ display:'flex', alignItems:'center', gap:'7px' }}>
      <div style={{ width:'48px', height:'3px', background:'rgba(255,255,255,0.07)', borderRadius:'2px', overflow:'hidden' }}>
        <div style={{ width:`${score}%`, height:'100%', background:color, borderRadius:'2px', boxShadow:`0 0 4px ${color}80` }} />
      </div>
      <span style={{ color, fontWeight:'700', fontSize:'13px', fontVariantNumeric:'tabular-nums' }}>{score}</span>
    </div>
  );
}

/* ── Severity chips ────────────────────────────────────── */
function SevChips({ summary }) {
  if (!summary) return <span style={{ color:'var(--t3)', fontSize:'12px' }}>—</span>;
  const parts = [
    { key:'critical', color:'#f87171', bg:'rgba(248,113,113,0.12)' },
    { key:'high',     color:'#fb923c', bg:'rgba(251,146,60,0.12)' },
    { key:'medium',   color:'#facc15', bg:'rgba(250,204,21,0.1)' },
    { key:'low',      color:'#4ade80', bg:'rgba(74,222,128,0.1)' },
  ].filter(p=>(summary[p.key]||0)>0);
  if (parts.length===0) return (
    <span style={{ fontSize:'11px', fontWeight:'700', color:'#4ade80', background:'rgba(74,222,128,0.1)', border:'1px solid rgba(74,222,128,0.22)', padding:'2px 8px', borderRadius:'10px' }}>Clean</span>
  );
  return (
    <div style={{ display:'flex', gap:'4px' }}>
      {parts.map(p=>(
        <span key={p.key} style={{ fontSize:'11px', fontWeight:'800', color:p.color, background:p.bg, padding:'2px 7px', borderRadius:'10px' }}>{summary[p.key]}</span>
      ))}
    </div>
  );
}

/* ── Skeleton loader ───────────────────────────────────── */
function SkeletonRows() {
  return (
    <>
      {[...Array(5)].map((_,i)=>(
        <div key={i} style={{ display:'grid', gridTemplateColumns:'2fr 90px 120px 130px 80px 70px', gap:0, alignItems:'center', padding:'15px 24px', borderBottom:'1px solid var(--b1)' }}>
          <div style={{ display:'flex', alignItems:'center', gap:'10px' }}>
            <div className="sk" style={{ width:'34px', height:'34px', borderRadius:'9px', flexShrink:0 }} />
            <div><div className="sk" style={{ width:'140px', height:'13px', marginBottom:'5px' }} /><div className="sk" style={{ width:'70px', height:'10px' }} /></div>
          </div>
          <div className="sk" style={{ width:'68px', height:'22px', borderRadius:'20px' }} />
          <div className="sk" style={{ width:'80px', height:'12px' }} />
          <div className="sk" style={{ width:'90px', height:'18px' }} />
          <div className="sk" style={{ width:'56px', height:'12px' }} />
          <div className="sk" style={{ width:'54px', height:'28px', borderRadius:'6px' }} />
        </div>
      ))}
    </>
  );
}

/* ── Empty hero ────────────────────────────────────────── */
function EmptyHero({ onStart }) {
  return (
    <div style={{ textAlign:'center', padding:'72px 40px', maxWidth:'480px', margin:'0 auto' }}>
      <div style={{ width:'80px', height:'80px', margin:'0 auto 24px', borderRadius:'22px', background:'linear-gradient(135deg,rgba(74,138,244,0.12),rgba(155,110,243,0.12))', border:'1px solid rgba(74,138,244,0.2)', display:'flex', alignItems:'center', justifyContent:'center', fontSize:'36px', boxShadow:'0 0 50px rgba(74,138,244,0.1), 0 0 0 12px rgba(74,138,244,0.04)' }}>🛡</div>
      <h2 style={{ fontSize:'22px', fontWeight:'800', letterSpacing:'-0.5px', marginBottom:'10px' }}>Ready to secure your AI?</h2>
      <p style={{ fontSize:'14px', color:'var(--t2)', lineHeight:'1.7', marginBottom:'28px' }}>
        Launch your first adversarial scan — 1 000+ attack prompts across 21 categories. No API key required in Simulation mode.
      </p>
      <div style={{ display:'flex', gap:'10px', justifyContent:'center', flexWrap:'wrap' }}>
        <button className="btn-primary" onClick={onStart} style={{ padding:'11px 24px', fontSize:'14px' }}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>
          Launch First Scan
        </button>
        <button className="btn-outline" onClick={()=>window.open('/threat-intel','_self')} style={{ padding:'11px 20px', fontSize:'14px' }}>
          View Attack Library
        </button>
      </div>
      <div style={{ marginTop:'36px', display:'flex', gap:'28px', justifyContent:'center' }}>
        {[['21','Attack categories'],['1K+','Prompts per scan'],['100','Max score']].map(([n,l])=>(
          <div key={l} style={{ textAlign:'center' }}>
            <div style={{ fontSize:'20px', fontWeight:'900', color:'var(--t1)', letterSpacing:'-0.5px' }}>{n}</div>
            <div style={{ fontSize:'11px', color:'var(--t3)', marginTop:'2px' }}>{l}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Main ──────────────────────────────────────────────── */
export default function Dashboard() {
  const [scans,   setScans]   = useState([]);
  const [loading, setLoading] = useState(true);
  const [search,  setSearch]  = useState('');
  const [filter,  setFilter]  = useState('ALL');
  const [page,    setPage]    = useState(1);
  const navigate = useNavigate();
  const { user } = useAuth();
  const toast    = useToast();

  useEffect(() => {
    fetchScans();
    const t = setInterval(fetchScans, 5000);
    return () => clearInterval(t);
  }, []);

  const fetchScans = async () => {
    try { const res = await scansAPI.list(); setScans(res.data.scans.reverse()); }
    catch {} finally { setLoading(false); }
  };

  const exportCSV = () => {
    if (!scans.length) { toast('No scans to export.', 'warning'); return; }
    const headers = ['Target','Status','Score','Critical','High','Medium','Low','Date'];
    const rows = scans.map(s => [
      s.target_name, s.status,
      s.results?.summary?.security_score ?? '',
      s.results?.summary?.critical ?? '',
      s.results?.summary?.high ?? '',
      s.results?.summary?.medium ?? '',
      s.results?.summary?.low ?? '',
      new Date(s.created_at).toLocaleString(),
    ]);
    const csv = [headers,...rows].map(r=>r.join(',')).join('\n');
    const url = URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
    Object.assign(document.createElement('a'),{href:url,download:'llm_scanner_results.csv'}).click();
    toast('CSV exported.', 'success');
  };

  /* ── Derived data ──────────────────────────────────────── */
  const completedScans = useMemo(()=>scans.filter(s=>s.status==='complete'), [scans]);
  const running  = useMemo(()=>scans.filter(s=>s.status==='running').length, [scans]);
  const total    = scans.length;
  const critical = useMemo(()=>scans.reduce((a,s)=>a+(s.results?.summary?.critical||0),0), [scans]);
  const avgScore = useMemo(()=>{
    const scored = completedScans.filter(s=>s.results?.summary?.security_score!=null);
    return scored.length ? Math.round(scored.reduce((a,s)=>a+s.results.summary.security_score,0)/scored.length) : null;
  }, [completedScans]);
  const scoreTrend = useMemo(()=>
    completedScans.filter(s=>s.results?.summary?.security_score!=null).slice(-12).map(s=>s.results.summary.security_score),
  [completedScans]);
  const trendDelta = scoreTrend.length>=2 ? scoreTrend[scoreTrend.length-1]-scoreTrend[scoreTrend.length-2] : null;
  const latestScan = scans[0]||null;
  const cleanScans = completedScans.filter(s=>!(s.results?.summary?.critical>0)&&!(s.results?.summary?.high>0)).length;

  const filtered = useMemo(()=>
    scans
      .filter(s=>filter==='ALL'||s.status===filter.toLowerCase())
      .filter(s=>s.target_name.toLowerCase().includes(search.toLowerCase())),
  [scans,filter,search]);
  const totalPages = Math.ceil(filtered.length/PER_PAGE);
  const paged = filtered.slice((page-1)*PER_PAGE, page*PER_PAGE);

  const scoreColor = avgScore==null ? 'var(--t3)' : avgScore>=70 ? '#4ade80' : avgScore>=40 ? '#facc15' : '#f87171';

  const STATS = [
    { label:'Total Scans',       value:total,    color:'var(--t1)',
      sub: completedScans.length>0 ? `${completedScans.length} completed` : 'None yet', subColor:'var(--t3)',
      iconBg:'rgba(255,255,255,0.05)',
      icon:<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>,
    },
    { label:'Avg Security Score', value:avgScore, color:scoreColor, suffix:'/100',
      sub: trendDelta!=null ? `${trendDelta>=0?'↑':'↓'} ${Math.abs(trendDelta)} pts vs last scan` : 'Need 2+ scans for trend',
      subColor: trendDelta==null ? 'var(--t3)' : trendDelta>=0 ? '#4ade80' : '#f87171',
      iconBg: avgScore==null ? 'rgba(255,255,255,0.04)' : avgScore>=70 ? 'rgba(74,222,128,0.12)' : avgScore>=40 ? 'rgba(250,204,21,0.1)' : 'var(--red-soft)',
      icon:<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>,
      chart: scoreTrend,
    },
    { label:'Critical Findings',  value:critical, color:critical>0 ? '#f87171' : 'var(--t3)',
      sub: critical>0 ? 'Require immediate review' : 'No critical issues',
      subColor: critical>0 ? 'rgba(248,113,113,0.7)' : '#4ade80',
      iconBg: critical>0 ? 'var(--red-soft)' : 'rgba(255,255,255,0.04)',
      icon:<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
    },
    { label:'Active Scans',       value:running,  color:running>0 ? 'var(--blue)' : 'var(--t3)',
      sub: running>0 ? `${running} scan${running>1?'s':''} in progress` : 'All scans complete',
      subColor: running>0 ? 'rgba(74,138,244,0.7)' : 'var(--t3)',
      iconBg: running>0 ? 'var(--blue-soft)' : 'rgba(255,255,255,0.04)',
      icon:<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>,
    },
  ];

  const statusBadge = status => {
    const M = {
      complete: { label:'Complete', cls:'badge badge-safe' },
      running:  { label:'Running',  cls:'badge badge-running' },
      pending:  { label:'Pending',  cls:'badge badge-pending' },
      failed:   { label:'Failed',   cls:'badge badge-critical' },
    };
    const b = M[status]||{label:status, cls:'badge'};
    return <span className={b.cls}>{status==='running'&&<span className="pulse-dot"/>}{b.label}</span>;
  };

  return (
    <div>

      {/* ── Header ───────────────────────────── */}
      <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', marginBottom:'28px' }}>
        <div>
          <div style={{ fontSize:'11px', fontWeight:'600', textTransform:'uppercase', letterSpacing:'1px', color:'rgba(255,255,255,0.18)', marginBottom:'5px' }}>
            {greetHour()}, {user?.username||'there'} 👋
          </div>
          <h1 className="page-title">Security Dashboard</h1>
          <p className="page-subtitle" style={{ marginBottom:0 }}>Monitor and manage your AI endpoint security assessments</p>
        </div>
        <div style={{ display:'flex', gap:'8px', marginTop:'4px', flexShrink:0 }}>
          <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={()=>navigate('/analytics')}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
            Analytics
          </button>
          <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={exportCSV}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            Export CSV
          </button>
          <button className="btn-primary" onClick={()=>navigate('/new-scan')}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            New Scan
          </button>
        </div>
      </div>

      {/* ── Stat cards ───────────────────────── */}
      <div className="stats-row" style={{ marginBottom:'16px' }}>
        {STATS.map(s=>(
          <div key={s.label} className="stat-card-glow" style={{ display:'flex', flexDirection:'column', gap:'4px', minHeight:'106px' }}>
            <div style={{ position:'absolute', top:'16px', right:'16px', width:'28px', height:'28px', borderRadius:'7px', background:s.iconBg, color:s.color, display:'flex', alignItems:'center', justifyContent:'center' }}>
              {s.icon}
            </div>
            <div className="stat-number" style={{ color:s.color, fontSize:'28px' }}>
              {s.value==null ? '—' : <><AnimatedNum value={s.value} />{s.suffix||''}</>}
            </div>
            <div className="stat-label">{s.label}</div>
            <div style={{ fontSize:'11px', color:s.subColor||'var(--t3)', fontWeight:'500', lineHeight:'1.4' }}>{s.sub}</div>
            {s.chart && s.chart.length>=2 && (
              <div style={{ marginTop:'auto', paddingTop:'8px', height:'26px' }}>
                <Spark data={s.chart} color={s.color} height={26} />
              </div>
            )}
          </div>
        ))}
      </div>

      {/* ── Empty state ──────────────────────── */}
      {!loading && total===0 && (
        <div className="card-glow" style={{ overflow:'hidden' }}>
          <EmptyHero onStart={()=>navigate('/new-scan')} />
        </div>
      )}

      {/* ── Posture + Score history ───────────── */}
      {completedScans.length>0 && (
        <div style={{ display:'grid', gridTemplateColumns:'210px 1fr', gap:'12px', marginBottom:'14px' }}>

          {/* Posture gauge */}
          <div className="card-glow" style={{ padding:'20px 18px', display:'flex', flexDirection:'column', gap:'12px' }}>
            <div style={{ fontSize:'10px', fontWeight:'700', textTransform:'uppercase', letterSpacing:'0.9px', color:'var(--t3)' }}>Security Posture</div>
            <PostureGauge score={avgScore} />
            <div style={{ display:'flex', flexDirection:'column', gap:'8px', borderTop:'1px solid var(--b1)', paddingTop:'12px' }}>
              {[
                { label:'Last scan',   val:latestScan ? relTime(latestScan.created_at) : '—' },
                { label:'Total scans', val:total,       vc:'var(--t1)' },
                { label:'Clean scans', val:`${cleanScans}/${completedScans.length}`, vc:'#4ade80' },
              ].map(row=>(
                <div key={row.label} style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
                  <span style={{ fontSize:'11px', color:'var(--t3)' }}>{row.label}</span>
                  <span style={{ fontSize:'12px', fontWeight:'700', color:row.vc||'var(--t2)' }}>{row.val}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Score history */}
          <div className="card-glow" style={{ padding:'18px 22px' }}>
            <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:'14px' }}>
              <div>
                <h2 style={{ fontSize:'14px', fontWeight:'700', color:'var(--t1)', letterSpacing:'-0.2px' }}>Score History</h2>
                <p style={{ fontSize:'12px', color:'var(--t3)', marginTop:'2px' }}>
                  Last {scoreTrend.length} scan{scoreTrend.length!==1?'s':''}
                  {trendDelta!=null && (
                    <span style={{ marginLeft:'8px', fontWeight:'700', color:trendDelta>=0?'#4ade80':'#f87171' }}>
                      {trendDelta>=0?'↑':'↓'} {Math.abs(trendDelta)} pts
                    </span>
                  )}
                </p>
              </div>
              <div style={{ display:'flex', gap:'10px' }}>
                {[['#4ade80','≥70'],['#facc15','40–69'],['#f87171','<40']].map(([c,l])=>(
                  <div key={l} style={{ display:'flex', alignItems:'center', gap:'4px' }}>
                    <div style={{ width:'7px', height:'7px', borderRadius:'2px', background:c }} />
                    <span style={{ fontSize:'10px', color:'var(--t3)' }}>{l}</span>
                  </div>
                ))}
              </div>
            </div>
            {scoreTrend.length<2 ? (
              <div style={{ display:'flex', alignItems:'center', justifyContent:'center', height:'68px', color:'var(--t3)', fontSize:'13px' }}>
                Complete more scans to see the trend chart
              </div>
            ) : (
              <div style={{ display:'flex', alignItems:'flex-end', gap:'4px', height:'72px' }}>
                {scoreTrend.map((sc,i)=>{
                  const color = sc>=70 ? '#4ade80' : sc>=40 ? '#facc15' : '#f87171';
                  const h = Math.max(6, Math.round((sc/100)*72));
                  const relScan = completedScans.filter(s=>s.results?.summary?.security_score!=null).slice(-12)[i];
                  return (
                    <div key={i} title={`${sc}/100 — click to view`}
                      className="score-chart-bar"
                      style={{ height:`${h}px`, background:color, boxShadow:`0 0 8px ${color}40`, flex:1, cursor:relScan?'pointer':'default', minWidth:0 }}
                      onClick={()=>relScan&&navigate(`/results/${relScan.scan_id}`)}
                    />
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Scan table ───────────────────────── */}
      {total>0 && (
        <div className="card-glow" style={{ overflow:'hidden' }}>
          {/* Toolbar */}
          <div style={{ padding:'16px 20px', borderBottom:'1px solid var(--b1)' }}>
            <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:'12px' }}>
              <div>
                <h2 style={{ fontSize:'14px', fontWeight:'700', color:'var(--t1)', letterSpacing:'-0.2px' }}>Scan History</h2>
                <p style={{ fontSize:'12px', color:'var(--t3)', marginTop:'2px' }}>
                  {total} scan{total!==1?'s':''} · {completedScans.length} completed
                </p>
              </div>
              <div style={{ display:'flex', gap:'8px', alignItems:'center' }}>
                {running>0 && (
                  <span style={{ display:'inline-flex', alignItems:'center', gap:'5px', fontSize:'11px', color:'var(--blue)', fontWeight:'700', background:'var(--blue-soft)', border:'1px solid rgba(74,138,244,0.2)', padding:'4px 11px', borderRadius:'20px' }}>
                    <span className="pulse-dot" style={{ margin:0 }} />{running} running
                  </span>
                )}
              </div>
            </div>
            <div style={{ display:'flex', gap:'10px', alignItems:'center' }}>
              <div style={{ position:'relative', flex:1, maxWidth:'280px' }}>
                <svg style={{ position:'absolute', left:'10px', top:'50%', transform:'translateY(-50%)', color:'var(--t3)', pointerEvents:'none' }} width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
                <input className="search-bar" style={{ paddingLeft:'30px', marginBottom:0, height:'34px', fontSize:'13px' }}
                  placeholder="Search by target name…" value={search}
                  onChange={e=>{setSearch(e.target.value);setPage(1);}} />
              </div>
              <div style={{ display:'flex', gap:'4px' }}>
                {['ALL','COMPLETE','RUNNING','FAILED'].map(f=>(
                  <button key={f} className={`filter-btn${filter===f?' active':''}`} style={{ padding:'4px 11px', fontSize:'11px' }}
                    onClick={()=>{setFilter(f);setPage(1);}}>{f[0]+f.slice(1).toLowerCase()}</button>
                ))}
              </div>
            </div>
          </div>

          {/* Table */}
          {loading ? <SkeletonRows /> : filtered.length===0 ? (
            <div className="empty-state" style={{ padding:'56px 40px' }}>
              <div className="empty-state-icon">{search?'🔍':'🛡️'}</div>
              <h3>{search?'No results found':'No scans match filter'}</h3>
              <p>{search?`Nothing matches "${search}"`:'Try changing the filter above.'}</p>
            </div>
          ) : (
            <>
              {/* Column headers */}
              <div style={{ display:'grid', gridTemplateColumns:'2fr 90px 130px 140px 80px 80px', padding:'9px 24px', borderBottom:'1px solid var(--b1)', fontSize:'11px', fontWeight:'700', color:'var(--t3)', textTransform:'uppercase', letterSpacing:'0.6px' }}>
                <span>Target</span><span>Status</span><span>Score</span><span>Findings</span><span>When</span><span></span>
              </div>
              {paged.map(scan=>{
                const initials = scan.target_name.slice(0,2).toUpperCase();
                const hue = scan.target_name.charCodeAt(0)*37%360;
                const isComplete = scan.status==='complete';
                return (
                  <div key={scan.scan_id}
                    style={{ display:'grid', gridTemplateColumns:'2fr 90px 130px 140px 80px 80px', padding:'13px 24px', borderBottom:'1px solid var(--b1)', alignItems:'center', cursor:isComplete?'pointer':'default', transition:'background 0.12s' }}
                    onClick={()=>isComplete&&navigate(`/results/${scan.scan_id}`)}
                    onMouseEnter={e=>{ if(isComplete) e.currentTarget.style.background='rgba(255,255,255,0.025)'; }}
                    onMouseLeave={e=>e.currentTarget.style.background='transparent'}
                  >
                    <div style={{ display:'flex', alignItems:'center', gap:'11px', minWidth:0 }}>
                      <div style={{ width:'34px', height:'34px', borderRadius:'9px', flexShrink:0, background:`linear-gradient(135deg, hsl(${hue},55%,30%), hsl(${(hue+40)%360},55%,22%))`, display:'flex', alignItems:'center', justifyContent:'center', fontSize:'11px', fontWeight:'800', color:'#fff', letterSpacing:'0.3px' }}>
                        {initials}
                      </div>
                      <div style={{ minWidth:0 }}>
                        <div style={{ fontWeight:'600', fontSize:'13px', color:'var(--t1)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{scan.target_name}</div>
                        <div style={{ fontSize:'10px', color:'var(--t3)', fontFamily:'monospace', marginTop:'1px' }}>{scan.scan_id?.slice(0,8)}…</div>
                      </div>
                    </div>
                    <div>{statusBadge(scan.status)}</div>
                    <div><ScorePill score={scan.results?.summary?.security_score} /></div>
                    <div><SevChips summary={scan.results?.summary} /></div>
                    <div>
                      <div style={{ fontSize:'12px', color:'var(--t2)', fontWeight:'500' }}>{relTime(scan.created_at)}</div>
                      <div style={{ fontSize:'10px', color:'var(--t3)', marginTop:'1px' }}>{new Date(scan.created_at).toLocaleDateString('en-US',{month:'short',day:'numeric'})}</div>
                    </div>
                    <div onClick={e=>e.stopPropagation()}>
                      {isComplete && (
                        <button className="btn-outline" style={{ padding:'5px 12px', fontSize:'12px' }}
                          onClick={()=>navigate(`/results/${scan.scan_id}`)}>View →</button>
                      )}
                    </div>
                  </div>
                );
              })}
              {totalPages>1 && (
                <div className="pagination" style={{ padding:'14px 0 18px' }}>
                  {Array.from({length:totalPages},(_,i)=>(
                    <button key={i} className={`page-btn${page===i+1?' active':''}`} onClick={()=>setPage(i+1)}>{i+1}</button>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
