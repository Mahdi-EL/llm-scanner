import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { scansAPI } from '../services/api';
import { scoreColor } from '../utils/format';

/* ── SVG Area chart ──────────────────────────────────────────── */
function AreaChart({ data, color = 'var(--blue)', height = 160 }) {
  const W = 600, H = height;
  const pad = { t:16, r:12, b:28, l:36 };
  const iW = W - pad.l - pad.r;
  const iH = H - pad.t - pad.b;

  if (data.length < 2) return (
    <div style={{ height, display:'flex', alignItems:'center', justifyContent:'center', color:'var(--t3)', fontSize:'13px' }}>
      A trend needs at least two completed scans
    </div>
  );

  const minY = 0, maxY = 100;
  const toX  = i => pad.l + (i / (data.length - 1)) * iW;
  const toY  = v => pad.t + iH - ((Math.max(minY, Math.min(maxY, v)) - minY) / (maxY - minY)) * iH;
  const pts  = data.map((d, i) => [toX(i), toY(d.score)]);

  const linePath = pts.map((p, i) => {
    if (i === 0) return `M ${p[0].toFixed(1)} ${p[1].toFixed(1)}`;
    const prev = pts[i - 1];
    const cx   = ((prev[0] + p[0]) / 2).toFixed(1);
    return `C ${cx} ${prev[1].toFixed(1)} ${cx} ${p[1].toFixed(1)} ${p[0].toFixed(1)} ${p[1].toFixed(1)}`;
  }).join(' ');

  const areaPath = `${linePath} L ${pts[pts.length-1][0]} ${H-pad.b} L ${pts[0][0]} ${H-pad.b} Z`;

  const yLines = [0, 25, 50, 75, 100];

  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ overflow:'visible' }}>
      <defs>
        <linearGradient id={`grad-${color.replace(/[^a-z]/g,'')}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%"   stopColor={color} stopOpacity="0.25" />
          <stop offset="100%" stopColor={color} stopOpacity="0.01" />
        </linearGradient>
      </defs>

      {/* Grid lines */}
      {yLines.map(y => (
        <g key={y}>
          <line x1={pad.l} y1={toY(y)} x2={W-pad.r} y2={toY(y)} stroke="rgba(17,24,39,0.04)" strokeWidth="1" />
          <text x={pad.l - 6} y={toY(y) + 4} textAnchor="end" fill="rgba(17,24,39,0.2)" fontSize="9" fontFamily="Inter,sans-serif">{y}</text>
        </g>
      ))}

      {/* Area fill */}
      <path d={areaPath} fill={`url(#grad-${color.replace(/[^a-z]/g,'')})`} />

      {/* Line */}
      <path d={linePath} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
        style={{ filter:`drop-shadow(0 0 6px ${color}60)` }} />

      {/* Points + labels */}
      {pts.map((p, i) => {
        const score = data[i].score;
        const dotColor = scoreColor(score);
        return (
          <g key={i}>
            <circle cx={p[0]} cy={p[1]} r="5" fill={dotColor} stroke="var(--bg)" strokeWidth="2"
              style={{ filter:`drop-shadow(0 0 4px ${dotColor}90)` }} />
            {/* X axis label */}
            <text x={p[0]} y={H - 6} textAnchor="middle" fill="rgba(17,24,39,0.2)" fontSize="8" fontFamily="Inter,sans-serif">
              {data[i].label}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

/* ── Donut chart ─────────────────────────────────────────────── */
function DonutChart({ segments, size = 120 }) {
  const R = 44, CIRC = 2 * Math.PI * R;
  let offset = 0;
  return (
    <svg width={size} height={size} viewBox="0 0 120 120">
      <circle cx="60" cy="60" r={R} fill="none" stroke="rgba(17,24,39,0.04)" strokeWidth="14" />
      {segments.map((s, i) => {
        const dash = (s.pct / 100) * CIRC;
        const seg = (
          <circle key={i} cx="60" cy="60" r={R} fill="none"
            stroke={s.color} strokeWidth="14" strokeLinecap="butt"
            strokeDasharray={`${dash} ${CIRC}`}
            strokeDashoffset={-offset}
            style={{ transform:'rotate(-90deg)', transformOrigin:'60px 60px', transition:'stroke-dasharray 1s ease', filter:`drop-shadow(0 0 6px ${s.color}50)` }}
          />
        );
        offset += dash;
        return seg;
      })}
    </svg>
  );
}

/* ── Mini spark bar ──────────────────────────────────────────── */
function SparkBar({ values }) {
  const max = Math.max(...values, 1);
  return (
    <div style={{ display:'flex', alignItems:'flex-end', gap:'2px', height:'32px' }}>
      {values.map((v, i) => {
        const h = Math.max(3, Math.round((v / max) * 32));
        return <div key={i} style={{ flex:1, height:`${h}px`, background:'var(--blue)', borderRadius:'2px', opacity: 0.4 + (i / values.length) * 0.6 }} />;
      })}
    </div>
  );
}

/* ── Trend indicator ─────────────────────────────────────────── */
function Trend({ value, label }) {
  const up = value >= 0;
  return (
    <div style={{ display:'flex', alignItems:'center', gap:'4px', fontSize:'11px', fontWeight:'600',
      color: up ? '#16a34a' : '#dc2626' }}>
      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round">
        {up
          ? <><line x1="12" y1="19" x2="12" y2="5"/><polyline points="5 12 12 5 19 12"/></>
          : <><line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/></>
        }
      </svg>
      {Math.abs(value)}% {label}
    </div>
  );
}

/* ── Category heatmap cell ───────────────────────────────────── */
function HeatCell({ label, count, rate }) {
  const pct  = rate;
  const bg   = pct > 0.7 ? 'rgba(248,113,113,0.35)' : pct > 0.4 ? 'rgba(250,204,21,0.25)' : pct > 0.1 ? 'rgba(37,99,235,0.2)' : 'rgba(17,24,39,0.04)';
  const border = pct > 0.7 ? 'rgba(248,113,113,0.4)' : pct > 0.4 ? 'rgba(250,204,21,0.3)' : 'rgba(17,24,39,0.08)';
  return (
    <div title={`${label}: ${count} failed attacks (${Math.round(rate * 100)}%)`} style={{
      background: bg, border:`1px solid ${border}`,
      borderRadius:'6px', padding:'8px 10px',
      fontSize:'10px', fontWeight:'600', color:'var(--t2)',
      textAlign:'center', cursor:'default', minWidth:0,
      transition:'transform 0.15s',
    }}
      onMouseEnter={e => e.currentTarget.style.transform='scale(1.05)'}
      onMouseLeave={e => e.currentTarget.style.transform='none'}
    >
      <div style={{ fontSize:'15px', marginBottom:'3px' }}>{Math.round(rate * 100)}%</div>
      <div style={{ fontSize:'10px', lineHeight:'1.3', color:'var(--t3)', overflowWrap:'anywhere', textTransform:'capitalize' }}>{label.replace(/_/g,' ')}</div>
    </div>
  );
}

/* ── Main Analytics page ─────────────────────────────────────── */
export default function Analytics() {
  const [scans,   setScans]   = useState([]);
  const [catStats, setCatStats] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    (async () => {
      try {
        const [list, cats] = await Promise.all([scansAPI.list(), scansAPI.categoryStats()]);
        setScans([...list.data.scans].reverse());      // oldest first, for the charts
        setCatStats(cats.data.categories);
      } catch { /* empty state below */ }
      finally { setLoading(false); }
    })();
  }, []);

  const completed = scans.filter(s => s.status === 'complete' && s.summary?.security_score != null);

  /* Score trend */
  const trendData = completed.slice(-12).map((s, i) => ({
    score: s.summary.security_score,
    label: new Date(s.created_at).toLocaleDateString('en-US', { month:'short', day:'numeric' }),
  }));

  /* Trend delta (last vs prev) */
  const trendDelta = trendData.length >= 2
    ? Math.round(trendData[trendData.length-1].score - trendData[trendData.length-2].score)
    : null;

  /* Stats */
  const total     = scans.length;
  const avgScore  = completed.length ? Math.round(completed.reduce((a,s) => a + s.summary.security_score, 0) / completed.length) : null;
  const totalCrit = completed.reduce((a,s) => a + (s.summary.critical || 0), 0);
  const totalHigh = completed.reduce((a,s) => a + (s.summary.high || 0), 0);
  const totalMed  = completed.reduce((a,s) => a + (s.summary.medium || 0), 0);
  const totalLow  = completed.reduce((a,s) => a + (s.summary.low || 0), 0);
  const totalFindings = totalCrit + totalHigh + totalMed + totalLow;

  /* Risk distribution for donut */
  const riskDist = [
    { label:'Critical', color:'#dc2626', count: totalCrit },
    { label:'High',     color:'#ea580c', count: totalHigh },
    { label:'Medium',   color:'#b45309', count: totalMed  },
    { label:'Low',      color:'#16a34a', count: totalLow  },
  ].filter(r => r.count > 0).map(r => ({
    ...r, pct: totalFindings > 0 ? Math.round((r.count / totalFindings) * 100) : 0,
  }));

  /* Category heatmap: share of attacks that succeeded, per category */
  const catEntries = catStats.filter(c => c.attacks > 0);

  /* Scan frequency (last 30 days) */
  const now = Date.now();
  const dayCounts = {};
  scans.forEach(s => {
    const d = new Date(s.created_at);
    const key = `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
    dayCounts[key] = (dayCounts[key] || 0) + 1;
  });
  const last30 = Array.from({ length:30 }, (_, i) => {
    const d = new Date(now - (29 - i) * 86400000);
    const key = `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
    return dayCounts[key] || 0;
  });

  const cardStyle = { background:'var(--s1)', border:'1px solid var(--b1)', borderRadius:'14px', padding:'24px', position:'relative', overflow:'hidden' };
  const shine = <div style={{ position:'absolute', top:0, left:0, right:0, height:'1px', background:'linear-gradient(90deg,transparent,rgba(17,24,39,0.06),transparent)' }} />;

  if (loading) return (
    <div style={{ display:'flex', alignItems:'center', justifyContent:'center', padding:'100px', gap:'12px' }}>
      <div className="spinner" style={{ width:'20px', height:'20px' }} />
      <span style={{ color:'var(--t3)', fontSize:'14px' }}>Loading analytics…</span>
    </div>
  );

  return (
    <div>
      {/* Header */}
      <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', marginBottom:'32px' }}>
        <div>
          <h1 className="page-title">Analytics</h1>
          <p className="page-subtitle" style={{ marginBottom:0 }}>Security trends, vulnerability patterns, and scan activity</p>
        </div>
        <button className="btn-primary" onClick={() => navigate('/new-scan')} style={{ marginTop:'4px' }}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          New Scan
        </button>
      </div>

      {/* KPI row */}
      <div className="stats-row" style={{ marginBottom:'20px' }}>
        {[
          { label:'Total Scans',       val: total,        color:'var(--t1)',   suffix:'' },
          { label:'Avg Security Score',val: avgScore,     color: avgScore >= 80 ? '#16a34a' : avgScore >= 50 ? '#b45309' : avgScore != null ? '#dc2626' : 'var(--t3)', suffix:'/100' },
          { label:'Total Findings',    val: totalFindings,color: totalFindings > 0 ? '#ea580c' : 'var(--t3)', suffix:'' },
          { label:'Critical Issues',   val: totalCrit,    color: totalCrit > 0 ? '#dc2626' : 'var(--t3)', suffix:'' },
        ].map(k => (
          <div key={k.label} className="stat-card-glow">
            <div className="stat-number" style={{ color:k.color, fontSize:'30px' }}>{k.val != null ? `${k.val}${k.suffix}` : '—'}</div>
            <div className="stat-label">{k.label}</div>
            {k.label === 'Avg Security Score' && trendDelta != null && <Trend value={trendDelta} label="vs last" />}
          </div>
        ))}
      </div>

      {/* Score trend + scan frequency */}
      <div className="an-row an-row-wide-left">

        {/* Area chart */}
        <div style={cardStyle}>
          {shine}
          <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', marginBottom:'20px' }}>
            <div>
              <div style={{ fontSize:'14px', fontWeight:'700', color:'var(--t1)' }}>Security Score Trend</div>
              <div style={{ fontSize:'12px', color:'var(--t3)', marginTop:'2px' }}>Last {trendData.length} completed scans</div>
            </div>
            {trendDelta != null && (
              <div style={{ textAlign:'right' }}>
                <Trend value={trendDelta} label="since last scan" />
              </div>
            )}
          </div>
          <AreaChart data={trendData} />
          {trendData.length < 2 && (
            <div style={{ marginTop:'16px', textAlign:'center' }}>
              <button className="btn-primary" onClick={() => navigate('/new-scan')} style={{ fontSize:'12px', padding:'7px 16px' }}>
                {trendData.length === 0 ? 'Run your first scan →' : 'Run another scan →'}
              </button>
            </div>
          )}
        </div>

        {/* Scan frequency spark */}
        <div style={cardStyle}>
          {shine}
          <div style={{ fontSize:'14px', fontWeight:'700', color:'var(--t1)', marginBottom:'4px' }}>Scan Activity</div>
          <div style={{ fontSize:'12px', color:'var(--t3)', marginBottom:'20px' }}>Last 30 days</div>
          <SparkBar values={last30} />
          <div style={{ marginTop:'14px', fontSize:'11px', color:'var(--t3)', display:'flex', justifyContent:'space-between' }}>
            <span>30d ago</span><span>Today</span>
          </div>
          <div style={{ marginTop:'16px', display:'flex', gap:'8px' }}>
            <div style={{ flex:1, background:'var(--s2)', border:'1px solid var(--b1)', borderRadius:'8px', padding:'10px 12px', textAlign:'center' }}>
              <div style={{ fontSize:'18px', fontWeight:'800', color:'var(--blue)' }}>{last30.reduce((a,v) => a + v, 0)}</div>
              <div style={{ fontSize:'10px', color:'var(--t3)', marginTop:'2px' }}>Scans run</div>
            </div>
            <div style={{ flex:1, background:'var(--s2)', border:'1px solid var(--b1)', borderRadius:'8px', padding:'10px 12px', textAlign:'center' }}>
              <div style={{ fontSize:'18px', fontWeight:'800', color:'#16a34a' }}>{Math.max(...last30)}</div>
              <div style={{ fontSize:'10px', color:'var(--t3)', marginTop:'2px' }}>Peak day</div>
            </div>
          </div>
        </div>
      </div>

      {/* Risk distribution + Category heatmap */}
      <div className="an-row an-row-wide-right">

        {/* Donut */}
        <div style={cardStyle}>
          {shine}
          <div style={{ fontSize:'14px', fontWeight:'700', color:'var(--t1)', marginBottom:'4px' }}>Risk Distribution</div>
          <div style={{ fontSize:'12px', color:'var(--t3)', marginBottom:'20px' }}>Total findings by severity</div>
          {totalFindings === 0 ? (
            <div style={{ display:'flex', alignItems:'center', justifyContent:'center', height:'120px', color:'var(--t3)', fontSize:'13px' }}>
              No findings yet
            </div>
          ) : (
            <div style={{ display:'flex', alignItems:'center', gap:'24px' }}>
              <DonutChart segments={riskDist} size={110} />
              <div style={{ flex:1, display:'flex', flexDirection:'column', gap:'8px' }}>
                {riskDist.map(r => (
                  <div key={r.label} style={{ display:'flex', alignItems:'center', gap:'8px' }}>
                    <div style={{ width:'8px', height:'8px', borderRadius:'50%', background:r.color, flexShrink:0 }} />
                    <div style={{ flex:1, fontSize:'12px', color:'var(--t2)' }}>{r.label}</div>
                    <div style={{ fontSize:'12px', fontWeight:'700', color:r.color }}>{r.pct}%</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Category heatmap */}
        <div style={cardStyle}>
          {shine}
          <div style={{ fontSize:'14px', fontWeight:'700', color:'var(--t1)', marginBottom:'4px' }}>Weakest categories</div>
          <div style={{ fontSize:'12px', color:'var(--t3)', marginBottom:'16px' }}>Share of attacks that succeeded in each category, across all your scans</div>
          {catEntries.length === 0 ? (
            <div style={{ display:'flex', alignItems:'center', justifyContent:'center', height:'100px', color:'var(--t3)', fontSize:'13px' }}>No findings recorded yet</div>
          ) : (
            <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(120px, 1fr))', gap:'6px' }}>
              {catEntries.slice(0, 15).map(c => (
                <HeatCell key={c.id} label={c.title} count={c.failed} rate={c.rate} />
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Score distribution bar */}
      {completed.length > 0 && (
        <div style={cardStyle}>
          {shine}
          <div style={{ fontSize:'14px', fontWeight:'700', color:'var(--t1)', marginBottom:'4px' }}>Score Distribution</div>
          <div style={{ fontSize:'12px', color:'var(--t3)', marginBottom:'20px' }}>How many scans fell in each score range</div>
          <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(110px, 1fr))', gap:'8px' }}>
            {[
              { label:'0–49 · grade F',  color:'#dc2626', bg:'rgba(248,113,113,0.12)', range:[0,49] },
              { label:'50–69 · grade D', color:'#b45309', bg:'rgba(250,204,21,0.12)', range:[50,69] },
              { label:'70–79 · grade C', color:'#b45309', bg:'rgba(250,204,21,0.12)', range:[70,79] },
              { label:'80–89 · grade B', color:'#16a34a', bg:'rgba(74,222,128,0.12)', range:[80,89] },
              { label:'90–100 · grade A',color:'#16a34a', bg:'rgba(74,222,128,0.12)', range:[90,100] },
            ].map(bucket => {
              const count = completed.filter(s => {
                const sc = s.summary.security_score;
                return sc >= bucket.range[0] && sc <= bucket.range[1];
              }).length;
              const pct = completed.length > 0 ? Math.round((count / completed.length) * 100) : 0;
              return (
                <div key={bucket.label} style={{ background: count ? bucket.bg : 'transparent', border:`1px solid ${bucket.color}30`, borderRadius:'10px', padding:'16px 14px', textAlign:'center', minWidth:0 }}>
                  <div style={{ fontSize:'22px', fontWeight:'800', color: count ? bucket.color : 'var(--t3)', letterSpacing:'-0.5px' }}>{count}</div>
                  <div style={{ fontSize:'11px', color:'var(--t3)', marginTop:'3px', lineHeight:'1.4' }}>{bucket.label}</div>
                  <div style={{ height:'4px', background:'var(--s2)', borderRadius:'2px', marginTop:'10px', overflow:'hidden' }}>
                    <div style={{ width:`${pct}%`, height:'100%', background:bucket.color, transition:'width 0.8s ease' }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Empty state CTA */}
      {completed.length === 0 && (
        <div style={{ ...cardStyle, textAlign:'center', padding:'60px 40px' }}>
          {shine}
          <div style={{ fontSize:'40px', marginBottom:'16px' }}>📊</div>
          <h3 style={{ fontSize:'18px', fontWeight:'700', marginBottom:'8px' }}>No data yet</h3>
          <p style={{ color:'var(--t3)', fontSize:'14px', marginBottom:'24px' }}>Run your first scan to start seeing analytics.</p>
          <button className="btn-primary" onClick={() => navigate('/new-scan')}>Launch First Scan →</button>
        </div>
      )}
    </div>
  );
}
