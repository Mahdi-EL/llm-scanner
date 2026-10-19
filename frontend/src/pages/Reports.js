import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { scansAPI, downloadReport, errorMessage } from '../services/api';
import { useToast } from '../context/ToastContext';
import { riskLabel } from '../utils/format';

const SEV_COLOR = { CRITICAL:'#dc2626', HIGH:'#ea580c', MEDIUM:'#b45309', LOW:'#16a34a' };

function relTime(ts) {
  const d = (Date.now() - new Date(ts)) / 1000;
  if (d < 60)     return `${Math.floor(d)}s ago`;
  if (d < 3600)   return `${Math.floor(d/60)}m ago`;
  if (d < 86400)  return `${Math.floor(d/3600)}h ago`;
  if (d < 604800) return `${Math.floor(d/86400)}d ago`;
  return new Date(ts).toLocaleDateString('en-US', { month:'short', day:'numeric', year:'numeric' });
}

function ScoreBar({ score }) {
  if (score == null) return <span style={{ color:'var(--t3)' }}>—</span>;
  const color = score >= 80 ? '#16a34a' : score >= 50 ? '#b45309' : '#dc2626';
  return (
    <div style={{ display:'flex', alignItems:'center', gap:'8px' }}>
      <div style={{ flex:1, height:'4px', background:'var(--s3)', borderRadius:'4px', overflow:'hidden', minWidth:'48px' }}>
        <div style={{ height:'100%', width:`${score}%`, background:color, borderRadius:'4px', transition:'width 0.6s ease' }} />
      </div>
      <span style={{ fontSize:'12px', fontWeight:'700', color, fontVariantNumeric:'tabular-nums', minWidth:'30px' }}>{score}</span>
    </div>
  );
}

function RiskBadge({ score }) {
  if (score == null) return null;
  const label = riskLabel(score);
  const color = score >= 80 ? '#16a34a' : score >= 50 ? '#b45309' : '#dc2626';
  const bg    = score >= 80 ? 'rgba(74,222,128,0.1)' : score >= 50 ? 'rgba(250,204,21,0.1)' : 'rgba(248,113,113,0.1)';
  return (
    <span style={{ background:bg, color, border:`1px solid ${color}30`, borderRadius:'20px', padding:'2px 9px', fontSize:'11px', fontWeight:'700', letterSpacing:'0.3px', whiteSpace:'nowrap' }}>
      {label}
    </span>
  );
}

function LetterAvatar({ name }) {
  const initials = name.slice(0,2).toUpperCase();
  const hue = name.charCodeAt(0) * 37 % 360;
  return (
    <div style={{
      width:'34px', height:'34px', borderRadius:'9px', flexShrink:0,
      background:`linear-gradient(135deg, hsl(${hue},60%,35%), hsl(${(hue+40)%360},60%,25%))`,
      display:'flex', alignItems:'center', justifyContent:'center',
      fontSize:'12px', fontWeight:'800', color:'#fff', letterSpacing:'0.5px',
    }}>
      {initials}
    </div>
  );
}

const RISK_FILTERS = [
  { key:'ALL',       label:'All' },
  { key:'LOW RISK',  label:'Low Risk' },
  { key:'MODERATE',  label:'Moderate' },
  { key:'HIGH RISK', label:'High Risk' },
];

export default function Reports() {
  const [scans,   setScans]   = useState([]);
  const [loading, setLoading] = useState(true);
  const [search,  setSearch]  = useState('');
  const [filter,  setFilter]  = useState('ALL');
  const [sortBy,  setSortBy]  = useState('date'); // date | score | name
  const [sortDir, setSortDir] = useState('desc');
  const navigate = useNavigate();
  const toast    = useToast();

  useEffect(() => {
    (async () => {
      try {
        const res = await scansAPI.list({ status: 'complete' });
        setScans(res.data.scans);
      } catch (e) {
        toast(errorMessage(e, 'Couldn\u2019t load your reports.'), 'error');
      }
      finally { setLoading(false); }
    })();
  }, []);

  const completed = useMemo(() => scans.filter(s => s.status === 'complete'), [scans]);

  const stats = useMemo(() => {
    const totalCritical = completed.reduce((a,s) => a + (s.summary?.critical || 0), 0);
    const totalHigh     = completed.reduce((a,s) => a + (s.summary?.high || 0), 0);
    const scores        = completed.map(s => s.summary?.security_score).filter(Boolean);
    const avgScore      = scores.length ? Math.round(scores.reduce((a,b)=>a+b,0)/scores.length) : null;
    const lowRisk       = completed.filter(s => (s.summary?.security_score||0) >= 80).length;
    const highRisk      = completed.filter(s => (s.summary?.security_score||0) < 50).length;
    return { totalCritical, totalHigh, avgScore, lowRisk, highRisk };
  }, [completed]);

  const filtered = useMemo(() => {
    let list = completed.filter(s => {
      const score  = s.summary?.security_score;
      const nameOk = s.target_name.toLowerCase().includes(search.toLowerCase());
      if (!nameOk) return false;
      if (filter === 'ALL')      return true;
      if (filter === 'LOW RISK') return score >= 80;
      if (filter === 'MODERATE') return score >= 50 && score < 80;
      if (filter === 'HIGH RISK')return score < 50;
      return true;
    });

    list = [...list].sort((a, b) => {
      let va, vb;
      if (sortBy === 'score') {
        va = a.summary?.security_score ?? -1;
        vb = b.summary?.security_score ?? -1;
      } else if (sortBy === 'name') {
        va = a.target_name.toLowerCase();
        vb = b.target_name.toLowerCase();
        return sortDir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
      } else {
        va = new Date(a.created_at).getTime();
        vb = new Date(b.created_at).getTime();
      }
      return sortDir === 'asc' ? va - vb : vb - va;
    });

    return list;
  }, [completed, search, filter, sortBy, sortDir]);

  const toggleSort = (col) => {
    if (sortBy === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortBy(col); setSortDir('desc'); }
  };

  const SortIcon = ({ col }) => {
    if (sortBy !== col) return <span style={{ opacity:0.3, fontSize:'10px', marginLeft:'3px' }}>↕</span>;
    return <span style={{ fontSize:'10px', marginLeft:'3px', color:'var(--blue)' }}>{sortDir === 'asc' ? '↑' : '↓'}</span>;
  };

  const scoreColor = stats.avgScore >= 80 ? '#16a34a' : stats.avgScore >= 50 ? '#b45309' : stats.avgScore != null ? '#dc2626' : 'var(--t3)';

  return (
    <div>
      {/* Header */}
      <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', marginBottom:'28px' }}>
        <div>
          <h1 className="page-title">Reports</h1>
          <p className="page-subtitle" style={{ marginBottom:0 }}>All completed scan reports — view findings or download PDF</p>
        </div>
        <button className="btn-primary" onClick={() => navigate('/new-scan')} style={{ marginTop:'4px', flexShrink:0 }}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          New Scan
        </button>
      </div>

      {/* Stats row */}
      <div className="stats-row" style={{ marginBottom:'24px' }}>
        {[
          {
            label:'Total Reports', value: completed.length, color:'var(--t1)', icon:(
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            ),
          },
          {
            label:'Avg Score', value: stats.avgScore != null ? `${stats.avgScore}/100` : '—', color: scoreColor, icon:(
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            ),
          },
          {
            label:'Critical Findings', value: stats.totalCritical, color: stats.totalCritical > 0 ? '#dc2626' : 'var(--t3)', icon:(
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            ),
          },
          {
            label:'Low Risk Scans', value: stats.lowRisk, color:'#16a34a', icon:(
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><polyline points="20 6 9 17 4 12"/></svg>
            ),
          },
        ].map(s => (
          <div key={s.label} className="stat-card-glow" style={{ display:'flex', flexDirection:'column', gap:'10px' }}>
            <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between' }}>
              <div style={{ color:'var(--t3)' }}>{s.icon}</div>
            </div>
            <div className="stat-number" style={{ color:s.color, fontSize:'28px', fontWeight:'800' }}>{s.value}</div>
            <div className="stat-label">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Score distribution */}
      {completed.length > 0 && (
        <div className="card-glow" style={{ padding:'18px 24px', marginBottom:'16px', display:'flex', gap:'12px 32px', alignItems:'center', flexWrap:'wrap' }}>
          <div style={{ fontSize:'13px', fontWeight:'700', color:'var(--t2)', whiteSpace:'nowrap' }}>Score distribution</div>
          <div style={{ flex:'1 1 160px', display:'flex', gap:'4px', height:'6px', borderRadius:'6px', overflow:'hidden' }}>
            {['LOW RISK','MODERATE','HIGH RISK'].map(r => {
              const cnt = r === 'LOW RISK' ? stats.lowRisk : r === 'HIGH RISK' ? stats.highRisk : completed.length - stats.lowRisk - stats.highRisk;
              const pct = completed.length ? (cnt / completed.length) * 100 : 0;
              const color = r === 'LOW RISK' ? '#16a34a' : r === 'MODERATE' ? '#b45309' : '#dc2626';
              return pct > 0 ? <div key={r} style={{ height:'100%', width:`${pct}%`, background:color }} /> : null;
            })}
          </div>
          <div style={{ display:'flex', gap:'8px 16px', flexWrap:'wrap' }}>
            {[['#16a34a','Low Risk',stats.lowRisk],['#b45309','Moderate',completed.length-stats.lowRisk-stats.highRisk],['#dc2626','High Risk',stats.highRisk]].map(([c,l,v])=>(
              <div key={l} style={{ display:'flex', alignItems:'center', gap:'6px', fontSize:'12px', color:'var(--t3)' }}>
                <div style={{ width:'8px', height:'8px', borderRadius:'2px', background:c }} />
                <span>{l}</span>
                <span style={{ color:'var(--t2)', fontWeight:'700' }}>{v}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Table card */}
      <div className="card-glow" style={{ overflow:'hidden' }}>
        {/* Toolbar */}
        <div style={{ padding:'14px 20px', borderBottom:'1px solid var(--b1)', display:'flex', alignItems:'center', gap:'12px', flexWrap:'wrap' }}>
          <div style={{ position:'relative', flex:1, minWidth:'180px', maxWidth:'280px' }}>
            <input
              className="search-bar"
              style={{ marginBottom:0, height:'34px', fontSize:'13px', paddingLeft:'38px', backgroundPosition:'12px center' }}
              aria-label="Search reports by target" placeholder="Search by target…"
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
          <div style={{ display:'flex', gap:'4px', flexWrap:'wrap' }}>
            {RISK_FILTERS.map(f => (
              <button key={f.key} className={`filter-btn${filter === f.key ? ' active' : ''}`} onClick={() => setFilter(f.key)} style={{ padding:'5px 12px', fontSize:'12px' }}>
                {f.label}
              </button>
            ))}
          </div>
          <div style={{ marginLeft:'auto', fontSize:'12px', color:'var(--t3)' }}>
            {filtered.length} report{filtered.length !== 1 ? 's' : ''}
          </div>
        </div>

        {loading ? (
          <div style={{ padding:'60px', textAlign:'center' }}>
            <div className="spinner" style={{ width:'20px', height:'20px', margin:'0 auto' }} />
            <p style={{ color:'var(--t3)', marginTop:'14px', fontSize:'13px' }}>Loading reports…</p>
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty-state" style={{ padding:'64px' }}>
            <div className="empty-state-icon">{search ? '🔍' : '📄'}</div>
            <h3>{search ? 'No results match your search' : 'No reports yet'}</h3>
            <p>{search ? `Nothing found for "${search}"` : 'Complete a scan to generate your first security report.'}</p>
            {!search && <button className="btn-primary" onClick={() => navigate('/new-scan')}>Launch First Scan</button>}
          </div>
        ) : (
          <div className="table-scroll"><div style={{ minWidth:'900px' }}>
            {/* Column headers */}
            <div style={{ display:'grid', gridTemplateColumns:'minmax(200px,2fr) 120px 160px 64px 64px 110px 130px', alignItems:'center', padding:'9px 20px', borderBottom:'1px solid var(--b1)', fontSize:'11px', fontWeight:'700', color:'var(--t3)', textTransform:'uppercase', letterSpacing:'0.6px' }}>
              <button onClick={() => toggleSort('name')} style={{ background:'none', border:'none', cursor:'pointer', color:'var(--t3)', textAlign:'left', padding:0, fontSize:'inherit', fontWeight:'inherit', letterSpacing:'inherit', textTransform:'inherit' }}>
                Target <SortIcon col="name" />
              </button>
              <span>Risk</span>
              <button onClick={() => toggleSort('score')} style={{ background:'none', border:'none', cursor:'pointer', color:'var(--t3)', textAlign:'left', padding:0, fontSize:'inherit', fontWeight:'inherit', letterSpacing:'inherit', textTransform:'inherit' }}>
                Score <SortIcon col="score" />
              </button>
              <span>Crit</span>
              <span>High</span>
              <button onClick={() => toggleSort('date')} style={{ background:'none', border:'none', cursor:'pointer', color:'var(--t3)', textAlign:'left', padding:0, fontSize:'inherit', fontWeight:'inherit', letterSpacing:'inherit', textTransform:'inherit' }}>
                Date <SortIcon col="date" />
              </button>
              <span></span>
            </div>

            {filtered.map(scan => {
              const sum   = scan.summary || {};
              const score = sum.security_score;
              return (
                <div
                  key={scan.scan_id}
                  style={{ display:'grid', gridTemplateColumns:'minmax(200px,2fr) 120px 160px 64px 64px 110px 130px', alignItems:'center', padding:'14px 20px', borderBottom:'1px solid var(--b1)', cursor:'pointer', transition:'background 0.12s' }}
                  onClick={() => navigate(`/results/${scan.scan_id}`)}
                  onMouseEnter={e => e.currentTarget.style.background='rgba(17,24,39,0.025)'}
                  onMouseLeave={e => e.currentTarget.style.background='transparent'}
                >
                  <div style={{ display:'flex', alignItems:'center', gap:'12px', minWidth:0 }}>
                    <LetterAvatar name={scan.target_name} />
                    <div style={{ minWidth:0 }}>
                      <div style={{ fontWeight:'600', fontSize:'14px', color:'var(--t1)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{scan.target_name}</div>
                      <div style={{ fontSize:'11px', color:'var(--t3)', marginTop:'2px', fontFamily:'monospace' }}>{scan.scan_id?.slice(0,8)}…</div>
                    </div>
                  </div>
                  <div><RiskBadge score={score} /></div>
                  <div><ScoreBar score={score} /></div>
                  <div style={{ color:sum.critical > 0 ? SEV_COLOR.CRITICAL : 'var(--t3)', fontWeight:'700', fontSize:'14px' }}>{sum.critical ?? '—'}</div>
                  <div style={{ color:sum.high > 0 ? SEV_COLOR.HIGH : 'var(--t3)', fontWeight:'700', fontSize:'14px' }}>{sum.high ?? '—'}</div>
                  <div style={{ color:'var(--t3)', fontSize:'12px' }}>{relTime(scan.created_at)}</div>
                  <div style={{ display:'flex', gap:'6px' }} onClick={e => e.stopPropagation()}>
                    <button
                      className="btn-outline"
                      style={{ padding:'5px 12px', fontSize:'12px' }}
                      onClick={() => navigate(`/results/${scan.scan_id}`)}
                    >
                      View
                    </button>
                    <button
                      className="btn-ghost"
                      style={{ padding:'5px 10px', fontSize:'12px', display:'flex', alignItems:'center', gap:'4px' }}
                      onClick={async () => {
                        try { await downloadReport(scan.scan_id, 'pdf'); }
                        catch (e) { toast(errorMessage(e, 'Download failed.'), 'error'); }
                      }}
                    >
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                      PDF
                    </button>
                  </div>
                </div>
              );
            })}
          </div></div>
        )}
      </div>
    </div>
  );
}
