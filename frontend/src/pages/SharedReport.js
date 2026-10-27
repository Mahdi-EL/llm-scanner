import React, { useEffect, useMemo, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { scansAPI } from '../services/api';
import { scoreColor, shortDate } from '../utils/format';
import CenterCard from '../components/CenterCard';

const SEV_COLORS = { CRITICAL:'#b42318', HIGH:'#c4320a', MEDIUM:'#a15c07', LOW:'#4b6b2f', SAFE:'#3d6b4f', ERROR:'#6b6b6b' };

/* A read-only report opened from a share link. No account needed. */
export default function SharedReport() {
  const { token } = useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState(false);
  const [showAll, setShowAll] = useState(false);

  useEffect(() => {
    scansAPI.shared(token).then(r => setData(r.data)).catch(e => setError(e?.response?.status === 404 ? 'gone' : 'other'));
  }, [token]);

  // Worst first, alternating categories within a severity, so the first page has an example of each problem.
  const failed = useMemo(() => {
    const rank = { CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3 };
    const seen = {};
    return (data?.results || [])
      .filter(r => !['SAFE','ERROR'].includes(r.severity))
      .sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9) || (b.score || 0) - (a.score || 0))
      .map((r, i) => { const k = r.severity + '|' + r.category; seen[k] = (seen[k] || 0) + 1; return { r, i, turn: seen[k] }; })
      .sort((a, b) => (rank[a.r.severity] ?? 9) - (rank[b.r.severity] ?? 9) || a.turn - b.turn || a.i - b.i)
      .map(x => x.r);
  }, [data]);

  if (error === 'other') return (
    <CenterCard title="Couldn’t load this report" subtitle="Check your connection and try again in a moment.">
      <button className="btn-outline" onClick={() => window.location.reload()}>Try again</button>
    </CenterCard>
  );
  if (error) return (
    <CenterCard title="This link no longer works" subtitle="It expired, or the owner stopped sharing this report. Ask them for a new link.">
      <Link to="/" className="btn-outline" style={{ display:'inline-flex' }}>About LLM Scanner</Link>
    </CenterCard>
  );
  if (!data) return <CenterCard title="Loading report…" />;

  const s = data.summary;
  const list = showAll ? failed : failed.slice(0, 30);

  return (
    <div style={{ maxWidth:'880px', margin:'0 auto', padding:'48px 20px 64px' }}>
      <div style={{ fontSize:'12px', letterSpacing:'0.12em', textTransform:'uppercase', color:'var(--t3)' }}>{data.brand || 'LLM Scanner'} · shared report</div>
      <h1 style={{ fontFamily:'Georgia, serif', fontSize:'34px', fontWeight:600, margin:'6px 0', overflowWrap:'anywhere' }}>{data.target_name}</h1>
      <div style={{ fontSize:'13px', color:'var(--t3)' }}>Scanned {data.created_at ? new Date(data.created_at).toLocaleString('en-US', { dateStyle:'long', timeStyle:'short' }) : data.scan_date} · {s.tested} attacks graded{data.expires_at && <> · Link expires {shortDate(data.expires_at, true)}</>}</div>

      <div style={{ display:'flex', gap:'32px', alignItems:'flex-end', margin:'28px 0 8px', flexWrap:'wrap' }}>
        <div>
          <div style={{ fontFamily:'Georgia, serif', fontSize:'64px', lineHeight:1, color: scoreColor(s.security_score) }}>{s.security_score}</div>
          <div style={{ fontSize:'12px', color:'var(--t3)' }}>Security score / 100</div>
        </div>
        <div style={{ fontFamily:'Georgia, serif', fontSize:'34px', color: scoreColor(s.security_score) }}>Grade {s.grade}</div>
        <div style={{ display:'flex', gap:'18px' }}>
          {['critical','high','medium','low','safe'].map(k => (
            <div key={k}>
              <div style={{ fontFamily:'Georgia, serif', fontSize:'24px', color: SEV_COLORS[k.toUpperCase()] }}>{s[k]}</div>
              <div style={{ fontSize:'11px', color:'var(--t3)', textTransform:'capitalize' }}>{k}</div>
            </div>
          ))}
        </div>
      </div>

      <h2 style={{ fontFamily:'Georgia, serif', fontSize:'22px', fontWeight:600, marginTop:'36px', paddingTop:'14px', borderTop:'1px solid var(--b1)' }}>What to fix first</h2>
      {data.recommendations.length === 0 ? <p style={{ fontSize:'14px' }}>No attack succeeded.</p> : data.recommendations.map((r, i, all) => (
        <div key={r.category} style={{ padding:'12px 0', borderBottom: i < all.length - 1 ? '1px solid var(--b1)' : 'none' }}>
          <div style={{ fontWeight:700, fontSize:'14px' }}>{r.priority} · {r.title} <span style={{ color:'var(--t3)', fontWeight:400, fontSize:'12px' }}>{r.failed} failed</span></div>
          <div style={{ fontSize:'12px', color:'var(--t3)', margin:'2px 0 4px' }}>{r.owasp.join(' · ')}</div>
          <ul style={{ margin:0, paddingLeft:'18px', fontSize:'13px', lineHeight:1.6 }}>{r.fix.map((t, i) => <li key={i}>{t}</li>)}</ul>
        </div>
      ))}

      <h2 style={{ fontFamily:'Georgia, serif', fontSize:'22px', fontWeight:600, marginTop:'36px', paddingTop:'14px', borderTop:'1px solid var(--b1)' }}>Failed attacks ({failed.length})</h2>
      {list.map((r, i) => (
        <details key={i} style={{ borderBottom:'1px solid var(--b1)', padding:'8px 0' }}>
          <summary style={{ cursor:'pointer', fontSize:'13px', overflowWrap:'anywhere' }}>
            <strong style={{ color: SEV_COLORS[r.severity], marginRight:'10px' }}>{r.severity}</strong>{r.attack.slice(0, 120)}
          </summary>
          <pre className="finding-pre" tabIndex={0} style={{ marginTop:'8px' }}>{r.response}</pre>
          <p style={{ fontSize:'13px', margin:'8px 0 0' }}>{r.reason}</p>
        </details>
      ))}
      {failed.length > list.length && <button className="btn-outline" style={{ marginTop:'12px' }} onClick={() => setShowAll(true)}>Show all {failed.length}</button>}

      <p style={{ fontSize:'12px', color:'var(--t3)', marginTop:'40px' }}>
        {data.brand
          ? <>Prepared by {data.brand}. This is a read-only copy shared by the scan’s owner.</>
          : <>Generated by <Link to="/">LLM Scanner</Link>. This is a read-only copy shared by the scan’s owner.</>}
      </p>
    </div>
  );
}
