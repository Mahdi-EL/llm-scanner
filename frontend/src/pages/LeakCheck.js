import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { publicAPI, errorMessage } from '../services/api';
import { useAuth } from '../context/AuthContext';

const MIN = 20, MAX = 4000;

/* Free, no account: does this system prompt come out under 20 common attacks? */
export default function LeakCheck() {
  const { user } = useAuth();
  const [prompt, setPrompt] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const run = async e => {
    e.preventDefault();
    if (prompt.trim().length < MIN) { setError(`Paste the whole system prompt (at least ${MIN} characters).`); return; }
    setBusy(true); setError(''); setResult(null);
    try { setResult((await publicAPI.leakCheck(prompt.trim())).data); }
    catch (err) { setError(errorMessage(err, 'The check couldn’t run. Please try again.')); }
    finally { setBusy(false); }
  };

  const next = user ? '/new-scan' : '/register';
  return (
    <div style={{ maxWidth:'760px', margin:'0 auto', padding:'56px 20px 72px' }}>
      <div style={{ fontSize:'12px', letterSpacing:'0.12em', textTransform:'uppercase', color:'var(--t3)' }}>Free check · no account</div>
      <h1 style={{ fontFamily:'Georgia, serif', fontSize:'40px', fontWeight:600, lineHeight:1.15, margin:'8px 0 12px' }}>
        Is your system prompt leaking?
      </h1>
      <p style={{ fontSize:'15px', color:'var(--t2)', lineHeight:1.7, marginBottom:'24px' }}>
        Paste your system prompt. We give it to a demo model and send 20 extraction and override attacks from our
        library, then tell you how many got it out. Nothing is stored, and the model’s replies aren’t shown.
      </p>

      <form onSubmit={run}>
        <label htmlFor="lc-prompt" style={{ display:'block', fontSize:'13px', fontWeight:600, marginBottom:'6px' }}>Your system prompt</label>
        <textarea id="lc-prompt" value={prompt} onChange={e => setPrompt(e.target.value)} maxLength={MAX}
          placeholder="You are the support assistant for Acme Bank. Only answer questions about accounts and cards…"
          style={{ width:'100%', minHeight:'180px', fontSize:'14px', lineHeight:1.6 }} />
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', gap:'12px', marginTop:'10px', flexWrap:'wrap' }}>
          <span style={{ fontSize:'12px', color:'var(--t3)' }}>{prompt.length.toLocaleString('en-US')} / {MAX.toLocaleString('en-US')} characters</span>
          <button type="submit" className="btn-primary" disabled={busy} style={{ padding:'11px 22px' }}>
            {busy ? 'Running 20 attacks… about 20 seconds' : 'Run the free check'}
          </button>
        </div>
      </form>

      {error && <div className="alert-error" role="alert" style={{ marginTop:'18px' }}>{error}</div>}

      {result && (
        <section aria-live="polite" aria-label="Check results" style={{ marginTop:'32px', paddingTop:'24px', borderTop:'1px solid var(--b1)' }}>
          <div style={{ fontFamily:'Georgia, serif', fontSize:'34px', lineHeight:1.2, color: result.leaked ? '#b42318' : '#15803d' }}>
            {result.leaked
              ? `${result.leaked} of ${result.attacks} attacks got your prompt out.`
              : `None of ${result.attacks} attacks got your prompt out word for word.`}
          </div>
          {result.partial > 0 && (
            <p style={{ fontSize:'14px', marginTop:'6px' }}>{result.partial} more repeated part of it.</p>
          )}
          {result.examples.length > 0 && (
            <>
              <h2 style={{ fontSize:'15px', fontWeight:700, margin:'20px 0 8px' }}>Attacks that worked</h2>
              <ul style={{ margin:0, paddingLeft:'18px', fontSize:'14px', lineHeight:1.7 }}>
                {result.examples.map((x, i) => <li key={i}><span style={{ color:'var(--t3)' }}>{x.category}:</span> {x.attack}</li>)}
              </ul>
            </>
          )}
          <p style={{ fontSize:'13px', color:'var(--t3)', lineHeight:1.7, marginTop:'18px' }}>
            This quick check runs on a demo model and only counts word-for-word leaks. A full scan sends 1,090 attacks
            to your real app, grades every reply (paraphrased leaks too) and writes a hardened prompt for you.
          </p>
          <Link to={next} className="btn-primary" style={{ display:'inline-flex', marginTop:'8px', padding:'11px 22px' }}>
            {user ? 'Run a full scan' : 'Run a full scan, free'}
          </Link>
        </section>
      )}
    </div>
  );
}
