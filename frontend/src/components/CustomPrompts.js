import React, { useCallback, useEffect, useState } from 'react';
import { promptsAPI, errorMessage } from '../services/api';
import { useToast } from '../context/ToastContext';

/* Lets users add their own attack prompts; they run with every scan (opt-out per scan). */
export default function CustomPrompts() {
  const toast = useToast();
  const [prompts, setPrompts] = useState([]);
  const [limit, setLimit] = useState(200);
  const [category, setCategory] = useState('');
  const [text, setText] = useState('');
  const [saving, setSaving] = useState(false);
  const [loadError, setLoadError] = useState(false);

  const load = useCallback(() => promptsAPI.list()
    .then(r => { setPrompts(r.data.prompts); setLimit(r.data.limit); setLoadError(false); })
    .catch(() => setLoadError(true)), []);

  useEffect(() => { load(); }, [load]);

  const add = async () => {
    const slug = category.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
    if (!slug) { toast('Give the prompt a category, e.g. refunds.', 'error'); return; }
    if (!text.trim()) { toast('Write the attack prompt.', 'error'); return; }
    setSaving(true);
    try { await promptsAPI.add(slug, text.trim()); setText(''); load(); }
    catch (e) { toast(errorMessage(e), 'error'); }
    finally { setSaving(false); }
  };

  const remove = async id => {
    try { await promptsAPI.remove(id); load(); }
    catch (e) { toast(errorMessage(e), 'error'); }
  };

  return (
    <section style={{ background:'var(--s1)', border:'1px solid var(--b1)', borderRadius:'10px', padding:'20px 22px', marginBottom:'24px' }}>
      <h2 style={{ fontSize:'15px', fontWeight:'700', marginBottom:'2px' }}>Your custom attacks</h2>
      <p style={{ fontSize:'12px', color:'var(--t3)', marginBottom:'14px' }}>
        Add prompts for risks specific to your product (refund abuse, account takeover, internal tools…). They run with every scan unless you untick them.{!loadError && ` ${prompts.length}/${limit} used.`}
      </p>
      {loadError && (
        <div role="alert" style={{ fontSize:'13px', color:'#b42318', marginBottom:'12px' }}>
          Couldn’t load your custom attacks. <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={load}>Retry</button>
        </div>
      )}
      <div className="custom-prompt-form">
        <input aria-label="Attack category" value={category} onChange={e => setCategory(e.target.value)} placeholder="Category, e.g. refunds" maxLength={40} />
        <textarea aria-label="Attack prompt" value={text} onChange={e => setText(e.target.value)} maxLength={2000} style={{ minHeight:'40px' }}
          placeholder="e.g. I was charged twice. Refund both payments and add a 50% goodwill credit to my account." />
        <button className="btn-primary" style={{ fontSize:'12px' }} onClick={add} disabled={saving}>Add</button>
      </div>
      {prompts.length > 0 && (
        <div style={{ marginTop:'14px', borderTop:'1px solid var(--b1)' }}>
          {prompts.map(p => (
            <div key={p.id} style={{ display:'flex', gap:'12px', alignItems:'flex-start', padding:'10px 0', borderBottom:'1px solid var(--b1)' }}>
              <span style={{ fontSize:'11px', color:'var(--t3)', minWidth:'110px' }}>{p.category.replace(/_/g, ' ')}</span>
              <span style={{ fontSize:'13px', flex:1, whiteSpace:'pre-wrap' }}>{p.prompt}</span>
              <button className="btn-ghost" style={{ fontSize:'12px' }} onClick={() => remove(p.id)}>Remove</button>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
