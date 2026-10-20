import React from 'react';

/* Shown instead of a page's content when its data couldn't be loaded, so a network
   problem never looks like "you have nothing here". */
export default function LoadError({ title, what, onRetry }) {
  return (
    <div>
      <h1 className="page-title">{title}</h1>
      <div className="card-glow" role="alert" style={{ padding:'14px 18px', marginTop:'16px', display:'flex', alignItems:'center', justifyContent:'space-between', gap:'12px', flexWrap:'wrap' }}>
        <span style={{ fontSize:'13px', color:'#b42318' }}>Couldn’t load {what}. Check your connection; the server may be waking up.</span>
        <button className="btn-outline" style={{ padding:'5px 12px', fontSize:'12px' }} onClick={onRetry}>Retry</button>
      </div>
    </div>
  );
}
