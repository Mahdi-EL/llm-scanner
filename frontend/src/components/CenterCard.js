import React from 'react';

/* A centered card for small standalone pages (email confirmation, errors). */
export default function CenterCard({ title, subtitle, children }) {
  return (
    <div style={{ minHeight:'calc(100vh - 60px)', display:'flex', alignItems:'center', justifyContent:'center', background:'var(--bg)', padding:'48px 24px' }}>
      <div style={{ background:'var(--s1)', border:'1px solid var(--b1)', borderRadius:'12px', padding:'40px', width:'100%', maxWidth:'440px', textAlign:'center' }}>
        {title && <h1 style={{ fontSize:'22px', fontWeight:'800', letterSpacing:'-0.4px', marginBottom:'8px' }}>{title}</h1>}
        {subtitle && <p style={{ fontSize:'14px', color:'var(--t2)', lineHeight:1.6, marginBottom:'20px' }}>{subtitle}</p>}
        {children}
      </div>
    </div>
  );
}
