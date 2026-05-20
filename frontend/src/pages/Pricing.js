import React, { useState } from 'react';
import { Link } from 'react-router-dom';

const PLANS = [
  {
    id      : 'starter',
    name    : 'Starter',
    price   : 49,
    scans   : '5 scans / month',
    desc    : 'Perfect for individual developers validating AI security.',
    color   : 'var(--t2)',
    features: [
      '1000+ attack prompts per scan',
      '21 vulnerability categories',
      'Full PDF security report',
      'JSON results export',
      'Email support',
    ],
    cta : 'Get Started',
  },
  {
    id      : 'pro',
    name    : 'Pro',
    price   : 99,
    scans   : '50 scans / month',
    desc    : 'For teams shipping AI products that need continuous assurance.',
    color   : 'var(--blue)',
    popular : true,
    features: [
      'Everything in Starter',
      'Custom system prompts',
      'AI attack generator',
      'Priority scan queue',
      'REST API access',
      'Priority support',
    ],
    cta : 'Start Free Trial',
  },
  {
    id      : 'agency',
    name    : 'Agency',
    price   : 299,
    scans   : 'Unlimited scans',
    desc    : 'For security teams and agencies running assessments at scale.',
    color   : 'var(--purple)',
    features: [
      'Everything in Pro',
      'White-label PDF reports',
      'Team member seats',
      'Custom branding',
      'Webhook integrations',
      'Dedicated support',
    ],
    cta : 'Contact Sales',
  },
];

const FAQS = [
  { q:'Is there a free trial?',           a:'Yes — all paid plans come with a 7-day free trial. No credit card required to start.' },
  { q:'What counts as one scan?',          a:'One scan fires 1000+ adversarial prompts across 21 attack categories at a single AI target and generates a full security report. Partial scans are never counted.' },
  { q:'Can I scan production AI apps?',    a:'Yes, with explicit written authorization from the owner. We include a legal compliance guide with every plan.' },
  { q:'How long does a scan take?',        a:'Typically 10–15 minutes for a complete assessment across all 21 attack categories.' },
  { q:'What LLMs are supported?',          a:'Any OpenAI-compatible API, Groq, custom REST endpoints, and our built-in simulation mode for safe development testing.' },
  { q:'Can I cancel anytime?',             a:'Absolutely. No long-term contracts. Cancel from your dashboard — your access continues until the end of the billing period.' },
];

function FAQ({ q, a }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{
      borderBottom:'1px solid var(--b1)',
      transition:'border-color 0.15s',
    }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width:'100%', padding:'20px 0',
          display:'flex', alignItems:'center', justifyContent:'space-between', gap:'16px',
          background:'none', border:'none', cursor:'pointer', textAlign:'left',
        }}
      >
        <span style={{ fontSize:'15px', fontWeight:'600', color:'var(--t1)', lineHeight:'1.4' }}>{q}</span>
        <div style={{
          width:'24px', height:'24px', flexShrink:0,
          background:'var(--s2)', border:'1px solid var(--b1)',
          borderRadius:'6px', display:'flex', alignItems:'center', justifyContent:'center',
          transition:'background 0.15s',
        }}>
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none" style={{ transform:open?'rotate(45deg)':'none', transition:'transform 0.2s' }}>
            <path d="M6 2v8M2 6h8" stroke="var(--t2)" strokeWidth="1.5" strokeLinecap="round"/>
          </svg>
        </div>
      </button>
      {open && (
        <p style={{ color:'var(--t2)', fontSize:'14px', lineHeight:'1.7', paddingBottom:'20px' }}>{a}</p>
      )}
    </div>
  );
}

export default function Pricing() {
  return (
    <div style={{ maxWidth:'1200px', margin:'0 auto' }}>

      {/* ── Header ──────────────────────────────── */}
      <div style={{ textAlign:'center', padding:'56px 24px 72px' }}>
        <div style={{ display:'inline-flex', alignItems:'center', gap:'8px', border:'1px solid var(--b2)', borderRadius:'20px', padding:'5px 14px', fontSize:'11px', fontWeight:'600', textTransform:'uppercase', letterSpacing:'1px', color:'var(--blue)', marginBottom:'24px', background:'var(--blue-soft)' }}>
          Simple pricing
        </div>
        <h1 style={{ fontSize:'56px', fontWeight:'900', letterSpacing:'-3px', lineHeight:'1.05', marginBottom:'18px' }}>
          Start free.<br />
          <span style={{ background:'linear-gradient(135deg, var(--blue), var(--purple))', WebkitBackgroundClip:'text', WebkitTextFillColor:'transparent', backgroundClip:'text' }}>
            Scale with confidence.
          </span>
        </h1>
        <p style={{ fontSize:'17px', color:'var(--t2)', maxWidth:'460px', margin:'0 auto', lineHeight:'1.65' }}>
          No hidden fees. No complex tiers. Cancel anytime.
        </p>
      </div>

      {/* ── Plans ───────────────────────────────── */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:'16px', marginBottom:'96px', padding:'0 16px' }}>
        {PLANS.map(plan => (
          <div key={plan.id} style={{
            background   : plan.popular ? 'var(--s2)' : 'var(--s1)',
            border       : `1px solid ${plan.popular ? 'rgba(74,138,244,0.35)' : 'var(--b1)'}`,
            borderRadius : '16px',
            padding      : '32px',
            position     : 'relative',
            overflow     : 'hidden',
            transform    : plan.popular ? 'scale(1.03)' : 'scale(1)',
            boxShadow    : plan.popular ? '0 8px 40px rgba(74,138,244,0.12)' : 'none',
            transition   : 'transform 0.2s, box-shadow 0.2s',
          }}
            onMouseEnter={e => { if (!plan.popular) { e.currentTarget.style.transform='translateY(-4px)'; e.currentTarget.style.borderColor='var(--b2)'; e.currentTarget.style.boxShadow='var(--sh)'; } }}
            onMouseLeave={e => { if (!plan.popular) { e.currentTarget.style.transform='none'; e.currentTarget.style.borderColor='var(--b1)'; e.currentTarget.style.boxShadow='none'; } }}
          >
            {/* Top gradient line */}
            <div style={{ position:'absolute', top:0, left:0, right:0, height:'2px', background:`linear-gradient(90deg, transparent, ${plan.color}, transparent)` }} />

            {plan.popular && (
              <div style={{
                position:'absolute', top:'18px', right:'18px',
                background:'var(--blue-soft)', border:'1px solid rgba(74,138,244,0.3)',
                color:'var(--blue)', padding:'3px 10px', borderRadius:'20px',
                fontSize:'10px', fontWeight:'700', letterSpacing:'0.5px', textTransform:'uppercase',
              }}>Most Popular</div>
            )}

            {/* Plan name */}
            <div style={{ fontSize:'13px', fontWeight:'700', textTransform:'uppercase', letterSpacing:'0.8px', color:plan.color, marginBottom:'12px' }}>
              {plan.name}
            </div>

            {/* Price */}
            <div style={{ display:'flex', alignItems:'baseline', gap:'4px', marginBottom:'6px' }}>
              <span style={{ fontSize:'52px', fontWeight:'900', letterSpacing:'-3px', lineHeight:'1', color:'var(--t1)' }}>€{plan.price}</span>
              <span style={{ fontSize:'14px', color:'var(--t3)', fontWeight:'500' }}>/mo</span>
            </div>

            <div style={{ fontSize:'13px', color:plan.color, fontWeight:'600', marginBottom:'8px' }}>{plan.scans}</div>
            <p style={{ fontSize:'13px', color:'var(--t3)', lineHeight:'1.5', marginBottom:'28px', paddingBottom:'24px', borderBottom:'1px solid var(--b1)' }}>
              {plan.desc}
            </p>

            {/* Features */}
            <ul style={{ listStyle:'none', marginBottom:'32px', display:'flex', flexDirection:'column', gap:'10px' }}>
              {plan.features.map((f, i) => (
                <li key={i} style={{ display:'flex', alignItems:'flex-start', gap:'10px', fontSize:'14px', color:'var(--t2)' }}>
                  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" style={{ flexShrink:0, marginTop:'2px' }}>
                    <circle cx="8" cy="8" r="7" fill={`${plan.color}20`} />
                    <path d="M5 8l2 2 4-4" stroke={plan.color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                  {f}
                </li>
              ))}
            </ul>

            {/* CTA */}
            <Link to="/register" style={{
              display      : 'block',
              textAlign    : 'center',
              padding      : '13px',
              borderRadius : '8px',
              fontSize     : '14px',
              fontWeight   : '700',
              transition   : 'all 0.15s',
              textDecoration: 'none',
              background   : plan.popular ? 'var(--blue)' : 'transparent',
              color        : plan.popular ? '#fff' : 'var(--t1)',
              border       : `1px solid ${plan.popular ? 'rgba(74,138,244,0.5)' : 'var(--b2)'}`,
              boxShadow    : plan.popular ? '0 2px 12px rgba(74,138,244,0.3)' : 'none',
            }}
              onMouseEnter={e => { e.target.style.opacity='0.85'; e.target.style.transform='translateY(-1px)'; }}
              onMouseLeave={e => { e.target.style.opacity='1';    e.target.style.transform='none'; }}
            >
              {plan.cta} →
            </Link>
          </div>
        ))}
      </div>

      {/* ── Comparison note ─────────────────────── */}
      <div style={{ textAlign:'center', marginBottom:'80px', padding:'0 16px' }}>
        <p style={{ fontSize:'13px', color:'var(--t3)' }}>
          All plans include a 7-day free trial · No credit card required · Cancel anytime
        </p>
      </div>

      {/* ── FAQ ─────────────────────────────────── */}
      <div style={{ maxWidth:'680px', margin:'0 auto', padding:'0 16px', marginBottom:'80px' }}>
        <div style={{ textAlign:'center', marginBottom:'48px' }}>
          <div style={{ fontSize:'11px', fontWeight:'700', textTransform:'uppercase', letterSpacing:'1.5px', color:'var(--blue)', marginBottom:'14px' }}>FAQ</div>
          <h2 style={{ fontSize:'36px', fontWeight:'900', letterSpacing:'-1.5px' }}>Common questions.</h2>
        </div>
        {FAQS.map((item, i) => <FAQ key={i} {...item} />)}
      </div>

      {/* ── Bottom CTA ──────────────────────────── */}
      <div style={{
        background  : 'var(--s1)',
        border      : '1px solid var(--b1)',
        borderRadius: '20px',
        padding     : '64px 48px',
        textAlign   : 'center',
        marginBottom: '56px',
        position    : 'relative',
        overflow    : 'hidden',
      }}>
        <div style={{ position:'absolute', inset:0, background:'radial-gradient(ellipse 60% 60% at 50% 0%, rgba(74,138,244,0.06) 0%, transparent 60%)', pointerEvents:'none' }} />
        <h2 style={{ fontSize:'40px', fontWeight:'900', letterSpacing:'-2px', lineHeight:'1.1', marginBottom:'14px' }}>
          Ready to secure your<br />AI application?
        </h2>
        <p style={{ fontSize:'16px', color:'var(--t2)', marginBottom:'36px', maxWidth:'400px', margin:'0 auto 36px', lineHeight:'1.65' }}>
          Start for free. Full report on your first scan. No credit card needed.
        </p>
        <div style={{ display:'flex', gap:'12px', justifyContent:'center', flexWrap:'wrap' }}>
          <Link to="/register" className="btn-hero btn-hero-primary" style={{ fontSize:'15px', padding:'13px 32px' }}>
            Start free today →
          </Link>
          <Link to="/login" className="btn-hero btn-hero-ghost" style={{ fontSize:'15px', padding:'13px 32px' }}>
            Sign in
          </Link>
        </div>
      </div>

    </div>
  );
}
