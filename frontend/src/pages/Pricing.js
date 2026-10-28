import React, { useEffect, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { plansAPI, errorMessage } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';

const ORDER = ['free', 'pro', 'enterprise'];
const RANK = { free: 0, pro: 1, enterprise: 2 };

const DESCRIPTIONS = {
  free      : 'Try the scanner on your own AI apps.',
  pro       : 'For teams that ship AI features and re-test every change.',
  enterprise: 'For security teams scanning many applications.',
};

const FAQS = [
  { q:'What counts as one scan?', a:'One scan sends every selected attack prompt (about 1,090 when you pick all 22 categories) to one target and produces a full report. A scan that fails or is cancelled before its first attack doesn’t count toward your monthly limit. A quick scan (about 110 attacks) and a re-test of the failed attacks also count as one scan each, and deleting a scan doesn’t give it back.' },
  { q:'How long does a scan take?', a:'It depends on how fast your target answers. Each attack is one call to your target plus one grading call. A quick scan (about 110 attacks) takes a few minutes; you can also pick fewer categories.' },
  { q:'Which AI apps can I scan?', a:'Any OpenAI-compatible API (OpenAI, Azure OpenAI, Together, Groq and others), your own Groq models, custom REST endpoints, and a simulation mode that tests a system prompt without a live API.' },
  { q:'Can I scan production apps?', a:'Only apps you own or are explicitly authorized to test. Scans send real adversarial prompts and use your target’s API quota.' },
  { q:'How do I cancel?', a:'From Settings → Manage billing. Stripe handles the subscription; your plan returns to Free when it ends.' },
];

function money(amount, currency) {
  return new Intl.NumberFormat('en', { style:'currency', currency: currency || 'eur', maximumFractionDigits: amount % 100 ? 2 : 0 }).format(amount / 100);
}

function FAQ({ q, a }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ borderBottom:'1px solid var(--b1)' }}>
      <button onClick={() => setOpen(o => !o)} aria-expanded={open}
        style={{ width:'100%', padding:'18px 0', display:'flex', justifyContent:'space-between', gap:'16px', background:'none', border:'none', cursor:'pointer', textAlign:'left', fontFamily:'inherit' }}>
        <span style={{ fontSize:'15px', fontWeight:'600', color:'var(--t1)' }}>{q}</span>
        <span style={{ color:'var(--t3)' }}>{open ? '−' : '+'}</span>
      </button>
      {open && <p style={{ color:'var(--t2)', fontSize:'14px', lineHeight:1.7, paddingBottom:'18px' }}>{a}</p>}
    </div>
  );
}

export default function Pricing() {
  const { user, role } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [plans, setPlans] = useState(null);
  const [busy, setBusy] = useState('');
  const [yearly, setYearly] = useState(false);

  // a yearly subscriber sees yearly prices first
  useEffect(() => { if (user?.billing_interval === 'year') setYearly(true); }, [user?.billing_interval]);

  useEffect(() => {
    plansAPI.list().then(r => setPlans(r.data.plans)).catch(() => setPlans({}));
    if (params.get('payment') === 'cancelled') toast('Checkout cancelled. You haven’t been charged.', 'info');
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const choose = async key => {
    if (!user) { navigate('/register'); return; }
    setBusy(key);
    try {
      const { data } = await plansAPI.checkout(key, yearly && plans[key]?.yearly ? 'year' : 'month');
      window.location.assign(data.url);
    } catch (e) {
      toast(errorMessage(e, 'Checkout is unavailable right now.'), 'error');
      setBusy('');
    }
  };

  const cta = (key, plan) => {
    if (user?.plan === key) {
      // the same plan, billed the other way: the subscription moves to that price (prorated)
      const interval = yearly && plan.yearly ? 'year' : 'month';
      const other = key !== 'free' && plan.purchasable && plan.yearly && user.billing_interval
        && user.billing_interval !== interval;
      if (!other) return { label:'Your current plan', disabled:true };
      if (role !== 'owner') return { label:'Only the workspace’s owner can change the plan', disabled:true };
      return { label: interval === 'year' ? 'Switch to yearly billing' : 'Switch to monthly billing', onClick: () => choose(key) };
    }
    if (key === 'free') return user ? null : { label:'Start free', onClick: () => navigate('/register') };
    if (!plan.purchasable) return { label:'Not available yet', disabled:true };
    if (!user) return { label:`Start with ${plan.name}`, onClick: () => choose(key) };
    if (role !== 'owner') return { label:'Only the workspace’s owner can change the plan', disabled:true };
    // A paying customer moves their subscription to the other plan (prorated) rather than buying a second one
    const up = (RANK[key] ?? 0) > (RANK[user.plan] ?? 0);
    return { label: `${up ? 'Upgrade' : 'Switch'} to ${plan.name}`, onClick: () => choose(key) };
  };

  const list = plans ? ORDER.filter(k => plans[k]).map(k => [k, plans[k]]) : [];
  const hasYearly = list.some(([, p]) => p.yearly);
  // Stripe gives one trial per customer: someone who has paid before doesn't get another
  const trialEligible = !user?.has_billing;
  const shown = plan => (yearly && plan.yearly ? plan.yearly : plan);
  const yearlySaving = plan => plan.yearly && plan.amount
    ? Math.round(100 - (plan.yearly.amount / (plan.amount * 12)) * 100) : 0;

  return (
    <div style={{ maxWidth:'1080px', margin:'0 auto', padding:'0 16px' }}>
      <div style={{ textAlign:'center', padding:'56px 0 48px' }}>
        <h1 style={{ fontFamily:'Georgia, serif', fontSize:'48px', fontWeight:600, letterSpacing:'-1px', lineHeight:1.1, marginBottom:'14px' }}>
          {hasYearly ? 'Simple pricing' : 'Simple, monthly pricing'}
        </h1>
        <p style={{ fontSize:'16px', color:'var(--t2)', maxWidth:'520px', margin:'0 auto', lineHeight:1.6 }}>
          Every plan tests all 22 attack categories and produces PDF, HTML and Markdown reports. Paid plans add more scans, team seats, scheduled scans, evidence reports, your brand on reports and the AI firewall.
        </p>
        {hasYearly && (
          <div role="group" aria-label="Billing period" style={{ display:'inline-flex', marginTop:'24px', border:'1px solid var(--b1)', borderRadius:'8px', padding:'3px' }}>
            {[['Monthly', false], ['Yearly', true]].map(([label, value]) => (
              <button key={label} type="button" aria-pressed={yearly === value} onClick={() => setYearly(value)}
                style={{ padding:'7px 16px', border:'none', borderRadius:'6px', cursor:'pointer', fontFamily:'inherit', fontSize:'13px',
                         background: yearly === value ? 'var(--t1)' : 'transparent', color: yearly === value ? 'var(--s1)' : 'var(--t2)' }}>
                {label}
              </button>
            ))}
          </div>
        )}
      </div>

      {!plans ? (
        <p style={{ textAlign:'center', color:'var(--t3)' }}>Loading plans…</p>
      ) : list.length === 0 ? (
        <p style={{ textAlign:'center', color:'var(--t3)' }}>Plans couldn’t be loaded. Please try again later.</p>
      ) : (
        <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(260px, 1fr))', gap:'16px', marginBottom:'72px' }}>
          {list.map(([key, plan]) => {
            const action = cta(key, plan);
            const featured = key === 'pro';
            return (
              <div key={key} style={{ background:'var(--s1)', border:`1px solid ${featured ? 'var(--t1)' : 'var(--b1)'}`, borderRadius:'12px', padding:'28px', display:'flex', flexDirection:'column' }}>
                <div style={{ fontSize:'13px', fontWeight:'700', textTransform:'uppercase', letterSpacing:'0.8px', marginBottom:'10px' }}>{plan.name}</div>
                <div style={{ display:'flex', alignItems:'baseline', gap:'4px', marginBottom:'6px' }}>
                  <span style={{ fontFamily:'Georgia, serif', fontSize:'44px', lineHeight:1 }}>{plan.amount ? money(shown(plan).amount, shown(plan).currency) : 'Free'}</span>
                  {plan.amount > 0 && <span style={{ fontSize:'14px', color:'var(--t3)' }}>/ {shown(plan).interval}</span>}
                </div>
                {yearly && plan.yearly && yearlySaving(plan) > 0 && (
                  <div style={{ fontSize:'12px', color:'var(--t3)', marginBottom:'6px' }}>
                    {money(Math.round(plan.yearly.amount / 12), plan.yearly.currency)} a month, {yearlySaving(plan)}% less than monthly
                  </div>
                )}
                <div style={{ fontSize:'13px', fontWeight:'600', marginBottom:'6px' }}>
                  {plan.scan_limit == null ? 'Unlimited scans' : `${plan.scan_limit} scans per month`}
                </div>
                {plan.trial_days > 0 && trialEligible && <div style={{ fontSize:'12px', color:'#16a34a', marginBottom:'6px' }}>{plan.trial_days}-day free trial</div>}
                <p style={{ fontSize:'13px', color:'var(--t3)', lineHeight:1.5, paddingBottom:'18px', borderBottom:'1px solid var(--b1)', marginBottom:'18px' }}>{DESCRIPTIONS[key]}</p>
                <ul style={{ listStyle:'none', padding:0, margin:'0 0 24px', display:'grid', gap:'8px', flex:1, alignContent:'start' }}>
                  {plan.features.map(f => <li key={f} style={{ fontSize:'14px', color:'var(--t2)' }}>✓ {f}</li>)}
                </ul>
                {action && (
                  <button onClick={action.onClick} disabled={action.disabled || busy === key}
                    className={featured && !action.disabled ? 'btn-primary' : 'btn-outline'}
                    style={{ width:'100%', justifyContent:'center', padding:'12px' }}>
                    {busy === key ? 'Opening checkout…' : action.label}
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}

      <div style={{ maxWidth:'680px', margin:'0 auto 72px' }}>
        <h2 style={{ fontFamily:'Georgia, serif', fontSize:'30px', fontWeight:600, textAlign:'center', marginBottom:'24px' }}>Questions</h2>
        {FAQS.map(item => <FAQ key={item.q} {...item} />)}
      </div>

      {!user && (
        <div style={{ textAlign:'center', marginBottom:'56px' }}>
          <Link to="/register" className="btn-hero btn-hero-primary" style={{ fontSize:'15px', padding:'13px 32px' }}>Create a free account</Link>
        </div>
      )}
    </div>
  );
}
