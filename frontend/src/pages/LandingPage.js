import React from 'react';
import { Link } from 'react-router-dom';

/* ── Data ─────────────────────────────────────────────────── */
const FEATURES = [
  { num:'01', icon:'🎯', title:'Prompt Injection Detection',   desc:'Automatically tests your AI against 30+ prompt injection variants designed to hijack system instructions and bypass safety filters.' },
  { num:'02', icon:'🔓', title:'Jailbreak & Policy Bypass',    desc:'Stress-tests your LLM against known jailbreak techniques — DAN, roleplay, encoding tricks — and measures resistance across all attempts.' },
  { num:'03', icon:'📡', title:'Data Exfiltration Testing',    desc:'Simulates adversarial prompts designed to extract sensitive data, PII, system prompts, or confidential information from your AI application.' },
  { num:'04', icon:'📊', title:'Automated Security Reports',   desc:'Every scan generates a full security report with severity scores, per-attack analysis, risk heatmaps, and actionable remediation guidance.' },
  { num:'05', icon:'⚡', title:'Any LLM, Any Infrastructure', desc:'Works with OpenAI, Groq, Anthropic, or any custom REST endpoint. Run real tests or safe simulations during development.' },
  { num:'06', icon:'🔄', title:'Continuous Re-scanning',       desc:'Schedule recurring scans to catch security regressions as your prompts evolve. Stay ahead of new attack techniques automatically.' },
];

const TRUST_STATS = [
  { num:'1000+', label:'Adversarial attack prompts per scan' },
  { num:'21',    label:'Vulnerability categories covered' },
  { num:'<15m', label:'Average time for a full assessment' },
];

const PREVIEW_ATTACKS = [
  { name:'Prompt Injection',    count:24, color:'#f87171' },
  { name:'Jailbreak Attempts',  count:18, color:'#fb923c' },
  { name:'Data Exfiltration',   count:15, color:'#facc15' },
  { name:'Policy Bypass',       count:12, color:'#4ade80' },
];

const ATTACK_PILLS = [
  { label:'Prompt Injection',         cls:'danger' },
  { label:'Jailbreak Attempts',       cls:'warn'   },
  { label:'Data Exfiltration',        cls:'danger' },
  { label:'Policy Bypass',            cls:'accent' },
  { label:'Role-play Exploits',       cls:'warn'   },
  { label:'Context Poisoning',        cls:'danger' },
  { label:'PII Extraction',           cls:'warn'   },
  { label:'Instruction Hijacking',    cls:'danger' },
  { label:'System Prompt Leakage',    cls:''       },
  { label:'Encoding Tricks',          cls:'warn'   },
  { label:'Indirect Injection',       cls:'danger' },
  { label:'Token Smuggling',          cls:'accent' },
  { label:'Adversarial Suffixes',     cls:'warn'   },
  { label:'Multi-turn Manipulation',  cls:'danger' },
  { label:'Goal Hijacking',           cls:'accent' },
  { label:'Refusal Bypass',           cls:'warn'   },
];
const PILLS_DOUBLED = [...ATTACK_PILLS, ...ATTACK_PILLS];

const INTEGRATIONS = [
  { icon:'🤖', name:'OpenAI'      },
  { icon:'⚡', name:'Groq'        },
  { icon:'◈',  name:'Anthropic'   },
  { icon:'🔌', name:'Custom REST' },
  { icon:'🧪', name:'Simulation'  },
  { icon:'⊕',  name:'Any LLM API' },
];

const COMPARE = [
  { feature:'Attack coverage',       manual:'Limited by analyst hours', scanner:'1000+ prompts, 21 categories'   },
  { feature:'Time to first result',  manual:'2 – 4 weeks',              scanner:'< 15 minutes'             },
  { feature:'Report generation',     manual:'Manual write-up',          scanner:'Auto PDF + JSON export'   },
  { feature:'Cost per assessment',   manual:'$5,000 – $25,000',         scanner:'From $49 / month'         },
  { feature:'Scan frequency',        manual:'Quarterly at best',        scanner:'Unlimited / on-demand'    },
  { feature:'Consistency',           manual:'Varies by analyst',        scanner:'100% reproducible results'},
];

const TESTIMONIALS = [
  {
    quote: "LLM Scanner caught prompt injection vulnerabilities in our customer service bot that our internal team missed completely. The report was ready in 12 minutes.",
    name : 'Sarah K.', role : 'Security Lead @ Fintech Startup', init:'SK',
  },
  {
    quote: "We ran our first scan before I even finished my coffee. The PDF report was detailed enough to share directly with our board without extra work.",
    name : 'Marcus R.', role : 'CTO @ AI SaaS Company', init:'MR',
  },
  {
    quote: "Simulation mode is perfect for testing during development before we have a production API key. The attack coverage is impressively thorough.",
    name : 'Priya N.', role : 'ML Engineer @ Healthcare AI', init:'PN',
  },
];

/* ── Component ────────────────────────────────────────────── */
export default function LandingPage() {
  return (
    <div className="landing">

      {/* ═══════════════════════════════════════
          HERO
      ═══════════════════════════════════════ */}
      <section className="hero">
        <div className="hero-bg" />
        <div className="hero-grid" />
        <div className="hero-noise" />

        <div className="hero-inner">
          <div className="hero-left">
            <div className="hero-tag fade-up">
              <span className="hero-tag-dot" />
              AI Security Platform — 2025
            </div>

            <h1 className="hero-title fade-up-d1">
              Secure Your<br />
              <span className="hero-title-gradient">AI Before<br />They Do.</span>
            </h1>

            <p className="hero-sub fade-up-d2">
              Automated red-teaming for LLM applications.
              Detect prompt injections, jailbreaks, and data
              exfiltration vulnerabilities in minutes — not months.
            </p>

            <div className="hero-ctas fade-up-d3">
              <Link to="/register" className="btn-hero btn-hero-primary">
                Start for free →
              </Link>
              <Link to="/login" className="btn-hero btn-hero-ghost">
                Sign in
              </Link>
            </div>

            <div className="hero-trust fade-up-d4">
              {TRUST_STATS.map(s => (
                <div key={s.num} className="hero-trust-item">
                  <span className="hero-trust-num">{s.num}</span>
                  <span className="hero-trust-label">{s.label}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Animated preview card */}
          <div className="hero-preview fade-up-d2">
            <div className="preview-card">
              <div className="preview-header">
                <div className="preview-dot" style={{ background:'#ef4444' }} />
                <div className="preview-dot" style={{ background:'#f59e0b' }} />
                <div className="preview-dot" style={{ background:'#22c55e' }} />
                <span className="preview-title">Live Scan — Banking AI Chatbot</span>
                <span style={{ marginLeft:'auto', display:'flex', alignItems:'center', gap:'5px' }}>
                  <span style={{ width:'6px', height:'6px', borderRadius:'50%', background:'var(--blue)', display:'inline-block', boxShadow:'0 0 6px var(--blue)', animation:'pulse-glow 1.8s ease-in-out infinite' }} />
                  <span style={{ fontSize:'10px', color:'rgba(74,138,244,0.9)', fontWeight:'700' }}>Running</span>
                </span>
              </div>
              <div className="preview-body">
                <div>
                  <div className="preview-progress-label">Attack progress — 68 / 85 prompts</div>
                  <div className="preview-progress-track"><div className="preview-progress-fill" /></div>
                </div>
                <div className="preview-attacks">
                  {PREVIEW_ATTACKS.map(a => (
                    <div key={a.name} className="preview-attack-row">
                      <span className="preview-attack-name">{a.name}</span>
                      <span className="preview-attack-count" style={{ color:a.color }}>{a.count} tested</span>
                    </div>
                  ))}
                </div>
                <div style={{ display:'flex', gap:'7px', paddingTop:'4px', borderTop:'1px solid rgba(255,255,255,0.05)' }}>
                  {[
                    { n:7, label:'Critical', c:'#f87171', bg:'rgba(240,68,56,0.1)',   bo:'rgba(240,68,56,0.15)' },
                    { n:12,label:'High',     c:'#fb923c', bg:'rgba(251,146,60,0.08)', bo:'rgba(251,146,60,0.15)' },
                    { n:'34%',label:'Score', c:'#4a8af4', bg:'rgba(74,138,244,0.08)', bo:'rgba(74,138,244,0.15)' },
                  ].map(s => (
                    <div key={s.label} style={{ flex:1, background:s.bg, border:`1px solid ${s.bo}`, borderRadius:'6px', padding:'10px 12px' }}>
                      <div style={{ fontSize:'18px', fontWeight:'800', color:s.c, letterSpacing:'-0.5px' }}>{s.n}</div>
                      <div style={{ fontSize:'10px', color:'rgba(255,255,255,0.3)', textTransform:'uppercase', letterSpacing:'0.5px', marginTop:'2px' }}>{s.label}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ═══════════════════════════════════════
          ATTACK TICKER
      ═══════════════════════════════════════ */}
      <div style={{ borderTop:'1px solid var(--b1)', borderBottom:'1px solid var(--b1)', background:'var(--s1)', padding:'20px 0' }}>
        <div className="marquee-outer">
          <div className="marquee-track">
            {PILLS_DOUBLED.map((p, i) => (
              <div key={i} className={`marquee-pill${p.cls ? ' ' + p.cls : ''}`}>{p.label}</div>
            ))}
          </div>
        </div>
      </div>

      {/* ═══════════════════════════════════════
          INTEGRATIONS
      ═══════════════════════════════════════ */}
      <div style={{ padding:'52px 80px', borderBottom:'1px solid var(--b1)' }}>
        <div style={{ maxWidth:'1200px', margin:'0 auto', textAlign:'center' }}>
          <p style={{ fontSize:'11px', fontWeight:'700', textTransform:'uppercase', letterSpacing:'1.2px', color:'var(--t3)', marginBottom:'28px' }}>
            Works with any AI infrastructure
          </p>
          <div className="integrations-row">
            {INTEGRATIONS.map(i => (
              <div key={i.name} className="integration-badge">
                <span style={{ fontSize:'16px' }}>{i.icon}</span>
                <span>{i.name}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ═══════════════════════════════════════
          FEATURES
      ═══════════════════════════════════════ */}
      <section className="section">
        <div style={{ maxWidth:'1200px', margin:'0 auto' }}>
          <div className="section-eyebrow">Capabilities</div>
          <h2 className="section-title">Everything you need to<br />test AI security.</h2>
          <p className="section-sub">
            A complete security testing suite built specifically for large language model
            applications — from rapid prototyping to enterprise deployments.
          </p>
          <div className="features-grid">
            {FEATURES.map(f => (
              <div key={f.num} className="feature-card">
                <div className="feature-num">{f.num}</div>
                <div className="feature-icon-wrap">{f.icon}</div>
                <h3 className="feature-title">{f.title}</h3>
                <p className="feature-desc">{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════════════════════════════════════
          HOW IT WORKS
      ═══════════════════════════════════════ */}
      <section className="section section-dark">
        <div style={{ maxWidth:'1200px', margin:'0 auto' }}>
          <div className="section-eyebrow">Process</div>
          <h2 className="section-title">Up and running in minutes.</h2>
          <p className="section-sub">No complex setup. No integrations required to start.</p>

          <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:'1px', background:'rgba(255,255,255,0.06)', border:'1px solid rgba(255,255,255,0.06)', borderRadius:'16px', overflow:'hidden' }}>
            {[
              { step:'01', icon:'🎯', title:'Connect your target',  desc:'Enter a name and choose your AI target — simulation mode works instantly, or point to any LLM API.' },
              { step:'02', icon:'🔥', title:'We run the gauntlet',  desc:'1000+ adversarial prompts fire automatically across 21 attack categories. Zero manual effort required.' },
              { step:'03', icon:'📋', title:'Get your full report', desc:'A detailed security report with scores, per-finding analysis, severity breakdown, and PDF download — in under 15 minutes.' },
            ].map((s, i) => (
              <div key={s.step} style={{ background:'var(--s2)', padding:'40px 36px', position:'relative' }}>
                {i < 2 && (
                  <div style={{ position:'absolute', top:'50px', right:'-12px', width:'24px', height:'24px', background:'var(--s3)', border:'1px solid var(--b2)', borderRadius:'50%', display:'flex', alignItems:'center', justifyContent:'center', zIndex:1 }}>
                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="var(--t3)" strokeWidth="2" strokeLinecap="round"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
                  </div>
                )}
                <div style={{ display:'flex', alignItems:'center', gap:'12px', marginBottom:'24px' }}>
                  <div style={{ width:'36px', height:'36px', background:'rgba(74,138,244,0.12)', border:'1px solid rgba(74,138,244,0.2)', borderRadius:'8px', display:'flex', alignItems:'center', justifyContent:'center', fontSize:'16px' }}>{s.icon}</div>
                  <span style={{ fontSize:'11px', fontWeight:'700', color:'rgba(255,255,255,0.18)', letterSpacing:'1px', textTransform:'uppercase' }}>Step {s.step}</span>
                </div>
                <h3 style={{ fontSize:'18px', fontWeight:'800', letterSpacing:'-0.4px', color:'var(--t1)', marginBottom:'10px' }}>{s.title}</h3>
                <p style={{ fontSize:'14px', color:'var(--t2)', lineHeight:'1.65' }}>{s.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════════════════════════════════════
          STATS
      ═══════════════════════════════════════ */}
      <section className="section section-dark">
        <div style={{ maxWidth:'1200px', margin:'0 auto' }}>
          <div className="section-eyebrow">By the numbers</div>
          <h2 className="section-title">Built for serious security.</h2>
          <div className="stats-landing">
            <div className="stat-landing">
              <div className="stat-landing-num">1000+</div>
              <div className="stat-landing-label">Adversarial attack prompts across 21 attack categories</div>
            </div>
            <div className="stat-landing">
              <div className="stat-landing-num">&lt;15m</div>
              <div className="stat-landing-label">Average time to complete a full security assessment</div>
            </div>
            <div className="stat-landing">
              <div className="stat-landing-num">∞</div>
              <div className="stat-landing-label">Scans on any LLM — OpenAI, Groq, or your own API</div>
            </div>
          </div>
        </div>
      </section>

      {/* ═══════════════════════════════════════
          VS MANUAL TESTING
      ═══════════════════════════════════════ */}
      <section className="section">
        <div style={{ maxWidth:'1200px', margin:'0 auto' }}>
          <div className="section-eyebrow">Why LLM Scanner</div>
          <h2 className="section-title">vs. Manual Pen Testing.</h2>
          <p className="section-sub">
            Get the coverage of a full red-team engagement in a fraction of the time and cost.
            No waiting weeks for a consultant's availability.
          </p>
          <div className="compare-wrap">
            <div className="compare-head">
              <div className="compare-head-cell" style={{ color:'var(--t3)' }}>Category</div>
              <div className="compare-head-cell" style={{ color:'var(--t3)' }}>Manual Pen Testing</div>
              <div className="compare-head-cell" style={{ color:'var(--blue)' }}>
                <span style={{ display:'flex', alignItems:'center', gap:'6px' }}>
                  🔐 LLM Scanner
                </span>
              </div>
            </div>
            {COMPARE.map((row, i) => (
              <div key={i} className="compare-row">
                <div className="compare-cell feat">{row.feature}</div>
                <div className="compare-cell">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--t3)" strokeWidth="2" strokeLinecap="round" style={{ flexShrink:0 }}>
                    <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                  </svg>
                  {row.manual}
                </div>
                <div className="compare-cell win">
                  <div className="compare-win-dot">✓</div>
                  {row.scanner}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════════════════════════════════════
          TESTIMONIALS
      ═══════════════════════════════════════ */}
      <section className="section section-dark">
        <div style={{ maxWidth:'1200px', margin:'0 auto' }}>
          <div className="section-eyebrow">Social Proof</div>
          <h2 className="section-title">Trusted by security teams.</h2>
          <p className="section-sub">
            Engineers and security leads use LLM Scanner to catch AI vulnerabilities
            before their users — or attackers — do.
          </p>
          <div className="testimonials-grid">
            {TESTIMONIALS.map(t => (
              <div key={t.name} className="testimonial-card">
                <p className="testimonial-quote">{t.quote}</p>
                <div className="testimonial-author">
                  <div className="testimonial-avatar">{t.init}</div>
                  <div>
                    <div className="testimonial-name">{t.name}</div>
                    <div className="testimonial-role">{t.role}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════════════════════════════════════
          CTA
      ═══════════════════════════════════════ */}
      <section className="cta-section">
        <div style={{ display:'inline-flex', alignItems:'center', gap:'8px', background:'rgba(255,255,255,0.04)', border:'1px solid var(--b2)', borderRadius:'20px', padding:'5px 16px', fontSize:'11px', fontWeight:'600', textTransform:'uppercase', letterSpacing:'1px', color:'var(--t2)', marginBottom:'8px' }}>
          <span style={{ width:'6px', height:'6px', borderRadius:'50%', background:'var(--green)', boxShadow:'0 0 6px var(--green)' }} />
          No credit card required
        </div>
        <h2 className="cta-title">
          Start securing your<br /><span>AI applications</span><br />today.
        </h2>
        <p className="cta-sub">Free to start. Full report on your first scan. No setup needed.</p>
        <div className="cta-buttons">
          <Link to="/register" className="btn-hero btn-hero-primary">Create free account →</Link>
          <Link to="/pricing"  className="btn-hero btn-hero-ghost">View pricing</Link>
        </div>
      </section>

      {/* ═══════════════════════════════════════
          FOOTER
      ═══════════════════════════════════════ */}
      <footer className="landing-footer">
        <div style={{ display:'flex', alignItems:'center', gap:'10px' }}>
          <div style={{ width:'22px', height:'22px', background:'rgba(74,138,244,0.1)', border:'1px solid rgba(74,138,244,0.25)', borderRadius:'5px', display:'flex', alignItems:'center', justifyContent:'center', fontSize:'10px' }}>🔐</div>
          <span className="footer-brand">LLM Scanner © 2025</span>
        </div>
        <div className="footer-links">
          <Link to="/pricing"  className="footer-link">Pricing</Link>
          <Link to="/login"    className="footer-link">Sign In</Link>
          <Link to="/register" className="footer-link">Get Started</Link>
        </div>
      </footer>

    </div>
  );
}
