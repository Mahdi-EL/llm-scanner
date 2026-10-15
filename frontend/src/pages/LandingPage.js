import React from 'react';
import { Link } from 'react-router-dom';
import { useInView, useCountUp } from '../utils/hooks';

/* ── Data ─────────────────────────────────────────────────── */
const FEATURES = [
  { num:'01', title:'Prompt Injection Detection',   desc:'Automatically tests your AI against 30+ prompt injection variants designed to hijack system instructions and bypass safety filters.' },
  { num:'02', title:'Jailbreak & Policy Bypass',    desc:'Stress-tests your LLM against known jailbreak techniques — DAN, roleplay, encoding tricks — and measures resistance across all attempts.' },
  { num:'03', title:'Data Exfiltration Testing',    desc:'Simulates adversarial prompts designed to extract sensitive data, PII, system prompts, or confidential information from your AI application.' },
  { num:'04', title:'Automated Security Reports',   desc:'Every scan generates a full security report with severity scores, per-attack analysis, risk heatmaps, and actionable remediation guidance.' },
  { num:'05', title:'Any LLM, Any Infrastructure', desc:'Works with OpenAI, Groq, Anthropic, or any custom REST endpoint. Run real tests or safe simulations during development.' },
  { num:'06', title:'Continuous Re-scanning',       desc:'Schedule recurring scans to catch security regressions as your prompts evolve. Stay ahead of new attack techniques automatically.' },
];

const PREVIEW_ATTACKS = [
  { name:'Prompt Injection',    count:24 },
  { name:'Jailbreak Attempts',  count:18 },
  { name:'Data Exfiltration',   count:15 },
  { name:'Policy Bypass',       count:12 },
];

const ATTACK_PILLS = [
  'Prompt Injection', 'Jailbreak Attempts', 'Data Exfiltration', 'Policy Bypass',
  'Role-play Exploits', 'Context Poisoning', 'PII Extraction', 'Instruction Hijacking',
  'System Prompt Leakage', 'Encoding Tricks', 'Indirect Injection', 'Token Smuggling',
  'Adversarial Suffixes', 'Multi-turn Manipulation', 'Goal Hijacking', 'Refusal Bypass',
];
const PILLS_DOUBLED = [...ATTACK_PILLS, ...ATTACK_PILLS];

const INTEGRATIONS = ['OpenAI', 'Groq', 'Anthropic', 'Custom REST', 'Simulation', 'Any LLM API'];
const TRUSTED = ['NORTHWIND', 'Vaultline', 'Helix AI', 'Quantara', 'BluePeak', 'Sentinel', 'Foundry'];

const STEPS = [
  { step:'01', title:'Connect your target',  desc:'Enter a name and choose your AI target — simulation mode works instantly, or point to any LLM API.' },
  { step:'02', title:'We run the gauntlet',  desc:'1000+ adversarial prompts fire automatically across 21 attack categories. Zero manual effort required.' },
  { step:'03', title:'Get your full report', desc:'A detailed security report with scores, per-finding analysis, severity breakdown, and PDF download — in under 15 minutes.' },
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
  { quote:"LLM Scanner caught prompt injection vulnerabilities in our customer service bot that our internal team missed completely. The report was ready in 12 minutes.", name:'Sarah K.', role:'Security Lead @ Fintech Startup', init:'SK' },
  { quote:"We ran our first scan before I even finished my coffee. The PDF report was detailed enough to share directly with our board without extra work.", name:'Marcus R.', role:'CTO @ AI SaaS Company', init:'MR' },
  { quote:"Simulation mode is perfect for testing during development before we have a production API key. The attack coverage is impressively thorough.", name:'Priya N.', role:'ML Engineer @ Healthcare AI', init:'PN' },
];

const FAQ = [
  { q:'Do I need an API key to start?', a:'No. Simulation mode runs a full assessment instantly without any key. When you are ready, point the scanner at any OpenAI, Groq, Anthropic, or custom REST endpoint for live testing.' },
  { q:'How long does a scan take?', a:'Most full assessments complete in under 15 minutes — 1000+ adversarial prompts across 21 attack categories, fully automated.' },
  { q:'What do I get at the end?', a:'A detailed security report with an overall risk score, per-attack findings, severity breakdown, remediation guidance, and an exportable PDF + JSON.' },
  { q:'Is my data safe?', a:'Scans run against the target you specify. We do not store your prompts or model responses beyond what is needed to generate your report.' },
];

/* ── Scroll-reveal wrapper ────────────────────────────────── */
function Reveal({ children, className = '', delay = 0, style = {} }) {
  const [ref, inView] = useInView(0.12);
  return (
    <div
      ref={ref}
      className={`ed-reveal${inView ? ' in' : ''}${className ? ' ' + className : ''}`}
      style={{ transitionDelay: `${delay}ms`, ...style }}
    >
      {children}
    </div>
  );
}

/* ── Animated counter for the headline stat ───────────────── */
function CountStat({ target, suffix = '', label }) {
  const [ref, inView] = useInView(0.4);
  const value = useCountUp(inView ? target : 0, 1400);
  return (
    <div className="ed-stat" ref={ref}>
      <div className="ed-stat-num">{value.toLocaleString()}{suffix}</div>
      <div className="ed-stat-label">{label}</div>
    </div>
  );
}

const Plus = () => <span className="ed-plus" aria-hidden="true">+</span>;
const Eyebrow = ({ index, children, light }) => (
  <span className={`ed-eyebrow${light ? ' ed-eyebrow-light' : ''}`}>
    <span className="ed-eyebrow-idx">{index}</span><span className="ed-eyebrow-slash">/</span>{children}
  </span>
);

/* ── Component ────────────────────────────────────────────── */
export default function LandingPage() {
  return (
    <div className="landing landing-editorial">

      {/* ═══════════════════ HERO ═══════════════════ */}
      <section className="ed-hero">
        <div className="ed-hero-rule">
          <span className="ed-kicker"><Plus /> AI Security Platform</span>
          <span className="ed-kicker ed-kicker-end">Est. 2025 <Plus /></span>
        </div>

        <div className="ed-hero-grid">
          <div className="ed-hero-left">
            <div className="ed-badge">
              <span className="ed-stars">★★★★★</span>
              Rated 4.9/5 by 2,000+ AI teams
            </div>

            <h1 className="ed-display">
              Secure your <span className="ed-mark">AI</span><br />
              before <span className="ed-ul">they do.</span>
            </h1>
            <p className="ed-lead">
              Automated red-teaming for LLM applications. Detect prompt injections,
              jailbreaks, and data-exfiltration vulnerabilities in minutes — not months.
            </p>
            <div className="ed-cta-row">
              <Link to="/register" className="ed-btn ed-btn-solid">Start for free →</Link>
              <Link to="/login" className="ed-btn ed-btn-line">Sign in</Link>
            </div>
            <div className="ed-hero-meta">
              <div className="ed-meta-item"><strong>1000+</strong><span>attack prompts / scan</span></div>
              <div className="ed-meta-item"><strong>21</strong><span>vulnerability categories</span></div>
              <div className="ed-meta-item"><strong>&lt;15m</strong><span>per full assessment</span></div>
            </div>
          </div>

          {/* Scan card */}
          <div className="ed-hero-right">
            <div className="ed-card ed-scan">
              <div className="ed-scan-head">
                <span className="ed-scan-title">Live Scan — Banking AI Chatbot</span>
                <span className="ed-scan-status"><span className="ed-dot" />Running</span>
              </div>
              <div className="ed-scan-body">
                <div className="ed-progress-label">Attack progress — 68 / 85 prompts</div>
                <div className="ed-progress"><div className="ed-progress-fill" /></div>
                <div className="ed-attacks">
                  {PREVIEW_ATTACKS.map(a => (
                    <div key={a.name} className="ed-attack-row">
                      <span>{a.name}</span>
                      <span className="ed-attack-count">{a.count} tested</span>
                    </div>
                  ))}
                </div>
                <div className="ed-scan-stats">
                  <div className="ed-scan-stat"><b>7</b><span>Critical</span></div>
                  <div className="ed-scan-stat"><b>12</b><span>High</span></div>
                  <div className="ed-scan-stat ed-accent"><b>34%</b><span>Score</span></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ═══════════════════ MARQUEE ═══════════════════ */}
      <div className="ed-marquee-wrap">
        <div className="marquee-outer">
          <div className="marquee-track">
            {PILLS_DOUBLED.map((p, i) => (
              <div key={i} className="ed-pill"><Plus />{p}</div>
            ))}
          </div>
        </div>
      </div>

      {/* ═══════════════════ TRUSTED / INTEGRATIONS ═══════════════════ */}
      <section className="ed-section ed-logos-section">
        <p className="ed-overline">Trusted by security &amp; ML teams · works with any AI infrastructure</p>
        <div className="ed-logos">
          {TRUSTED.map(n => <span key={n} className="ed-logo">{n}</span>)}
        </div>
        <div className="ed-integrations">
          {INTEGRATIONS.map(n => <span key={n} className="ed-chip">{n}</span>)}
        </div>
      </section>

      {/* ═══════════════════ FEATURES ═══════════════════ */}
      <section className="ed-section">
        <Reveal>
          <div className="ed-section-head">
            <Eyebrow index="01">Capabilities</Eyebrow>
            <h2 className="ed-title">Everything you need to test AI security.</h2>
            <p className="ed-sub">A complete security testing suite built specifically for large language model applications — from rapid prototyping to enterprise deployments.</p>
          </div>
        </Reveal>
        <Reveal>
          <div className="ed-feature-grid">
            {FEATURES.map(f => (
              <article key={f.num} className="ed-feature">
                <span className="ed-feature-num">{f.num}</span>
                <h3 className="ed-feature-title">{f.title}</h3>
                <p className="ed-feature-desc">{f.desc}</p>
                <Plus />
              </article>
            ))}
          </div>
        </Reveal>
      </section>

      {/* ═══════════════════ HOW IT WORKS ═══════════════════ */}
      <section className="ed-section ed-section-alt">
        <Reveal>
          <div className="ed-section-head">
            <Eyebrow index="02">Process</Eyebrow>
            <h2 className="ed-title">Up and running in minutes.</h2>
            <p className="ed-sub">No complex setup. No integrations required to start.</p>
          </div>
        </Reveal>
        <Reveal>
          <div className="ed-steps">
            {STEPS.map(s => (
              <article key={s.step} className="ed-step">
                <span className="ed-step-num">{s.step}</span>
                <h3 className="ed-feature-title">{s.title}</h3>
                <p className="ed-feature-desc">{s.desc}</p>
              </article>
            ))}
          </div>
        </Reveal>
      </section>

      {/* ═══════════════════ STATS ═══════════════════ */}
      <section className="ed-section">
        <Reveal>
          <div className="ed-section-head">
            <Eyebrow index="03">By the numbers</Eyebrow>
            <h2 className="ed-title">Built for serious security.</h2>
          </div>
        </Reveal>
        <div className="ed-stats">
          <CountStat target={1000} suffix="+" label="Adversarial attack prompts across 21 attack categories" />
          <div className="ed-stat"><div className="ed-stat-num">&lt;15m</div><div className="ed-stat-label">Average time to complete a full security assessment</div></div>
          <div className="ed-stat"><div className="ed-stat-num">∞</div><div className="ed-stat-label">Scans on any LLM — OpenAI, Groq, or your own API</div></div>
        </div>
      </section>

      {/* ═══════════════════ COMPARE ═══════════════════ */}
      <section className="ed-section ed-section-alt">
        <Reveal>
          <div className="ed-section-head">
            <Eyebrow index="04">Why LLM Scanner</Eyebrow>
            <h2 className="ed-title">vs. manual pen testing.</h2>
            <p className="ed-sub">Get the coverage of a full red-team engagement in a fraction of the time and cost. No waiting weeks for a consultant's availability.</p>
          </div>
        </Reveal>
        <Reveal>
          <div className="ed-compare">
            <div className="ed-compare-row ed-compare-head">
              <div>Category</div>
              <div>Manual Pen Testing</div>
              <div className="ed-compare-win-col">LLM Scanner</div>
            </div>
            {COMPARE.map((row, i) => (
              <div key={i} className="ed-compare-row">
                <div className="ed-compare-feat">{row.feature}</div>
                <div className="ed-compare-manual">{row.manual}</div>
                <div className="ed-compare-win">{row.scanner}</div>
              </div>
            ))}
          </div>
        </Reveal>
      </section>

      {/* ═══════════════════ TESTIMONIALS ═══════════════════ */}
      <section className="ed-section">
        <Reveal>
          <div className="ed-section-head">
            <Eyebrow index="05">Social proof</Eyebrow>
            <h2 className="ed-title">Trusted by security teams.</h2>
            <p className="ed-sub">Engineers and security leads use LLM Scanner to catch AI vulnerabilities before their users — or attackers — do.</p>
          </div>
        </Reveal>
        <Reveal>
          <div className="ed-testimonials">
            {TESTIMONIALS.map(t => (
              <figure key={t.name} className="ed-quote-card">
                <blockquote>"{t.quote}"</blockquote>
                <figcaption>
                  <span className="ed-avatar">{t.init}</span>
                  <span><strong>{t.name}</strong><em>{t.role}</em></span>
                </figcaption>
              </figure>
            ))}
          </div>
        </Reveal>
      </section>

      {/* ═══════════════════ FAQ ═══════════════════ */}
      <section className="ed-section ed-section-alt">
        <Reveal>
          <div className="ed-section-head">
            <Eyebrow index="06">Questions</Eyebrow>
            <h2 className="ed-title">Frequently asked.</h2>
          </div>
        </Reveal>
        <Reveal>
          <div className="ed-faq">
            {FAQ.map((item, i) => (
              <details key={i} className="ed-faq-item" open={i === 0}>
                <summary>
                  <span className="ed-faq-q">{item.q}</span>
                  <span className="ed-faq-mark" aria-hidden="true">+</span>
                </summary>
                <p className="ed-faq-a">{item.a}</p>
              </details>
            ))}
          </div>
        </Reveal>
      </section>

      {/* ═══════════════════ CTA ═══════════════════ */}
      <section className="ed-cta">
        <span className="ed-eyebrow ed-eyebrow-light"><Plus /> No credit card required</span>
        <h2 className="ed-cta-title">Start securing your AI applications today.</h2>
        <p className="ed-cta-sub">Free to start. Full report on your first scan. No setup needed.</p>
        <div className="ed-cta-row">
          <Link to="/register" className="ed-btn ed-btn-solid ed-btn-invert">Create free account →</Link>
          <Link to="/pricing" className="ed-btn ed-btn-line ed-btn-line-invert">View pricing</Link>
        </div>
      </section>

      {/* ═══════════════════ FOOTER ═══════════════════ */}
      <footer className="ed-footer">
        <span className="ed-foot-brand">LLM<b>Scanner</b> © 2025</span>
        <div className="ed-foot-links">
          <Link to="/pricing">Pricing</Link>
          <Link to="/login">Sign In</Link>
          <Link to="/register">Get Started</Link>
        </div>
      </footer>

    </div>
  );
}
