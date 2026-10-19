import React from 'react';
import { Link } from 'react-router-dom';
import { useInView, useCountUp } from '../utils/hooks';
import { fmtNum } from '../utils/format';

/* ── Data ─────────────────────────────────────────────────── */
const FEATURES = [
  { num:'01', title:'Prompt Injection Detection',   desc:'Tests your AI against hundreds of injection prompts, direct and hidden in documents, designed to hijack its instructions.' },
  { num:'02', title:'Jailbreak & Policy Bypass',    desc:'Stress-tests your LLM against known jailbreak techniques — DAN, roleplay, encoding tricks — and measures resistance across all attempts.' },
  { num:'03', title:'Data Exfiltration Testing',    desc:'Simulates adversarial prompts designed to extract sensitive data, PII, system prompts, or confidential information from your AI application.' },
  { num:'04', title:'Automated Security Reports',   desc:'Every scan produces a PDF, HTML and Markdown report with severity scores, the OWASP LLM Top 10 risk for each finding, and fixes for the categories that failed.' },
  { num:'05', title:'Any OpenAI-compatible API',    desc:'Works with OpenAI, Groq, Mistral, Together, OpenRouter or any custom REST endpoint. Or test a system prompt in simulation mode.' },
  { num:'06', title:'Scheduled Re-scanning',        desc:'On Pro, schedule daily or weekly scans and get an email or webhook alert when the score drops.' },
];

const PREVIEW_ATTACKS = [
  { name:'Prompt Injection',    count:24 },
  { name:'Jailbreak Attempts',  count:18 },
  { name:'Data Exfiltration',   count:15 },
  { name:'Policy Bypass',       count:12 },
];

const ATTACK_PILLS = [
  'Instruction Override', 'Jailbreak Templates', 'Data Exfiltration', 'System Prompt Leakage',
  'Role-play Exploits', 'Encoding Tricks', 'Indirect Injection', 'Token Smuggling',
  'RAG Poisoning', 'Few-shot Poisoning', 'Multi-turn Manipulation', 'Authority Impersonation',
  'System Prompt Spoofing', 'Multilingual Attacks', 'Prompt Chaining', 'Hallucination Induction',
];
const PILLS_DOUBLED = [...ATTACK_PILLS, ...ATTACK_PILLS];

const INTEGRATIONS = ['OpenAI', 'Groq', 'Mistral', 'Together AI', 'OpenRouter', 'Custom REST', 'Simulation'];

const STEPS = [
  { step:'01', title:'Connect your target',  desc:'Enter a name and choose your AI target — simulation mode works instantly, or point to any LLM API.' },
  { step:'02', title:'We run the gauntlet',  desc:'Over 1,000 adversarial prompts across 22 attack categories, including multi-turn conversations, graded one by one. You can watch the progress live.' },
  { step:'03', title:'Get your full report', desc:'A score and grade, every finding with the model’s reply, and what to fix first. Download it as PDF, HTML, Markdown or JSON.' },
];

const COMPARE = [
  { feature:'Attack coverage',       manual:'Limited by analyst hours', scanner:'1,000+ prompts, 22 categories' },
  { feature:'Time to first result',  manual:'Weeks to schedule',        scanner:'Same day, from your browser'   },
  { feature:'Report generation',     manual:'Manual write-up',          scanner:'PDF, HTML, Markdown and JSON'  },
  { feature:'Re-testing',            manual:'A new engagement',         scanner:'Re-scan any time, or on a schedule' },
  { feature:'Grading',               manual:'Varies by analyst',        scanner:'Deterministic judge settings plus rule-based leak detection' },
  { feature:'Depth',                 manual:'Creative, multi-step attacks', scanner:'Broad automated coverage; use both' },
];

const FAQ = [
  { q:'Do I need an API key to start?', a:'No. Simulation mode tests a system prompt on a hosted model without any key. When you are ready, point the scanner at any OpenAI-compatible API or custom REST endpoint.' },
  { q:'How long does a scan take?', a:'It depends on how fast your target answers. A full scan sends about 1,090 attacks; you can pick fewer categories for a quicker one, and watch the progress live.' },
  { q:'What do I get at the end?', a:'A 0–100 score and a letter grade, every finding with the model’s reply and why it failed, the OWASP LLM Top 10 risk it maps to, and fixes for each failed category.' },
  { q:'What happens to my data?', a:'Your target’s API key is encrypted while a scan runs and deleted when it ends, unless you save the target. Attack replies are kept with your scan so you can read the report. Delete the scan, or your account, to remove them.' },
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
      <div className="ed-stat-num">{fmtNum(value)}{suffix}</div>
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
          <span className="ed-kicker ed-kicker-end">Open source <Plus /></span>
        </div>

        <div className="ed-hero-grid">
          <div className="ed-hero-left">

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
              <div className="ed-meta-item"><strong>22</strong><span>attack categories</span></div>
              <div className="ed-meta-item"><strong>OWASP</strong><span>LLM Top 10 mapping</span></div>
            </div>
          </div>

          {/* Scan card */}
          <div className="ed-hero-right">
            <div className="ed-card ed-scan">
              <div className="ed-scan-head">
                <span className="ed-scan-title">Example scan — banking chatbot</span>
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

      {/* ═══════════════════ INTEGRATIONS ═══════════════════ */}
      <section className="ed-section ed-logos-section">
        <p className="ed-overline">Works with any OpenAI-compatible API, your own REST endpoint, or a simulated model</p>
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
          <CountStat target={1000} suffix="+" label="Adversarial attack prompts across 22 attack categories" />
          <div className="ed-stat"><div className="ed-stat-num">22</div><div className="ed-stat-label">Attack categories, each mapped to the OWASP Top 10 for LLM Applications</div></div>
          <div className="ed-stat"><div className="ed-stat-num">4</div><div className="ed-stat-label">Report formats: PDF, HTML, Markdown and JSON</div></div>
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

      {/* ═══════════════════ FAQ ═══════════════════ */}
      <section className="ed-section ed-section-alt">
        <Reveal>
          <div className="ed-section-head">
            <Eyebrow index="05">Questions</Eyebrow>
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
        <span className="ed-foot-brand">LLM<b>Scanner</b> © {new Date().getFullYear()}</span>
        <div className="ed-foot-links">
          <Link to="/pricing">Pricing</Link>
          <Link to="/login">Sign In</Link>
          <Link to="/register">Get Started</Link>
        </div>
      </footer>

    </div>
  );
}
