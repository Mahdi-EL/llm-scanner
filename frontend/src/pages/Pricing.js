import React from 'react';
import { useNavigate } from 'react-router-dom';

const plans = [
  {
    name      : "Starter",
    price     : "49",
    color     : "#2E75B6",
    scans     : "5 scans / month",
    features  : [
      "85+ attack prompts",
      "9 attack categories",
      "PDF security report",
      "JSON results export",
      "Email support"
    ],
    cta       : "Start Free Trial",
    popular   : false
  },
  {
    name      : "Pro",
    price     : "99",
    color     : "#1F3864",
    scans     : "50 scans / month",
    features  : [
      "Everything in Starter",
      "AI prompt generator",
      "Priority scanning",
      "Custom system prompts",
      "API access",
      "Priority support"
    ],
    cta       : "Get Started",
    popular   : true
  },
  {
    name      : "Agency",
    price     : "299",
    color     : "#C0392B",
    scans     : "Unlimited scans",
    features  : [
      "Everything in Pro",
      "White-label reports",
      "Multiple team members",
      "Custom branding",
      "Dedicated support",
      "Custom integrations"
    ],
    cta       : "Contact Us",
    popular   : false
  }
];

function Pricing() {
  const navigate = useNavigate();

  return (
    <div>
      {/* Header */}
      <div style={{ textAlign: 'center', marginBottom: '48px' }}>
        <h1 className="page-title" style={{ textAlign: 'center' }}>
          Simple, Transparent Pricing
        </h1>
        <p className="page-subtitle" style={{ textAlign: 'center' }}>
          Start free. Scale as you grow. Cancel anytime.
        </p>
      </div>

      {/* Plans */}
      <div style={{
        display        : 'grid',
        gridTemplateColumns : 'repeat(3, 1fr)',
        gap            : '24px',
        maxWidth       : '1000px',
        margin         : '0 auto 60px'
      }}>
        {plans.map(plan => (
          <div key={plan.name} style={{
            background    : '#1a1d27',
            border        : plan.popular
                            ? `2px solid ${plan.color}`
                            : '1px solid #2a2d3a',
            borderRadius  : '16px',
            padding       : '32px',
            position      : 'relative',
            transform     : plan.popular ? 'scale(1.05)' : 'scale(1)',
          }}>

            {/* Popular badge */}
            {plan.popular && (
              <div style={{
                position        : 'absolute',
                top             : '-14px',
                left            : '50%',
                transform       : 'translateX(-50%)',
                background      : plan.color,
                color           : 'white',
                padding         : '4px 16px',
                borderRadius    : '20px',
                fontSize        : '12px',
                fontWeight      : '700',
                whiteSpace      : 'nowrap'
              }}>
                ⭐ Most Popular
              </div>
            )}

            {/* Plan name */}
            <h2 style={{
              fontSize    : '22px',
              fontWeight  : '700',
              color       : plan.color,
              marginBottom: '8px'
            }}>
              {plan.name}
            </h2>

            {/* Price */}
            <div style={{ marginBottom: '8px' }}>
              <span style={{
                fontSize  : '48px',
                fontWeight: '800',
                color     : 'white'
              }}>
                €{plan.price}
              </span>
              <span style={{ color: '#888888', fontSize: '14px' }}>
                /month
              </span>
            </div>

            {/* Scans */}
            <p style={{
              color        : plan.color,
              fontSize     : '14px',
              fontWeight   : '600',
              marginBottom : '24px',
              paddingBottom: '24px',
              borderBottom : '1px solid #2a2d3a'
            }}>
              {plan.scans}
            </p>

            {/* Features */}
            <ul style={{
              listStyle   : 'none',
              marginBottom: '32px'
            }}>
              {plan.features.map((f, i) => (
                <li key={i} style={{
                  padding    : '8px 0',
                  fontSize   : '14px',
                  color      : '#cccccc',
                  display    : 'flex',
                  alignItems : 'center',
                  gap        : '10px'
                }}>
                  <span style={{ color: '#2ECC71' }}>✓</span>
                  {f}
                </li>
              ))}
            </ul>

            {/* CTA Button */}
            <button
              style={{
                width       : '100%',
                padding     : '14px',
                background  : plan.popular ? plan.color : 'transparent',
                border      : `2px solid ${plan.color}`,
                borderRadius: '10px',
                color       : 'white',
                fontSize    : '15px',
                fontWeight  : '600',
                cursor      : 'pointer',
              }}
              onClick={() => navigate('/new-scan')}
            >
              {plan.cta}
            </button>

          </div>
        ))}
      </div>

      {/* FAQ */}
      <div style={{
        maxWidth    : '700px',
        margin      : '0 auto',
        paddingBottom: '60px'
      }}>
        <h2 style={{
          fontSize    : '24px',
          fontWeight  : '700',
          marginBottom: '32px',
          textAlign   : 'center'
        }}>
          Frequently Asked Questions
        </h2>

        {[
          {
            q: "Is there a free trial ?",
            a: "Yes. All plans start with a 7-day free trial. No credit card required."
          },
          {
            q: "What is a scan ?",
            a: "One scan = firing 85+ attack prompts against one AI application and generating a full PDF report."
          },
          {
            q: "Can I scan real AI applications ?",
            a: "Yes, with explicit written permission from the application owner. We include legal guidelines with every plan."
          },
          {
            q: "How long does a scan take ?",
            a: "Approximately 10-15 minutes for a full scan with all 85+ attack prompts and intelligent analysis."
          },
          {
            q: "Can I cancel anytime ?",
            a: "Yes. No contracts, no commitments. Cancel from your dashboard at any time."
          }
        ].map((item, i) => (
          <div key={i} style={{
            marginBottom : '16px',
            background   : '#1a1d27',
            border       : '1px solid #2a2d3a',
            borderRadius : '10px',
            padding      : '20px'
          }}>
            <h3 style={{
              fontSize    : '15px',
              fontWeight  : '600',
              marginBottom: '8px'
            }}>
              {item.q}
            </h3>
            <p style={{ color: '#888888', fontSize: '14px', lineHeight: '1.6' }}>
              {item.a}
            </p>
          </div>
        ))}
      </div>

      {/* Bottom CTA */}
      <div style={{
        textAlign  : 'center',
        padding    : '60px',
        background : '#1F3864',
        borderRadius: '16px',
        marginBottom: '40px'
      }}>
        <h2 style={{ fontSize: '28px', fontWeight: '700', marginBottom: '12px' }}>
          Ready to secure your AI app ?
        </h2>
        <p style={{ color: '#aaaaaa', marginBottom: '24px' }}>
          Join the beta — free access during beta period
        </p>
        <button
          className="btn-primary"
          style={{ fontSize: '16px', padding: '16px 40px' }}
          onClick={() => navigate('/new-scan')}
        >
          🚀 Start Free Scan
        </button>
      </div>

    </div>
  );
}

export default Pricing;