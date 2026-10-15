import React from 'react';

/* ──────────────────────────────────────────────────────────────
   LLMScanner brand mark — a security shield with a radar scan
   sweep. Crisp at any size, themeable via the `tone` prop.

   tone:
     'gradient' (default) — blue→purple brand gradient fill
     'mono'               — single solid color (pass `color`)
   ────────────────────────────────────────────────────────────── */
let _uid = 0;

export default function Logo({ size = 30, tone = 'gradient', color = '#2563eb', className, style }) {
  const id = React.useMemo(() => `lmk${++_uid}`, []);
  const stroke = tone === 'mono' ? color : `url(#${id}g)`;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      className={className}
      style={style}
      aria-hidden="true"
      role="img"
    >
      <defs>
        <linearGradient id={`${id}g`} x1="4" y1="2" x2="28" y2="30" gradientUnits="userSpaceOnUse">
          <stop stopColor="#2563eb" />
          <stop offset="1" stopColor="#6366f1" />
        </linearGradient>
      </defs>

      {/* Shield body */}
      <path
        d="M16 2.6 27 6.4v8.1c0 7.2-5.0 11.7-11 14.9-6-3.2-11-7.7-11-14.9V6.4L16 2.6Z"
        stroke={stroke}
        strokeWidth="2"
        strokeLinejoin="round"
        fill={tone === 'mono' ? 'none' : `url(#${id}g)`}
        fillOpacity={tone === 'mono' ? 0 : 0.12}
      />

      {/* Radar scan arcs */}
      <path d="M11.4 16a4.6 4.6 0 0 1 9.2 0" stroke={stroke} strokeWidth="1.9" strokeLinecap="round" />
      <path d="M8.2 16a7.8 7.8 0 0 1 15.6 0" stroke={stroke} strokeWidth="1.9" strokeLinecap="round" opacity="0.55" />

      {/* Center node + sweep line */}
      <circle cx="16" cy="16" r="1.7" fill={stroke} />
      <path d="M16 16 22 11" stroke={stroke} strokeWidth="1.9" strokeLinecap="round" />
    </svg>
  );
}
