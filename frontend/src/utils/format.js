/* Small formatting helpers shared by the pages. */

/** "3m ago", "2h ago", or a short date. */
export function relTime(dateStr) {
  if (!dateStr) return '—';
  const diff = Date.now() - new Date(dateStr).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 7) return `${d}d ago`;
  return new Date(dateStr).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

/** "Oct 19" or, with year, "Oct 19, 2026" (the UI is English, so dates are too). */
export function shortDate(dateStr, withYear = false) {
  if (!dateStr) return '—';
  return new Date(dateStr).toLocaleDateString('en-US', { month: 'short', day: 'numeric', ...(withYear && { year: 'numeric' }) });
}

/** 12,345 rather than the browser locale's "12 345". */
export const fmtNum = n => Number(n).toLocaleString('en-US');

/** Where to go after signing in: a path on this site only (never "//evil.com" or a full URL). */
export function safeNext(raw) {
  return typeof raw === 'string' && raw.startsWith('/') && !raw.startsWith('//') && !raw.startsWith('/\\')
    ? raw : '/';
}

/** Display names of target types. */
export const TARGET_TYPES = {
  simulation       : 'Simulation',
  groq             : 'Groq',
  openai_compatible: 'OpenAI-compatible',
  custom_rest      : 'Custom REST',
};
export const typeLabel = t => TARGET_TYPES[t] || (t || '').replace(/_/g, ' ');

/** The settings each target type uses. Forms send only these: a field hidden by switching the type keeps
 *  its text, and a leftover URL or key would otherwise go with a simulation (and a bad URL get it refused). */
export const TARGET_FIELDS = {
  simulation       : ['system_prompt', 'model', 'baseline_question'],
  groq             : ['api_key', 'model', 'system_prompt', 'baseline_question'],
  openai_compatible: ['api_url', 'api_key', 'model', 'system_prompt', 'baseline_question'],
  custom_rest      : ['api_url', 'api_key', 'input_field', 'output_field', 'system_prompt', 'baseline_question'],
};

/** Score colour, matching the grade bands (A/B green, C/D amber, F red). */
export function scoreColor(score) {
  if (score == null) return 'var(--t3)';
  if (score >= 80) return '#16a34a';
  if (score >= 50) return '#b45309';
  return '#dc2626';
}

/** Risk label, matching the backend's scoring.risk_label bands. */
export function riskLabel(score) {
  if (score == null) return null;
  if (score >= 80) return 'Low risk';
  if (score >= 50) return 'Moderate risk';
  return 'High risk';
}

export function gradeOf(score) {
  if (score == null) return null;
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

/**
 * Builds CSV text. Every cell is quoted, and cells that spreadsheet apps
 * would run as formulas (=, +, -, @, tab, CR) get a leading apostrophe.
 */
export function toCSV(rows) {
  const cell = value => {
    let text = value == null ? '' : String(value);
    if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
    return `"${text.replace(/"/g, '""')}"`;
  };
  return rows.map(row => row.map(cell).join(',')).join('\r\n');
}

export const isActive = scan => scan?.status === 'pending' || scan?.status === 'running';

export function formatDuration(seconds) {
  if (!seconds && seconds !== 0) return '—';
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return m ? `${m}m ${String(s).padStart(2, '0')}s` : `${s}s`;
}
