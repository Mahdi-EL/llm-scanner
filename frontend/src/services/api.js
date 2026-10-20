import axios from 'axios';

export const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const ACCESS_KEY  = 'access_token';
const REFRESH_KEY = 'refresh_token';

// Clear ONLY auth keys — never wipe the whole localStorage (preserves UI prefs
// like sidebar state, etc.)
// The team workspace the app acts in (absent = the person's own account)
export const WORKSPACE_KEY = 'workspace_id';

export function clearAuth() {
  localStorage.removeItem(ACCESS_KEY);
  localStorage.removeItem(REFRESH_KEY);
  localStorage.removeItem(WORKSPACE_KEY);
}

export function saveTokens(data) {
  if (data?.access_token)  localStorage.setItem(ACCESS_KEY, data.access_token);
  if (data?.refresh_token) localStorage.setItem(REFRESH_KEY, data.refresh_token);
}

const api = axios.create({ baseURL: API_URL });

// Attach JWT to every request
api.interceptors.request.use(cfg => {
  const token = localStorage.getItem(ACCESS_KEY);
  if (token) cfg.headers.Authorization = `Bearer ${token}`;
  const workspace = localStorage.getItem(WORKSPACE_KEY);
  if (workspace) cfg.headers['X-Workspace'] = workspace;
  return cfg;
});

// Auto-refresh on 401 — with a single shared refresh promise so concurrent 401s
// don't each spend (and rotate away) the refresh token.
let refreshPromise = null;

api.interceptors.response.use(
  res => res,
  async err => {
    const original = err.config;
    const isAuthCall = original?.url?.startsWith('/auth/login') || original?.url?.startsWith('/auth/refresh');
    if (err.response?.status === 401 && original && !original._retry && !isAuthCall) {
      original._retry = true;
      const refresh = localStorage.getItem(REFRESH_KEY);
      if (!refresh) return Promise.reject(err);

      try {
        if (!refreshPromise) {
          refreshPromise = axios
            .post(`${API_URL}/auth/refresh`, { refresh_token: refresh })
            .then(({ data }) => { saveTokens(data); return data.access_token; })
            .finally(() => { refreshPromise = null; });
        }
        const newToken = await refreshPromise;
        original.headers.Authorization = `Bearer ${newToken}`;
        return api(original);
      } catch {
        clearAuth();
        const here = window.location.pathname + window.location.search;
        window.location.href = here.startsWith('/login') ? '/login' : `/login?next=${encodeURIComponent(here)}`;
        return Promise.reject(err);
      }
    }
    return Promise.reject(err);
  }
);

/** The API's error message, or a fallback. */
export function errorMessage(err, fallback = 'Something went wrong. Please try again.') {
  const detail = err?.response?.data?.detail;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail) && detail[0]?.msg) return detail[0].msg.replace(/^Value error, /, '');
  if (err?.message === 'Network Error') return 'Can’t reach the server. Check your connection and retry.';
  return fallback;
}

/** Saves a Blob as a file without opening it in the app's origin. */
export function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const DOWNLOAD_PATHS = { pdf: '/download', html: '/download/html', md: '/download/md', json: '/download/json',
                         evidence: '/download/evidence' };

/**
 * Downloads a report with the user's token (window.open can't send it).
 * The file is saved, never rendered inside the app, so a malicious HTML
 * report can't read the app's storage.
 */
export async function downloadReport(scanId, format = 'pdf') {
  let res;
  try {
    res = await api.get(`${DOWNLOAD_PATHS[format]}/${scanId}`, { responseType: 'blob' });
  } catch (e) {
    // the error body arrives as a Blob too: read it so errorMessage() can show its "detail"
    if (e.response?.data instanceof Blob) {
      try { e.response.data = JSON.parse(await e.response.data.text()); } catch { /* not JSON */ }
    }
    throw e;
  }
  const disposition = res.headers?.['content-disposition'] || '';
  const match = /filename="?([^";]+)"?/i.exec(disposition);
  saveBlob(res.data, match ? match[1] : `LLM_Security_Report_${scanId}.${format === 'evidence' ? 'pdf' : format}`);
}

// ── Auth ──────────────────────────────────────────────────────
export const authAPI = {
  login    : (username, password) => api.post('/auth/login', { username, password }),
  register : (username, email, password) => api.post('/auth/register', { username, email, password }),
  me       : () => api.get('/auth/me'),
  logout   : async () => {
    const refresh = localStorage.getItem(REFRESH_KEY);
    clearAuth();
    if (refresh) {
      try { await axios.post(`${API_URL}/auth/logout`, { refresh_token: refresh }); } catch { /* offline: tokens expire anyway */ }
    }
  },
  logoutEverywhere: () => api.post('/auth/logout', { refresh_token: localStorage.getItem(REFRESH_KEY), everywhere: true }),
  forgotPassword : email => api.post('/auth/forgot-password', { email }),
  resetPassword  : (token, new_password) => api.post('/auth/reset-password', { token, new_password }),
  changePassword : (current_password, new_password) => api.put('/auth/password', { current_password, new_password }),
  verifyEmail    : token => api.post('/auth/verify-email', { token }),
  resendVerification: () => api.post('/auth/resend-verification'),
  exportData     : () => api.get('/auth/me/export'),
  deleteAccount  : password => api.delete('/auth/me', { data: { password } }),
};

// ── Scans ─────────────────────────────────────────────────────
export const scansAPI = {
  list   : (params = {}) => api.get('/scans', { params: { limit: 200, ...params } }),
  stats  : ()          => api.get('/scans/stats'),
  /** Every scan summary (pages through /scans), up to `cap`. Resolves to { scans, total }. */
  listAll: async (params = {}, cap = 1000) => {
    const scans = [];
    let total = 0;
    while (scans.length < cap) {
      const { data } = await api.get('/scans', { params: { limit: 200, offset: scans.length, ...params } });
      total = data.total;
      scans.push(...data.scans);
      if (!data.scans.length || scans.length >= total) break;
    }
    return { scans, total };
  },
  get    : id       => api.get(`/scan/${id}`),
  start  : payload  => api.post('/scan', payload),
  cancel : id       => api.post(`/scan/${id}/cancel`),
  delete : id       => api.delete(`/scan/${id}`),
  results: id       => api.get(`/results/${id}`),
  compare: (baseId, headId) => api.get(`/scan/compare/${baseId}/${headId}`),
  share  : (id, days = 7) => api.post(`/scan/${id}/share`, { days }),
  remediate: (id, body = {}) => api.post(`/scan/${id}/remediate`, body),
  retest : (id, body = {}) => api.post(`/scan/${id}/retest`, body),
  unshare: id       => api.delete(`/scan/${id}/share`),
  triage : (id, key, status, note) => api.put(`/scan/${id}/triage`, { key, status, note }),
  shared : token    => api.get(`/shared/${token}`),
  categories: ()    => api.get('/categories'),
  categoryStats: () => api.get('/analytics/categories'),
  models: ()        => api.get('/models'),
  testTarget: payload => api.post('/targets/test', payload),
};

// ── Saved targets, schedules, custom prompts ──────────────────
export const targetsAPI = {
  list  : ()          => api.get('/api/targets'),
  create: payload     => api.post('/api/targets', payload),
  update: (id, body)  => api.put(`/api/targets/${id}`, body),
  remove: id          => api.delete(`/api/targets/${id}`),
};

export const schedulesAPI = {
  list  : ()          => api.get('/api/schedules'),
  create: payload     => api.post('/api/schedules', payload),
  update: (id, body)  => api.put(`/api/schedules/${id}`, body),
  remove: id          => api.delete(`/api/schedules/${id}`),
};

export const publicAPI = {
  leakCheck: systemPrompt => api.post('/public/leak-check', { system_prompt: systemPrompt }, { timeout: 90000 }),
};

export const teamAPI = {
  get         : ()            => api.get('/api/team'),
  invite      : (email, role) => api.post('/api/team/invites', { email, role }),
  revokeInvite: id            => api.delete(`/api/team/invites/${id}`),
  setRole     : (id, role)    => api.put(`/api/team/members/${id}`, { role }),
  remove      : id            => api.delete(`/api/team/members/${id}`),
  accept      : token         => api.post('/api/team/accept', { token }),
};

export const gatewayAPI = {
  stats: (targetId, days = 7) => api.get('/api/gateway/stats', { params: { target_id: targetId, days } }),
};

export const firewallAPI = {
  usage : ()   => api.get('/api/firewall/usage'),
  check : text => api.post('/api/firewall/check', { text }),
};

export const promptsAPI = {
  list  : ()                  => api.get('/api/prompts'),
  add   : (category, prompt)  => api.post('/api/prompts', { category, prompt }),
  remove: id                  => api.delete(`/api/prompts/${id}`),
};

// ── API keys and webhook ──────────────────────────────────────
export const keysAPI = {
  list  : ()    => api.get('/api/keys'),
  create: name  => api.post('/api/keys', { name }),
  revoke: id    => api.delete(`/api/keys/${id}`),
};

export const brandingAPI = {
  set: brand => api.put('/api/branding', { brand: brand || null }),
};

export const webhookAPI = {
  get   : ()    => api.get('/api/webhook'),
  set   : url   => api.put('/api/webhook', { url: url || null }),
  rotate: ()    => api.post('/api/webhook/rotate'),
  test  : ()    => api.post('/api/webhook/test'),
};

// ── Health ────────────────────────────────────────────────────
export const healthAPI = {
  check: () => api.get('/health'),
};

// ── Waitlist ──────────────────────────────────────────────────
export const waitlistAPI = {
  join : (email, name) => api.post('/api/waitlist', { email, name }),
  count: ()            => api.get('/api/waitlist/count'),
};

// ── Plans / Payment ───────────────────────────────────────────
export const plansAPI = {
  list    : ()   => api.get('/api/plans'),
  checkout: (plan, interval = 'month') => api.post('/api/checkout', { plan, interval }),
  portal  : ()   => api.post('/api/billing/portal'),
};

export default api;
