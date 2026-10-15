import axios from 'axios';

export const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const ACCESS_KEY  = 'access_token';
const REFRESH_KEY = 'refresh_token';

// Clear ONLY auth keys — never wipe the whole localStorage (preserves UI prefs
// like sidebar state, etc.)
export function clearAuth() {
  localStorage.removeItem(ACCESS_KEY);
  localStorage.removeItem(REFRESH_KEY);
}

const api = axios.create({ baseURL: API_URL });

// Attach JWT to every request
api.interceptors.request.use(cfg => {
  const token = localStorage.getItem(ACCESS_KEY);
  if (token) cfg.headers.Authorization = `Bearer ${token}`;
  return cfg;
});

// Auto-refresh on 401 — with a single shared refresh promise so concurrent 401s
// don't each spend (and rotate away) the refresh token.
let refreshPromise = null;

api.interceptors.response.use(
  res => res,
  async err => {
    const original = err.config;
    if (err.response?.status === 401 && original && !original._retry) {
      original._retry = true;
      const refresh = localStorage.getItem(REFRESH_KEY);
      if (!refresh) return Promise.reject(err);

      try {
        if (!refreshPromise) {
          refreshPromise = axios
            .post(`${API_URL}/auth/refresh`, { refresh_token: refresh })
            .then(({ data }) => {
              localStorage.setItem(ACCESS_KEY,  data.access_token);
              localStorage.setItem(REFRESH_KEY, data.refresh_token);
              return data.access_token;
            })
            .finally(() => { refreshPromise = null; });
        }
        const newToken = await refreshPromise;
        original.headers.Authorization = `Bearer ${newToken}`;
        return api(original);
      } catch {
        clearAuth();
        window.location.href = '/login';
        return Promise.reject(err);
      }
    }
    return Promise.reject(err);
  }
);

// ── Auth ──────────────────────────────────────────────────────
export const authAPI = {
  login    : (username, password) =>
    api.post('/auth/login',    { username, password }),
  register : (username, email, password) =>
    api.post('/auth/register', { username, email, password }),
  me       : () => api.get('/auth/me'),
  logout   : () => clearAuth(),
  forgotPassword : email =>
    api.post('/auth/forgot-password', { email }),
  resetPassword  : (token, new_password) =>
    api.post('/auth/reset-password', { token, new_password }),
  changePassword : (current_password, new_password) =>
    api.put('/auth/password', { current_password, new_password }),
};

// ── Scans ─────────────────────────────────────────────────────
export const scansAPI = {
  list   : ()       => api.get('/scans'),
  get    : id       => api.get(`/scan/${id}`),
  start  : payload  => api.post('/scan', payload),
  delete : id       => api.delete(`/scan/${id}`),
  results: id       => api.get(`/results/${id}`),
};

// ── Health ────────────────────────────────────────────────────
export const healthAPI = {
  check: () => api.get('/health'),
};

// ── Waitlist ──────────────────────────────────────────────────
export const waitlistAPI = {
  join : email => api.post(`/api/waitlist?email=${encodeURIComponent(email)}`),
  count: ()    => api.get('/api/waitlist/count'),
};

// ── Plans / Payment ───────────────────────────────────────────
export const plansAPI = {
  list    : ()              => api.get('/api/plans'),
  checkout: (plan, email)   => api.post('/api/checkout', { plan, email }),
};

export default api;
