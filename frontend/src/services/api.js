import axios from 'axios';

export const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({ baseURL: API_URL });

// Attach JWT to every request
api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('access_token');
  if (token) cfg.headers.Authorization = `Bearer ${token}`;
  return cfg;
});

// Auto-refresh on 401
api.interceptors.response.use(
  res => res,
  async err => {
    const original = err.config;
    if (err.response?.status === 401 && !original._retry) {
      original._retry = true;
      const refresh = localStorage.getItem('refresh_token');
      if (refresh) {
        try {
          const { data } = await axios.post(`${API_URL}/auth/refresh`, {
            refresh_token: refresh
          });
          localStorage.setItem('access_token',  data.access_token);
          localStorage.setItem('refresh_token', data.refresh_token);
          original.headers.Authorization = `Bearer ${data.access_token}`;
          return api(original);
        } catch {
          localStorage.clear();
          window.location.href = '/login';
        }
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
  logout   : () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
  },
  forgotPassword : email =>
    api.post('/auth/forgot-password', { email }),
  resetPassword  : (token, new_password) =>
    api.post('/auth/reset-password', { token, new_password }),
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
