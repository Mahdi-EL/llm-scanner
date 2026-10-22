import axios from 'axios';
import { vi } from 'vitest';
import api, { getWorkspace, setWorkspace } from './api';

// Answers like the API: 401 for the expired access token, 200 for any other.
function serve(config) {
  const auth = config.headers?.Authorization || config.headers?.get?.('Authorization');
  const status = auth === 'Bearer expired' ? 401 : 200;
  const response = { data: { auth }, status, statusText: '', headers: {}, config };
  if (status >= 400) {
    const err = new Error(`Request failed with status code ${status}`);
    err.config = config; err.response = response;
    return Promise.reject(err);
  }
  return Promise.resolve(response);
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  api.defaults.adapter = serve;
});

test('each tab keeps the workspace it shows; a new tab starts in the last one chosen', async () => {
  let sent;
  api.defaults.adapter = config => { sent = config.headers['X-Workspace']; return serve(config); };
  localStorage.setItem('access_token', 'ok');
  setWorkspace('team-a');
  await api.get('/scans');
  expect(sent).toBe('team-a');

  // another tab switches to its own account: this tab's requests stay in team-a
  localStorage.removeItem('workspace_id');
  await api.get('/scans');
  expect(sent).toBe('team-a');

  // a new tab (empty sessionStorage) starts where the last switch left off
  localStorage.setItem('workspace_id', 'team-b');
  sessionStorage.clear();
  expect(getWorkspace()).toBe('team-b');
  setWorkspace(null);
  await api.get('/scans');
  expect(sent).toBeUndefined();
});

test('a refresh token another tab just spent: carry on with the tokens it saved', async () => {
  localStorage.setItem('access_token', 'expired');
  localStorage.setItem('refresh_token', 'old-refresh');
  vi.spyOn(axios, 'post').mockImplementation(async () => {
    // meanwhile the other tab refreshed with the same token and saved new ones
    localStorage.setItem('access_token', 'fresh-from-other-tab');
    localStorage.setItem('refresh_token', 'new-refresh');
    const err = new Error('Request failed with status code 401');
    err.response = { status: 401, data: { detail: 'Invalid or expired refresh token' } };
    throw err;
  });
  const res = await api.get('/scans');
  expect(res.data.auth).toBe('Bearer fresh-from-other-tab');
  expect(localStorage.getItem('refresh_token')).toBe('new-refresh');      // still signed in
});

test('a refresh that fails for real signs out', async () => {
  localStorage.setItem('access_token', 'expired');
  localStorage.setItem('refresh_token', 'revoked');
  vi.spyOn(axios, 'post').mockRejectedValue(Object.assign(new Error('401'), { response: { status: 401 } }));
  delete window.location;
  window.location = { pathname: '/reports', search: '', href: '' };
  await expect(api.get('/scans')).rejects.toBeTruthy();
  expect(localStorage.getItem('refresh_token')).toBeNull();
  expect(window.location.href).toBe('/login?next=%2Freports');
});
