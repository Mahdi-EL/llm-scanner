import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';

vi.mock('../services/api', () => ({ scansAPI: { list: vi.fn() } }));
const auth = vi.hoisted(() => ({ value: null }));
vi.mock('../context/AuthContext', () => ({ useAuth: () => auth.value }));

const api = await import('../services/api');
const { default: TopBar } = await import('./TopBar');

const scan = (id, when) => ({
  scan_id: id, target_name: `Bot ${id}`, status: 'complete', created_at: when, completed_at: when,
  summary: { security_score: 80, grade: 'B', critical: 0, high: 1 },
});

beforeEach(() => {
  localStorage.clear();
  auth.value = { user: { id: 'u1', username: 'ann' }, canEdit: true };
  api.scansAPI.list.mockResolvedValue({ data: { scans: [
    scan('a', '2026-10-20T10:00:00+00:00'), scan('b', '2026-10-21T10:00:00+00:00'), scan('c', '2026-10-22T10:00:00+00:00'),
  ] } });
});

const renderBar = () => render(<MemoryRouter><TopBar onOpenCmd={() => {}} onOpenNav={() => {}} /></MemoryRouter>);

test('Clear all clears every notification, not just the last one', async () => {
  renderBar();
  fireEvent.click(await screen.findByRole('button', { name: 'Notifications, 3 unread' }));
  expect(await screen.findAllByText(/^Scan complete: Bot/)).toHaveLength(3);
  fireEvent.click(screen.getByText('Clear all'));
  expect(screen.queryAllByText(/^Scan complete: Bot/)).toHaveLength(0);
  expect(screen.getByText(/Nothing new/)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Notifications' })).toBeInTheDocument();
});

test('marking one workspace read leaves the other workspaces unread', async () => {
  const { unmount } = renderBar();
  fireEvent.click(await screen.findByRole('button', { name: 'Notifications, 3 unread' }));
  fireEvent.click(screen.getByText('Mark all read'));
  expect(screen.getByRole('button', { name: 'Notifications' })).toBeInTheDocument();
  unmount();

  auth.value = { user: { id: 'u1', username: 'ann', workspace: { id: 'team', name: 'Acme', role: 'member' } }, canEdit: true };
  renderBar();
  expect(await screen.findByRole('button', { name: 'Notifications, 3 unread' })).toBeInTheDocument();
});
