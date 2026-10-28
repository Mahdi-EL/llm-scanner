import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';

vi.mock('../services/api', async () => {
  const actual = await vi.importActual('../services/api');
  return { ...actual, teamAPI: { get: vi.fn(), invite: vi.fn(), revokeInvite: vi.fn(), setRole: vi.fn(), remove: vi.fn(), leave: vi.fn() } };
});
vi.mock('../context/AuthContext', () => ({ useAuth: () => ({
  user: { id: 'owner1', workspaces: [] }, role: 'owner', switchWorkspace: vi.fn(), refreshUser: vi.fn(),
}) }));
vi.mock('../context/ToastContext', () => ({ useToast: () => vi.fn() }));
vi.mock('../context/ConfirmContext', () => ({ useConfirm: () => () => Promise.resolve(true) }));

const api = await import('../services/api');
const { default: TeamPanel } = await import('./TeamPanel');

test('a pending invite can be sent again when every seat is taken', async () => {
  api.teamAPI.get.mockResolvedValue({ data: {
    role: 'owner', seats: { used: 2, limit: 2 },
    members: [{ user_id: 'owner1', username: 'ann', email: 'ann@example.com', role: 'owner', seat: true }],
    invites: [{ id: 'inv1', email: 'bob@example.com', role: 'viewer', expires_at: '2026-11-03T10:00:00+00:00' }],
  } });
  api.teamAPI.invite.mockResolvedValue({ data: { email: 'bob@example.com', link: 'https://app/invite?token=new', emailed: false } });
  render(<MemoryRouter><TeamPanel /></MemoryRouter>);
  expect(await screen.findByLabelText('Email to invite')).toBeDisabled();       // no seat for someone new
  fireEvent.click(screen.getByRole('button', { name: 'Send bob@example.com a new invite' }));
  await waitFor(() => expect(api.teamAPI.invite).toHaveBeenCalledWith('bob@example.com', 'viewer'));
  expect(await screen.findByText('https://app/invite?token=new')).toBeInTheDocument();
});
