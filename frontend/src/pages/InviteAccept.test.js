import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { vi } from 'vitest';

vi.mock('../services/api', async () => {
  const actual = await vi.importActual('../services/api');
  return { ...actual, teamAPI: { accept: vi.fn() }, authAPI: { resendVerification: vi.fn() } };
});
const logout = vi.fn(() => Promise.resolve());
vi.mock('../context/AuthContext', () => ({ useAuth: () => ({
  user: { id: 'u1', username: 'carol', email: 'carol@example.com', email_verified: true }, loading: false, logout,
}) }));

const api = await import('../services/api');
const { default: InviteAccept } = await import('./InviteAccept');

test('an invite for another address offers to sign out and use that one', async () => {
  const err = new Error('403');
  err.response = { status: 403, data: { detail: 'This invite is for bob@example.com. Sign in with that address to accept it.' } };
  api.teamAPI.accept.mockRejectedValue(err);
  render(<MemoryRouter initialEntries={['/invite?token=tok123']}><Routes><Route path="/invite" element={<InviteAccept />} /></Routes></MemoryRouter>);
  fireEvent.click(screen.getByText('Join the workspace'));
  expect(await screen.findByText(/This invite is for bob@example.com/)).toBeInTheDocument();
  fireEvent.click(screen.getByText('Sign out and use that address'));
  await waitFor(() => expect(logout).toHaveBeenCalled());
});
