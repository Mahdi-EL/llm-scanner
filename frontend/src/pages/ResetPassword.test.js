import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { vi } from 'vitest';

vi.mock('../services/api', async () => {
  const actual = await vi.importActual('../services/api');
  return { ...actual, authAPI: { resetPassword: vi.fn() } };
});

const api = await import('../services/api');
const { default: ResetPassword } = await import('./ResetPassword');

const renderAt = path => render(
  <MemoryRouter initialEntries={[path]}><Routes><Route path="/reset-password" element={<ResetPassword />} /></Routes></MemoryRouter>);
const type = (label, value) => fireEvent.change(screen.getByLabelText(label), { target: { value } });

test('a typo keeps the form; an expired link offers a new one', async () => {
  renderAt('/reset-password?token=tok');
  type('New Password', 'longpassword1');
  type('Confirm Password', 'longpassword2');
  fireEvent.click(screen.getByText('Set New Password →'));
  expect(screen.getByText('Passwords do not match.')).toBeInTheDocument();
  expect(screen.getByLabelText('New Password')).toBeInTheDocument();          // still there to fix the typo

  const err = new Error('400');
  err.response = { status: 400, data: { detail: 'Invalid or expired reset token' } };
  api.authAPI.resetPassword.mockRejectedValue(err);
  type('Confirm Password', 'longpassword1');
  fireEvent.click(screen.getByText('Set New Password →'));
  expect(await screen.findByText('Get a new reset link')).toHaveAttribute('href', '/forgot-password');
  expect(screen.queryByLabelText('New Password')).toBeNull();
});

test('a link without a token goes straight to asking for a new one', () => {
  renderAt('/reset-password');
  expect(screen.getByText('This reset link is incomplete.')).toBeInTheDocument();
  expect(screen.getByText('Get a new reset link')).toBeInTheDocument();
});
