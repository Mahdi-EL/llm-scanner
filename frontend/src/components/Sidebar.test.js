import React, { useState } from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';

vi.mock('../context/AuthContext', () => ({ useAuth: () => ({
  user: { id: 'u1', username: 'ann', plan: 'free', workspaces: [] }, logout: vi.fn(), switchWorkspace: vi.fn(), canEdit: true,
}) }));

const { default: Sidebar } = await import('./Sidebar');

function Shell() {
  const [open, setOpen] = useState(false);
  return (
    <MemoryRouter>
      <button onClick={() => setOpen(true)}>Open menu</button>
      <Sidebar mobileOpen={open} onClose={() => setOpen(false)} />
    </MemoryRouter>
  );
}

test('the phone menu takes focus when it opens and gives it back when it closes', () => {
  render(<Shell />);
  const opener = screen.getByText('Open menu');
  opener.focus();
  fireEvent.click(opener);
  const drawer = document.querySelector('aside.sidebar');
  expect(drawer.classList.contains('mobile-open')).toBe(true);
  expect(drawer.contains(document.activeElement)).toBe(true);           // in the menu that just opened
  fireEvent.keyDown(window, { key: 'Escape' });
  expect(drawer.classList.contains('mobile-open')).toBe(false);
  expect(document.activeElement).toBe(opener);                         // back where it was
});
