import React from 'react';
import { act, render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { vi } from 'vitest';
import CommandPalette from './CommandPalette';

function Where() {
  return <div data-testid="where">{useLocation().pathname}</div>;
}

test('Enter opens the selected result, closes, and swallows the key', () => {
  const onClose = vi.fn();
  render(
    <MemoryRouter initialEntries={['/reports']}>
      <CommandPalette open onClose={onClose} />
      <Routes><Route path="*" element={<Where />} /></Routes>
    </MemoryRouter>
  );
  fireEvent.change(screen.getByRole('combobox', { name: /search pages/i }), { target: { value: 'settings' } });
  const enter = new KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true });
  act(() => { window.dispatchEvent(enter); });
  expect(onClose).toHaveBeenCalled();
  expect(enter.defaultPrevented).toBe(true);    // so a refocused button can't re-open the palette
  expect(screen.getByTestId('where')).toHaveTextContent('/settings');
});

test('the palette is a labelled dialog with a listbox of options', () => {
  render(<MemoryRouter><CommandPalette open onClose={() => {}} /></MemoryRouter>);
  expect(screen.getByRole('dialog', { name: 'Command palette' })).toBeInTheDocument();
  expect(screen.getAllByRole('option').length).toBeGreaterThan(0);
});

test('Tab keeps focus inside the open palette', () => {
  render(<MemoryRouter><button>Behind</button><CommandPalette open onClose={() => {}} /></MemoryRouter>);
  const box = screen.getByRole('combobox', { name: /search pages/i });
  box.focus();
  act(() => { window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true })); });
  expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Close' }));
  act(() => { window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true })); });
  expect(document.activeElement).toBe(box);               // wraps around, never to the page behind
});
