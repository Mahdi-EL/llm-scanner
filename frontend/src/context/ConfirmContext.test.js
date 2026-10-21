import React, { useState } from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ConfirmProvider, useConfirm } from './ConfirmContext';

function Asker() {
  const confirm = useConfirm();
  const [answer, setAnswer] = useState('none');
  const ask = async () => setAnswer(String(await confirm({ title: 'Delete this scan?', body: 'Gone for good.',
                                                           confirmLabel: 'Delete scan' })));
  return <><button onClick={ask}>Ask</button><output>{answer}</output></>;
}

function setup() {
  render(<ConfirmProvider><Asker /></ConfirmProvider>);
  const opener = screen.getByText('Ask');
  opener.focus();
  fireEvent.click(opener);
  return opener;
}

test('the dialog is labelled, starts on Cancel and keeps focus inside', () => {
  setup();
  const dialog = screen.getByRole('alertdialog', { name: 'Delete this scan?' });
  expect(dialog).toHaveAttribute('aria-modal', 'true');
  expect(dialog).toHaveAccessibleDescription('Gone for good.');
  expect(screen.getByText('Cancel')).toHaveFocus();
  fireEvent.keyDown(dialog, { key: 'Tab' });
  expect(screen.getByText('Delete scan')).toHaveFocus();
  fireEvent.keyDown(dialog, { key: 'Tab' });
  expect(screen.getByText('Cancel')).toHaveFocus();
});

test('Escape cancels and gives focus back', async () => {
  const opener = setup();
  fireEvent.keyDown(screen.getByRole('alertdialog'), { key: 'Escape' });
  await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('false'));
  expect(screen.queryByRole('alertdialog')).toBeNull();
  expect(opener).toHaveFocus();
});

test('the confirm button answers yes', async () => {
  setup();
  fireEvent.click(screen.getByText('Delete scan'));
  await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('true'));
});
