import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { vi } from 'vitest';

vi.mock('../services/api', async () => {
  const actual = await vi.importActual('../services/api');
  return {
    ...actual,
    plansAPI: { list: vi.fn(), checkout: vi.fn(), portal: vi.fn() },
    scansAPI: {
      get: vi.fn(), list: vi.fn(), compare: vi.fn(), categories: vi.fn(), cancel: vi.fn(),
      share: vi.fn(), delete: vi.fn(),
    },
    downloadReport: vi.fn(),
  };
});

vi.mock('../context/AuthContext', () => ({ useAuth: () => ({ user: null }) }));
vi.mock('../context/ToastContext', () => ({ useToast: () => vi.fn() }));

const api = await import('../services/api');
const { default: Pricing } = await import('./Pricing');
const { default: Results } = await import('./Results');

function renderAt(path, element, route) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes><Route path={route} element={element} /></Routes>
    </MemoryRouter>
  );
}

test('Pricing shows the plans from the API, and unbuyable plans are disabled', async () => {
  api.plansAPI.list.mockResolvedValue({ data: { plans: {
    free: { name: 'Free', amount: 0, currency: 'eur', interval: 'month', scan_limit: 10, features: ['10 scans per month'], purchasable: false, trial_days: 0 },
    pro: { name: 'Pro', amount: 4900, currency: 'eur', interval: 'month', scan_limit: 200, features: ['200 scans per month'], purchasable: false, trial_days: 0 },
  } } });
  renderAt('/pricing', <Pricing />, '/pricing');
  expect(await screen.findByText('200 scans per month', { selector: 'div' })).toBeInTheDocument();
  expect(screen.getByText('€49')).toBeInTheDocument();
  expect(screen.getByText('Not available yet')).toBeDisabled();
  expect(screen.queryByText(/free trial/i)).toBeNull();
});

const CATEGORIES = { data: { categories: [{ id: 'extraction', title: 'System prompt extraction', tests: '', owasp: ['LLM07 System Prompt Leakage'], attacks: 68 }] } };

test('Results shows real progress for a running scan', async () => {
  api.scansAPI.categories.mockResolvedValue(CATEGORIES);
  api.scansAPI.get.mockResolvedValue({ data: {
    scan_id: 'abc', target_name: 'Bot', status: 'running', progress: 42,
    completed_attacks: 450, total_attacks: 1075, current_category: 'extraction', created_at: '2026-10-16T10:00:00+00:00',
  } });
  renderAt('/results/abc', <Results />, '/results/:id');
  expect(await screen.findByText('42%')).toBeInTheDocument();
  expect(screen.getByText(/450 of 1075 attacks done/)).toBeInTheDocument();
  expect(screen.getByText('Cancel scan')).toBeInTheDocument();
});

test('Results lists every finding with "show more" and downloads with auth', async () => {
  const results = Array.from({ length: 30 }, (_, i) => ({
    category: 'extraction', attack: `attack ${i}`, response: `reply ${i}`, score: 9,
    severity: i < 28 ? 'HIGH' : 'SAFE', reason: 'leaked', owasp: ['LLM07'],
  }));
  api.scansAPI.categories.mockResolvedValue(CATEGORIES);
  api.scansAPI.list.mockResolvedValue({ data: { scans: [] } });
  api.scansAPI.get.mockResolvedValue({ data: {
    scan_id: 'done', target_name: 'Bot', status: 'complete', created_at: '2026-10-16T10:00:00+00:00',
    summary: { security_score: 30, grade: 'F', critical: 0, high: 28, medium: 0, low: 0, safe: 2, errors: 0 },
    results: { summary: { security_score: 30, grade: 'F', high: 28, safe: 2, tested: 30, errors: 0 }, results },
    recommendations: [{ priority: 'P1', category: 'extraction', title: 'System prompt extraction', owasp: ['LLM07 System Prompt Leakage'], failed: 28, worst: 'HIGH', fix: ['Remove secrets from the prompt.'] }],
  } });
  renderAt('/results/done', <Results />, '/results/:id');
  expect(await screen.findByText('Grade F')).toBeInTheDocument();
  expect(screen.getByText('Remove secrets from the prompt.')).toBeInTheDocument();
  expect(screen.getAllByText(/^attack \d+$/)).toHaveLength(25);
  fireEvent.click(screen.getByText(/Show 3 more/));
  expect(screen.getAllByText(/^attack \d+$/)).toHaveLength(28);
  fireEvent.click(screen.getByText('Download PDF'));
  await waitFor(() => expect(api.downloadReport).toHaveBeenCalledWith('done', 'pdf'));
});
