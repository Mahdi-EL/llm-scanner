import { render } from '@testing-library/react';
import { vi } from 'vitest';
import App from './App';

// The landing page asks the API for the attack library's counts: answer here, so the test stays offline
vi.mock('./services/api', async () => {
  const actual = await vi.importActual('./services/api');
  return { ...actual, scansAPI: { ...actual.scansAPI, categories: vi.fn(() => Promise.resolve({ data: { categories: [] } })) } };
});

// Smoke test: the app mounts (Router + providers) without throwing.
test('app renders without crashing', () => {
  const { container } = render(<App />);
  expect(container).toBeTruthy();
});
