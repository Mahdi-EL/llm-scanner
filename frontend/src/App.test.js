import { render } from '@testing-library/react';
import App from './App';

// Smoke test: the app mounts (Router + providers) without throwing.
test('app renders without crashing', () => {
  const { container } = render(<App />);
  expect(container).toBeTruthy();
});
