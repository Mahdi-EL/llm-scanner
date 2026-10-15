import React from 'react';

/* Catches render-time errors anywhere below it and shows a recoverable
   fallback instead of unmounting the whole app to a blank screen. */
export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch(error, info) {
    // Surface in the console; hook a real logger (Sentry, etc.) here later.
    console.error('Unhandled UI error:', error, info);
  }

  handleReload = () => {
    this.setState({ hasError: false });
    window.location.assign('/');
  };

  render() {
    if (!this.state.hasError) return this.props.children;

    return (
      <div style={{
        minHeight: '100vh', display: 'flex', alignItems: 'center',
        justifyContent: 'center', padding: '24px',
        background: 'var(--bg, #f7f8fa)', color: 'var(--t1, #14161c)',
        fontFamily: "'Inter', system-ui, sans-serif", textAlign: 'center',
      }}>
        <div style={{ maxWidth: 420 }}>
          <div style={{ fontSize: 34, marginBottom: 14 }}>⚠️</div>
          <h1 style={{ fontSize: 22, fontWeight: 800, letterSpacing: '-0.4px', marginBottom: 10 }}>
            Something went wrong
          </h1>
          <p style={{ fontSize: 14, lineHeight: 1.6, color: 'var(--t2, #545b68)', marginBottom: 24 }}>
            The page hit an unexpected error. You can reload and continue — your data is safe.
          </p>
          <button onClick={this.handleReload} className="btn-primary" style={{ padding: '11px 22px' }}>
            Reload app
          </button>
        </div>
      </div>
    );
  }
}
