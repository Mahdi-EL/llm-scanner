import React, { useState, useEffect, Suspense, lazy } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, Link, useLocation } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ToastProvider } from './context/ToastContext';
import { ConfirmProvider } from './context/ConfirmContext';
import Navbar          from './components/Navbar';
import Sidebar         from './components/Sidebar';
import TopBar          from './components/TopBar';
import CommandPalette  from './components/CommandPalette';
import ErrorBoundary   from './components/ErrorBoundary';
import LandingPage     from './pages/LandingPage';
import Login           from './pages/Login';
import Register        from './pages/Register';
import { safeNext } from './utils/format';
import './App.css';

// The app's pages load on demand, so visitors to the landing page don't
// download the dashboard and its chart library.
const Dashboard      = lazy(() => import('./pages/Dashboard'));
const NewScan        = lazy(() => import('./pages/NewScan'));
const Results        = lazy(() => import('./pages/Results'));
const Reports        = lazy(() => import('./pages/Reports'));
const Targets        = lazy(() => import('./pages/Targets'));
const Analytics      = lazy(() => import('./pages/Analytics'));
const ThreatIntel    = lazy(() => import('./pages/ThreatIntel'));
const Settings       = lazy(() => import('./pages/Settings'));
const Pricing        = lazy(() => import('./pages/Pricing'));
const ForgotPassword = lazy(() => import('./pages/ForgotPassword'));
const ResetPassword  = lazy(() => import('./pages/ResetPassword'));
const VerifyEmail    = lazy(() => import('./pages/VerifyEmail'));
const SharedReport   = lazy(() => import('./pages/SharedReport'));
const LeakCheck      = lazy(() => import('./pages/LeakCheck'));
const InviteAccept   = lazy(() => import('./pages/InviteAccept'));

/* ── Layout shells ──────────────────────────────────────────── */

function Loading({ label = 'Loading…' }) {
  return (
    <div style={{ display:'flex', alignItems:'center', justifyContent:'center', minHeight:'60vh', gap:'12px' }}>
      <div className="spinner" style={{ width:'20px', height:'20px' }} />
      <span style={{ color:'var(--t3)', fontSize:'14px' }}>{label}</span>
    </div>
  );
}

function PublicShell({ children }) {
  return (
    <div className="app">
      <a href="#main" className="skip-link">Skip to content</a>
      <Navbar />
      <main id="main" tabIndex={-1}><Suspense fallback={<Loading />}>{children}</Suspense></main>
    </div>
  );
}

function AppShell({ children }) {
  const { canEdit } = useAuth();
  const [cmdOpen, setCmdOpen] = useState(false);
  const [navOpen, setNavOpen] = useState(false);
  const { pathname } = useLocation();
  useEffect(() => { setNavOpen(false); }, [pathname]);

  useEffect(() => {
    const handler = e => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setCmdOpen(o => !o);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  return (
    <div className="app-with-sidebar">
      <a href="#main" className="skip-link">Skip to content</a>
      <Sidebar mobileOpen={navOpen} onClose={() => setNavOpen(false)} />
      <div className="app-main">
        <TopBar onOpenCmd={() => setCmdOpen(true)} onOpenNav={() => setNavOpen(true)} />
        <main id="main" className="main-content" tabIndex={-1}>
          <EmailBanner />
          <Suspense fallback={<Loading />}>{children}</Suspense>
        </main>
      </div>
      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} canScan={canEdit} />
    </div>
  );
}

/* Shown until the user confirms their email (only when email delivery is set up). */
function EmailBanner() {
  const { user } = useAuth();
  if (!user || user.email_verified) return null;
  return (
    <div style={{ marginBottom:'20px', padding:'10px 14px', border:'1px solid var(--b1)', borderRadius:'8px', fontSize:'13px', color:'var(--t2)' }}>
      Please confirm your email address. We sent a link to <strong>{user.email}</strong>.
      You can resend it from <Link to="/settings">Settings</Link>.
    </div>
  );
}

function Offline({ onRetry }) {
  return (
    <div className="empty-state" style={{ padding:'120px 24px' }}>
      <h3>Can’t reach the server</h3>
      <p>The API may be waking up or your connection dropped. You’re still signed in.</p>
      <button className="btn-primary" onClick={onRetry}>Retry</button>
    </div>
  );
}

/* ── Auth guard ─────────────────────────────────────────────── */

function ProtectedRoute({ children }) {
  const { user } = useAuth();
  const { pathname, search } = useLocation();
  return user ? children : <Navigate to={`/login?next=${encodeURIComponent(pathname + search)}`} replace />;
}

/* ── Browser tab titles ─────────────────────────────────────── */

const TITLES = {
  '/new-scan': 'New scan', '/reports': 'Reports', '/targets': 'Targets and CI', '/analytics': 'Analytics',
  '/threat-intel': 'Attack library', '/settings': 'Settings', '/pricing': 'Pricing', '/login': 'Sign in',
  '/register': 'Create account', '/forgot-password': 'Reset password', '/reset-password': 'Reset password',
  '/verify-email': 'Confirm email', '/results/': 'Scan results', '/shared/': 'Shared report',
  '/check': 'Free leak check', '/invite': 'Team invite',
};
const BASE_TITLE = 'LLM Scanner: red-team your AI applications';

function useDocumentTitle(signedIn) {
  const { pathname } = useLocation();
  useEffect(() => {
    const key = Object.keys(TITLES).find(k => k.endsWith('/') ? pathname.startsWith(k) : pathname === k);
    const page = key ? TITLES[key] : pathname === '/' && signedIn ? 'Dashboard' : null;
    document.title = page ? `${page} · LLM Scanner` : BASE_TITLE;
  }, [pathname, signedIn]);
}

/* ── Routes ─────────────────────────────────────────────────── */

function AppRoutes() {
  const { user, loading, offline, refreshUser } = useAuth();
  const { search } = useLocation();
  useDocumentTitle(!!user);
  const next = safeNext(new URLSearchParams(search).get('next'));

  if (loading) return <Loading />;
  if (offline) return <Offline onRetry={refreshUser} />;

  const app = page => <ProtectedRoute><AppShell>{page}</AppShell></ProtectedRoute>;

  return (
    <Routes>
      {/* ── Public: marketing + auth ─────────────────── */}
      <Route path="/" element={user ? app(<Dashboard />) : <PublicShell><LandingPage /></PublicShell>} />
      <Route path="/landing"         element={<PublicShell><LandingPage /></PublicShell>} />
      <Route path="/login"           element={user ? <Navigate to={next} replace /> : <PublicShell><Login /></PublicShell>} />
      <Route path="/register"        element={user ? <Navigate to={next} replace /> : <PublicShell><Register /></PublicShell>} />
      <Route path="/forgot-password" element={<PublicShell><ForgotPassword /></PublicShell>} />
      <Route path="/reset-password"  element={<PublicShell><ResetPassword /></PublicShell>} />
      <Route path="/verify-email"    element={<PublicShell><VerifyEmail /></PublicShell>} />
      <Route path="/shared/:token"   element={<PublicShell><SharedReport /></PublicShell>} />
      <Route path="/check"           element={<PublicShell><LeakCheck /></PublicShell>} />
      <Route path="/invite"          element={<PublicShell><InviteAccept /></PublicShell>} />

      {/* ── Pricing: sidebar when signed in, navbar when not ── */}
      <Route path="/pricing" element={user ? <AppShell><Pricing /></AppShell> : <PublicShell><Pricing /></PublicShell>} />

      {/* ── Protected: app shell with sidebar ─────────── */}
      <Route path="/dashboard"    element={<Navigate to="/" replace />} />
      <Route path="/new-scan"     element={app(<NewScan />)} />
      <Route path="/results/:id"  element={app(<Results />)} />
      <Route path="/reports"      element={app(<Reports />)} />
      <Route path="/targets"      element={app(<Targets />)} />
      <Route path="/integrations" element={<Navigate to="/targets" replace />} />
      <Route path="/analytics"    element={app(<Analytics />)} />
      <Route path="/threat-intel" element={app(<ThreatIntel />)} />
      <Route path="/settings"     element={app(<Settings />)} />

      {/* ── Fallback ──────────────────────────────────── */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <ToastProvider>
          <ConfirmProvider>
            <Router>
              <AppRoutes />
            </Router>
          </ConfirmProvider>
        </ToastProvider>
      </AuthProvider>
    </ErrorBoundary>
  );
}
