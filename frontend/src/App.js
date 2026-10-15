import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ToastProvider } from './context/ToastContext';
import Navbar          from './components/Navbar';
import Sidebar         from './components/Sidebar';
import TopBar          from './components/TopBar';
import CommandPalette  from './components/CommandPalette';
import ErrorBoundary   from './components/ErrorBoundary';
import LandingPage     from './pages/LandingPage';
import Dashboard       from './pages/Dashboard';
import NewScan         from './pages/NewScan';
import Results         from './pages/Results';
import Reports         from './pages/Reports';
import Integrations    from './pages/Integrations';
import Analytics       from './pages/Analytics';
import ThreatIntel     from './pages/ThreatIntel';
import Settings        from './pages/Settings';
import Pricing         from './pages/Pricing';
import Login           from './pages/Login';
import Register        from './pages/Register';
import ForgotPassword  from './pages/ForgotPassword';
import ResetPassword   from './pages/ResetPassword';
import './App.css';

/* ── Layout shells ──────────────────────────────────────────── */

function PublicShell({ children }) {
  return (
    <div className="app">
      <Navbar />
      {children}
    </div>
  );
}

function AppShell({ children }) {
  const [cmdOpen, setCmdOpen] = useState(false);

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
      <Sidebar />
      <div className="app-main">
        <TopBar onOpenCmd={() => setCmdOpen(true)} />
        <div className="main-content">{children}</div>
      </div>
      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} />
    </div>
  );
}

/* ── Auth guard ─────────────────────────────────────────────── */

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) return (
    <div style={{ display:'flex', alignItems:'center', justifyContent:'center', minHeight:'100vh', gap:'12px' }}>
      <div className="spinner" style={{ width:'20px', height:'20px' }} />
      <span style={{ color:'var(--t3)', fontSize:'14px' }}>Loading…</span>
    </div>
  );
  return user ? children : <Navigate to="/login" replace />;
}

/* ── Routes ─────────────────────────────────────────────────── */

function AppRoutes() {
  const { user, loading } = useAuth();

  if (loading) return (
    <div style={{ display:'flex', alignItems:'center', justifyContent:'center', minHeight:'100vh', gap:'12px' }}>
      <div className="spinner" style={{ width:'20px', height:'20px' }} />
      <span style={{ color:'var(--t3)', fontSize:'14px' }}>Loading…</span>
    </div>
  );

  return (
    <Routes>

      {/* ── Public: marketing + auth ─────────────────── */}
      <Route path="/landing"
        element={<PublicShell><LandingPage /></PublicShell>} />
      <Route path="/login"
        element={user ? <Navigate to="/" replace /> : <PublicShell><Login /></PublicShell>} />
      <Route path="/register"
        element={user ? <Navigate to="/" replace /> : <PublicShell><Register /></PublicShell>} />
      <Route path="/forgot-password"
        element={<PublicShell><ForgotPassword /></PublicShell>} />
      <Route path="/reset-password"
        element={<PublicShell><ResetPassword /></PublicShell>} />

      {/* ── Pricing: sidebar when auth, navbar when not ── */}
      <Route path="/pricing"
        element={user
          ? <AppShell><Pricing /></AppShell>
          : <PublicShell><Pricing /></PublicShell>
        } />

      {/* ── Protected: app shell with sidebar ─────────── */}
      <Route path="/" element={
        <ProtectedRoute><AppShell><Dashboard /></AppShell></ProtectedRoute>
      } />
      <Route path="/new-scan" element={
        <ProtectedRoute><AppShell><NewScan /></AppShell></ProtectedRoute>
      } />
      <Route path="/results/:id" element={
        <ProtectedRoute><AppShell><Results /></AppShell></ProtectedRoute>
      } />
      <Route path="/reports" element={
        <ProtectedRoute><AppShell><Reports /></AppShell></ProtectedRoute>
      } />
      <Route path="/integrations" element={
        <ProtectedRoute><AppShell><Integrations /></AppShell></ProtectedRoute>
      } />
      <Route path="/analytics" element={
        <ProtectedRoute><AppShell><Analytics /></AppShell></ProtectedRoute>
      } />
      <Route path="/threat-intel" element={
        <ProtectedRoute><AppShell><ThreatIntel /></AppShell></ProtectedRoute>
      } />
      <Route path="/settings" element={
        <ProtectedRoute><AppShell><Settings /></AppShell></ProtectedRoute>
      } />

      {/* ── Fallback ──────────────────────────────────── */}
      <Route path="*" element={<Navigate to={user ? '/' : '/landing'} replace />} />

    </Routes>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <ToastProvider>
          <Router>
            <AppRoutes />
          </Router>
        </ToastProvider>
      </AuthProvider>
    </ErrorBoundary>
  );
}
