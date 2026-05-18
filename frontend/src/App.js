import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Navbar      from './components/Navbar';
import Dashboard   from './pages/Dashboard';
import NewScan     from './pages/NewScan';
import Results     from './pages/Results';
import Pricing     from './pages/Pricing';
import Login       from './pages/Login';
import Register    from './pages/Register';
import ForgotPassword from './pages/ForgotPassword';
import './App.css';

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <div style={{ color: '#64748b', padding: '80px', textAlign: 'center' }}>Loading...</div>;
  return user ? children : <Navigate to="/login" replace />;
}

function AppRoutes() {
  const [darkMode, setDarkMode] = useState(true);
  const { user } = useAuth();

  return (
    <div className={`app ${darkMode ? '' : 'light-mode'}`}>
      <Navbar darkMode={darkMode} toggleDarkMode={() => setDarkMode(d => !d)} />
      <div className="main-content">
        <Routes>
          {/* Public */}
          <Route path="/login"           element={user ? <Navigate to="/"        replace /> : <Login />} />
          <Route path="/register"        element={user ? <Navigate to="/"        replace /> : <Register />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />

          {/* Protected */}
          <Route path="/"            element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
          <Route path="/new-scan"    element={<ProtectedRoute><NewScan /></ProtectedRoute>} />
          <Route path="/results/:id" element={<ProtectedRoute><Results /></ProtectedRoute>} />
          <Route path="/pricing"     element={<Pricing />} />
        </Routes>
      </div>
    </div>
  );
}

function App() {
  return (
    <AuthProvider>
      <Router>
        <AppRoutes />
      </Router>
    </AuthProvider>
  );
}

export default App;
