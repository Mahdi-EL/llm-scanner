import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import Results from './pages/Results';
import Pricing from './pages/Pricing';
import './App.css';

function App() {
  return (
    <Router>
      <div className="app">
        <Navbar />
        <div className="main-content">
          <Routes>
            <Route path="/"            element={<Dashboard />} />
            <Route path="/new-scan"    element={<NewScan />} />
            <Route path="/results/:id" element={<Results />} />
            <Route path="/pricing"     element={<Pricing />} />
          </Routes>
        </div>
      </div>
    </Router>
  );
}

export default App;