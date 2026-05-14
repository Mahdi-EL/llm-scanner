import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import Results from './pages/Results';
import Pricing from './pages/Pricing';
import './App.css';

function App() {
  const [darkMode, setDarkMode] = useState(true);

  const toggleDarkMode = () => setDarkMode(!darkMode);

  return (
    <Router>
      <div className={`app ${darkMode ? '' : 'light-mode'}`}>
        <Navbar darkMode={darkMode} toggleDarkMode={toggleDarkMode} />
        <div className="main-content">
          <Routes>
            <Route path="/"             element={<Dashboard />} />
            <Route path="/new-scan"     element={<NewScan />} />
            <Route path="/results/:id"  element={<Results />} />
            <Route path="/pricing"      element={<Pricing />} />
          </Routes>
        </div>
      </div>
    </Router>
  );
}

export default App;