import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const API = 'http://localhost:8000';

function NewScan() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [form, setForm] = useState({
    target_name  : '',
    target_type  : 'simulation',
    system_prompt: '',
    api_url      : '',
    api_key      : '',
  });

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async () => {
    if (!form.target_name) {
      alert('Please enter a target name');
      return;
    }

    setLoading(true);
    try {
      const res = await axios.post(`${API}/scan`, {
        target_name  : form.target_name,
        target_type  : form.target_type,
        system_prompt: form.system_prompt || null,
        api_url      : form.api_url || null,
        api_key      : form.api_key || null,
      });

      navigate(`/results/${res.data.scan_id}`);
    } catch (err) {
      alert('Error starting scan. Is the API running ?');
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: '600px' }}>
      <h1 className="page-title">New Scan</h1>
      <p className="page-subtitle">
        Configure and launch an AI security scan
      </p>

      <div className="card">

        <div className="form-group">
          <label>Target Name *</label>
          <input
            name="target_name"
            value={form.target_name}
            onChange={handleChange}
            placeholder="e.g. Banking Chatbot, Customer Support AI"
          />
        </div>

        <div className="form-group">
          <label>Target Type</label>
          <select
            name="target_type"
            value={form.target_type}
            onChange={handleChange}
          >
            <option value="simulation">Simulation (safe for development)</option>
            <option value="groq">Groq Model</option>
            <option value="openai_compatible">OpenAI Compatible API</option>
            <option value="custom_rest">Custom REST API</option>
          </select>
        </div>

        {form.target_type === 'simulation' && (
          <div className="form-group">
            <label>Custom System Prompt (optional)</label>
            <textarea
              name="system_prompt"
              value={form.system_prompt}
              onChange={handleChange}
              placeholder="Leave empty to use default banking simulation..."
            />
          </div>
        )}

        {(form.target_type === 'openai_compatible' ||
          form.target_type === 'custom_rest') && (
          <>
            <div className="form-group">
              <label>API URL *</label>
              <input
                name="api_url"
                value={form.api_url}
                onChange={handleChange}
                placeholder="https://api.yourapp.com/chat"
              />
            </div>
            <div className="form-group">
              <label>API Key</label>
              <input
                name="api_key"
                value={form.api_key}
                onChange={handleChange}
                placeholder="sk-..."
                type="password"
              />
            </div>
          </>
        )}

        <div style={{
          background: '#0f1117',
          border: '1px solid #2a2d3a',
          borderRadius: '8px',
          padding: '16px',
          marginBottom: '24px',
          fontSize: '13px',
          color: '#888888'
        }}>
          ⚡ The scan will fire <strong style={{ color: 'white' }}>85+ attack prompts</strong> across
          9 categories and generate a professional PDF report automatically.
          Estimated time : <strong style={{ color: 'white' }}>10-15 minutes</strong>.
        </div>

        <button
          className="btn-primary"
          onClick={handleSubmit}
          disabled={loading}
          style={{ width: '100%', padding: '14px', fontSize: '16px' }}
        >
          {loading ? 'Starting scan...' : '🚀 Launch Security Scan'}
        </button>

      </div>
    </div>
  );
}

export default NewScan;