import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';

const API = 'http://localhost:8000';

function Results() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan]     = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchScan();
    const interval = setInterval(() => {
      if (scan?.status !== 'complete') fetchScan();
    }, 3000);
    return () => clearInterval(interval);
  }, [id]);

  const fetchScan = async () => {
    try {
      const res = await axios.get(`${API}/scan/${id}`);
      setScan(res.data);
      setLoading(false);
    } catch (err) {
      setLoading(false);
    }
  };

  const downloadPDF = () => {
    window.open(`${API}/download/${id}`, '_blank');
  };

  const getScoreColor = (score) => {
    if (score >= 70) return '#2ECC71';
    if (score >= 40) return '#F1C40F';
    return '#C0392B';
  };

  if (loading) return (
    <div style={{ textAlign: 'center', padding: '80px', color: '#888888' }}>
      Loading...
    </div>
  );

  if (!scan) return (
    <div style={{ textAlign: 'center', padding: '80px', color: '#888888' }}>
      Scan not found.
    </div>
  );

  if (scan.status === 'running' || scan.status === 'pending') return (
    <div style={{ textAlign: 'center', padding: '80px' }}>
      <div style={{ fontSize: '64px', marginBottom: '24px' }}>⏳</div>
      <h2 style={{ marginBottom: '12px' }}>Scan In Progress</h2>
      <p style={{ color: '#888888', marginBottom: '8px' }}>
        Target : <strong>{scan.target_name}</strong>
      </p>
      <p style={{ color: '#888888', marginBottom: '32px' }}>
        Firing 85+ attack prompts and analyzing responses...
      </p>
      <div style={{
        background: '#1a1d27',
        borderRadius: '8px',
        padding: '16px',
        display: 'inline-block',
        color: '#2E75B6'
      }}>
        This usually takes 10-15 minutes. Page refreshes automatically.
      </div>
    </div>
  );

  if (scan.status === 'failed') return (
    <div style={{ textAlign: 'center', padding: '80px' }}>
      <div style={{ fontSize: '64px', marginBottom: '24px' }}>❌</div>
      <h2 style={{ marginBottom: '12px', color: '#C0392B' }}>Scan Failed</h2>
      <p style={{ color: '#888888' }}>{scan.error}</p>
    </div>
  );

  const summary = scan.results?.summary || {};
  const score   = summary.security_score || 0;

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '30px' }}>
        <div>
          <h1 className="page-title">{scan.target_name}</h1>
          <p className="page-subtitle">
            Scan completed on {new Date(scan.created_at).toLocaleString()}
          </p>
        </div>
        <div style={{ display: 'flex', gap: '12px' }}>
          <button
            className="btn-primary"
            onClick={downloadPDF}
          >
            Download PDF Report
          </button>
          <button
            style={{ background: 'transparent', border: '1px solid #2a2d3a', color: '#888888', padding: '12px 24px', borderRadius: '8px', cursor: 'pointer' }}
            onClick={() => navigate('/')}
          >
            Back to Dashboard
          </button>
        </div>
      </div>

      {/* Score + Summary */}
      <div className="stats-row">
        <div className="stat-card" style={{ textAlign: 'center' }}>
          <div className="stat-number" style={{ color: getScoreColor(score), fontSize: '42px' }}>
            {score}%
          </div>
          <div className="stat-label">Security Score</div>
        </div>
        <div className="stat-card">
          <div className="stat-number critical">{summary.critical || 0}</div>
          <div className="stat-label">Critical</div>
        </div>
        <div className="stat-card">
          <div className="stat-number high">{summary.high || 0}</div>
          <div className="stat-label">High</div>
        </div>
        <div className="stat-card">
          <div className="stat-number safe">{summary.safe || 0}</div>
          <div className="stat-label">Safe</div>
        </div>
      </div>

      {/* Results by severity */}
      {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => {
        const items = scan.results?.results?.filter(r => r.severity === sev) || [];
        if (items.length === 0) return null;

        return (
          <div key={sev} className="card">
            <h2 style={{ fontSize: '16px', marginBottom: '16px' }}>
              <span className={`badge badge-${sev.toLowerCase()}`}>{sev}</span>
              <span style={{ marginLeft: '12px', color: '#888888', fontSize: '14px' }}>
                {items.length} finding{items.length > 1 ? 's' : ''}
              </span>
            </h2>

            {items.slice(0, 5).map((item, idx) => (
              <div key={idx} style={{
                borderBottom: '1px solid #2a2d3a',
                paddingBottom: '16px',
                marginBottom: '16px'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <span style={{ color: '#aaaaaa', fontSize: '13px' }}>
                    {item.category.replace(/_/g, ' ').toUpperCase()}
                  </span>
                  <span style={{ color: '#888888', fontSize: '13px' }}>
                    Score: {item.score}/10
                  </span>
                </div>
                <p style={{ fontSize: '14px', marginBottom: '6px' }}>
                  <strong>Attack:</strong> {item.attack.substring(0, 80)}...
                </p>
                <p style={{ fontSize: '13px', color: '#888888' }}>
                  <strong style={{ color: '#aaaaaa' }}>Reason:</strong> {item.reason}
                </p>
              </div>
            ))}

            {items.length > 5 && (
              <p style={{ color: '#888888', fontSize: '13px', textAlign: 'center' }}>
                + {items.length - 5} more findings in the PDF report
              </p>
            )}
          </div>
        );
      })}

    </div>
  );
}

export default Results;