import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const API = 'http://localhost:8000';
const ITEMS_PER_PAGE = 5;

function Dashboard() {
  const [scans, setScans]         = useState([]);
  const [loading, setLoading]     = useState(true);
  const [search, setSearch]       = useState('');
  const [filter, setFilter]       = useState('ALL');
  const [currentPage, setCurrentPage] = useState(1);
  const navigate = useNavigate();

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 3000);
    return () => clearInterval(interval);
  }, []);

  const fetchScans = async () => {
    try {
      const res = await axios.get(`${API}/scans`);
      setScans(res.data.scans.reverse());
      setLoading(false);
    } catch (err) {
      setLoading(false);
    }
  };

  const exportCSV = () => {
    const headers = ['Target', 'Status', 'Security Score', 'Critical', 'High', 'Date'];
    const rows = scans.map(s => [
      s.target_name,
      s.status,
      s.results?.summary?.security_score || 0,
      s.results?.summary?.critical || 0,
      s.results?.summary?.high || 0,
      new Date(s.created_at).toLocaleString()
    ]);

    const csv = [headers, ...rows]
      .map(r => r.join(','))
      .join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = 'llm_scanner_results.csv';
    a.click();
  };

  const getStatusBadge = (status) => {
    const map = {
      complete : { label: 'Complete', cls: 'badge badge-safe' },
      running  : { label: 'Running',  cls: 'badge badge-running' },
      pending  : { label: 'Pending',  cls: 'badge badge-pending' },
      failed   : { label: 'Failed',   cls: 'badge badge-critical' },
    };
    const s = map[status] || { label: status, cls: 'badge' };
    return <span className={s.cls}>{s.label}</span>;
  };

  const getScoreColor = (results) => {
    if (!results) return '#888888';
    const score = results.summary?.security_score || 0;
    if (score >= 70) return '#2ECC71';
    if (score >= 40) return '#F1C40F';
    return '#C0392B';
  };

  // Filter + Search
  const filteredScans = scans
    .filter(s => {
      if (filter === 'ALL') return true;
      return s.status === filter.toLowerCase();
    })
    .filter(s =>
      s.target_name.toLowerCase().includes(search.toLowerCase())
    );

  // Pagination
  const totalPages   = Math.ceil(filteredScans.length / ITEMS_PER_PAGE);
  const paginatedScans = filteredScans.slice(
    (currentPage - 1) * ITEMS_PER_PAGE,
    currentPage * ITEMS_PER_PAGE
  );

  const totalScans     = scans.length;
  const completedScans = scans.filter(s => s.status === 'complete').length;
  const runningScans   = scans.filter(s => s.status === 'running').length;
  const avgScore = completedScans > 0
    ? Math.round(
        scans
          .filter(s => s.status === 'complete')
          .reduce((acc, s) => acc + (s.results?.summary?.security_score || 0), 0)
        / completedScans
      )
    : 0;

  return (
    <div>
      <h1 className="page-title">Dashboard</h1>
      <p className="page-subtitle">
        Overview of all your AI security scans
      </p>

      {/* Stats */}
      <div className="stats-row">
        <div className="stat-card">
          <div className="stat-number" style={{ color: '#2E75B6' }}>
            {totalScans}
          </div>
          <div className="stat-label">Total Scans</div>
        </div>
        <div className="stat-card">
          <div className="stat-number" style={{ color: '#2ECC71' }}>
            {completedScans}
          </div>
          <div className="stat-label">Completed</div>
        </div>
        <div className="stat-card">
          <div className="stat-number" style={{ color: '#F1C40F' }}>
            {runningScans}
          </div>
          <div className="stat-label">Running</div>
        </div>
        <div className="stat-card">
          <div className="stat-number" style={{ color: '#E67E22' }}>
            {avgScore}%
          </div>
          <div className="stat-label">Avg Security Score</div>
        </div>
      </div>

      {/* Scans Table */}
      <div className="card">
        <div style={{
          display       : 'flex',
          justifyContent: 'space-between',
          alignItems    : 'center',
          marginBottom  : '16px'
        }}>
          <h2 style={{ fontSize: '18px' }}>Recent Scans</h2>
          <div style={{ display: 'flex', gap: '10px' }}>
            <button
              className="btn-primary"
              style={{ padding: '8px 16px', fontSize: '13px' }}
              onClick={exportCSV}
            >
              Export CSV
            </button>
            <button
              className="btn-primary"
              onClick={() => navigate('/new-scan')}
            >
              + New Scan
            </button>
          </div>
        </div>

        {/* Search */}
        <input
          className="search-bar"
          placeholder="Search by target name..."
          value={search}
          onChange={e => {
            setSearch(e.target.value);
            setCurrentPage(1);
          }}
        />

        {/* Filters */}
        <div className="filter-row">
          {['ALL', 'COMPLETE', 'RUNNING', 'FAILED'].map(f => (
            <button
              key={f}
              className={`filter-btn ${filter === f ? 'active' : ''}`}
              onClick={() => {
                setFilter(f);
                setCurrentPage(1);
              }}
            >
              {f}
            </button>
          ))}
        </div>

        {loading ? (
          <p style={{ color: '#888888' }}>Loading...</p>
        ) : filteredScans.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '40px', color: '#888888' }}>
            <p style={{ fontSize: '48px', marginBottom: '16px' }}>🔐</p>
            <p style={{ fontSize: '18px', marginBottom: '8px' }}>
              {search ? 'No scans found' : 'No scans yet'}
            </p>
            <button
              className="btn-primary"
              onClick={() => navigate('/new-scan')}
            >
              Start First Scan
            </button>
          </div>
        ) : (
          <>
            <table className="scan-table">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Security Score</th>
                  <th>Critical</th>
                  <th>High</th>
                  <th>Date</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {paginatedScans.map(scan => (
                  <tr
                    key={scan.scan_id}
                    onClick={() =>
                      scan.status === 'complete' &&
                      navigate(`/results/${scan.scan_id}`)
                    }
                  >
                    <td style={{ fontWeight: '500' }}>
                      {scan.target_name}
                    </td>
                    <td>{getStatusBadge(scan.status)}</td>
                    <td>
                      {scan.results ? (
                        <span style={{
                          color     : getScoreColor(scan.results),
                          fontWeight: '600'
                        }}>
                          {scan.results.summary?.security_score}%
                        </span>
                      ) : '—'}
                    </td>
                    <td>
                      {scan.results ? (
                        <span className="critical" style={{ fontWeight: '600' }}>
                          {scan.results.summary?.critical}
                        </span>
                      ) : '—'}
                    </td>
                    <td>
                      {scan.results ? (
                        <span className="high" style={{ fontWeight: '600' }}>
                          {scan.results.summary?.high}
                        </span>
                      ) : '—'}
                    </td>
                    <td style={{ color: '#888888', fontSize: '13px' }}>
                      {new Date(scan.created_at).toLocaleString()}
                    </td>
                    <td>
                      {scan.status === 'complete' && (
                        <button
                          className="btn-primary"
                          style={{ padding: '6px 14px', fontSize: '12px' }}
                          onClick={e => {
                            e.stopPropagation();
                            navigate(`/results/${scan.scan_id}`);
                          }}
                        >
                          View Report
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="pagination">
                {Array.from({ length: totalPages }, (_, i) => (
                  <button
                    key={i}
                    className={`page-btn ${currentPage === i+1 ? 'active' : ''}`}
                    onClick={() => setCurrentPage(i + 1)}
                  >
                    {i + 1}
                  </button>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

export default Dashboard;