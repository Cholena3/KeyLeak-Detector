import React, { useState } from 'react';

function FindingsTable({ findings, apiBase, onUpdate }) {
  const [severityFilter, setSeverityFilter] = useState('all');
  const [serviceFilter, setServiceFilter] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');

  const services = [...new Set(findings.map((f) => f.service))];
  const sources = [...new Set(findings.map((f) => f.source))];

  const filtered = findings.filter((f) => {
    if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
    if (serviceFilter !== 'all' && f.service !== serviceFilter) return false;
    if (sourceFilter !== 'all' && f.source !== sourceFilter) return false;
    if (statusFilter !== 'all' && f.status !== statusFilter) return false;
    return true;
  });

  const updateStatus = async (id, status) => {
    try {
      await fetch(`${apiBase}/findings/${id}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      });
      onUpdate();
    } catch { /* ignore */ }
  };

  return (
    <div>
      <div className="card" style={{ marginBottom: '20px' }}>
        <div className="card-title">🔓 All Findings ({filtered.length})</div>
        <div className="filter-bar">
          <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} aria-label="Filter by severity">
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select value={serviceFilter} onChange={(e) => setServiceFilter(e.target.value)} aria-label="Filter by service">
            <option value="all">All Services</option>
            {services.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)} aria-label="Filter by source">
            <option value="all">All Sources</option>
            {sources.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} aria-label="Filter by status">
            <option value="all">All Statuses</option>
            <option value="active">Active</option>
            <option value="notified">Notified</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Service</th>
                <th>Severity</th>
                <th>Risk</th>
                <th>Source</th>
                <th>Masked Secret</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f) => (
                <tr key={f.id}>
                  <td style={{ fontSize: '13px', fontWeight: 500 }}>{f.credential_type}</td>
                  <td style={{ fontSize: '13px' }}>{f.service}</td>
                  <td><span className={`severity-badge ${f.severity}`}>{f.severity}</span></td>
                  <td>
                    <span className={`risk-score ${f.risk_score >= 80 ? 'critical' : f.risk_score >= 60 ? 'high' : f.risk_score >= 40 ? 'medium' : 'low'}`}>
                      {f.risk_score}
                    </span>
                  </td>
                  <td style={{ fontSize: '12px' }}>{f.source}</td>
                  <td className="mono">{f.secret_masked}</td>
                  <td><span className={`status-badge ${f.status}`}>{f.status}</span></td>
                  <td>
                    {f.status !== 'resolved' && (
                      <button className="btn btn-success btn-sm" onClick={() => updateStatus(f.id, 'resolved')}>
                        Resolve
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {filtered.length === 0 && (
          <p style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
            No findings match the current filters.
          </p>
        )}
      </div>
    </div>
  );
}

export default FindingsTable;
