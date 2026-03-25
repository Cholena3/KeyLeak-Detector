import React from 'react';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const SEVERITY_COLORS = { critical: '#f06070', high: '#f0b050', medium: '#50b8e0', low: '#4ecb8d' };
const SOURCE_COLORS = ['#7c6ef0', '#a78bfa', '#f06070', '#f0b050', '#4ecb8d', '#50b8e0'];

const CustomTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    return (
      <div style={{
        background: 'var(--bg-card-solid)',
        border: '1px solid var(--border)',
        borderRadius: '10px',
        padding: '10px 14px',
        boxShadow: 'var(--shadow-md)',
        fontSize: '13px',
        fontWeight: 600,
      }}>
        <span style={{ color: 'var(--text-primary)' }}>{payload[0].name}: </span>
        <span style={{ color: payload[0].color || 'var(--accent)' }}>{payload[0].value}</span>
      </div>
    );
  }
  return null;
};

function Dashboard({ stats, findings }) {
  if (!stats) return <div className="loading-state"><p>No data available</p></div>;

  const severityData = Object.entries(stats.by_severity || {}).map(([name, value]) => ({ name, value }));
  const serviceData = Object.entries(stats.by_service || {}).map(([name, value]) => ({ name, value }));
  const sourceData = Object.entries(stats.by_source || {}).map(([name, value]) => ({ name, value }));
  const recentFindings = (findings || []).slice(0, 5);

  return (
    <div>
      <div className="stats-grid">
        <div className="stat-card critical">
          <div className="stat-icon">🚨</div>
          <div className="stat-value">{stats.total_findings}</div>
          <div className="stat-label">Total Findings</div>
        </div>
        <div className="stat-card high">
          <div className="stat-icon">⚠️</div>
          <div className="stat-value">{stats.by_severity?.critical || 0}</div>
          <div className="stat-label">Critical Severity</div>
        </div>
        <div className="stat-card medium">
          <div className="stat-icon">📊</div>
          <div className="stat-value">{stats.average_risk_score}</div>
          <div className="stat-label">Avg Risk Score</div>
        </div>
        <div className="stat-card success">
          <div className="stat-icon">🔔</div>
          <div className="stat-value">{stats.notifications?.total_sent || 0}</div>
          <div className="stat-label">Alerts Sent</div>
        </div>
        <div className="stat-card" style={{ position: 'relative', overflow: 'hidden' }}>
          <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: '3px', background: 'var(--gradient-hero)', opacity: 1 }}></div>
          <div className="stat-icon">🏆</div>
          <div className="stat-value" style={{ color: 'var(--accent)' }}>{stats.max_risk_score}</div>
          <div className="stat-label">Max Risk Score</div>
        </div>
      </div>

      <div className="charts-grid">
        <div className="card">
          <div className="card-title">Findings by Severity</div>
          <ResponsiveContainer width="100%" height={290}>
            <PieChart>
              <Pie
                data={severityData} cx="50%" cy="50%"
                innerRadius={65} outerRadius={105}
                dataKey="value" paddingAngle={3}
                stroke="none"
                label={({ name, value }) => `${name}: ${value}`}
              >
                {severityData.map((entry) => (
                  <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || '#52546e'} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
              <Legend
                wrapperStyle={{ fontSize: '12px', fontWeight: 600 }}
                iconType="circle"
                iconSize={8}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <div className="card-title">Findings by Service</div>
          <ResponsiveContainer width="100%" height={290}>
            <BarChart data={serviceData} layout="vertical" margin={{ left: 10 }}>
              <XAxis type="number" tick={{ fontSize: 11, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" width={150} tick={{ fontSize: 11, fill: 'var(--text-secondary)', fontWeight: 600 }} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="value" radius={[0, 8, 8, 0]} barSize={20}>
                {serviceData.map((_, i) => (
                  <Cell key={i} fill={SOURCE_COLORS[i % SOURCE_COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <div className="card-title">Findings by Source</div>
          <ResponsiveContainer width="100%" height={290}>
            <PieChart>
              <Pie
                data={sourceData} cx="50%" cy="50%"
                outerRadius={105}
                dataKey="value" paddingAngle={2}
                stroke="none"
                label={({ name, value }) => `${name}: ${value}`}
              >
                {sourceData.map((_, i) => (
                  <Cell key={i} fill={SOURCE_COLORS[i % SOURCE_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
              <Legend
                wrapperStyle={{ fontSize: '12px', fontWeight: 600 }}
                iconType="circle"
                iconSize={8}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <div className="card-title">Recent Findings</div>
          <table className="data-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Severity</th>
                <th>Risk</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {recentFindings.map((f) => (
                <tr key={f.id}>
                  <td style={{ fontSize: '12px', fontWeight: 600 }}>{f.credential_type}</td>
                  <td><span className={`severity-badge ${f.severity}`}>{f.severity}</span></td>
                  <td>
                    <span className={`risk-score ${f.risk_score >= 80 ? 'critical' : f.risk_score >= 60 ? 'high' : f.risk_score >= 40 ? 'medium' : 'low'}`}>
                      {f.risk_score}
                    </span>
                  </td>
                  <td style={{ fontSize: '11px', fontWeight: 500, color: 'var(--text-muted)' }}>{f.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
