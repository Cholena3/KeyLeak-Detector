import React from 'react';

function KeyTypesPanel({ keyTypes }) {
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted = [...keyTypes].sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4));

  return (
    <div>
      <div className="card" style={{ marginBottom: '20px' }}>
        <div className="card-title">🔑 Supported Credential Types ({keyTypes.length})</div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '14px', marginBottom: '8px' }}>
          CredShield detects the following credential formats using regex pattern matching and entropy analysis.
        </p>
      </div>

      <div className="key-types-grid">
        {sorted.map((kt, i) => (
          <div className="key-type-card" key={i}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <h3>{kt.name}</h3>
              <span className={`severity-badge ${kt.severity}`}>{kt.severity}</span>
            </div>
            <div className="service">{kt.service}</div>
            <div className="description">{kt.description}</div>
            <div className="pattern" title={kt.pattern_hint}>{kt.pattern_hint}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default KeyTypesPanel;
