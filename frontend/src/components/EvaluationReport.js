import React from 'react';

function EvaluationReport({ evaluation, onRun }) {
  if (!evaluation) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '60px' }}>
        <p style={{ fontSize: '16px', marginBottom: '16px', color: 'var(--text-secondary)' }}>
          Run the precision/recall evaluation to test detection accuracy across multiple key formats.
        </p>
        <button className="btn btn-primary" onClick={onRun}>📈 Run Evaluation</button>
      </div>
    );
  }

  const { overall, per_type, details } = evaluation;

  const getScoreClass = (val) => val >= 0.8 ? 'good' : val >= 0.5 ? 'ok' : 'bad';

  return (
    <div>
      <div className="card" style={{ marginBottom: '20px' }}>
        <div className="card-title">📈 Detection Accuracy Report</div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '14px', marginBottom: '16px' }}>
          Evaluated against a synthetic labeled dataset of {overall.total_samples} samples including true secrets and false positives.
        </p>

        <div className="eval-overall">
          <div className="eval-metric">
            <div className={`value ${getScoreClass(overall.precision)}`}>{(overall.precision * 100).toFixed(1)}%</div>
            <div className="label">Precision</div>
          </div>
          <div className="eval-metric">
            <div className={`value ${getScoreClass(overall.recall)}`}>{(overall.recall * 100).toFixed(1)}%</div>
            <div className="label">Recall</div>
          </div>
          <div className="eval-metric">
            <div className={`value ${getScoreClass(overall.f1_score)}`}>{(overall.f1_score * 100).toFixed(1)}%</div>
            <div className="label">F1 Score</div>
          </div>
          <div className="eval-metric">
            <div className="value" style={{ color: 'var(--success)' }}>{overall.true_positives}</div>
            <div className="label">True Positives</div>
          </div>
          <div className="eval-metric">
            <div className="value" style={{ color: 'var(--danger)' }}>{overall.false_positives}</div>
            <div className="label">False Positives</div>
          </div>
          <div className="eval-metric">
            <div className="value" style={{ color: 'var(--warning)' }}>{overall.false_negatives}</div>
            <div className="label">False Negatives</div>
          </div>
          <div className="eval-metric">
            <div className="value" style={{ color: 'var(--info)' }}>{overall.true_negatives}</div>
            <div className="label">True Negatives</div>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: '20px' }}>
        <div className="card-title">Per-Type Metrics</div>
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Credential Type</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>F1</th>
                <th>TP</th>
                <th>FP</th>
                <th>FN</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(per_type).map(([type, m]) => (
                <tr key={type}>
                  <td style={{ fontWeight: 500 }}>{type}</td>
                  <td><span className={`value ${getScoreClass(m.precision)}`}>{(m.precision * 100).toFixed(0)}%</span></td>
                  <td><span className={`value ${getScoreClass(m.recall)}`}>{(m.recall * 100).toFixed(0)}%</span></td>
                  <td><span className={`value ${getScoreClass(m.f1)}`}>{(m.f1 * 100).toFixed(0)}%</span></td>
                  <td>{m.tp}</td>
                  <td>{m.fp}</td>
                  <td>{m.fn}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card">
        <div className="card-title">Detailed Results</div>
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Sample Text</th>
                <th>Expected</th>
                <th>Detected</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {details.map((d, i) => (
                <tr key={i}>
                  <td className="mono" style={{ maxWidth: '400px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.text}</td>
                  <td style={{ fontSize: '13px' }}>{d.expected}</td>
                  <td style={{ fontSize: '13px' }}>{Array.isArray(d.detected) ? d.detected.join(', ') : d.detected}</td>
                  <td>
                    <span className={`severity-badge ${d.result === 'TP' || d.result === 'TN' ? 'low' : d.result === 'FP' ? 'high' : 'critical'}`}>
                      {d.result}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div style={{ marginTop: '16px', textAlign: 'center' }}>
        <button className="btn btn-primary" onClick={onRun}>🔄 Re-run Evaluation</button>
      </div>
    </div>
  );
}

export default EvaluationReport;
