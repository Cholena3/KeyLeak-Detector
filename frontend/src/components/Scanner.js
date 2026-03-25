import React, { useState } from 'react';

function Scanner({ apiBase, onScanComplete }) {
  const [text, setText] = useState('');
  const [source, setSource] = useState('manual_scan');
  const [sourceUrl, setSourceUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);

  const handleScan = async () => {
    if (!text.trim()) return;
    setScanning(true);
    setResult(null);
    try {
      const res = await fetch(`${apiBase}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, source, source_url: sourceUrl }),
      });
      const data = await res.json();
      setResult(data);
      onScanComplete(data);
    } catch (err) {
      setResult({ error: 'Scan failed. Check API connection.' });
    } finally {
      setScanning(false);
    }
  };

  const sampleTextEncoded = "IyBFeGFtcGxlIGNvbmZpZyB3aXRoIGxlYWtlZCBjcmVkZW50aWFscwpBV1NfQUNDRVNTX0tFWV9JRD1BS0lBSjVRVkhaM1JXTUdLN04yUQpHSVRIVUJfVE9LRU49Z2hwX1I3bUtwTDl4V3FOdkoyc1loVDRkQmNGZ0E4ZVU2aU8zblprUgpTVFJJUEVfS0VZPXNrX2xpdmVfUjdtS3BMOXhXcU52SjJzWWhUNGRCY0ZnCkdPT0dMRV9BUElfS0VZPUFJemFTeUM4a1IybU5wTHFXNHZYalQ5YlloVTZkRmdBM2VJNW9LNwpTRU5ER1JJRF9BUElfS0VZPVNHLlI3bUtwTDl4V3FOdkoyc1loVDRkQmMuRmdBOGVVNmlPM25aa1IybU5wTHFXNHZYalQ5YlloVTZkRmdBM2VJNW9LN3IKLS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBMFozVlM1SkpjZHMzeGZuL3lnV3lGOFBibkd5MEFIQTJNZ2dIY1R6NnNFMkkycFBCCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0t";
  const sampleText = atob(sampleTextEncoded);

  return (
    <div>
      <div className="card" style={{ marginBottom: '20px' }}>
        <div className="card-title">🔍 KeyLeak Scanner</div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '14px', marginBottom: '16px' }}>
          Paste code, config files, logs, or any text to scan for exposed credentials.
          Detection uses regex pattern matching + Shannon entropy analysis.
        </p>

        <div className="form-group">
          <label htmlFor="scan-text">Text to Scan</label>
          <textarea
            id="scan-text"
            rows={12}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Paste code, config, or text here..."
          />
        </div>

        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          <div className="form-group" style={{ flex: 1, minWidth: '200px' }}>
            <label htmlFor="scan-source">Source Type</label>
            <select id="scan-source" value={source} onChange={(e) => setSource(e.target.value)}>
              <option value="manual_scan">Manual Scan</option>
              <option value="github_repo">GitHub Repository</option>
              <option value="github_gist">GitHub Gist</option>
              <option value="pastebin">Pastebin</option>
              <option value="forum">Forum / Q&A</option>
              <option value="log_file">Log File</option>
            </select>
          </div>
          <div className="form-group" style={{ flex: 2, minWidth: '200px' }}>
            <label htmlFor="source-url">Source URL (optional)</label>
            <input
              id="source-url"
              type="text"
              value={sourceUrl}
              onChange={(e) => setSourceUrl(e.target.value)}
              placeholder="https://github.com/user/repo/..."
            />
          </div>
        </div>

        <div style={{ display: 'flex', gap: '12px' }}>
          <button className="btn btn-primary" onClick={handleScan} disabled={scanning || !text.trim()}>
            {scanning ? '⏳ Scanning...' : '🔍 Scan for Secrets'}
          </button>
          <button className="btn btn-success" onClick={() => setText(sampleText)}>
            📋 Load Sample
          </button>
          <button className="btn" style={{ background: 'var(--glass)', color: 'var(--text-secondary)', border: '1px solid var(--border)', backdropFilter: 'blur(8px)' }} onClick={() => { setText(''); setResult(null); }}>
            🗑️ Clear
          </button>
        </div>
      </div>

      {result && !result.error && (
        <div className="card">
          <div className="card-title">
            Scan Results — {result.findings_count} credential{result.findings_count !== 1 ? 's' : ''} found
          </div>
          {result.findings_count === 0 ? (
            <p style={{ color: 'var(--success)', fontSize: '16px', padding: '20px 0' }}>
              ✅ No exposed credentials detected. The text appears clean.
            </p>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Service</th>
                  <th>Severity</th>
                  <th>Risk Score</th>
                  <th>Entropy</th>
                  <th>Masked Secret</th>
                </tr>
              </thead>
              <tbody>
                {result.findings.map((f) => (
                  <tr key={f.id}>
                    <td>{f.credential_type}</td>
                    <td>{f.service}</td>
                    <td><span className={`severity-badge ${f.severity}`}>{f.severity}</span></td>
                    <td>
                      <span className={`risk-score ${f.risk_score >= 80 ? 'critical' : f.risk_score >= 60 ? 'high' : 'medium'}`}>
                        {f.risk_score}
                      </span>
                    </td>
                    <td className="mono">{f.entropy}</td>
                    <td className="mono">{f.secret_masked}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {result.notifications_sent > 0 && (
            <p style={{ marginTop: '16px', color: 'var(--warning)', fontSize: '13px' }}>
              🔔 {result.notifications_sent} alert notification{result.notifications_sent !== 1 ? 's' : ''} sent via mock channels.
            </p>
          )}
        </div>
      )}

      {result?.error && (
        <div className="card" style={{ borderColor: 'var(--danger)' }}>
          <p style={{ color: 'var(--danger)' }}>❌ {result.error}</p>
        </div>
      )}
    </div>
  );
}

export default Scanner;
