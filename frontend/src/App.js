import React, { useState, useEffect, useCallback } from 'react';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import Dashboard from './components/Dashboard';
import Scanner from './components/Scanner';
import FindingsTable from './components/FindingsTable';
import KeyTypesPanel from './components/KeyTypesPanel';
import EvaluationReport from './components/EvaluationReport';
import NotificationLog from './components/NotificationLog';
import './App.css';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:5050/api';

function App() {
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem('credshield-dark-mode');
    return saved !== null ? JSON.parse(saved) : true;
  });
  const [activeTab, setActiveTab] = useState('dashboard');
  const [stats, setStats] = useState(null);
  const [findings, setFindings] = useState([]);
  const [notifications, setNotifications] = useState([]);
  const [keyTypes, setKeyTypes] = useState([]);
  const [evaluation, setEvaluation] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    localStorage.setItem('credshield-dark-mode', JSON.stringify(darkMode));
    document.body.className = darkMode ? 'dark' : 'light';
  }, [darkMode]);

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, findingsRes, notifsRes, keyTypesRes] = await Promise.all([
        fetch(`${API_BASE}/dashboard/stats`),
        fetch(`${API_BASE}/findings`),
        fetch(`${API_BASE}/notifications`),
        fetch(`${API_BASE}/key-types`),
      ]);
      setStats(await statsRes.json());
      const findingsData = await findingsRes.json();
      setFindings(findingsData.findings);
      const notifsData = await notifsRes.json();
      setNotifications(notifsData.notifications);
      const keyTypesData = await keyTypesRes.json();
      setKeyTypes(keyTypesData.key_types);
    } catch (err) {
      toast.error('Failed to connect to KeyLeak Detector API. Is the backend running?');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleScanComplete = (result) => {
    if (result.findings_count > 0) {
      result.findings.forEach((f) => {
        toast.warn(
          `🚨 ${f.severity.toUpperCase()}: ${f.credential_type} detected! Risk: ${f.risk_score}/100`,
          { autoClose: 8000, position: 'top-right' }
        );
      });
    } else {
      toast.success('✅ No credentials detected in the scanned text.', { position: 'top-right' });
    }
    fetchData();
  };

  const runEvaluation = async () => {
    try {
      const res = await fetch(`${API_BASE}/evaluate`);
      const data = await res.json();
      setEvaluation(data);
      toast.info(`Evaluation complete: F1=${data.overall.f1_score}`, { position: 'top-right' });
    } catch {
      toast.error('Failed to run evaluation');
    }
  };

  const tabs = [
    { id: 'dashboard', label: '📊 Dashboard' },
    { id: 'scanner', label: '🔍 Scanner' },
    { id: 'findings', label: '🔓 Findings' },
    { id: 'key-types', label: '🔑 Key Types' },
    { id: 'notifications', label: '🔔 Alerts' },
    { id: 'evaluation', label: '📈 Evaluation' },
  ];

  return (
    <div className={`app ${darkMode ? 'dark' : 'light'}`}>
      <ToastContainer theme={darkMode ? 'dark' : 'light'} />
      <header className="app-header">
        <div className="header-left">
          <span className="logo">🛡️</span>
          <h1>KeyLeak Detector</h1>
          <span className="tagline">Secret Leak Detection Framework</span>
        </div>
        <div className="header-right">
          <span style={{
            background: '#dc2626',
            color: '#fff',
            padding: '5px 14px',
            borderRadius: '6px',
            fontSize: '12px',
            fontWeight: 700,
            letterSpacing: '0.5px',
            textTransform: 'uppercase',
          }}>Team CipherHeist</span>
          <button
            className="theme-toggle"
            onClick={() => setDarkMode(!darkMode)}
            aria-label={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
            title={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {darkMode ? '☀️' : '🌙'}
          </button>
        </div>
      </header>

      <nav className="tab-nav" role="tablist">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            role="tab"
            aria-selected={activeTab === tab.id}
            className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => {
              setActiveTab(tab.id);
              if (tab.id === 'evaluation' && !evaluation) runEvaluation();
            }}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <main className="main-content">
        {loading ? (
          <div className="loading-state">
            <div className="spinner" role="status" aria-label="Loading"></div>
            <p>Connecting to KeyLeak Detector API...</p>
          </div>
        ) : (
          <>
            {activeTab === 'dashboard' && <Dashboard stats={stats} findings={findings} />}
            {activeTab === 'scanner' && <Scanner apiBase={API_BASE} onScanComplete={handleScanComplete} />}
            {activeTab === 'findings' && <FindingsTable findings={findings} apiBase={API_BASE} onUpdate={fetchData} />}
            {activeTab === 'key-types' && <KeyTypesPanel keyTypes={keyTypes} />}
            {activeTab === 'notifications' && <NotificationLog notifications={notifications} />}
            {activeTab === 'evaluation' && <EvaluationReport evaluation={evaluation} onRun={runEvaluation} />}
          </>
        )}
      </main>

      <footer className="app-footer">
        <p>KeyLeak Detector v1.0 — Passive credential leak detection by Team CipherHeist. Never validates or uses discovered keys.</p>
      </footer>
    </div>
  );
}

export default App;
