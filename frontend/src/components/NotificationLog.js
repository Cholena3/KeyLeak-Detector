import React from 'react';

function NotificationLog({ notifications }) {
  return (
    <div>
      <div className="card" style={{ marginBottom: '20px' }}>
        <div className="card-title">🔔 Alert Notifications ({notifications.length})</div>
        <p style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>
          Mock notifications sent when credentials are detected. In production, these would go to email, Slack, PagerDuty, and SMS.
        </p>
      </div>

      {notifications.length === 0 ? (
        <div className="card">
          <p style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
            No notifications yet. Scan some text to trigger alerts.
          </p>
        </div>
      ) : (
        notifications.map((n) => (
          <div className="notification-card" key={n.id}>
            <div className="notif-header">
              <span className={`severity-badge ${n.severity}`}>{n.severity}</span>
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                {new Date(n.sent_at).toLocaleString()}
              </span>
            </div>
            <div className="notif-message">{n.message}</div>
            <div className="notif-meta">
              <span>Service: {n.service}</span>
              <span>Risk: {n.risk_score}/100</span>
              <div className="notif-channels">
                {n.channels.map((ch) => (
                  <span className="channel-badge" key={ch}>{ch}</span>
                ))}
              </div>
            </div>
          </div>
        ))
      )}
    </div>
  );
}

export default NotificationLog;
