import React from 'react';
import type { ScanOverview } from '../../types';

interface ThreatDistributionChartProps {
  overview: ScanOverview;
}

export const ThreatDistributionChart: React.FC<ThreatDistributionChartProps> = ({ overview }) => {
  const totalAlerts = overview.threatAlertsCount || 0;
  const totalProcesses = overview.totalProcesses || 0;
  const normalCount = overview.normalCount ?? totalProcesses;

  const levels = [
    { label: 'Critical', count: overview.criticalCount, color: 'var(--pt-critical)', pct: totalAlerts > 0 ? Math.round((overview.criticalCount / totalAlerts) * 100) : 0 },
    { label: 'High', count: overview.highCount, color: 'var(--pt-high)', pct: totalAlerts > 0 ? Math.round((overview.highCount / totalAlerts) * 100) : 0 },
    { label: 'Medium', count: overview.mediumCount, color: 'var(--pt-medium)', pct: totalAlerts > 0 ? Math.round((overview.mediumCount / totalAlerts) * 100) : 0 },
    { label: 'Low', count: overview.lowCount, color: 'var(--pt-low)', pct: totalAlerts > 0 ? Math.round((overview.lowCount / totalAlerts) * 100) : 0 },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Distribution Progress Bars */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem', fontSize: '0.78rem' }}>
          <span style={{ color: '#94a3b8' }}>Active Alerts Severity Breakdown</span>
          <span style={{ color: totalAlerts > 0 ? 'var(--pt-critical)' : '#10b981', fontWeight: 600 }}>
            {totalAlerts > 0 ? `${totalAlerts} Total Alerts` : '0 Alerts (100% Clean)'}
          </span>
        </div>

        {/* Multi-segment stacked bar */}
        <div
          style={{
            height: '10px',
            borderRadius: '5px',
            background: totalAlerts === 0 ? 'rgba(16, 185, 129, 0.25)' : 'rgba(255, 255, 255, 0.05)',
            overflow: 'hidden',
            display: 'flex',
            marginBottom: '1rem'
          }}
        >
          {totalAlerts === 0 ? (
            <div
              style={{
                width: '100%',
                background: '#10b981',
                transition: 'width 0.4s ease',
              }}
              title={`100% Clean: ${normalCount} Normal Processes`}
            />
          ) : (
            levels.map((lvl) => (
              <div
                key={lvl.label}
                style={{
                  width: `${lvl.pct}%`,
                  background: lvl.color,
                  transition: 'width 0.4s ease',
                }}
                title={`${lvl.label}: ${lvl.count} (${lvl.pct}%)`}
              />
            ))
          )}
        </div>

        {/* Legend Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.65rem' }}>
          {levels.map((lvl) => (
            <div
              key={lvl.label}
              style={{
                background: 'rgba(255, 255, 255, 0.02)',
                border: '1px solid rgba(255, 255, 255, 0.05)',
                borderRadius: '6px',
                padding: '0.5rem 0.75rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: lvl.color }} />
                <span style={{ fontSize: '0.8rem', color: '#cbd5e1' }}>{lvl.label}</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <strong style={{ fontSize: '0.9rem', color: '#ffffff' }}>{lvl.count}</strong>
                <span style={{ fontSize: '0.7rem', color: '#64748b' }}>({lvl.pct}%)</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Detection Correlation Summary */}
      <div
        style={{
          background: 'rgba(9, 15, 26, 0.6)',
          border: '1px solid var(--pt-border-subtle)',
          borderRadius: '8px',
          padding: '0.85rem'
        }}
      >
        <div style={{ fontSize: '0.78rem', color: '#94a3b8', marginBottom: '0.65rem', fontWeight: 600 }}>
          Score Modes Across Active Alerts
        </div>
        {totalAlerts === 0 ? (
          <div style={{ fontSize: '0.78rem', color: '#6ee7b7', lineHeight: 1.5 }}>
            No active threat alerts detected. All {normalCount} inspected host processes evaluated within normal baseline limits (Score 0/100).
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', fontSize: '0.78rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1' }}>Critical &amp; High Severity Alerts</span>
              <span style={{ color: '#f43f5e', fontWeight: 600 }}>{overview.criticalCount + overview.highCount} alerts</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1' }}>Medium &amp; Low Severity Alerts</span>
              <span style={{ color: '#fb923c', fontWeight: 600 }}>{overview.mediumCount + overview.lowCount} alerts</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1' }}>Normal Baseline Clean Processes</span>
              <span style={{ color: '#10b981', fontWeight: 600 }}>{normalCount} processes</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
