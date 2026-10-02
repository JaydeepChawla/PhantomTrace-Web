import React from 'react';
import type { ScanOverview } from '../../types';

interface ThreatDistributionChartProps {
  overview: ScanOverview;
}

export const ThreatDistributionChart: React.FC<ThreatDistributionChartProps> = ({ overview }) => {
  const levels = [
    { label: 'Critical', count: overview.criticalCount, color: 'var(--pt-critical)', pct: Math.round((overview.criticalCount / overview.threatAlertsCount) * 100) },
    { label: 'High', count: overview.highCount, color: 'var(--pt-high)', pct: Math.round((overview.highCount / overview.threatAlertsCount) * 100) },
    { label: 'Medium', count: overview.mediumCount, color: 'var(--pt-medium)', pct: Math.round((overview.mediumCount / overview.threatAlertsCount) * 100) },
    { label: 'Low', count: overview.lowCount, color: 'var(--pt-low)', pct: Math.round((overview.lowCount / overview.threatAlertsCount) * 100) },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Distribution Progress Bars */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem', fontSize: '0.78rem' }}>
          <span style={{ color: '#94a3b8' }}>Active Alerts Severity Breakdown</span>
          <span style={{ color: '#00e5ff', fontWeight: 600 }}>{overview.threatAlertsCount} Total Alerts</span>
        </div>

        {/* Multi-segment stacked bar */}
        <div 
          style={{ 
            height: '10px', 
            borderRadius: '5px', 
            background: 'rgba(255, 255, 255, 0.05)', 
            overflow: 'hidden', 
            display: 'flex',
            marginBottom: '1rem' 
          }}
        >
          {levels.map((lvl) => (
            <div
              key={lvl.label}
              style={{
                width: `${lvl.pct}%`,
                background: lvl.color,
                transition: 'width 0.4s ease',
              }}
              title={`${lvl.label}: ${lvl.count} (${lvl.pct}%)`}
            />
          ))}
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
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', fontSize: '0.78rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ color: '#cbd5e1' }}>Correlated (Memory + Behavior)</span>
            <span style={{ color: '#38bdf8', fontWeight: 600 }}>3 alerts (50%)</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ color: '#cbd5e1' }}>Memory Evidence Only</span>
            <span style={{ color: '#a78bfa', fontWeight: 600 }}>1 alert (17%)</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ color: '#cbd5e1' }}>Behavioral Telemetry Only</span>
            <span style={{ color: '#fb923c', fontWeight: 600 }}>1 alert (17%)</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ color: '#cbd5e1' }}>Baseline Developer Telemetry</span>
            <span style={{ color: '#34d399', fontWeight: 600 }}>1 alert (17%)</span>
          </div>
        </div>
      </div>
    </div>
  );
};
