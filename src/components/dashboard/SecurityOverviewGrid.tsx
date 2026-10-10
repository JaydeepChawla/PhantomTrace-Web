import React from 'react';
import {
  ShieldAlert,
  Cpu,
  Flame,
  Layers,
  HardDrive,
  Activity,
  AlertTriangle,
  CheckCircle2,
} from 'lucide-react';
import type { DashboardSecurityOverview } from '../../types';

interface SecurityOverviewGridProps {
  overview: DashboardSecurityOverview | null;
  loading: boolean;
  error?: string | null;
}

export const SecurityOverviewGrid: React.FC<SecurityOverviewGridProps> = ({
  overview,
  loading,
  error,
}) => {
  if (loading && !overview) {
    return (
      <div className="pt-card" style={{ padding: '2rem', textAlign: 'center', color: '#94a3b8' }}>
        <div style={{ display: 'inline-block', width: '20px', height: '20px', border: '2px solid #00e5ff', borderTopColor: 'transparent', borderRadius: '50%', animation: 'spin 1s linear infinite', marginBottom: '0.75rem' }} />
        <div>Loading security monitor metrics...</div>
      </div>
    );
  }

  if (error && !overview) {
    return (
      <div className="pt-card" style={{ padding: '1.5rem', background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.3)', color: '#fca5a5' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', fontWeight: 600 }}>
          <AlertTriangle size={18} />
          <span>Security Monitor Unavailable</span>
        </div>
        <p style={{ fontSize: '0.82rem', marginTop: '0.4rem', color: '#f87171' }}>{error}</p>
      </div>
    );
  }

  const hasScans = overview && overview.totalScans > 0;
  const findings = overview?.processFindings || {
    totalAnalyzed: 0,
    cleanProcesses: 0,
    elevatedProcesses: 0,
    highestThreatScore: 0,
    memoryInspectedMb: 0,
  };

  const dist = overview?.threatAlertsDistribution || {
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    byStatus: { new: 0, investigating: 0, contained: 0, resolved: 0, dismissed: 0 },
    byVector: { memory: 0, web: 0 },
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Primary KPI Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(175px, 1fr))', gap: '1rem' }}>
        {/* Total Scans Card */}
        <div className="pt-card" style={{ padding: '1.15rem 1.25rem', position: 'relative', overflow: 'hidden' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Total Scans
            </span>
            <HardDrive size={18} style={{ color: '#00e5ff' }} />
          </div>
          <div style={{ fontSize: '1.85rem', fontWeight: 800, color: '#ffffff', margin: '0.35rem 0 0.15rem 0', fontFamily: 'var(--font-mono)' }}>
            {hasScans ? overview.totalScans : 0}
          </div>
          <div style={{ fontSize: '0.74rem', color: hasScans ? '#6ee7b7' : '#64748b' }}>
            {hasScans ? 'Ingested from host PC' : 'Awaiting initial scan'}
          </div>
        </div>

        {/* Registered Endpoints */}
        <div className="pt-card" style={{ padding: '1.15rem 1.25rem', position: 'relative', overflow: 'hidden' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Endpoints
            </span>
            <Activity size={18} style={{ color: '#38bdf8' }} />
          </div>
          <div style={{ fontSize: '1.85rem', fontWeight: 800, color: '#ffffff', margin: '0.35rem 0 0.15rem 0', fontFamily: 'var(--font-mono)' }}>
            {overview?.registeredEndpoints ?? 0}
          </div>
          <div style={{ fontSize: '0.74rem', color: (overview?.registeredEndpoints ?? 0) > 0 ? '#38bdf8' : '#64748b' }}>
            {(overview?.registeredEndpoints ?? 0) > 0 ? 'Enrolled Windows devices' : 'No paired devices'}
          </div>
        </div>

        {/* Process Findings (Analyzed) */}
        <div className="pt-card" style={{ padding: '1.15rem 1.25rem', position: 'relative', overflow: 'hidden' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Processes Analyzed
            </span>
            <Cpu size={18} style={{ color: '#10b981' }} />
          </div>
          <div style={{ fontSize: '1.85rem', fontWeight: 800, color: '#ffffff', margin: '0.35rem 0 0.15rem 0', fontFamily: 'var(--font-mono)' }}>
            {hasScans ? findings.totalAnalyzed : '--'}
          </div>
          <div style={{ fontSize: '0.74rem', color: hasScans ? '#94a3b8' : '#64748b' }}>
            {hasScans ? `${findings.memoryInspectedMb} MB RAM passive scan` : 'No telemetry recorded'}
          </div>
        </div>

        {/* Threat Alerts Count */}
        <div className="pt-card" style={{ padding: '1.15rem 1.25rem', position: 'relative', overflow: 'hidden' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Threat Alerts
            </span>
            <ShieldAlert size={18} style={{ color: dist.total > 0 ? '#ef4444' : '#10b981' }} />
          </div>
          <div
            style={{
              fontSize: '1.85rem',
              fontWeight: 800,
              color: dist.total > 0 ? '#f87171' : '#10b981',
              margin: '0.35rem 0 0.15rem 0',
              fontFamily: 'var(--font-mono)',
            }}
          >
            {dist.total}
          </div>
          <div style={{ fontSize: '0.74rem', color: dist.total > 0 ? '#fca5a5' : '#6ee7b7' }}>
            {dist.total > 0 ? `${dist.critical} critical • ${dist.high} high` : 'Clean baseline'}
          </div>
        </div>

        {/* Highest Threat Score */}
        <div className="pt-card" style={{ padding: '1.15rem 1.25rem', position: 'relative', overflow: 'hidden' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Highest Score
            </span>
            <Flame size={18} style={{ color: findings.highestThreatScore >= 60 ? '#ef4444' : '#10b981' }} />
          </div>
          <div
            style={{
              fontSize: '1.85rem',
              fontWeight: 800,
              color: findings.highestThreatScore >= 60 ? '#f87171' : findings.highestThreatScore > 0 ? '#fbbf24' : '#10b981',
              margin: '0.35rem 0 0.15rem 0',
              fontFamily: 'var(--font-mono)',
            }}
          >
            {hasScans ? `${findings.highestThreatScore}/100` : '--'}
          </div>
          <div style={{ fontSize: '0.74rem', color: '#94a3b8' }}>
            {hasScans ? (findings.highestThreatScore >= 75 ? 'Critical elevated risk' : findings.highestThreatScore >= 40 ? 'Moderate alert' : 'Verified baseline') : 'Pending scan'}
          </div>
        </div>
      </div>

      {/* Secondary Detailed Distribution Strip */}
      <div
        className="pt-card"
        style={{
          padding: '1.15rem 1.5rem',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '1.5rem',
          background: 'rgba(10, 16, 28, 0.75)',
        }}
      >
        {/* Severity Breakdown */}
        <div>
          <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#ffffff', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <Layers size={14} style={{ color: '#00e5ff' }} />
            <span>Alerts by Severity</span>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.65rem', borderRadius: '4px', background: 'rgba(239, 68, 68, 0.15)', color: '#f87171', border: '1px solid rgba(239, 68, 68, 0.3)', fontWeight: 600 }}>
              Critical: {dist.critical}
            </span>
            <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.65rem', borderRadius: '4px', background: 'rgba(249, 115, 22, 0.15)', color: '#fb923c', border: '1px solid rgba(249, 115, 22, 0.3)', fontWeight: 600 }}>
              High: {dist.high}
            </span>
            <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.65rem', borderRadius: '4px', background: 'rgba(234, 179, 8, 0.15)', color: '#facc15', border: '1px solid rgba(234, 179, 8, 0.3)', fontWeight: 600 }}>
              Medium: {dist.medium}
            </span>
            <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.65rem', borderRadius: '4px', background: 'rgba(0, 229, 255, 0.12)', color: '#38bdf8', border: '1px solid rgba(0, 229, 255, 0.25)', fontWeight: 600 }}>
              Low: {dist.low}
            </span>
          </div>
        </div>

        {/* Triage Status Breakdown */}
        <div>
          <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#ffffff', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <CheckCircle2 size={14} style={{ color: '#10b981' }} />
            <span>Triage Lifecycle Status</span>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.65rem', borderRadius: '4px', background: 'rgba(239, 68, 68, 0.12)', color: '#fca5a5', fontWeight: 600 }}>
              New: {dist.byStatus.new}
            </span>
            <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.65rem', borderRadius: '4px', background: 'rgba(245, 158, 11, 0.12)', color: '#fbbf24', fontWeight: 600 }}>
              Investigating: {dist.byStatus.investigating}
            </span>
            <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.65rem', borderRadius: '4px', background: 'rgba(168, 85, 247, 0.12)', color: '#c084fc', fontWeight: 600 }}>
              Contained: {dist.byStatus.contained}
            </span>
            <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.65rem', borderRadius: '4px', background: 'rgba(16, 185, 129, 0.12)', color: '#34d399', fontWeight: 600 }}>
              Resolved: {dist.byStatus.resolved}
            </span>
          </div>
        </div>

        {/* Detection Vector Breakdown */}
        <div>
          <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#ffffff', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <Activity size={14} style={{ color: '#38bdf8' }} />
            <span>Detection Vectors</span>
          </div>
          <div style={{ display: 'flex', gap: '0.65rem' }}>
            <div style={{ flex: 1, padding: '0.4rem 0.6rem', borderRadius: '6px', background: 'rgba(0, 229, 255, 0.06)', border: '1px solid rgba(0, 229, 255, 0.15)' }}>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Endpoint Memory</div>
              <div style={{ fontSize: '1rem', fontWeight: 700, color: '#00e5ff', fontFamily: 'var(--font-mono)' }}>
                {dist.byVector.memory}
              </div>
            </div>
            <div style={{ flex: 1, padding: '0.4rem 0.6rem', borderRadius: '6px', background: 'rgba(168, 85, 247, 0.06)', border: '1px solid rgba(168, 85, 247, 0.15)' }}>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>Web Threat Monitor</div>
              <div style={{ fontSize: '1rem', fontWeight: 700, color: '#c084fc', fontFamily: 'var(--font-mono)' }}>
                {dist.byVector.web}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
