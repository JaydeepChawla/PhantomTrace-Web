import React from 'react';
import {
  Server,
  Database,
  UploadCloud,
  RefreshCw,
  Clock,
  Info,
} from 'lucide-react';
import type { SystemHealthStatus } from '../../types';

interface SystemHealthMonitorProps {
  health: SystemHealthStatus | null;
  loading: boolean;
  onRefresh: () => void;
}

export const SystemHealthMonitor: React.FC<SystemHealthMonitorProps> = ({
  health,
  loading,
  onRefresh,
}) => {
  const isApiOnline = health?.apiStatus === 'ONLINE';
  const isDbConnected = health?.database.connected === true;
  const freshness = health?.endpointTelemetryFreshness.status || 'NO_TELEMETRY';

  const getFreshnessColor = () => {
    switch (freshness) {
      case 'FRESH':
        return '#10b981';
      case 'RECENT':
        return '#00e5ff';
      case 'STALE':
        return '#f59e0b';
      default:
        return '#64748b';
    }
  };

  const getFreshnessBadge = () => {
    switch (freshness) {
      case 'FRESH':
        return 'FRESH (<2h)';
      case 'RECENT':
        return 'RECENT (<24h)';
      case 'STALE':
        return 'STALE (>24h)';
      default:
        return 'NO TELEMETRY';
    }
  };

  return (
    <div
      className="pt-card"
      style={{
        padding: '1.25rem 1.5rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '1rem',
        background: 'linear-gradient(135deg, rgba(13, 20, 36, 0.85) 0%, rgba(9, 14, 26, 0.95) 100%)',
      }}
    >
      {/* Top Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <Server size={18} style={{ color: '#00e5ff' }} />
          <div>
            <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#ffffff', margin: 0 }}>
              System Health &amp; Subsystem Telemetry
            </h4>
            <div style={{ fontSize: '0.74rem', color: '#94a3b8', marginTop: '0.1rem' }}>
              Real-time diagnostic probes for backend services, database, and telemetry ingestion.
            </div>
          </div>
        </div>

        <button
          type="button"
          onClick={onRefresh}
          disabled={loading}
          className="pt-btn pt-btn-secondary"
          style={{ padding: '0.35rem 0.75rem', fontSize: '0.76rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
        >
          <RefreshCw size={13} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
          <span>{loading ? 'Refreshing...' : 'Refresh Health'}</span>
        </button>
      </div>

      {/* Grid of 4 Health Probes */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '0.85rem' }}>
        {/* Render Backend Probe */}
        <div
          style={{
            padding: '0.85rem 1rem',
            borderRadius: '6px',
            background: 'rgba(15, 23, 42, 0.6)',
            border: `1px solid ${isApiOnline ? 'rgba(16, 185, 129, 0.25)' : 'rgba(239, 68, 68, 0.25)'}`,
            display: 'flex',
            flexDirection: 'column',
            gap: '0.35rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.72rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
              Backend API
            </span>
            <span
              style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                background: isApiOnline ? '#10b981' : '#ef4444',
                display: 'inline-block',
              }}
            />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <span style={{ fontSize: '1.05rem', fontWeight: 700, color: '#ffffff' }}>
              {health?.apiStatus || 'CHECKING...'}
            </span>
            {health?.apiLatencyMs !== undefined && (
              <span style={{ fontSize: '0.74rem', color: '#6ee7b7', fontFamily: 'var(--font-mono)' }}>
                ({health.apiLatencyMs}ms)
              </span>
            )}
          </div>
          <div style={{ fontSize: '0.72rem', color: '#64748b' }}>
            Render Platform • v{health?.apiVersion || '1.0.0'}
          </div>
        </div>

        {/* PostgreSQL Database Probe */}
        <div
          style={{
            padding: '0.85rem 1rem',
            borderRadius: '6px',
            background: 'rgba(15, 23, 42, 0.6)',
            border: `1px solid ${isDbConnected ? 'rgba(0, 229, 255, 0.25)' : 'rgba(239, 68, 68, 0.25)'}`,
            display: 'flex',
            flexDirection: 'column',
            gap: '0.35rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.72rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
              Database
            </span>
            <Database size={14} style={{ color: isDbConnected ? '#00e5ff' : '#ef4444' }} />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <span style={{ fontSize: '1.05rem', fontWeight: 700, color: isDbConnected ? '#38bdf8' : '#f87171' }}>
              {isDbConnected ? 'PostgreSQL Connected' : 'Unavailable / Memory Fallback'}
            </span>
          </div>
          <div style={{ fontSize: '0.72rem', color: '#64748b' }}>
            {isDbConnected ? 'Supabase Pooler Verified' : 'Check DATABASE_URL'}
          </div>
        </div>

        {/* Last Scan Upload */}
        <div
          style={{
            padding: '0.85rem 1rem',
            borderRadius: '6px',
            background: 'rgba(15, 23, 42, 0.6)',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.35rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.72rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
              Last Scan Upload
            </span>
            <UploadCloud size={14} style={{ color: '#a855f7' }} />
          </div>
          <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#ffffff', fontFamily: 'var(--font-mono)' }}>
            {health?.lastScanUpload ? new Date(health.lastScanUpload).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' }) : 'No scan ingested'}
          </div>
          <div style={{ fontSize: '0.72rem', color: '#64748b' }}>
            {health?.lastScanUpload ? 'Verified HTTPS ingestion' : 'Run scanner to upload'}
          </div>
        </div>

        {/* Endpoint Freshness */}
        <div
          style={{
            padding: '0.85rem 1rem',
            borderRadius: '6px',
            background: 'rgba(15, 23, 42, 0.6)',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.35rem',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '0.72rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
              Telemetry Freshness
            </span>
            <Clock size={14} style={{ color: getFreshnessColor() }} />
          </div>
          <div>
            <span
              style={{
                fontSize: '0.72rem',
                padding: '0.15rem 0.5rem',
                borderRadius: '4px',
                background: `${getFreshnessColor()}20`,
                color: getFreshnessColor(),
                fontWeight: 700,
                letterSpacing: '0.03em',
              }}
            >
              {getFreshnessBadge()}
            </span>
          </div>
          <div style={{ fontSize: '0.72rem', color: '#64748b' }}>
            {health?.endpointTelemetryFreshness.description || 'Periodic scan basis'}
          </div>
        </div>
      </div>

      {/* Explicit Architecture Disclaimer */}
      <div
        style={{
          padding: '0.6rem 0.85rem',
          borderRadius: '6px',
          background: 'rgba(255, 255, 255, 0.03)',
          border: '1px solid rgba(255, 255, 255, 0.06)',
          display: 'flex',
          alignItems: 'center',
          gap: '0.6rem',
          fontSize: '0.74rem',
          color: '#94a3b8',
        }}
      >
        <Info size={15} style={{ color: '#00e5ff', flexShrink: 0 }} />
        <span>
          <strong>Operational Model Notice:</strong> {health?.monitoringNotice || 'Endpoint telemetry is derived from periodic scan snapshots (PhantomTrace Windows Engine). Continuous real-time process monitoring requires the active background Agent Service.'}
        </span>
      </div>
    </div>
  );
};
