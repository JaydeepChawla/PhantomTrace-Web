import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import {
  RefreshCw,
  Clock,
  Lock,
  Server,
  Cloud,
  CloudOff,
  WifiOff,
  AlertTriangle,
  AlertCircle,
  CheckCircle2,
  ShieldCheck,
  Database,
  X
} from 'lucide-react';
import { Logo } from '../common/Logo';
import { dataService } from '../../services';
import type { CloudConnectionStatus, TelemetrySource } from '../../services';

interface HeaderProps {
  onRefresh?: () => Promise<void> | void;
  isRefreshing?: boolean;
}

export const Header: React.FC<HeaderProps> = ({ onRefresh, isRefreshing = false }) => {
  const location = useLocation();
  const [currentTime, setCurrentTime] = useState<Date>(() => new Date());
  const [cloudStatus, setCloudStatus] = useState<CloudConnectionStatus>("API Offline");
  const [telemetrySource, setTelemetrySource] = useState<TelemetrySource>(() => {
    return dataService.getTelemetrySource ? dataService.getTelemetrySource() : "Local Fixture (Demo)";
  });
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [syncNotification, setSyncNotification] = useState<{
    message: string;
    type: 'success' | 'warning' | 'error';
  } | null>(null);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);

    return () => window.clearInterval(timer);
  }, []);

  const [nodeName, setNodeName] = useState<string>("WINDOWS-ENDPOINT-3E7489");

  // Initial backend health & cloud verification
  useEffect(() => {
    let active = true;

    const checkStatus = async () => {
      try {
        if (dataService.checkHealth) {
          const health = await dataService.checkHealth();
          if (active) {
            setCloudStatus(health.status);
            if (dataService.getTelemetrySource) {
              setTelemetrySource(dataService.getTelemetrySource());
            }
          }
        }
        if (dataService.getScanOverview) {
          const overview = await dataService.getScanOverview();
          if (active && overview && 'endpointName' in overview && overview.endpointName) {
            setNodeName(overview.endpointName);
          }
        }
      } catch {
        if (active) {
          setCloudStatus("API Offline");
        }
      }
    };

    checkStatus();
    return () => {
      active = false;
    };
  }, []);

  const formattedTime = new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  }).format(currentTime);

  const getPageTitle = (pathname: string) => {
    if (pathname === '/dashboard') return 'Security Operations Dashboard';
    if (pathname === '/alerts') return 'Threat Alerts & Detections';
    if (pathname.startsWith('/processes/')) return 'Forensic Process Inspection';
    if (pathname === '/processes') return 'Active Process Explorer';
    if (pathname === '/history') return 'Historical Scan Cycles';
    if (pathname === '/reports') return 'Telemetry Reports & Export';
    if (pathname === '/settings') return 'Platform & Scanner Configuration';
    return 'Console';
  };

  const handleSync = async () => {
    // Requirement 8: Prevent duplicate Sync clicks
    if (isSyncing) return;

    // Requirement 7: Show "Syncing..." while request is running
    setIsSyncing(true);
    setSyncNotification(null);

    try {
      if (dataService.syncTelemetry) {
        const result = await dataService.syncTelemetry();
        setCloudStatus(result.status);
        setTelemetrySource(result.source);

        // Requirement 4: Sync must never report success unless backend actually confirms successful synchronization
        if (result.success) {
          setSyncNotification({
            type: 'success',
            message: result.message,
          });
          if (onRefresh) {
            await onRefresh();
          }
        } else {
          // Requirements 5 & 6
          setSyncNotification({
            type: result.status === 'Cloud Not Configured' ? 'warning' : 'error',
            message: result.message,
          });
        }
      } else {
        if (onRefresh) {
          await onRefresh();
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Sync connection error";
      setCloudStatus("API Offline");
      setSyncNotification({
        type: 'error',
        message: `Sync unavailable — ${msg}`,
      });
    } finally {
      setIsSyncing(false);
    }
  };

  return (
    <div style={{ position: 'sticky', top: 0, zIndex: 30, width: '100%' }}>
      <header className="pt-header">
        {/* Page Title & Breadcrumb */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <h1 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.01em', margin: 0 }}>
            {getPageTitle(location.pathname)}
          </h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', background: 'rgba(255, 255, 255, 0.04)', padding: '0.2rem 0.6rem', borderRadius: '4px', fontSize: '0.74rem', color: '#94a3b8' }}>
            <Server size={12} style={{ color: '#00e5ff' }} />
            <span>{nodeName}</span>
          </div>
        </div>

        {/* Header Badges & Actions */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          {/* Requirement 9: Clearly distinguish Windows Scanner (Cloud) vs Local Fixture (Demo) */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
              padding: '0.22rem 0.55rem',
              borderRadius: '4px',
              background: telemetrySource === 'Windows Scanner (Cloud)' ? 'rgba(0, 229, 255, 0.08)' : 'rgba(255, 255, 255, 0.04)',
              border: telemetrySource === 'Windows Scanner (Cloud)' ? '1px solid rgba(0, 229, 255, 0.25)' : '1px solid rgba(255, 255, 255, 0.1)',
              fontSize: '0.72rem',
              color: telemetrySource === 'Windows Scanner (Cloud)' ? '#38bdf8' : '#94a3b8',
              fontWeight: 600
            }}
            title={`Active Telemetry Source: ${telemetrySource}`}
          >
            {telemetrySource === 'Windows Scanner (Cloud)' ? (
              <ShieldCheck size={12} style={{ color: '#00e5ff' }} />
            ) : (
              <Database size={12} style={{ color: '#94a3b8' }} />
            )}
            <span>{telemetrySource}</span>
          </div>

          {/* Requirement 2 & 3: Cloud Status Indicator */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
              padding: '0.22rem 0.55rem',
              borderRadius: '4px',
              background: cloudStatus === 'Cloud Connected'
                ? 'rgba(16, 185, 129, 0.08)'
                : cloudStatus === 'Cloud Not Configured'
                ? 'rgba(245, 158, 11, 0.08)'
                : 'rgba(239, 68, 68, 0.08)',
              border: cloudStatus === 'Cloud Connected'
                ? '1px solid rgba(16, 185, 129, 0.25)'
                : cloudStatus === 'Cloud Not Configured'
                ? '1px solid rgba(245, 158, 11, 0.25)'
                : '1px solid rgba(239, 68, 68, 0.25)',
              fontSize: '0.72rem',
              color: cloudStatus === 'Cloud Connected'
                ? '#6ee7b7'
                : cloudStatus === 'Cloud Not Configured'
                ? '#fcd34d'
                : '#fca5a5',
              fontWeight: 600
            }}
            title={
              cloudStatus === 'Cloud Connected'
                ? 'Cloud Connected: Backend API is live with PostgreSQL/Supabase'
                : cloudStatus === 'Cloud Not Configured'
                ? 'Cloud sync is not configured yet.'
                : 'Sync unavailable — API connection could not be established.'
            }
          >
            {cloudStatus === 'Cloud Connected' ? (
              <Cloud size={12} style={{ color: '#10b981' }} />
            ) : cloudStatus === 'Cloud Not Configured' ? (
              <CloudOff size={12} style={{ color: '#f59e0b' }} />
            ) : (
              <WifiOff size={12} style={{ color: '#ef4444' }} />
            )}
            <span>{cloudStatus}</span>
          </div>

          {/* Read-Only Status Indicator */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
              padding: '0.22rem 0.55rem',
              borderRadius: '4px',
              background: 'rgba(0, 229, 255, 0.08)',
              border: '1px solid rgba(0, 229, 255, 0.25)',
              fontSize: '0.72rem',
              color: '#38bdf8',
              fontWeight: 600
            }}
            title="PhantomTrace operates strictly as a read-only threat detection engine"
          >
            <Lock size={12} style={{ color: '#00e5ff' }} />
            <span>Read-Only</span>
          </div>

          {/* Dynamic Local Clock */}
          <div
            style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.75rem', color: '#94a3b8' }}
            title="Local System Time"
          >
            <Clock size={13} style={{ color: '#00e5ff' }} />
            <span style={{ fontVariantNumeric: 'tabular-nums', fontWeight: 500, color: '#e2e8f0' }}>
              {formattedTime}
            </span>
          </div>

          {/* Requirement 1, 7, 8: Sync Action Button */}
          <button
            onClick={handleSync}
            disabled={isSyncing || isRefreshing}
            className="pt-btn pt-btn-secondary"
            style={{
              padding: '0.35rem 0.75rem',
              fontSize: '0.78rem',
              cursor: (isSyncing || isRefreshing) ? 'not-allowed' : 'pointer',
              opacity: (isSyncing || isRefreshing) ? 0.75 : 1,
            }}
            title="Synchronize telemetry with PhantomTrace API"
          >
            <RefreshCw size={13} className={(isSyncing || isRefreshing) ? 'pt-spin' : ''} />
            <span>{isSyncing ? 'Syncing...' : 'Sync'}</span>
          </button>

          {/* Analyst Session Badge with Official App Icon */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', paddingLeft: '0.5rem', borderLeft: '1px solid var(--pt-border-subtle)' }}>
            <Logo variant="app" height={28} />
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: '0.78rem', fontWeight: 600, color: '#f8fafc', lineHeight: 1.1 }}>
                Analyst SEC-8842
              </span>
              <span style={{ fontSize: '0.68rem', color: '#64748b' }}>
                Tier 2 Triage
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* Requirements 5 & 6: Sync Notification Banner */}
      {syncNotification && (
        <div
          style={{
            padding: '0.45rem 1.5rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background:
              syncNotification.type === 'success'
                ? 'rgba(6, 78, 59, 0.95)'
                : syncNotification.type === 'warning'
                ? 'rgba(120, 53, 15, 0.95)'
                : 'rgba(127, 29, 29, 0.95)',
            borderBottom: `1px solid ${
              syncNotification.type === 'success'
                ? 'rgba(16, 185, 129, 0.4)'
                : syncNotification.type === 'warning'
                ? 'rgba(245, 158, 11, 0.4)'
                : 'rgba(239, 68, 68, 0.4)'
            }`,
            backdropFilter: 'blur(8px)',
            color: '#ffffff',
            fontSize: '0.8rem',
            animation: 'fadeIn 0.2s ease',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            {syncNotification.type === 'success' ? (
              <CheckCircle2 size={15} style={{ color: '#34d399', flexShrink: 0 }} />
            ) : syncNotification.type === 'warning' ? (
              <AlertTriangle size={15} style={{ color: '#fbbf24', flexShrink: 0 }} />
            ) : (
              <AlertCircle size={15} style={{ color: '#f87171', flexShrink: 0 }} />
            )}
            <span style={{ fontWeight: 500 }}>{syncNotification.message}</span>
          </div>
          <button
            onClick={() => setSyncNotification(null)}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#ffffff',
              cursor: 'pointer',
              padding: '0.2rem',
              display: 'flex',
              alignItems: 'center',
              opacity: 0.8,
            }}
            title="Dismiss notice"
          >
            <X size={14} />
          </button>
        </div>
      )}
    </div>
  );
};
