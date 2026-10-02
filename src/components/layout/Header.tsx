import React from 'react';
import { useLocation } from 'react-router-dom';
import { 
  RefreshCw, 
  Clock, 
  Lock, 
  Server
} from 'lucide-react';
import { Logo } from '../common/Logo';

interface HeaderProps {
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

export const Header: React.FC<HeaderProps> = ({ onRefresh, isRefreshing = false }) => {
  const location = useLocation();
  const [currentTime, setCurrentTime] = React.useState<Date>(() => new Date());

  React.useEffect(() => {
    const timer = window.setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);

    return () => window.clearInterval(timer);
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

  return (
    <header className="pt-header">
      {/* Page Title & Breadcrumb */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        <h1 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.01em', margin: 0 }}>
          {getPageTitle(location.pathname)}
        </h1>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', background: 'rgba(255, 255, 255, 0.04)', padding: '0.2rem 0.6rem', borderRadius: '4px', fontSize: '0.74rem', color: '#94a3b8' }}>
          <Server size={12} style={{ color: '#00e5ff' }} />
          <span>SEC-WORKSTATION-09</span>
        </div>
      </div>

      {/* Header Badges & Actions */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        {/* Read-Only Status Indicator */}
        <div 
          style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: '0.4rem', 
            padding: '0.25rem 0.65rem', 
            borderRadius: '4px', 
            background: 'rgba(0, 229, 255, 0.08)', 
            border: '1px solid rgba(0, 229, 255, 0.25)',
            fontSize: '0.75rem',
            color: '#38bdf8',
            fontWeight: 600
          }}
          title="PhantomTrace operates strictly as a read-only threat detection engine"
        >
          <Lock size={12} style={{ color: '#00e5ff' }} />
          <span>Read-Only Mode</span>
        </div>

        {/* Dynamic Local Clock */}
        <div 
          style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.75rem', color: '#94a3b8' }}
          title="Local System Time"
        >
          <Clock size={13} style={{ color: '#00e5ff' }} />
          <span style={{ fontVariantNumeric: 'tabular-nums', fontWeight: 500, color: '#e2e8f0' }}>
            {formattedTime}
          </span>
        </div>

        {/* Refresh Action */}
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            className="pt-btn pt-btn-secondary"
            style={{ padding: '0.35rem 0.75rem', fontSize: '0.78rem' }}
            title="Reload telemetry data from service layer"
          >
            <RefreshCw size={13} className={isRefreshing ? 'pt-spin' : ''} />
            <span>Sync</span>
          </button>
        )}

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
  );
};
