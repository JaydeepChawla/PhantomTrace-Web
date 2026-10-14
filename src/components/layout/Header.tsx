import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import {
  RefreshCw,
  Clock,
  Server,
  Cloud,
  CloudOff,
  WifiOff,
  AlertTriangle,
  AlertCircle,
  CheckCircle2,
  X,
  Menu
} from 'lucide-react';
import { Logo } from '../common/Logo';
import { dataService } from '../../services';
import type { CloudConnectionStatus } from '../../services';

export interface HeaderProps {
  onRefresh?: () => Promise<void> | void;
  isRefreshing?: boolean;
  isMobileNavOpen?: boolean;
  onToggleMobileNav?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  onRefresh,
  isRefreshing = false,
  isMobileNavOpen = false,
  onToggleMobileNav,
}) => {
  const location = useLocation();
  const [currentTime, setCurrentTime] = useState<Date>(() => new Date());
  const [cloudStatus, setCloudStatus] = useState<CloudConnectionStatus>("API Offline");
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

  // Initial backend health & cloud verification
  useEffect(() => {
    let active = true;

    const checkStatus = async () => {
      try {
        if (dataService.checkHealth) {
          const health = await dataService.checkHealth();
          if (active) {
            setCloudStatus(health.status);
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
    if (pathname === '/history' || pathname === '/scan-history') return 'Historical Scan Cycles';
    if (pathname === '/reports') return 'Telemetry Reports & Export';
    if (pathname === '/settings') return 'Platform & Scanner Configuration';
    if (pathname === '/setup' || pathname === '/onboarding' || pathname === '/download') return 'Agent Installation & Setup';
    return 'Investigation Console';
  };

  const handleSync = async () => {
    if (isSyncing) return;

    setIsSyncing(true);
    setSyncNotification(null);

    try {
      if (dataService.syncTelemetry) {
        const result = await dataService.syncTelemetry();
        setCloudStatus(result.status);

        if (result.success) {
          const isNoNew = result.message.includes('No new scan');
          setSyncNotification({
            type: isNoNew ? 'warning' : 'success',
            message: result.message,
          });
          if (onRefresh) {
            await onRefresh();
          }
        } else {
          setSyncNotification({
            type: 'error',
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
      setSyncNotification({
        type: 'error',
        message: `Unable to update telemetry: ${msg}`,
      });
    } finally {
      setIsSyncing(false);
    }
  };

  return (
    <div className="pt-header-sticky-wrapper">
      <header className="pt-header" aria-label="Console Application Header">
        {/* Left Section: Mobile Menu Button + Page Title + Context Chip */}
        <div className="pt-header-left">
          {onToggleMobileNav && (
            <button
              type="button"
              className="pt-header-menu-btn"
              onClick={onToggleMobileNav}
              aria-label={isMobileNavOpen ? "Close navigation menu" : "Open navigation menu"}
              aria-expanded={isMobileNavOpen}
              aria-controls="primary-navigation"
            >
              {isMobileNavOpen ? <X size={20} aria-hidden="true" /> : <Menu size={20} aria-hidden="true" />}
            </button>
          )}

          <div className="pt-header-title-group">
            <h1 className="pt-header-title">
              {getPageTitle(location.pathname)}
            </h1>

            <div className="pt-header-endpoint-chip" title="Active Target Endpoint">
              <Server size={12} className="text-cyan" aria-hidden="true" />
              <span>Windows PC</span>
            </div>
          </div>
        </div>

        {/* Right Section: Badges, Live Clock, Sync, Endpoint Identity */}
        <div className="pt-header-actions">
          {/* Cloud Status Indicator */}
          <div
            className={`pt-cloud-badge pt-cloud-badge-${
              cloudStatus === 'Cloud Connected'
                ? 'connected'
                : cloudStatus === 'Cloud Not Configured'
                ? 'unconfigured'
                : 'offline'
            }`}
            title={
              cloudStatus === 'Cloud Connected'
                ? 'Cloud Connected: Backend API is live with PostgreSQL/Supabase'
                : cloudStatus === 'Cloud Not Configured'
                ? 'Cloud sync is not configured yet.'
                : 'Sync unavailable — API connection could not be established.'
            }
            role="status"
          >
            {cloudStatus === 'Cloud Connected' ? (
              <Cloud size={13} className="pt-cloud-icon text-success" aria-hidden="true" />
            ) : cloudStatus === 'Cloud Not Configured' ? (
              <CloudOff size={13} className="pt-cloud-icon text-warning" aria-hidden="true" />
            ) : (
              <WifiOff size={13} className="pt-cloud-icon text-critical" aria-hidden="true" />
            )}
            <span className="pt-cloud-text">{cloudStatus}</span>
          </div>

          {/* Dynamic Local Clock */}
          <div
            className="pt-header-clock"
            title="Local System Time"
            aria-label={`Current system time: ${formattedTime}`}
          >
            <Clock size={13} className="text-cyan" aria-hidden="true" />
            <span className="pt-header-clock-time">{formattedTime}</span>
          </div>

          {/* Sync Action Button */}
          <button
            type="button"
            onClick={handleSync}
            disabled={isSyncing || isRefreshing}
            className="pt-btn pt-btn-secondary pt-header-sync-btn"
            title="Synchronize telemetry with PhantomTrace API"
            aria-busy={isSyncing || isRefreshing}
          >
            <RefreshCw
              size={13}
              className={(isSyncing || isRefreshing) ? 'pt-spin' : ''}
              aria-hidden="true"
            />
            <span className="pt-sync-label">{isSyncing ? 'Syncing...' : 'Sync'}</span>
          </button>

          {/* Endpoint Identity Badge with Official App Icon */}
          <div className="pt-header-identity" title="Protected Windows Endpoint">
            <Logo variant="app" height={28} />
            <div className="pt-header-identity-text">
              <span className="pt-identity-name">Windows PC</span>
              <span className="pt-identity-status">Protected</span>
            </div>
          </div>
        </div>
      </header>

      {/* Sync Notification Banner */}
      {syncNotification && (
        <div
          className={`pt-sync-notification pt-sync-notification-${syncNotification.type}`}
          role="status"
          aria-live="polite"
        >
          <div className="pt-sync-notification-content">
            {syncNotification.type === 'success' ? (
              <CheckCircle2 size={15} className="text-success" aria-hidden="true" />
            ) : syncNotification.type === 'warning' ? (
              <AlertTriangle size={15} className="text-warning" aria-hidden="true" />
            ) : (
              <AlertCircle size={15} className="text-critical" aria-hidden="true" />
            )}
            <span className="pt-sync-notification-message">{syncNotification.message}</span>
          </div>
          <button
            type="button"
            onClick={() => setSyncNotification(null)}
            className="pt-sync-notification-close"
            title="Dismiss notice"
            aria-label="Dismiss notification"
          >
            <X size={14} aria-hidden="true" />
          </button>
        </div>
      )}
    </div>
  );
};
