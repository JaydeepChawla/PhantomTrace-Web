import React, { useState, useEffect, useCallback } from 'react';
import {
  Globe,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Info,
  CheckCircle2,
  XCircle
} from 'lucide-react';
import { ApiDataService } from '../../services/apiDataService';
import type { WebThreatEvent, WebThreatStatus } from '../../types';
import { formatScanDate } from '../../utils/dateFormat';

interface WebThreatMonitorSectionProps {
  onEventCountChanged?: (count: number) => void;
}

export const WebThreatMonitorSection: React.FC<WebThreatMonitorSectionProps> = ({
  onEventCountChanged,
}) => {
  const [events, setEvents] = useState<WebThreatEvent[]>([]);
  const [status, setStatus] = useState<WebThreatStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [dismissingId, setDismissingId] = useState<string | null>(null);

  const apiService = React.useMemo(() => new ApiDataService(), []);

  const loadData = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    setError(null);

    try {
      const [statusRes, eventsRes] = await Promise.all([
        apiService.getWebThreatStatus(),
        apiService.getWebThreatEvents(),
      ]);

      setStatus(statusRes);
      setEvents(eventsRes);
      if (onEventCountChanged) {
        onEventCountChanged(eventsRes.length);
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to communicate with web threat reputation service.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [apiService, onEventCountChanged]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleDismiss = async (eventId: string) => {
    setDismissingId(eventId);
    try {
      const ok = await apiService.dismissWebThreatEvent(eventId);
      if (ok) {
        setEvents((prev) => prev.filter((e) => e.id !== eventId));
        if (onEventCountChanged) {
          onEventCountChanged(events.length - 1);
        }
      }
    } catch {
      // ignore
    } finally {
      setDismissingId(null);
    }
  };

  const isServiceOnline = status?.serviceOnline ?? false;
  const isExtensionConnected = events.length > 0;

  return (
    <div className="pt-card pt-card-cyber" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
      {/* Header */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '0.75rem',
        marginBottom: '1rem',
        borderBottom: '1px solid rgba(51, 65, 85, 0.4)',
        paddingBottom: '0.85rem',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <div style={{
            width: '36px',
            height: '36px',
            borderRadius: '8px',
            background: 'rgba(6, 182, 212, 0.12)',
            border: '1px solid rgba(6, 182, 212, 0.3)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#06b6d4'
          }}>
            <Globe size={20} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#ffffff', margin: 0 }}>
                Web Threat Monitor
              </h3>
              <span style={{
                fontSize: '0.68rem',
                fontWeight: 700,
                padding: '0.15rem 0.5rem',
                borderRadius: '4px',
                background: 'rgba(6, 182, 212, 0.15)',
                color: '#38bdf8',
                border: '1px solid rgba(6, 182, 212, 0.3)',
                letterSpacing: '0.5px'
              }}>
                PHASE 3
              </span>
            </div>
            <p style={{ fontSize: '0.78rem', color: '#94a3b8', margin: 0, marginTop: '2px' }}>
              Browser navigation reputation verification & threat intelligence integration
            </p>
          </div>
        </div>

        {/* Status Indicators & Refresh */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          {isServiceOnline ? (
            <span style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
              fontSize: '0.75rem',
              fontWeight: 600,
              padding: '0.25rem 0.65rem',
              borderRadius: '6px',
              background: 'rgba(16, 185, 129, 0.12)',
              color: '#34d399',
              border: '1px solid rgba(16, 185, 129, 0.3)'
            }}>
              <CheckCircle2 size={13} />
              Threat Intel Online
            </span>
          ) : (
            <span style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
              fontSize: '0.75rem',
              fontWeight: 600,
              padding: '0.25rem 0.65rem',
              borderRadius: '6px',
              background: 'rgba(239, 68, 68, 0.12)',
              color: '#f87171',
              border: '1px solid rgba(239, 68, 68, 0.3)'
            }}>
              <XCircle size={13} />
              Reputation Unavailable
            </span>
          )}

          <button
            type="button"
            onClick={() => loadData(true)}
            disabled={refreshing}
            className="pt-btn pt-btn-secondary"
            style={{ padding: '0.35rem 0.65rem', fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
            title="Refresh Web Threat Telemetry"
          >
            <RefreshCw size={13} className={refreshing ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {/* Configuration & Privacy Meta Banner */}
      <div style={{
        background: 'rgba(15, 23, 42, 0.6)',
        border: '1px solid rgba(51, 65, 85, 0.3)',
        borderRadius: '6px',
        padding: '0.65rem 0.85rem',
        fontSize: '0.74rem',
        color: '#94a3b8',
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '0.5rem',
        marginBottom: '1rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ color: '#cbd5e1' }}><strong>Active Provider:</strong> {status?.provider || 'PhantomTrace-Mock-ThreatIntel'}</span>
          <span>•</span>
          <span style={{ color: '#cbd5e1' }}><strong>Browser Extension:</strong> {isExtensionConnected ? 'Reporting Live Telemetry' : 'Unpacked Extension Available (Chrome/Edge)'}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', color: '#64748b' }}>
          <Info size={12} />
          <span>Passive inspection: Query strings & form passwords are never transmitted.</span>
        </div>
      </div>

      {/* Main Content Area */}
      {loading ? (
        <div style={{ padding: '2rem', textAlign: 'center', color: '#94a3b8', fontSize: '0.85rem' }}>
          <RefreshCw size={18} className="animate-spin" style={{ display: 'inline-block', marginBottom: '0.5rem', color: '#06b6d4' }} />
          <div>Checking web threat reputation engine...</div>
        </div>
      ) : error ? (
        <div style={{
          padding: '1.25rem',
          background: 'rgba(239, 68, 68, 0.08)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          borderRadius: '6px',
          color: '#fca5a5',
          fontSize: '0.82rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.75rem'
        }}>
          <AlertTriangle size={18} style={{ color: '#ef4444', flexShrink: 0 }} />
          <div>
            <strong>Web Threat Monitor Notice:</strong> {error}
            <div style={{ fontSize: '0.74rem', color: '#f87171', marginTop: '2px' }}>
              Ensure backend server is running on port 5000 or Render cloud deployment is active.
            </div>
          </div>
        </div>
      ) : events.length === 0 ? (
        <div style={{
          padding: '2rem 1rem',
          textAlign: 'center',
          background: 'rgba(15, 23, 42, 0.4)',
          borderRadius: '8px',
          border: '1px dashed rgba(51, 65, 85, 0.5)'
        }}>
          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '0.75rem', color: '#10b981' }}>
            <ShieldCheck size={36} />
          </div>
          <h4 style={{ fontSize: '0.98rem', fontWeight: 600, color: '#f1f5f9', margin: '0 0 0.35rem 0' }}>
            No Web Threat Incidents Detected
          </h4>
          <p style={{ fontSize: '0.8rem', color: '#94a3b8', maxWidth: '520px', margin: '0 auto 1.25rem auto', lineHeight: 1.5 }}>
            Visited domains have not triggered high-risk threat intelligence or suspicious heuristic rules.
            Unknown domains are safely preserved without fabricated alerts.
          </p>

          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            background: 'rgba(30, 41, 59, 0.6)',
            padding: '0.5rem 0.85rem',
            borderRadius: '6px',
            fontSize: '0.74rem',
            color: '#cbd5e1',
            border: '1px solid #334155'
          }}>
            <Info size={14} style={{ color: '#38bdf8' }} />
            <span>Install the unpacked extension from <code style={{ color: '#38bdf8', background: '#0b0f19', padding: '1px 5px', borderRadius: '3px' }}>browser-extension/</code> in Chrome or Edge to enable real-time tab protection.</span>
          </div>
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #334155', color: '#94a3b8' }}>
                <th style={{ padding: '0.65rem 0.75rem', fontWeight: 600 }}>Domain / Host</th>
                <th style={{ padding: '0.65rem 0.75rem', fontWeight: 600 }}>Severity</th>
                <th style={{ padding: '0.65rem 0.75rem', fontWeight: 600 }}>Classification</th>
                <th style={{ padding: '0.65rem 0.75rem', fontWeight: 600 }}>Source & Rule</th>
                <th style={{ padding: '0.65rem 0.75rem', fontWeight: 600 }}>Reason / Details</th>
                <th style={{ padding: '0.65rem 0.75rem', fontWeight: 600 }}>Detected At</th>
                <th style={{ padding: '0.65rem 0.75rem', fontWeight: 600, textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {events.map((ev) => {
                const isCritical = ev.severity === 'CRITICAL';
                const isHigh = ev.severity === 'HIGH';
                const isMedium = ev.severity === 'MEDIUM';

                const badgeBg = isCritical
                  ? 'rgba(239, 68, 68, 0.2)'
                  : isHigh
                  ? 'rgba(249, 115, 22, 0.2)'
                  : isMedium
                  ? 'rgba(245, 158, 11, 0.2)'
                  : 'rgba(148, 163, 184, 0.2)';

                const badgeColor = isCritical
                  ? '#f87171'
                  : isHigh
                  ? '#fb923c'
                  : isMedium
                  ? '#fbbf24'
                  : '#94a3b8';

                return (
                  <tr
                    key={ev.id}
                    style={{
                      borderBottom: '1px solid rgba(30, 41, 59, 0.6)',
                      background: 'rgba(11, 15, 25, 0.4)',
                    }}
                  >
                    <td style={{ padding: '0.75rem', fontWeight: 600, color: '#f8fafc', whiteSpace: 'nowrap' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                        <Globe size={14} style={{ color: '#06b6d4' }} />
                        <span style={{ fontFamily: 'monospace' }}>{ev.domain}</span>
                      </div>
                    </td>
                    <td style={{ padding: '0.75rem' }}>
                      <span style={{
                        padding: '0.2rem 0.5rem',
                        borderRadius: '4px',
                        fontSize: '0.7rem',
                        fontWeight: 700,
                        background: badgeBg,
                        color: badgeColor,
                        border: `1px solid ${badgeColor}40`
                      }}>
                        {ev.severity}
                      </span>
                    </td>
                    <td style={{ padding: '0.75rem', color: '#cbd5e1' }}>
                      {ev.classification.replace(/_/g, ' ')}
                    </td>
                    <td style={{ padding: '0.75rem', color: '#94a3b8', fontSize: '0.76rem' }}>
                      <div>{ev.detectionSource.replace(/_/g, ' ')}</div>
                      {ev.ruleId && (
                        <div style={{ fontFamily: 'monospace', color: '#64748b', fontSize: '0.7rem' }}>
                          {ev.ruleId}
                        </div>
                      )}
                    </td>
                    <td style={{ padding: '0.75rem', color: '#cbd5e1', maxWidth: '300px' }}>
                      <div style={{ lineHeight: 1.4 }}>{ev.explanation}</div>
                      {ev.browser && (
                        <div style={{ fontSize: '0.68rem', color: '#64748b', marginTop: '2px' }}>
                          Source: {ev.browser}
                        </div>
                      )}
                    </td>
                    <td style={{ padding: '0.75rem', color: '#94a3b8', fontSize: '0.74rem', whiteSpace: 'nowrap' }}>
                      {formatScanDate(ev.timestamp)}
                    </td>
                    <td style={{ padding: '0.75rem', textAlign: 'right', whiteSpace: 'nowrap' }}>
                      <button
                        type="button"
                        onClick={() => handleDismiss(ev.id)}
                        disabled={dismissingId === ev.id}
                        className="pt-btn pt-btn-secondary"
                        style={{ padding: '0.25rem 0.55rem', fontSize: '0.72rem', color: '#94a3b8' }}
                      >
                        {dismissingId === ev.id ? 'Dismissing...' : 'Dismiss'}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
