import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  ShieldAlert,
  ExternalLink,
} from 'lucide-react';
import { useThreatData } from '../hooks/useThreatData';
import { dataService } from '../services';
import { Logo } from '../components/common/Logo';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { ScorePill } from '../components/common/ScorePill';
import { ThreatActivityChart } from '../components/charts/ThreatActivityChart';
import { ThreatDistributionChart } from '../components/charts/ThreatDistributionChart';
import { ScanMyPcCard } from '../components/agent/ScanMyPcCard';
import { MyDevicesSection } from '../components/agent/MyDevicesSection';
import { DownloadAgentButton } from '../components/agent/DownloadAgentButton';
import { WebThreatMonitorSection } from '../components/webthreat/WebThreatMonitorSection';
import { SecurityOverviewGrid } from '../components/dashboard/SecurityOverviewGrid';
import { SecurityEventTimeline } from '../components/dashboard/SecurityEventTimeline';
import { SystemHealthMonitor } from '../components/dashboard/SystemHealthMonitor';
import type {
  DashboardSecurityOverview,
  SecurityTimelineEvent,
  SystemHealthStatus,
} from '../types';

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const { overview, alerts, activityTimeline, loading, error, refreshData } = useThreatData();

  // Phase 5 Dashboard Security Monitor state
  const [securityOverview, setSecurityOverview] = useState<DashboardSecurityOverview | null>(null);
  const [timelineEvents, setTimelineEvents] = useState<SecurityTimelineEvent[]>([]);
  const [timelineTotal, setTimelineTotal] = useState<number>(0);
  const [timelineLoading, setTimelineLoading] = useState<boolean>(true);
  const [systemHealth, setSystemHealth] = useState<SystemHealthStatus | null>(null);
  const [healthLoading, setHealthLoading] = useState<boolean>(true);

  // Fetch Phase 5 Security Monitor data
  const loadPhase5Data = useCallback(async () => {
    try {
      setHealthLoading(true);
      if (dataService.getSystemHealth) {
        const health = await dataService.getSystemHealth();
        setSystemHealth(health);
      }
    } catch (err) {
      console.warn('[Dashboard] Error fetching system health:', err);
    } finally {
      setHealthLoading(false);
    }

    try {
      if (dataService.getDashboardOverview) {
        const ov = await dataService.getDashboardOverview();
        setSecurityOverview(ov);
      }
    } catch (err) {
      console.warn('[Dashboard] Error fetching security overview:', err);
    }

    try {
      setTimelineLoading(true);
      if (dataService.getSecurityTimeline) {
        const timeline = await dataService.getSecurityTimeline('ALL', 'ALL', 15, 0);
        setTimelineEvents(timeline.events);
        setTimelineTotal(timeline.total);
      }
    } catch (err) {
      console.warn('[Dashboard] Error fetching timeline events:', err);
    } finally {
      setTimelineLoading(false);
    }
  }, []);

  const handleTimelineFilterChange = async (
    type?: string,
    severity?: string,
    limit = 15,
    offset = 0
  ) => {
    try {
      setTimelineLoading(true);
      if (dataService.getSecurityTimeline) {
        const timeline = await dataService.getSecurityTimeline(type, severity, limit, offset);
        setTimelineEvents(timeline.events);
        setTimelineTotal(timeline.total);
      }
    } catch (err) {
      console.warn('[Dashboard] Error filtering timeline:', err);
    } finally {
      setTimelineLoading(false);
    }
  };

  const handleCombinedRefresh = async () => {
    await Promise.all([refreshData(), loadPhase5Data()]);
  };

  useEffect(() => {
    loadPhase5Data();
  }, [loadPhase5Data]);

  if (loading && !overview && !securityOverview) {
    return (
      <div style={{ padding: '3rem', textAlign: 'center', color: '#94a3b8' }}>
        Loading PhantomTrace data...
      </div>
    );
  }

  if (error && !overview && !securityOverview) {
    return (
      <div style={{ padding: '2rem', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', borderRadius: '8px', color: '#fca5a5', textAlign: 'center' }}>
        Unable to load PhantomTrace data.
      </div>
    );
  }

  const data = overview;
  const isRealScannerData = Boolean(
    securityOverview?.isRealScannerData ||
    data?.scanMode?.includes('Windows Ingested') ||
    data?.engineVersion?.includes('PhantomTrace') ||
    data?.engineVersion?.includes('Release') ||
    ((data?.totalProcesses ?? 0) >= 200)
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Phase 5: System Health & Diagnostic Probes Banner */}
      <SystemHealthMonitor
        health={systemHealth}
        loading={healthLoading}
        onRefresh={handleCombinedRefresh}
      />

      {/* Official Dashboard Branding Header */}
      <div
        className="pt-card pt-card-cyber"
        style={{
          padding: '1.15rem 1.5rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
          background: 'linear-gradient(135deg, rgba(16, 26, 46, 0.85) 0%, rgba(9, 15, 26, 0.95) 100%)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.15rem' }}>
          <Logo variant="dashboard" height={48} />
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#ffffff', letterSpacing: '-0.01em', margin: 0 }}>
                Security Dashboard
              </h2>
              <span className="pt-badge pt-badge-low" style={{ fontSize: '0.7rem' }}>
                Phase 5 Security Monitor
              </span>
            </div>
            <p style={{ fontSize: '0.8rem', color: '#94a3b8', marginTop: '0.2rem' }}>
              "Trace what others can't see." • Live Production Telemetry
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Telemetry Source</div>
            <div style={{ fontSize: '0.82rem', color: isRealScannerData ? '#10b981' : '#f59e0b', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.35rem', justifyContent: 'flex-end' }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: isRealScannerData ? '#10b981' : '#f59e0b', display: 'inline-block' }} />
              {isRealScannerData ? 'Windows Scanner (Cloud)' : 'Cloud Connected'}
            </div>
          </div>
          <div style={{ height: '28px', width: '1px', background: 'var(--pt-border-subtle)' }} />
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Endpoint</div>
            <div style={{ fontSize: '0.82rem', color: '#ffffff', fontWeight: 600 }}>
              Windows PC
            </div>
          </div>
          <div style={{ height: '28px', width: '1px', background: 'var(--pt-border-subtle)' }} />
          <DownloadAgentButton variant="cyber" size="sm" />
        </div>
      </div>

      {/* One-Click "Scan My PC" Windows Agent Card */}
      <ScanMyPcCard
        lastScanTime={securityOverview?.lastSuccessfulScanUpload || data?.scanTime}
        onScanCompleted={handleCombinedRefresh}
      />

      {/* Phase 5: Security Overview Grid (Actual backend data without fake fallbacks) */}
      <SecurityOverviewGrid
        overview={securityOverview}
        loading={loading}
        error={error}
      />

      {/* Interactive Charts (Risk Activity & Severity Distribution) */}
      {activityTimeline && activityTimeline.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '1.25rem' }}>
          <ThreatActivityChart data={activityTimeline} />
          {overview && (
            <ThreatDistributionChart overview={overview} />
          )}
        </div>
      )}

      {/* Phase 5: Security Event Timeline (Multi-vector chronological audit) */}
      <SecurityEventTimeline
        events={timelineEvents}
        total={timelineTotal}
        loading={timelineLoading}
        onFilterChange={handleTimelineFilterChange}
      />

      {/* Recent Threat Alerts Summary Table */}
      <Card
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <ShieldAlert size={18} style={{ color: 'var(--pt-critical)' }} />
            <span>Recent Threat Alerts</span>
          </div>
        }
        subtitle="Click any alert to inspect memory structures, behavior lineage, and recommended investigation steps"
        action={
          <Link to="/alerts" className="pt-btn pt-btn-cyber" style={{ padding: '0.35rem 0.85rem', fontSize: '0.78rem' }}>
            <span>View All Alerts ({alerts.length})</span>
            <ExternalLink size={13} />
          </Link>
        }
      >
        <div className="pt-table-container">
          <table className="pt-table">
            <thead>
              <tr>
                <th>PID</th>
                <th>Process</th>
                <th>Threat Score</th>
                <th>Threat Level</th>
                <th>Application</th>
                <th>Score Mode</th>
                <th>Behavior</th>
                <th>Memory</th>
                <th>Primary Evidence Vector</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan={10} style={{ textAlign: 'center', padding: '2.5rem', color: '#64748b' }}>
                    No elevated threat alerts detected in latest scan.
                  </td>
                </tr>
              ) : (
                alerts.slice(0, 5).map((alert) => (
                  <tr
                    key={alert.id}
                    className="clickable-row"
                    onClick={() => navigate(`/alerts/${alert.id}`)}
                  >
                    <td className="text-mono" style={{ fontWeight: 600, color: '#00e5ff' }}>
                      {alert.pid}
                    </td>
                    <td style={{ fontWeight: 600, color: '#ffffff' }}>
                      {alert.process || alert.processName}
                    </td>
                    <td>
                      <ScorePill score={alert.threatScore ?? alert.score} />
                    </td>
                    <td>
                      <Badge level={alert.threatLevel}>{alert.threatLevel}</Badge>
                    </td>
                    <td>
                      <Badge level="neutral">{alert.application}</Badge>
                    </td>
                    <td style={{ fontSize: '0.78rem', color: '#cbd5e1' }}>
                      {alert.scoreMode}
                    </td>
                    <td className="text-mono" style={{ color: '#f97316', fontWeight: 600 }}>
                      {alert.behaviorScore ?? 0}
                    </td>
                    <td className="text-mono" style={{ color: '#00e5ff', fontWeight: 600 }}>
                      {alert.memoryScore ?? 0}
                    </td>
                    <td style={{ maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: '0.78rem', color: '#94a3b8' }}>
                      {typeof alert.memoryEvidence === 'string'
                        ? alert.memoryEvidence
                        : alert.memoryEvidence?.details?.[0] || alert.memoryEvidence?.indicators?.[0] || 'None'}
                    </td>
                    <td>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/alerts/${alert.id}`);
                        }}
                        className="pt-btn pt-btn-cyber"
                        style={{ padding: '0.25rem 0.6rem', fontSize: '0.72rem' }}
                      >
                        Investigate
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Phase 3 & 4 Web Threat Monitor & Domain Policies Section */}
      <WebThreatMonitorSection />

      {/* Enrolled Devices Management */}
      <MyDevicesSection />
    </div>
  );
};
