import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  ShieldAlert,
  ExternalLink,
  Server,
  AlertCircle
} from 'lucide-react';
import { useThreatData } from '../hooks/useThreatData';
import { dataService } from '../services';
import { Logo } from '../components/common/Logo';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { ScorePill } from '../components/common/ScorePill';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { EmptyState } from '../components/common/EmptyState';
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

  // Dashboard Security Monitor state
  const [securityOverview, setSecurityOverview] = useState<DashboardSecurityOverview | null>(null);
  const [timelineEvents, setTimelineEvents] = useState<SecurityTimelineEvent[]>([]);
  const [timelineTotal, setTimelineTotal] = useState<number>(0);
  const [timelineLoading, setTimelineLoading] = useState<boolean>(true);
  const [systemHealth, setSystemHealth] = useState<SystemHealthStatus | null>(null);
  const [healthLoading, setHealthLoading] = useState<boolean>(true);

  // Fetch Security Monitor data
  const loadSecurityMonitorData = useCallback(async () => {
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
    await Promise.all([refreshData(), loadSecurityMonitorData()]);
  };

  useEffect(() => {
    loadSecurityMonitorData();
  }, [loadSecurityMonitorData]);

  if (loading && !overview && !securityOverview) {
    return (
      <LoadingSpinner
        label="Loading PhantomTrace Unified Threat Telemetry..."
        size="lg"
        fullHeight
      />
    );
  }

  if (error && !overview && !securityOverview) {
    return (
      <div
        className="pt-card"
        style={{
          padding: '2.5rem',
          border: '1px solid var(--pt-critical-border)',
          background: 'var(--pt-critical-bg)',
          textAlign: 'center',
          color: '#fca5a5'
        }}
        role="alert"
      >
        <div style={{ display: 'inline-flex', padding: '0.75rem', borderRadius: '50%', background: 'rgba(239, 68, 68, 0.2)', marginBottom: '1rem' }}>
          <AlertCircle size={32} className="text-critical" />
        </div>
        <h3 style={{ color: '#ffffff', fontSize: '1.2rem', marginBottom: '0.5rem', fontWeight: 700 }}>
          Unable to Load PhantomTrace Telemetry
        </h3>
        <p style={{ color: 'var(--pt-text-secondary)', marginBottom: '1.5rem', maxWidth: '480px', margin: '0 auto 1.5rem auto' }}>
          {error || 'Unable to establish connection with the PhantomTrace backend API. Please verify backend service status.'}
        </p>
        <button
          type="button"
          onClick={handleCombinedRefresh}
          className="pt-btn pt-btn-secondary"
        >
          <span>Retry Connection</span>
        </button>
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
      {/* System Health & Diagnostic Probes Banner */}
      <SystemHealthMonitor
        health={systemHealth}
        loading={healthLoading}
        onRefresh={handleCombinedRefresh}
      />

      {/* Official Dashboard Branding Header */}
      <div
        className="pt-card pt-card-cyber"
        style={{
          padding: '1.25rem 1.75rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
          background: 'linear-gradient(135deg, rgba(16, 26, 46, 0.9) 0%, rgba(9, 15, 26, 0.98) 100%)',
          border: '1px solid var(--pt-border-cyan)'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
          <Logo variant="dashboard" height={48} />
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <h2 style={{ fontSize: '1.35rem', fontWeight: 800, color: '#ffffff', letterSpacing: '-0.015em', margin: 0 }}>
                Security Operations Dashboard
              </h2>
              <Badge level="low" size="sm">
                Live Console
              </Badge>
            </div>
            <p style={{ fontSize: '0.82rem', color: 'var(--pt-text-muted)', marginTop: '0.25rem' }}>
              &ldquo;Trace what others can&apos;t see.&rdquo; &bull; Memory &amp; Behavioral Threat Telemetry
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--pt-text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Telemetry Source
            </div>
            <div style={{ fontSize: '0.84rem', color: isRealScannerData ? 'var(--pt-status-success)' : 'var(--pt-status-warning)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.4rem', justifyContent: 'flex-end' }}>
              <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: isRealScannerData ? 'var(--pt-status-success)' : 'var(--pt-status-warning)', display: 'inline-block' }} />
              {isRealScannerData ? 'Windows Scanner (Cloud)' : 'Cloud Connected'}
            </div>
          </div>

          <div style={{ height: '32px', width: '1px', background: 'var(--pt-border-subtle)' }} />

          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--pt-text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Endpoint
            </div>
            <div style={{ fontSize: '0.84rem', color: '#ffffff', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <Server size={13} className="text-cyan" />
              <span>Windows PC</span>
            </div>
          </div>

          <div style={{ height: '32px', width: '1px', background: 'var(--pt-border-subtle)' }} />

          <DownloadAgentButton variant="cyber" size="sm" />
        </div>
      </div>

      {/* One-Click "Scan My PC" Windows Agent Card */}
      <ScanMyPcCard
        lastScanTime={securityOverview?.lastSuccessfulScanUpload || data?.scanTime}
        onScanCompleted={handleCombinedRefresh}
      />

      {/* Security Overview Grid (Actual backend data without fake fallbacks) */}
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

      {/* Security Event Timeline (Multi-vector chronological audit) */}
      <SecurityEventTimeline
        events={timelineEvents}
        total={timelineTotal}
        loading={timelineLoading}
        onFilterChange={handleTimelineFilterChange}
      />

      {/* Recent Threat Alerts Summary Table */}
      <Card
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <ShieldAlert size={18} className="text-critical" />
            <span>Recent Threat Alerts</span>
          </div>
        }
        subtitle="Click any alert to inspect memory structures, behavior lineage, and recommended investigation steps"
        action={
          <Link to="/alerts" className="pt-btn pt-btn-cyber pt-btn-sm">
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
                  <td colSpan={10} style={{ padding: '2rem 1rem' }}>
                    <EmptyState
                      variant="clean"
                      title="No elevated threat alerts detected"
                      description="All monitored processes and volatile memory regions are operating within verified forensic baselines."
                    />
                  </td>
                </tr>
              ) : (
                alerts.slice(0, 5).map((alert) => (
                  <tr
                    key={alert.id}
                    className="clickable-row"
                    onClick={() => navigate(`/alerts/${alert.id}`)}
                  >
                    <td className="text-mono" style={{ fontWeight: 600, color: 'var(--pt-cyan)' }}>
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
                    <td style={{ fontSize: '0.78rem', color: 'var(--pt-text-secondary)' }}>
                      {alert.scoreMode}
                    </td>
                    <td className="text-mono" style={{ color: 'var(--pt-status-high)', fontWeight: 600 }}>
                      {alert.behaviorScore ?? 0}
                    </td>
                    <td className="text-mono" style={{ color: 'var(--pt-cyan)', fontWeight: 600 }}>
                      {alert.memoryScore ?? 0}
                    </td>
                    <td style={{ maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: '0.78rem', color: 'var(--pt-text-muted)' }}>
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
                        className="pt-btn pt-btn-cyber pt-btn-sm"
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

      {/* Web Threat Monitor & Domain Policies Section */}
      <WebThreatMonitorSection />

      {/* Enrolled Devices Management */}
      <MyDevicesSection />
    </div>
  );
};

export default DashboardPage;
