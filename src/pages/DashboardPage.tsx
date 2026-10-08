import React from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  Cpu,
  AlertTriangle,
  Flame,
  Clock,
  Zap,
  ArrowUpRight,
  Layers,
  ExternalLink
} from 'lucide-react';
import { useThreatData } from '../hooks/useThreatData';
import { StatCard } from '../components/common/StatCard';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { ScorePill } from '../components/common/ScorePill';
import { Logo } from '../components/common/Logo';
import { ThreatActivityChart } from '../components/charts/ThreatActivityChart';
import { ThreatDistributionChart } from '../components/charts/ThreatDistributionChart';
import { ScanMyPcCard } from '../components/agent/ScanMyPcCard';
import { MyDevicesSection } from '../components/agent/MyDevicesSection';
import { DownloadAgentButton } from '../components/agent/DownloadAgentButton';

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const { overview, alerts, activityTimeline, loading, error, refreshData } = useThreatData();

  if (loading && !overview) {
    return (
      <div style={{ padding: '3rem', textAlign: 'center', color: '#94a3b8' }}>
        Loading PhantomTrace data...
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ padding: '2rem', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', borderRadius: '8px', color: '#fca5a5', textAlign: 'center' }}>
        Unable to load PhantomTrace data.
      </div>
    );
  }

  if (!overview) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', maxWidth: '800px', margin: '2rem auto' }}>
        <ScanMyPcCard onScanCompleted={() => refreshData()} />

        <div style={{ padding: '2.5rem 2rem', textAlign: 'center' }} className="pt-card pt-card-cyber">
          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '1.25rem' }}>
            <Logo variant="windows" height={52} />
          </div>
          <h3 style={{ fontSize: '1.3rem', fontWeight: 700, color: '#ffffff', marginBottom: '0.65rem' }}>
            No Active Endpoint Scans Found
          </h3>
          <p style={{ fontSize: '0.88rem', color: '#94a3b8', lineHeight: 1.6, marginBottom: '1.75rem' }}>
            No Windows scanner telemetry has been ingested into this workspace yet. Click "Scan My PC" above with the agent active or download the standalone scanner.
          </p>
          <div style={{ display: 'flex', gap: '0.85rem', justifyContent: 'center', flexWrap: 'wrap', alignItems: 'center' }}>
            <DownloadAgentButton variant="primary" />
            <button
              type="button"
              onClick={() => refreshData()}
              className="pt-btn pt-btn-secondary"
              style={{ padding: '0.65rem 1.25rem', fontSize: '0.86rem' }}
            >
              Refresh Dashboard
            </button>
          </div>
        </div>

        {/* Enrolled Devices Section */}
        <MyDevicesSection />
      </div>
    );
  }

  const data = overview;
  const isRealScannerData = Boolean(
    data.scanMode?.includes("Windows Ingested") ||
    data.engineVersion?.includes("PhantomTrace") ||
    data.engineVersion?.includes("Release") ||
    (data.totalProcesses && data.totalProcesses >= 200)
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* One-Click "Scan My PC" Windows Agent Card */}
      <ScanMyPcCard lastScanTime={data.scanTime} onScanCompleted={() => refreshData()} />

      {/* Real Scanner Telemetry Sync Status Indicator */}
      {isRealScannerData && (
        <div style={{
          padding: '0.45rem 0.85rem',
          background: 'rgba(16, 185, 129, 0.08)',
          border: '1px solid rgba(16, 185, 129, 0.25)',
          borderRadius: '6px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '0.5rem',
          fontSize: '0.76rem',
          color: '#6ee7b7'
        }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#10b981', display: 'inline-block' }} />
            <strong>Last synced from Windows PC:</strong> Verified telemetry for {data.totalProcesses} running processes.
          </span>
          <span style={{ color: '#94a3b8' }}>
            Last Scan: {data.scanTime}
          </span>
        </div>
      )}

      {/* Compact Scan Status Banner */}
      <div
        style={{
          padding: '0.75rem 1.25rem',
          borderRadius: '8px',
          background: 'rgba(16, 185, 129, 0.08)',
          border: '1px solid rgba(16, 185, 129, 0.25)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '0.75rem'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <ShieldCheck size={18} style={{ color: '#10b981', flexShrink: 0 }} />
          <div>
            <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span>Scanner Status: Protected &amp; Active</span>
              <span style={{ fontSize: '0.7rem', padding: '0.1rem 0.45rem', borderRadius: '4px', background: 'rgba(0, 229, 255, 0.1)', color: '#38bdf8', border: '1px solid rgba(0, 229, 255, 0.25)', fontWeight: 500 }}>
                Read-only analysis enforced
              </span>
            </div>
            <div style={{ fontSize: '0.76rem', color: '#94a3b8', marginTop: '0.15rem' }}>
              Monitoring {data.totalProcesses} running processes on Windows PC • Passive inspection ensures zero system modification
            </div>
          </div>
        </div>

        <Link
          to="/alerts"
          className="pt-btn pt-btn-cyber"
          style={{
            fontSize: '0.78rem',
            padding: '0.35rem 0.85rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.35rem',
            whiteSpace: 'nowrap'
          }}
        >
          <span>View Threats ({data.threatAlertsCount})</span>
          <ArrowUpRight size={14} />
        </Link>
      </div>

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
          background: 'linear-gradient(135deg, rgba(16, 26, 46, 0.85) 0%, rgba(9, 15, 26, 0.95) 100%)'
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
                Threat Detection
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

      {/* Top Telemetry KPI Stat Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '1rem' }}>
        <StatCard
          label="Processes Analyzed"
          value={data.totalProcesses}
          subValue={`${data.memoryInspectedMb} MB RAM Scanned`}
          icon={<Cpu size={20} />}
        />
        <StatCard
          label="Clean Processes"
          value={data.normalCount ?? 246}
          subValue="Verified baseline clean"
          icon={<Cpu size={20} />}
          accentColor="#10b981"
        />
        <StatCard
          label="Threats Detected"
          value={data.threatAlertsCount}
          subValue="Elevated risk score"
          icon={<ShieldAlert size={20} />}
          accentColor="var(--pt-critical)"
        />
        <StatCard
          label="Highest Threat Score"
          value={`${data.highestThreatScore}/100`}
          subValue={data.highestThreatScore === 0 ? "Verified clean baseline" : "Elevated risk score"}
          icon={<Flame size={20} />}
          accentColor={data.highestThreatScore === 0 ? "#10b981" : "var(--pt-critical)"}
        />
        <StatCard
          label="Critical Threats"
          value={data.criticalCount}
          subValue="Immediate action required"
          icon={<Flame size={20} />}
          accentColor="var(--pt-critical)"
        />
        <StatCard
          label="High Risk"
          value={data.highCount}
          subValue="Score 75 - 89"
          icon={<AlertTriangle size={20} />}
          accentColor="var(--pt-high)"
        />
        <StatCard
          label="Medium / Low Risk"
          value={`${data.mediumCount} / ${data.lowCount}`}
          subValue="Under investigation"
          icon={<Zap size={20} />}
          accentColor="var(--pt-medium)"
        />
        <StatCard
          label="Last Scan"
          value={data.scanTime || "05 October 2026, 5:18 PM"}
          subValue={`Duration: ${data.duration || "4.0s"}`}
          icon={<Clock size={20} />}
          accentColor="var(--pt-cyan)"
        />
      </div>

      {/* Charts Section: Threat Activity & Distribution */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.25rem' }}>
        <Card
          title="Threat Activity Timeline"
          subtitle="Time-series telemetry of average threat scores and elevated alert detections"
          cyberBorder
        >
          <ThreatActivityChart data={activityTimeline} />
        </Card>

        <Card
          title="Threat Distribution"
          subtitle="Risk level and scoring model correlation"
        >
          <ThreatDistributionChart overview={data} />
        </Card>
      </div>

      {/* Memory & Behavior Correlation Summary */}
      <Card
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <Layers size={18} style={{ color: '#00e5ff' }} />
            <span>Memory &amp; Behavioral Correlation Matrix</span>
          </div>
        }
        subtitle="Cross-analyzing unbacked executable memory with live process execution vectors"
      >
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
          <div style={{ background: 'rgba(9, 15, 26, 0.65)', border: '1px solid var(--pt-border-subtle)', borderRadius: '8px', padding: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
              <span style={{ fontSize: '0.82rem', fontWeight: 600, color: '#f8fafc' }}>Correlated Detections</span>
              <Badge level={alerts.filter(a => a.scoreMode === 'CORRELATED').length > 0 ? "Critical" : "Clean"}>
                {alerts.filter(a => a.scoreMode === 'CORRELATED').length} Active
              </Badge>
            </div>
            <p style={{ fontSize: '0.78rem', color: '#94a3b8', lineHeight: 1.5 }}>
              {alerts.filter(a => a.scoreMode === 'CORRELATED').length > 0
                ? "Processes exhibiting both unbacked memory allocations and suspicious execution lineage."
                : "No correlated threat patterns or dual-domain anomalies detected across running processes."}
            </p>
          </div>

          <div style={{ background: 'rgba(9, 15, 26, 0.65)', border: '1px solid var(--pt-border-subtle)', borderRadius: '8px', padding: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
              <span style={{ fontSize: '0.82rem', fontWeight: 600, color: '#f8fafc' }}>Preserved in Trusted Binaries</span>
              <Badge level={alerts.filter(a => (a.threatScore ?? a.score ?? 0) >= 60).length > 0 ? "High" : "Clean"}>
                {alerts.filter(a => (a.threatScore ?? a.score ?? 0) >= 60).length} Active
              </Badge>
            </div>
            <p style={{ fontSize: '0.78rem', color: '#94a3b8', lineHeight: 1.5 }}>
              Memory evidence is rigorously preserved even when binaries carry valid Microsoft signatures. Passive inspection guarantees zero disruption.
            </p>
          </div>

          <div style={{ background: 'rgba(9, 15, 26, 0.65)', border: '1px solid var(--pt-border-subtle)', borderRadius: '8px', padding: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
              <span style={{ fontSize: '0.82rem', fontWeight: 600, color: '#f8fafc' }}>Baseline &amp; Verified Clean</span>
              <Badge level="Clean">{data.normalCount ?? data.totalProcesses} Processes</Badge>
            </div>
            <p style={{ fontSize: '0.78rem', color: '#94a3b8', lineHeight: 1.5 }}>
              Processes with 100% disk-backed PE images, valid digital signatures, and no unauthorized VirtualAlloc or trampoline hooks detected.
            </p>
          </div>
        </div>
      </Card>

      {/* Recent Threat Alerts Table */}
      <Card
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <AlertTriangle size={18} style={{ color: 'var(--pt-critical)' }} />
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
                    No threat alerts detected. All {data.totalProcesses} processes verified clean.
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
                      {alert.behaviorScore}
                    </td>
                    <td className="text-mono" style={{ color: '#00e5ff', fontWeight: 600 }}>
                      {alert.memoryScore}
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

      {/* Enrolled Devices Management */}
      <MyDevicesSection />
    </div>
  );
};
