import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search,
  ExternalLink,
  ArrowUpDown,
  Lock,
  Globe,
  Cpu,
  Layers,
  AlertCircle
} from 'lucide-react';
import { dataService } from '../services';
import { Badge } from '../components/common/Badge';
import { ScorePill } from '../components/common/ScorePill';
import { Card } from '../components/common/Card';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import { EmptyState } from '../components/common/EmptyState';
import type { UnifiedThreatAlert } from '../types';

export const ThreatAlertsPage: React.FC = () => {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState<UnifiedThreatAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function loadAlerts() {
      try {
        setLoading(true);
        setError(null);
        let result: UnifiedThreatAlert[] = [];
        if (dataService.getUnifiedThreatAlerts) {
          result = await dataService.getUnifiedThreatAlerts();
        } else {
          const raw = await dataService.getThreatAlerts();
          result = raw.map((a) => ({
            id: a.id,
            vector: 'ENDPOINT_MEMORY',
            title: a.title || `Memory Threat: ${a.processName} (PID ${a.pid})`,
            targetName: a.processName,
            targetDetail: `PID ${a.pid}`,
            level: a.level,
            score: a.score,
            status: ((a.status as unknown) as 'NEW') || 'NEW',
            timestamp: a.detectedAt || new Date().toISOString(),
            indicators: [
              ...(a.memoryEvidence?.indicators || []),
              ...(a.behaviorEvidence?.indicators || []),
            ],
            explanation: a.description,
            rawAlert: a,
          }));
        }

        if (!cancelled) {
          setAlerts(result);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Unable to load unified threat alerts.');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadAlerts();

    return () => {
      cancelled = true;
    };
  }, []);

  const [searchTerm, setSearchTerm] = useState('');
  const [vectorFilter, setVectorFilter] = useState<'ALL' | 'ENDPOINT_MEMORY' | 'WEB_THREAT'>('ALL');
  const [levelFilter, setLevelFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [sortField, setSortField] = useState<'score' | 'targetName' | 'timestamp'>('score');
  const [sortAsc, setSortAsc] = useState(false);

  const memoryCount = alerts.filter((a) => a.vector === 'ENDPOINT_MEMORY').length;
  const webCount = alerts.filter((a) => a.vector === 'WEB_THREAT').length;

  const filteredAlerts = useMemo(() => {
    return alerts
      .filter((alert) => {
        const matchesVector = vectorFilter === 'ALL' || alert.vector === vectorFilter;

        const target = alert.targetName || '';
        const detail = alert.targetDetail || '';
        const expl = alert.explanation || '';
        const indStr = alert.indicators?.join(' ') || '';

        const matchesSearch =
          target.toLowerCase().includes(searchTerm.toLowerCase()) ||
          detail.toLowerCase().includes(searchTerm.toLowerCase()) ||
          expl.toLowerCase().includes(searchTerm.toLowerCase()) ||
          indStr.toLowerCase().includes(searchTerm.toLowerCase()) ||
          alert.id.toLowerCase().includes(searchTerm.toLowerCase());

        const matchesLevel =
          levelFilter === 'ALL' ||
          String(alert.level).toUpperCase() === levelFilter.toUpperCase();

        const matchesStatus =
          statusFilter === 'ALL' ||
          String(alert.status).toUpperCase() === statusFilter.toUpperCase();

        return matchesVector && matchesSearch && matchesLevel && matchesStatus;
      })
      .sort((a, b) => {
        if (sortField === 'score') {
          return sortAsc ? a.score - b.score : b.score - a.score;
        }
        if (sortField === 'targetName') {
          return sortAsc ? a.targetName.localeCompare(b.targetName) : b.targetName.localeCompare(a.targetName);
        }
        if (sortField === 'timestamp') {
          return sortAsc
            ? new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
            : new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
        }
        return 0;
      });
  }, [alerts, searchTerm, vectorFilter, levelFilter, statusFilter, sortField, sortAsc]);

  const toggleSort = (field: 'score' | 'targetName' | 'timestamp') => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  if (loading && alerts.length === 0) {
    return (
      <LoadingSpinner
        label="Loading PhantomTrace Unified Threat Telemetry..."
        size="lg"
        fullHeight
      />
    );
  }

  if (error && alerts.length === 0) {
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
          Unable to Load Threat Alerts
        </h3>
        <p style={{ color: 'var(--pt-text-secondary)', marginBottom: '1.5rem', maxWidth: '480px', margin: '0 auto 1.5rem auto' }}>
          {error}
        </p>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header Info Banner */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <h2 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.01em', margin: 0 }}>
              Unified Threat Alerts
            </h2>
            <Badge level="critical" size="sm">
              Live Triage
            </Badge>
          </div>
          <p style={{ fontSize: '0.82rem', color: 'var(--pt-text-muted)', marginTop: '0.2rem' }}>
            Correlated triage stream combining Endpoint Memory anomalies and Web Threat Monitor detections
          </p>
        </div>

        {/* Read-Only Safety Assurance */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(0, 209, 255, 0.08)', border: '1px solid var(--pt-border-cyan)', padding: '0.4rem 0.85rem', borderRadius: '6px', fontSize: '0.78rem', color: '#38bdf8' }}>
          <Lock size={14} className="text-cyan" />
          <span>Non-destructive inspection &bull; Read-only evidence preservation</span>
        </div>
      </div>

      {/* Vector Selection Tabs */}
      <div
        style={{
          display: 'flex',
          gap: '0.5rem',
          borderBottom: '1px solid var(--pt-border-subtle)',
          paddingBottom: '0.5rem',
          flexWrap: 'wrap'
        }}
      >
        <button
          type="button"
          onClick={() => setVectorFilter('ALL')}
          style={{
            padding: '0.45rem 1rem',
            borderRadius: '6px',
            fontSize: '0.82rem',
            fontWeight: 600,
            cursor: 'pointer',
            border: vectorFilter === 'ALL' ? '1px solid var(--pt-border-cyan)' : '1px solid transparent',
            background: vectorFilter === 'ALL' ? 'rgba(0, 209, 255, 0.12)' : 'transparent',
            color: vectorFilter === 'ALL' ? 'var(--pt-cyan)' : 'var(--pt-text-muted)',
            display: 'flex',
            alignItems: 'center',
            gap: '0.45rem',
            transition: 'all 0.15s ease'
          }}
        >
          <Layers size={14} />
          <span>All Threat Vectors ({alerts.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setVectorFilter('ENDPOINT_MEMORY')}
          style={{
            padding: '0.45rem 1rem',
            borderRadius: '6px',
            fontSize: '0.82rem',
            fontWeight: 600,
            cursor: 'pointer',
            border: vectorFilter === 'ENDPOINT_MEMORY' ? '1px solid rgba(6, 182, 212, 0.4)' : '1px solid transparent',
            background: vectorFilter === 'ENDPOINT_MEMORY' ? 'rgba(6, 182, 212, 0.15)' : 'transparent',
            color: vectorFilter === 'ENDPOINT_MEMORY' ? '#38bdf8' : 'var(--pt-text-muted)',
            display: 'flex',
            alignItems: 'center',
            gap: '0.45rem',
            transition: 'all 0.15s ease'
          }}
        >
          <Cpu size={14} />
          <span>Endpoint Memory ({memoryCount})</span>
        </button>

        <button
          type="button"
          onClick={() => setVectorFilter('WEB_THREAT')}
          style={{
            padding: '0.45rem 1rem',
            borderRadius: '6px',
            fontSize: '0.82rem',
            fontWeight: 600,
            cursor: 'pointer',
            border: vectorFilter === 'WEB_THREAT' ? '1px solid rgba(168, 85, 247, 0.4)' : '1px solid transparent',
            background: vectorFilter === 'WEB_THREAT' ? 'rgba(168, 85, 247, 0.15)' : 'transparent',
            color: vectorFilter === 'WEB_THREAT' ? '#c084fc' : 'var(--pt-text-muted)',
            display: 'flex',
            alignItems: 'center',
            gap: '0.45rem',
            transition: 'all 0.15s ease'
          }}
        >
          <Globe size={14} />
          <span>Web Threat Monitor ({webCount})</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div
        className="pt-card"
        style={{
          padding: '1rem 1.25rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '1rem',
          flexWrap: 'wrap',
        }}
      >
        {/* Search Input */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: 1, minWidth: '240px' }}>
          <Search size={16} style={{ color: 'var(--pt-text-muted)' }} />
          <input
            type="text"
            placeholder="Search by target domain, process PID, indicators, or keyword..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pt-input"
            style={{ width: '100%' }}
          />
        </div>

        {/* Level Filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.78rem', color: 'var(--pt-text-muted)', fontWeight: 600 }}>Severity:</span>
          <select
            value={levelFilter}
            onChange={(e) => setLevelFilter(e.target.value)}
            className="pt-select"
            style={{ minWidth: '130px' }}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="NORMAL">Normal</option>
          </select>
        </div>

        {/* Status Filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.78rem', color: 'var(--pt-text-muted)', fontWeight: 600 }}>Status:</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="pt-select"
            style={{ minWidth: '130px' }}
          >
            <option value="ALL">All Statuses</option>
            <option value="NEW">New</option>
            <option value="ACTIVE">Active</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="RESOLVED">Resolved</option>
            <option value="DISMISSED">Dismissed</option>
          </select>
        </div>

        {/* Reset */}
        {(searchTerm || levelFilter !== 'ALL' || statusFilter !== 'ALL' || vectorFilter !== 'ALL') && (
          <button
            type="button"
            onClick={() => {
              setSearchTerm('');
              setLevelFilter('ALL');
              setStatusFilter('ALL');
              setVectorFilter('ALL');
            }}
            className="pt-btn pt-btn-secondary pt-btn-sm"
          >
            Reset Filters
          </button>
        )}
      </div>

      {/* Threat Alerts Table */}
      <Card>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem', fontSize: '0.8rem', color: 'var(--pt-text-muted)' }}>
          <span>Showing <strong>{filteredAlerts.length}</strong> matching threat alerts</span>
          <span>Click any row or Triage button to inspect forensic evidence</span>
        </div>

        <div className="pt-table-container">
          <table className="pt-table">
            <thead>
              <tr>
                <th style={{ width: '120px' }}>Vector</th>
                <th onClick={() => toggleSort('targetName')} style={{ cursor: 'pointer' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                    <span>Target &amp; Origin</span>
                    <ArrowUpDown size={12} />
                  </div>
                </th>
                <th onClick={() => toggleSort('score')} style={{ cursor: 'pointer', width: '110px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                    <span>Threat Score</span>
                    <ArrowUpDown size={12} />
                  </div>
                </th>
                <th style={{ width: '110px' }}>Severity</th>
                <th style={{ width: '130px' }}>Status</th>
                <th>Observed Evidence Indicators</th>
                <th onClick={() => toggleSort('timestamp')} style={{ cursor: 'pointer', width: '120px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                    <span>Detected</span>
                    <ArrowUpDown size={12} />
                  </div>
                </th>
                <th style={{ width: '100px', textAlign: 'right' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ padding: '2rem 1rem' }}>
                    <EmptyState
                      variant="info"
                      title="No threat alerts matching selected filters"
                      description="Try adjusting your search terms, vector filter, or severity filters to view additional security findings."
                    />
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => {
                  const isMemory = alert.vector === 'ENDPOINT_MEMORY';
                  return (
                    <tr
                      key={alert.id}
                      onClick={() => navigate(`/alerts/${alert.id}`)}
                      className="clickable-row"
                    >
                      {/* Vector Column */}
                      <td>
                        <span
                          style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.3rem',
                            fontSize: '0.72rem',
                            fontWeight: 700,
                            padding: '0.2rem 0.55rem',
                            borderRadius: '4px',
                            background: isMemory ? 'rgba(6, 182, 212, 0.15)' : 'rgba(168, 85, 247, 0.15)',
                            color: isMemory ? '#38bdf8' : '#c084fc',
                            border: `1px solid ${isMemory ? 'rgba(6, 182, 212, 0.3)' : 'rgba(168, 85, 247, 0.3)'}`,
                            letterSpacing: '0.5px',
                          }}
                        >
                          {isMemory ? <Cpu size={12} /> : <Globe size={12} />}
                          <span>{isMemory ? 'MEMORY' : 'WEB'}</span>
                        </span>
                      </td>

                      {/* Target Column */}
                      <td>
                        <div>
                          <div style={{ fontWeight: 600, color: '#ffffff', fontFamily: isMemory ? 'var(--font-mono)' : 'inherit' }}>
                            {alert.targetName}
                          </div>
                          <div style={{ fontSize: '0.74rem', color: 'var(--pt-text-muted)', marginTop: '1px' }}>
                            {alert.targetDetail}
                            {alert.correlatedProcess && (
                              <span
                                style={{ color: 'var(--pt-cyan)', marginLeft: '0.4rem', cursor: 'help' }}
                                title="Heuristic correlation: Active browser process was identified in endpoint telemetry during scan window. Does not constitute proof that this process executed the URL."
                              >
                                &bull; Correlated: {alert.correlatedProcess.name} (PID {alert.correlatedProcess.pid})
                              </span>
                            )}
                          </div>
                        </div>
                      </td>

                      {/* Score Column */}
                      <td>
                        <ScorePill score={alert.score} />
                      </td>

                      {/* Level Column */}
                      <td>
                        <Badge level={alert.level}>{alert.level}</Badge>
                      </td>

                      {/* Status Column */}
                      <td>
                        <span
                          style={{
                            fontSize: '0.72rem',
                            fontWeight: 600,
                            padding: '0.15rem 0.45rem',
                            borderRadius: '4px',
                            background:
                              alert.status === 'RESOLVED'
                                ? 'var(--pt-clean-bg)'
                                : alert.status === 'INVESTIGATING'
                                ? 'var(--pt-medium-bg)'
                                : alert.status === 'DISMISSED'
                                ? 'rgba(148, 163, 184, 0.15)'
                                : 'var(--pt-critical-bg)',
                            color:
                              alert.status === 'RESOLVED'
                                ? 'var(--pt-status-clean)'
                                : alert.status === 'INVESTIGATING'
                                ? 'var(--pt-status-warning)'
                                : alert.status === 'DISMISSED'
                                ? 'var(--pt-text-muted)'
                                : 'var(--pt-status-critical)',
                            border: `1px solid ${
                              alert.status === 'RESOLVED'
                                ? 'var(--pt-clean-border)'
                                : alert.status === 'INVESTIGATING'
                                ? 'var(--pt-medium-border)'
                                : alert.status === 'DISMISSED'
                                ? 'var(--pt-border-subtle)'
                                : 'var(--pt-critical-border)'
                            }`
                          }}
                        >
                          {alert.status || 'NEW'}
                        </span>
                      </td>

                      {/* Indicators Column */}
                      <td>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                          {alert.indicators && alert.indicators.length > 0 ? (
                            alert.indicators.slice(0, 3).map((ind, i) => (
                              <span
                                key={i}
                                style={{
                                  fontSize: '0.7rem',
                                  padding: '0.15rem 0.45rem',
                                  background: 'rgba(255, 255, 255, 0.05)',
                                  border: '1px solid var(--pt-border-subtle)',
                                  borderRadius: '3px',
                                  color: 'var(--pt-text-secondary)',
                                }}
                              >
                                {ind}
                              </span>
                            ))
                          ) : (
                            <span style={{ fontSize: '0.75rem', color: 'var(--pt-text-muted)' }}>None</span>
                          )}
                          {alert.indicators && alert.indicators.length > 3 && (
                            <span style={{ fontSize: '0.7rem', color: 'var(--pt-text-muted)' }}>
                              +{alert.indicators.length - 3} more
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Detected Column */}
                      <td style={{ fontSize: '0.75rem', color: 'var(--pt-text-muted)' }}>
                        {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Recent'}
                      </td>

                      {/* Action Column */}
                      <td style={{ textAlign: 'right' }}>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/alerts/${alert.id}`);
                          }}
                          className="pt-btn pt-btn-secondary pt-btn-sm"
                        >
                          <span>Triage</span>
                          <ExternalLink size={12} />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};

export default ThreatAlertsPage;
