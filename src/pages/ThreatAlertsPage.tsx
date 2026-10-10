import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search,
  ExternalLink,
  ArrowUpDown,
  Lock,
  Globe,
  Cpu,
  Layers
} from 'lucide-react';
import { dataService } from '../services';
import { Badge } from '../components/common/Badge';
import { ScorePill } from '../components/common/ScorePill';
import { Card } from '../components/common/Card';
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
            status: (a.status as any) || 'NEW',
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
      <div style={{ padding: '3rem', textAlign: 'center', color: '#94a3b8' }}>
        Loading PhantomTrace Unified Threat Telemetry...
      </div>
    );
  }

  if (error && alerts.length === 0) {
    return (
      <div style={{ padding: '2rem', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', borderRadius: '8px', color: '#fca5a5', textAlign: 'center' }}>
        Unable to load PhantomTrace threat alerts: {error}
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header Info Banner */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <h2 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.01em', margin: 0 }}>
              Unified Threat Alerts
            </h2>
            <span
              style={{
                fontSize: '0.68rem',
                fontWeight: 700,
                padding: '0.15rem 0.5rem',
                borderRadius: '4px',
                background: 'rgba(6, 182, 212, 0.15)',
                color: '#38bdf8',
                border: '1px solid rgba(6, 182, 212, 0.3)',
              }}
            >
              PHASE 4 UNIFIED
            </span>
          </div>
          <p style={{ fontSize: '0.82rem', color: '#94a3b8', marginTop: '0.2rem' }}>
            Correlated triage stream combining Endpoint Memory anomalies and Web Threat Monitor detections
          </p>
        </div>

        {/* Read-Only Safety Assurance */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(0, 229, 255, 0.08)', border: '1px solid rgba(0, 229, 255, 0.25)', padding: '0.4rem 0.85rem', borderRadius: '6px', fontSize: '0.78rem', color: '#38bdf8' }}>
          <Lock size={14} style={{ color: '#00e5ff' }} />
          <span>Non-destructive inspection • Read-only evidence preservation</span>
        </div>
      </div>

      {/* Vector Selection Tabs */}
      <div
        style={{
          display: 'flex',
          gap: '0.5rem',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          paddingBottom: '0.5rem',
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
            border: 'none',
            background: vectorFilter === 'ALL' ? 'rgba(0, 229, 255, 0.15)' : 'transparent',
            color: vectorFilter === 'ALL' ? '#00e5ff' : '#94a3b8',
            display: 'flex',
            alignItems: 'center',
            gap: '0.45rem',
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
            border: 'none',
            background: vectorFilter === 'ENDPOINT_MEMORY' ? 'rgba(6, 182, 212, 0.2)' : 'transparent',
            color: vectorFilter === 'ENDPOINT_MEMORY' ? '#38bdf8' : '#94a3b8',
            display: 'flex',
            alignItems: 'center',
            gap: '0.45rem',
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
            border: 'none',
            background: vectorFilter === 'WEB_THREAT' ? 'rgba(168, 85, 247, 0.2)' : 'transparent',
            color: vectorFilter === 'WEB_THREAT' ? '#c084fc' : '#94a3b8',
            display: 'flex',
            alignItems: 'center',
            gap: '0.45rem',
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
          <Search size={16} style={{ color: '#64748b' }} />
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
          <span style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 600 }}>Severity:</span>
          <select
            value={levelFilter}
            onChange={(e) => setLevelFilter(e.target.value)}
            className="pt-select"
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
          <span style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 600 }}>Status:</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="pt-select"
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
            onClick={() => {
              setSearchTerm('');
              setLevelFilter('ALL');
              setStatusFilter('ALL');
              setVectorFilter('ALL');
            }}
            className="pt-btn pt-btn-secondary"
            style={{ padding: '0.45rem 0.85rem', fontSize: '0.78rem' }}
          >
            Reset Filters
          </button>
        )}
      </div>

      {/* Threat Alerts Table */}
      <Card>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem', fontSize: '0.8rem', color: '#94a3b8' }}>
          <span>Showing <strong>{filteredAlerts.length}</strong> matching threat alerts</span>
          <span>Click any row or Investigate button to triage forensic evidence</span>
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
                  <td colSpan={8} style={{ textAlign: 'center', padding: '2.5rem', color: '#94a3b8' }}>
                    No threat alerts matching selected filters.
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => {
                  const isMemory = alert.vector === 'ENDPOINT_MEMORY';
                  return (
                    <tr
                      key={alert.id}
                      onClick={() => navigate(`/alerts/${alert.id}`)}
                      style={{ cursor: 'pointer' }}
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
                          <div style={{ fontWeight: 600, color: '#ffffff', fontFamily: isMemory ? 'var(--font-mono)' : 'sans-serif' }}>
                            {alert.targetName}
                          </div>
                          <div style={{ fontSize: '0.74rem', color: '#94a3b8', marginTop: '1px' }}>
                            {alert.targetDetail}
                            {alert.correlatedProcess && (
                              <span
                                style={{ color: '#00e5ff', marginLeft: '0.4rem', cursor: 'help' }}
                                title="Heuristic correlation: Active browser process was identified in endpoint telemetry during scan window. Does not constitute proof that this process executed the URL."
                              >
                                • Correlated: {alert.correlatedProcess.name} (PID {alert.correlatedProcess.pid})
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
                                ? 'rgba(16, 185, 129, 0.15)'
                                : alert.status === 'INVESTIGATING'
                                ? 'rgba(245, 158, 11, 0.15)'
                                : alert.status === 'DISMISSED'
                                ? 'rgba(100, 116, 139, 0.15)'
                                : 'rgba(239, 68, 68, 0.15)',
                            color:
                              alert.status === 'RESOLVED'
                                ? '#34d399'
                                : alert.status === 'INVESTIGATING'
                                ? '#fbbf24'
                                : alert.status === 'DISMISSED'
                                ? '#94a3b8'
                                : '#f87171',
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
                                  border: '1px solid rgba(255, 255, 255, 0.1)',
                                  borderRadius: '3px',
                                  color: '#cbd5e1',
                                }}
                              >
                                {ind}
                              </span>
                            ))
                          ) : (
                            <span style={{ fontSize: '0.75rem', color: '#64748b' }}>None</span>
                          )}
                          {alert.indicators && alert.indicators.length > 3 && (
                            <span style={{ fontSize: '0.7rem', color: '#64748b' }}>
                              +{alert.indicators.length - 3} more
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Detected Column */}
                      <td style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
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
                          className="pt-btn pt-btn-secondary"
                          style={{ padding: '0.3rem 0.65rem', fontSize: '0.75rem', display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}
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
