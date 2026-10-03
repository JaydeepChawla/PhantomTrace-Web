import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Search, 
  ExternalLink, 
  ArrowUpDown,
  Lock
} from 'lucide-react';
import { dataService } from '../services';
import { Badge } from '../components/common/Badge';
import { ScorePill } from '../components/common/ScorePill';
import { Card } from '../components/common/Card';
import type { ThreatAlert, ThreatLevel, ScoreMode } from '../types';

export const ThreatAlertsPage: React.FC = () => {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function loadAlerts() {
      try {
        setLoading(true);
        setError(null);
        const result = await dataService.getThreatAlerts();
        if (!cancelled) {
          setAlerts(result);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Unable to load threat alerts.');
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
  const [levelFilter, setLevelFilter] = useState<string>('ALL');
  const [modeFilter, setModeFilter] = useState<string>('ALL');
  const [sortField, setSortField] = useState<'threatScore' | 'pid' | 'process'>('threatScore');
  const [sortAsc, setSortAsc] = useState(false);

  const filteredAlerts = useMemo(() => {
    return alerts
      .filter((alert) => {
        const procName = alert.process || alert.processName || '';
        const memStr = typeof alert.memoryEvidence === 'string'
          ? alert.memoryEvidence
          : alert.memoryEvidence?.details?.join(' ') || alert.memoryEvidence?.indicators?.join(' ') || '';
        const correlationStr = alert.correlation || '';

        const matchesSearch = 
          procName.toLowerCase().includes(searchTerm.toLowerCase()) ||
          alert.pid.toString().includes(searchTerm) ||
          memStr.toLowerCase().includes(searchTerm.toLowerCase()) ||
          correlationStr.toLowerCase().includes(searchTerm.toLowerCase());

        const matchesLevel = levelFilter === 'ALL' || (alert.level as string) === levelFilter || alert.threatLevel === levelFilter;
        const matchesMode = modeFilter === 'ALL' || (alert.scoreMode as string) === modeFilter;

        return matchesSearch && matchesLevel && matchesMode;
      })
      .sort((a, b) => {
        const valA = a[sortField] ?? (sortField === 'threatScore' ? a.score : sortField === 'process' ? a.processName : a.pid);
        const valB = b[sortField] ?? (sortField === 'threatScore' ? b.score : sortField === 'process' ? b.processName : b.pid);
        if (typeof valA === 'string') {
          return sortAsc ? valA.localeCompare(valB as string) : (valB as string).localeCompare(valA);
        }
        return sortAsc ? (valA as number) - (valB as number) : (valB as number) - (valA as number);
      });
  }, [alerts, searchTerm, levelFilter, modeFilter, sortField, sortAsc]);

  const toggleSort = (field: 'threatScore' | 'pid' | 'process') => {
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
        Loading PhantomTrace data...
      </div>
    );
  }

  if (error && alerts.length === 0) {
    return (
      <div style={{ padding: '2rem', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', borderRadius: '8px', color: '#fca5a5', textAlign: 'center' }}>
        Unable to load PhantomTrace data.
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Header Info Banner */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.01em' }}>
            Elevated Threat Alerts
          </h2>
          <p style={{ fontSize: '0.82rem', color: '#94a3b8', marginTop: '0.2rem' }}>
            Search and filter memory anomalies, behavioral indicators, and correlated execution vectors
          </p>
        </div>

        {/* Read-Only Safety Assurance */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(0, 229, 255, 0.08)', border: '1px solid rgba(0, 229, 255, 0.25)', padding: '0.4rem 0.85rem', borderRadius: '6px', fontSize: '0.78rem', color: '#38bdf8' }}>
          <Lock size={14} style={{ color: '#00e5ff' }} />
          <span>Non-destructive inspection • Read-only telemetry</span>
        </div>
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
          flexWrap: 'wrap'
        }}
      >
        {/* Search Input */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: 1, minWidth: '240px' }}>
          <Search size={16} style={{ color: '#64748b' }} />
          <input
            type="text"
            placeholder="Search by PID, process name, evidence keyword..."
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
            onChange={(e) => setLevelFilter(e.target.value as ThreatLevel | 'ALL')}
            className="pt-select"
          >
            <option value="ALL">All Severities ({alerts.length})</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>

        {/* Score Mode Filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 600 }}>Score Mode:</span>
          <select 
            value={modeFilter} 
            onChange={(e) => setModeFilter(e.target.value as ScoreMode | 'ALL')}
            className="pt-select"
          >
            <option value="ALL">All Modes</option>
            <option value="Correlated">Correlated (Mem + Beh)</option>
            <option value="Memory Only">Memory Only</option>
            <option value="Behavior Only">Behavior Only</option>
            <option value="Baseline">Baseline</option>
          </select>
        </div>

        {/* Reset */}
        {(searchTerm || levelFilter !== 'ALL' || modeFilter !== 'ALL') && (
          <button
            onClick={() => {
              setSearchTerm('');
              setLevelFilter('ALL');
              setModeFilter('ALL');
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
          <span>Click any row to open full alert investigation &amp; response workflow</span>
        </div>

        <div className="pt-table-container">
          <table className="pt-table">
            <thead>
              <tr>
                <th onClick={() => toggleSort('pid')} style={{ cursor: 'pointer' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                    <span>PID</span>
                    <ArrowUpDown size={12} />
                  </div>
                </th>
                <th onClick={() => toggleSort('process')} style={{ cursor: 'pointer' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                    <span>Process</span>
                    <ArrowUpDown size={12} />
                  </div>
                </th>
                <th onClick={() => toggleSort('threatScore')} style={{ cursor: 'pointer' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                    <span>Threat Score</span>
                    <ArrowUpDown size={12} />
                  </div>
                </th>
                <th>Threat Level</th>
                <th>Status</th>
                <th>Application</th>
                <th>Score Mode</th>
                <th>Behavior</th>
                <th>Memory</th>
                <th>Correlation</th>
                <th>Memory Evidence</th>
                <th>Timestamp</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={13} style={{ textAlign: 'center', padding: '2.5rem', color: '#64748b' }}>
                    No threat alerts matched the current search and filter criteria.
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => (
                  <tr
                    key={alert.id}
                    className="clickable-row"
                    onClick={() => navigate(`/alerts/${alert.id}`)}
                  >
                    <td className="text-mono" style={{ fontWeight: 700, color: '#00e5ff' }}>
                      {alert.pid}
                    </td>
                    <td style={{ fontWeight: 600, color: '#ffffff' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <span>{alert.process || alert.processName}</span>
                        <ExternalLink size={12} style={{ color: '#64748b' }} />
                      </div>
                    </td>
                    <td>
                      <ScorePill score={alert.threatScore ?? alert.score} />
                    </td>
                    <td>
                      <Badge level={alert.threatLevel}>{alert.threatLevel}</Badge>
                    </td>
                    <td>
                      <Badge level={alert.status === 'INVESTIGATING' ? 'High' : alert.status === 'RESOLVED' ? 'Clean' : 'neutral'}>
                        {alert.status || 'NEW'}
                      </Badge>
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
                    <td style={{ fontSize: '0.78rem', color: '#cbd5e1', maxWidth: '180px' }}>
                      {alert.correlation}
                    </td>
                    <td style={{ fontSize: '0.78rem', color: '#94a3b8', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {typeof alert.memoryEvidence === 'string'
                        ? alert.memoryEvidence
                        : alert.memoryEvidence?.details?.[0] || alert.memoryEvidence?.indicators?.[0] || 'None'}
                    </td>
                    <td className="text-mono" style={{ fontSize: '0.74rem', color: '#64748b', whiteSpace: 'nowrap' }}>
                      {alert.timestamp || alert.detectedAt}
                    </td>
                    <td>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/alerts/${alert.id}`);
                        }}
                        className="pt-btn pt-btn-cyber"
                        style={{ padding: '0.25rem 0.65rem', fontSize: '0.72rem' }}
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
    </div>
  );
};
