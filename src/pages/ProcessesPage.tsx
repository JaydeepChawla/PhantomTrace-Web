import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search,
  ArrowUpDown,
  Lock
} from 'lucide-react';
import { dataService } from '../services';
import { Badge } from '../components/common/Badge';
import { ScorePill } from '../components/common/ScorePill';
import { Card } from '../components/common/Card';
import type { Process } from '../types';

export const ProcessesPage: React.FC = () => {
  const navigate = useNavigate();
  const [processes, setProcesses] = useState<Process[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function loadProcesses() {
      try {
        setLoading(true);
        setError(null);
        const result = await dataService.getProcesses();
        if (!cancelled) {
          setProcesses(result);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Unable to load PhantomTrace data.");
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadProcesses();

    return () => {
      cancelled = true;
    };
  }, []);

  const [searchTerm, setSearchTerm] = useState('');
  const [levelFilter, setLevelFilter] = useState<string>('ALL');
  const [sortField, setSortField] = useState<'threatScore' | 'pid' | 'name'>('threatScore');
  const [sortAsc, setSortAsc] = useState(false);

  const filteredProcesses = useMemo(() => {
    return processes
      .filter((p) => {
        const pPath = p.path || p.executablePath || '';
        const pUser = p.userContext || '';
        const pCmd = p.commandLine || '';
        const matchesSearch =
          p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
          p.pid.toString().includes(searchTerm) ||
          pPath.toLowerCase().includes(searchTerm.toLowerCase()) ||
          pUser.toLowerCase().includes(searchTerm.toLowerCase()) ||
          pCmd.toLowerCase().includes(searchTerm.toLowerCase());

        const matchesLevel = levelFilter === 'ALL' || (p.threatLevel as string) === levelFilter || (p.threatLevel as string).toUpperCase() === levelFilter.toUpperCase();
        return matchesSearch && matchesLevel;
      })
      .sort((a, b) => {
        let valA = a[sortField];
        let valB = b[sortField];
        if (typeof valA === 'string') {
          return sortAsc ? valA.localeCompare(valB as string) : (valB as string).localeCompare(valA);
        }
        return sortAsc ? (valA as number) - (valB as number) : (valB as number) - (valA as number);
      });
  }, [processes, searchTerm, levelFilter, sortField, sortAsc]);

  const toggleSort = (field: 'threatScore' | 'pid' | 'name') => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  if (loading && processes.length === 0) {
    return (
      <div style={{ padding: '3rem', textAlign: 'center', color: '#94a3b8' }}>
        Loading PhantomTrace data...
      </div>
    );
  }

  if (error && processes.length === 0) {
    return (
      <div style={{ padding: '2rem', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', borderRadius: '8px', color: '#fca5a5', textAlign: 'center' }}>
        Unable to load PhantomTrace data.
      </div>
    );
  }

  if (!loading && !error && processes.length === 0) {
    return (
      <div style={{ padding: '3rem', textAlign: 'center', color: '#94a3b8' }}>
        No scan data available.
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Page Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.02em', display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <span>Active Process Explorer</span>
            <span style={{ fontSize: '0.75rem', fontWeight: 500, padding: '0.15rem 0.5rem', background: 'rgba(0, 229, 255, 0.1)', color: '#00e5ff', borderRadius: '4px', border: '1px solid rgba(0, 229, 255, 0.3)' }}>
              LIVE HOST TELEMETRY
            </span>
          </h2>
          <p style={{ fontSize: '0.84rem', color: '#94a3b8', marginTop: '0.2rem' }}>
            Enumerated running Windows binaries evaluated via read-only memory heuristics and MITRE behavioral telemetry.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.78rem', color: '#64748b' }}>
          <Lock size={14} style={{ color: '#00e5ff' }} />
          <span>Kernel Read-Only Enforced</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'center', background: 'var(--pt-bg-surface)', padding: '0.85rem 1.15rem', borderRadius: '8px', border: '1px solid var(--pt-border-subtle)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: '1 1 280px', position: 'relative' }}>
          <Search size={16} style={{ position: 'absolute', left: '0.75rem', color: '#64748b' }} />
          <input
            type="text"
            placeholder="Search by PID, Process Name, Path, or Command Line..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pt-input"
            style={{ paddingLeft: '2.25rem', width: '100%' }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 600 }}>Severity:</span>
          <select
            value={levelFilter}
            onChange={(e) => setLevelFilter(e.target.value)}
            className="pt-select"
          >
            <option value="ALL">All Levels ({processes.length})</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Clean">Clean</option>
          </select>
        </div>

        {(searchTerm || levelFilter !== 'ALL') && (
          <button
            onClick={() => {
              setSearchTerm('');
              setLevelFilter('ALL');
            }}
            className="pt-btn pt-btn-secondary"
            style={{ padding: '0.45rem 0.85rem', fontSize: '0.78rem' }}
          >
            Reset Filters
          </button>
        )}
      </div>

      {/* Process Table Card */}
      <Card>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem', fontSize: '0.8rem', color: '#94a3b8' }}>
          <span>Showing <strong>{filteredProcesses.length}</strong> matching processes</span>
          <span>Click any process to view full memory evidence &amp; response guidance</span>
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
                <th onClick={() => toggleSort('name')} style={{ cursor: 'pointer' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                    <span>Process Name</span>
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
                <th>Classification</th>
                <th>Parent PID</th>
                <th>Memory Evidence</th>
                <th>Behavior Signals</th>
                <th>User Context</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredProcesses.map((proc) => (
                <tr
                  key={proc.pid}
                  className="clickable-row"
                  onClick={() => navigate(`/processes/${proc.pid}`)}
                >
                  <td className="text-mono" style={{ fontWeight: 700, color: '#00e5ff' }}>
                    {proc.pid}
                  </td>
                  <td style={{ fontWeight: 600, color: '#ffffff' }}>
                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                      <span>{proc.name}</span>
                      <span style={{ fontSize: '0.7rem', color: '#64748b', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {proc.path || proc.executablePath}
                      </span>
                    </div>
                  </td>
                  <td>
                    <ScorePill score={proc.threatScore} />
                  </td>
                  <td>
                    <Badge level={proc.threatLevel}>{proc.threatLevel}</Badge>
                  </td>
                  <td>
                    <Badge level="neutral">{proc.application || proc.applicationName || 'Unclassified'}</Badge>
                  </td>
                  <td className="text-mono" style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
                    {proc.parentPid} ({proc.parentName})
                  </td>
                  <td style={{ textAlign: 'center' }}>
                    <span
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.78rem',
                        color: (proc.memoryEvidenceCount ?? 0) > 0 ? '#00e5ff' : '#64748b',
                        fontWeight: (proc.memoryEvidenceCount ?? 0) > 0 ? 700 : 400
                      }}
                    >
                      {proc.memoryEvidenceCount ?? 0} items
                    </span>
                  </td>
                  <td style={{ textAlign: 'center' }}>
                    <span
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.78rem',
                        color: (proc.behaviorEvidenceCount ?? 0) > 0 ? '#f97316' : '#64748b',
                        fontWeight: (proc.behaviorEvidenceCount ?? 0) > 0 ? 700 : 400
                      }}
                    >
                      {proc.behaviorEvidenceCount ?? 0} signals
                    </span>
                  </td>
                  <td style={{ fontSize: '0.78rem', color: '#cbd5e1' }}>
                    {proc.userContext || 'SYSTEM'}
                  </td>
                  <td>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(`/processes/${proc.pid}`);
                      }}
                      className="pt-btn pt-btn-cyber"
                      style={{ padding: '0.25rem 0.6rem', fontSize: '0.72rem' }}
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};
