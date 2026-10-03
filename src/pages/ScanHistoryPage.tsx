import React, { useState, useEffect } from 'react';
import { 
  Search, 
  Calendar, 
  Lock
} from 'lucide-react';
import { dataService } from '../services';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { ScorePill } from '../components/common/ScorePill';
import type { ScanHistory } from '../types';

export const ScanHistoryPage: React.FC = () => {
  const [history, setHistory] = useState<ScanHistory[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  useEffect(() => {
    let cancelled = false;

    async function loadHistory() {
      try {
        setLoading(true);
        setError(null);
        const result = await dataService.getScanHistory();
        if (!cancelled) {
          setHistory(result);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Unable to load scan history');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadHistory();

    return () => {
      cancelled = true;
    };
  }, []);

  const filteredHistory = history.filter((item) => {
    const dateStr = item.scanDate || item.startedAt || '';
    const idStr = item.id || '';
    const matchesSearch = 
      dateStr.toLowerCase().includes(searchTerm.toLowerCase()) ||
      idStr.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'ALL' || item.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const getStatusBadge = (status?: string) => {
    switch (status) {
      case 'Investigation Flags':
        return <Badge level="High">Investigation Flags</Badge>;
      case 'Verified Clean':
        return <Badge level="Clean">Verified Clean</Badge>;
      default:
        return <Badge level="neutral">Completed</Badge>;
    }
  };

  if (loading && history.length === 0) {
    return (
      <div style={{ padding: '3rem', textAlign: 'center', color: '#94a3b8' }}>
        Loading PhantomTrace data...
      </div>
    );
  }

  if (error && history.length === 0) {
    return (
      <div style={{ padding: '2rem', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', borderRadius: '8px', color: '#fca5a5', textAlign: 'center' }}>
        Unable to load PhantomTrace data.
      </div>
    );
  }

  if (!loading && !error && history.length === 0) {
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
          <h2 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.01em' }}>
            Historical Scan Cycles
          </h2>
          <p style={{ fontSize: '0.82rem', color: '#94a3b8', marginTop: '0.2rem' }}>
            Audit trail of scheduled and on-demand memory &amp; behavioral scan executions
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(0, 229, 255, 0.08)', border: '1px solid rgba(0, 229, 255, 0.25)', padding: '0.4rem 0.85rem', borderRadius: '6px', fontSize: '0.78rem', color: '#38bdf8' }}>
          <Lock size={14} style={{ color: '#00e5ff' }} />
          <span>Immutable Forensic Audit Log</span>
        </div>
      </div>

      {/* Filter Bar */}
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
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: 1, minWidth: '240px' }}>
          <Search size={16} style={{ color: '#64748b' }} />
          <input
            type="text"
            placeholder="Search by date or scan cycle ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pt-input"
            style={{ width: '100%' }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 600 }}>Status:</span>
          <select 
            value={statusFilter} 
            onChange={(e) => setStatusFilter(e.target.value)}
            className="pt-select"
          >
            <option value="ALL">All Statuses ({history.length})</option>
            <option value="Investigation Flags">Investigation Flags</option>
            <option value="Completed">Completed</option>
            <option value="Verified Clean">Verified Clean</option>
          </select>
        </div>
      </div>

      {/* Scan History Table */}
      <Card>
        <div className="pt-table-container">
          <table className="pt-table">
            <thead>
              <tr>
                <th>Scan Date</th>
                <th>Processes</th>
                <th>Alerts</th>
                <th>Critical</th>
                <th>High</th>
                <th>Medium</th>
                <th>Low</th>
                <th>Highest Score</th>
                <th>Duration</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredHistory.map((item) => (
                <tr key={item.id}>
                  <td className="text-mono" style={{ fontWeight: 600, color: '#ffffff' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <Calendar size={13} style={{ color: '#00e5ff' }} />
                      <span>{item.scanDate}</span>
                    </div>
                  </td>
                  <td className="text-mono" style={{ color: '#cbd5e1' }}>
                    {item.processes}
                  </td>
                  <td>
                    <span 
                      style={{ 
                        fontFamily: 'var(--font-mono)', 
                        fontWeight: 700, 
                        color: (item.alerts ?? item.totalAlerts ?? 0) > 0 ? '#ef4444' : '#10b981' 
                      }}
                    >
                      {item.alerts ?? item.totalAlerts ?? 0}
                    </span>
                  </td>
                  <td className="text-mono" style={{ color: (item.critical ?? 0) > 0 ? '#ef4444' : '#64748b' }}>
                    {item.critical ?? 0}
                  </td>
                  <td className="text-mono" style={{ color: (item.high ?? 0) > 0 ? '#f97316' : '#64748b' }}>
                    {item.high ?? 0}
                  </td>
                  <td className="text-mono" style={{ color: (item.medium ?? 0) > 0 ? '#eab308' : '#64748b' }}>
                    {item.medium ?? 0}
                  </td>
                  <td className="text-mono" style={{ color: (item.low ?? 0) > 0 ? '#00e5ff' : '#64748b' }}>
                    {item.low ?? 0}
                  </td>
                  <td>
                    <ScorePill score={item.highestScore ?? 0} size="sm" />
                  </td>
                  <td className="text-mono" style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
                    {item.duration || '0s'}
                  </td>
                  <td>
                    {getStatusBadge(item.status)}
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
