import React, { useState } from 'react';
import {
  Clock,
  Search,
  ShieldAlert,
  Globe,
  Sliders,
  CheckCircle,
  HardDrive,
  Info,
  ChevronLeft,
  ChevronRight,
  HelpCircle,
} from 'lucide-react';
import { Badge } from '../common/Badge';
import type { SecurityTimelineEvent, TimelineEventType } from '../../types';

interface SecurityEventTimelineProps {
  events: SecurityTimelineEvent[];
  total: number;
  loading: boolean;
  onFilterChange: (type?: string, severity?: string, limit?: number, offset?: number) => void;
}

export const SecurityEventTimeline: React.FC<SecurityEventTimelineProps> = ({
  events,
  total,
  loading,
  onFilterChange,
}) => {
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [page, setPage] = useState<number>(0);
  const pageSize = 15;

  const handleTypeSelect = (type: string) => {
    setTypeFilter(type);
    setPage(0);
    onFilterChange(type, severityFilter, pageSize, 0);
  };

  const handleSeveritySelect = (sev: string) => {
    setSeverityFilter(sev);
    setPage(0);
    onFilterChange(typeFilter, sev, pageSize, 0);
  };

  const handleNextPage = () => {
    const nextOffset = (page + 1) * pageSize;
    setPage(page + 1);
    onFilterChange(typeFilter, severityFilter, pageSize, nextOffset);
  };

  const handlePrevPage = () => {
    const prevOffset = Math.max(0, (page - 1) * pageSize);
    setPage(page - 1);
    onFilterChange(typeFilter, severityFilter, pageSize, prevOffset);
  };

  const filteredEvents = events.filter((e) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      e.title.toLowerCase().includes(term) ||
      e.target.toLowerCase().includes(term) ||
      e.description.toLowerCase().includes(term) ||
      e.source.toLowerCase().includes(term)
    );
  });

  const getEventIcon = (type: TimelineEventType) => {
    switch (type) {
      case 'SCAN_FINDING':
        return <ShieldAlert size={14} style={{ color: '#ef4444' }} />;
      case 'WEB_THREAT':
        return <Globe size={14} style={{ color: '#c084fc' }} />;
      case 'POLICY_EVENT':
        return <Sliders size={14} style={{ color: '#00e5ff' }} />;
      case 'ALERT_TRIAGE':
        return <CheckCircle size={14} style={{ color: '#10b981' }} />;
      case 'SCAN_INGEST':
        return <HardDrive size={14} style={{ color: '#38bdf8' }} />;
      default:
        return <Info size={14} style={{ color: '#94a3b8' }} />;
    }
  };

  const getTypeLabel = (type: TimelineEventType) => {
    switch (type) {
      case 'SCAN_FINDING':
        return 'Memory Anomaly';
      case 'WEB_THREAT':
        return 'Web Threat';
      case 'POLICY_EVENT':
        return 'Domain Policy';
      case 'ALERT_TRIAGE':
        return 'SOC Triage';
      case 'SCAN_INGEST':
        return 'Scan Ingest';
      default:
        return type;
    }
  };

  return (
    <div className="pt-card" style={{ padding: '1.25rem 1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Timeline Header & Filters */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#ffffff', margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Clock size={16} style={{ color: '#00e5ff' }} />
            <span>Security Event Timeline</span>
            <span style={{ fontSize: '0.74rem', padding: '0.15rem 0.5rem', borderRadius: '10px', background: 'rgba(0, 229, 255, 0.12)', color: '#00e5ff', fontWeight: 600 }}>
              {total} events
            </span>
          </h3>
          <p style={{ fontSize: '0.78rem', color: '#94a3b8', margin: '0.2rem 0 0 0' }}>
            Chronological audit stream across endpoint scans, web threat events, domain policies, and triage actions.
          </p>
        </div>

        {/* Filter Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap' }}>
          {/* Search Box */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', background: 'rgba(15, 23, 42, 0.8)', padding: '0.35rem 0.65rem', borderRadius: '6px', border: '1px solid var(--pt-border-subtle)' }}>
            <Search size={13} style={{ color: '#64748b' }} />
            <input
              type="text"
              placeholder="Filter target, keyword..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{ background: 'transparent', border: 'none', color: '#ffffff', fontSize: '0.78rem', outline: 'none', width: '130px' }}
            />
          </div>

          {/* Type Select */}
          <select
            value={typeFilter}
            onChange={(e) => handleTypeSelect(e.target.value)}
            className="pt-select"
            style={{ padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
          >
            <option value="ALL">All Event Types</option>
            <option value="SCAN_FINDING">Memory Anomalies</option>
            <option value="WEB_THREAT">Web Threats</option>
            <option value="POLICY_EVENT">Domain Policies</option>
            <option value="ALERT_TRIAGE">Triage Updates</option>
            <option value="SCAN_INGEST">Scan Ingests</option>
          </select>

          {/* Severity Select */}
          <select
            value={severityFilter}
            onChange={(e) => handleSeveritySelect(e.target.value)}
            className="pt-select"
            style={{ padding: '0.35rem 0.65rem', fontSize: '0.78rem' }}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
        </div>
      </div>

      {/* Non-Attribution Discretion Notice */}
      <div
        style={{
          padding: '0.5rem 0.85rem',
          borderRadius: '6px',
          background: 'rgba(0, 229, 255, 0.04)',
          border: '1px solid rgba(0, 229, 255, 0.15)',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          fontSize: '0.74rem',
          color: '#94a3b8',
        }}
      >
        <HelpCircle size={14} style={{ color: '#00e5ff', flexShrink: 0 }} />
        <span>
          <strong>Forensic Integrity Standard:</strong> Event entries reflect observed telemetry. Cross-vector process linkages indicate temporal co-occurrence in scan snapshots, not definitive proof of process execution.
        </span>
      </div>

      {/* Event Stream */}
      {loading ? (
        <div style={{ padding: '2.5rem', textAlign: 'center', color: '#94a3b8' }}>
          Loading timeline telemetry...
        </div>
      ) : filteredEvents.length === 0 ? (
        <div style={{ padding: '3rem', textAlign: 'center', color: '#64748b' }}>
          <Clock size={28} style={{ margin: '0 auto 0.75rem auto', opacity: 0.5 }} />
          <div style={{ fontSize: '0.9rem', color: '#94a3b8', fontWeight: 600 }}>No Security Events Matched</div>
          <p style={{ fontSize: '0.78rem', marginTop: '0.25rem' }}>
            Adjust your type or severity filters, or upload a new scan to populate event records.
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
          {filteredEvents.map((event) => (
            <div
              key={event.id}
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                justifyContent: 'space-between',
                padding: '0.85rem 1rem',
                borderRadius: '6px',
                background: 'rgba(15, 23, 42, 0.55)',
                border: '1px solid rgba(255, 255, 255, 0.05)',
                gap: '1rem',
                transition: 'background 0.15s ease',
              }}
            >
              {/* Left Column: Icon & Metadata */}
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.85rem', flex: 1 }}>
                <div
                  style={{
                    padding: '0.4rem',
                    borderRadius: '6px',
                    background: 'rgba(255, 255, 255, 0.04)',
                    border: '1px solid rgba(255, 255, 255, 0.08)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    marginTop: '2px',
                  }}
                >
                  {getEventIcon(event.eventType)}
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem', flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                    <span style={{ fontSize: '0.7rem', padding: '0.1rem 0.45rem', borderRadius: '4px', background: 'rgba(255, 255, 255, 0.06)', color: '#94a3b8', fontWeight: 600 }}>
                      {getTypeLabel(event.eventType)}
                    </span>
                    <span style={{ fontSize: '0.86rem', fontWeight: 700, color: '#ffffff' }}>
                      {event.title}
                    </span>
                    <span style={{ fontSize: '0.78rem', color: '#00e5ff', fontFamily: 'var(--font-mono)' }}>
                      [{event.target}]
                    </span>
                  </div>

                  <p style={{ fontSize: '0.78rem', color: '#cbd5e1', margin: '0.15rem 0', lineHeight: 1.45 }}>
                    {event.description}
                  </p>

                  {/* Evidence tags */}
                  {event.evidenceSummary && event.evidenceSummary.length > 0 && (
                    <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap', marginTop: '0.2rem' }}>
                      {event.evidenceSummary.slice(0, 3).map((ind, i) => (
                        <span
                          key={i}
                          style={{
                            fontSize: '0.68rem',
                            padding: '0.1rem 0.35rem',
                            borderRadius: '3px',
                            background: 'rgba(0, 229, 255, 0.08)',
                            color: '#38bdf8',
                            fontFamily: 'var(--font-mono)',
                          }}
                        >
                          {ind}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Correlation Disclaimer if present */}
                  {event.disclaimer && (
                    <div style={{ fontSize: '0.7rem', color: '#f59e0b', marginTop: '0.25rem', fontStyle: 'italic' }}>
                      ⚠ {event.disclaimer}
                    </div>
                  )}
                </div>
              </div>

              {/* Right Column: Severity, Status & Timestamp */}
              <div style={{ textAlign: 'right', display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.35rem', flexShrink: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  {event.status && (
                    <span style={{ fontSize: '0.7rem', padding: '0.1rem 0.4rem', borderRadius: '4px', background: 'rgba(255, 255, 255, 0.05)', color: '#94a3b8' }}>
                      {event.status}
                    </span>
                  )}
                  <Badge level={event.severity}>{event.severity}</Badge>
                </div>

                <div style={{ fontSize: '0.72rem', color: '#64748b', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  <Clock size={11} />
                  <span>
                    {event.timestamp ? new Date(event.timestamp).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' }) : 'Unknown'}
                  </span>
                </div>

                <span style={{ fontSize: '0.68rem', color: '#475569' }}>{event.source}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Pagination Footer */}
      {total > pageSize && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: '0.75rem', borderTop: '1px solid rgba(255, 255, 255, 0.06)' }}>
          <span style={{ fontSize: '0.74rem', color: '#64748b' }}>
            Showing {page * pageSize + 1}–{Math.min(total, (page + 1) * pageSize)} of {total} events
          </span>
          <div style={{ display: 'flex', gap: '0.4rem' }}>
            <button
              type="button"
              disabled={page === 0}
              onClick={handlePrevPage}
              className="pt-btn pt-btn-secondary"
              style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
            >
              <ChevronLeft size={13} />
              <span>Previous</span>
            </button>
            <button
              type="button"
              disabled={(page + 1) * pageSize >= total}
              onClick={handleNextPage}
              className="pt-btn pt-btn-secondary"
              style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
            >
              <span>Next</span>
              <ChevronRight size={13} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
