import React, { useState, useEffect } from 'react';
import { 
  FileText, 
  Download, 
  Copy, 
  Check, 
  FileCode, 
  Layers, 
  Lock 
} from 'lucide-react';
import { dataService } from '../services';
import type { Report } from '../types';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';

export const ReportsPage: React.FC = () => {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedReportId, setSelectedReportId] = useState<string>('rep-01');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function loadReports() {
      try {
        setLoading(true);
        setError(null);
        const result = await dataService.getReports();
        if (!cancelled) {
          setReports(result);
          if (result.length > 0 && !result.some(r => r.id === selectedReportId)) {
            setSelectedReportId(result[0].id);
          }
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Unable to load telemetry reports');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadReports();

    return () => {
      cancelled = true;
    };
  }, []);

  const selectedReport = reports.find((r) => r.id === selectedReportId) || reports[0];

  const handleCopy = () => {
    if (selectedReport && selectedReport.content) {
      navigator.clipboard.writeText(selectedReport.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownload = () => {
    if (!selectedReport || !selectedReport.content) return;
    const mimeType = selectedReport.type === 'json' ? 'application/json' : 'text/plain';
    const blob = new Blob([selectedReport.content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = selectedReport.name || 'report.txt';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  if (loading && reports.length === 0) {
    return <div style={{ padding: '3rem', textAlign: 'center', color: '#94a3b8' }}>Loading telemetry reports...</div>;
  }

  if (error && reports.length === 0) {
    return (
      <div style={{ padding: '2rem', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', borderRadius: '8px', color: '#fca5a5' }}>
        {error}
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Page Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.01em' }}>
            Telemetry Reports &amp; Artifact Exports
          </h2>
          <p style={{ fontSize: '0.82rem', color: '#94a3b8', marginTop: '0.2rem' }}>
            Structured JSON exports, diagnostic text validation logs, and forensic audit trails
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(0, 229, 255, 0.08)', border: '1px solid rgba(0, 229, 255, 0.25)', padding: '0.4rem 0.85rem', borderRadius: '6px', fontSize: '0.78rem', color: '#38bdf8' }}>
          <Lock size={14} style={{ color: '#00e5ff' }} />
          <span>Prepared for Real File Ingestion</span>
        </div>
      </div>

      {/* Reports Selection Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
        {reports.map((rep) => {
          const isSelected = rep.id === selectedReportId;
          return (
            <div
              key={rep.id}
              onClick={() => setSelectedReportId(rep.id)}
              className={`pt-card ${isSelected ? 'pt-card-cyber' : ''}`}
              style={{
                padding: '1.25rem',
                cursor: 'pointer',
                borderColor: isSelected ? 'var(--pt-cyan)' : undefined,
                background: isSelected ? 'rgba(0, 229, 255, 0.06)' : undefined,
                display: 'flex',
                flexDirection: 'column',
                gap: '0.65rem'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  {rep.type === 'json' ? (
                    <FileCode size={20} style={{ color: '#00e5ff' }} />
                  ) : (
                    <FileText size={20} style={{ color: '#38bdf8' }} />
                  )}
                  <span style={{ fontSize: '0.92rem', fontWeight: 700, color: '#ffffff', fontFamily: 'var(--font-mono)' }}>
                    {rep.name}
                  </span>
                </div>
                <Badge level="neutral">{(rep.type || 'TXT').toUpperCase()}</Badge>
              </div>

              <p style={{ fontSize: '0.78rem', color: '#94a3b8', lineHeight: 1.45, flex: 1 }}>
                {rep.description}
              </p>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.72rem', color: '#64748b', borderTop: '1px solid rgba(255, 255, 255, 0.05)', paddingTop: '0.5rem' }}>
                <span>Size: <strong style={{ color: '#cbd5e1' }}>{rep.size}</strong></span>
                <span>Modified: {rep.lastModified}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Active Report Viewer */}
      {selectedReport && (
        <Card
          title={
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <span className="text-mono" style={{ color: '#00e5ff', fontSize: '1rem', fontWeight: 700 }}>
                {selectedReport.name}
              </span>
              <Badge level="neutral">{selectedReport.size}</Badge>
            </div>
          }
          subtitle={`Last generated: ${selectedReport.lastModified}`}
          action={
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <button
                onClick={handleCopy}
                className="pt-btn pt-btn-secondary"
                style={{ padding: '0.35rem 0.75rem', fontSize: '0.78rem' }}
              >
                {copied ? <Check size={13} style={{ color: '#10b981' }} /> : <Copy size={13} />}
                <span>{copied ? 'Copied' : 'Copy Content'}</span>
              </button>

              <button
                onClick={handleDownload}
                className="pt-btn pt-btn-primary"
                style={{ padding: '0.35rem 0.85rem', fontSize: '0.78rem' }}
              >
                <Download size={13} />
                <span>Export / Download</span>
              </button>
            </div>
          }
        >
          {/* Architecture readiness comment */}
          <div style={{ marginBottom: '1rem', background: 'rgba(5, 9, 17, 0.75)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.85rem', fontSize: '0.78rem', color: '#64748b', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Layers size={14} style={{ color: '#00e5ff' }} />
            <span>Architecture Readiness: This report UI is designed to stream production JSON/TXT artifacts directly from the PhantomTrace API or Firebase Storage bucket.</span>
          </div>

          <div 
            style={{ 
              background: '#04070e', 
              border: '1px solid var(--pt-border-subtle)', 
              borderRadius: '8px', 
              padding: '1.25rem',
              maxHeight: '520px',
              overflowY: 'auto'
            }}
          >
            <pre 
              style={{ 
                margin: 0, 
                fontSize: '0.8rem', 
                color: '#e2e8f0', 
                fontFamily: 'var(--font-mono)', 
                lineHeight: 1.55,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word'
              }}
            >
              {selectedReport.content}
            </pre>
          </div>
        </Card>
      )}
    </div>
  );
};
