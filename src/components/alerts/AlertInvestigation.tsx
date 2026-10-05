import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowLeft,
  ShieldAlert,
  Cpu,
  Clock,
  Lock,
  CheckCircle2,
  HelpCircle,
  Layers,
  ArrowUpRight
} from 'lucide-react';
import { Badge } from '../common/Badge';
import { Card } from '../common/Card';
import { EvidencePanel } from './EvidencePanel';
import { RecommendedResponse } from './RecommendedResponse';
import type { ThreatAlert } from '../../types';

interface AlertInvestigationProps {
  alert: ThreatAlert;
  onStatusChange?: (newStatus: 'NEW' | 'INVESTIGATING' | 'RESOLVED' | 'DISMISSED') => void;
  onBack?: () => void;
}

export const AlertInvestigation: React.FC<AlertInvestigationProps> = ({
  alert,
  onStatusChange,
  onBack,
}) => {
  const [currentStatus, setCurrentStatus] = useState<ThreatAlert['status']>(alert.status || 'NEW');

  const handleStatusUpdate = (status: 'NEW' | 'INVESTIGATING' | 'RESOLVED' | 'DISMISSED') => {
    setCurrentStatus(status);
    if (onStatusChange) {
      onStatusChange(status);
    }
  };

  // Evaluate detection reason based purely on real evidence within ThreatAlert model
  const hasMemory = Boolean(
    alert.memoryEvidence &&
    (alert.memoryEvidence.present || (alert.memoryEvidence.indicators && alert.memoryEvidence.indicators.length > 0))
  );

  const hasBehavior = Boolean(
    alert.behaviorEvidence &&
    (alert.behaviorEvidence.present || (alert.behaviorEvidence.indicators && alert.behaviorEvidence.indicators.length > 0))
  );

  const getWhyDetectedText = (): string => {
    if (hasMemory && hasBehavior) {
      return "Memory and behavioral evidence were observed in the same process and were correlated.";
    }
    if (hasMemory && !hasBehavior) {
      return "The alert is based on memory evidence. Memory-only evidence should be treated as a signal requiring investigation, not automatic proof of malicious activity.";
    }
    if (!hasMemory && hasBehavior) {
      return "The alert is based on behavioral indicators.";
    }
    return "No supporting evidence is currently available.";
  };

  const getStatusBadge = (status?: string) => {
    switch (status) {
      case 'INVESTIGATING':
        return <Badge level="High">INVESTIGATING</Badge>;
      case 'RESOLVED':
        return <Badge level="Clean">RESOLVED</Badge>;
      case 'DISMISSED':
        return <Badge level="neutral">DISMISSED</Badge>;
      case 'NEW':
      default:
        return <Badge level="Critical">NEW</Badge>;
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Top Header & Breadcrumb Navigation */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {onBack ? (
            <button
              type="button"
              onClick={onBack}
              className="pt-btn pt-btn-secondary"
              style={{ padding: '0.4rem 0.85rem', fontSize: '0.8rem' }}
            >
              <ArrowLeft size={14} />
              <span>Back to Threat Alerts</span>
            </button>
          ) : (
            <Link
              to="/alerts"
              className="pt-btn pt-btn-secondary"
              style={{ padding: '0.4rem 0.85rem', fontSize: '0.8rem' }}
            >
              <ArrowLeft size={14} />
              <span>Back to Threat Alerts</span>
            </Link>
          )}

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', color: '#94a3b8' }}>
            <span>Alert ID:</span>
            <span className="text-mono" style={{ color: '#00e5ff', fontWeight: 700 }}>
              {alert.id}
            </span>
          </div>
        </div>

        {/* Read-Only Safety Protocol Badge */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(0, 229, 255, 0.08)', border: '1px solid rgba(0, 229, 255, 0.25)', padding: '0.35rem 0.75rem', borderRadius: '6px', fontSize: '0.76rem', color: '#38bdf8' }}>
          <Lock size={13} style={{ color: '#00e5ff' }} />
          <span>Read-Only Telemetry • Passive Forensic Triage</span>
        </div>
      </div>

      {/* Main Alert Identity Card (Alert Overview) */}
      <div
        className="pt-card pt-card-cyber"
        style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1.25rem' }}>
          {/* Identity Group */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '1.15rem' }}>
            <div
              style={{
                width: '56px',
                height: '56px',
                borderRadius: '12px',
                background: 'rgba(239, 68, 68, 0.12)',
                border: '1px solid rgba(239, 68, 68, 0.35)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}
            >
              <ShieldAlert size={30} style={{ color: '#ef4444' }} />
            </div>

            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                <h2 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#ffffff', letterSpacing: '-0.01em', margin: 0 }}>
                  {alert.processName || alert.process}
                </h2>
                <span className="text-mono" style={{ fontSize: '1.05rem', color: '#00e5ff', fontWeight: 700 }}>
                  PID: {alert.pid}
                </span>
                <Badge level={alert.level || alert.threatLevel}>
                  {alert.level || alert.threatLevel}
                </Badge>
                {getStatusBadge(currentStatus)}
              </div>

              <div style={{ fontSize: '0.84rem', color: '#cbd5e1', marginTop: '0.35rem' }}>
                {alert.title || 'Elevated Heuristic Threat Finding'}
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginTop: '0.35rem', fontSize: '0.76rem', color: '#64748b' }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <Clock size={12} />
                  Detected: <strong style={{ color: '#94a3b8' }}>{alert.detectedAt || alert.timestamp}</strong>
                </span>
                <span>•</span>
                <span>
                  Classification: <strong style={{ color: '#94a3b8' }}>{alert.application || 'Standard Execution Context'}</strong>
                </span>
              </div>
            </div>
          </div>

          {/* Threat Score Large Display */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.7rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                Threat Score
              </div>
              <div style={{ fontSize: '2.1rem', fontWeight: 800, color: (alert.score ?? alert.threatScore ?? 0) >= 75 ? '#ef4444' : '#facc15', fontFamily: 'var(--font-mono)', lineHeight: 1.1 }}>
                {alert.score ?? alert.threatScore ?? 0}<span style={{ fontSize: '1.1rem', color: '#64748b' }}>/100</span>
              </div>
            </div>

            <div style={{ borderLeft: '1px solid var(--pt-border-subtle)', paddingLeft: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.4rem', fontSize: '0.78rem' }}>
              <div>
                <span style={{ color: '#64748b' }}>Score Mode: </span>
                <Badge level="neutral">{alert.scoreMode}</Badge>
              </div>
              <div>
                <span style={{ color: '#64748b' }}>Memory Component: </span>
                <strong style={{ color: '#00e5ff', fontFamily: 'var(--font-mono)' }}>
                  {alert.memoryScore ?? 'N/A'}
                </strong>
              </div>
              <div>
                <span style={{ color: '#64748b' }}>Behavior Component: </span>
                <strong style={{ color: '#f97316', fontFamily: 'var(--font-mono)' }}>
                  {alert.behaviorScore ?? alert.behaviorEvidence?.score ?? 'N/A'}
                </strong>
              </div>
            </div>
          </div>
        </div>

        {/* Status Lifecycle Controls & Process Drilldown Link */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            paddingTop: '1rem',
            borderTop: '1px solid var(--pt-border-subtle)',
            flexWrap: 'wrap',
            gap: '1rem'
          }}
        >
          {/* Status Controls */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 600, marginRight: '0.25rem' }}>
              Triage Lifecycle:
            </span>

            <button
              type="button"
              onClick={() => handleStatusUpdate('NEW')}
              className={`pt-btn ${currentStatus === 'NEW' ? 'pt-btn-primary' : 'pt-btn-secondary'}`}
              style={{ padding: '0.3rem 0.75rem', fontSize: '0.75rem' }}
            >
              Reset to New
            </button>

            <button
              type="button"
              onClick={() => handleStatusUpdate('INVESTIGATING')}
              className={`pt-btn ${currentStatus === 'INVESTIGATING' ? 'pt-btn-cyber' : 'pt-btn-secondary'}`}
              style={{ padding: '0.3rem 0.75rem', fontSize: '0.75rem' }}
            >
              Mark Investigating
            </button>

            <button
              type="button"
              onClick={() => handleStatusUpdate('RESOLVED')}
              className={`pt-btn ${currentStatus === 'RESOLVED' ? 'pt-btn-primary' : 'pt-btn-secondary'}`}
              style={{ padding: '0.3rem 0.75rem', fontSize: '0.75rem', color: currentStatus === 'RESOLVED' ? '#10b981' : undefined }}
            >
              <CheckCircle2 size={13} />
              <span>Mark Resolved</span>
            </button>

            <button
              type="button"
              onClick={() => handleStatusUpdate('DISMISSED')}
              className={`pt-btn ${currentStatus === 'DISMISSED' ? 'pt-btn-primary' : 'pt-btn-secondary'}`}
              style={{ padding: '0.3rem 0.75rem', fontSize: '0.75rem' }}
            >
              Dismiss
            </button>
          </div>

          {/* Jump to Process Explorer Link */}
          <Link
            to={`/processes/${alert.pid}`}
            className="pt-btn pt-btn-cyber"
            style={{ padding: '0.4rem 0.95rem', fontSize: '0.78rem' }}
          >
            <Cpu size={14} />
            <span>Open Process Explorer (PID: {alert.pid})</span>
            <ArrowUpRight size={13} />
          </Link>
        </div>
      </div>

      {/* 2. WHY WAS THIS DETECTED? */}
      <Card
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <HelpCircle size={18} style={{ color: '#00e5ff' }} />
            <span>Why Was This Detected?</span>
          </div>
        }
        subtitle="Objective detection explanation derived directly from scanner telemetry"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Evidence-Based Primary Explanation */}
          <div
            style={{
              background: 'rgba(0, 229, 255, 0.05)',
              borderLeft: '4px solid var(--pt-cyan)',
              borderRadius: '0 6px 6px 0',
              padding: '1rem 1.25rem'
            }}
          >
            <strong style={{ fontSize: '0.76rem', color: '#00e5ff', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: '0.3rem' }}>
              Primary Forensic Rationale
            </strong>
            <p style={{ fontSize: '0.9rem', color: '#f8fafc', lineHeight: 1.6, margin: 0, fontWeight: 500 }}>
              {getWhyDetectedText()}
            </p>
          </div>

          {/* Contextual Narrative if Present */}
          {alert.description && (
            <div style={{ background: 'rgba(9, 15, 26, 0.7)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.85rem 1rem' }}>
              <span style={{ fontSize: '0.74rem', color: '#94a3b8', display: 'block', textTransform: 'uppercase', marginBottom: '0.3rem', fontWeight: 600 }}>
                Scanner Contextual Summary
              </span>
              <p style={{ fontSize: '0.84rem', color: '#cbd5e1', lineHeight: 1.55, margin: 0 }}>
                {alert.description}
              </p>
            </div>
          )}

          {/* Correlation Summary if Present */}
          {alert.correlation && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', fontSize: '0.8rem', color: '#38bdf8', background: 'rgba(2, 132, 199, 0.08)', padding: '0.6rem 0.85rem', borderRadius: '4px' }}>
              <Layers size={15} style={{ color: '#00e5ff', flexShrink: 0 }} />
              <span>
                <strong>Correlation Signal: </strong>{alert.correlation}
              </span>
            </div>
          )}

          {/* Security Language Guardrail */}
          <div style={{ fontSize: '0.75rem', color: '#64748b', lineHeight: 1.5, background: 'rgba(255, 255, 255, 0.02)', padding: '0.5rem 0.75rem', borderRadius: '4px' }}>
            Evidence Preservation Policy: PhantomTrace reports observable signals and heuristics discovered during read-only inspection. Telemetry does not claim definitive compromise without analyst validation.
          </div>
        </div>
      </Card>

      {/* 3, 4, 5. EVIDENCE PANELS (Memory, Behavior, Correlation) */}
      <EvidencePanel
        memoryEvidence={alert.memoryEvidence}
        behaviorEvidence={alert.behaviorEvidence}
        correlationEvidence={alert.correlationEvidence}
      />

      {/* 6, 7. INVESTIGATION GUIDANCE & RECOMMENDED RESPONSE */}
      <RecommendedResponse alert={alert} />
    </div>
  );
};
