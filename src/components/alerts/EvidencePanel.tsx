import React, { useState } from 'react';
import { 
  FileCheck2, 
  Activity, 
  Layers, 
  Terminal, 
  ShieldCheck, 
  Lock, 
  AlertCircle 
} from 'lucide-react';
import { Badge } from '../common/Badge';
import { Card } from '../components/../common/Card';
import type { 
  MemoryEvidence, 
  BehaviorEvidence, 
  CorrelationEvidence 
} from '../../types';

interface EvidencePanelProps {
  memoryEvidence?: MemoryEvidence;
  behaviorEvidence?: BehaviorEvidence;
  correlationEvidence?: CorrelationEvidence;
}

export const EvidencePanel: React.FC<EvidencePanelProps> = ({
  memoryEvidence,
  behaviorEvidence,
  correlationEvidence,
}) => {
  const [activeTab, setActiveTab] = useState<'memory' | 'behavior' | 'correlation'>('memory');

  const hasMemory = Boolean(memoryEvidence && (memoryEvidence.present || (memoryEvidence.indicators && memoryEvidence.indicators.length > 0)));
  const hasBehavior = Boolean(behaviorEvidence && (behaviorEvidence.present || (behaviorEvidence.indicators && behaviorEvidence.indicators.length > 0)));
  const hasCorrelation = Boolean(correlationEvidence && (correlationEvidence.present || correlationEvidence.explanation));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Evidence Sub-Navigation Tabs */}
      <div 
        style={{ 
          display: 'flex', 
          gap: '0.5rem', 
          borderBottom: '1px solid var(--pt-border-subtle)', 
          paddingBottom: '0.65rem',
          flexWrap: 'wrap'
        }}
      >
        <button
          type="button"
          onClick={() => setActiveTab('memory')}
          className={`pt-btn ${activeTab === 'memory' ? 'pt-btn-primary' : 'pt-btn-secondary'}`}
          style={{ padding: '0.45rem 1rem', fontSize: '0.82rem' }}
        >
          <FileCheck2 size={15} />
          <span>Memory Evidence {hasMemory ? `(${memoryEvidence?.indicators.length ?? 0})` : '(0)'}</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('behavior')}
          className={`pt-btn ${activeTab === 'behavior' ? 'pt-btn-primary' : 'pt-btn-secondary'}`}
          style={{ padding: '0.45rem 1rem', fontSize: '0.82rem' }}
        >
          <Activity size={15} />
          <span>Behavior Evidence {hasBehavior ? `(${behaviorEvidence?.indicators.length ?? 0})` : '(0)'}</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('correlation')}
          className={`pt-btn ${activeTab === 'correlation' ? 'pt-btn-primary' : 'pt-btn-secondary'}`}
          style={{ padding: '0.45rem 1rem', fontSize: '0.82rem' }}
        >
          <Layers size={15} />
          <span>Correlation Evidence</span>
        </button>
      </div>

      {/* 1. Memory Evidence Tab */}
      {activeTab === 'memory' && (
        <Card
          title="Memory Evidence Telemetry"
          subtitle="Observed characteristics discovered during read-only virtual memory inspection"
          action={
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.74rem', color: '#38bdf8' }}>
              <Lock size={12} style={{ color: '#00e5ff' }} />
              <span>Read-Only Memory Scan</span>
            </div>
          }
        >
          {!hasMemory ? (
            <div 
              style={{ 
                padding: '2.5rem 1.5rem', 
                textAlign: 'center', 
                background: 'rgba(9, 15, 26, 0.5)', 
                borderRadius: '8px',
                border: '1px solid var(--pt-border-subtle)' 
              }}
            >
              <AlertCircle size={24} style={{ color: '#64748b', marginBottom: '0.5rem' }} />
              <p style={{ color: '#94a3b8', fontSize: '0.88rem', margin: 0 }}>
                Memory evidence was not available for this process.
              </p>
              <span style={{ fontSize: '0.75rem', color: '#64748b', display: 'block', marginTop: '0.35rem' }}>
                All virtual memory pages are disk-backed by validated executable images or unflagged.
              </span>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {/* Evidence Metrics Grid */}
              <div 
                style={{ 
                  display: 'grid', 
                  gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', 
                  gap: '0.75rem', 
                  padding: '1rem',
                  background: 'rgba(5, 9, 17, 0.7)',
                  borderRadius: '6px',
                  border: '1px solid var(--pt-border-subtle)'
                }}
              >
                <div>
                  <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Evidence Present</span>
                  <strong style={{ color: memoryEvidence?.present ? '#ef4444' : '#10b981', fontSize: '0.88rem' }}>
                    {memoryEvidence?.present ? 'YES' : 'NO'}
                  </strong>
                </div>

                {memoryEvidence?.strength && (
                  <div>
                    <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Evidence Strength</span>
                    <Badge level={memoryEvidence.strength === 'HIGH' ? 'Critical' : memoryEvidence.strength === 'MEDIUM' ? 'High' : 'Low'}>
                      {memoryEvidence.strength}
                    </Badge>
                  </div>
                )}

                {memoryEvidence?.scanStatus && (
                  <div>
                    <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Scan Status</span>
                    <strong className="text-mono" style={{ color: '#38bdf8', fontSize: '0.84rem' }}>
                      {memoryEvidence.scanStatus}
                    </strong>
                  </div>
                )}

                {memoryEvidence?.accessDenied !== undefined && (
                  <div>
                    <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Access Denied</span>
                    <strong style={{ color: memoryEvidence.accessDenied ? '#f97316' : '#10b981', fontSize: '0.84rem' }}>
                      {memoryEvidence.accessDenied ? 'YES (Protected Process)' : 'NO'}
                    </strong>
                  </div>
                )}

                {memoryEvidence?.suspiciousRegions !== undefined && (
                  <div>
                    <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Suspicious Regions</span>
                    <strong className="text-mono" style={{ color: '#f87171', fontSize: '0.88rem' }}>
                      {memoryEvidence.suspiciousRegions}
                    </strong>
                  </div>
                )}

                {memoryEvidence?.rwxRegions !== undefined && (
                  <div>
                    <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>RWX Regions</span>
                    <strong className="text-mono" style={{ color: '#ef4444', fontSize: '0.88rem' }}>
                      {memoryEvidence.rwxRegions}
                    </strong>
                  </div>
                )}

                {memoryEvidence?.privateExecutableRegions !== undefined && (
                  <div>
                    <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Private Executable Regions</span>
                    <strong className="text-mono" style={{ color: '#facc15', fontSize: '0.88rem' }}>
                      {memoryEvidence.privateExecutableRegions}
                    </strong>
                  </div>
                )}

                {memoryEvidence?.executableWritableRegions !== undefined && (
                  <div>
                    <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Executable Writable Regions</span>
                    <strong className="text-mono" style={{ color: '#f87171', fontSize: '0.88rem' }}>
                      {memoryEvidence.executableWritableRegions}
                    </strong>
                  </div>
                )}

                {memoryEvidence?.timestamp && (
                  <div>
                    <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Inspection Timestamp</span>
                    <span className="text-mono" style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>
                      {memoryEvidence.timestamp}
                    </span>
                  </div>
                )}
              </div>

              {/* Observed Memory Indicators */}
              {memoryEvidence?.indicators && memoryEvidence.indicators.length > 0 && (
                <div>
                  <h4 style={{ fontSize: '0.82rem', fontWeight: 600, color: '#ffffff', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    Observed Memory Indicators ({memoryEvidence.indicators.length})
                  </h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                    {memoryEvidence.indicators.map((ind, i) => (
                      <div 
                        key={i}
                        style={{ 
                          display: 'flex', 
                          alignItems: 'center', 
                          gap: '0.6rem', 
                          padding: '0.5rem 0.85rem', 
                          background: 'rgba(239, 68, 68, 0.08)', 
                          border: '1px solid rgba(239, 68, 68, 0.25)', 
                          borderRadius: '6px',
                          fontSize: '0.8rem',
                          color: '#fca5a5'
                        }}
                      >
                        <AlertCircle size={14} style={{ color: '#ef4444', flexShrink: 0 }} />
                        <span>{ind}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Forensic Details List */}
              {memoryEvidence?.details && memoryEvidence.details.length > 0 && (
                <div>
                  <h4 style={{ fontSize: '0.82rem', fontWeight: 600, color: '#ffffff', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    Forensic Observations
                  </h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    {memoryEvidence.details.map((det, i) => (
                      <div 
                        key={i}
                        style={{ 
                          padding: '0.65rem 0.85rem', 
                          background: 'rgba(5, 9, 17, 0.8)', 
                          borderLeft: '3px solid var(--pt-cyan)', 
                          borderRadius: '0 6px 6px 0',
                          fontSize: '0.82rem',
                          color: '#cbd5e1',
                          lineHeight: 1.5
                        }}
                      >
                        {det}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Signal Assessment Notice */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.74rem', color: '#64748b', background: 'rgba(255, 255, 255, 0.02)', padding: '0.5rem 0.75rem', borderRadius: '4px' }}>
                <ShieldCheck size={14} style={{ color: '#38bdf8' }} />
                <span>Memory evidence is a forensic signal indicating non-standard execution and requires analyst correlation before drawing definitive conclusions.</span>
              </div>
            </div>
          )}
        </Card>
      )}

      {/* 2. Behavior Evidence Tab */}
      {activeTab === 'behavior' && (
        <Card
          title="Behavioral Telemetry & Execution Lineage"
          subtitle="Process creation anomalies, command-line syntax, and MITRE execution techniques"
        >
          {!hasBehavior ? (
            <div 
              style={{ 
                padding: '2.5rem 1.5rem', 
                textAlign: 'center', 
                background: 'rgba(9, 15, 26, 0.5)', 
                borderRadius: '8px',
                border: '1px solid var(--pt-border-subtle)' 
              }}
            >
              <AlertCircle size={24} style={{ color: '#64748b', marginBottom: '0.5rem' }} />
              <p style={{ color: '#94a3b8', fontSize: '0.88rem', margin: 0 }}>
                Behavior evidence was not available for this process.
              </p>
              <span style={{ fontSize: '0.75rem', color: '#64748b', display: 'block', marginTop: '0.35rem' }}>
                Process lineage and invocation parameters conform to standard endpoint orchestration.
              </span>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {/* Behavioral Metrics Grid */}
              <div 
                style={{ 
                  display: 'grid', 
                  gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', 
                  gap: '0.75rem', 
                  padding: '1rem',
                  background: 'rgba(5, 9, 17, 0.7)',
                  borderRadius: '6px',
                  border: '1px solid var(--pt-border-subtle)'
                }}
              >
                <div>
                  <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Present</span>
                  <strong style={{ color: behaviorEvidence?.present ? '#f97316' : '#10b981', fontSize: '0.88rem' }}>
                    {behaviorEvidence?.present ? 'YES' : 'NO'}
                  </strong>
                </div>

                {behaviorEvidence?.score !== undefined && (
                  <div>
                    <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Behavior Score</span>
                    <strong className="text-mono" style={{ color: '#f97316', fontSize: '1rem', fontWeight: 800 }}>
                      {behaviorEvidence.score}<span style={{ fontSize: '0.75rem', color: '#64748b' }}>/100</span>
                    </strong>
                  </div>
                )}

                {behaviorEvidence?.suspiciousCommandLine !== undefined && (
                  <div>
                    <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Suspicious Command Line</span>
                    <strong style={{ color: behaviorEvidence.suspiciousCommandLine ? '#ef4444' : '#10b981', fontSize: '0.84rem' }}>
                      {behaviorEvidence.suspiciousCommandLine ? 'YES (Obfuscated Flags)' : 'NO'}
                    </strong>
                  </div>
                )}

                {behaviorEvidence?.suspiciousParent !== undefined && (
                  <div>
                    <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Suspicious Parent</span>
                    <strong style={{ color: behaviorEvidence.suspiciousParent ? '#ef4444' : '#10b981', fontSize: '0.84rem' }}>
                      {behaviorEvidence.suspiciousParent ? 'YES (Anomalous Lineage)' : 'NO'}
                    </strong>
                  </div>
                )}

                {behaviorEvidence?.parentProcess && (
                  <div>
                    <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Parent Process</span>
                    <strong className="text-mono" style={{ color: '#cbd5e1', fontSize: '0.84rem' }}>
                      {behaviorEvidence.parentProcess}
                    </strong>
                  </div>
                )}

                {behaviorEvidence?.timestamp && (
                  <div>
                    <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Telemetry Timestamp</span>
                    <span className="text-mono" style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>
                      {behaviorEvidence.timestamp}
                    </span>
                  </div>
                )}
              </div>

              {/* Command Line Box */}
              {behaviorEvidence?.commandLine && (
                <div style={{ background: 'rgba(5, 9, 17, 0.85)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.85rem 1rem' }}>
                  <span style={{ fontSize: '0.74rem', color: '#94a3b8', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.4rem' }}>
                    <Terminal size={14} style={{ color: '#00e5ff' }} />
                    Captured Command Line Invocations
                  </span>
                  <code 
                    style={{ 
                      fontSize: '0.78rem', 
                      color: '#38bdf8', 
                      wordBreak: 'break-all', 
                      lineHeight: 1.5, 
                      display: 'block',
                      fontFamily: 'var(--font-mono)'
                    }}
                  >
                    {behaviorEvidence.commandLine}
                  </code>
                </div>
              )}

              {/* Behavioral Indicators List */}
              {behaviorEvidence?.indicators && behaviorEvidence.indicators.length > 0 && (
                <div>
                  <h4 style={{ fontSize: '0.82rem', fontWeight: 600, color: '#ffffff', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    Observed Behavioral Indicators ({behaviorEvidence.indicators.length})
                  </h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                    {behaviorEvidence.indicators.map((ind, i) => (
                      <div 
                        key={i}
                        style={{ 
                          display: 'flex', 
                          alignItems: 'center', 
                          gap: '0.6rem', 
                          padding: '0.5rem 0.85rem', 
                          background: 'rgba(249, 115, 22, 0.08)', 
                          border: '1px solid rgba(249, 115, 22, 0.25)', 
                          borderRadius: '6px',
                          fontSize: '0.8rem',
                          color: '#fdba74'
                        }}
                      >
                        <Activity size={14} style={{ color: '#f97316', flexShrink: 0 }} />
                        <span>{ind}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Additional Contextual Details */}
              {behaviorEvidence?.details && behaviorEvidence.details.length > 0 && (
                <div>
                  <h4 style={{ fontSize: '0.82rem', fontWeight: 600, color: '#ffffff', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    Contextual Behavioral Details
                  </h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    {behaviorEvidence.details.map((det, i) => (
                      <div 
                        key={i}
                        style={{ 
                          padding: '0.65rem 0.85rem', 
                          background: 'rgba(5, 9, 17, 0.8)', 
                          borderLeft: '3px solid #f97316', 
                          borderRadius: '0 6px 6px 0',
                          fontSize: '0.82rem',
                          color: '#cbd5e1',
                          lineHeight: 1.5
                        }}
                      >
                        {det}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </Card>
      )}

      {/* 3. Correlation Evidence Tab */}
      {activeTab === 'correlation' && (
        <Card
          title="Forensic Correlation Analysis"
          subtitle="Cross-domain co-occurrence analysis linking memory heuristics with execution behavior"
        >
          {!hasCorrelation ? (
            <div 
              style={{ 
                padding: '2.5rem 1.5rem', 
                textAlign: 'center', 
                background: 'rgba(9, 15, 26, 0.5)', 
                borderRadius: '8px',
                border: '1px solid var(--pt-border-subtle)' 
              }}
            >
              <AlertCircle size={24} style={{ color: '#64748b', marginBottom: '0.5rem' }} />
              <p style={{ color: '#94a3b8', fontSize: '0.88rem', margin: 0 }}>
                No correlation evidence is currently available.
              </p>
              <span style={{ fontSize: '0.75rem', color: '#64748b', display: 'block', marginTop: '0.35rem' }}>
                Correlation analysis is computed when both memory allocation anomalies and behavioral signals co-occur.
              </span>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {/* Correlation Architectural Callout */}
              <div 
                style={{ 
                  background: 'rgba(0, 229, 255, 0.05)', 
                  borderLeft: '4px solid var(--pt-cyan)', 
                  padding: '1rem 1.25rem', 
                  borderRadius: '0 6px 6px 0'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                  <Layers size={16} style={{ color: '#00e5ff' }} />
                  <strong style={{ fontSize: '0.84rem', color: '#00e5ff', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    Synthesis of Multiple Evidence Domains
                  </strong>
                </div>
                <p style={{ fontSize: '0.86rem', color: '#f8fafc', lineHeight: 1.6, margin: 0 }}>
                  {correlationEvidence?.explanation || 'Correlation combines volatile memory allocations with observable execution lineage to elevate confidence.'}
                </p>
              </div>

              {/* Correlation Attributes Grid */}
              <div 
                style={{ 
                  display: 'grid', 
                  gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', 
                  gap: '0.75rem', 
                  padding: '1rem',
                  background: 'rgba(5, 9, 17, 0.7)',
                  borderRadius: '6px',
                  border: '1px solid var(--pt-border-subtle)'
                }}
              >
                <div>
                  <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Present</span>
                  <strong style={{ color: correlationEvidence?.present ? '#ef4444' : '#10b981', fontSize: '0.88rem' }}>
                    {correlationEvidence?.present ? 'YES' : 'NO'}
                  </strong>
                </div>

                {correlationEvidence?.score !== undefined && (
                  <div>
                    <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Correlation Score</span>
                    <strong className="text-mono" style={{ color: '#00e5ff', fontSize: '1rem', fontWeight: 800 }}>
                      {correlationEvidence.score}<span style={{ fontSize: '0.75rem', color: '#64748b' }}>/100</span>
                    </strong>
                  </div>
                )}

                <div>
                  <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Memory Evidence Linked</span>
                  <strong style={{ color: correlationEvidence?.memoryEvidencePresent ? '#00e5ff' : '#64748b', fontSize: '0.84rem' }}>
                    {correlationEvidence?.memoryEvidencePresent ? 'YES' : 'NO'}
                  </strong>
                </div>

                <div>
                  <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Behavior Evidence Linked</span>
                  <strong style={{ color: correlationEvidence?.behaviorEvidencePresent ? '#f97316' : '#64748b', fontSize: '0.84rem' }}>
                    {correlationEvidence?.behaviorEvidencePresent ? 'YES' : 'NO'}
                  </strong>
                </div>

                {correlationEvidence?.timestamp && (
                  <div>
                    <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Correlation Timestamp</span>
                    <span className="text-mono" style={{ color: '#cbd5e1', fontSize: '0.78rem' }}>
                      {correlationEvidence.timestamp}
                    </span>
                  </div>
                )}
              </div>

              {/* Correlated Indicators Tag Group */}
              {correlationEvidence?.correlatedIndicators && correlationEvidence.correlatedIndicators.length > 0 && (
                <div>
                  <h4 style={{ fontSize: '0.82rem', fontWeight: 600, color: '#ffffff', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    Correlated Evidence Indicators ({correlationEvidence.correlatedIndicators.length})
                  </h4>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                    {correlationEvidence.correlatedIndicators.map((ind, i) => (
                      <span 
                        key={i}
                        style={{ 
                          padding: '0.3rem 0.75rem', 
                          background: 'rgba(0, 229, 255, 0.08)', 
                          border: '1px solid rgba(0, 229, 255, 0.3)', 
                          borderRadius: '4px',
                          fontSize: '0.78rem',
                          color: '#38bdf8',
                          fontFamily: 'var(--font-mono)'
                        }}
                      >
                        {ind}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Objective Note */}
              <div style={{ fontSize: '0.75rem', color: '#64748b', lineHeight: 1.5, background: 'rgba(255, 255, 255, 0.02)', padding: '0.65rem 0.85rem', borderRadius: '4px' }}>
                Note: Correlation evaluates co-occurrence between unbacked memory regions and active process invocation lineage. Correlation describes existing evidence and does not invent independent findings.
              </div>
            </div>
          )}
        </Card>
      )}
    </div>
  );
};
