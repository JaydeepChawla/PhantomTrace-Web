import React from 'react';
import {
  ShieldCheck,
  AlertCircle,
  FileCheck2,
  Terminal,
  Network,
  KeyRound,
  Layers,
  Lock
} from 'lucide-react';
import type { Process, ProcessItem } from '../../types';

interface RecommendedResponseGuideProps {
  process: Process | ProcessItem;
}

export const RecommendedResponseGuide: React.FC<RecommendedResponseGuideProps> = ({ process }) => {
  const responseRecommendation = process.responseRecommendation || {
    whyFlagged: 'Flagged for forensic review based on heuristic and behavioral telemetry.',
    investigationSteps: [
      'Inspect parent process lineage and command line invocation parameters.',
      'Analyze virtual memory allocations for unbacked executable pages or RWX sections.',
      'Check host persistence keys and network connections.'
    ],
    mitreReferences: [],
    containmentGuidance: 'Preserve process memory dump and isolate host if malicious activity is suspected.',
    readOnlyNotice: 'The PhantomTrace scanner operates in strict read-only mode to preserve forensic integrity.'
  };

  const investigationStepsIcons = [
    <Terminal size={16} key="cmd" style={{ color: '#00e5ff' }} />,
    <Layers size={16} key="parent" style={{ color: '#38bdf8' }} />,
    <KeyRound size={16} key="user" style={{ color: '#818cf8' }} />,
    <FileCheck2 size={16} key="mem" style={{ color: '#f43f5e' }} />,
    <Network size={16} key="net" style={{ color: '#fb923c' }} />,
    <AlertCircle size={16} key="pers" style={{ color: '#facc15' }} />,
    <ShieldCheck size={16} key="ir" style={{ color: '#34d399' }} />,
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Read-Only Safety Protocol Box (Crucial for PhantomTrace) */}
      <div
        style={{
          background: 'rgba(2, 132, 199, 0.08)',
          border: '1px solid rgba(0, 229, 255, 0.25)',
          borderRadius: '8px',
          padding: '1rem 1.25rem',
          display: 'flex',
          gap: '1rem',
          alignItems: 'flex-start'
        }}
      >
        <Lock size={20} style={{ color: '#00e5ff', flexShrink: 0, marginTop: '2px' }} />
        <div style={{ fontSize: '0.82rem', lineHeight: 1.5 }}>
          <strong style={{ color: '#00e5ff', display: 'block', marginBottom: '0.2rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            Non-Destructive Read-Only Analysis Protocol
          </strong>
          <span style={{ color: '#cbd5e1' }}>
            {responseRecommendation.readOnlyNotice} PhantomTrace enforces strict read-only execution to prevent unintended endpoint perturbation or forensic destruction. Automated termination, file deletion, and memory wiping are intentionally prohibited.
          </span>
        </div>
      </div>

      {/* Why This Was Flagged */}
      <div
        style={{
          background: 'rgba(16, 26, 46, 0.65)',
          border: '1px solid var(--pt-border-subtle)',
          borderRadius: '8px',
          padding: '1.25rem'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
          <AlertCircle size={16} style={{ color: '#f97316' }} />
          <h4 style={{ fontSize: '0.92rem', fontWeight: 600, color: '#ffffff' }}>
            Why This Was Flagged
          </h4>
        </div>
        <p style={{ fontSize: '0.84rem', color: '#cbd5e1', lineHeight: 1.6 }}>
          {responseRecommendation.whyFlagged}
        </p>

        {process.correlationSummary && (
          <div
            style={{
              marginTop: '0.75rem',
              padding: '0.65rem 0.85rem',
              background: 'rgba(0, 229, 255, 0.04)',
              borderLeft: '3px solid var(--pt-cyan)',
              borderRadius: '0 4px 4px 0',
              fontSize: '0.8rem',
              color: '#94a3b8'
            }}
          >
            <strong style={{ color: '#00e5ff' }}>Evidence Correlation: </strong>
            {process.correlationSummary}
          </div>
        )}
      </div>

      {/* Recommended Investigation Steps */}
      <div
        style={{
          background: 'rgba(16, 26, 46, 0.65)',
          border: '1px solid var(--pt-border-subtle)',
          borderRadius: '8px',
          padding: '1.25rem'
        }}
      >
        <h4 style={{ fontSize: '0.92rem', fontWeight: 600, color: '#ffffff', marginBottom: '0.85rem' }}>
          Recommended Investigation Steps
        </h4>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
          {responseRecommendation.investigationSteps.map((step, idx) => (
            <div
              key={idx}
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '0.85rem',
                padding: '0.65rem 0.85rem',
                background: 'rgba(7, 11, 20, 0.5)',
                border: '1px solid rgba(255, 255, 255, 0.04)',
                borderRadius: '6px'
              }}
            >
              <div
                style={{
                  width: '24px',
                  height: '24px',
                  borderRadius: '4px',
                  background: 'rgba(0, 229, 255, 0.1)',
                  border: '1px solid rgba(0, 229, 255, 0.2)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                  fontSize: '0.75rem',
                  fontFamily: 'var(--font-mono)',
                  color: '#00e5ff',
                  fontWeight: 700
                }}
              >
                {idx + 1}
              </div>

              <div style={{ flex: 1, fontSize: '0.84rem', color: '#e2e8f0', lineHeight: 1.45 }}>
                {step}
              </div>

              <div style={{ flexShrink: 0 }}>
                {investigationStepsIcons[idx % investigationStepsIcons.length]}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Containment Guidance (Non-Destructive) */}
      <div
        style={{
          background: 'rgba(16, 26, 46, 0.65)',
          border: '1px solid var(--pt-border-subtle)',
          borderRadius: '8px',
          padding: '1rem 1.25rem'
        }}
      >
        <h4 style={{ fontSize: '0.86rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '0.35rem' }}>
          Forensic Containment Guidance
        </h4>
        <p style={{ fontSize: '0.8rem', color: '#94a3b8', lineHeight: 1.5 }}>
          {responseRecommendation.containmentGuidance}
        </p>

        {responseRecommendation.mitreReferences.length > 0 && (
          <div style={{ marginTop: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.74rem', color: '#64748b', fontWeight: 600 }}>MITRE ATT&CK:</span>
            {responseRecommendation.mitreReferences.map((ref) => (
              <span
                key={ref}
                style={{
                  background: 'rgba(255, 255, 255, 0.05)',
                  border: '1px solid rgba(255, 255, 255, 0.1)',
                  padding: '0.15rem 0.45rem',
                  borderRadius: '4px',
                  fontSize: '0.72rem',
                  fontFamily: 'var(--font-mono)',
                  color: '#38bdf8'
                }}
              >
                {ref}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
