import React from 'react';
import { 
  ShieldCheck, 
  Search, 
  Terminal, 
  Layers, 
  FileCheck2, 
  Lock, 
  AlertTriangle,
  ArrowRight
} from 'lucide-react';
import { Card } from '../common/Card';
import type { ThreatAlert } from '../../types';

interface RecommendedResponseProps {
  alert: ThreatAlert;
}

export const RecommendedResponse: React.FC<RecommendedResponseProps> = ({ alert }) => {
  const hasMemory = Boolean(
    alert.memoryEvidence && 
    (alert.memoryEvidence.present || (alert.memoryEvidence.indicators && alert.memoryEvidence.indicators.length > 0))
  );

  const hasBehavior = Boolean(
    alert.behaviorEvidence && 
    (alert.behaviorEvidence.present || (alert.behaviorEvidence.indicators && alert.behaviorEvidence.indicators.length > 0))
  );

  const hasCorrelation = Boolean(
    alert.correlationEvidence && 
    (alert.correlationEvidence.present || alert.correlationEvidence.explanation)
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* 1. Strict Read-Only Protocol Assurance */}
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
            Non-Destructive Read-Only Operation Protocol
          </strong>
          <span style={{ color: '#cbd5e1' }}>
            PhantomTrace operates strictly in passive forensic inspection mode. The platform intentionally prohibits automated process termination, file deletion, quarantine modification, or shell execution to preserve evidentiary integrity for legal and incident-response standards.
          </span>
        </div>
      </div>

      {/* 2. Investigation Guidance: "WHAT SHOULD I INVESTIGATE?" */}
      <Card
        title="What Should I Investigate?"
        subtitle="Forensic triage guide tailored to observed memory and behavioral indicators"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* A. If Correlated Evidence Exists */}
          {hasCorrelation && (
            <div 
              style={{ 
                background: 'rgba(0, 229, 255, 0.04)', 
                borderLeft: '4px solid var(--pt-cyan)', 
                borderRadius: '0 6px 6px 0', 
                padding: '0.85rem 1rem' 
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                <Layers size={16} style={{ color: '#00e5ff' }} />
                <strong style={{ color: '#ffffff', fontSize: '0.86rem' }}>
                  Correlated Investigation Priority (High Confidence Vector)
                </strong>
              </div>
              <ul style={{ margin: 0, paddingLeft: '1.25rem', fontSize: '0.82rem', color: '#cbd5e1', lineHeight: 1.6 }}>
                <li>Review both memory and behavioral evidence categories together to understand the multi-stage execution vector.</li>
                <li>Verify whether the co-occurring process activity was anticipated or part of authorized administrative tooling.</li>
                <li>Examine the correlation indicators connecting volatile memory buffers with live process lineage.</li>
                <li>Review the complete process ancestry and parent-child hierarchy under anomalous inception.</li>
              </ul>
            </div>
          )}

          {/* B. If Memory Evidence Exists */}
          {hasMemory && (
            <div 
              style={{ 
                background: 'rgba(239, 68, 68, 0.04)', 
                borderLeft: '4px solid #ef4444', 
                borderRadius: '0 6px 6px 0', 
                padding: '0.85rem 1rem' 
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                <FileCheck2 size={16} style={{ color: '#ef4444' }} />
                <strong style={{ color: '#ffffff', fontSize: '0.86rem' }}>
                  Volatile Memory Heuristics Review
                </strong>
              </div>
              <ul style={{ margin: 0, paddingLeft: '1.25rem', fontSize: '0.82rem', color: '#cbd5e1', lineHeight: 1.6 }}>
                <li>Review the listed memory indicators (e.g. unbacked executable pages, erased PE headers, or inline API hooks).</li>
                <li>Review suspicious memory regions and verify whether code pages correspond to known Microsoft modules or third-party DLLs.</li>
                <li>Check whether the process image ({alert.processName}) is expected on this specific workstation role.</li>
                <li>Review the process binary executable path on disk to check for masquerading or path spoofing.</li>
                <li>Compare the observed memory allocations with expected baseline software behavior.</li>
              </ul>
            </div>
          )}

          {/* C. If Behavior Evidence Exists */}
          {hasBehavior && (
            <div 
              style={{ 
                background: 'rgba(249, 115, 22, 0.04)', 
                borderLeft: '4px solid #f97316', 
                borderRadius: '0 6px 6px 0', 
                padding: '0.85rem 1rem' 
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                <Terminal size={16} style={{ color: '#f97316' }} />
                <strong style={{ color: '#ffffff', fontSize: '0.86rem' }}>
                  Process Lineage & Execution Syntax Review
                </strong>
              </div>
              <ul style={{ margin: 0, paddingLeft: '1.25rem', fontSize: '0.82rem', color: '#cbd5e1', lineHeight: 1.6 }}>
                <li>Review the complete command-line invocation captured during scanning for hidden flags, execution bypasses, or encoded blobs.</li>
                <li>Confirm whether the command invocation was initiated by a legitimate user session or automated task scheduler.</li>
                <li>Review the parent process and investigate if the spawning relationship matches standard system architecture.</li>
                <li>Check the user security context (e.g., SYSTEM vs. interactive user profile) under which the process executed.</li>
              </ul>
            </div>
          )}

          {/* Baseline if neither is heavily flagged */}
          {!hasMemory && !hasBehavior && (
            <div 
              style={{ 
                background: 'rgba(16, 185, 129, 0.04)', 
                borderLeft: '4px solid #10b981', 
                borderRadius: '0 6px 6px 0', 
                padding: '0.85rem 1rem' 
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                <Search size={16} style={{ color: '#10b981' }} />
                <strong style={{ color: '#ffffff', fontSize: '0.86rem' }}>
                  Standard Baseline Verification
                </strong>
              </div>
              <ul style={{ margin: 0, paddingLeft: '1.25rem', fontSize: '0.82rem', color: '#cbd5e1', lineHeight: 1.6 }}>
                <li>Confirm that the process binary corresponds to verified vendor signatures.</li>
                <li>Review recent software deployments or system updates on the target host.</li>
                <li>Verify that no outbound network connections deviate from established security baselines.</li>
              </ul>
            </div>
          )}
        </div>
      </Card>

      {/* 3. Recommended Response Steps for Analyst */}
      <Card
        title="Recommended Response Protocol"
        subtitle="Ordered, non-destructive investigation steps for security operations analysts"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {[
            {
              step: 1,
              title: 'Verify Endpoint Context & Software Role',
              desc: `Verify whether ${alert.processName} (PID: ${alert.pid}) is an authorized application for this host and matches assigned operational workloads.`,
            },
            {
              step: 2,
              title: 'Audit Process Path & Parent Hierarchy',
              desc: 'Confirm the executable path on disk against verified operating system hashes and inspect parent-child process relationship trees.',
            },
            {
              step: 3,
              title: 'Inspect Preserved Memory Indicators',
              desc: 'Review volatile indicators, unbacked code allocations, and inline hook heuristics documented in this alert.',
            },
            {
              step: 4,
              title: 'Review Behavioral Signals & Command Syntax',
              desc: 'Inspect arguments, script parameters, and execution flags for obfuscation, bypass switches, or encoded streams.',
            },
            {
              step: 5,
              title: 'Compare Against Application Baseline',
              desc: 'Cross-reference the observed behavioral profile against known vendor documentation and corporate environment baselines.',
            },
            {
              step: 6,
              title: 'Escalate or Conclude Investigation',
              desc: 'If the telemetry cannot be definitively attributed to authorized system operations, escalate the incident to Tier 2/3 for detailed memory dump triage.',
            },
          ].map((item) => (
            <div 
              key={item.step}
              style={{ 
                display: 'flex', 
                gap: '1rem', 
                alignItems: 'flex-start', 
                padding: '0.85rem 1rem',
                background: 'rgba(9, 15, 26, 0.65)',
                border: '1px solid var(--pt-border-subtle)',
                borderRadius: '6px'
              }}
            >
              <div 
                style={{ 
                  width: '26px', 
                  height: '26px', 
                  borderRadius: '50%', 
                  background: 'rgba(0, 229, 255, 0.12)', 
                  border: '1px solid rgba(0, 229, 255, 0.35)', 
                  color: '#00e5ff', 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'center', 
                  fontSize: '0.78rem',
                  fontWeight: 700,
                  flexShrink: 0
                }}
              >
                {item.step}
              </div>

              <div style={{ flex: 1 }}>
                <strong style={{ fontSize: '0.86rem', color: '#ffffff', display: 'block', marginBottom: '0.2rem' }}>
                  {item.title}
                </strong>
                <span style={{ fontSize: '0.8rem', color: '#94a3b8', lineHeight: 1.5 }}>
                  {item.desc}
                </span>
              </div>

              <ArrowRight size={14} style={{ color: '#64748b', marginTop: '4px', flexShrink: 0 }} />
            </div>
          ))}

          {/* Scanner-Provided Actions (if explicitly provided in alert payload) */}
          {alert.recommendedActions && alert.recommendedActions.length > 0 && (
            <div style={{ marginTop: '0.5rem', padding: '0.85rem 1rem', background: 'rgba(5, 9, 17, 0.85)', borderRadius: '6px', border: '1px solid var(--pt-border-subtle)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
                <ShieldCheck size={14} style={{ color: '#00e5ff' }} />
                <span style={{ fontSize: '0.76rem', color: '#38bdf8', fontWeight: 600, textTransform: 'uppercase' }}>
                  Scanner Prescriptive Triage Recommendations
                </span>
              </div>
              <ul style={{ margin: 0, paddingLeft: '1.25rem', fontSize: '0.8rem', color: '#cbd5e1', lineHeight: 1.6 }}>
                {alert.recommendedActions.map((action, i) => (
                  <li key={i}>{action}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Careful Security Language Disclaimer */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.74rem', color: '#64748b', marginTop: '0.5rem' }}>
            <AlertTriangle size={13} style={{ color: '#f59e0b', flexShrink: 0 }} />
            <span>Analysis Guidance: PhantomTrace provides objective telemetry signals to assist analyst evaluation. Do not classify processes as malicious or initiate containment without verifying contextual authorization.</span>
          </div>
        </div>
      </Card>
    </div>
  );
};
