import React from 'react';
import {
  Download,
  ShieldCheck,
  Terminal,
  Cpu,
  UploadCloud,
  CheckCircle2,
  Lock,
  Info
} from 'lucide-react';
import { Logo } from '../common/Logo';
import { DownloadAgentButton } from '../agent/DownloadAgentButton';

export const WindowsDownloadSection: React.FC = () => {
  const steps = [
    {
      step: '01',
      title: 'Download',
      desc: 'Download the verified PhantomTrace Windows Agent with one click.',
      icon: <Download size={20} style={{ color: '#00e5ff' }} />
    },
    {
      step: '02',
      title: 'Install',
      desc: 'Run the standalone setup EXE. Installs automatically with zero Python or dependencies needed.',
      icon: <CheckCircle2 size={20} style={{ color: '#38bdf8' }} />
    },
    {
      step: '03',
      title: 'Agent Starts',
      desc: 'The agent service starts automatically in the background on 127.0.0.1:49152.',
      icon: <Terminal size={20} style={{ color: '#818cf8' }} />
    },
    {
      step: '04',
      title: 'Pair PC',
      desc: 'Click "Connect This PC" on the dashboard for instant local pairing.',
      icon: <Cpu size={20} style={{ color: '#a78bfa' }} />
    },
    {
      step: '05',
      title: 'Scan',
      desc: 'Click "SCAN MY PC" to trigger the read-only memory and process analysis engine.',
      icon: <UploadCloud size={20} style={{ color: '#f43f5e' }} />
    },
    {
      step: '06',
      title: 'Review',
      desc: 'Inspect real telemetry, process inspections, and threat alerts in the dashboard.',
      icon: <CheckCircle2 size={20} style={{ color: '#34d399' }} />
    }
  ];

  return (
    <section
      id="download"
      style={{
        maxWidth: '1200px',
        margin: '0 auto',
        padding: '3.5rem 2rem 4.5rem 2rem',
        width: '100%'
      }}
    >
      {/* Section Header */}
      <div style={{ textAlign: 'center', marginBottom: '2.5rem' }}>
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.45rem',
            padding: '0.3rem 0.85rem',
            borderRadius: '20px',
            background: 'rgba(0, 229, 255, 0.08)',
            border: '1px solid rgba(0, 229, 255, 0.25)',
            fontSize: '0.75rem',
            fontWeight: 700,
            color: '#00e5ff',
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            marginBottom: '0.75rem'
          }}
        >
          <Lock size={12} />
          <span>Standalone Endpoint Scanner</span>
        </div>
        <h2 style={{ fontSize: '2.2rem', fontWeight: 800, color: '#ffffff', letterSpacing: '-0.02em', marginBottom: '0.5rem' }}>
          PHANTOMTRACE FOR WINDOWS
        </h2>
        <p style={{ fontSize: '1.1rem', color: '#00e5ff', fontStyle: 'italic', fontWeight: 500, marginBottom: '0.85rem' }}>
          "Trace what others can't see."
        </p>
        <p style={{ fontSize: '0.98rem', color: '#94a3b8', maxWidth: '720px', margin: '0 auto', lineHeight: 1.6 }}>
          Download the PhantomTrace Windows scanner and perform a read-only security analysis of your Windows endpoint.
          It analyzes running processes and memory for suspicious indicators without modifying your files.
        </p>
      </div>

      {/* Main Download Hero Card */}
      <div
        className="pt-card pt-card-cyber"
        style={{
          padding: '2.5rem',
          marginBottom: '3rem',
          background: 'linear-gradient(135deg, rgba(16, 26, 46, 0.95) 0%, rgba(9, 15, 26, 0.98) 100%)',
          border: '1px solid rgba(0, 229, 255, 0.25)',
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.4), 0 0 20px rgba(0, 229, 255, 0.08)',
          position: 'relative',
          overflow: 'hidden'
        }}
      >
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
            gap: '2.5rem',
            alignItems: 'center'
          }}
        >
          {/* Left Column: Product Information & Specs */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', marginBottom: '1rem' }}>
              <Logo variant="windows" height={48} />
              <div>
                <h3 style={{ fontSize: '1.35rem', fontWeight: 800, color: '#ffffff', margin: 0 }}>
                  PhantomTrace Windows Scanner
                </h3>
                <div style={{ fontSize: '0.8rem', color: '#38bdf8', fontWeight: 600 }}>
                  PhantomTrace Windows Release 1.0
                </div>
              </div>
            </div>

            <p style={{ fontSize: '0.92rem', color: '#cbd5e1', lineHeight: 1.6, marginBottom: '1.5rem' }}>
              Download and run the PhantomTrace Windows scanner on your Windows PC. It analyzes running processes and memory for suspicious indicators without modifying your files.
            </p>

            {/* Specification Badges Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem', marginBottom: '1.75rem' }}>
              <div style={{ background: 'rgba(5, 9, 17, 0.6)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.85rem' }}>
                <div style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Version</div>
                <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#f8fafc' }}>Release 1.0</div>
              </div>
              <div style={{ background: 'rgba(5, 9, 17, 0.6)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.85rem' }}>
                <div style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Platform</div>
                <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#f8fafc' }}>Windows (x64)</div>
              </div>
              <div style={{ background: 'rgba(5, 9, 17, 0.6)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.85rem' }}>
                <div style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Operation Mode</div>
                <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#34d399' }}>Read-only analysis</div>
              </div>
              <div style={{ background: 'rgba(5, 9, 17, 0.6)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.85rem' }}>
                <div style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>System Impact</div>
                <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#38bdf8' }}>No file modification</div>
              </div>
            </div>

            <div style={{ fontSize: '0.82rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <Info size={14} style={{ color: '#00e5ff', flexShrink: 0 }} />
              <span>After scanning, results can be synchronized with the PhantomTrace dashboard.</span>
            </div>
          </div>

          {/* Right Column: Download Actions & CLI Quickstart */}
          <div
            style={{
              background: 'rgba(9, 15, 26, 0.75)',
              border: '1px solid rgba(0, 229, 255, 0.2)',
              borderRadius: '10px',
              padding: '1.75rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '1.25rem'
            }}
          >
            <div>
              <div style={{ fontSize: '0.75rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '0.45rem', fontWeight: 600 }}>
                Windows Agent
              </div>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#ffffff' }}>
                Windows 10 / 11 (64-bit)
              </div>
            </div>

            {/* Download CTA Button */}
            <DownloadAgentButton
              variant="primary"
              size="lg"
              style={{ width: '100%', justifyContent: 'center' }}
            />

            {/* Quickstart Notice */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                background: '#040711',
                border: '1px solid var(--pt-border-subtle)',
                borderRadius: '6px',
                padding: '0.65rem 0.85rem',
                fontSize: '0.8rem',
                color: '#94a3b8'
              }}
            >
              <CheckCircle2 size={16} style={{ color: '#10b981', flexShrink: 0 }} />
              <span>Standalone executable with zero Python or terminal setup required.</span>
            </div>
          </div>
        </div>
      </div>

      {/* "How It Works" 5-Step Pipeline */}
      <div style={{ marginBottom: '3.5rem' }}>
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <h3 style={{ fontSize: '1.4rem', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.01em' }}>
            How It Works: End-to-End Analysis Lifecycle
          </h3>
          <p style={{ fontSize: '0.86rem', color: '#94a3b8', marginTop: '0.35rem' }}>
            5 simple steps from local Windows execution to unified cloud SOC triage
          </p>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '1rem'
          }}
        >
          {steps.map((s) => (
            <div
              key={s.step}
              className="pt-card pt-card-cyber"
              style={{
                padding: '1.25rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.65rem',
                position: 'relative'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div
                  style={{
                    width: '36px',
                    height: '36px',
                    borderRadius: '6px',
                    background: 'rgba(0, 229, 255, 0.08)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    border: '1px solid rgba(0, 229, 255, 0.2)'
                  }}
                >
                  {s.icon}
                </div>
                <span
                  style={{
                    fontSize: '0.75rem',
                    fontFamily: 'var(--font-mono)',
                    color: '#64748b',
                    fontWeight: 700
                  }}
                >
                  STEP {s.step}
                </span>
              </div>
              <h4 style={{ fontSize: '1rem', fontWeight: 700, color: '#ffffff', margin: 0 }}>
                {s.title}
              </h4>
              <p style={{ fontSize: '0.82rem', color: '#94a3b8', lineHeight: 1.5, margin: 0 }}>
                {s.desc}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Safety & Architecture Guarantees Section */}
      <div
        style={{
          background: 'rgba(9, 15, 26, 0.65)',
          border: '1px solid var(--pt-border-subtle)',
          borderRadius: '10px',
          padding: '1.75rem 2rem'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1rem' }}>
          <ShieldCheck size={22} style={{ color: '#00e5ff' }} />
          <h4 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#ffffff', margin: 0 }}>
            Forensic Integrity &amp; Operational Safety Guarantees
          </h4>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.25rem' }}>
          <div>
            <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#f8fafc', marginBottom: '0.25rem' }}>
              100% Read-Only Inspection
            </div>
            <p style={{ fontSize: '0.8rem', color: '#94a3b8', lineHeight: 1.5, margin: 0 }}>
              The Windows scanner never modifies process memory, terminates active processes, or alters system files or registry keys.
            </p>
          </div>

          <div>
            <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#f8fafc', marginBottom: '0.25rem' }}>
              Browser Isolation
            </div>
            <p style={{ fontSize: '0.8rem', color: '#94a3b8', lineHeight: 1.5, margin: 0 }}>
              The web console acts purely as a visualization and triage dashboard. The browser itself never directly interacts with or scans endpoint RAM.
            </p>
          </div>

          <div>
            <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#f8fafc', marginBottom: '0.25rem' }}>
              Zero Kernel Driver Risk
            </div>
            <p style={{ fontSize: '0.8rem', color: '#94a3b8', lineHeight: 1.5, margin: 0 }}>
              Operates strictly in user mode using standard Windows diagnostic APIs. No intrusive kernel drivers or risky hooks installed.
            </p>
          </div>

          <div>
            <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#f8fafc', marginBottom: '0.25rem' }}>
              Complementary Security
            </div>
            <p style={{ fontSize: '0.8rem', color: '#94a3b8', lineHeight: 1.5, margin: 0 }}>
              PhantomTrace is a specialized memory and fileless threat detection utility, engineered to complement rather than replace standard antivirus.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
};
