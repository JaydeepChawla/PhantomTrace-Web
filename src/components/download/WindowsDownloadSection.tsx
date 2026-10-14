import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Download,
  ShieldCheck,
  Terminal,
  Cpu,
  UploadCloud,
  CheckCircle2,
  Lock,
  Info,
  ExternalLink,
  ArrowRight,
  Copy,
  Check,
  Layers
} from 'lucide-react';
import { Logo } from '../common/Logo';
import { DownloadAgentButton } from '../agent/DownloadAgentButton';
import { releaseMetadata } from '../../data/releaseMetadata';

export const WindowsDownloadSection: React.FC = () => {
  const [copiedChecksum, setCopiedChecksum] = useState(false);
  const [copiedCommand, setCopiedCommand] = useState(false);

  const handleCopyChecksum = async () => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(releaseMetadata.sha256);
      } else {
        const textarea = document.createElement('textarea');
        textarea.value = releaseMetadata.sha256;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }
      setCopiedChecksum(true);
      setTimeout(() => setCopiedChecksum(false), 3000);
    } catch {
      setCopiedChecksum(true);
      setTimeout(() => setCopiedChecksum(false), 3000);
    }
  };

  const handleCopyCommand = async () => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(releaseMetadata.powershellVerifyCommand);
      } else {
        const textarea = document.createElement('textarea');
        textarea.value = releaseMetadata.powershellVerifyCommand;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }
      setCopiedCommand(true);
      setTimeout(() => setCopiedCommand(false), 3000);
    } catch {
      setCopiedCommand(true);
      setTimeout(() => setCopiedCommand(false), 3000);
    }
  };

  const steps = [
    {
      step: '01',
      title: 'Download Agent',
      badge: 'Standalone Executable & Backend API',
      badgeColor: 'var(--pt-brand-cyan)',
      icon: <Download size={22} style={{ color: 'var(--pt-brand-cyan)' }} />,
      desc: 'Download the verified PhantomTrace Windows Agent installer (PhantomTrace_Agent_Setup.exe) or standalone binary (PhantomTrace-Agent.exe) using the verified backend endpoint. Zero Python runtime or terminal dependencies required.',
      detail: 'Available directly via the download button below or via GET /api/agent/download?installer=true from the backend.'
    },
    {
      step: '02',
      title: 'Install Agent',
      badge: 'SHA-256 Inno Setup Package',
      badgeColor: 'var(--pt-brand-blue)',
      icon: <CheckCircle2 size={22} style={{ color: 'var(--pt-brand-blue)' }} />,
      desc: 'Run the standalone setup executable. Installs standard user-mode files into %LocalAppData%\\PhantomTraceAgent with zero system file mutation. If prompted by Windows SmartScreen, click "More info" then "Run anyway".',
      detail: 'No intrusive kernel drivers or risky hooks installed. Operates with standard user-mode permissions.'
    },
    {
      step: '03',
      title: 'Start Protection',
      badge: 'Localhost Service: 127.0.0.1:49152',
      badgeColor: '#818cf8',
      icon: <Terminal size={22} style={{ color: '#818cf8' }} />,
      desc: 'The agent service launches in the background and listens exclusively on localhost (http://127.0.0.1:49152). Verify active operational status via the built-in HTTP diagnostic probe at /api/status or using the console status monitor.',
      detail: 'Zero network exposure to external interfaces. Operates strictly in passive diagnostic mode.'
    },
    {
      step: '04',
      title: 'Connect Your PC',
      badge: 'Short-Lived 6-Digit Pairing Code',
      badgeColor: '#a78bfa',
      icon: <Cpu size={22} style={{ color: '#a78bfa' }} />,
      desc: 'Navigate to the Operations Dashboard, open the "Scan My PC" panel, and click "Connect This PC". The backend issues a short-lived pairing code (/api/devices/pair) that enrolls your device to your cloud analyst account.',
      detail: 'Pairing generates an authenticated cloud device token without hardcoded passwords or master server keys.'
    },
    {
      step: '05',
      title: 'Scan Your PC',
      badge: '100% Read-Only Forensic Analysis',
      badgeColor: 'var(--pt-status-danger)',
      icon: <UploadCloud size={22} style={{ color: 'var(--pt-status-danger)' }} />,
      desc: 'Trigger the real Windows scanner by clicking "SCAN MY PC" on the web dashboard (or via POST /api/scan/start on localhost). Evaluates unbacked executable memory regions, PAGE_EXECUTE_READWRITE permissions, and anomalous process trees.',
      detail: 'Passive memory scanning only. Never alters RAM, terminates active processes, or modifies filesystem records.'
    },
    {
      step: '06',
      title: 'Review Results',
      badge: 'Unified SOC Telemetry & Triage',
      badgeColor: 'var(--pt-status-success)',
      icon: <ShieldCheck size={22} style={{ color: 'var(--pt-status-success)' }} />,
      desc: 'Completed scan telemetry (scan_results.json) syncs to your console. Review fileless indicators in Threat Alerts (/alerts), inspect memory maps in Processes (/processes), examine history in (/history), and export reports in (/reports).',
      detail: 'Full evidence preservation for incident response, malware classification, and compliance audits.'
    }
  ];

  return (
    <section
      id="download"
      aria-labelledby="windows-download-heading"
      style={{
        maxWidth: 'var(--pt-max-width, 1200px)',
        margin: '0 auto',
        padding: '3.5rem 1.5rem 4.5rem 1.5rem',
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
            padding: '0.35rem 0.9rem',
            borderRadius: '20px',
            background: 'var(--pt-cyan-glow, rgba(0, 209, 255, 0.08))',
            border: '1px solid var(--pt-border-cyan, rgba(0, 209, 255, 0.25))',
            fontSize: '0.75rem',
            fontWeight: 700,
            color: 'var(--pt-brand-cyan)',
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            marginBottom: '0.85rem'
          }}
        >
          <Lock size={12} aria-hidden="true" />
          <span>Endpoint Protection • Windows x64</span>
        </div>

        <h2
          id="windows-download-heading"
          style={{
            fontSize: 'clamp(1.75rem, 3.5vw, 2.35rem)',
            fontWeight: 800,
            color: 'var(--pt-text-primary, #ffffff)',
            letterSpacing: '-0.025em',
            marginBottom: '0.5rem',
            lineHeight: 1.2
          }}
        >
          WINDOWS AGENT INSTALLATION &amp; PC PROTECTION
        </h2>

        <p
          style={{
            fontSize: '1.05rem',
            color: 'var(--pt-brand-cyan)',
            fontStyle: 'italic',
            fontWeight: 500,
            marginBottom: '0.85rem'
          }}
        >
          &ldquo;Trace what others can&apos;t see.&rdquo;
        </p>

        <p
          style={{
            fontSize: '0.98rem',
            color: 'var(--pt-text-secondary, #94a3b8)',
            maxWidth: '720px',
            margin: '0 auto 1.5rem auto',
            lineHeight: 1.65
          }}
        >
          Download the verified PhantomTrace Windows scanner and perform read-only security analysis of your Windows endpoint.
          It analyzes running processes and memory for suspicious indicators without modifying your files.
        </p>

        {/* Explicit Separation Banner */}
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.6rem',
            background: 'rgba(10, 30, 58, 0.65)',
            border: '1px solid var(--pt-border-subtle, rgba(255, 255, 255, 0.12))',
            borderRadius: '8px',
            padding: '0.55rem 1.15rem',
            fontSize: '0.82rem',
            color: 'var(--pt-brand-neutral, #e6e6e6)',
            maxWidth: '820px'
          }}
        >
          <Layers size={15} style={{ color: 'var(--pt-brand-cyan)', flexShrink: 0 }} aria-hidden="true" />
          <span>
            <strong>Separate Components:</strong> The Windows Agent (endpoint memory scanner) and the Chrome Extension (browser threat monitor) are separate installations designed to protect different attack surfaces.
          </span>
        </div>
      </div>

      {/* Main Download Hero Card */}
      <div
        className="pt-card pt-card-cyber"
        style={{
          padding: 'clamp(1.5rem, 3vw, 2.5rem)',
          marginBottom: '3rem',
          background: 'linear-gradient(135deg, rgba(16, 26, 46, 0.96) 0%, rgba(9, 15, 26, 0.98) 100%)',
          border: '1px solid var(--pt-border-cyan, rgba(0, 209, 255, 0.28))',
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5), 0 0 24px rgba(0, 209, 255, 0.08)',
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
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', marginBottom: '1.15rem' }}>
              <Logo variant="windows" height={48} />
              <div>
                <h3 style={{ fontSize: '1.35rem', fontWeight: 800, color: 'var(--pt-text-primary, #ffffff)', margin: 0 }}>
                  PhantomTrace Windows Agent
                </h3>
                <div style={{ fontSize: '0.8rem', color: 'var(--pt-brand-blue, #007bff)', fontWeight: 600 }}>
                  PhantomTrace Windows Release {releaseMetadata.version} (x64)
                </div>
              </div>
            </div>

            <p style={{ fontSize: '0.92rem', color: 'var(--pt-text-secondary, #94a3b8)', lineHeight: 1.6, marginBottom: '1.5rem' }}>
              Download and run the PhantomTrace Windows scanner on your Windows PC. It analyzes running processes and memory for suspicious indicators without modifying your files.
            </p>

            {/* Specification Badges Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem', marginBottom: '1.5rem' }}>
              <div style={{ background: 'rgba(5, 9, 17, 0.75)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.85rem' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--pt-text-muted, #94a3b8)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Version</div>
                <div style={{ fontSize: '0.86rem', fontWeight: 700, color: 'var(--pt-text-primary, #ffffff)' }}>Release {releaseMetadata.version}</div>
              </div>
              <div style={{ background: 'rgba(5, 9, 17, 0.75)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.85rem' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--pt-text-muted, #94a3b8)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Package Size</div>
                <div style={{ fontSize: '0.86rem', fontWeight: 700, color: 'var(--pt-text-primary, #ffffff)' }}>{releaseMetadata.fileSizeFormatted}</div>
              </div>
              <div style={{ background: 'rgba(5, 9, 17, 0.75)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.85rem' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--pt-text-muted, #94a3b8)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Operation Mode</div>
                <div style={{ fontSize: '0.86rem', fontWeight: 700, color: 'var(--pt-status-success, #10b981)' }}>100% Read-Only Mode</div>
              </div>
              <div style={{ background: 'rgba(5, 9, 17, 0.75)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.85rem' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--pt-text-muted, #94a3b8)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Platform</div>
                <div style={{ fontSize: '0.86rem', fontWeight: 700, color: 'var(--pt-brand-cyan, #00d1ff)' }}>Windows 10 / 11 (x64)</div>
              </div>
            </div>

            <div style={{ fontSize: '0.82rem', color: 'var(--pt-text-secondary, #94a3b8)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Info size={14} style={{ color: 'var(--pt-brand-cyan)', flexShrink: 0 }} aria-hidden="true" />
              <span>After scanning, telemetry can be synchronized with the PhantomTrace operations dashboard.</span>
            </div>
          </div>

          {/* Right Column: Download Actions & Quickstart */}
          <div
            style={{
              background: 'rgba(9, 15, 26, 0.85)',
              border: '1px solid var(--pt-border-cyan, rgba(0, 209, 255, 0.2))',
              borderRadius: '10px',
              padding: '1.75rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '1.25rem'
            }}
          >
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--pt-text-muted, #94a3b8)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '0.45rem', fontWeight: 600 }}>
                Verified Windows Deliverable
              </div>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--pt-text-primary, #ffffff)' }}>
                {releaseMetadata.filename}
              </div>
            </div>

            {/* Preserved Official Download CTA Button */}
            <DownloadAgentButton
              variant="primary"
              size="lg"
              style={{ width: '100%', justifyContent: 'center' }}
            />

            {/* SHA-256 Checksum Box with Copy Action */}
            <div
              style={{
                background: '#040711',
                border: '1px solid var(--pt-border-cyan, rgba(0, 209, 255, 0.25))',
                borderRadius: '6px',
                padding: '0.75rem 0.85rem'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--pt-text-muted, #94a3b8)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 700 }}>
                  SHA-256 Release Checksum
                </span>
                <button
                  type="button"
                  id="btn-copy-installer-checksum"
                  onClick={handleCopyChecksum}
                  aria-live="polite"
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: copiedChecksum ? 'var(--pt-status-success, #10b981)' : 'var(--pt-brand-cyan)',
                    cursor: 'pointer',
                    fontSize: '0.72rem',
                    fontWeight: 600,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.25rem',
                    padding: '0.15rem 0.35rem',
                    borderRadius: '4px'
                  }}
                  title="Copy SHA-256 Checksum"
                >
                  {copiedChecksum ? <Check size={12} aria-hidden="true" /> : <Copy size={12} aria-hidden="true" />}
                  <span>{copiedChecksum ? 'Copied' : 'Copy Checksum'}</span>
                </button>
              </div>
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.7rem',
                  color: 'var(--pt-brand-neutral, #e6e6e6)',
                  wordBreak: 'break-all',
                  lineHeight: 1.35
                }}
              >
                {releaseMetadata.sha256}
              </div>
            </div>

            {/* Verification Command Snippet */}
            <div
              style={{
                background: 'rgba(15, 23, 42, 0.75)',
                border: '1px solid var(--pt-border-subtle)',
                borderRadius: '6px',
                padding: '0.65rem 0.85rem'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                <span style={{ fontSize: '0.68rem', color: 'var(--pt-text-muted, #94a3b8)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
                  PowerShell Verification Command
                </span>
                <button
                  type="button"
                  id="btn-copy-verify-cmd"
                  onClick={handleCopyCommand}
                  aria-live="polite"
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: copiedCommand ? 'var(--pt-status-success, #10b981)' : 'var(--pt-brand-blue, #007bff)',
                    cursor: 'pointer',
                    fontSize: '0.7rem',
                    fontWeight: 600,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.25rem',
                    padding: '0.15rem 0.35rem',
                    borderRadius: '4px'
                  }}
                  title="Copy PowerShell Command"
                >
                  {copiedCommand ? <Check size={11} aria-hidden="true" /> : <Copy size={11} aria-hidden="true" />}
                  <span>{copiedCommand ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <code
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.68rem',
                  color: 'var(--pt-brand-cyan, #00d1ff)',
                  wordBreak: 'break-all',
                  display: 'block'
                }}
              >
                {releaseMetadata.powershellVerifyCommand}
              </code>
            </div>

            {/* Secondary Links: Releases & Setup */}
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              <a
                href="https://github.com/JaydeepChawla/PhantomTrace-Web/releases"
                target="_blank"
                rel="noopener noreferrer"
                className="pt-btn pt-btn-secondary"
                style={{ flex: 1, justifyContent: 'center', padding: '0.55rem 0.75rem', fontSize: '0.8rem', display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}
                title="View verified GitHub releases"
              >
                <ExternalLink size={13} aria-hidden="true" />
                <span>GitHub Releases</span>
              </a>

              <Link
                to="/dashboard"
                className="pt-btn pt-btn-cyber"
                style={{ flex: 1, justifyContent: 'center', padding: '0.55rem 0.75rem', fontSize: '0.8rem', display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}
                title="Go to Operations Dashboard"
              >
                <span>Console Dashboard</span>
                <ArrowRight size={13} aria-hidden="true" />
              </Link>
            </div>

            {/* Integrity & SmartScreen Guidance Notice */}
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '0.35rem',
                background: '#040711',
                border: '1px solid var(--pt-border-subtle)',
                borderRadius: '6px',
                padding: '0.65rem 0.85rem',
                fontSize: '0.76rem',
                color: 'var(--pt-text-secondary, #94a3b8)',
                lineHeight: 1.45
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', color: 'var(--pt-text-primary, #ffffff)', fontWeight: 600 }}>
                <CheckCircle2 size={14} style={{ color: 'var(--pt-status-success, #10b981)', flexShrink: 0 }} aria-hidden="true" />
                <span>Integrity &amp; Installation Guidance</span>
              </div>
              <span>
                Comparing your downloaded SHA-256 hash confirms the installer is identical to the verified release.
                Windows SmartScreen may display an unrecognized app notice on new releases until reputation accumulates; click <em>More info</em> then <em>Run anyway</em> to proceed.
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Six Numbered Step Cards */}
      <div style={{ marginBottom: '3.5rem' }}>
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <h3 style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--pt-text-primary, #ffffff)', letterSpacing: '-0.01em' }}>
            Windows Agent Installation Guide
          </h3>
          <p style={{ fontSize: '0.86rem', color: 'var(--pt-text-secondary, #94a3b8)', marginTop: '0.35rem' }}>
            6 numbered steps from standalone download to unified cloud threat triage
          </p>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
            gap: '1.25rem'
          }}
        >
          {steps.map((s) => (
            <div
              key={s.step}
              className="pt-card pt-card-cyber"
              style={{
                padding: '1.5rem',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                position: 'relative',
                background: 'rgba(10, 18, 34, 0.85)',
                border: '1px solid var(--pt-border-subtle)',
                borderRadius: '10px'
              }}
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.85rem' }}>
                  <div
                    style={{
                      width: '42px',
                      height: '42px',
                      borderRadius: '8px',
                      background: 'rgba(0, 209, 255, 0.08)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      border: '1px solid var(--pt-border-cyan, rgba(0, 209, 255, 0.2))'
                    }}
                  >
                    {s.icon}
                  </div>
                  <span
                    style={{
                      fontSize: '0.78rem',
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--pt-text-muted, #94a3b8)',
                      fontWeight: 700
                    }}
                  >
                    STEP {s.step}
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem', marginBottom: '0.45rem', flexWrap: 'wrap' }}>
                  <h4 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--pt-text-primary, #ffffff)', margin: 0 }}>
                    {s.title}
                  </h4>
                </div>

                <div
                  style={{
                    display: 'inline-block',
                    fontSize: '0.7rem',
                    fontWeight: 700,
                    color: s.badgeColor,
                    background: 'rgba(255, 255, 255, 0.04)',
                    border: '1px solid var(--pt-border-subtle)',
                    padding: '0.15rem 0.5rem',
                    borderRadius: '4px',
                    marginBottom: '0.75rem'
                  }}
                >
                  {s.badge}
                </div>

                <p style={{ fontSize: '0.84rem', color: 'var(--pt-text-secondary, #94a3b8)', lineHeight: 1.55, margin: 0, marginBottom: '0.75rem' }}>
                  {s.desc}
                </p>
              </div>

              <div
                style={{
                  borderTop: '1px solid var(--pt-border-subtle)',
                  paddingTop: '0.65rem',
                  fontSize: '0.75rem',
                  color: 'var(--pt-text-muted, #94a3b8)',
                  lineHeight: 1.45
                }}
              >
                {s.detail}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Forensic Integrity & Operational Safety Guarantees */}
      <div
        style={{
          background: 'rgba(9, 15, 26, 0.75)',
          border: '1px solid var(--pt-border-subtle)',
          borderRadius: '10px',
          padding: '1.75rem 2rem'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1rem' }}>
          <ShieldCheck size={22} style={{ color: 'var(--pt-brand-cyan)' }} aria-hidden="true" />
          <h4 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--pt-text-primary, #ffffff)', margin: 0 }}>
            Forensic Integrity &amp; Operational Safety Guarantees
          </h4>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.25rem' }}>
          <div>
            <div style={{ fontSize: '0.86rem', fontWeight: 700, color: 'var(--pt-text-primary, #ffffff)', marginBottom: '0.25rem' }}>
              100% Read-Only Inspection
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--pt-text-secondary, #94a3b8)', lineHeight: 1.5, margin: 0 }}>
              The Windows scanner never modifies process memory, terminates active processes, or alters system files or registry keys.
            </p>
          </div>

          <div>
            <div style={{ fontSize: '0.86rem', fontWeight: 700, color: 'var(--pt-text-primary, #ffffff)', marginBottom: '0.25rem' }}>
              Browser Isolation
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--pt-text-secondary, #94a3b8)', lineHeight: 1.5, margin: 0 }}>
              The web console acts purely as a visualization and triage dashboard. The browser itself never directly interacts with or scans endpoint RAM.
            </p>
          </div>

          <div>
            <div style={{ fontSize: '0.86rem', fontWeight: 700, color: 'var(--pt-text-primary, #ffffff)', marginBottom: '0.25rem' }}>
              Zero Kernel Driver Risk
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--pt-text-secondary, #94a3b8)', lineHeight: 1.5, margin: 0 }}>
              Operates strictly in user mode using standard Windows diagnostic APIs. No intrusive kernel drivers or risky hooks installed.
            </p>
          </div>

          <div>
            <div style={{ fontSize: '0.86rem', fontWeight: 700, color: 'var(--pt-text-primary, #ffffff)', marginBottom: '0.25rem' }}>
              Complementary Security
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--pt-text-secondary, #94a3b8)', lineHeight: 1.5, margin: 0 }}>
              PhantomTrace is a specialized memory and fileless threat detection utility, engineered to complement rather than replace standard antivirus.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
};
