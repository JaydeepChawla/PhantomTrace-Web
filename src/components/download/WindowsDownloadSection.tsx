import React from 'react';
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
  ArrowRight
} from 'lucide-react';
import { Logo } from '../common/Logo';
import { DownloadAgentButton } from '../agent/DownloadAgentButton';

export const WindowsDownloadSection: React.FC = () => {
  const steps = [
    {
      step: '01',
      title: 'Download Agent',
      badge: 'Signed Executable & Backend API',
      badgeColor: '#00e5ff',
      icon: <Download size={22} style={{ color: '#00e5ff' }} />,
      desc: 'Download the verified PhantomTrace Windows Agent installer (PhantomTrace_Agent_Setup.exe) or standalone binary (PhantomTrace-Agent.exe) using the verified backend endpoint. Zero Python runtime or terminal dependencies required.',
      detail: 'Available directly via the download button below or via GET /api/agent/download?installer=true from the backend.'
    },
    {
      step: '02',
      title: 'Install Agent',
      badge: 'Authenticode SHA-256 Inno Setup',
      badgeColor: '#38bdf8',
      icon: <CheckCircle2 size={22} style={{ color: '#38bdf8' }} />,
      desc: 'Run the standalone setup executable. Installs standard user-mode files into %LocalAppData%\\PhantomTraceAgent with zero system file mutation. If prompted by Windows SmartScreen, click "More info" then "Run anyway".',
      detail: 'No intrusive kernel drivers or risky hooks installed. Preserves full system integrity and compliance.'
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
      badgeColor: '#f43f5e',
      icon: <UploadCloud size={22} style={{ color: '#f43f5e' }} />,
      desc: 'Trigger the real Windows scanner by clicking "SCAN MY PC" on the web dashboard (or via POST /api/scan/start on localhost). Evaluates unbacked executable memory regions, PAGE_EXECUTE_READWRITE permissions, and anomalous process trees.',
      detail: 'Passive memory scanning only. Never alters RAM, terminates active processes, or modifies filesystem records.'
    },
    {
      step: '06',
      title: 'Review Results',
      badge: 'Unified SOC Telemetry & Triage',
      badgeColor: '#34d399',
      icon: <ShieldCheck size={22} style={{ color: '#34d399' }} />,
      desc: 'Completed scan telemetry (scan_results.json) syncs to your console. Review fileless indicators in Threat Alerts (/alerts), inspect memory maps in Processes (/processes), examine history in (/history), and export reports in (/reports).',
      detail: 'Full evidence preservation for incident response, malware classification, and compliance audits.'
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
          <span>Endpoint Protection • Windows x64</span>
        </div>

        <h2 style={{ fontSize: '2.2rem', fontWeight: 800, color: '#ffffff', letterSpacing: '-0.02em', marginBottom: '0.5rem' }}>
          WINDOWS AGENT INSTALLATION &amp; PC PROTECTION
        </h2>

        <p style={{ fontSize: '1.1rem', color: '#00e5ff', fontStyle: 'italic', fontWeight: 500, marginBottom: '0.85rem' }}>
          "Trace what others can't see."
        </p>

        <p style={{ fontSize: '0.98rem', color: '#94a3b8', maxWidth: '720px', margin: '0 auto', lineHeight: 1.6 }}>
          Download the verified PhantomTrace Windows scanner and perform read-only security analysis of your Windows endpoint.
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
                  PhantomTrace Windows Agent
                </h3>
                <div style={{ fontSize: '0.8rem', color: '#38bdf8', fontWeight: 600 }}>
                  PhantomTrace Windows Release 1.0 (x64)
                </div>
              </div>
            </div>

            <p style={{ fontSize: '0.92rem', color: '#cbd5e1', lineHeight: 1.6, marginBottom: '1.5rem' }}>
              Download and run the PhantomTrace Windows scanner on your Windows PC. It analyzes running processes and memory for suspicious indicators without modifying your files.
            </p>

            {/* Specification Badges Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem', marginBottom: '1.5rem' }}>
              <div style={{ background: 'rgba(5, 9, 17, 0.6)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.85rem' }}>
                <div style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Version</div>
                <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#f8fafc' }}>Release 1.0 (Signed)</div>
              </div>
              <div style={{ background: 'rgba(5, 9, 17, 0.6)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.85rem' }}>
                <div style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Platform</div>
                <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#f8fafc' }}>Windows 10 / 11 (x64)</div>
              </div>
              <div style={{ background: 'rgba(5, 9, 17, 0.6)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.85rem' }}>
                <div style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Operation Mode</div>
                <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#34d399' }}>100% Read-Only Mode</div>
              </div>
              <div style={{ background: 'rgba(5, 9, 17, 0.6)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.85rem' }}>
                <div style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Local Service</div>
                <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#38bdf8' }}>127.0.0.1:49152</div>
              </div>
            </div>

            <div style={{ fontSize: '0.82rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <Info size={14} style={{ color: '#00e5ff', flexShrink: 0 }} />
              <span>After scanning, telemetry can be synchronized with the PhantomTrace operations dashboard.</span>
            </div>
          </div>

          {/* Right Column: Download Actions & Quickstart */}
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
                Verified Windows Release
              </div>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#ffffff' }}>
                PhantomTrace_Agent_Setup.exe
              </div>
            </div>

            {/* Preserved Official Download CTA Button */}
            <DownloadAgentButton
              variant="primary"
              size="lg"
              style={{ width: '100%', justifyContent: 'center' }}
            />

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
                <ExternalLink size={13} />
                <span>GitHub Releases</span>
              </a>

              <Link
                to="/dashboard"
                className="pt-btn pt-btn-cyber"
                style={{ flex: 1, justifyContent: 'center', padding: '0.55rem 0.75rem', fontSize: '0.8rem', display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}
                title="Go to Operations Dashboard"
              >
                <span>Console Dashboard</span>
                <ArrowRight size={13} />
              </Link>
            </div>

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

      {/* Six Numbered Step Cards */}
      <div style={{ marginBottom: '3.5rem' }}>
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <h3 style={{ fontSize: '1.4rem', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.01em' }}>
            Windows Agent Installation Guide
          </h3>
          <p style={{ fontSize: '0.86rem', color: '#94a3b8', marginTop: '0.35rem' }}>
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
                background: 'rgba(10, 18, 34, 0.75)',
                border: '1px solid rgba(0, 229, 255, 0.18)',
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
                      fontSize: '0.78rem',
                      fontFamily: 'var(--font-mono)',
                      color: '#64748b',
                      fontWeight: 700
                    }}
                  >
                    STEP {s.step}
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem', marginBottom: '0.45rem', flexWrap: 'wrap' }}>
                  <h4 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#ffffff', margin: 0 }}>
                    {s.title}
                  </h4>
                </div>

                <div
                  style={{
                    display: 'inline-block',
                    fontSize: '0.7rem',
                    fontWeight: 700,
                    color: s.badgeColor,
                    background: `${s.badgeColor}18`,
                    border: `1px solid ${s.badgeColor}40`,
                    padding: '0.15rem 0.5rem',
                    borderRadius: '4px',
                    marginBottom: '0.75rem'
                  }}
                >
                  {s.badge}
                </div>

                <p style={{ fontSize: '0.84rem', color: '#cbd5e1', lineHeight: 1.55, margin: 0, marginBottom: '0.75rem' }}>
                  {s.desc}
                </p>
              </div>

              <div
                style={{
                  borderTop: '1px solid rgba(255, 255, 255, 0.06)',
                  paddingTop: '0.65rem',
                  fontSize: '0.75rem',
                  color: '#64748b',
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
