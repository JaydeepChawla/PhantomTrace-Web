import React, { useState } from 'react';
import { 
  Download, 
  ShieldCheck, 
  Terminal, 
  Cpu, 
  UploadCloud, 
  CheckCircle2, 
  ExternalLink, 
  Lock, 
  Info,
  Copy,
  Check
} from 'lucide-react';
import { Logo } from '../common/Logo';

export const WindowsDownloadSection: React.FC = () => {
  const [copiedCmd, setCopiedCmd] = useState<boolean>(false);

  // Configurable download asset URL via environment variable
  const configuredDownloadUrl = 
    typeof import.meta !== 'undefined' && import.meta.env?.VITE_WINDOWS_SCANNER_DOWNLOAD_URL
      ? import.meta.env.VITE_WINDOWS_SCANNER_DOWNLOAD_URL
      : null;

  // Official fallback repository release URL
  const officialReleasesUrl = 'https://github.com/JaydeepChawla/PhantomTrace-Web/releases';
  const downloadUrl = configuredDownloadUrl || officialReleasesUrl;
  const isDirectBinary = Boolean(configuredDownloadUrl);

  const handleCopyCommand = () => {
    navigator.clipboard.writeText('.\\PhantomTrace_Windows_Release_1.0.exe --output scan_results.json');
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2500);
  };

  const steps = [
    {
      step: '01',
      title: 'Download',
      desc: 'Obtain PhantomTrace_Windows_Release_1.0.exe. Standalone portable executable with zero installation needed.',
      icon: <Download size={20} style={{ color: '#00e5ff' }} />
    },
    {
      step: '02',
      title: 'Run',
      desc: 'Launch the scanner on your Windows PC via PowerShell, Command Prompt, or direct execution.',
      icon: <Terminal size={20} style={{ color: '#38bdf8' }} />
    },
    {
      step: '03',
      title: 'Scan',
      desc: 'Performs passive read-only analysis across running processes and outputs scan_results.json.',
      icon: <Cpu size={20} style={{ color: '#818cf8' }} />
    },
    {
      step: '04',
      title: 'Sync',
      desc: 'Synchronize scan_results.json with the PhantomTrace dashboard using the authenticated upload integration.',
      icon: <UploadCloud size={20} style={{ color: '#a78bfa' }} />
    },
    {
      step: '05',
      title: 'Review',
      desc: 'Triage volatile memory artifacts, behavioral anomalies, and threat scores on the web console.',
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
                Release Executable
              </div>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#ffffff', fontFamily: 'var(--font-mono)' }}>
                PhantomTrace_Windows_Release_1.0.exe
              </div>
            </div>

            {/* Download CTA Button */}
            <a 
              href={downloadUrl}
              target={isDirectBinary ? '_self' : '_blank'}
              rel="noopener noreferrer"
              className="pt-btn pt-btn-primary"
              style={{ 
                padding: '0.9rem 1.5rem', 
                fontSize: '1rem', 
                fontWeight: 700, 
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center',
                gap: '0.65rem',
                textDecoration: 'none',
                boxShadow: '0 4px 16px rgba(0, 229, 255, 0.3)'
              }}
            >
              <Download size={20} />
              <span>Download for Windows</span>
              {!isDirectBinary && <ExternalLink size={15} style={{ opacity: 0.8 }} />}
            </a>

            {!isDirectBinary && (
              <div 
                style={{ 
                  fontSize: '0.75rem', 
                  color: '#94a3b8', 
                  background: 'rgba(16, 26, 46, 0.8)', 
                  border: '1px solid var(--pt-border-subtle)', 
                  padding: '0.65rem 0.85rem', 
                  borderRadius: '6px',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '0.5rem'
                }}
              >
                <Info size={14} style={{ color: '#38bdf8', marginTop: '2px', flexShrink: 0 }} />
                <span>
                  Official release packages are published in the project’s GitHub Releases repository. Direct mirror URL can be configured via <code style={{ color: '#00e5ff' }}>VITE_WINDOWS_SCANNER_DOWNLOAD_URL</code>.
                </span>
              </div>
            )}

            {/* Quickstart Command Preview */}
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                <span style={{ fontSize: '0.72rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Execution Syntax
                </span>
                <button
                  type="button"
                  onClick={handleCopyCommand}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: copiedCmd ? '#10b981' : '#00e5ff',
                    cursor: 'pointer',
                    fontSize: '0.72rem',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.25rem',
                    padding: '0.1rem 0.3rem'
                  }}
                >
                  {copiedCmd ? <Check size={12} /> : <Copy size={12} />}
                  <span>{copiedCmd ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <pre 
                style={{ 
                  margin: 0, 
                  background: '#040711', 
                  border: '1px solid var(--pt-border-subtle)', 
                  borderRadius: '6px', 
                  padding: '0.65rem 0.85rem', 
                  color: '#38bdf8', 
                  fontFamily: 'var(--font-mono)', 
                  fontSize: '0.78rem',
                  overflowX: 'auto'
                }}
              >
                .\PhantomTrace_Windows_Release_1.0.exe --output scan_results.json
              </pre>
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
