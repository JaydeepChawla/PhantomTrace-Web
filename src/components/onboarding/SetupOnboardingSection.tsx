import React, { useState, useEffect, useCallback } from 'react';
import {
  Shield,
  Download,
  Globe,
  CheckCircle2,
  AlertCircle,
  Terminal,
  ExternalLink,
  RefreshCw,
  X,
  Layers,
  ArrowRight
} from 'lucide-react';
import { localAgentService } from '../../services/localAgentService';

export type WindowsChecklistState =
  | 'Not started'
  | 'Downloaded'
  | 'Complete this step'
  | 'Not verified'
  | 'Installed/connected';

export type ExtensionChecklistState =
  | 'Not started'
  | 'Complete this step'
  | 'Not verified'
  | 'Installed/connected';

interface SetupOnboardingSectionProps {
  onContinueToDashboard?: () => void;
}

export const SetupOnboardingSection: React.FC<SetupOnboardingSectionProps> = ({
  onContinueToDashboard: _onContinueToDashboard
}) => {
  // Independent checklist states
  const [windowsState, setWindowsState] = useState<WindowsChecklistState>('Not started');
  const [extensionState] = useState<ExtensionChecklistState>('Not verified');
  const [agentVersion, setAgentVersion] = useState<string | null>(null);

  // Verification loading states
  const [isVerifyingAgent, setIsVerifyingAgent] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  // Post-download modal state
  const [showPostDownloadModal, setShowPostDownloadModal] = useState(false);

  // Active guide tab for Card 2 (developer installation)
  const [extensionGuideTab, setExtensionGuideTab] = useState<'chrome' | 'edge'>('chrome');

  // Load saved local download state on mount
  useEffect(() => {
    try {
      const savedDownload = localStorage.getItem('pt_windows_agent_downloaded');
      if (savedDownload === 'true') {
        setWindowsState('Downloaded');
      }
    } catch {
      // Ignore localStorage errors
    }
  }, []);

  // Genuine Windows Agent Verification probe via 127.0.0.1:49152
  const verifyWindowsAgent = useCallback(async (isAutoProbe = false) => {
    setIsVerifyingAgent(true);
    setVerifyError(null);

    try {
      const status = await localAgentService.checkStatus();
      if (status.connected) {
        setWindowsState('Installed/connected');
        setAgentVersion(status.version || 'v1.0.0');
      } else {
        // If not connected
        setWindowsState((prev) => (prev === 'Downloaded' ? 'Not verified' : 'Complete this step'));
        if (!isAutoProbe) {
          setVerifyError(
            'PhantomTrace Agent service not detected on localhost (127.0.0.1:49152). Please ensure the setup executable was run and launched.'
          );
        }
      }
    } catch {
      setWindowsState((prev) => (prev === 'Downloaded' ? 'Not verified' : 'Complete this step'));
      if (!isAutoProbe) {
        setVerifyError(
          'Unable to reach local agent at 127.0.0.1:49152. Launch the agent on this PC and try again.'
        );
      }
    } finally {
      setIsVerifyingAgent(false);
    }
  }, []);

  // Initial passive probe
  useEffect(() => {
    verifyWindowsAgent(true);
  }, [verifyWindowsAgent]);

  // Handle Download for Windows click
  const handleDownloadWindows = () => {
    try {
      localStorage.setItem('pt_windows_agent_downloaded', 'true');
    } catch {
      // Ignore
    }
    if (windowsState !== 'Installed/connected') {
      setWindowsState('Downloaded');
    }

    // Trigger actual download of the approved installer executable
    const installerUrl = '/downloads/PhantomTrace_Agent_Setup.exe';
    const link = document.createElement('a');
    link.href = installerUrl;
    link.download = 'PhantomTrace_Agent_Setup.exe';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    // Open post-download instructions panel
    setShowPostDownloadModal(true);
  };

  const handleContinueToBrowserSetup = () => {
    setShowPostDownloadModal(false);
    const element = document.getElementById('card-browser-protection');
    if (element) {
      element.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  };

  const handleInstallExtension = (target: 'chrome' | 'edge' = 'chrome') => {
    setExtensionGuideTab(target);
    const guideElement = document.getElementById('guide-browser-extension');
    if (guideElement) {
      guideElement.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      guideElement.focus?.();
    }
  };

  return (
    <section
      id="setup-onboarding"
      aria-labelledby="setup-heading"
      style={{
        maxWidth: 'var(--pt-max-width, 1240px)',
        margin: '0 auto',
        padding: '3rem 1.5rem 5rem 1.5rem',
        width: '100%'
      }}
    >
      {/* Primary Required Header */}
      <div style={{ textAlign: 'center', marginBottom: '2.5rem' }}>
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.45rem',
            padding: '0.35rem 0.95rem',
            borderRadius: '20px',
            background: 'var(--pt-cyan-glow, rgba(0, 209, 255, 0.08))',
            border: '1px solid var(--pt-border-cyan, rgba(0, 209, 255, 0.25))',
            fontSize: '0.74rem',
            fontWeight: 700,
            color: 'var(--pt-brand-cyan)',
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            marginBottom: '0.9rem'
          }}
        >
          <Shield size={13} aria-hidden="true" />
          <span>Endpoint &amp; Browser Protection Suite</span>
        </div>

        <h1
          id="setup-heading"
          style={{
            fontSize: 'clamp(2rem, 4vw, 2.6rem)',
            fontWeight: 800,
            color: 'var(--pt-text-primary, #ffffff)',
            letterSpacing: '-0.025em',
            marginBottom: '0.75rem',
            lineHeight: 1.2
          }}
        >
          Complete Your PhantomTrace Setup
        </h1>

        <p
          style={{
            fontSize: '1.05rem',
            color: 'var(--pt-text-secondary, #94a3b8)',
            maxWidth: '780px',
            margin: '0 auto',
            lineHeight: 1.6,
            fontWeight: 400
          }}
        >
          Install the PhantomTrace Windows Agent and add Browser Protection to complete your setup.
          These are two separate components and must be installed separately.
        </p>
      </div>

      {/* Setup Checklist Summary Bar */}
      <div
        className="pt-card"
        style={{
          marginBottom: '2.5rem',
          padding: '1.25rem 1.75rem',
          background: 'rgba(10, 18, 34, 0.85)',
          border: '1px solid var(--pt-border-cyan, rgba(0, 209, 255, 0.2))',
          borderRadius: '12px',
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '1.25rem'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Layers size={20} style={{ color: 'var(--pt-brand-cyan)' }} aria-hidden="true" />
          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--pt-text-muted, #94a3b8)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>
              Installation Checklist
            </div>
            <div style={{ fontSize: '0.92rem', fontWeight: 700, color: 'var(--pt-text-primary, #ffffff)' }}>
              Two-Component Defense Matrix
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem', flexWrap: 'wrap' }}>
          {/* Windows Agent Status Pill */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <span style={{ fontSize: '0.82rem', color: 'var(--pt-brand-neutral, #e6e6e6)' }}>1. Windows Agent:</span>
            <span
              style={{
                fontSize: '0.75rem',
                fontWeight: 700,
                padding: '0.2rem 0.65rem',
                borderRadius: '12px',
                background:
                  windowsState === 'Installed/connected'
                    ? 'rgba(16, 185, 129, 0.15)'
                    : windowsState === 'Downloaded'
                    ? 'rgba(0, 209, 255, 0.15)'
                    : 'rgba(245, 158, 11, 0.15)',
                color:
                  windowsState === 'Installed/connected'
                    ? 'var(--pt-status-success, #10b981)'
                    : windowsState === 'Downloaded'
                    ? 'var(--pt-brand-cyan, #00d1ff)'
                    : 'var(--pt-status-warning, #f59e0b)',
                border:
                  windowsState === 'Installed/connected'
                    ? '1px solid rgba(16, 185, 129, 0.35)'
                    : windowsState === 'Downloaded'
                    ? '1px solid rgba(0, 209, 255, 0.35)'
                    : '1px solid rgba(245, 158, 11, 0.35)'
              }}
            >
              {windowsState}
            </span>
          </div>

          {/* Browser Protection Status Pill */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <span style={{ fontSize: '0.82rem', color: 'var(--pt-brand-neutral, #e6e6e6)' }}>2. Browser Protection:</span>
            <span
              style={{
                fontSize: '0.75rem',
                fontWeight: 700,
                padding: '0.2rem 0.65rem',
                borderRadius: '12px',
                background:
                  extensionState === 'Installed/connected'
                    ? 'rgba(16, 185, 129, 0.15)'
                    : 'rgba(148, 163, 184, 0.15)',
                color:
                  extensionState === 'Installed/connected'
                    ? 'var(--pt-status-success, #10b981)'
                    : 'var(--pt-text-secondary, #94a3b8)',
                border:
                  extensionState === 'Installed/connected'
                    ? '1px solid rgba(16, 185, 129, 0.35)'
                    : '1px solid rgba(148, 163, 184, 0.35)'
              }}
            >
              {extensionState}
            </span>
          </div>

          {/* Fast Verify Trigger */}
          <button
            type="button"
            onClick={() => verifyWindowsAgent(false)}
            disabled={isVerifyingAgent}
            aria-live="polite"
            className="pt-btn pt-btn-secondary"
            style={{ padding: '0.35rem 0.75rem', fontSize: '0.76rem', display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}
            title="Probe local agent on 127.0.0.1:49152"
          >
            <RefreshCw size={12} className={isVerifyingAgent ? 'pt-spin' : ''} aria-hidden="true" />
            <span>{isVerifyingAgent ? 'Probing...' : 'Check Status'}</span>
          </button>
        </div>
      </div>

      {/* Two Distinct Component Cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
          gap: '2rem',
          alignItems: 'stretch'
        }}
      >
        {/* ========================================================= */}
        {/* CARD 1 — PHANTOMTRACE WINDOWS AGENT                       */}
        {/* ========================================================= */}
        <div
          id="card-windows-agent"
          className="pt-card pt-card-cyber"
          style={{
            padding: '2rem',
            background: 'linear-gradient(145deg, rgba(16, 26, 46, 0.96) 0%, rgba(9, 15, 26, 0.98) 100%)',
            border: '1px solid var(--pt-border-cyan, rgba(0, 209, 255, 0.28))',
            boxShadow: '0 8px 30px rgba(0, 0, 0, 0.45)',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            position: 'relative'
          }}
        >
          <div>
            {/* Header with Title & Windows Icon */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
                <div
                  style={{
                    width: '46px',
                    height: '46px',
                    borderRadius: '10px',
                    background: 'rgba(0, 209, 255, 0.1)',
                    border: '1px solid var(--pt-border-cyan, rgba(0, 209, 255, 0.3))',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--pt-brand-cyan)'
                  }}
                >
                  <Terminal size={24} aria-hidden="true" />
                </div>
                <div>
                  <h2 style={{ fontSize: '1.35rem', fontWeight: 800, color: 'var(--pt-text-primary, #ffffff)', margin: 0 }}>
                    PhantomTrace Windows Agent
                  </h2>
                  <div style={{ fontSize: '0.78rem', color: 'var(--pt-brand-cyan, #00d1ff)', fontWeight: 600 }}>
                    Endpoint &amp; Volatile Memory Scanner (x64)
                  </div>
                </div>
              </div>

              {/* Status Badge */}
              <span
                style={{
                  fontSize: '0.72rem',
                  fontWeight: 700,
                  padding: '0.2rem 0.6rem',
                  borderRadius: '10px',
                  background:
                    windowsState === 'Installed/connected'
                      ? 'rgba(16, 185, 129, 0.2)'
                      : 'rgba(0, 209, 255, 0.15)',
                  color:
                    windowsState === 'Installed/connected'
                      ? 'var(--pt-status-success, #10b981)'
                      : 'var(--pt-brand-cyan, #00d1ff)',
                  border:
                    windowsState === 'Installed/connected'
                      ? '1px solid rgba(16, 185, 129, 0.4)'
                      : '1px solid rgba(0, 209, 255, 0.3)'
                }}
              >
                {windowsState}
              </span>
            </div>

            {/* Description */}
            <p style={{ fontSize: '0.92rem', color: 'var(--pt-text-secondary, #94a3b8)', lineHeight: 1.6, marginBottom: '1.5rem' }}>
              Analyzes running processes, volatile RAM, and unbacked executable regions for suspicious indicators,
              PAGE_EXECUTE_READWRITE heuristics, and anomalous parent-child relationships. Operates in 100% read-only passive inspection mode with zero file mutation.
            </p>

            {/* Feature Highlights Grid */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(2, 1fr)',
                gap: '0.75rem',
                marginBottom: '1.75rem'
              }}
            >
              <div style={{ background: 'rgba(5, 9, 17, 0.75)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.8rem' }}>
                <div style={{ fontSize: '0.68rem', color: 'var(--pt-text-muted, #94a3b8)', textTransform: 'uppercase' }}>Mode</div>
                <div style={{ fontSize: '0.84rem', fontWeight: 700, color: 'var(--pt-status-success, #10b981)' }}>100% Read-Only</div>
              </div>
              <div style={{ background: 'rgba(5, 9, 17, 0.75)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.8rem' }}>
                <div style={{ fontSize: '0.68rem', color: 'var(--pt-text-muted, #94a3b8)', textTransform: 'uppercase' }}>Packaging</div>
                <div style={{ fontSize: '0.84rem', fontWeight: 700, color: 'var(--pt-text-primary, #ffffff)' }}>Standalone EXE</div>
              </div>
              <div style={{ background: 'rgba(5, 9, 17, 0.75)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.8rem' }}>
                <div style={{ fontSize: '0.68rem', color: 'var(--pt-text-muted, #94a3b8)', textTransform: 'uppercase' }}>Local Service</div>
                <div style={{ fontSize: '0.84rem', fontWeight: 700, color: 'var(--pt-brand-cyan, #00d1ff)' }}>127.0.0.1:49152</div>
              </div>
              <div style={{ background: 'rgba(5, 9, 17, 0.75)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.8rem' }}>
                <div style={{ fontSize: '0.68rem', color: 'var(--pt-text-muted, #94a3b8)', textTransform: 'uppercase' }}>Compatibility</div>
                <div style={{ fontSize: '0.84rem', fontWeight: 700, color: 'var(--pt-text-primary, #ffffff)' }}>Windows 10 / 11</div>
              </div>
            </div>

            {/* Installation & First-Run Instructions */}
            <div
              style={{
                background: 'rgba(5, 9, 17, 0.85)',
                border: '1px solid var(--pt-border-cyan, rgba(0, 209, 255, 0.18))',
                borderRadius: '8px',
                padding: '1rem',
                marginBottom: '1.75rem'
              }}
            >
              <div style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--pt-brand-cyan)', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <Terminal size={14} aria-hidden="true" />
                <span>Installation &amp; First-Run Instructions:</span>
              </div>
              <ol style={{ margin: 0, paddingLeft: '1.2rem', fontSize: '0.82rem', color: 'var(--pt-brand-neutral, #e6e6e6)', lineHeight: 1.6 }}>
                <li>Click the <strong>Download for Windows</strong> button below to save <code>PhantomTrace_Agent_Setup.exe</code>.</li>
                <li>Open the downloaded installer file.</li>
                <li>If prompted by Windows SmartScreen, click <em>More info</em> then <em>Run anyway</em>.</li>
                <li>Complete the standard setup. The agent starts automatically in the background as a local service.</li>
                <li>Click <em>Verify Agent Connection</em> below to confirm synchronization.</li>
              </ol>
            </div>
          </div>

          <div>
            {/* Primary Download CTA Button */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <button
                type="button"
                id="btn-download-windows-agent"
                onClick={handleDownloadWindows}
                className="pt-btn pt-btn-primary"
                style={{
                  width: '100%',
                  justifyContent: 'center',
                  padding: '0.85rem 1.5rem',
                  fontSize: '0.96rem',
                  fontWeight: 700
                }}
              >
                <Download size={18} aria-hidden="true" />
                <span>Download for Windows (x64)</span>
              </button>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem' }}>
                <button
                  type="button"
                  onClick={() => verifyWindowsAgent(false)}
                  disabled={isVerifyingAgent}
                  aria-live="polite"
                  className="pt-btn pt-btn-cyber"
                  style={{ flex: 1, padding: '0.55rem 0.85rem', fontSize: '0.8rem', justifyContent: 'center' }}
                >
                  <RefreshCw size={13} className={isVerifyingAgent ? 'pt-spin' : ''} aria-hidden="true" />
                  <span>{isVerifyingAgent ? 'Verifying...' : 'Verify Agent Connection'}</span>
                </button>

                <a
                  href="https://github.com/JaydeepChawla/PhantomTrace-Web/releases"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="pt-btn pt-btn-secondary"
                  style={{ padding: '0.55rem 0.85rem', fontSize: '0.8rem', display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}
                  title="View GitHub Releases & Documentation"
                >
                  <ExternalLink size={13} aria-hidden="true" />
                  <span>Release Notes</span>
                </a>
              </div>

              {/* Verified connection banner */}
              {windowsState === 'Installed/connected' && (
                <div
                  style={{
                    background: 'rgba(16, 185, 129, 0.1)',
                    border: '1px solid rgba(16, 185, 129, 0.3)',
                    borderRadius: '6px',
                    padding: '0.65rem 0.85rem',
                    fontSize: '0.78rem',
                    color: 'var(--pt-status-success, #10b981)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem'
                  }}
                >
                  <CheckCircle2 size={16} style={{ flexShrink: 0 }} aria-hidden="true" />
                  <span>
                    Windows Agent genuinely connected ({agentVersion || 'v1.0.0'}) on 127.0.0.1:49152.
                  </span>
                </div>
              )}

              {verifyError && (
                <div
                  style={{
                    background: 'rgba(239, 68, 68, 0.1)',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                    borderRadius: '6px',
                    padding: '0.65rem 0.85rem',
                    fontSize: '0.76rem',
                    color: '#fca5a5',
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '0.45rem'
                  }}
                >
                  <AlertCircle size={15} style={{ flexShrink: 0, marginTop: '2px' }} aria-hidden="true" />
                  <span>{verifyError}</span>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* ========================================================= */}
        {/* CARD 2 — PHANTOMTRACE BROWSER PROTECTION                  */}
        {/* ========================================================= */}
        <div
          id="card-browser-protection"
          className="pt-card pt-card-cyber"
          style={{
            padding: '2rem',
            background: 'linear-gradient(145deg, rgba(16, 26, 46, 0.96) 0%, rgba(9, 15, 26, 0.98) 100%)',
            border: '1px solid rgba(0, 123, 255, 0.3)',
            boxShadow: '0 8px 30px rgba(0, 0, 0, 0.45)',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            position: 'relative'
          }}
        >
          <div>
            {/* Header with Title & Browser Icon */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
                <div
                  style={{
                    width: '46px',
                    height: '46px',
                    borderRadius: '10px',
                    background: 'rgba(0, 123, 255, 0.12)',
                    border: '1px solid rgba(0, 123, 255, 0.35)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--pt-brand-blue, #007bff)'
                  }}
                >
                  <Globe size={24} aria-hidden="true" />
                </div>
                <div>
                  <h2 style={{ fontSize: '1.35rem', fontWeight: 800, color: 'var(--pt-text-primary, #ffffff)', margin: 0 }}>
                    Browser Protection
                  </h2>
                  <div style={{ fontSize: '0.78rem', color: 'var(--pt-brand-blue, #007bff)', fontWeight: 600 }}>
                    Chrome &amp; Edge Web Threat Monitor (MV3)
                  </div>
                </div>
              </div>

              {/* Status Badge */}
              <span
                style={{
                  fontSize: '0.72rem',
                  fontWeight: 700,
                  padding: '0.2rem 0.6rem',
                  borderRadius: '10px',
                  background: 'rgba(148, 163, 184, 0.15)',
                  color: 'var(--pt-text-secondary, #94a3b8)',
                  border: '1px solid rgba(148, 163, 184, 0.3)'
                }}
              >
                {extensionState}
              </span>
            </div>

            {/* Description */}
            <p style={{ fontSize: '0.92rem', color: 'var(--pt-text-secondary, #94a3b8)', lineHeight: 1.6, marginBottom: '1.5rem' }}>
              Inspects visited domains in real-time against threat intelligence lists and heuristic scoring models.
              Displays non-destructive warning interstitials on phishing and malware domains with zero transmission of passwords, queries, or browsing history.
            </p>

            {/* Extension Installation Guide Container */}
            <div
              id="guide-browser-extension"
              tabIndex={-1}
              style={{
                background: 'rgba(5, 9, 17, 0.85)',
                border: '1px solid rgba(0, 123, 255, 0.25)',
                borderRadius: '8px',
                padding: '1rem',
                marginBottom: '1.5rem',
                outline: 'none'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.65rem' }}>
                <span style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--pt-brand-blue, #007bff)' }}>
                  Extension Installation Guide:
                </span>
                <div style={{ display: 'flex', gap: '0.35rem' }}>
                  <button
                    type="button"
                    onClick={() => setExtensionGuideTab('chrome')}
                    style={{
                      background: extensionGuideTab === 'chrome' ? 'rgba(0, 123, 255, 0.2)' : 'transparent',
                      border: '1px solid ' + (extensionGuideTab === 'chrome' ? 'var(--pt-brand-blue, #007bff)' : 'var(--pt-border-subtle)'),
                      color: extensionGuideTab === 'chrome' ? 'var(--pt-brand-blue, #007bff)' : 'var(--pt-text-secondary, #94a3b8)',
                      borderRadius: '4px',
                      padding: '0.15rem 0.5rem',
                      fontSize: '0.72rem',
                      cursor: 'pointer'
                    }}
                  >
                    Chrome
                  </button>
                  <button
                    type="button"
                    onClick={() => setExtensionGuideTab('edge')}
                    style={{
                      background: extensionGuideTab === 'edge' ? 'rgba(0, 123, 255, 0.2)' : 'transparent',
                      border: '1px solid ' + (extensionGuideTab === 'edge' ? 'var(--pt-brand-blue, #007bff)' : 'var(--pt-border-subtle)'),
                      color: extensionGuideTab === 'edge' ? 'var(--pt-brand-blue, #007bff)' : 'var(--pt-text-secondary, #94a3b8)',
                      borderRadius: '4px',
                      padding: '0.15rem 0.5rem',
                      fontSize: '0.72rem',
                      cursor: 'pointer'
                    }}
                  >
                    Edge
                  </button>
                </div>
              </div>

              <ol style={{ margin: 0, paddingLeft: '1.2rem', fontSize: '0.8rem', color: 'var(--pt-brand-neutral, #e6e6e6)', lineHeight: 1.6 }}>
                <li>Open <strong>{extensionGuideTab === 'chrome' ? 'Google Chrome' : 'Microsoft Edge'}</strong>.</li>
                <li>
                  Navigate to{' '}
                  <code style={{ color: 'var(--pt-brand-cyan, #00d1ff)', background: '#020617', padding: '0.1rem 0.3rem', borderRadius: '3px' }}>
                    {extensionGuideTab === 'chrome' ? 'chrome://extensions' : 'edge://extensions'}
                  </code>
                  .
                </li>
                <li>Enable <strong>Developer mode</strong> using the toggle in the top-right corner.</li>
                <li>Click the <strong>Load unpacked</strong> button.</li>
                <li>
                  Select the existing <code style={{ color: 'var(--pt-brand-blue, #007bff)' }}>browser-extension/</code> folder in the PhantomTrace repository containing <code>manifest.json</code>.
                </li>
                <li>Confirm the extension appears and is enabled with badge active.</li>
                <li>Pin the extension using the browser toolbar Extensions menu for quick access.</li>
              </ol>
            </div>
          </div>

          <div>
            {/* Action Buttons */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <button
                type="button"
                id="btn-add-chrome-extension"
                onClick={() => handleInstallExtension('chrome')}
                className="pt-btn pt-btn-primary"
                style={{
                  width: '100%',
                  justifyContent: 'center',
                  padding: '0.85rem 1.5rem',
                  fontSize: '0.96rem',
                  fontWeight: 700,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.5rem'
                }}
                title="View Chrome extension installation instructions"
              >
                <Globe size={18} aria-hidden="true" />
                <span>Install Chrome Extension</span>
              </button>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem' }}>
                <button
                  type="button"
                  onClick={() => handleInstallExtension('edge')}
                  className="pt-btn pt-btn-secondary"
                  style={{ flex: 1, padding: '0.55rem 0.85rem', fontSize: '0.8rem', justifyContent: 'center', display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}
                >
                  <span>Microsoft Edge Setup</span>
                </button>
                <a
                  href="/downloads/PhantomTrace-Chrome-Extension.zip"
                  download="PhantomTrace-Chrome-Extension.zip"
                  className="pt-btn pt-btn-cyber"
                  style={{ padding: '0.55rem 0.85rem', fontSize: '0.8rem', display: 'inline-flex', alignItems: 'center', gap: '0.35rem', textDecoration: 'none' }}
                  title="Download Extension ZIP Package"
                >
                  <Download size={13} aria-hidden="true" />
                  <span>Download ZIP</span>
                </a>
              </div>

              <div style={{ fontSize: '0.78rem', color: 'var(--pt-text-secondary, #94a3b8)', textAlign: 'center', lineHeight: 1.45 }}>
                Separate installation: You can install and use Browser Protection independently of the Windows agent.
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Post-Download Confirmation Modal / Panel */}
      {showPostDownloadModal && (
        <div
          role="dialog"
          aria-modal="true"
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.75)',
            backdropFilter: 'blur(8px)',
            WebkitBackdropFilter: 'blur(8px)',
            zIndex: 1000,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '1.5rem'
          }}
        >
          <div
            className="pt-card pt-card-cyber"
            style={{
              maxWidth: '560px',
              width: '100%',
              background: '#090f1a',
              border: '1px solid var(--pt-border-cyan, rgba(0, 209, 255, 0.35))',
              borderRadius: '12px',
              padding: '2rem',
              boxShadow: '0 20px 50px rgba(0, 0, 0, 0.8), 0 0 30px rgba(0, 209, 255, 0.15)',
              position: 'relative'
            }}
          >
            <button
              type="button"
              onClick={() => setShowPostDownloadModal(false)}
              style={{
                position: 'absolute',
                top: '1.25rem',
                right: '1.25rem',
                background: 'transparent',
                border: 'none',
                color: 'var(--pt-text-muted, #94a3b8)',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                padding: '0.25rem'
              }}
              title="Close Panel"
            >
              <X size={20} aria-hidden="true" />
            </button>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.25rem' }}>
              <div
                style={{
                  width: '42px',
                  height: '42px',
                  borderRadius: '8px',
                  background: 'rgba(0, 209, 255, 0.12)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--pt-brand-cyan)'
                }}
              >
                <Download size={22} aria-hidden="true" />
              </div>
              <div>
                <h3 style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--pt-text-primary, #ffffff)', margin: 0 }}>
                  Windows Agent Download Started
                </h3>
                <div style={{ fontSize: '0.78rem', color: 'var(--pt-brand-blue, #007bff)' }}>
                  Next Steps to Complete Setup
                </div>
              </div>
            </div>

            <p style={{ fontSize: '0.88rem', color: 'var(--pt-text-secondary, #94a3b8)', lineHeight: 1.6, marginBottom: '1.25rem' }}>
              <code>PhantomTrace_Agent_Setup.exe</code> is downloading. Follow these steps to finish setting up the Windows endpoint scanner:
            </p>

            <div
              style={{
                background: 'rgba(5, 9, 17, 0.75)',
                border: '1px solid var(--pt-border-subtle)',
                borderRadius: '8px',
                padding: '1rem',
                marginBottom: '1.5rem'
              }}
            >
              <ol style={{ margin: 0, paddingLeft: '1.2rem', fontSize: '0.82rem', color: 'var(--pt-brand-neutral, #e6e6e6)', lineHeight: 1.7 }}>
                <li>Open <strong>PhantomTrace_Agent_Setup.exe</strong> from your browser downloads.</li>
                <li>If prompted by Windows Defender SmartScreen, click <em>More info</em> then <em>Run anyway</em>.</li>
                <li>Complete setup. The agent will launch in the background on <strong>127.0.0.1:49152</strong>.</li>
                <li>Remember: Downloading does not mean the agent is running yet until you open the installer.</li>
              </ol>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <button
                type="button"
                onClick={handleContinueToBrowserSetup}
                className="pt-btn pt-btn-primary"
                style={{ width: '100%', justifyContent: 'center', padding: '0.75rem', display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}
              >
                <span>Continue to Browser Protection Setup</span>
                <ArrowRight size={16} aria-hidden="true" />
              </button>

              <button
                type="button"
                onClick={() => setShowPostDownloadModal(false)}
                className="pt-btn pt-btn-secondary"
                style={{ width: '100%', justifyContent: 'center', padding: '0.55rem', fontSize: '0.82rem' }}
              >
                <span>Dismiss &amp; Keep Setup Accessible</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
};
