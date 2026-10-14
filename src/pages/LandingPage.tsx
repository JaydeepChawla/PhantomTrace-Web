import React from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  Cpu,
  Activity,
  Layers,
  Lock,
  ArrowRight,
  Eye,
  FileCheck2,
  Database,
  Server,
  Download,
  Globe,
  ShieldCheck,
  AlertTriangle
} from 'lucide-react';
import { Logo } from '../components/common/Logo';
import { Badge } from '../components/common/Badge';
import { WindowsDownloadSection } from '../components/download/WindowsDownloadSection';
import { ChromeExtensionInstallationSection } from '../components/download/ChromeExtensionInstallationSection';

export const LandingPage: React.FC = () => {
  const capabilities = [
    {
      icon: <Cpu size={24} className="text-cyan" />,
      title: 'Volatile Memory Scanning',
      description:
        'Scans unbacked executable memory regions, detects PAGE_EXECUTE_READWRITE permissions, and identifies hollowed PE headers without injecting intrusive kernel hooks.'
    },
    {
      icon: <Activity size={24} style={{ color: '#38bdf8' }} />,
      title: 'Behavioral Process Lineage',
      description:
        'Inspects anomalous parent-child relationships, obfuscated command-line arguments, encoded base64 invocations, and suspicious dynamic memory allocations.'
    },
    {
      icon: <Layers size={24} style={{ color: '#818cf8' }} />,
      title: 'Multi-Vector Threat Correlation',
      description:
        'Cross-correlates volatile memory evidence with behavioral execution patterns, retaining vital forensic evidence even when processes resolve to trusted certificates.'
    },
    {
      icon: <Lock size={24} className="text-success" />,
      title: 'Passive Read-Only Engine',
      description:
        'Strict zero-mutation architecture. Operates entirely in passive forensic inspection mode, preserving volatile system state for incident response and compliance.'
    }
  ];

  return (
    <div className="pt-landing-page" style={{ minHeight: '100vh', background: 'var(--pt-bg-base)', color: 'var(--pt-text-primary)', display: 'flex', flexDirection: 'column' }}>
      {/* Universal Skip to Main Content Link */}
      <a href="#main-content" className="pt-skip-link">
        Skip to main content
      </a>

      {/* Top Navigation */}
      <header
        style={{
          borderBottom: '1px solid var(--pt-border-subtle)',
          background: 'rgba(9, 15, 26, 0.92)',
          backdropFilter: 'blur(12px)',
          WebkitBackdropFilter: 'blur(12px)',
          position: 'sticky',
          top: 0,
          zIndex: 50,
          padding: '0.85rem 2rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem'
        }}
      >
        <Link to="/" style={{ display: 'inline-flex', alignItems: 'center' }} aria-label="PhantomTrace Home">
          <Logo variant="navbar" height={36} />
        </Link>

        <nav aria-label="Primary Navigation" style={{ display: 'flex', alignItems: 'center', gap: '1.25rem', flexWrap: 'wrap' }}>
          <a
            href="#download"
            style={{
              fontSize: '0.85rem',
              color: 'var(--pt-cyan)',
              fontWeight: 600,
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.35rem'
            }}
          >
            <Download size={15} aria-hidden="true" />
            <span>Windows Agent</span>
          </a>
          <a
            href="#browser-protection"
            style={{
              fontSize: '0.85rem',
              color: 'var(--pt-text-secondary)',
              fontWeight: 500,
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.35rem'
            }}
          >
            <Globe size={15} aria-hidden="true" />
            <span>Chrome Extension</span>
          </a>
          <Link
            to="/setup"
            style={{ fontSize: '0.85rem', color: 'var(--pt-text-secondary)', fontWeight: 500 }}
          >
            Setup Guide
          </Link>
          <Link
            to="/alerts"
            style={{ fontSize: '0.85rem', color: 'var(--pt-text-muted)', fontWeight: 500 }}
          >
            Threat Alerts
          </Link>
          <Link
            to="/processes"
            style={{ fontSize: '0.85rem', color: 'var(--pt-text-muted)', fontWeight: 500 }}
          >
            Processes
          </Link>
          <Link
            to="/reports"
            style={{ fontSize: '0.85rem', color: 'var(--pt-text-muted)', fontWeight: 500 }}
          >
            Reports
          </Link>
          <Link
            to="/dashboard"
            className="pt-btn pt-btn-primary"
            style={{ padding: '0.45rem 1rem', fontSize: '0.84rem' }}
          >
            <span>Enter Console</span>
            <ArrowRight size={15} aria-hidden="true" />
          </Link>
        </nav>
      </header>

      {/* Main Content */}
      <main id="main-content" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        {/* Hero Section */}
        <section
          style={{
            padding: '5rem 2rem 4rem 2rem',
            maxWidth: 'var(--pt-width-marketing, 1200px)',
            margin: '0 auto',
            textAlign: 'center',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            position: 'relative'
          }}
        >
          {/* Official Full Logo */}
          <div style={{ marginBottom: '2.25rem', display: 'flex', justifyContent: 'center' }}>
            <Logo
              variant="full"
              height={86}
              style={{ filter: 'drop-shadow(0 4px 28px rgba(0, 209, 255, 0.3))' }}
            />
          </div>

          <h1
            style={{
              fontSize: 'clamp(2.1rem, 4.2vw, 3rem)',
              fontWeight: 800,
              letterSpacing: '-0.025em',
              color: '#ffffff',
              maxWidth: '880px',
              lineHeight: 1.18,
              marginBottom: '0.85rem'
            }}
          >
            See the threats hiding beyond the surface.
          </h1>

          <p
            style={{
              fontSize: '1.25rem',
              color: 'var(--pt-cyan)',
              fontStyle: 'italic',
              fontWeight: 600,
              marginBottom: '1.25rem',
              letterSpacing: '0.015em'
            }}
          >
            &ldquo;Trace what others can&apos;t see.&rdquo;
          </p>

          <p
            style={{
              fontSize: '1.05rem',
              color: 'var(--pt-text-muted)',
              maxWidth: '740px',
              lineHeight: 1.65,
              marginBottom: '2.5rem'
            }}
          >
            PhantomTrace delivers memory and fileless threat detection on Windows endpoints,
            correlating volatile memory anomalies with process lineage and behavioral telemetry in a strict read-only architecture.
          </p>

          {/* Action CTAs */}
          <div
            style={{
              display: 'flex',
              gap: '1rem',
              alignItems: 'center',
              flexWrap: 'wrap',
              justifyContent: 'center',
              marginBottom: '3.5rem'
            }}
          >
            <a
              href="#download"
              className="pt-btn pt-btn-primary"
              style={{ padding: '0.75rem 1.75rem', fontSize: '0.95rem' }}
            >
              <Download size={18} aria-hidden="true" />
              <span>Download Windows Agent</span>
            </a>
            <Link
              to="/dashboard"
              className="pt-btn pt-btn-secondary"
              style={{
                padding: '0.75rem 1.5rem',
                fontSize: '0.95rem',
                border: '1px solid var(--pt-border-cyan)'
              }}
            >
              <span>Explore Dashboard</span>
              <ArrowRight size={17} aria-hidden="true" />
            </Link>
            <Link
              to="/setup"
              className="pt-btn pt-btn-secondary"
              style={{ padding: '0.75rem 1.35rem', fontSize: '0.95rem' }}
            >
              <Shield size={17} className="text-cyan" aria-hidden="true" />
              <span>Setup Guide</span>
            </Link>
            <Link
              to="/alerts"
              className="pt-btn pt-btn-secondary"
              style={{ padding: '0.75rem 1.35rem', fontSize: '0.95rem' }}
            >
              <Eye size={17} style={{ color: 'var(--pt-cyan)' }} aria-hidden="true" />
              <span>View Alerts</span>
            </Link>
          </div>

          {/* Live Product Interface Preview Mockup */}
          <div
            className="pt-card pt-card-cyber"
            style={{
              width: '100%',
              maxWidth: '960px',
              padding: '1.25rem',
              textAlign: 'left',
              background: 'linear-gradient(135deg, rgba(16, 26, 46, 0.95) 0%, rgba(9, 15, 26, 0.98) 100%)',
              border: '1px solid var(--pt-border-cyan)',
              boxShadow: 'var(--pt-shadow-modal)'
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                paddingBottom: '0.85rem',
                marginBottom: '1rem',
                borderBottom: '1px solid var(--pt-border-subtle)',
                flexWrap: 'wrap',
                gap: '0.75rem'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#ef4444', display: 'inline-block' }} />
                <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#eab308', display: 'inline-block' }} />
                <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#10b981', display: 'inline-block' }} />
                <span style={{ fontSize: '0.8rem', color: 'var(--pt-text-muted)', marginLeft: '0.5rem', fontFamily: 'var(--font-mono)' }}>
                  PhantomTrace Forensic Console — Endpoint Telemetry Preview
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Badge level="clean" size="sm">
                  <ShieldCheck size={12} aria-hidden="true" />
                  <span>Read-Only Active</span>
                </Badge>
                <Badge level="info" size="sm">
                  <span>Windows 11 / 10 x64</span>
                </Badge>
              </div>
            </div>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                gap: '1rem',
                marginBottom: '1rem'
              }}
            >
              <div style={{ background: 'rgba(7, 11, 20, 0.75)', padding: '0.85rem', borderRadius: '6px', border: '1px solid var(--pt-border-subtle)' }}>
                <div style={{ fontSize: '0.72rem', color: 'var(--pt-text-muted)', textTransform: 'uppercase' }}>Target Process</div>
                <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#ffffff', fontFamily: 'var(--font-mono)' }}>powershell.exe (PID 4812)</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--pt-status-critical)', marginTop: '0.2rem' }}>Suspicious RWX Allocation</div>
              </div>
              <div style={{ background: 'rgba(7, 11, 20, 0.75)', padding: '0.85rem', borderRadius: '6px', border: '1px solid var(--pt-border-subtle)' }}>
                <div style={{ fontSize: '0.72rem', color: 'var(--pt-text-muted)', textTransform: 'uppercase' }}>Threat Severity</div>
                <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--pt-status-critical)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <AlertTriangle size={15} />
                  <span>Score: 92 — CRITICAL</span>
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--pt-text-muted)', marginTop: '0.2rem' }}>Memory &bull; Correlated Vector</div>
              </div>
              <div style={{ background: 'rgba(7, 11, 20, 0.75)', padding: '0.85rem', borderRadius: '6px', border: '1px solid var(--pt-border-subtle)' }}>
                <div style={{ fontSize: '0.72rem', color: 'var(--pt-text-muted)', textTransform: 'uppercase' }}>Memory Finding</div>
                <div style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--pt-cyan)', fontFamily: 'var(--font-mono)' }}>PAGE_EXECUTE_READWRITE</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--pt-text-muted)', marginTop: '0.2rem' }}>Base 0x00007FF7B40A0000 (64 KB)</div>
              </div>
              <div style={{ background: 'rgba(7, 11, 20, 0.75)', padding: '0.85rem', borderRadius: '6px', border: '1px solid var(--pt-border-subtle)' }}>
                <div style={{ fontSize: '0.72rem', color: 'var(--pt-text-muted)', textTransform: 'uppercase' }}>Command Line Analysis</div>
                <div style={{ fontSize: '0.85rem', fontWeight: 500, color: 'var(--pt-text-secondary)', fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  -enc SQBFAFgAIAAoAE4AZQB3...
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--pt-status-warning)', marginTop: '0.2rem' }}>Base64 Encoded Script Flag</div>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--pt-text-muted)' }}>
              <span>Diagnostic Source: Localhost Scanner (127.0.0.1:49152)</span>
              <span className="text-cyan">Zero State Mutation &bull; Forensic Evidence Intact</span>
            </div>
          </div>
        </section>

        {/* Core Capabilities Section */}
        <section
          style={{
            maxWidth: 'var(--pt-width-marketing, 1200px)',
            margin: '0 auto',
            padding: '2rem 2rem 4.5rem 2rem',
            width: '100%'
          }}
        >
          <div style={{ textAlign: 'center', marginBottom: '2.5rem' }}>
            <h2 style={{ fontSize: '1.75rem', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.015em' }}>
              Core Threat Detection Capabilities
            </h2>
            <p style={{ fontSize: '0.92rem', color: 'var(--pt-text-muted)', marginTop: '0.45rem' }}>
              Built for high-fidelity security visibility without endpoint mutation or operational disruption
            </p>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
              gap: '1.25rem'
            }}
          >
            {capabilities.map((feat) => (
              <div
                key={feat.title}
                className="pt-card pt-card-cyber"
                style={{
                  padding: '1.5rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.85rem',
                  background: 'var(--pt-bg-surface-elevated)'
                }}
              >
                <div
                  style={{
                    width: '44px',
                    height: '44px',
                    borderRadius: '8px',
                    background: 'rgba(0, 209, 255, 0.08)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    border: '1px solid var(--pt-border-cyan)'
                  }}
                  aria-hidden="true"
                >
                  {feat.icon}
                </div>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#ffffff' }}>
                  {feat.title}
                </h3>
                <p style={{ fontSize: '0.86rem', color: 'var(--pt-text-secondary)', lineHeight: 1.6 }}>
                  {feat.description}
                </p>
              </div>
            ))}
          </div>
        </section>

        {/* Windows Agent Installation Section */}
        <WindowsDownloadSection />

        {/* Chrome Extension Installation Section */}
        <ChromeExtensionInstallationSection />

        {/* Architecture Pipeline Section */}
        <section
          style={{
            background: 'rgba(9, 15, 26, 0.78)',
            borderTop: '1px solid var(--pt-border-subtle)',
            borderBottom: '1px solid var(--pt-border-subtle)',
            padding: '4rem 2rem'
          }}
        >
          <div style={{ maxWidth: 'var(--pt-width-narrow, 1000px)', margin: '0 auto', textAlign: 'center' }}>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#ffffff', marginBottom: '0.4rem' }}>
              Enterprise Telemetry Pipeline Architecture
            </h2>
            <p style={{ fontSize: '0.9rem', color: 'var(--pt-text-muted)', marginBottom: '2.5rem' }}>
              Structured forensic pipeline bridging local Windows memory inspection to cloud-based analyst triage
            </p>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '1rem',
                flexWrap: 'wrap'
              }}
            >
              <div
                style={{
                  background: 'var(--pt-bg-surface-elevated)',
                  border: '1px solid var(--pt-border-cyan)',
                  padding: '1rem 1.25rem',
                  borderRadius: '8px',
                  minWidth: '170px',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center'
                }}
              >
                <Logo variant="windows" height={42} style={{ marginBottom: '0.4rem' }} />
                <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#ffffff' }}>PhantomTrace EXE</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--pt-text-muted)' }}>Windows Scanner (Read-Only)</div>
              </div>

              <ArrowRight size={20} className="text-cyan" aria-hidden="true" />

              <div
                style={{
                  background: 'var(--pt-bg-surface-elevated)',
                  border: '1px solid var(--pt-border-subtle)',
                  padding: '1rem 1.25rem',
                  borderRadius: '8px',
                  minWidth: '170px'
                }}
              >
                <FileCheck2 size={24} style={{ color: 'var(--pt-cyan)', margin: '0 auto 0.4rem auto' }} aria-hidden="true" />
                <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#ffffff' }}>scan_results.json</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--pt-text-muted)' }}>Forensic Telemetry File</div>
              </div>

              <ArrowRight size={20} className="text-cyan" aria-hidden="true" />

              <div
                style={{
                  background: 'var(--pt-bg-surface-elevated)',
                  border: '1px solid var(--pt-border-subtle)',
                  padding: '1rem 1.25rem',
                  borderRadius: '8px',
                  minWidth: '170px'
                }}
              >
                <Server size={24} style={{ color: '#818cf8', margin: '0 auto 0.4rem auto' }} aria-hidden="true" />
                <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#ffffff' }}>PhantomTrace API</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--pt-text-muted)' }}>Ingestion &amp; Analysis</div>
              </div>

              <ArrowRight size={20} className="text-cyan" aria-hidden="true" />

              <div
                style={{
                  background: 'var(--pt-bg-surface-elevated)',
                  border: '1px solid var(--pt-border-subtle)',
                  padding: '1rem 1.25rem',
                  borderRadius: '8px',
                  minWidth: '170px'
                }}
              >
                <Database size={24} style={{ color: 'var(--pt-cyan)', margin: '0 auto 0.4rem auto' }} aria-hidden="true" />
                <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#ffffff' }}>PostgreSQL / Supabase</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--pt-text-muted)' }}>Cloud Relational Store</div>
              </div>

              <ArrowRight size={20} className="text-cyan" aria-hidden="true" />

              <div
                style={{
                  background: 'rgba(0, 209, 255, 0.1)',
                  border: '1px solid var(--pt-cyan)',
                  padding: '1rem 1.25rem',
                  borderRadius: '8px',
                  minWidth: '170px'
                }}
              >
                <Shield size={24} className="text-cyan" style={{ margin: '0 auto 0.4rem auto' }} aria-hidden="true" />
                <div style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--pt-cyan)' }}>React Dashboard</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--pt-text-secondary)' }}>Analyst Console</div>
              </div>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer
        style={{
          marginTop: 'auto',
          padding: '2.5rem 2rem',
          borderTop: '1px solid var(--pt-border-subtle)',
          background: 'rgba(5, 9, 17, 0.95)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1.25rem',
          fontSize: '0.82rem',
          color: 'var(--pt-text-muted)'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', flexWrap: 'wrap' }}>
          <Logo variant="navbar" height={26} />
          <span>&bull; Memory &amp; Fileless Threat Detection</span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem', flexWrap: 'wrap' }}>
          <Link to="/setup" style={{ color: 'var(--pt-text-muted)', transition: 'color 0.15s ease' }}>
            Setup &amp; Install
          </Link>
          <Link to="/dashboard" style={{ color: 'var(--pt-text-muted)', transition: 'color 0.15s ease' }}>
            Console Dashboard
          </Link>
          <Link to="/alerts" style={{ color: 'var(--pt-text-muted)', transition: 'color 0.15s ease' }}>
            Threat Alerts
          </Link>
          <Link to="/processes" style={{ color: 'var(--pt-text-muted)', transition: 'color 0.15s ease' }}>
            Processes
          </Link>
          <Link to="/reports" style={{ color: 'var(--pt-text-muted)', transition: 'color 0.15s ease' }}>
            Reports
          </Link>
          <Link to="/settings" style={{ color: 'var(--pt-text-muted)', transition: 'color 0.15s ease' }}>
            Settings
          </Link>
        </div>

        <div>
          &ldquo;Trace what others can&apos;t see.&rdquo; &bull; Strict Read-Only Architecture
        </div>
      </footer>
    </div>
  );
};

export default LandingPage;
