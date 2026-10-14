import React from 'react';
import { Link } from 'react-router-dom';
import { LayoutDashboard, ArrowRight, ArrowLeft } from 'lucide-react';
import { SetupOnboardingSection } from '../components/onboarding/SetupOnboardingSection';
import { Logo } from '../components/common/Logo';

export const SetupPage: React.FC = () => {
  return (
    <div style={{ minHeight: '100vh', background: 'var(--pt-bg-base)', color: 'var(--pt-text-primary)', display: 'flex', flexDirection: 'column' }}>
      {/* Universal Skip Link */}
      <a href="#setup-main" className="pt-skip-link">
        Skip to setup checklist
      </a>

      {/* Top Header */}
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
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <Link to="/" style={{ display: 'inline-flex', alignItems: 'center' }} title="Return to PhantomTrace Home">
            <Logo variant="navbar" height={36} />
          </Link>
          <div style={{ height: '24px', width: '1px', background: 'var(--pt-border-subtle)' }} />
          <span style={{ fontSize: '0.85rem', color: 'var(--pt-text-muted)', fontWeight: 500 }}>
            Setup &amp; Onboarding Guide
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Link
            to="/"
            className="pt-btn pt-btn-secondary"
            style={{ padding: '0.45rem 0.95rem', fontSize: '0.82rem' }}
          >
            <ArrowLeft size={14} aria-hidden="true" />
            <span>Home</span>
          </Link>
          <Link
            to="/dashboard"
            className="pt-btn pt-btn-primary"
            style={{ padding: '0.45rem 1rem', fontSize: '0.82rem' }}
          >
            <LayoutDashboard size={14} aria-hidden="true" />
            <span>Enter Console</span>
            <ArrowRight size={14} aria-hidden="true" />
          </Link>
        </div>
      </header>

      {/* Main Setup Experience */}
      <main id="setup-main" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        <SetupOnboardingSection />
      </main>

      {/* Footer */}
      <footer
        style={{
          marginTop: 'auto',
          padding: '1.75rem 2rem',
          borderTop: '1px solid var(--pt-border-subtle)',
          background: 'rgba(5, 9, 17, 0.95)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
          fontSize: '0.8rem',
          color: 'var(--pt-text-muted)'
        }}
      >
        <div>PhantomTrace Endpoint &amp; Browser Protection Setup</div>
        <div>Strict Read-Only Passive Inspection Architecture &bull; Forensic Integrity Preserved</div>
      </footer>
    </div>
  );
};

export default SetupPage;
