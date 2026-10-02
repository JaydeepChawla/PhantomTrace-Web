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
  Server
} from 'lucide-react';
import { Logo } from '../components/common/Logo';

export const LandingPage: React.FC = () => {
  const features = [
    {
      icon: <Cpu size={24} style={{ color: '#00e5ff' }} />,
      title: 'Memory Analysis',
      description: 'Deep unbacked executable memory scanning, PAGE_EXECUTE_READWRITE heuristic detection, and hollowed PE header analysis without invasive hooking.'
    },
    {
      icon: <Activity size={24} style={{ color: '#38bdf8' }} />,
      title: 'Behavioral Detection',
      description: 'Inspect anomalous parent-child relationships, command-line obfuscation, base64 script flags, and suspicious dynamic memory allocation patterns.'
    },
    {
      icon: <Layers size={24} style={{ color: '#818cf8' }} />,
      title: 'Threat Correlation',
      description: 'Cross-correlate behavioral telemetry with volatile memory artifacts. Preserve memory evidence even when binaries resolve to trusted system certificates.'
    },
    {
      icon: <Lock size={24} style={{ color: '#34d399' }} />,
      title: 'Read-Only Analysis',
      description: 'Zero endpoint state mutation. Operates strictly in passive forensic inspection mode. Preserves volatile evidence for compliance and incident response.'
    }
  ];

  return (
    <div style={{ minHeight: '100vh', background: 'var(--pt-bg-base)', color: '#f8fafc', display: 'flex', flexDirection: 'column' }}>
      {/* Top Navigation with Official Navbar Logo */}
      <header 
        style={{ 
          borderBottom: '1px solid var(--pt-border-subtle)', 
          background: 'rgba(9, 15, 26, 0.85)', 
          backdropFilter: 'blur(12px)',
          position: 'sticky',
          top: 0,
          zIndex: 50,
          padding: '0.85rem 2rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between'
        }}
      >
        <Link to="/" style={{ display: 'inline-flex', alignItems: 'center' }}>
          <Logo variant="navbar" height={38} />
        </Link>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
          <Link to="/alerts" style={{ fontSize: '0.86rem', color: '#94a3b8', fontWeight: 500 }}>
            Threat Alerts
          </Link>
          <Link to="/processes" style={{ fontSize: '0.86rem', color: '#94a3b8', fontWeight: 500 }}>
            Processes
          </Link>
          <Link to="/reports" style={{ fontSize: '0.86rem', color: '#94a3b8', fontWeight: 500 }}>
            Reports
          </Link>
          <Link 
            to="/dashboard" 
            className="pt-btn pt-btn-primary" 
            style={{ padding: '0.45rem 1rem', fontSize: '0.84rem' }}
          >
            <span>Enter Console</span>
            <ArrowRight size={15} />
          </Link>
        </div>
      </header>

      {/* Hero Section with Official Full Logo */}
      <section 
        style={{ 
          padding: '4.5rem 2rem 3.5rem 2rem', 
          maxWidth: '1200px', 
          margin: '0 auto', 
          textAlign: 'center',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center'
        }}
      >
        {/* Official Full Logo Banner */}
        <div style={{ marginBottom: '2rem', display: 'flex', justifyContent: 'center' }}>
          <Logo variant="full" height={88} style={{ filter: 'drop-shadow(0 4px 20px rgba(0, 229, 255, 0.25))' }} />
        </div>

        <h1 
          style={{ 
            fontSize: '2.5rem', 
            fontWeight: 800, 
            letterSpacing: '-0.02em', 
            color: '#ffffff', 
            maxWidth: '850px',
            lineHeight: 1.2,
            marginBottom: '0.85rem'
          }}
        >
          Memory &amp; Fileless Threat Detection
        </h1>

        <p 
          style={{ 
            fontSize: '1.35rem', 
            color: '#00e5ff', 
            fontStyle: 'italic', 
            fontWeight: 500,
            marginBottom: '1.25rem',
            letterSpacing: '0.02em'
          }}
        >
          "Trace what others can't see."
        </p>

        <p 
          style={{ 
            fontSize: '1.05rem', 
            color: '#94a3b8', 
            maxWidth: '720px', 
            lineHeight: 1.6, 
            marginBottom: '2.5rem' 
          }}
        >
          PhantomTrace inspects live process address spaces for stealth shellcode injection, unbacked RWX segments, and reflective memory tampering without disruptive endpoint modifications.
        </p>

        {/* CTA Buttons */}
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
          <Link 
            to="/dashboard" 
            className="pt-btn pt-btn-primary" 
            style={{ padding: '0.75rem 1.75rem', fontSize: '0.95rem' }}
          >
            <span>Launch Operations Dashboard</span>
            <ArrowRight size={18} />
          </Link>
          <Link 
            to="/alerts" 
            className="pt-btn pt-btn-secondary" 
            style={{ padding: '0.75rem 1.5rem', fontSize: '0.95rem' }}
          >
            <Eye size={17} style={{ color: '#00e5ff' }} />
            <span>View Active Alerts (6)</span>
          </Link>
        </div>
      </section>

      {/* Core Features Grid */}
      <section style={{ maxWidth: '1200px', margin: '0 auto', padding: '2rem 2rem 4rem 2rem', width: '100%' }}>
        <div style={{ textAlign: 'center', marginBottom: '2.5rem' }}>
          <h2 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.01em' }}>
            Core Threat Detection Capabilities
          </h2>
          <p style={{ fontSize: '0.88rem', color: '#94a3b8', marginTop: '0.35rem' }}>
            Built for forensic analysts seeking definitive evidence without operational disruption
          </p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1.25rem' }}>
          {features.map((feat) => (
            <div 
              key={feat.title}
              className="pt-card pt-card-cyber"
              style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}
            >
              <div 
                style={{ 
                  width: '44px', 
                  height: '44px', 
                  borderRadius: '8px', 
                  background: 'rgba(0, 229, 255, 0.08)', 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'center',
                  border: '1px solid rgba(0, 229, 255, 0.2)' 
                }}
              >
                {feat.icon}
              </div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#ffffff' }}>
                {feat.title}
              </h3>
              <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.55 }}>
                {feat.description}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* Architecture Flow Diagram with Windows Icon */}
      <section 
        style={{ 
          background: 'rgba(9, 15, 26, 0.65)', 
          borderTop: '1px solid var(--pt-border-subtle)',
          borderBottom: '1px solid var(--pt-border-subtle)',
          padding: '3.5rem 2rem'
        }}
      >
        <div style={{ maxWidth: '1000px', margin: '0 auto', textAlign: 'center' }}>
          <h2 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#ffffff', marginBottom: '0.5rem' }}>
            Enterprise Telemetry Pipeline Architecture
          </h2>
          <p style={{ fontSize: '0.85rem', color: '#94a3b8', marginBottom: '2.5rem' }}>
            Structured pipeline bridging Windows memory inspection to cloud-based triage
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
            {/* Windows Application Branding Node */}
            <div style={{ background: 'rgba(16, 26, 46, 0.8)', border: '1px solid rgba(0, 229, 255, 0.3)', padding: '1rem 1.25rem', borderRadius: '8px', minWidth: '170px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <Logo variant="windows" height={44} style={{ marginBottom: '0.4rem' }} />
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#ffffff' }}>PhantomTrace EXE</div>
              <div style={{ fontSize: '0.72rem', color: '#64748b' }}>Windows Scanner (Read-Only)</div>
            </div>

            <ArrowRight size={20} style={{ color: '#00e5ff' }} />

            <div style={{ background: 'rgba(16, 26, 46, 0.8)', border: '1px solid var(--pt-border-subtle)', padding: '1rem 1.25rem', borderRadius: '8px', minWidth: '170px' }}>
              <FileCheck2 size={24} style={{ color: '#38bdf8', margin: '0 auto 0.4rem auto' }} />
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#ffffff' }}>scan_results.json</div>
              <div style={{ fontSize: '0.72rem', color: '#64748b' }}>Forensic Telemetry File</div>
            </div>

            <ArrowRight size={20} style={{ color: '#00e5ff' }} />

            <div style={{ background: 'rgba(16, 26, 46, 0.8)', border: '1px solid var(--pt-border-subtle)', padding: '1rem 1.25rem', borderRadius: '8px', minWidth: '170px' }}>
              <Server size={24} style={{ color: '#818cf8', margin: '0 auto 0.4rem auto' }} />
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#ffffff' }}>PhantomTrace API</div>
              <div style={{ fontSize: '0.72rem', color: '#64748b' }}>Ingestion &amp; Analysis</div>
            </div>

            <ArrowRight size={20} style={{ color: '#00e5ff' }} />

            <div style={{ background: 'rgba(16, 26, 46, 0.8)', border: '1px solid var(--pt-border-subtle)', padding: '1rem 1.25rem', borderRadius: '8px', minWidth: '170px' }}>
              <Database size={24} style={{ color: '#f59e0b', margin: '0 auto 0.4rem auto' }} />
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#ffffff' }}>Firebase Cloud</div>
              <div style={{ fontSize: '0.72rem', color: '#64748b' }}>Realtime Firestore</div>
            </div>

            <ArrowRight size={20} style={{ color: '#00e5ff' }} />

            <div style={{ background: 'rgba(0, 229, 255, 0.1)', border: '1px solid #00e5ff', padding: '1rem 1.25rem', borderRadius: '8px', minWidth: '170px' }}>
              <Shield size={24} style={{ color: '#00e5ff', margin: '0 auto 0.4rem auto' }} />
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#00e5ff' }}>React Dashboard</div>
              <div style={{ fontSize: '0.72rem', color: '#cbd5e1' }}>Analyst Console</div>
            </div>
          </div>
        </div>
      </section>

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
          fontSize: '0.78rem',
          color: '#64748b'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
          <Logo variant="navbar" height={26} />
          <span>• Memory &amp; Fileless Threat Detection</span>
        </div>
        <div>
          "Trace what others can't see." • Strict Read-Only Architecture
        </div>
      </footer>
    </div>
  );
};
