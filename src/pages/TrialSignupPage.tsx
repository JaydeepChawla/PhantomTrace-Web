import React, { useState, useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import {
  ShieldCheck,
  CheckCircle2,
  AlertCircle,
  ArrowRight,
  ArrowLeft,
  Download,
  Laptop,
  RefreshCw,
  User,
  Mail,
  Building2,
  Check
} from 'lucide-react';
import { Logo } from '../components/common/Logo';
import { dataService } from '../services';

export const TrialSignupPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const returnTo = searchParams.get('returnTo');

  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [organization, setOrganization] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successData, setSuccessData] = useState<{
    uid: string;
    email: string;
    displayName: string;
    expiresAt?: string;
  } | null>(null);

  // Check if an existing session is already active in local storage
  const [existingUser, setExistingUser] = useState<{
    uid: string;
    email: string;
    name: string;
  } | null>(null);

  useEffect(() => {
    try {
      const token = localStorage.getItem('phantomtrace_auth_token') || localStorage.getItem('phantomtrace_session_token');
      const savedEmail = localStorage.getItem('phantomtrace_user_email');
      const savedName = localStorage.getItem('phantomtrace_user_name');
      const savedUid = localStorage.getItem('phantomtrace_user_uid');

      if (token && (savedEmail || savedUid)) {
        setExistingUser({
          uid: savedUid || 'Active Tenant',
          email: savedEmail || 'Registered User',
          name: savedName || 'Security Analyst'
        });
      }
    } catch {
      // Ignore localStorage access errors
    }
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const trimmedEmail = email.trim();
    const trimmedName = displayName.trim() || 'Security Analyst';

    if (!trimmedEmail) {
      setError('Please provide a valid work email address.');
      return;
    }

    // Basic email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(trimmedEmail)) {
      setError('Please enter a valid email address format (e.g. analyst@company.com).');
      return;
    }

    setLoading(true);

    try {
      if (dataService.registerTrial) {
        const res = await dataService.registerTrial(trimmedEmail, trimmedName);
        if (res.success && res.user) {
          setSuccessData({
            uid: res.user.uid,
            email: res.user.email,
            displayName: res.user.displayName,
            expiresAt: res.expiresAt
          });
          setExistingUser(null);
        } else {
          setError(res.message || 'Registration failed. Please verify network status.');
        }
      } else {
        setError('Registration service is currently unavailable.');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Network error';
      setError(`Unable to connect to PhantomTrace registration service: ${msg}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', background: 'var(--pt-bg-base)', color: 'var(--pt-text-primary)', display: 'flex', flexDirection: 'column' }}>
      {/* Universal Skip Link */}
      <a href="#trial-main" className="pt-skip-link">
        Skip to registration form
      </a>

      {/* Header */}
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
        <Link to="/" style={{ display: 'inline-flex', alignItems: 'center' }} title="PhantomTrace Home">
          <Logo variant="navbar" height={36} />
        </Link>

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
            <span>Enter Console</span>
            <ArrowRight size={14} aria-hidden="true" />
          </Link>
        </div>
      </header>

      {/* Main Content */}
      <main
        id="trial-main"
        style={{
          flex: 1,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '3rem 1.5rem 5rem 1.5rem',
          maxWidth: '680px',
          width: '100%',
          margin: '0 auto'
        }}
      >
        <div style={{ width: '100%' }}>
          {/* Referral Notice if referred from PC Pairing dialog */}
          {returnTo === 'pair' && !successData && (
            <div
              style={{
                marginBottom: '1.5rem',
                padding: '0.85rem 1.25rem',
                borderRadius: '8px',
                background: 'rgba(0, 229, 255, 0.08)',
                border: '1px solid rgba(0, 229, 255, 0.3)',
                display: 'flex',
                alignItems: 'center',
                gap: '0.75rem',
                fontSize: '0.84rem',
                color: '#38bdf8'
              }}
            >
              <Laptop size={18} style={{ flexShrink: 0, color: '#00e5ff' }} aria-hidden="true" />
              <div>
                <strong>Device Pairing:</strong> Complete your free trial registration below. You will be automatically guided to connect your Windows PC immediately after.
              </div>
            </div>
          )}

          {/* Success Card */}
          {successData ? (
            <div
              className="pt-card pt-card-cyber"
              style={{
                padding: '2.5rem 2rem',
                background: 'linear-gradient(135deg, rgba(16, 26, 46, 0.98) 0%, rgba(9, 15, 26, 0.99) 100%)',
                border: '1px solid #10b981',
                boxShadow: '0 20px 50px rgba(0, 0, 0, 0.6), 0 0 24px rgba(16, 185, 129, 0.2)',
                textAlign: 'center'
              }}
              role="status"
            >
              <div
                style={{
                  width: '64px',
                  height: '64px',
                  borderRadius: '50%',
                  background: 'rgba(16, 185, 129, 0.15)',
                  border: '1px solid #10b981',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  margin: '0 auto 1.25rem auto',
                  color: '#10b981'
                }}
              >
                <CheckCircle2 size={36} aria-hidden="true" />
              </div>

              <h1 style={{ fontSize: '1.6rem', fontWeight: 800, color: '#ffffff', marginBottom: '0.5rem' }}>
                Free Trial Activated
              </h1>
              <p style={{ fontSize: '0.92rem', color: '#94a3b8', maxWidth: '480px', margin: '0 auto 1.75rem auto', lineHeight: 1.6 }}>
                Your 30-day Security Analyst evaluation account has been successfully created and linked to the cloud backend.
              </p>

              {/* Account Details Box */}
              <div
                style={{
                  background: '#040711',
                  border: '1px solid var(--pt-border-subtle)',
                  borderRadius: '8px',
                  padding: '1.25rem',
                  marginBottom: '2rem',
                  textAlign: 'left',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.65rem'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem' }}>
                  <span style={{ color: '#64748b' }}>Account Name:</span>
                  <span style={{ color: '#f8fafc', fontWeight: 600 }}>{successData.displayName}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem' }}>
                  <span style={{ color: '#64748b' }}>Registered Email:</span>
                  <span style={{ color: '#38bdf8', fontWeight: 600 }}>{successData.email}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem' }}>
                  <span style={{ color: '#64748b' }}>Assigned Tenant UID:</span>
                  <span style={{ color: '#00e5ff', fontFamily: 'monospace', fontWeight: 700 }}>{successData.uid}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem' }}>
                  <span style={{ color: '#64748b' }}>Trial Access Duration:</span>
                  <span style={{ color: '#10b981', fontWeight: 600 }}>30 Days Active Access</span>
                </div>
              </div>

              {/* Next Steps Buttons */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                {returnTo === 'pair' ? (
                  <Link
                    to="/dashboard?openPairing=true"
                    id="btn-return-to-pairing"
                    className="pt-btn pt-btn-primary"
                    style={{ padding: '0.85rem 1.75rem', fontSize: '0.98rem', fontWeight: 800, justifyContent: 'center' }}
                  >
                    <Laptop size={18} aria-hidden="true" />
                    <span>Return to PC Pairing</span>
                    <ArrowRight size={17} aria-hidden="true" />
                  </Link>
                ) : (
                  <Link
                    to="/dashboard"
                    className="pt-btn pt-btn-primary"
                    style={{ padding: '0.85rem 1.75rem', fontSize: '0.98rem', fontWeight: 800, justifyContent: 'center' }}
                  >
                    <span>Enter Security Console</span>
                    <ArrowRight size={17} aria-hidden="true" />
                  </Link>
                )}

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem' }}>
                  <a
                    href="/downloads/PhantomTrace_Agent_Setup.exe"
                    download="PhantomTrace_Agent_Setup.exe"
                    className="pt-btn pt-btn-secondary"
                    style={{ padding: '0.65rem 1rem', fontSize: '0.85rem', justifyContent: 'center' }}
                  >
                    <Download size={15} aria-hidden="true" />
                    <span>Download Windows Agent</span>
                  </a>

                  <Link
                    to="/setup"
                    className="pt-btn pt-btn-secondary"
                    style={{ padding: '0.65rem 1rem', fontSize: '0.85rem', justifyContent: 'center' }}
                  >
                    <ShieldCheck size={15} className="text-cyan" aria-hidden="true" />
                    <span>View Setup Guide</span>
                  </Link>
                </div>
              </div>
            </div>
          ) : (
            <div
              className="pt-card pt-card-cyber"
              style={{
                padding: '2.5rem 2rem',
                background: 'linear-gradient(135deg, rgba(16, 26, 46, 0.95) 0%, rgba(9, 15, 26, 0.98) 100%)',
                border: '1px solid rgba(0, 229, 255, 0.35)',
                boxShadow: '0 20px 50px rgba(0, 0, 0, 0.5), 0 0 20px rgba(0, 229, 255, 0.12)'
              }}
            >
              {/* Badge */}
              <div style={{ textAlign: 'center', marginBottom: '1.25rem' }}>
                <div
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.45rem',
                    padding: '0.35rem 0.9rem',
                    borderRadius: '20px',
                    background: 'rgba(0, 229, 255, 0.1)',
                    border: '1px solid rgba(0, 229, 255, 0.3)',
                    fontSize: '0.75rem',
                    fontWeight: 700,
                    color: '#00e5ff',
                    letterSpacing: '0.08em',
                    textTransform: 'uppercase'
                  }}
                >
                  <ShieldCheck size={13} aria-hidden="true" />
                  <span>30-Day Free Evaluation</span>
                </div>
              </div>

              <h1
                style={{
                  fontSize: 'clamp(1.6rem, 3.2vw, 2.1rem)',
                  fontWeight: 800,
                  color: '#ffffff',
                  textAlign: 'center',
                  marginBottom: '0.5rem',
                  letterSpacing: '-0.02em'
                }}
              >
                Start Your Free Trial
              </h1>

              <p
                style={{
                  fontSize: '0.92rem',
                  color: '#94a3b8',
                  textAlign: 'center',
                  maxWidth: '520px',
                  margin: '0 auto 2rem auto',
                  lineHeight: 1.55
                }}
              >
                Experience passive Windows memory scanning, fileless threat detection, and real-time browser monitoring. No credit card required.
              </p>

              {/* Notice for existing active session */}
              {existingUser && (
                <div
                  style={{
                    marginBottom: '1.75rem',
                    padding: '0.85rem 1rem',
                    borderRadius: '8px',
                    background: 'rgba(16, 185, 129, 0.08)',
                    border: '1px solid rgba(16, 185, 129, 0.25)',
                    fontSize: '0.82rem',
                    color: '#a7f3d0',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '0.75rem'
                  }}
                >
                  <div>
                    <strong>Active Session Detected:</strong> Registered as {existingUser.email} ({existingUser.uid}).
                  </div>
                  <Link
                    to="/dashboard"
                    className="pt-btn pt-btn-primary"
                    style={{ padding: '0.35rem 0.85rem', fontSize: '0.76rem' }}
                  >
                    Open Console
                  </Link>
                </div>
              )}

              {/* Registration Form */}
              <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                <div>
                  <label
                    htmlFor="trial-name"
                    style={{ fontSize: '0.82rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}
                  >
                    Full Name or Security Analyst ID
                  </label>
                  <div style={{ position: 'relative' }}>
                    <User
                      size={16}
                      style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)', color: '#64748b' }}
                      aria-hidden="true"
                    />
                    <input
                      id="trial-name"
                      type="text"
                      value={displayName}
                      onChange={(e) => setDisplayName(e.target.value)}
                      placeholder="e.g. Jane Doe"
                      className="pt-input"
                      style={{ width: '100%', paddingLeft: '2.5rem' }}
                    />
                  </div>
                </div>

                <div>
                  <label
                    htmlFor="trial-email"
                    style={{ fontSize: '0.82rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}
                  >
                    Work Email Address <span style={{ color: '#ef4444' }}>*</span>
                  </label>
                  <div style={{ position: 'relative' }}>
                    <Mail
                      size={16}
                      style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)', color: '#64748b' }}
                      aria-hidden="true"
                    />
                    <input
                      id="trial-email"
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="analyst@organization.com"
                      className="pt-input"
                      style={{ width: '100%', paddingLeft: '2.5rem' }}
                    />
                  </div>
                  <span style={{ fontSize: '0.72rem', color: '#64748b', marginTop: '0.25rem', display: 'block' }}>
                    Your session credential will be issued directly to this tenant identity.
                  </span>
                </div>

                <div>
                  <label
                    htmlFor="trial-org"
                    style={{ fontSize: '0.82rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}
                  >
                    Organization or Department <span style={{ color: '#64748b' }}>(Optional)</span>
                  </label>
                  <div style={{ position: 'relative' }}>
                    <Building2
                      size={16}
                      style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)', color: '#64748b' }}
                      aria-hidden="true"
                    />
                    <input
                      id="trial-org"
                      type="text"
                      value={organization}
                      onChange={(e) => setOrganization(e.target.value)}
                      placeholder="e.g. SOC Team / IT Security"
                      className="pt-input"
                      style={{ width: '100%', paddingLeft: '2.5rem' }}
                    />
                  </div>
                </div>

                {error && (
                  <div
                    role="alert"
                    style={{
                      padding: '0.75rem 1rem',
                      background: 'rgba(239, 68, 68, 0.1)',
                      border: '1px solid rgba(239, 68, 68, 0.3)',
                      borderRadius: '6px',
                      color: '#fca5a5',
                      fontSize: '0.82rem',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.5rem'
                    }}
                  >
                    <AlertCircle size={16} style={{ flexShrink: 0 }} aria-hidden="true" />
                    <span>{error}</span>
                  </div>
                )}

                <button
                  type="submit"
                  id="btn-submit-trial-signup"
                  disabled={loading}
                  className="pt-btn pt-btn-primary"
                  style={{
                    width: '100%',
                    justifyContent: 'center',
                    padding: '0.85rem 1.75rem',
                    fontSize: '0.98rem',
                    fontWeight: 800,
                    marginTop: '0.5rem',
                    boxShadow: '0 0 20px rgba(0, 229, 255, 0.35)'
                  }}
                >
                  {loading ? (
                    <>
                      <RefreshCw size={17} className="animate-spin" aria-hidden="true" />
                      <span>Creating Trial Account...</span>
                    </>
                  ) : (
                    <>
                      <ShieldCheck size={18} aria-hidden="true" />
                      <span>Start 30-Day Free Trial</span>
                      <ArrowRight size={17} aria-hidden="true" />
                    </>
                  )}
                </button>
              </form>

              {/* Trust Badges */}
              <div
                style={{
                  marginTop: '2rem',
                  paddingTop: '1.5rem',
                  borderTop: '1px solid rgba(255, 255, 255, 0.08)',
                  display: 'flex',
                  justifyContent: 'center',
                  gap: '1.5rem',
                  flexWrap: 'wrap',
                  fontSize: '0.75rem',
                  color: '#64748b'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <Check size={14} style={{ color: '#10b981' }} aria-hidden="true" />
                  <span>Zero Kernel Drivers</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <Check size={14} style={{ color: '#10b981' }} aria-hidden="true" />
                  <span>Read-Only Passive Inspection</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <Check size={14} style={{ color: '#10b981' }} aria-hidden="true" />
                  <span>Privacy-Preserving Telemetry</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default TrialSignupPage;
