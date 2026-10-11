import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Globe,
  Copy,
  Check,
  ExternalLink,
  AlertCircle,
  FolderArchive,
  Terminal,
  ShieldCheck,
  CheckCircle2,
  Key,
  Lock,
  Download,
  FolderCheck
} from 'lucide-react';

export const ChromeExtensionInstallationSection: React.FC = () => {
  const [copiedUrl, setCopiedUrl] = useState(false);
  const [copiedChecksum, setCopiedChecksum] = useState(false);
  const sha256Checksum = '00dc47fc4acaeb647577660155a1cdf5a755cd71624c6a923b1368658128e426';

  const handleCopyChromeUrl = async () => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText('chrome://extensions');
      } else {
        const textarea = document.createElement('textarea');
        textarea.value = 'chrome://extensions';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }
      setCopiedUrl(true);
      setTimeout(() => setCopiedUrl(false), 4000);
    } catch {
      setCopiedUrl(true);
      setTimeout(() => setCopiedUrl(false), 4000);
    }
  };

  const handleCopyChecksum = async () => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(sha256Checksum);
      } else {
        const textarea = document.createElement('textarea');
        textarea.value = sha256Checksum;
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

  const steps = [
    {
      step: '01',
      title: 'Download Extension ZIP',
      badge: 'PhantomTrace-Chrome-Extension.zip',
      badgeColor: '#38bdf8',
      icon: <Download size={22} style={{ color: '#38bdf8' }} />,
      desc: 'Download the official PhantomTrace-Chrome-Extension.zip package directly from the PhantomTrace website using the download button above.',
      detail: 'Verified distribution package containing manifest.json, background service worker, popup UI, warning interstitials, and required icons.'
    },
    {
      step: '02',
      title: 'Extract to Permanent Folder',
      badge: 'Direct manifest.json Location',
      badgeColor: '#00e5ff',
      icon: <FolderArchive size={22} style={{ color: '#00e5ff' }} />,
      desc: 'Extract the downloaded ZIP package to a permanent directory on your machine (e.g., C:\\PhantomTrace\\browser-extension\\ or your Documents folder). Do not delete this folder after installation.',
      detail: 'Confirm that manifest.json is directly inside the selected folder without extra nested folders (PhantomTrace-Chrome-Extension/manifest.json).'
    },
    {
      step: '03',
      title: 'Open chrome://extensions',
      badge: 'chrome://extensions',
      badgeColor: '#a78bfa',
      icon: <Terminal size={22} style={{ color: '#a78bfa' }} />,
      desc: 'Open Google Chrome (or Microsoft Edge). Navigate to chrome://extensions (or edge://extensions) in your address bar. Use the Copy button above for quick access.',
      detail: 'Web browsers restrict websites from opening internal chrome:// URLs automatically, so paste the copied address into your browser address bar.'
    },
    {
      step: '04',
      title: 'Enable Developer Mode & Click Load Unpacked',
      badge: 'Developer Mode Toggle',
      badgeColor: '#34d399',
      icon: <CheckCircle2 size={22} style={{ color: '#34d399' }} />,
      desc: 'Toggle the "Developer mode" switch to ON in the upper-right corner of the Extensions page. Once enabled, the "Load unpacked" button will appear in the top-left toolbar.',
      detail: 'Developer mode allows installing verified local Manifest V3 packages prior to Chrome Web Store general availability.'
    },
    {
      step: '05',
      title: 'Select Extracted Folder',
      badge: 'Select Unpacked Folder',
      badgeColor: '#f59e0b',
      icon: <FolderCheck size={22} style={{ color: '#f59e0b' }} />,
      desc: 'In the file dialog, navigate to and select the extracted folder directly containing manifest.json. Confirm that "PhantomTrace Web Threat Monitor" (v1.0.0) appears in your extensions list, then pin it to your browser toolbar.',
      detail: 'Chrome validates the Manifest V3 service worker and dynamic declarativeNetRequest rules without requiring a browser restart.'
    },
    {
      step: '06',
      title: 'Configure Authentication & Sync',
      badge: 'Scoped Extension Token',
      badgeColor: '#10b981',
      icon: <ShieldCheck size={22} style={{ color: '#10b981' }} />,
      desc: 'Open the extension popup in your browser toolbar. The default production backend is https://phantomtrace-web.onrender.com. Enter your scoped token (pt_ext_... or pt_usr_...) and click "Sync Policies".',
      detail: 'Toggle Active Web Monitoring to ON. Visited domains are evaluated against threat policies with 100% hostname-only inspection and zero browsing history logging.'
    }
  ];

  return (
    <section
      id="browser-protection"
      style={{
        maxWidth: '1200px',
        margin: '0 auto',
        padding: '3.5rem 2rem 5rem 2rem',
        width: '100%',
        borderTop: '1px solid var(--pt-border-subtle)'
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
            background: 'rgba(56, 189, 248, 0.08)',
            border: '1px solid rgba(56, 189, 248, 0.25)',
            fontSize: '0.75rem',
            fontWeight: 700,
            color: '#38bdf8',
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            marginBottom: '0.75rem'
          }}
        >
          <Globe size={12} />
          <span>Browser Protection • Manifest V3</span>
        </div>

        <h2 style={{ fontSize: '2.2rem', fontWeight: 800, color: '#ffffff', letterSpacing: '-0.02em', marginBottom: '0.5rem' }}>
          CHROME EXTENSION INSTALLATION &amp; BROWSER PROTECTION
        </h2>

        <p style={{ fontSize: '1.1rem', color: '#38bdf8', fontStyle: 'italic', fontWeight: 500, marginBottom: '0.85rem' }}>
          "Real-time web threat inspection with deterministic privacy preservation."
        </p>

        <p style={{ fontSize: '0.98rem', color: '#94a3b8', maxWidth: '760px', margin: '0 auto', lineHeight: 1.6 }}>
          Deploy the PhantomTrace Web Threat Monitor in Google Chrome or Microsoft Edge. Evaluates visited hostnames
          against threat intelligence, enforces tenant allowlists and blocklists via declarativeNetRequest, and preserves complete
          analyst privacy with zero URL parameter or password capture.
        </p>
      </div>

      {/* Main Extension Hero Card */}
      <div
        className="pt-card pt-card-cyber"
        style={{
          padding: '2.5rem',
          marginBottom: '3rem',
          background: 'linear-gradient(135deg, rgba(16, 26, 46, 0.95) 0%, rgba(9, 15, 26, 0.98) 100%)',
          border: '1px solid rgba(56, 189, 248, 0.28)',
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.4), 0 0 20px rgba(56, 189, 248, 0.08)',
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
          {/* Left Column: Extension Specs & Store Publication Status */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', marginBottom: '1rem' }}>
              <div
                style={{
                  width: '48px',
                  height: '48px',
                  borderRadius: '10px',
                  background: 'rgba(56, 189, 248, 0.12)',
                  border: '1px solid rgba(56, 189, 248, 0.3)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#38bdf8'
                }}
              >
                <Globe size={26} />
              </div>
              <div>
                <h3 style={{ fontSize: '1.35rem', fontWeight: 800, color: '#ffffff', margin: 0 }}>
                  PhantomTrace Web Threat Monitor
                </h3>
                <div style={{ fontSize: '0.8rem', color: '#38bdf8', fontWeight: 600 }}>
                  Manifest V3 Browser Extension (Chrome &amp; Edge)
                </div>
              </div>
            </div>

            <p style={{ fontSize: '0.92rem', color: '#cbd5e1', lineHeight: 1.6, marginBottom: '1.25rem' }}>
              Inspects visited hostnames against threat intelligence, intercepts malicious domains with warning interstitials,
              and synchronizes enterprise security policies. Operates in 100% read-only passive inspection mode without reading page inputs or passwords.
            </p>

            {/* Store Status Notice */}
            <div
              style={{
                background: 'rgba(245, 158, 11, 0.08)',
                border: '1px solid rgba(245, 158, 11, 0.3)',
                borderRadius: '8px',
                padding: '0.85rem 1rem',
                marginBottom: '1.5rem',
                display: 'flex',
                alignItems: 'flex-start',
                gap: '0.65rem'
              }}
            >
              <AlertCircle size={17} style={{ color: '#f59e0b', flexShrink: 0, marginTop: '2px' }} />
              <div>
                <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#f59e0b', marginBottom: '0.2rem' }}>
                  Developer Installation — Store Publication Pending
                </div>
                <div style={{ fontSize: '0.78rem', color: '#cbd5e1', lineHeight: 1.5 }}>
                  The official Chrome Web Store and Microsoft Edge Add-ons listings are currently pending review.
                  Download the verified extension ZIP package and follow the 6-step developer guide below to load the unpacked extension in Chrome.
                </div>
              </div>
            </div>

            {/* Specification Badges Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '0.75rem', marginBottom: '1.25rem' }}>
              <div style={{ background: 'rgba(5, 9, 17, 0.6)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.85rem' }}>
                <div style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Manifest Version</div>
                <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#f8fafc' }}>MV3 (Service Worker)</div>
              </div>
              <div style={{ background: 'rgba(5, 9, 17, 0.6)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.85rem' }}>
                <div style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Browser Compatibility</div>
                <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#f8fafc' }}>Chrome &amp; Edge (Chromium)</div>
              </div>
              <div style={{ background: 'rgba(5, 9, 17, 0.6)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.85rem' }}>
                <div style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Privacy Guarantee</div>
                <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#34d399' }}>Hostnames Only</div>
              </div>
              <div style={{ background: 'rgba(5, 9, 17, 0.6)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.65rem 0.85rem' }}>
                <div style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Policy Enforcement</div>
                <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#38bdf8' }}>declarativeNetRequest</div>
              </div>
            </div>
          </div>

          {/* Right Column: Actions & Quick Links */}
          <div
            style={{
              background: 'rgba(9, 15, 26, 0.75)',
              border: '1px solid rgba(56, 189, 248, 0.25)',
              borderRadius: '10px',
              padding: '1.75rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '1.25rem'
            }}
          >
            <div>
              <div style={{ fontSize: '0.75rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '0.45rem', fontWeight: 600 }}>
                Browser Extension Package
              </div>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#ffffff' }}>
                Verified ZIP Distribution
              </div>
            </div>

            {/* Prominent Download Button */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <a
                href="/downloads/PhantomTrace-Chrome-Extension.zip"
                download="PhantomTrace-Chrome-Extension.zip"
                id="btn-download-chrome-extension-zip"
                className="pt-btn pt-btn-primary"
                style={{
                  width: '100%',
                  justifyContent: 'center',
                  padding: '0.9rem 1.4rem',
                  fontSize: '0.96rem',
                  fontWeight: 800,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.65rem',
                  background: 'linear-gradient(135deg, #00e5ff 0%, #0284c7 100%)',
                  color: '#050911',
                  boxShadow: '0 0 20px rgba(0, 229, 255, 0.35)',
                  textDecoration: 'none'
                }}
                title="Download verified PhantomTrace Chrome Extension ZIP"
              >
                <Download size={20} />
                <span>Download Chrome Extension ZIP</span>
              </a>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.74rem', color: '#94a3b8', padding: '0 0.25rem' }}>
                <span>📦 ZIP Archive (125 KB)</span>
                <span style={{ color: '#34d399', fontWeight: 600 }}>✓ Verified MV3 Bundle</span>
              </div>
            </div>

            {/* Checksum Box */}
            <div
              style={{
                background: '#040711',
                border: '1px solid rgba(56, 189, 248, 0.2)',
                borderRadius: '6px',
                padding: '0.65rem 0.85rem'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                <span style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
                  SHA-256 Checksum
                </span>
                <button
                  type="button"
                  onClick={handleCopyChecksum}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: copiedChecksum ? '#10b981' : '#38bdf8',
                    cursor: 'pointer',
                    fontSize: '0.72rem',
                    fontWeight: 600,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.25rem',
                    padding: 0
                  }}
                  title="Copy SHA-256 Checksum"
                >
                  {copiedChecksum ? <Check size={12} /> : <Copy size={12} />}
                  <span>{copiedChecksum ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.7rem',
                  color: '#cbd5e1',
                  wordBreak: 'break-all',
                  lineHeight: 1.3
                }}
              >
                {sha256Checksum}
              </div>
            </div>

            {/* Open Chrome Extensions CTA Button with Clipboard Copy */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
              <button
                type="button"
                id="btn-open-chrome-extensions"
                onClick={handleCopyChromeUrl}
                className="pt-btn pt-btn-secondary"
                style={{
                  width: '100%',
                  justifyContent: 'center',
                  padding: '0.75rem 1.25rem',
                  fontSize: '0.88rem',
                  fontWeight: 700
                }}
                title="Copy chrome://extensions to clipboard"
              >
                {copiedUrl ? (
                  <>
                    <Check size={16} style={{ color: '#10b981' }} />
                    <span>chrome://extensions Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy size={16} />
                    <span>Copy chrome://extensions</span>
                  </>
                )}
              </button>

              {copiedUrl ? (
                <div
                  role="status"
                  style={{
                    fontSize: '0.75rem',
                    color: '#34d399',
                    background: 'rgba(16, 185, 129, 0.12)',
                    border: '1px solid rgba(16, 185, 129, 0.3)',
                    borderRadius: '6px',
                    padding: '0.5rem 0.75rem',
                    lineHeight: 1.4
                  }}
                >
                  ✓ <strong>chrome://extensions</strong> copied to clipboard! Paste it into your Chrome address bar.
                </div>
              ) : (
                <div style={{ fontSize: '0.74rem', color: '#64748b', textAlign: 'center' }}>
                  Copies <code style={{ color: '#00e5ff', background: '#040711', padding: '0.1rem 0.3rem', borderRadius: '3px' }}>chrome://extensions</code> for quick pasting.
                </div>
              )}
            </div>

            {/* Action Links */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {/* Official Chrome Documentation Link */}
              <a
                href="https://developer.chrome.com/docs/extensions/get-started/tutorial/hello-world"
                target="_blank"
                rel="noopener noreferrer"
                className="pt-btn pt-btn-cyber"
                style={{
                  width: '100%',
                  justifyContent: 'center',
                  padding: '0.6rem 1rem',
                  fontSize: '0.82rem',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.45rem'
                }}
                title="Official Chrome Extension Developer Documentation"
              >
                <ExternalLink size={14} style={{ color: '#38bdf8' }} />
                <span>Official Chrome Extension Guide</span>
              </a>

              {/* Connect Extension via Dashboard Link */}
              <Link
                to="/settings"
                className="pt-btn pt-btn-cyber"
                style={{
                  width: '100%',
                  justifyContent: 'center',
                  padding: '0.6rem 1rem',
                  fontSize: '0.82rem',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '0.45rem'
                }}
                title="Generate Scoped Extension Sync Token"
              >
                <Key size={14} />
                <span>Generate Extension Sync Token</span>
              </Link>
            </div>

            {/* Honest Notice */}
            <div
              style={{
                background: '#040711',
                border: '1px solid var(--pt-border-subtle)',
                borderRadius: '6px',
                padding: '0.65rem 0.85rem',
                fontSize: '0.76rem',
                color: '#94a3b8',
                display: 'flex',
                alignItems: 'flex-start',
                gap: '0.5rem'
              }}
            >
              <Lock size={14} style={{ color: '#00e5ff', flexShrink: 0, marginTop: '2px' }} />
              <span>
                Manual install: Downloading the ZIP does not automatically install the extension into Chrome. Follow the 6 steps below to extract and Load unpacked.
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Six Numbered Steps Cards */}
      <div style={{ marginBottom: '3.5rem' }}>
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <h3 style={{ fontSize: '1.4rem', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.01em' }}>
            Chrome Extension Installation Guide
          </h3>
          <p style={{ fontSize: '0.86rem', color: '#94a3b8', marginTop: '0.35rem' }}>
            6 numbered steps from repository files to active declarative web threat protection
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
                border: '1px solid rgba(56, 189, 248, 0.2)',
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
                      background: 'rgba(56, 189, 248, 0.08)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      border: '1px solid rgba(56, 189, 248, 0.2)'
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

      {/* Safety & Privacy Guarantees Section */}
      <div
        style={{
          background: 'rgba(9, 15, 26, 0.65)',
          border: '1px solid var(--pt-border-subtle)',
          borderRadius: '10px',
          padding: '1.75rem 2rem'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '1rem' }}>
          <ShieldCheck size={22} style={{ color: '#38bdf8' }} />
          <h4 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#ffffff', margin: 0 }}>
            Browser Extension Privacy &amp; Operational Guarantees
          </h4>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.25rem' }}>
          <div>
            <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#f8fafc', marginBottom: '0.25rem' }}>
              Zero Credential Leakage
            </div>
            <p style={{ fontSize: '0.8rem', color: '#94a3b8', lineHeight: 1.5, margin: 0 }}>
              The client extension and popup contain zero database connection strings, server environment secrets, or master keys. Only scoped user tokens are stored locally.
            </p>
          </div>

          <div>
            <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#f8fafc', marginBottom: '0.25rem' }}>
              Deterministic Policy Precedence
            </div>
            <p style={{ fontSize: '0.8rem', color: '#94a3b8', lineHeight: 1.5, margin: 0 }}>
              Enforces custom enterprise rules via declarativeNetRequest: Subdomain Specificity &gt; Custom BLOCK (Default Deny) &gt; Custom ALLOW &gt; External Threat Intel.
            </p>
          </div>

          <div>
            <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#f8fafc', marginBottom: '0.25rem' }}>
              Strict Hostname-Only Inspection
            </div>
            <p style={{ fontSize: '0.8rem', color: '#94a3b8', lineHeight: 1.5, margin: 0 }}>
              Only domain hostnames are evaluated against threat databases. Query strings, search terms, form passwords, and session cookies are never monitored or transmitted.
            </p>
          </div>

          <div>
            <div style={{ fontSize: '0.86rem', fontWeight: 700, color: '#f8fafc', marginBottom: '0.25rem' }}>
              Fail-Safe Offline Resilience
            </div>
            <p style={{ fontSize: '0.8rem', color: '#94a3b8', lineHeight: 1.5, margin: 0 }}>
              If backend connectivity is interrupted, web navigation is never blocked. Cached enterprise policies remain enforced locally via Chrome's dynamic rule cache.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
};
