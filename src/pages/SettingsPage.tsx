import React, { useState, useEffect } from 'react';
import {
  Key,
  Database,
  UserCheck,
  Lock,
  CheckCircle2,
  AlertCircle,
  Save,
  RefreshCw,
  Layers
} from 'lucide-react';
import { dataService } from '../services';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { Logo } from '../components/common/Logo';
import type { SystemSettings } from '../types';

export const SettingsPage: React.FC = () => {
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [pingStatus, setPingStatus] = useState<{ message: string; success: boolean } | null>(null);
  const [isPinging, setIsPinging] = useState(false);
  const [adminAuthStatus, setAdminAuthStatus] = useState<{ message: string; success: boolean } | null>(null);
  const [isAdminAuthenticating, setIsAdminAuthenticating] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const s = await dataService.getSettings();
        setSettings(s);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!settings) return;
    setSaving(true);
    try {
      const updated = await dataService.updateSettings(settings);
      setSettings(updated);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } finally {
      setSaving(false);
    }
  };

  const handleTestPing = async () => {
    if (!settings) return;
    setIsPinging(true);
    setPingStatus(null);
    try {
      const res = await dataService.testApiConnection(settings.api.endpointUrl);
      setPingStatus({
        success: res.success,
        message: `${res.message} (Latency: ${res.latencyMs}ms)`
      });
    } catch {
      setPingStatus({
        success: false,
        message: 'Failed to establish test ping.'
      });
    } finally {
      setIsPinging(false);
    }
  };

  const handleAdminAuth = async () => {
    if (!settings?.api.apiKeyMasked) return;
    setIsAdminAuthenticating(true);
    setAdminAuthStatus(null);
    try {
      if (dataService.loginWithApiKey) {
        const res = await dataService.loginWithApiKey(settings.api.apiKeyMasked);
        if (res.success) {
          setAdminAuthStatus({
            success: true,
            message: 'Authenticated successfully as System Administrator (phantomtrace-owner).'
          });
        } else {
          setAdminAuthStatus({
            success: false,
            message: res.message || 'Invalid administrator API key.'
          });
        }
      }
    } catch {
      setAdminAuthStatus({
        success: false,
        message: 'Administrator authentication failed.'
      });
    } finally {
      setIsAdminAuthenticating(false);
    }
  };

  if (loading || !settings) {
    return <div style={{ padding: '3rem', textAlign: 'center', color: '#94a3b8' }}>Loading configuration parameters...</div>;
  }

  return (
    <form onSubmit={handleSave} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Page Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.35rem', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.01em' }}>
            Platform &amp; Integration Settings
          </h2>
          <p style={{ fontSize: '0.82rem', color: '#94a3b8', marginTop: '0.2rem' }}>
            Configure endpoint scanner parameters, REST API targets, and Firebase ingestion pipelines
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {saveSuccess && (
            <span style={{ fontSize: '0.78rem', color: '#10b981', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
              <CheckCircle2 size={14} />
              Configuration updated successfully
            </span>
          )}
          <button
            type="submit"
            disabled={saving}
            className="pt-btn pt-btn-primary"
            style={{ padding: '0.45rem 1.15rem', fontSize: '0.82rem' }}
          >
            <Save size={14} />
            <span>{saving ? 'Saving...' : 'Save Configuration'}</span>
          </button>
        </div>
      </div>

      {/* 1. Endpoint Scanner Section with Official Windows App Logo */}
      <Card
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <Logo variant="windows" height={26} />
            <span>Endpoint Scanner Configuration (Windows x86_64)</span>
          </div>
        }
        subtitle="Parameters governing local Windows memory inspection routines"
        action={
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontSize: '0.75rem', color: '#38bdf8' }}>
            <Lock size={13} style={{ color: '#00e5ff' }} />
            <span>Read-Only Constraint: Enforced</span>
          </div>
        }
      >
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
          <div>
            <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}>
              Scanner Node ID
            </label>
            <input
              type="text"
              value={settings.scanner.scannerId}
              onChange={(e) => setSettings({ ...settings, scanner: { ...settings.scanner, scannerId: e.target.value } })}
              className="pt-input text-mono"
              style={{ width: '100%' }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}>
              Inspection Engine Mode
            </label>
            <select
              value={settings.scanner.engineMode}
              onChange={(e) => setSettings({ ...settings, scanner: { ...settings.scanner, engineMode: e.target.value } })}
              className="pt-select"
              style={{ width: '100%' }}
            >
              <option value="Deep Memory & Behavioral Analysis">Deep Memory &amp; Behavioral Analysis</option>
              <option value="Memory Only (Forensic Focus)">Memory Only (Forensic Focus)</option>
              <option value="Behavioral Lineage Only">Behavioral Lineage Only</option>
            </select>
          </div>

          <div>
            <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}>
              Scan Polling Interval (Seconds)
            </label>
            <input
              type="number"
              value={settings.scanner.pollingIntervalSeconds}
              onChange={(e) => setSettings({ ...settings, scanner: { ...settings.scanner, pollingIntervalSeconds: Number(e.target.value) } })}
              className="pt-input text-mono"
              style={{ width: '100%' }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}>
              Target System Architecture
            </label>
            <input
              type="text"
              disabled
              value={settings.scanner.targetArchitecture}
              className="pt-input text-mono"
              style={{ width: '100%', opacity: 0.7 }}
            />
          </div>
        </div>

        <div style={{ marginTop: '1rem', padding: '0.75rem 1rem', background: 'rgba(5, 9, 17, 0.75)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', fontSize: '0.78rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <AlertCircle size={15} style={{ color: '#f59e0b', flexShrink: 0 }} />
          <span>Status: <strong>Configured (Awaiting Ingestion Stream)</strong>. In live production, this agent streams output from scan_results.json.</span>
        </div>
      </Card>

      {/* 2. REST API Section */}
      <Card
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <Key size={18} style={{ color: '#38bdf8' }} />
            <span>REST API Integration</span>
          </div>
        }
        subtitle="PhantomTrace cloud REST API connection settings"
      >
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
          <div>
            <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}>
              API Base Endpoint URL
            </label>
            <input
              type="text"
              value={settings.api.endpointUrl}
              onChange={(e) => setSettings({ ...settings, api: { ...settings.api, endpointUrl: e.target.value } })}
              className="pt-input text-mono"
              style={{ width: '100%' }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}>
              API Key (Masked Bearer Token)
            </label>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <input
                type="password"
                value={settings.api.apiKeyMasked}
                onChange={(e) => setSettings({ ...settings, api: { ...settings.api, apiKeyMasked: e.target.value } })}
                className="pt-input text-mono"
                style={{ flex: 1 }}
                placeholder="Enter master owner API key..."
              />
              <button
                type="button"
                onClick={handleAdminAuth}
                disabled={isAdminAuthenticating || !settings.api.apiKeyMasked}
                className="pt-btn pt-btn-cyber"
                style={{ padding: '0.35rem 0.75rem', fontSize: '0.75rem', whiteSpace: 'nowrap' }}
                title="Authenticate session as phantomtrace-owner using this key"
              >
                {isAdminAuthenticating ? 'Verifying...' : 'Sign In as Owner'}
              </button>
            </div>
            {adminAuthStatus && (
              <div
                style={{
                  marginTop: '0.45rem',
                  fontSize: '0.74rem',
                  color: adminAuthStatus.success ? '#10b981' : '#ef4444',
                }}
              >
                {adminAuthStatus.message}
              </div>
            )}
          </div>

          <div>
            <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}>
              Request Timeout (Seconds)
            </label>
            <input
              type="number"
              value={settings.api.timeoutSeconds}
              onChange={(e) => setSettings({ ...settings, api: { ...settings.api, timeoutSeconds: Number(e.target.value) } })}
              className="pt-input text-mono"
              style={{ width: '100%' }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}>
              API Ingestion Status
            </label>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginTop: '0.2rem' }}>
              <Badge level="neutral">{settings.api.ingestionStatus}</Badge>
              <button
                type="button"
                onClick={handleTestPing}
                disabled={isPinging}
                className="pt-btn pt-btn-cyber"
                style={{ padding: '0.35rem 0.75rem', fontSize: '0.75rem' }}
              >
                <RefreshCw size={12} className={isPinging ? 'pt-spin' : ''} />
                <span>{isPinging ? 'Pinging...' : 'Test Connection'}</span>
              </button>
            </div>
          </div>
        </div>

        {pingStatus && (
          <div style={{ marginTop: '1rem', padding: '0.75rem 1rem', background: pingStatus.success ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)', border: `1px solid ${pingStatus.success ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`, borderRadius: '6px', fontSize: '0.78rem', color: pingStatus.success ? '#6ee7b7' : '#fca5a5' }}>
            {pingStatus.message}
          </div>
        )}
      </Card>

      {/* 3. Firebase Cloud Configuration */}
      <Card
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <Database size={18} style={{ color: '#f59e0b' }} />
            <span>Firebase Cloud Storage &amp; Firestore</span>
          </div>
        }
        subtitle="Real-time telemetry synchronization and cloud database configuration"
      >
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
          <div>
            <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}>
              Firebase Project ID
            </label>
            <input
              type="text"
              value={settings.firebase.projectId}
              onChange={(e) => setSettings({ ...settings, firebase: { ...settings.firebase, projectId: e.target.value } })}
              className="pt-input text-mono"
              style={{ width: '100%' }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}>
              Firestore Collection
            </label>
            <input
              type="text"
              value={settings.firebase.firestoreCollection}
              onChange={(e) => setSettings({ ...settings, firebase: { ...settings.firebase, firestoreCollection: e.target.value } })}
              className="pt-input text-mono"
              style={{ width: '100%' }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}>
              Auth Domain
            </label>
            <input
              type="text"
              value={settings.firebase.authDomain}
              onChange={(e) => setSettings({ ...settings, firebase: { ...settings.firebase, authDomain: e.target.value } })}
              className="pt-input text-mono"
              style={{ width: '100%' }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}>
              Realtime Synchronization
            </label>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginTop: '0.45rem' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.82rem', color: '#cbd5e1' }}>
                <input
                  type="checkbox"
                  checked={settings.firebase.realtimeSync}
                  onChange={(e) => setSettings({ ...settings, firebase: { ...settings.firebase, realtimeSync: e.target.checked } })}
                />
                <span>Enable Realtime Snapshot Listeners</span>
              </label>
            </div>
          </div>
        </div>

        <div style={{ marginTop: '1rem', padding: '0.75rem 1rem', background: 'rgba(5, 9, 17, 0.75)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', fontSize: '0.78rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <Layers size={14} style={{ color: '#00e5ff' }} />
          <span>Status: <strong>{settings.firebase.syncStatus}</strong>. Ready to bind Firestore listeners in <code>src/services/firebase.ts</code>.</span>
        </div>
      </Card>

      {/* 4. Authentication & Access Control */}
      <Card
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <UserCheck size={18} style={{ color: '#10b981' }} />
            <span>Authentication &amp; Security Roles</span>
          </div>
        }
        subtitle="Analyst session management and forensic audit logging"
      >
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
          <div>
            <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}>
              Current Analyst
            </label>
            <input
              type="text"
              disabled
              value={settings.auth.currentAnalyst}
              className="pt-input"
              style={{ width: '100%', opacity: 0.8 }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}>
              Role Designation
            </label>
            <input
              type="text"
              disabled
              value={settings.auth.role}
              className="pt-input"
              style={{ width: '100%', opacity: 0.8 }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}>
              Session Expiry
            </label>
            <input
              type="text"
              disabled
              value={settings.auth.sessionExpiry}
              className="pt-input text-mono"
              style={{ width: '100%', opacity: 0.8 }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}>
              Forensic Audit Logging
            </label>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.45rem' }}>
              <Badge level="Clean">Enforced &amp; Active</Badge>
              <span style={{ fontSize: '0.75rem', color: '#64748b' }}>Every triage action is logged</span>
            </div>
          </div>
        </div>
      </Card>
    </form>
  );
};
