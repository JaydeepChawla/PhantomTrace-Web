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
  Layers,
  Globe,
  Copy,
  Check
} from 'lucide-react';
import { dataService } from '../services';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { Logo } from '../components/common/Logo';
import { LoadingSpinner } from '../components/common/LoadingSpinner';
import type { SystemSettings } from '../types';

export type SyncState = 'Idle' | 'Syncing' | 'Synced' | 'Offline' | 'Failed';

export const SettingsPage: React.FC = () => {
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [pingStatus, setPingStatus] = useState<{ message: string; success: boolean } | null>(null);
  const [isPinging, setIsPinging] = useState(false);
  const [adminAuthStatus, setAdminAuthStatus] = useState<{ message: string; success: boolean } | null>(null);
  const [isAdminAuthenticating, setIsAdminAuthenticating] = useState(false);

  // Browser Extension Integration State
  const [extensionToken, setExtensionToken] = useState<string | null>(null);
  const [copiedToken, setCopiedToken] = useState(false);
  const [loadingExtensionToken, setLoadingExtensionToken] = useState(false);
  const [extensionTokenStatus, setExtensionTokenStatus] = useState<string | null>(null);
  const [extensionTokenError, setExtensionTokenError] = useState<string | null>(null);

  // Cloud Synchronization State Machine
  const [syncState, setSyncState] = useState<SyncState>('Idle');
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [lastSyncTime, setLastSyncTime] = useState<string | null>(null);
  const [syncMessage, setSyncMessage] = useState<string | null>(null);
  const [syncError, setSyncError] = useState<string | null>(null);
  const [telemetrySource, setTelemetrySource] = useState<string>('Real Cloud');

  useEffect(() => {
    async function load() {
      try {
        const s = await dataService.getSettings();
        setSettings(s);
        if (dataService.getSyncStatus) {
          const syncStatus = dataService.getSyncStatus();
          if (syncStatus?.lastSyncedAt) {
            setLastSyncTime(syncStatus.lastSyncedAt);
          }
        }
        if (dataService.getTelemetrySource) {
          setTelemetrySource(dataService.getTelemetrySource());
        }
        if (dataService.getAuthToken) {
          const t = dataService.getAuthToken();
          if (t) setExtensionToken(t);
        }
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const handleGenerateExtensionToken = async (forceFresh = false) => {
    setLoadingExtensionToken(true);
    setExtensionTokenError(null);
    setExtensionTokenStatus(null);
    try {
      if (dataService.generateExtensionToken) {
        const res = await dataService.generateExtensionToken(forceFresh);
        if (res && res.success && res.extensionToken) {
          setExtensionToken(res.extensionToken);
          setExtensionTokenStatus(res.message || 'Scoped extension synchronization token generated and verified with backend.');
          return;
        } else if (res && !res.success) {
          setExtensionTokenError(res.message || 'Failed to generate extension credential with backend API.');
          return;
        }
      }
      if (dataService.getAuthToken) {
        const t = dataService.getAuthToken();
        if (t) {
          setExtensionToken(t);
          setExtensionTokenStatus('Active tenant credential ready for extension sync.');
          return;
        }
      }
      setExtensionTokenError('Unable to generate extension token. Please verify backend connection.');
    } catch (err: any) {
      setExtensionTokenError(err?.message || 'Failed to generate extension token.');
    } finally {
      setLoadingExtensionToken(false);
    }
  };

  const handleCopyExtensionToken = async () => {
    if (!extensionToken) return;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(extensionToken);
      } else {
        const textarea = document.createElement('textarea');
        textarea.value = extensionToken;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
      }
      setCopiedToken(true);
      setTimeout(() => setCopiedToken(false), 2500);
    } catch {
      setCopiedToken(true);
      setTimeout(() => setCopiedToken(false), 2500);
    }
  };

  const handleSyncNow = async () => {
    // Prevent concurrent duplicate sync requests
    if (isSyncing) return;
    setIsSyncing(true);
    setSyncState('Syncing');
    setSyncError(null);
    setSyncMessage('Synchronizing endpoint scans, alerts, and browser threats with cloud backend...');

    try {
      if (!dataService.syncTelemetry) {
        setSyncState('Failed');
        setSyncError('Cloud synchronization service is not available.');
        return;
      }

      const res = await dataService.syncTelemetry();
      if (res.success) {
        setSyncState('Synced');
        const timestamp = res.timestamp || new Date().toLocaleTimeString();
        setLastSyncTime(timestamp);
        setSyncMessage(res.message);
        if (dataService.getTelemetrySource) {
          setTelemetrySource(dataService.getTelemetrySource());
        }
      } else {
        if (res.status === 'API Offline') {
          setSyncState('Offline');
          setSyncError(res.message || 'API backend is currently offline / unreachable.');
        } else {
          setSyncState('Failed');
          setSyncError(res.message || 'Synchronization failed.');
        }
      }
    } catch (err: unknown) {
      setSyncState('Failed');
      setSyncError(err instanceof Error ? err.message : 'Network error during synchronization.');
    } finally {
      setIsSyncing(false);
    }
  };

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
    return (
      <div style={{ padding: '3rem 1rem' }}>
        <LoadingSpinner message="Loading PhantomTrace platform & integration parameters..." size="lg" fullHeight />
      </div>
    );
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

      {/* 3. Cloud Telemetry Synchronization */}
      <Card
        title={
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%', flexWrap: 'wrap', gap: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <Database size={18} style={{ color: '#00e5ff' }} />
              <span>Cloud Telemetry Synchronization</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <span
                style={{
                  fontSize: '0.72rem',
                  fontWeight: 700,
                  padding: '0.2rem 0.65rem',
                  borderRadius: '12px',
                  background:
                    syncState === 'Synced'
                      ? 'rgba(16, 185, 129, 0.15)'
                      : syncState === 'Syncing'
                      ? 'rgba(0, 229, 255, 0.15)'
                      : syncState === 'Offline'
                      ? 'rgba(245, 158, 11, 0.15)'
                      : syncState === 'Failed'
                      ? 'rgba(239, 68, 68, 0.15)'
                      : 'rgba(100, 116, 139, 0.15)',
                  color:
                    syncState === 'Synced'
                      ? '#10b981'
                      : syncState === 'Syncing'
                      ? '#00e5ff'
                      : syncState === 'Offline'
                      ? '#f59e0b'
                      : syncState === 'Failed'
                      ? '#ef4444'
                      : '#94a3b8',
                  border:
                    syncState === 'Synced'
                      ? '1px solid rgba(16, 185, 129, 0.35)'
                      : syncState === 'Syncing'
                      ? '1px solid rgba(0, 229, 255, 0.35)'
                      : syncState === 'Offline'
                      ? '1px solid rgba(245, 158, 11, 0.35)'
                      : syncState === 'Failed'
                      ? '1px solid rgba(239, 68, 68, 0.35)'
                      : '1px solid rgba(100, 116, 139, 0.35)',
                }}
              >
                Status: {syncState}
              </span>

              <button
                type="button"
                id="btn-sync-now"
                onClick={handleSyncNow}
                disabled={isSyncing}
                className="pt-btn pt-btn-primary"
                style={{ padding: '0.35rem 0.85rem', fontSize: '0.76rem' }}
                title="Synchronize endpoint scan results and threat telemetry immediately"
              >
                <RefreshCw size={13} className={isSyncing ? 'pt-spin' : ''} />
                <span>{isSyncing ? 'Syncing...' : 'Sync Now'}</span>
              </button>
            </div>
          </div>
        }
        subtitle="Real-time ingestion pipeline: Windows Agent → Render API → Supabase PostgreSQL → Dashboard"
      >
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
          <div>
            <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}>
              Last Successful Synchronization
            </label>
            <div
              style={{
                padding: '0.55rem 0.85rem',
                background: 'rgba(5, 9, 17, 0.65)',
                border: '1px solid var(--pt-border-subtle)',
                borderRadius: '6px',
                fontSize: '0.85rem',
                color: lastSyncTime ? '#38bdf8' : '#64748b',
                fontFamily: 'var(--font-mono)'
              }}
            >
              {lastSyncTime ? `${lastSyncTime}` : 'Not yet synchronized in this session'}
            </div>
          </div>

          <div>
            <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}>
              Active Telemetry Source
            </label>
            <div
              style={{
                padding: '0.55rem 0.85rem',
                background: 'rgba(5, 9, 17, 0.65)',
                border: '1px solid var(--pt-border-subtle)',
                borderRadius: '6px',
                fontSize: '0.85rem',
                color: telemetrySource.includes('Demo') ? '#f59e0b' : '#10b981',
                fontWeight: 600
              }}
            >
              {telemetrySource}
            </div>
          </div>

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
              Realtime Telemetry Ingestion
            </label>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginTop: '0.45rem' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.82rem', color: '#cbd5e1' }}>
                <input
                  type="checkbox"
                  checked={settings.firebase.realtimeSync}
                  onChange={(e) => setSettings({ ...settings, firebase: { ...settings.firebase, realtimeSync: e.target.checked } })}
                />
                <span>Enable Realtime Snapshot Ingestion</span>
              </label>
            </div>
          </div>
        </div>

        {syncMessage && !syncError && (
          <div
            style={{
              marginTop: '1rem',
              padding: '0.75rem 1rem',
              background: 'rgba(0, 229, 255, 0.08)',
              border: '1px solid rgba(0, 229, 255, 0.25)',
              borderRadius: '6px',
              fontSize: '0.78rem',
              color: '#38bdf8',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}
          >
            <CheckCircle2 size={15} style={{ flexShrink: 0 }} />
            <span>{syncMessage}</span>
          </div>
        )}

        {syncError && (
          <div
            style={{
              marginTop: '1rem',
              padding: '0.75rem 1rem',
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              borderRadius: '6px',
              fontSize: '0.78rem',
              color: '#fca5a5',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}
          >
            <AlertCircle size={15} style={{ flexShrink: 0 }} />
            <span>{syncError}</span>
          </div>
        )}

        <div style={{ marginTop: '1rem', padding: '0.75rem 1rem', background: 'rgba(5, 9, 17, 0.75)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', fontSize: '0.78rem', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <Layers size={14} style={{ color: '#00e5ff' }} />
          <span>PostgreSQL Sync Engine: <strong>Active</strong>. Live scans from paired Windows endpoints and Browser Monitor events are synchronized automatically.</span>
        </div>
      </Card>

      {/* 4. Browser Extension Integration */}
      <Card
        title={
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%', flexWrap: 'wrap', gap: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <Globe size={18} style={{ color: '#00e5ff' }} />
              <span>Chrome &amp; Edge Browser Extension Integration</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span
                style={{
                  fontSize: '0.72rem',
                  fontWeight: 700,
                  padding: '0.2rem 0.65rem',
                  borderRadius: '12px',
                  background: extensionToken ? 'rgba(16, 185, 129, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                  color: extensionToken ? '#10b981' : '#f59e0b',
                  border: `1px solid ${extensionToken ? 'rgba(16, 185, 129, 0.35)' : 'rgba(245, 158, 11, 0.35)'}`,
                }}
              >
                {extensionToken ? 'Token Configured' : 'No Token'}
              </span>
            </div>
          </div>
        }
        subtitle="Scoped, revocable credentials for real-time web threat inspection and domain security policy synchronization"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <p style={{ margin: 0, fontSize: '0.82rem', color: '#cbd5e1', lineHeight: 1.5 }}>
            The PhantomTrace browser extension monitors visited domains in Chrome and Edge against threat intelligence and enforces your tenant's custom Domain Security Policies (Allowlist &amp; Blocklist). Scoped extension tokens authenticate via SHA-256 session records and never expose master API keys, database credentials, or server secrets.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
            <div>
              <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}>
                Extension Target Backend URL
              </label>
              <input
                type="text"
                readOnly
                value="https://phantomtrace-web.onrender.com"
                className="pt-input text-mono"
                style={{ width: '100%', opacity: 0.85 }}
              />
              <span style={{ fontSize: '0.7rem', color: '#64748b', marginTop: '3px', display: 'block' }}>
                Default production endpoint configured in extension manifest
              </span>
            </div>

            <div>
              <label style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '0.35rem', fontWeight: 600 }}>
                Extension Synchronization Token
              </label>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <input
                  type="text"
                  readOnly
                  value={loadingExtensionToken ? 'Generating token...' : extensionToken || 'No token generated yet'}
                  className="pt-input text-mono"
                  style={{ flex: 1, color: extensionToken ? '#38bdf8' : '#94a3b8' }}
                  onClick={(e) => (e.target as HTMLInputElement).select()}
                />
                <button
                  type="button"
                  id="btn-copy-settings-extension-token"
                  onClick={handleCopyExtensionToken}
                  disabled={!extensionToken || loadingExtensionToken}
                  className="pt-btn pt-btn-primary"
                  style={{
                    padding: '0.35rem 0.85rem',
                    fontSize: '0.75rem',
                    whiteSpace: 'nowrap',
                    background: copiedToken ? '#10b981' : undefined,
                    borderColor: copiedToken ? '#10b981' : undefined,
                  }}
                >
                  {copiedToken ? <Check size={13} /> : <Copy size={13} />}
                  <span>{copiedToken ? 'Copied!' : 'Copy'}</span>
                </button>
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
            <button
              type="button"
              id="btn-generate-extension-token-settings"
              onClick={() => handleGenerateExtensionToken(Boolean(extensionToken))}
              disabled={loadingExtensionToken}
              className="pt-btn pt-btn-cyber"
              style={{ padding: '0.45rem 1rem', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
            >
              <RefreshCw size={14} className={loadingExtensionToken ? 'pt-spin' : ''} />
              <span>
                {loadingExtensionToken
                  ? 'Generating...'
                  : extensionToken
                  ? 'Regenerate Extension Sync Token'
                  : 'Generate Extension Sync Token'}
              </span>
            </button>
          </div>

          {extensionTokenStatus && (
            <div style={{ padding: '0.65rem 0.85rem', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: '6px', fontSize: '0.78rem', color: '#6ee7b7', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <CheckCircle2 size={14} style={{ flexShrink: 0 }} />
              <span>{extensionTokenStatus}</span>
            </div>
          )}

          {extensionTokenError && (
            <div style={{ padding: '0.65rem 0.85rem', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', borderRadius: '6px', fontSize: '0.78rem', color: '#fca5a5', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <AlertCircle size={14} style={{ flexShrink: 0 }} />
              <span>{extensionTokenError}</span>
            </div>
          )}

          <div style={{ padding: '0.85rem 1rem', background: 'rgba(5, 9, 17, 0.75)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', fontSize: '0.76rem', color: '#94a3b8', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
            <div style={{ color: '#e2e8f0', fontWeight: 600 }}>Extension Connection Instructions:</div>
            <div>1. In Chrome or Edge, navigate to <code style={{ color: '#38bdf8' }}>chrome://extensions</code>, enable Developer mode, and click <strong>Load unpacked</strong> on the <code style={{ color: '#38bdf8' }}>browser-extension/</code> folder.</div>
            <div>2. Click <strong>Generate Extension Sync Token</strong> (or <strong>Copy</strong>) above to obtain your scoped credential.</div>
            <div>3. Click the PhantomTrace shield icon in your browser toolbar, paste into <strong>Extension Sync Token</strong>, and click <strong>Set</strong>.</div>
            <div>4. Click <strong>Sync Policies</strong> to authenticate and verify live rule synchronization.</div>
          </div>
        </div>
      </Card>

      {/* 5. Authentication & Access Control */}
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
