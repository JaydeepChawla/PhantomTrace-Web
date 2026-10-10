import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Shield,
  ShieldCheck,
  RefreshCw,
  CheckCircle2,
  AlertCircle,
  Link2
} from 'lucide-react';
import { localAgentService } from '../../services/localAgentService';
import type { AgentStatus } from '../../services/localAgentService';
import { DevicePairingModal } from './DevicePairingModal';
import { DownloadAgentButton } from './DownloadAgentButton';

interface ScanMyPcCardProps {
  lastScanTime?: string;
  onScanCompleted?: () => void;
}

export const ScanMyPcCard: React.FC<ScanMyPcCardProps> = ({
  lastScanTime = "05 October 2026, 5:18 PM",
  onScanCompleted
}) => {
  const [isPairingOpen, setIsPairingOpen] = useState<boolean>(false);
  const [agentStatus, setAgentStatus] = useState<AgentStatus>({
    connected: false,
    state: 'NOT_INSTALLED',
    message: 'Checking for PhantomTrace Agent...'
  });
  const [checking, setChecking] = useState<boolean>(true);
  const [actionError, setActionError] = useState<string | null>(null);
  const pollingRef = useRef<number | null>(null);

  const checkAgent = useCallback(async () => {
    try {
      const status = await localAgentService.checkStatus();
      setAgentStatus(status);
      setActionError(null);
    } catch {
      setAgentStatus({
        connected: false,
        state: 'NOT_INSTALLED',
        message: 'PhantomTrace Agent Not Installed'
      });
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    let mounted = true;
    void localAgentService.checkStatus().then((status) => {
      if (mounted) {
        setAgentStatus(status);
        setActionError(null);
        setChecking(false);
      }
    });

    // Ping local agent every 15 seconds when idle
    const interval = window.setInterval(async () => {
      try {
        const status = await localAgentService.checkStatus();
        if (mounted) {
          setAgentStatus(status);
        }
      } catch {
        // keep prior state on transient network blip
      }
    }, 15000);

    return () => {
      mounted = false;
      window.clearInterval(interval);
    };
  }, []);

  // Handle active scan polling
  useEffect(() => {
    const isScanning = ['STARTING', 'SCANNING', 'VALIDATING', 'UPLOADING'].includes(agentStatus.state);

    if (isScanning) {
      pollingRef.current = window.setInterval(async () => {
        const update = await localAgentService.getScanStatus();
        setAgentStatus(update);

        if (update.state === 'COMPLETED') {
          if (pollingRef.current) clearInterval(pollingRef.current);
          if (onScanCompleted) {
            onScanCompleted();
          }
          // Dispatch global refresh event so all hooks/pages update telemetry
          window.dispatchEvent(new CustomEvent('phantomtrace:telemetry-refresh'));
        } else if (update.state === 'ERROR') {
          if (pollingRef.current) clearInterval(pollingRef.current);
        }
      }, 1000);
    } else {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
        pollingRef.current = null;
      }
    }

    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [agentStatus.state, onScanCompleted]);

  const handleStartScan = async () => {
    setActionError(null);
    setAgentStatus(prev => ({
      ...prev,
      state: 'STARTING',
      message: 'Initializing Windows Scanner...'
    }));

    const result = await localAgentService.startScan();
    if (!result.success) {
      setActionError(result.message);
      setAgentStatus(prev => ({
        ...prev,
        state: 'ERROR',
        message: result.message
      }));
    }
  };

  const isScanning = ['STARTING', 'SCANNING', 'VALIDATING', 'UPLOADING'].includes(agentStatus.state);

  return (
    <div
      className="pt-card pt-card-cyber"
      style={{
        padding: '1.75rem 2rem',
        background: 'linear-gradient(135deg, rgba(16, 26, 46, 0.95) 0%, rgba(9, 15, 26, 0.98) 100%)',
        border: '1px solid rgba(0, 229, 255, 0.25)',
        boxShadow: '0 8px 32px rgba(0, 0, 0, 0.35), 0 0 16px rgba(0, 229, 255, 0.08)',
        position: 'relative',
        overflow: 'hidden'
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '1.5rem'
        }}
      >
        {/* Left Side: Product Identity & Subtitle */}
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '0.4rem' }}>
            <span style={{ fontSize: '0.74rem', textTransform: 'uppercase', letterSpacing: '0.1em', color: '#00e5ff', fontWeight: 700 }}>
              PHANTOMTRACE
            </span>
            <span style={{ color: '#475569' }}>•</span>
            {agentStatus.connected ? (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.74rem', color: '#6ee7b7', fontWeight: 600 }}>
                <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#10b981', display: 'inline-block', boxShadow: '0 0 8px #10b981' }} />
                PC Connected
              </span>
            ) : (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.74rem', color: '#94a3b8', fontWeight: 500 }}>
                <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#64748b', display: 'inline-block' }} />
                PC Not Connected
              </span>
            )}
          </div>

          <h2 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#ffffff', letterSpacing: '-0.02em', margin: 0 }}>
            Protect your Windows PC
          </h2>

          <p style={{ fontSize: '0.85rem', color: '#94a3b8', marginTop: '0.35rem', marginBottom: '0.5rem', maxWidth: '520px', lineHeight: 1.5 }}>
            Run a passive, read-only memory and behavioral security scan across all running Windows processes without altering any system files.
          </p>

          <div style={{ fontSize: '0.78rem', color: '#64748b' }}>
            Last Scan: <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{lastScanTime}</span>
          </div>
        </div>

        {/* Right Side: Primary CTA & Action States */}
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.75rem' }}>
          {checking ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#94a3b8', fontSize: '0.82rem' }}>
              <RefreshCw size={15} className="animate-spin" />
              <span>Detecting Windows agent...</span>
            </div>
          ) : agentStatus.connected ? (
            <div>
              {isScanning ? (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.5rem' }}>
                  <button
                    type="button"
                    disabled
                    className="pt-btn pt-btn-primary"
                    style={{
                      padding: '0.75rem 1.75rem',
                      fontSize: '0.92rem',
                      opacity: 0.85,
                      cursor: 'wait',
                      background: 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)'
                    }}
                  >
                    <RefreshCw size={17} className="animate-spin" />
                    <span>{agentStatus.state === 'UPLOADING' ? 'Securely synchronizing...' : 'Scanning your Windows PC...'}</span>
                  </button>
                  <span style={{ fontSize: '0.76rem', color: '#38bdf8' }}>
                    {agentStatus.message || 'Analyzing process memory address spaces...'} {agentStatus.elapsedSeconds ? `(${agentStatus.elapsedSeconds}s)` : ''}
                  </span>
                </div>
              ) : agentStatus.state === 'COMPLETED' ? (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <button
                      type="button"
                      onClick={handleStartScan}
                      className="pt-btn pt-btn-primary"
                      style={{ padding: '0.75rem 1.75rem', fontSize: '0.92rem', fontWeight: 700 }}
                    >
                      <Shield size={17} />
                      <span>SCAN MY PC AGAIN</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setIsPairingOpen(true)}
                      className="pt-btn pt-btn-secondary"
                      style={{ padding: '0.75rem 0.85rem' }}
                      title="Re-pair or connect another device"
                    >
                      <Link2 size={15} />
                    </button>
                  </div>
                  <span style={{ fontSize: '0.76rem', color: '#34d399', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                    <CheckCircle2 size={13} />
                    <span>{agentStatus.message || 'Scan completed successfully.'}</span>
                  </span>
                </div>
              ) : (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                  <button
                    type="button"
                    onClick={handleStartScan}
                    className="pt-btn pt-btn-primary"
                    style={{
                      padding: '0.85rem 2.25rem',
                      fontSize: '1rem',
                      fontWeight: 800,
                      letterSpacing: '0.04em',
                      boxShadow: '0 0 20px rgba(0, 229, 255, 0.4)'
                    }}
                  >
                    <ShieldCheck size={19} />
                    <span>SCAN MY PC</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setIsPairingOpen(true)}
                    className="pt-btn pt-btn-secondary"
                    style={{ padding: '0.85rem 0.95rem' }}
                    title="Connect or re-pair device"
                  >
                    <Link2 size={16} />
                  </button>
                </div>
              )}
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.5rem' }}>
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                <button
                  type="button"
                  onClick={() => setIsPairingOpen(true)}
                  className="pt-btn pt-btn-primary"
                  style={{
                    padding: '0.75rem 1.65rem',
                    fontSize: '0.92rem',
                    fontWeight: 800,
                    boxShadow: '0 0 16px rgba(0, 229, 255, 0.3)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.45rem'
                  }}
                >
                  <Link2 size={16} />
                  <span>Connect This PC</span>
                </button>
                <DownloadAgentButton variant="secondary" size="md" />
                {agentStatus.state === 'OFFLINE' && (
                  <button
                    type="button"
                    onClick={checkAgent}
                    className="pt-btn pt-btn-secondary"
                    style={{ padding: '0.75rem 1.25rem', fontSize: '0.88rem' }}
                  >
                    <RefreshCw size={15} />
                    <span>Retry</span>
                  </button>
                )}
              </div>
              <span style={{ fontSize: '0.76rem', color: '#94a3b8' }}>
                Generate a secure pairing code to link this Windows PC
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Action / Cloud Authentication Feedback Message */}
      {actionError && (
        <div
          style={{
            marginTop: '1rem',
            padding: '0.65rem 0.95rem',
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
          <span>{actionError}</span>
        </div>
      )}

      {agentStatus.uploadResult && !agentStatus.uploadResult.success && (
        <div
          style={{
            marginTop: '1rem',
            padding: '0.65rem 0.95rem',
            background: 'rgba(234, 179, 8, 0.1)',
            border: '1px solid rgba(234, 179, 8, 0.3)',
            borderRadius: '6px',
            fontSize: '0.78rem',
            color: '#fde047',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem'
          }}
        >
          <AlertCircle size={15} style={{ flexShrink: 0 }} />
          <span>
            {agentStatus.uploadResult.message ||
              "Your scan completed, but cloud synchronization requires authentication. Results remain stored safely on this PC."}
          </span>
        </div>
      )}

      {/* Device Pairing Modal */}
      <DevicePairingModal
        isOpen={isPairingOpen}
        onClose={() => setIsPairingOpen(false)}
        onDevicePaired={() => {
          checkAgent();
        }}
      />
    </div>
  );
};
