import React, { useState, useEffect, useRef } from 'react';
import {
  Laptop,
  ShieldCheck,
  Copy,
  Check,
  Clock,
  RefreshCw,
  X,
  CheckCircle2,
  AlertCircle,
  Terminal,
  Zap
} from 'lucide-react';
import { localAgentService } from '../../services/localAgentService';
import { ApiDataService } from '../../services/apiDataService';

interface DevicePairingModalProps {
  isOpen: boolean;
  onClose: () => void;
  onDevicePaired?: () => void;
}

export const DevicePairingModal: React.FC<DevicePairingModalProps> = ({
  isOpen,
  onClose,
  onDevicePaired,
}) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [pairingCode, setPairingCode] = useState<string>('');
  const [pairingId, setPairingId] = useState<string>('');
  const [expiresAt, setExpiresAt] = useState<string>('');
  const [remainingSeconds, setRemainingSeconds] = useState<number>(600);
  const [copied, setCopied] = useState<boolean>(false);
  const [pairedSuccess, setPairedSuccess] = useState<boolean>(false);
  const [autoPairing, setAutoPairing] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const apiServiceRef = useRef<ApiDataService>(new ApiDataService());
  const timerRef = useRef<number | null>(null);
  const pollingRef = useRef<number | null>(null);

  // Initialize pairing request when modal opens
  useEffect(() => {
    if (!isOpen) return;

    let active = true;
    setLoading(true);
    setPairedSuccess(false);
    setErrorMsg(null);
    setCopied(false);

    apiServiceRef.current
      .startDevicePairing()
      .then((res) => {
        if (!active) return;
        setPairingCode(res.pairingCode);
        setPairingId(res.pairingId);
        setExpiresAt(res.expiresAt);
        setRemainingSeconds(600);
        setLoading(false);
      })
      .catch((err) => {
        if (!active) return;
        setLoading(false);
        setErrorMsg(err.message || 'Failed to initiate device pairing.');
      });

    return () => {
      active = false;
      if (timerRef.current) clearInterval(timerRef.current);
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [isOpen]);

  // Countdown timer for pairing code expiration
  useEffect(() => {
    if (!isOpen || !expiresAt || pairedSuccess) return;

    timerRef.current = window.setInterval(() => {
      const remaining = Math.max(0, Math.floor((new Date(expiresAt).getTime() - Date.now()) / 1000));
      setRemainingSeconds(remaining);
      if (remaining <= 0 && timerRef.current) {
        clearInterval(timerRef.current);
      }
    }, 1000);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isOpen, expiresAt, pairedSuccess]);

  // Poll server to detect when agent redeems code
  useEffect(() => {
    if (!isOpen || !pairingId || pairedSuccess) return;

    pollingRef.current = window.setInterval(async () => {
      try {
        const res = await apiServiceRef.current.checkDevicePairingStatus(pairingId);
        if (res.status === 'PAIRED') {
          setPairedSuccess(true);
          if (pollingRef.current) clearInterval(pollingRef.current);
          if (onDevicePaired) onDevicePaired();
          window.dispatchEvent(new CustomEvent('phantomtrace:telemetry-refresh'));
        } else if (res.status === 'EXPIRED') {
          if (pollingRef.current) clearInterval(pollingRef.current);
          setErrorMsg('Pairing code has expired. Please close and generate a new code.');
        }
      } catch {
        // ignore transient network errors during polling
      }
    }, 2000);

    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [isOpen, pairingId, pairedSuccess, onDevicePaired]);

  const handleCopyCode = () => {
    if (!pairingCode) return;
    navigator.clipboard.writeText(pairingCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleAutoPairLocalAgent = async () => {
    setAutoPairing(true);
    setErrorMsg(null);
    try {
      const res = await localAgentService.pairWithCode(pairingCode);
      if (res.success) {
        setPairedSuccess(true);
        if (onDevicePaired) onDevicePaired();
        window.dispatchEvent(new CustomEvent('phantomtrace:telemetry-refresh'));
      } else {
        setErrorMsg(res.message || 'Local agent pairing failed.');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to contact local agent';
      setErrorMsg(msg);
    } finally {
      setAutoPairing(false);
    }
  };

  if (!isOpen) return null;

  const minutes = Math.floor(remainingSeconds / 60);
  const seconds = remainingSeconds % 60;
  const timeFormatted = `${minutes}:${seconds.toString().padStart(2, '0')}`;

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: 'rgba(5, 9, 17, 0.85)',
        backdropFilter: 'blur(8px)',
        zIndex: 9999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '1.5rem',
      }}
      onClick={onClose}
    >
      <div
        className="pt-card pt-card-cyber"
        style={{
          width: '100%',
          maxWidth: '540px',
          background: 'linear-gradient(135deg, rgba(16, 26, 46, 0.98) 0%, rgba(9, 15, 26, 0.99) 100%)',
          border: '1px solid rgba(0, 229, 255, 0.35)',
          boxShadow: '0 20px 50px rgba(0, 0, 0, 0.6), 0 0 24px rgba(0, 229, 255, 0.15)',
          padding: '2rem',
          position: 'relative',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Close Button */}
        <button
          type="button"
          onClick={onClose}
          style={{
            position: 'absolute',
            top: '1.25rem',
            right: '1.25rem',
            background: 'transparent',
            border: 'none',
            color: '#64748b',
            cursor: 'pointer',
            padding: '0.25rem',
          }}
        >
          <X size={20} />
        </button>

        {/* Modal Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.25rem' }}>
          <div
            style={{
              width: '42px',
              height: '42px',
              borderRadius: '8px',
              background: 'rgba(0, 229, 255, 0.1)',
              border: '1px solid rgba(0, 229, 255, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#00e5ff'
            }}
          >
            <Laptop size={22} />
          </div>
          <div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#ffffff', margin: 0 }}>
              Connect This Windows PC
            </h3>
            <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
              Secure one-time pairing links this endpoint to your PhantomTrace account.
            </div>
          </div>
        </div>

        {loading ? (
          <div style={{ padding: '3rem 1rem', textAlign: 'center', color: '#94a3b8' }}>
            <RefreshCw size={24} className="animate-spin" style={{ margin: '0 auto 1rem auto', color: '#00e5ff' }} />
            <div>Generating secure pairing code...</div>
          </div>
        ) : pairedSuccess ? (
          <div style={{ textAlign: 'center', padding: '1.5rem 0' }}>
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
              <CheckCircle2 size={36} />
            </div>

            <h4 style={{ fontSize: '1.3rem', fontWeight: 800, color: '#f8fafc', marginBottom: '0.5rem' }}>
              ✓ PC Connected Successfully!
            </h4>
            <p style={{ fontSize: '0.88rem', color: '#94a3b8', lineHeight: 1.6, maxWidth: '420px', margin: '0 auto 1.75rem auto' }}>
              Your Windows PC is now securely registered. Scans initiated on this PC will automatically synchronize to your private dashboard.
            </p>

            <button
              type="button"
              onClick={onClose}
              className="pt-btn pt-btn-primary"
              style={{ padding: '0.65rem 2rem', fontSize: '0.92rem', fontWeight: 700 }}
            >
              Start Scanning
            </button>
          </div>
        ) : (
          <div>
            {/* Pairing Code Box */}
            <div
              style={{
                padding: '1.25rem',
                borderRadius: '8px',
                background: 'rgba(5, 9, 17, 0.9)',
                border: '1px solid rgba(0, 229, 255, 0.3)',
                textAlign: 'center',
                marginBottom: '1.25rem'
              }}
            >
              <div style={{ fontSize: '0.74rem', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#64748b', marginBottom: '0.5rem' }}>
                Your One-Time Pairing Code
              </div>

              <div
                style={{
                  fontSize: '2rem',
                  fontWeight: 900,
                  letterSpacing: '0.12em',
                  color: '#00e5ff',
                  fontFamily: 'monospace',
                  marginBottom: '0.75rem'
                }}
              >
                {pairingCode}
              </div>

              <div style={{ display: 'flex', justifyContent: 'center', gap: '0.75rem', alignItems: 'center' }}>
                <button
                  type="button"
                  onClick={handleCopyCode}
                  className="pt-btn pt-btn-secondary"
                  style={{ padding: '0.4rem 0.85rem', fontSize: '0.78rem' }}
                >
                  {copied ? <Check size={14} style={{ color: '#10b981' }} /> : <Copy size={14} />}
                  <span>{copied ? 'Copied' : 'Copy Code'}</span>
                </button>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.78rem', color: '#94a3b8' }}>
                  <Clock size={13} style={{ color: '#eab308' }} />
                  <span>Expires in {timeFormatted}</span>
                </div>
              </div>
            </div>

            {/* Quick Action: Auto-Pair Connected Agent */}
            <div
              style={{
                padding: '1rem',
                background: 'rgba(0, 229, 255, 0.05)',
                border: '1px solid rgba(0, 229, 255, 0.2)',
                borderRadius: '8px',
                marginBottom: '1.25rem'
              }}
            >
              <div style={{ fontSize: '0.84rem', fontWeight: 700, color: '#f8fafc', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <Zap size={15} style={{ color: '#00e5ff' }} />
                <span>Instant Localhost Pairing</span>
              </div>
              <p style={{ fontSize: '0.76rem', color: '#94a3b8', margin: '0 0 0.75rem 0', lineHeight: 1.5 }}>
                If the PhantomTrace Agent is already running on this machine (127.0.0.1:49152), pair it immediately with one click:
              </p>
              <button
                type="button"
                onClick={handleAutoPairLocalAgent}
                disabled={autoPairing || remainingSeconds <= 0}
                className="pt-btn pt-btn-primary"
                style={{ width: '100%', padding: '0.55rem 1rem', fontSize: '0.84rem', justifyContent: 'center' }}
              >
                {autoPairing ? <RefreshCw size={15} className="animate-spin" /> : <ShieldCheck size={15} />}
                <span>{autoPairing ? 'Pairing Local Agent...' : 'PAIR LOCAL AGENT NOW'}</span>
              </button>
            </div>

            {/* Manual Terminal Instructions */}
            <div style={{ fontSize: '0.76rem', color: '#64748b', lineHeight: 1.5, marginBottom: '0.5rem' }}>
              <strong>Or pair via Windows Command Prompt / PowerShell:</strong>
            </div>
            <div
              style={{
                padding: '0.65rem 0.85rem',
                background: '#090f1a',
                borderRadius: '6px',
                border: '1px solid var(--pt-border-subtle)',
                fontFamily: 'monospace',
                fontSize: '0.76rem',
                color: '#38bdf8',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                overflowX: 'auto',
              }}
            >
              <Terminal size={14} style={{ flexShrink: 0, color: '#64748b' }} />
              <span>python -m agent_service.main --pair {pairingCode}</span>
            </div>

            {errorMsg && (
              <div
                style={{
                  marginTop: '1rem',
                  padding: '0.65rem 0.85rem',
                  background: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  borderRadius: '6px',
                  color: '#fca5a5',
                  fontSize: '0.78rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem'
                }}
              >
                <AlertCircle size={15} style={{ flexShrink: 0 }} />
                <span>{errorMsg}</span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
