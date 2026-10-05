import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Laptop,
  Trash2,
  RefreshCw,
  Plus
} from 'lucide-react';
import { ApiDataService } from '../../services/apiDataService';
import { DevicePairingModal } from './DevicePairingModal';

interface DeviceItem {
  deviceId: string;
  deviceName: string;
  createdAt: string;
  lastSeenAt: string;
  isRevoked: boolean;
}

export const MyDevicesSection: React.FC = () => {
  const [devices, setDevices] = useState<DeviceItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [isPairingOpen, setIsPairingOpen] = useState<boolean>(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);

  const apiServiceRef = useRef<ApiDataService>(new ApiDataService());

  const fetchDevices = useCallback(async () => {
    try {
      const list = await apiServiceRef.current.getDevices();
      setDevices(list);
    } catch {
      setDevices([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDevices();
    const handleRefresh = () => fetchDevices();
    window.addEventListener('phantomtrace:telemetry-refresh', handleRefresh);
    return () => window.removeEventListener('phantomtrace:telemetry-refresh', handleRefresh);
  }, [fetchDevices]);

  const handleRevoke = async (deviceId: string) => {
    if (!window.confirm("Are you sure you want to revoke this device? It will immediately lose permission to upload scans.")) {
      return;
    }

    setRevokingId(deviceId);
    try {
      const success = await apiServiceRef.current.revokeDevice(deviceId);
      if (success) {
        setDevices(prev => prev.map(d => d.deviceId === deviceId ? { ...d, isRevoked: true } : d));
      }
    } catch (err) {
      console.error("Failed to revoke device:", err);
    } finally {
      setRevokingId(null);
    }
  };

  return (
    <div
      className="pt-card pt-card-cyber"
      style={{
        padding: '1.5rem',
        background: 'rgba(9, 15, 26, 0.75)',
        border: '1px solid var(--pt-border-subtle)',
        borderRadius: '8px',
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '1.25rem',
          flexWrap: 'wrap',
          gap: '0.75rem',
        }}
      >
        <div>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f8fafc', margin: 0 }}>
            My Enrolled Devices
          </h3>
          <div style={{ fontSize: '0.76rem', color: '#94a3b8', marginTop: '0.15rem' }}>
            Windows endpoints authorized to synchronize memory telemetry with your account.
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <button
            type="button"
            onClick={() => setIsPairingOpen(true)}
            className="pt-btn pt-btn-primary"
            style={{ padding: '0.45rem 0.95rem', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            <Plus size={14} />
            <span>Connect This PC</span>
          </button>
          <button
            type="button"
            onClick={fetchDevices}
            className="pt-btn pt-btn-secondary"
            style={{ padding: '0.45rem 0.65rem' }}
            title="Refresh devices list"
          >
            <RefreshCw size={13} className={loading ? "animate-spin" : ""} />
          </button>
        </div>
      </div>

      {loading ? (
        <div style={{ padding: '1.5rem', textAlign: 'center', color: '#64748b', fontSize: '0.82rem' }}>
          Loading enrolled devices...
        </div>
      ) : devices.length === 0 ? (
        <div
          style={{
            padding: '2rem 1.5rem',
            textAlign: 'center',
            background: 'rgba(5, 9, 17, 0.4)',
            borderRadius: '6px',
            border: '1px dashed var(--pt-border-subtle)',
          }}
        >
          <Laptop size={32} style={{ color: '#475569', margin: '0 auto 0.75rem auto' }} />
          <div style={{ fontSize: '0.88rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '0.35rem' }}>
            No Devices Enrolled Yet
          </div>
          <p style={{ fontSize: '0.78rem', color: '#64748b', maxWidth: '380px', margin: '0 auto 1rem auto' }}>
            Click "Connect This PC" to generate a short-lived pairing code and register your Windows machine.
          </p>
          <button
            type="button"
            onClick={() => setIsPairingOpen(true)}
            className="pt-btn pt-btn-primary"
            style={{ padding: '0.45rem 1.15rem', fontSize: '0.82rem' }}
          >
            Connect This PC
          </button>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {devices.map((device) => (
            <div
              key={device.deviceId}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0.85rem 1.15rem',
                borderRadius: '6px',
                background: device.isRevoked ? 'rgba(239, 68, 68, 0.04)' : 'rgba(16, 26, 46, 0.6)',
                border: device.isRevoked ? '1px solid rgba(239, 68, 68, 0.2)' : '1px solid var(--pt-border-subtle)',
                flexWrap: 'wrap',
                gap: '0.75rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <div
                  style={{
                    width: '36px',
                    height: '36px',
                    borderRadius: '6px',
                    background: device.isRevoked ? 'rgba(239, 68, 68, 0.1)' : 'rgba(0, 229, 255, 0.08)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: device.isRevoked ? '#ef4444' : '#00e5ff'
                  }}
                >
                  <Laptop size={18} />
                </div>
                <div>
                  <div style={{ fontSize: '0.88rem', fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span>{device.deviceName}</span>
                    {device.isRevoked ? (
                      <span style={{ fontSize: '0.68rem', padding: '0.1rem 0.4rem', borderRadius: '4px', background: 'rgba(239, 68, 68, 0.15)', color: '#fca5a5', border: '1px solid rgba(239, 68, 68, 0.3)' }}>
                        Revoked
                      </span>
                    ) : (
                      <span style={{ fontSize: '0.68rem', padding: '0.1rem 0.4rem', borderRadius: '4px', background: 'rgba(16, 185, 129, 0.12)', color: '#6ee7b7', border: '1px solid rgba(16, 185, 129, 0.25)' }}>
                        Connected
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: '0.74rem', color: '#64748b', marginTop: '0.15rem' }}>
                    Device ID: <span style={{ fontFamily: 'monospace', color: '#94a3b8' }}>{device.deviceId}</span> • Last seen: {device.lastSeenAt}
                  </div>
                </div>
              </div>

              {!device.isRevoked && (
                <button
                  type="button"
                  onClick={() => handleRevoke(device.deviceId)}
                  disabled={revokingId === device.deviceId}
                  className="pt-btn pt-btn-secondary"
                  style={{
                    padding: '0.35rem 0.75rem',
                    fontSize: '0.74rem',
                    color: '#f87171',
                    borderColor: 'rgba(239, 68, 68, 0.3)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.35rem'
                  }}
                >
                  <Trash2 size={13} />
                  <span>{revokingId === device.deviceId ? "Revoking..." : "Revoke Device"}</span>
                </button>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Device Pairing Modal */}
      <DevicePairingModal
        isOpen={isPairingOpen}
        onClose={() => setIsPairingOpen(false)}
        onDevicePaired={() => {
          fetchDevices();
        }}
      />
    </div>
  );
};
