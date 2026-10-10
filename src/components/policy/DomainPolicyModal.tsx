import React, { useState, useEffect } from 'react';
import {
  Shield,
  Plus,
  Trash2,
  CheckCircle2,
  AlertTriangle,
  X,
  Lock,
  Globe,
  RefreshCw,
} from 'lucide-react';
import { dataService } from '../../services';
import type { DomainPolicy } from '../../types';

interface DomainPolicyModalProps {
  isOpen: boolean;
  onClose: () => void;
  onPoliciesUpdated?: () => void;
}

export const DomainPolicyModal: React.FC<DomainPolicyModalProps> = ({
  isOpen,
  onClose,
  onPoliciesUpdated,
}) => {
  const [policies, setPolicies] = useState<DomainPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<'ALL' | 'ALLOW' | 'BLOCK'>('ALL');
  const [domainInput, setDomainInput] = useState('');
  const [policyType, setPolicyType] = useState<'BLOCK' | 'ALLOW'>('BLOCK');
  const [reasonInput, setReasonInput] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const fetchPolicies = async () => {
    try {
      setLoading(true);
      setErrorMessage(null);
      if (dataService.getDomainPolicies) {
        const list = await dataService.getDomainPolicies();
        setPolicies(list);
      }
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to retrieve domain security policies.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchPolicies();
    }
  }, [isOpen]);

  const handleAddPolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanDomain = domainInput.trim().toLowerCase();
    if (!cleanDomain) {
      setErrorMessage('Please specify a valid domain or hostname.');
      return;
    }

    try {
      setSubmitting(true);
      setErrorMessage(null);
      setSuccessMessage(null);

      if (dataService.addDomainPolicy) {
        const newPolicy = await dataService.addDomainPolicy(cleanDomain, policyType, reasonInput.trim() || undefined);
        setPolicies((prev) => [newPolicy, ...prev.filter((p) => p.domain.toLowerCase() !== cleanDomain)]);
        setSuccessMessage(`Domain '${cleanDomain}' successfully added to ${policyType}list.`);
        setDomainInput('');
        setReasonInput('');
        if (onPoliciesUpdated) onPoliciesUpdated();
      }
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to create domain security policy.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDeletePolicy = async (policyId: string, domain: string) => {
    if (!window.confirm(`Remove policy rule for '${domain}'?`)) return;

    try {
      setErrorMessage(null);
      if (dataService.deleteDomainPolicy) {
        const success = await dataService.deleteDomainPolicy(policyId);
        if (success) {
          setPolicies((prev) => prev.filter((p) => p.policyId !== policyId));
          setSuccessMessage(`Policy rule for '${domain}' removed.`);
          if (onPoliciesUpdated) onPoliciesUpdated();
        } else {
          setErrorMessage('Could not remove policy rule.');
        }
      }
    } catch (err: any) {
      setErrorMessage(err?.message || 'Failed to remove policy rule.');
    }
  };

  if (!isOpen) return null;

  const filteredPolicies = policies.filter((p) => {
    if (filter === 'ALL') return true;
    return p.policyType === filter;
  });

  const allowCount = policies.filter((p) => p.policyType === 'ALLOW').length;
  const blockCount = policies.filter((p) => p.policyType === 'BLOCK').length;

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 9999,
        background: 'rgba(5, 10, 20, 0.85)',
        backdropFilter: 'blur(8px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '1.5rem',
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        style={{
          width: '100%',
          maxWidth: '750px',
          maxHeight: '90vh',
          background: '#0d1527',
          border: '1px solid rgba(0, 229, 255, 0.3)',
          borderRadius: '12px',
          boxShadow: '0 20px 50px rgba(0, 0, 0, 0.7), 0 0 25px rgba(0, 229, 255, 0.15)',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: '1.25rem 1.5rem',
            borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: 'rgba(15, 23, 42, 0.75)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '8px',
                background: 'rgba(0, 229, 255, 0.12)',
                border: '1px solid rgba(0, 229, 255, 0.3)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#00e5ff',
              }}
            >
              <Shield size={20} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700, color: '#ffffff' }}>
                  Domain Security Policies
                </h3>
                <span
                  style={{
                    fontSize: '0.68rem',
                    fontWeight: 700,
                    padding: '0.15rem 0.5rem',
                    borderRadius: '4px',
                    background: 'rgba(6, 182, 212, 0.15)',
                    color: '#38bdf8',
                    border: '1px solid rgba(6, 182, 212, 0.3)',
                  }}
                >
                  PHASE 4
                </span>
              </div>
              <p style={{ margin: 0, fontSize: '0.78rem', color: '#94a3b8', marginTop: '2px' }}>
                Enforce custom domain Allowlist &amp; Blocklist rules synchronized with browser extension
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="pt-btn pt-btn-secondary"
            style={{ padding: '0.4rem', borderRadius: '6px' }}
          >
            <X size={18} />
          </button>
        </div>

        {/* Sync Status Banner */}
        <div
          style={{
            padding: '0.65rem 1.5rem',
            background: 'rgba(0, 229, 255, 0.05)',
            borderBottom: '1px solid rgba(0, 229, 255, 0.15)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: '0.78rem',
            color: '#cbd5e1',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <span
              style={{
                width: '7px',
                height: '7px',
                borderRadius: '50%',
                background: '#10b981',
                boxShadow: '0 0 6px #10b981',
              }}
            />
            <span>Extension Policy Sync: <strong>Active</strong></span>
          </div>
          <button
            type="button"
            onClick={fetchPolicies}
            className="pt-btn pt-btn-secondary"
            style={{ padding: '0.2rem 0.6rem', fontSize: '0.72rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            <RefreshCw size={12} />
            <span>Refresh</span>
          </button>
        </div>

        {/* Body content */}
        <div style={{ padding: '1.25rem 1.5rem', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* Notifications */}
          {errorMessage && (
            <div
              style={{
                padding: '0.75rem 1rem',
                borderRadius: '6px',
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                color: '#f87171',
                fontSize: '0.8rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
              }}
            >
              <AlertTriangle size={16} />
              <span>{errorMessage}</span>
            </div>
          )}

          {successMessage && (
            <div
              style={{
                padding: '0.75rem 1rem',
                borderRadius: '6px',
                background: 'rgba(16, 185, 129, 0.1)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                color: '#34d399',
                fontSize: '0.8rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
              }}
            >
              <CheckCircle2 size={16} />
              <span>{successMessage}</span>
            </div>
          )}

          {/* Add Policy Form */}
          <form
            onSubmit={handleAddPolicy}
            style={{
              padding: '1rem',
              borderRadius: '8px',
              background: 'rgba(15, 23, 42, 0.6)',
              border: '1px solid rgba(255, 255, 255, 0.08)',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.85rem',
            }}
          >
            <div style={{ fontSize: '0.84rem', fontWeight: 600, color: '#e2e8f0', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Plus size={15} style={{ color: '#00e5ff' }} />
              <span>Define New Domain Policy Rule</span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1.2fr', gap: '0.75rem' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.3rem' }}>
                  Target Domain or Hostname
                </label>
                <div style={{ position: 'relative' }}>
                  <Globe
                    size={14}
                    style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: '#64748b' }}
                  />
                  <input
                    type="text"
                    value={domainInput}
                    onChange={(e) => setDomainInput(e.target.value)}
                    placeholder="e.g. evil-phishing.org, intranet.local"
                    style={{
                      width: '100%',
                      padding: '0.55rem 0.75rem 0.55rem 2rem',
                      borderRadius: '6px',
                      background: '#090e17',
                      border: '1px solid rgba(255, 255, 255, 0.12)',
                      color: '#ffffff',
                      fontSize: '0.84rem',
                      outline: 'none',
                    }}
                  />
                </div>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.3rem' }}>
                  Policy Enforcement Action
                </label>
                <div style={{ display: 'flex', gap: '0.4rem' }}>
                  <button
                    type="button"
                    onClick={() => setPolicyType('BLOCK')}
                    style={{
                      flex: 1,
                      padding: '0.55rem 0.5rem',
                      borderRadius: '6px',
                      fontSize: '0.78rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                      border: policyType === 'BLOCK' ? '1px solid #ef4444' : '1px solid rgba(255, 255, 255, 0.1)',
                      background: policyType === 'BLOCK' ? 'rgba(239, 68, 68, 0.2)' : 'transparent',
                      color: policyType === 'BLOCK' ? '#fca5a5' : '#94a3b8',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    BLOCK (Deny)
                  </button>
                  <button
                    type="button"
                    onClick={() => setPolicyType('ALLOW')}
                    style={{
                      flex: 1,
                      padding: '0.55rem 0.5rem',
                      borderRadius: '6px',
                      fontSize: '0.78rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                      border: policyType === 'ALLOW' ? '1px solid #10b981' : '1px solid rgba(255, 255, 255, 0.1)',
                      background: policyType === 'ALLOW' ? 'rgba(16, 185, 129, 0.2)' : 'transparent',
                      color: policyType === 'ALLOW' ? '#6ee7b7' : '#94a3b8',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    ALLOW (Trust)
                  </button>
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
              <input
                type="text"
                value={reasonInput}
                onChange={(e) => setReasonInput(e.target.value)}
                placeholder="Optional justification: e.g. Confirmed phishing campaign #812, Partner API"
                style={{
                  flex: 1,
                  padding: '0.5rem 0.75rem',
                  borderRadius: '6px',
                  background: '#090e17',
                  border: '1px solid rgba(255, 255, 255, 0.12)',
                  color: '#ffffff',
                  fontSize: '0.8rem',
                  outline: 'none',
                }}
              />
              <button
                type="submit"
                disabled={submitting}
                className="pt-btn pt-btn-primary"
                style={{ padding: '0.5rem 1rem', fontSize: '0.82rem', whiteSpace: 'nowrap' }}
              >
                {submitting ? 'Applying Rule...' : 'Add Rule'}
              </button>
            </div>
          </form>

          {/* Policy List Filtering Tabs */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '0.65rem' }}>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                type="button"
                onClick={() => setFilter('ALL')}
                style={{
                  padding: '0.35rem 0.75rem',
                  borderRadius: '6px',
                  fontSize: '0.76rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  border: 'none',
                  background: filter === 'ALL' ? 'rgba(0, 229, 255, 0.2)' : 'transparent',
                  color: filter === 'ALL' ? '#00e5ff' : '#94a3b8',
                }}
              >
                All Rules ({policies.length})
              </button>
              <button
                type="button"
                onClick={() => setFilter('BLOCK')}
                style={{
                  padding: '0.35rem 0.75rem',
                  borderRadius: '6px',
                  fontSize: '0.76rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  border: 'none',
                  background: filter === 'BLOCK' ? 'rgba(239, 68, 68, 0.2)' : 'transparent',
                  color: filter === 'BLOCK' ? '#f87171' : '#94a3b8',
                }}
              >
                Blocklist ({blockCount})
              </button>
              <button
                type="button"
                onClick={() => setFilter('ALLOW')}
                style={{
                  padding: '0.35rem 0.75rem',
                  borderRadius: '6px',
                  fontSize: '0.76rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  border: 'none',
                  background: filter === 'ALLOW' ? 'rgba(16, 185, 129, 0.2)' : 'transparent',
                  color: filter === 'ALLOW' ? '#34d399' : '#94a3b8',
                }}
              >
                Allowlist ({allowCount})
              </button>
            </div>
            <span style={{ fontSize: '0.72rem', color: '#64748b' }}>
              Prioritized over external threat intel feeds
            </span>
          </div>

          {/* Table / List */}
          {loading ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: '#94a3b8', fontSize: '0.85rem' }}>
              Loading domain policy rules...
            </div>
          ) : filteredPolicies.length === 0 ? (
            <div
              style={{
                padding: '2.5rem 1.5rem',
                textAlign: 'center',
                borderRadius: '8px',
                background: 'rgba(15, 23, 42, 0.3)',
                border: '1px dashed rgba(255, 255, 255, 0.1)',
                color: '#94a3b8',
              }}
            >
              <Lock size={28} style={{ color: '#475569', marginBottom: '0.5rem' }} />
              <div style={{ fontSize: '0.88rem', fontWeight: 600, color: '#e2e8f0' }}>No Domain Policies Configured</div>
              <div style={{ fontSize: '0.78rem', color: '#64748b', marginTop: '0.2rem' }}>
                Create a Blocklist or Allowlist rule above to enforce custom domain governance.
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {filteredPolicies.map((p) => {
                const isBlock = p.policyType === 'BLOCK';
                return (
                  <div
                    key={p.policyId}
                    style={{
                      padding: '0.75rem 1rem',
                      borderRadius: '6px',
                      background: 'rgba(15, 23, 42, 0.65)',
                      border: '1px solid rgba(255, 255, 255, 0.06)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '0.75rem',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                      <span
                        style={{
                          fontSize: '0.7rem',
                          fontWeight: 700,
                          padding: '0.15rem 0.55rem',
                          borderRadius: '4px',
                          background: isBlock ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                          color: isBlock ? '#ef4444' : '#10b981',
                          border: `1px solid ${isBlock ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`,
                          letterSpacing: '0.5px',
                        }}
                      >
                        {p.policyType}
                      </span>
                      <div>
                        <div style={{ fontSize: '0.88rem', fontWeight: 600, color: '#ffffff', fontFamily: 'monospace' }}>
                          {p.domain}
                        </div>
                        {p.reason && (
                          <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '1px' }}>
                            {p.reason}
                          </div>
                        )}
                      </div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                      <span style={{ fontSize: '0.72rem', color: '#64748b' }}>
                        {new Date(p.updatedAt || p.createdAt).toLocaleDateString()}
                      </span>
                      <button
                        type="button"
                        onClick={() => handleDeletePolicy(p.policyId, p.domain)}
                        className="pt-btn pt-btn-secondary"
                        style={{ padding: '0.35rem', borderRadius: '4px', color: '#ef4444' }}
                        title="Delete policy rule"
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
