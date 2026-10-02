import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { ArrowLeft, AlertCircle } from 'lucide-react';
import { dataService } from '../services';
import { AlertInvestigation } from '../components/alerts/AlertInvestigation';
import type { ThreatAlert } from '../types';

export const AlertInvestigationPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [alert, setAlert] = useState<ThreatAlert | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    if (!id) {
      setLoading(false);
      return;
    }

    async function loadAlert() {
      try {
        setLoading(true);
        setError(null);
        const result = await dataService.getThreatAlert(id!);
        if (!cancelled) {
          setAlert(result);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Unable to load threat alert telemetry');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadAlert();

    return () => {
      cancelled = true;
    };
  }, [id]);

  const handleStatusChange = async (newStatus: 'NEW' | 'INVESTIGATING' | 'RESOLVED' | 'DISMISSED') => {
    if (!id || !alert) return;
    try {
      if (dataService.updateAlertStatus) {
        await dataService.updateAlertStatus(id, newStatus);
      }
      setAlert((prev) => prev ? { ...prev, status: newStatus } : null);
    } catch (err) {
      console.error('Failed to update alert status:', err);
    }
  };

  if (loading && !alert) {
    return <div style={{ padding: '3rem', textAlign: 'center', color: '#94a3b8' }}>Loading Threat Alert Telemetry...</div>;
  }

  if (error) {
    return (
      <div style={{ padding: '3rem', textAlign: 'center' }}>
        <h3 style={{ color: '#ef4444', marginBottom: '1rem' }}>Alert Investigation Error</h3>
        <p style={{ color: '#94a3b8', marginBottom: '1.5rem' }}>{error}</p>
        <Link to="/alerts" className="pt-btn pt-btn-secondary">
          <ArrowLeft size={16} />
          <span>Back to Threat Alerts</span>
        </Link>
      </div>
    );
  }

  if (!alert) {
    return (
      <div style={{ padding: '3rem', textAlign: 'center' }}>
        <div style={{ display: 'inline-flex', padding: '1rem', background: 'rgba(239, 68, 68, 0.1)', borderRadius: '50%', marginBottom: '1rem' }}>
          <AlertCircle size={32} style={{ color: '#ef4444' }} />
        </div>
        <h3 style={{ color: '#ffffff', marginBottom: '0.5rem' }}>Threat Alert Not Found</h3>
        <p style={{ color: '#94a3b8', marginBottom: '1.5rem' }}>
          No active telemetry for Alert ID <span className="text-mono" style={{ color: '#00e5ff' }}>{id}</span> was located in current scan records.
        </p>
        <Link to="/alerts" className="pt-btn pt-btn-secondary">
          <ArrowLeft size={16} />
          <span>Return to Threat Alerts</span>
        </Link>
      </div>
    );
  }

  return (
    <AlertInvestigation 
      alert={alert} 
      onStatusChange={handleStatusChange}
      onBack={() => navigate('/alerts')}
    />
  );
};
