import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { 
  ArrowLeft, 
  Terminal, 
  Cpu, 
  FileCheck2, 
  Activity, 
  Layers, 
  ShieldAlert, 
  Lock,
  Copy,
  Check
} from 'lucide-react';
import { dataService } from '../services';
import type { Process } from '../types';
import { Card } from '../components/common/Card';
import { Badge } from '../components/common/Badge';
import { RecommendedResponseGuide } from '../components/response/RecommendedResponseGuide';

export const ProcessDetailsPage: React.FC = () => {
  const { pid } = useParams<{ pid: string }>();
  const navigate = useNavigate();
  const numericPid = pid ? parseInt(pid, 10) : NaN;
  const [currentProcess, setCurrentProcess] = useState<Process | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [activeTab, setActiveTab] = useState<'evidence' | 'memory' | 'behavior' | 'response'>('evidence');
  const [copiedCmd, setCopiedCmd] = useState(false);

  useEffect(() => {
    let cancelled = false;

    if (isNaN(numericPid)) {
      setLoading(false);
      return;
    }

    async function loadProcess() {
      try {
        setLoading(true);
        setError(null);
        const result = await dataService.getProcess(numericPid);
        if (!cancelled) {
          setCurrentProcess(result);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Unable to load process details');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadProcess();

    return () => {
      cancelled = true;
    };
  }, [numericPid]);

  if (loading && !currentProcess) {
    return <div style={{ padding: '3rem', textAlign: 'center', color: '#94a3b8' }}>Loading process telemetry...</div>;
  }

  if (error) {
    return (
      <div style={{ padding: '3rem', textAlign: 'center' }}>
        <h3 style={{ color: '#ef4444', marginBottom: '1rem' }}>Telemetry Error</h3>
        <p style={{ color: '#94a3b8', marginBottom: '1.5rem' }}>{error}</p>
        <Link to="/processes" className="pt-btn pt-btn-secondary">
          <ArrowLeft size={16} />
          <span>Back to Process Explorer</span>
        </Link>
      </div>
    );
  }

  if (!currentProcess) {
    return (
      <div style={{ padding: '3rem', textAlign: 'center' }}>
        <h3 style={{ color: '#ffffff', marginBottom: '1rem' }}>Process Not Found</h3>
        <p style={{ color: '#94a3b8', marginBottom: '1.5rem' }}>
          No active telemetry for PID {pid} was located in the current scan results.
        </p>
        <Link to="/processes" className="pt-btn pt-btn-secondary">
          <ArrowLeft size={16} />
          <span>Back to Process Explorer</span>
        </Link>
      </div>
    );
  }

  const p = currentProcess;
  const memoryItems = p.detailedMemoryEvidence || [];
  const behaviorItems = p.detailedBehaviorEvidence || [];
  const memoryIndicators = p.memoryIndicators || p.memoryEvidence?.indicators || [];
  const correlationText = p.correlationSummary || p.correlationEvidence?.explanation || 'No correlation notes available.';

  const copyCommandLine = () => {
    if (p.commandLine) {
      navigator.clipboard.writeText(p.commandLine);
      setCopiedCmd(true);
      setTimeout(() => setCopiedCmd(false), 2000);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Back button and quick breadcrumb */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <button
          onClick={() => navigate(-1)}
          className="pt-btn pt-btn-secondary"
          style={{ padding: '0.4rem 0.85rem', fontSize: '0.8rem' }}
        >
          <ArrowLeft size={14} />
          <span>Back</span>
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          <span style={{ fontSize: '0.78rem', color: '#64748b' }}>Score Mode:</span>
          <Badge level="neutral">{p.scoreMode}</Badge>
          <span style={{ fontSize: '0.78rem', color: '#64748b', marginLeft: '0.5rem' }}>Integrity:</span>
          <Badge level="neutral">{p.integrityLevel}</Badge>
        </div>
      </div>

      {/* Main Process Identity Card */}
      <div 
        className="pt-card pt-card-cyber"
        style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div 
              style={{ 
                width: '52px', 
                height: '52px', 
                borderRadius: '10px', 
                background: 'rgba(0, 229, 255, 0.1)', 
                border: '1px solid rgba(0, 229, 255, 0.3)',
                display: 'flex', 
                alignItems: 'center', 
                justifyContent: 'center' 
              }}
            >
              <Cpu size={28} style={{ color: '#00e5ff' }} />
            </div>

            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <h2 style={{ fontSize: '1.45rem', fontWeight: 800, color: '#ffffff', letterSpacing: '-0.01em', margin: 0 }}>
                  {p.name}
                </h2>
                <span className="text-mono" style={{ fontSize: '1rem', color: '#00e5ff', fontWeight: 700 }}>
                  PID: {p.pid}
                </span>
                <Badge level={p.threatLevel}>{p.threatLevel}</Badge>
              </div>
              <div style={{ fontSize: '0.82rem', color: '#94a3b8', marginTop: '0.25rem', fontFamily: 'var(--font-mono)' }}>
                {p.path}
              </div>
            </div>
          </div>

          {/* Threat Score Big Display */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.72rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Threat Score
              </div>
              <div style={{ fontSize: '1.85rem', fontWeight: 800, color: p.threatScore >= 75 ? '#ef4444' : '#facc15', fontFamily: 'var(--font-mono)' }}>
                {p.threatScore}<span style={{ fontSize: '1rem', color: '#64748b' }}>/100</span>
              </div>
            </div>

            <div style={{ borderLeft: '1px solid var(--pt-border-subtle)', paddingLeft: '1rem', display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.78rem' }}>
              <div>
                <span style={{ color: '#64748b' }}>Behavior Score: </span>
                <strong style={{ color: '#f97316', fontFamily: 'var(--font-mono)' }}>{p.behaviorScore}</strong>
              </div>
              <div>
                <span style={{ color: '#64748b' }}>Memory Score: </span>
                <strong style={{ color: '#00e5ff', fontFamily: 'var(--font-mono)' }}>{p.memoryScore}</strong>
              </div>
            </div>
          </div>
        </div>

        {/* Process Metadata Attributes Grid */}
        <div 
          style={{ 
            display: 'grid', 
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', 
            gap: '0.85rem', 
            paddingTop: '1rem', 
            borderTop: '1px solid var(--pt-border-subtle)' 
          }}
        >
          <div>
            <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Classification</span>
            <span style={{ fontSize: '0.86rem', color: '#f8fafc', fontWeight: 600 }}>{p.application}</span>
          </div>

          <div>
            <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Parent Process</span>
            <span style={{ fontSize: '0.86rem', color: '#f8fafc', fontWeight: 600 }}>{p.parentName} (PID: {p.parentPid})</span>
          </div>

          <div>
            <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>User Context</span>
            <span style={{ fontSize: '0.86rem', color: '#f8fafc', fontWeight: 600 }}>{p.userContext}</span>
          </div>

          <div>
            <span style={{ fontSize: '0.72rem', color: '#64748b', display: 'block', textTransform: 'uppercase' }}>Scan Timestamp</span>
            <span style={{ fontSize: '0.86rem', color: '#f8fafc', fontWeight: 600 }}>{p.timestamp}</span>
          </div>
        </div>

        {/* Command Line Box */}
        <div style={{ background: 'rgba(5, 9, 17, 0.75)', border: '1px solid var(--pt-border-subtle)', borderRadius: '6px', padding: '0.75rem 1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
            <span style={{ fontSize: '0.74rem', color: '#94a3b8', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
              <Terminal size={13} style={{ color: '#00e5ff' }} />
              Command Line
            </span>
            <button
              onClick={copyCommandLine}
              style={{ fontSize: '0.72rem', color: copiedCmd ? '#10b981' : '#38bdf8', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
            >
              {copiedCmd ? <Check size={12} /> : <Copy size={12} />}
              <span>{copiedCmd ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
          <code 
            style={{ 
              fontSize: '0.78rem', 
              color: '#38bdf8', 
              wordBreak: 'break-all', 
              lineHeight: 1.45, 
              display: 'block' 
            }}
          >
            {p.commandLine}
          </code>
        </div>
      </div>

      {/* Navigation Tabs for Forensic Drill-Down */}
      <div style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid var(--pt-border-subtle)', paddingBottom: '0.5rem' }}>
        <button
          onClick={() => setActiveTab('evidence')}
          className={`pt-btn ${activeTab === 'evidence' ? 'pt-btn-primary' : 'pt-btn-secondary'}`}
          style={{ padding: '0.45rem 1rem', fontSize: '0.82rem' }}
        >
          <Layers size={15} />
          <span>Evidence Overview &amp; Correlation</span>
        </button>

        <button
          onClick={() => setActiveTab('memory')}
          className={`pt-btn ${activeTab === 'memory' ? 'pt-btn-primary' : 'pt-btn-secondary'}`}
          style={{ padding: '0.45rem 1rem', fontSize: '0.82rem' }}
        >
          <FileCheck2 size={15} />
          <span>Memory Evidence ({memoryItems.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('behavior')}
          className={`pt-btn ${activeTab === 'behavior' ? 'pt-btn-primary' : 'pt-btn-secondary'}`}
          style={{ padding: '0.45rem 1rem', fontSize: '0.82rem' }}
        >
          <Activity size={15} />
          <span>Behavior Evidence ({behaviorItems.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('response')}
          className={`pt-btn ${activeTab === 'response' ? 'pt-btn-primary' : 'pt-btn-secondary'}`}
          style={{ padding: '0.45rem 1rem', fontSize: '0.82rem' }}
        >
          <ShieldAlert size={15} />
          <span>Recommended Response</span>
        </button>
      </div>

      {/* Tab 1: Evidence Overview & Correlation */}
      {activeTab === 'evidence' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* Correlation Banner */}
          <Card
            title="Forensic Correlation Analysis"
            subtitle="Synthesizing volatile memory allocations with behavioral execution signals"
          >
            <div style={{ background: 'rgba(0, 229, 255, 0.04)', borderLeft: '4px solid var(--pt-cyan)', padding: '1rem', borderRadius: '0 6px 6px 0', marginBottom: '1.25rem' }}>
              <p style={{ fontSize: '0.88rem', color: '#f8fafc', lineHeight: 1.6 }}>
                {correlationText}
              </p>
            </div>

            {/* Memory Indicators Badges */}
            <div style={{ marginBottom: '1.25rem' }}>
              <div style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 600, marginBottom: '0.5rem', textTransform: 'uppercase' }}>
                Primary Memory Indicators
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                {memoryIndicators.map((ind, i) => (
                  <span
                    key={i}
                    style={{
                      background: 'rgba(239, 68, 68, 0.1)',
                      border: '1px solid rgba(239, 68, 68, 0.3)',
                      color: '#fca5a5',
                      padding: '0.25rem 0.65rem',
                      borderRadius: '4px',
                      fontSize: '0.78rem',
                      fontFamily: 'var(--font-mono)'
                    }}
                  >
                    {ind}
                  </span>
                ))}
              </div>
            </div>

            {/* Preserved Evidence Note */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.78rem', color: '#64748b' }}>
              <Lock size={13} style={{ color: '#00e5ff' }} />
              <span>Evidence preservation policy: Volatile indicators are captured in read-only telemetry and preserved independently of binary trust flags.</span>
            </div>
          </Card>

          {/* Mini Preview of Response Guidance */}
          <Card
            title="Triage &amp; Recommended Response Summary"
            subtitle="Immediate non-destructive investigation steps"
            action={
              <button onClick={() => setActiveTab('response')} className="pt-btn pt-btn-cyber" style={{ padding: '0.25rem 0.75rem', fontSize: '0.75rem' }}>
                View Full Response Protocol
              </button>
            }
          >
            <RecommendedResponseGuide process={p} />
          </Card>
        </div>
      )}

      {/* Tab 2: Memory Evidence Details */}
      {activeTab === 'memory' && (
        <Card
          title="Memory Evidence Telemetry"
          subtitle="Unbacked executable regions, protection anomalies, and inline hook heuristics"
        >
          {memoryItems.length === 0 ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: '#64748b' }}>
              No anomalous memory regions detected for this process. All code pages are backed by verified disk modules.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {memoryItems.map((mem) => (
                <div 
                  key={mem.id}
                  style={{ 
                    background: 'rgba(9, 15, 26, 0.7)', 
                    border: '1px solid var(--pt-border-subtle)', 
                    borderRadius: '8px', 
                    padding: '1.25rem' 
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                      <span style={{ fontSize: '0.92rem', fontWeight: 700, color: '#ffffff' }}>
                        {mem.type}
                      </span>
                      <Badge level={mem.severity}>{mem.severity}</Badge>
                    </div>
                    <span className="text-mono" style={{ fontSize: '0.75rem', color: '#00e5ff', background: 'rgba(0, 229, 255, 0.1)', padding: '0.15rem 0.5rem', borderRadius: '4px' }}>
                      ID: {mem.id}
                    </span>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '0.75rem', marginBottom: '0.75rem', fontSize: '0.78rem' }}>
                    <div>
                      <span style={{ color: '#64748b', display: 'block' }}>Base Address</span>
                      <strong className="text-mono" style={{ color: '#38bdf8' }}>{mem.address}</strong>
                    </div>
                    <div>
                      <span style={{ color: '#64748b', display: 'block' }}>Region Size</span>
                      <strong className="text-mono" style={{ color: '#cbd5e1' }}>{mem.size}</strong>
                    </div>
                    <div>
                      <span style={{ color: '#64748b', display: 'block' }}>Page Protection</span>
                      <strong className="text-mono" style={{ color: '#f87171' }}>{mem.protection}</strong>
                    </div>
                  </div>

                  <p style={{ fontSize: '0.82rem', color: '#94a3b8', lineHeight: 1.5, background: 'rgba(0, 0, 0, 0.3)', padding: '0.65rem 0.85rem', borderRadius: '4px', borderLeft: '2px solid rgba(0, 229, 255, 0.4)' }}>
                    {mem.details}
                  </p>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      {/* Tab 3: Behavior Evidence Details */}
      {activeTab === 'behavior' && (
        <Card
          title="Behavioral Telemetry &amp; Lineage Signals"
          subtitle="Observed execution behaviors mapped to MITRE ATT&CK techniques"
        >
          {behaviorItems.length === 0 ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: '#64748b' }}>
              No anomalous behavioral events recorded for this process.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {behaviorItems.map((beh) => (
                <div 
                  key={beh.id}
                  style={{ 
                    background: 'rgba(9, 15, 26, 0.7)', 
                    border: '1px solid var(--pt-border-subtle)', 
                    borderRadius: '8px', 
                    padding: '1.25rem' 
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.45rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                      <span style={{ fontSize: '0.92rem', fontWeight: 700, color: '#ffffff' }}>
                        {beh.category}
                      </span>
                      <Badge level="neutral">Confidence: {beh.confidence}</Badge>
                    </div>
                    <span className="text-mono" style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                      {beh.timestamp}
                    </span>
                  </div>

                  <p style={{ fontSize: '0.84rem', color: '#cbd5e1', lineHeight: 1.5, marginBottom: '0.75rem' }}>
                    {beh.description}
                  </p>

                  {beh.mitreTechnique && (
                    <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', background: 'rgba(2, 132, 199, 0.12)', border: '1px solid rgba(0, 229, 255, 0.25)', padding: '0.2rem 0.6rem', borderRadius: '4px', fontSize: '0.74rem', color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>
                      <strong>MITRE ATT&amp;CK:</strong>
                      <span>{beh.mitreTechnique}</span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      {/* Tab 4: Recommended Response Protocol */}
      {activeTab === 'response' && (
        <Card
          title="Recommended Investigation Protocol"
          subtitle="Structured step-by-step guidance for Tier 1 & Tier 2 forensic triage"
        >
          <RecommendedResponseGuide process={p} />
        </Card>
      )}
    </div>
  );
};
