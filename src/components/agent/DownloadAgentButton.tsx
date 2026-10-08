import React, { useState } from 'react';
import { Download, Loader2, AlertCircle } from 'lucide-react';

interface DownloadAgentButtonProps {
  className?: string;
  style?: React.CSSProperties;
  variant?: 'primary' | 'secondary' | 'cyber';
  size?: 'sm' | 'md' | 'lg';
}

export const DownloadAgentButton: React.FC<DownloadAgentButtonProps> = ({
  className = '',
  style = {},
  variant = 'secondary',
  size = 'md'
}) => {
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleDownload = async () => {
    if (downloading) return;
    setDownloading(true);
    setError(null);

    try {
      const installerUrl = '/downloads/PhantomTrace_Agent_Setup.exe';
      const link = document.createElement('a');
      link.href = installerUrl;
      link.download = 'PhantomTrace_Agent_Setup.exe';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    } catch {
      setError('Unable to download the PhantomTrace Agent. Please try again.');
    } finally {
      setDownloading(false);
    }
  };

  const btnClass = variant === 'primary'
    ? 'pt-btn pt-btn-primary'
    : variant === 'cyber'
      ? 'pt-btn pt-btn-cyber'
      : 'pt-btn pt-btn-secondary';

  const sizeStyle = size === 'sm'
    ? { padding: '0.45rem 0.85rem', fontSize: '0.8rem' }
    : size === 'lg'
      ? { padding: '0.85rem 1.65rem', fontSize: '0.96rem' }
      : { padding: '0.65rem 1.25rem', fontSize: '0.88rem' };

  return (
    <div style={{ display: 'inline-flex', flexDirection: 'column', gap: '0.4rem' }}>
      <button
        type="button"
        id="pt-download-agent-btn"
        onClick={handleDownload}
        disabled={downloading}
        className={`${btnClass} ${className}`.trim()}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.45rem',
          cursor: downloading ? 'not-allowed' : 'pointer',
          opacity: downloading ? 0.75 : 1,
          ...sizeStyle,
          ...style
        }}
        title="Download Agent"
      >
        {downloading ? (
          <>
            <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} />
            <span>Downloading...</span>
          </>
        ) : (
          <>
            <Download size={16} />
            <span>Download Agent</span>
          </>
        )}
      </button>

      {error && (
        <div
          role="alert"
          style={{
            fontSize: '0.74rem',
            color: '#fca5a5',
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid rgba(239, 68, 68, 0.25)',
            borderRadius: '4px',
            padding: '0.35rem 0.65rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.35rem'
          }}
        >
          <AlertCircle size={13} style={{ flexShrink: 0 }} />
          <span>{error}</span>
        </div>
      )}
    </div>
  );
};
