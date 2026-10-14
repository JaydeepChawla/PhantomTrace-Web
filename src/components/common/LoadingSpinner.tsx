import React from 'react';
import { Loader2 } from 'lucide-react';

export interface LoadingSpinnerProps {
  label?: string;
  message?: string;
  size?: 'sm' | 'md' | 'lg';
  fullHeight?: boolean;
  className?: string;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  label,
  message,
  size = 'md',
  fullHeight = false,
  className = '',
}) => {
  const displayText = message || label || 'Loading telemetry data...';
  const iconSize = {
    sm: 18,
    md: 26,
    lg: 38,
  }[size];

  return (
    <div
      className={`pt-loading-container ${fullHeight ? 'pt-loading-full-height' : ''} ${className}`}
      role="status"
      aria-live="polite"
    >
      <Loader2 size={iconSize} className="pt-spinner pt-spin text-cyan" aria-hidden="true" />
      {displayText && <span className="pt-loading-label">{displayText}</span>}
      <span className="sr-only">Loading</span>
    </div>
  );
};
