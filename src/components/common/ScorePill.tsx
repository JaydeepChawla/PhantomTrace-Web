import React from 'react';

export interface ScorePillProps {
  score: number;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
  className?: string;
}

export const ScorePill: React.FC<ScorePillProps> = ({
  score,
  size = 'md',
  showLabel = false,
  className = '',
}) => {
  let scoreClass = 'pt-score-clean';
  let label = 'Clean';

  if (score >= 90) {
    scoreClass = 'pt-score-critical';
    label = 'Critical';
  } else if (score >= 75) {
    scoreClass = 'pt-score-high';
    label = 'High';
  } else if (score >= 50) {
    scoreClass = 'pt-score-medium';
    label = 'Medium';
  } else if (score >= 25) {
    scoreClass = 'pt-score-low';
    label = 'Low';
  }

  const sizeClass = {
    sm: 'pt-score-sm',
    md: 'pt-score-md',
    lg: 'pt-score-lg',
  }[size];

  return (
    <div className={`pt-score-container ${className}`}>
      <span className={`pt-score-pill ${scoreClass} ${sizeClass}`} aria-label={`Threat score: ${score} (${label})`}>
        {score}
      </span>
      {showLabel && (
        <span className="pt-score-label">
          {label}
        </span>
      )}
    </div>
  );
};
