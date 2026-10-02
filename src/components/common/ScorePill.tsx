import React from 'react';

interface ScorePillProps {
  score: number;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
}

export const ScorePill: React.FC<ScorePillProps> = ({
  score,
  size = 'md',
  showLabel = false,
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

  const sizeStyles = {
    sm: { fontSize: '0.75rem', padding: '0.12rem 0.45rem' },
    md: { fontSize: '0.85rem', padding: '0.2rem 0.6rem' },
    lg: { fontSize: '1.05rem', padding: '0.35rem 0.85rem' },
  }[size];

  return (
    <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
      <span className={`pt-score-pill ${scoreClass}`} style={sizeStyles}>
        {score}
      </span>
      {showLabel && (
        <span style={{ fontSize: '0.75rem', color: '#94a3b8', textTransform: 'uppercase', fontWeight: 600 }}>
          {label}
        </span>
      )}
    </div>
  );
};
