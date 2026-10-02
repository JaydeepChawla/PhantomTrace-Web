import React from 'react';

interface StatCardProps {
  label: string;
  value: string | number;
  subValue?: string;
  icon?: React.ReactNode;
  accentColor?: string;
  trend?: {
    direction: 'up' | 'down' | 'neutral';
    label: string;
  };
}

export const StatCard: React.FC<StatCardProps> = ({
  label,
  value,
  subValue,
  icon,
  accentColor,
}) => {
  return (
    <div className="pt-stat-card">
      <div className="pt-stat-label">
        <span>{label}</span>
        {icon && (
          <span style={{ color: accentColor || 'var(--pt-cyan)', display: 'inline-flex' }}>
            {icon}
          </span>
        )}
      </div>
      <div className="pt-stat-value" style={accentColor ? { color: accentColor } : {}}>
        {value}
      </div>
      {subValue && (
        <div style={{ fontSize: '0.75rem', color: 'var(--pt-text-muted)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          {subValue}
        </div>
      )}
    </div>
  );
};
