import React from 'react';
import { ArrowUpRight, ArrowDownRight, Minus } from 'lucide-react';

export interface StatCardProps {
  label: string;
  value: string | number;
  subValue?: string;
  icon?: React.ReactNode;
  accentColor?: string;
  trend?: {
    direction: 'up' | 'down' | 'neutral';
    label: string;
  };
  className?: string;
  onClick?: () => void;
}

export const StatCard: React.FC<StatCardProps> = ({
  label,
  value,
  subValue,
  icon,
  accentColor,
  trend,
  className = '',
  onClick,
}) => {
  return (
    <div
      className={`pt-stat-card ${onClick ? 'is-clickable' : ''} ${className}`}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={
        onClick
          ? (e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                onClick();
              }
            }
          : undefined
      }
    >
      <div className="pt-stat-label">
        <span>{label}</span>
        {icon && (
          <span
            className="pt-stat-icon"
            style={{ color: accentColor || 'var(--pt-cyan)' }}
            aria-hidden="true"
          >
            {icon}
          </span>
        )}
      </div>
      <div
        className="pt-stat-value"
        style={accentColor ? { color: accentColor } : undefined}
      >
        {value}
      </div>
      <div className="pt-stat-footer">
        {subValue && <span className="pt-stat-subvalue">{subValue}</span>}
        {trend && (
          <span className={`pt-stat-trend pt-trend-${trend.direction}`}>
            {trend.direction === 'up' && <ArrowUpRight size={13} aria-hidden="true" />}
            {trend.direction === 'down' && <ArrowDownRight size={13} aria-hidden="true" />}
            {trend.direction === 'neutral' && <Minus size={13} aria-hidden="true" />}
            <span>{trend.label}</span>
          </span>
        )}
      </div>
    </div>
  );
};
