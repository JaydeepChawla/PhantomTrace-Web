import React from 'react';
import type { ThreatLevel } from '../../types';

export interface BadgeProps {
  level?: ThreatLevel | 'neutral' | 'clean' | 'info' | 'warning' | 'critical' | 'high' | 'medium' | 'low' | 'success' | 'danger' | string;
  children: React.ReactNode;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'subtle' | 'outline' | 'pill';
  className?: string;
  icon?: React.ReactNode;
}

export const Badge: React.FC<BadgeProps> = ({
  level = 'neutral',
  children,
  size = 'md',
  variant = 'subtle',
  className = '',
  icon,
}) => {
  const getBadgeClass = () => {
    const normalized = String(level).toUpperCase();
    switch (normalized) {
      case 'CRITICAL':
      case 'DANGER':
        return 'pt-badge-critical';
      case 'HIGH':
      case 'WARNING':
        return 'pt-badge-high';
      case 'MEDIUM':
        return 'pt-badge-medium';
      case 'LOW':
      case 'INFO':
        return 'pt-badge-low';
      case 'NORMAL':
      case 'CLEAN':
      case 'SUCCESS':
        return 'pt-badge-clean';
      default:
        return 'pt-badge-neutral';
    }
  };

  const sizeClass = {
    sm: 'pt-badge-sm',
    md: 'pt-badge-md',
    lg: 'pt-badge-lg',
  }[size] || 'pt-badge-md';

  const variantClass = variant === 'outline' ? 'pt-badge-outline' : variant === 'pill' ? 'pt-badge-pill' : '';

  return (
    <span className={`pt-badge ${getBadgeClass()} ${sizeClass} ${variantClass} ${className}`}>
      {icon && (
        <span className="pt-badge-icon" aria-hidden="true">
          {icon}
        </span>
      )}
      <span className="pt-badge-text">{children}</span>
    </span>
  );
};
