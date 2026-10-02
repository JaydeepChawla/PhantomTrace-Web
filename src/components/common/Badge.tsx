import React from 'react';
import type { ThreatLevel } from '../../types';

interface BadgeProps {
  level?: ThreatLevel | 'neutral' | string;
  children: React.ReactNode;
  size?: 'sm' | 'md';
  className?: string;
  icon?: React.ReactNode;
}

export const Badge: React.FC<BadgeProps> = ({
  level = 'neutral',
  children,
  size = 'md',
  className = '',
  icon,
}) => {
  const getBadgeClass = () => {
    switch (level) {
      case 'CRITICAL':
      case 'Critical':
        return 'pt-badge-critical';
      case 'HIGH':
      case 'High':
        return 'pt-badge-high';
      case 'MEDIUM':
      case 'Medium':
        return 'pt-badge-medium';
      case 'LOW':
      case 'Low':
        return 'pt-badge-low';
      case 'NORMAL':
      case 'Clean':
        return 'pt-badge-clean';
      default:
        return 'pt-badge-neutral';
    }
  };

  const sizeStyle = size === 'sm' 
    ? { fontSize: '0.68rem', padding: '0.15rem 0.45rem' } 
    : {};

  return (
    <span className={`pt-badge ${getBadgeClass()} ${className}`} style={sizeStyle}>
      {icon && <span style={{ display: 'inline-flex', alignItems: 'center' }}>{icon}</span>}
      {children}
    </span>
  );
};
