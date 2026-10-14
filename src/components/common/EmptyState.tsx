import React from 'react';
import { ShieldAlert, ShieldCheck } from 'lucide-react';

export interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
  variant?: 'clean' | 'info' | 'alert';
  className?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon,
  title,
  description,
  action,
  variant = 'clean',
  className = '',
}) => {
  const defaultIcon =
    variant === 'alert' ? (
      <ShieldAlert size={36} className="text-warning" />
    ) : (
      <ShieldCheck size={36} className="text-cyan" />
    );

  return (
    <div className={`pt-empty-state pt-empty-state-${variant} ${className}`} role="status">
      <div className="pt-empty-icon-wrap" aria-hidden="true">
        {icon || defaultIcon}
      </div>
      <h3 className="pt-empty-title">{title}</h3>
      {description && <p className="pt-empty-description">{description}</p>}
      {action && <div className="pt-empty-action">{action}</div>}
    </div>
  );
};
