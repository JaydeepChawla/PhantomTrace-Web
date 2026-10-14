import React from 'react';

export interface CardProps {
  title?: React.ReactNode;
  subtitle?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  cyberBorder?: boolean;
  headerBorder?: boolean;
  footer?: React.ReactNode;
  noPadding?: boolean;
  style?: React.CSSProperties;
}

export const Card: React.FC<CardProps> = ({
  title,
  subtitle,
  action,
  children,
  className = '',
  cyberBorder = false,
  headerBorder = true,
  footer,
  noPadding = false,
  style,
}) => {
  return (
    <div
      className={`pt-card ${cyberBorder ? 'pt-card-cyber' : ''} ${className}`}
      style={style}
    >
      {(title || action) && (
        <div className={`pt-card-header ${headerBorder ? 'has-border' : ''}`}>
          <div className="pt-card-header-main">
            {typeof title === 'string' ? (
              <h3 className="pt-card-title">{title}</h3>
            ) : (
              title
            )}
            {subtitle && <p className="pt-card-subtitle">{subtitle}</p>}
          </div>
          {action && <div className="pt-card-action">{action}</div>}
        </div>
      )}
      <div className={`pt-card-content ${noPadding ? 'pt-card-content-no-padding' : ''}`}>
        {children}
      </div>
      {footer && <div className="pt-card-footer">{footer}</div>}
    </div>
  );
};
