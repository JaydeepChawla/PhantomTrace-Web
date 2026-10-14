import React from 'react';

export interface PanelProps {
  title?: React.ReactNode;
  subtitle?: string;
  badge?: React.ReactNode;
  action?: React.ReactNode;
  footer?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  cyberBorder?: boolean;
  noPadding?: boolean;
}

export const Panel: React.FC<PanelProps> = ({
  title,
  subtitle,
  badge,
  action,
  footer,
  children,
  className = '',
  cyberBorder = false,
  noPadding = false,
}) => {
  return (
    <section
      className={`pt-panel ${cyberBorder ? 'pt-panel-cyber' : ''} ${className}`}
      aria-labelledby={typeof title === 'string' ? `panel-title-${title.toLowerCase().replace(/\s+/g, '-')}` : undefined}
    >
      {(title || action || badge) && (
        <header className="pt-panel-header">
          <div className="pt-panel-header-left">
            {typeof title === 'string' ? (
              <h2
                id={`panel-title-${title.toLowerCase().replace(/\s+/g, '-')}`}
                className="pt-panel-title"
              >
                {title}
              </h2>
            ) : (
              title
            )}
            {badge && <span className="pt-panel-badge">{badge}</span>}
            {subtitle && <p className="pt-panel-subtitle">{subtitle}</p>}
          </div>
          {action && <div className="pt-panel-header-right">{action}</div>}
        </header>
      )}
      <div className={`pt-panel-body ${noPadding ? 'pt-panel-body-no-padding' : ''}`}>
        {children}
      </div>
      {footer && <footer className="pt-panel-footer">{footer}</footer>}
    </section>
  );
};
