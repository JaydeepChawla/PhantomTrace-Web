import React from 'react';

export interface TabItem {
  id: string;
  label: string;
  icon?: React.ReactNode;
  badge?: React.ReactNode;
  disabled?: boolean;
}

export interface TabsProps {
  items: TabItem[];
  activeId: string;
  onChange: (id: string) => void;
  className?: string;
  size?: 'sm' | 'md';
}

export const Tabs: React.FC<TabsProps> = ({
  items,
  activeId,
  onChange,
  className = '',
  size = 'md',
}) => {
  return (
    <div className={`pt-tabs-container ${size === 'sm' ? 'pt-tabs-sm' : ''} ${className}`} role="tablist">
      {items.map((tab) => {
        const isActive = tab.id === activeId;
        return (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={isActive}
            aria-controls={`panel-${tab.id}`}
            id={`tab-${tab.id}`}
            disabled={tab.disabled}
            onClick={() => onChange(tab.id)}
            className={`pt-tab-btn ${isActive ? 'is-active' : ''}`}
          >
            {tab.icon && (
              <span className="pt-tab-icon" aria-hidden="true">
                {tab.icon}
              </span>
            )}
            <span className="pt-tab-label">{tab.label}</span>
            {tab.badge && <span className="pt-tab-badge">{tab.badge}</span>}
          </button>
        );
      })}
    </div>
  );
};
