import React, { useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  AlertTriangle,
  Cpu,
  History,
  FileText,
  Settings,
  ExternalLink,
  Lock,
  ShieldCheck,
  X,
} from 'lucide-react';

export interface SidebarProps {
  threatAlertsCount?: number;
  isOpenMobile?: boolean;
  onCloseMobile?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  threatAlertsCount = 6,
  isOpenMobile = false,
  onCloseMobile,
}) => {
  const navItems = [
    { to: '/dashboard', label: 'Dashboard', icon: <LayoutDashboard size={18} /> },
    {
      to: '/alerts',
      label: 'Threat Alerts',
      icon: <AlertTriangle size={18} />,
      badge: threatAlertsCount > 0 ? threatAlertsCount : undefined,
    },
    { to: '/processes', label: 'Processes', icon: <Cpu size={18} /> },
    { to: '/history', label: 'Scan History', icon: <History size={18} /> },
    { to: '/reports', label: 'Reports', icon: <FileText size={18} /> },
    { to: '/setup', label: 'Setup & Install', icon: <ShieldCheck size={18} /> },
    { to: '/settings', label: 'Settings', icon: <Settings size={18} /> },
  ];

  // Close mobile drawer on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpenMobile && onCloseMobile) {
        onCloseMobile();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpenMobile, onCloseMobile]);

  const handleNavClick = () => {
    if (isOpenMobile && onCloseMobile) {
      onCloseMobile();
    }
  };

  return (
    <aside
      className={`pt-sidebar ${isOpenMobile ? 'pt-sidebar-mobile-open' : ''}`}
      aria-label="Primary Navigation"
    >
      {/* Mobile Drawer Close Button Header */}
      {isOpenMobile && onCloseMobile && (
        <div className="pt-sidebar-mobile-header">
          <button
            type="button"
            className="pt-sidebar-close-btn"
            onClick={onCloseMobile}
            aria-label="Close navigation menu"
          >
            <X size={18} />
          </button>
        </div>
      )}

      {/* Navigation Links */}
      <nav className="pt-sidebar-nav" aria-label="Investigation Console Links">
        <div className="pt-nav-section-title">
          Investigation Console
        </div>

        <div className="pt-nav-list" role="list">
          {navItems.map((item) => (
            <div key={item.to} role="listitem">
              <NavLink
                to={item.to}
                onClick={handleNavClick}
                title={item.label}
                aria-label={
                  item.badge !== undefined
                    ? `${item.label} (${item.badge} active alerts)`
                    : item.label
                }
                className={({ isActive }) =>
                  `pt-nav-item ${isActive ? 'pt-nav-item-active' : ''}`
                }
              >
                <div className="pt-nav-item-content">
                  <span className="pt-nav-icon" aria-hidden="true">
                    {item.icon}
                  </span>
                  <span className="nav-text pt-nav-text">{item.label}</span>
                </div>

                {item.badge !== undefined && (
                  <span
                    className="pt-nav-badge"
                    aria-label={`${item.badge} alerts`}
                  >
                    <span className="pt-nav-badge-pill">{item.badge}</span>
                    <span className="pt-nav-badge-dot" aria-hidden="true" />
                  </span>
                )}
              </NavLink>
            </div>
          ))}
        </div>

        {/* Secondary Navigation Section */}
        <div className="pt-nav-secondary">
          <NavLink
            to="/"
            onClick={handleNavClick}
            className="pt-nav-secondary-item"
            title="PhantomTrace Product Landing Page"
          >
            <ExternalLink size={16} aria-hidden="true" />
            <span className="nav-text pt-nav-text">Product Landing Page</span>
          </NavLink>
        </div>
      </nav>

      {/* Read-Only Engine Status Footer */}
      <div className="pt-sidebar-footer" title="Read-Only Security Engine Active">
        <div className="pt-sidebar-footer-heading">
          <span className="pt-sidebar-footer-icon" aria-hidden="true">
            <Lock size={13} />
          </span>
          <span className="sidebar-footer-text pt-sidebar-footer-title">
            Read-Only Engine: Active
          </span>
        </div>
        <div className="sidebar-footer-text pt-sidebar-footer-subtext">
          Zero state mutation &bull; Forensic integrity preserved
        </div>
      </div>
    </aside>
  );
};
