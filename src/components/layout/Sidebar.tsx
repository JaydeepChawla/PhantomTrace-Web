import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  AlertTriangle,
  Cpu,
  History,
  FileText,
  Settings,
  ExternalLink,
  Lock
} from 'lucide-react';
import { Logo } from '../common/Logo';

interface SidebarProps {
  threatAlertsCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({ threatAlertsCount = 6 }) => {
  const navItems = [
    { to: '/dashboard', label: 'Dashboard', icon: <LayoutDashboard size={18} /> },
    {
      to: '/alerts',
      label: 'Threat Alerts',
      icon: <AlertTriangle size={18} />,
      badge: threatAlertsCount > 0 ? threatAlertsCount : undefined
    },
    { to: '/processes', label: 'Processes', icon: <Cpu size={18} /> },
    { to: '/history', label: 'Scan History', icon: <History size={18} /> },
    { to: '/reports', label: 'Reports', icon: <FileText size={18} /> },
    { to: '/settings', label: 'Settings', icon: <Settings size={18} /> },
  ];

  return (
    <aside className="pt-sidebar">
      {/* Brand Header with Official Navbar Logo (Desktop) and App Icon (Mobile/Collapsed) */}
      <div style={{ padding: '1.25rem 1.25rem 1rem 1.25rem', borderBottom: '1px solid var(--pt-border-subtle)' }}>
        <NavLink to="/dashboard" style={{ textDecoration: 'none', display: 'flex', flexDirection: 'column' }}>
          <div className="pt-desktop-logo">
            <Logo variant="navbar" height={36} />
          </div>
          <div className="pt-mobile-icon" style={{ display: 'none' }}>
            <Logo variant="app" height={32} />
          </div>
        </NavLink>
        <div
          className="sidebar-tagline"
          style={{
            fontSize: '0.72rem',
            color: '#64748b',
            fontStyle: 'italic',
            marginTop: '0.65rem',
            paddingLeft: '0.2rem'
          }}
        >
          "Trace what others can't see."
        </div>
      </div>

      {/* Navigation Links */}
      <nav style={{ flex: 1, padding: '1rem 0.75rem', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
        <div style={{ fontSize: '0.68rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.08em', padding: '0.5rem 0.75rem', fontWeight: 600 }}>
          Investigation Console
        </div>

        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '0.65rem 0.85rem',
              borderRadius: '6px',
              fontSize: '0.86rem',
              fontWeight: isActive ? 600 : 500,
              color: isActive ? '#00e5ff' : '#94a3b8',
              background: isActive ? 'rgba(0, 229, 255, 0.08)' : 'transparent',
              border: isActive ? '1px solid rgba(0, 229, 255, 0.25)' : '1px solid transparent',
              transition: 'all 0.15s ease',
            })}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <span>{item.icon}</span>
              <span className="nav-text">{item.label}</span>
            </div>
            {item.badge !== undefined && (
              <span
                style={{
                  background: 'rgba(239, 68, 68, 0.2)',
                  color: '#f87171',
                  border: '1px solid rgba(239, 68, 68, 0.4)',
                  fontSize: '0.7rem',
                  fontWeight: 700,
                  padding: '0.1rem 0.45rem',
                  borderRadius: '10px',
                  fontFamily: 'var(--font-mono)'
                }}
              >
                {item.badge}
              </span>
            )}
          </NavLink>
        ))}

        <div style={{ marginTop: 'auto', paddingTop: '1rem', borderTop: '1px solid var(--pt-border-subtle)' }}>
          <NavLink
            to="/"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.75rem',
              padding: '0.65rem 0.85rem',
              borderRadius: '6px',
              fontSize: '0.82rem',
              color: '#64748b',
              transition: 'color 0.15s ease',
            }}
          >
            <ExternalLink size={16} />
            <span className="nav-text">Product Landing Page</span>
          </NavLink>
        </div>
      </nav>

      {/* Read-Only Engine Status Footer */}
      <div
        style={{
          padding: '1rem 1.15rem',
          background: 'rgba(5, 9, 17, 0.7)',
          borderTop: '1px solid var(--pt-border-subtle)',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.45rem'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.75rem', color: '#38bdf8', fontWeight: 600 }}>
          <Lock size={13} style={{ color: '#00e5ff' }} />
          <span className="sidebar-footer-text">Read-Only Engine: Active</span>
        </div>
        <div className="sidebar-footer-text" style={{ fontSize: '0.7rem', color: '#64748b' }}>
          Zero state mutation • Forensic integrity preserved
        </div>
      </div>
    </aside>
  );
};
