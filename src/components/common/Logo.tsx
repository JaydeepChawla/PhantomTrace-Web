import React from 'react';

export type LogoVariant = 'full' | 'navbar' | 'dashboard' | 'app' | 'windows' | 'horizontal' | 'icon';

interface LogoProps {
  variant?: LogoVariant;
  size?: 'sm' | 'md' | 'lg' | 'xl';
  height?: number | string;
  width?: number | string;
  className?: string;
  alt?: string;
  style?: React.CSSProperties;
}

export const Logo: React.FC<LogoProps> = ({
  variant = 'navbar',
  size = 'md',
  height,
  width,
  className = '',
  alt,
  style = {},
}) => {
  // Map backwards-compatible variants to the official logo files
  let resolvedVariant = variant;
  if (variant === 'horizontal') {
    resolvedVariant = size === 'xl' ? 'full' : 'navbar';
  } else if (variant === 'icon') {
    resolvedVariant = 'app';
  }

  // File paths from public/PhantomTrace_Logo_Assets/
  const logoSrcMap: Record<string, { src: string; defaultAlt: string; defaultHeights: Record<string, number> }> = {
    full: {
      src: '/PhantomTrace_Logo_Assets/phantomtrace-full-logo.png',
      defaultAlt: 'PhantomTrace - Memory & Fileless Threat Detection',
      defaultHeights: { sm: 40, md: 54, lg: 76, xl: 105 },
    },
    navbar: {
      src: '/PhantomTrace_Logo_Assets/phantomtrace-navbar-logo.png',
      defaultAlt: 'PhantomTrace',
      defaultHeights: { sm: 30, md: 40, lg: 48, xl: 64 },
    },
    dashboard: {
      src: '/PhantomTrace_Logo_Assets/phantomtrace-dashboard-icon.png',
      defaultAlt: 'PhantomTrace Security Dashboard',
      defaultHeights: { sm: 32, md: 44, lg: 60, xl: 80 },
    },
    app: {
      src: '/PhantomTrace_Logo_Assets/phantomtrace-app-icon.png',
      defaultAlt: 'PhantomTrace Application Icon',
      defaultHeights: { sm: 26, md: 36, lg: 48, xl: 64 },
    },
    windows: {
      src: '/PhantomTrace_Logo_Assets/phantomtrace-windows-icon.png',
      defaultAlt: 'PhantomTrace Windows Endpoint Scanner',
      defaultHeights: { sm: 28, md: 38, lg: 52, xl: 72 },
    },
  };

  const currentConfig = logoSrcMap[resolvedVariant] || logoSrcMap.navbar;
  const calculatedHeight = height ?? currentConfig.defaultHeights[size] ?? 40;

  return (
    <img
      src={currentConfig.src}
      alt={alt || currentConfig.defaultAlt}
      className={`pt-official-logo pt-logo-${resolvedVariant} ${className}`}
      style={{
        height: typeof calculatedHeight === 'number' ? `${calculatedHeight}px` : calculatedHeight,
        width: width ? (typeof width === 'number' ? `${width}px` : width) : 'auto',
        maxWidth: '100%',
        objectFit: 'contain',
        display: 'inline-block',
        verticalAlign: 'middle',
        filter: 'drop-shadow(0 2px 8px rgba(0, 229, 255, 0.12))',
        ...style,
      }}
    />
  );
};
