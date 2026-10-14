import React from 'react';

export interface SeparatorProps {
  orientation?: 'horizontal' | 'vertical';
  className?: string;
}

export const Separator: React.FC<SeparatorProps> = ({
  orientation = 'horizontal',
  className = '',
}) => {
  return (
    <div
      role="separator"
      aria-orientation={orientation}
      className={`pt-separator pt-separator-${orientation} ${className}`}
    />
  );
};
