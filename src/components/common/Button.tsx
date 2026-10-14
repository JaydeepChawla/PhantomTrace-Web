import React from 'react';
import { Loader2 } from 'lucide-react';

export type ButtonVariant = 'primary' | 'secondary' | 'cyber' | 'outline' | 'danger' | 'ghost';
export type ButtonSize = 'sm' | 'md' | 'lg';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  icon?: React.ReactNode;
  iconPosition?: 'left' | 'right';
  loading?: boolean;
  fullWidth?: boolean;
  children?: React.ReactNode;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      variant = 'secondary',
      size = 'md',
      icon,
      iconPosition = 'left',
      loading = false,
      fullWidth = false,
      disabled = false,
      className = '',
      children,
      type = 'button',
      ...rest
    },
    ref
  ) => {
    const variantClass = {
      primary: 'pt-btn-primary',
      secondary: 'pt-btn-secondary',
      cyber: 'pt-btn-cyber',
      outline: 'pt-btn-outline',
      danger: 'pt-btn-danger',
      ghost: 'pt-btn-ghost',
    }[variant];

    const sizeClass = {
      sm: 'pt-btn-sm',
      md: 'pt-btn-md',
      lg: 'pt-btn-lg',
    }[size];

    const isIconOnly = Boolean(icon && !children);

    return (
      <button
        ref={ref}
        type={type}
        disabled={disabled || loading}
        className={`pt-btn ${variantClass} ${sizeClass} ${isIconOnly ? 'pt-btn-icon' : ''} ${
          fullWidth ? 'w-full' : ''
        } ${className}`}
        aria-busy={loading}
        {...rest}
      >
        {loading ? (
          <>
            <Loader2 size={size === 'sm' ? 14 : size === 'lg' ? 18 : 16} className="pt-spin" />
            {children && <span>{children}</span>}
          </>
        ) : (
          <>
            {icon && iconPosition === 'left' && (
              <span className="pt-btn-icon-wrapper" aria-hidden="true">
                {icon}
              </span>
            )}
            {children && <span>{children}</span>}
            {icon && iconPosition === 'right' && (
              <span className="pt-btn-icon-wrapper" aria-hidden="true">
                {icon}
              </span>
            )}
          </>
        )}
      </button>
    );
  }
);

Button.displayName = 'Button';
