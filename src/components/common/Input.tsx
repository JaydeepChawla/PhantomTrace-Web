import React from 'react';

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  helperText?: string;
  error?: string;
  icon?: React.ReactNode;
  rightElement?: React.ReactNode;
}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  (
    {
      label,
      helperText,
      error,
      icon,
      rightElement,
      id,
      className = '',
      disabled,
      required,
      ...rest
    },
    ref
  ) => {
    const inputId = id || (label ? `pt-input-${label.toLowerCase().replace(/\s+/g, '-')}` : undefined);

    return (
      <div className={`pt-form-group ${disabled ? 'is-disabled' : ''}`}>
        {label && (
          <label htmlFor={inputId} className="pt-form-label">
            {label}
            {required && <span className="pt-required-mark" aria-hidden="true"> *</span>}
          </label>
        )}
        <div className="pt-input-wrapper">
          {icon && (
            <span className="pt-input-icon pt-input-icon-left" aria-hidden="true">
              {icon}
            </span>
          )}
          <input
            ref={ref}
            id={inputId}
            disabled={disabled}
            required={required}
            aria-invalid={Boolean(error)}
            aria-describedby={
              error ? `${inputId}-error` : helperText ? `${inputId}-helper` : undefined
            }
            className={`pt-input ${icon ? 'has-left-icon' : ''} ${rightElement ? 'has-right-element' : ''} ${
              error ? 'is-invalid' : ''
            } ${className}`}
            {...rest}
          />
          {rightElement && (
            <div className="pt-input-right-element">
              {rightElement}
            </div>
          )}
        </div>
        {error && (
          <p id={`${inputId}-error`} className="pt-form-error" role="alert">
            {error}
          </p>
        )}
        {!error && helperText && (
          <p id={`${inputId}-helper`} className="pt-form-helper">
            {helperText}
          </p>
        )}
      </div>
    );
  }
);

Input.displayName = 'Input';
