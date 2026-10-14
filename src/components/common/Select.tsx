import React from 'react';
import { ChevronDown } from 'lucide-react';

export interface SelectOption {
  value: string | number;
  label: string;
  disabled?: boolean;
}

export interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  helperText?: string;
  error?: string;
  options?: SelectOption[];
  icon?: React.ReactNode;
}

export const Select = React.forwardRef<HTMLSelectElement, SelectProps>(
  (
    {
      label,
      helperText,
      error,
      options,
      icon,
      id,
      className = '',
      children,
      disabled,
      required,
      ...rest
    },
    ref
  ) => {
    const selectId = id || (label ? `pt-select-${label.toLowerCase().replace(/\s+/g, '-')}` : undefined);

    return (
      <div className={`pt-form-group ${disabled ? 'is-disabled' : ''}`}>
        {label && (
          <label htmlFor={selectId} className="pt-form-label">
            {label}
            {required && <span className="pt-required-mark" aria-hidden="true"> *</span>}
          </label>
        )}
        <div className="pt-select-wrapper">
          {icon && (
            <span className="pt-select-icon pt-select-icon-left" aria-hidden="true">
              {icon}
            </span>
          )}
          <select
            ref={ref}
            id={selectId}
            disabled={disabled}
            required={required}
            aria-invalid={Boolean(error)}
            aria-describedby={
              error ? `${selectId}-error` : helperText ? `${selectId}-helper` : undefined
            }
            className={`pt-select ${icon ? 'has-left-icon' : ''} ${error ? 'is-invalid' : ''} ${className}`}
            {...rest}
          >
            {options
              ? options.map((opt) => (
                  <option key={opt.value} value={opt.value} disabled={opt.disabled}>
                    {opt.label}
                  </option>
                ))
              : children}
          </select>
          <span className="pt-select-arrow" aria-hidden="true">
            <ChevronDown size={14} />
          </span>
        </div>
        {error && (
          <p id={`${selectId}-error`} className="pt-form-error" role="alert">
            {error}
          </p>
        )}
        {!error && helperText && (
          <p id={`${selectId}-helper`} className="pt-form-helper">
            {helperText}
          </p>
        )}
      </div>
    );
  }
);

Select.displayName = 'Select';
