import React from 'react';
import { Search, X } from 'lucide-react';
import './Input.css';

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  helperText?: string;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
  wrapperClassName?: string;
}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  (
    {
      label,
      error,
      helperText,
      leftIcon,
      rightIcon,
      className = '',
      wrapperClassName = '',
      disabled,
      id,
      ...rest
    },
    ref
  ) => {
    const generatedId = React.useId();
    const inputId = id || `input-${generatedId}`;
    const helperId = `${inputId}-helper`;
    const errorId = `${inputId}-error`;
    const describedBy = [error ? errorId : undefined, !error && helperText ? helperId : undefined]
      .filter(Boolean)
      .join(' ') || undefined;

    return (
      <div className={`vs-input-group ${wrapperClassName}`}>
        {label && <label className="vs-input-label" htmlFor={inputId}>{label}</label>}
        <div
          className={`vs-input-wrapper ${error ? 'vs-input-wrapper--error' : ''} ${
            disabled ? 'vs-input-wrapper--disabled' : ''
          }`}
        >
          {leftIcon && <span className="vs-input__icon">{leftIcon}</span>}
          <input
            ref={ref}
            id={inputId}
            disabled={disabled}
            aria-invalid={error ? true : undefined}
            aria-describedby={describedBy}
            className={`vs-input ${leftIcon ? 'vs-input--has-left-icon' : ''} ${
              rightIcon ? 'vs-input--has-right-icon' : ''
            } ${className}`}
            {...rest}
          />
          {rightIcon && <span className="vs-input__icon">{rightIcon}</span>}
        </div>
        {error && <span id={errorId} className="vs-input-error" role="alert">{error}</span>}
        {!error && helperText && (
          <span id={helperId} className="vs-input-helper">{helperText}</span>
        )}
      </div>
    );
  }
);

Input.displayName = 'Input';

export interface SearchInputProps
  extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'onChange'> {
  value: string;
  onChange: (val: string) => void;
  onClear?: () => void;
  placeholder?: string;
  className?: string;
}

export const SearchInput: React.FC<SearchInputProps> = ({
  value,
  onChange,
  onClear,
  placeholder = 'Search vulnerabilities, targets, CVEs...',
  className = '',
  ...rest
}) => {
  return (
    <Input
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      leftIcon={<Search size={16} />}
      rightIcon={
        value ? (
          <button
            type="button"
            onClick={() => {
              onChange('');
              onClear?.();
            }}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--color-text-muted)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
            }}
            aria-label="Clear search"
          >
            <X size={14} />
          </button>
        ) : undefined
      }
      className={className}
      aria-label={rest['aria-label'] || 'Search'}
      {...rest}
    />
  );
};

export default Input;
