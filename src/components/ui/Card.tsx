import React from 'react';
import './Card.css';

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  hoverable?: boolean;
  interactive?: boolean;
  glow?: boolean;
  glass?: boolean;
  children: React.ReactNode;
  className?: string;
}

export const Card: React.FC<CardProps> = ({
  hoverable = false,
  interactive = false,
  glow = false,
  glass = false,
  children,
  className = '',
  ...rest
}) => {
  return (
    <div
      className={`vs-card ${hoverable ? 'vs-card--hoverable' : ''} ${interactive ? 'vs-card--interactive' : ''} ${glow ? 'vs-card--glow' : ''} ${glass ? 'vs-card--glass' : ''} ${className}`}
      {...rest}
    >
      {children}
    </div>
  );
};

export interface CardHeaderProps extends Omit<React.HTMLAttributes<HTMLDivElement>, 'title'> {
  title?: React.ReactNode;
  description?: React.ReactNode;
  action?: React.ReactNode;
  children?: React.ReactNode;
  className?: string;
}

export const CardHeader: React.FC<CardHeaderProps> = ({
  title,
  description,
  action,
  children,
  className = '',
  ...rest
}) => {
  return (
    <div className={`vs-card__header ${className}`} {...rest}>
      {children ? (
        children
      ) : (
        <>
          <div className="vs-card__header-content">
            {title && <h3 className="vs-card__title">{title}</h3>}
            {description && <p className="vs-card__description">{description}</p>}
          </div>
          {action && <div className="vs-card__header-action">{action}</div>}
        </>
      )}
    </div>
  );
};

export const CardTitle: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({
  children,
  className = '',
  ...rest
}) => {
  return (
    <h3 className={`vs-card__title ${className}`} {...rest}>
      {children}
    </h3>
  );
};

export const CardContent: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  children,
  className = '',
  ...rest
}) => {
  return (
    <div className={`vs-card__content ${className}`} {...rest}>
      {children}
    </div>
  );
};

export const CardFooter: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  children,
  className = '',
  ...rest
}) => {
  return (
    <div className={`vs-card__footer ${className}`} {...rest}>
      {children}
    </div>
  );
};

export default Card;
