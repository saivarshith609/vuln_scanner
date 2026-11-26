import React from 'react';
import './RadarPing.css';

export interface RadarPingProps {
  active: boolean;
  size?: 'sm' | 'md';
  className?: string;
}

export const RadarPing: React.FC<RadarPingProps> = ({
  active,
  size = 'md',
  className = '',
}) => (
  <span
    className={`vs-radar-ping vs-radar-ping--${size} ${active ? 'vs-radar-ping--active' : ''} ${className}`.trim()}
    data-active={active ? 'true' : 'false'}
    aria-hidden="true"
  >
    <span className="vs-radar-ping__core" />
  </span>
);

export default RadarPing;
