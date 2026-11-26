import React from 'react';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';
import { Card, CardHeader, CardContent } from '../ui/Card';
import { PieChart as PieIcon } from 'lucide-react';

export interface SeverityItem {
  name: string;
  value: number;
  color: string;
  [key: string]: unknown;
}

export interface SeverityDonutChartProps {
  data: SeverityItem[];
  total: number;
  className?: string;
}

export const SeverityDonutChart: React.FC<SeverityDonutChartProps> = ({
  data,
  total,
  className = '',
}) => {
  return (
    <Card className={className}>
      <CardHeader
        title={
          <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <PieIcon size={18} color="var(--color-brand)" /> Severity Breakdown
          </span>
        }
        description="Active findings partitioned by CVSS risk tier"
      />
      <CardContent style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <div style={{ position: 'relative', width: '100%', height: '200px' }}>
          {total === 0 ? (
            /* Clean baseline: no findings to display — render a labeled ring placeholder */
            <div
              style={{
                height: '100%',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '6px',
              }}
            >
              <span style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--color-low)', lineHeight: 1 }}>0</span>
              <span
                style={{
                  fontSize: '0.75rem',
                  color: 'var(--color-text-secondary)',
                  fontWeight: 600,
                  textAlign: 'center',
                }}
              >
                Findings — Clean Baseline
              </span>
            </div>
          ) : (
            <>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={data}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={85}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {data.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} stroke="#0d131f" strokeWidth={2} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#162034',
                      borderColor: '#1e293b',
                      borderRadius: '8px',
                      color: '#f8fafc',
                      fontSize: '12px',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
              {/* Centered Total Count */}
              <div
                style={{
                  position: 'absolute',
                  top: '50%',
                  left: '50%',
                  transform: 'translate(-50%, -50%)',
                  textAlign: 'center',
                  pointerEvents: 'none',
                }}
              >
                <span style={{ fontSize: '1.5rem', fontWeight: 800, color: '#f8fafc', lineHeight: 1 }}>
                  {total}
                </span>
                <span style={{ fontSize: '0.6875rem', color: '#64748b', display: 'block', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Findings
                </span>
              </div>
            </>
          )}
        </div>

        {/* Custom Legend */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(2, 1fr)',
            gap: '8px 16px',
            width: '100%',
            marginTop: '12px',
            borderTop: '1px solid var(--color-border)',
            paddingTop: '12px',
          }}
        >
          {data.map((item) => (
            <div key={item.name} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.75rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span
                  style={{
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    backgroundColor: item.color,
                  }}
                />
                <span style={{ color: 'var(--color-text-secondary)' }}>{item.name}</span>
              </div>
              <span style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>{item.value}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};

export default SeverityDonutChart;
