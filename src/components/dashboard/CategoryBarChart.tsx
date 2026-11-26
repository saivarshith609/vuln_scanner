import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import { Card, CardHeader, CardContent } from '../ui/Card';
import { ShieldAlert } from 'lucide-react';

export interface CategoryItem {
  category: string;
  count: number;
  color: string;
  [key: string]: unknown;
}

export interface CategoryBarChartProps {
  data: CategoryItem[];
  className?: string;
}

export const CategoryBarChart: React.FC<CategoryBarChartProps> = ({
  data,
  className = '',
}) => {
  return (
    <Card className={className}>
      <CardHeader
        title={
          <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ShieldAlert size={18} color="var(--color-brand)" /> Attack Surface Categories
          </span>
        }
        description="Distribution of vulnerabilities across OWASP Top 10 threat classifications"
      />
      <CardContent style={{ height: '260px' }}>
        {data.length === 0 ? (
          /* Honest empty state: backend does not aggregate OWASP/threat categories. */
          <div
            style={{
              height: '100%',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '10px',
              color: 'var(--color-text-muted)',
              fontSize: '0.875rem',
              textAlign: 'center',
              padding: '0 24px',
            }}
          >
            <ShieldAlert size={32} style={{ opacity: 0.3 }} />
            <span style={{ fontWeight: 600, color: 'var(--color-text-secondary)' }}>
              Category Telemetry Unavailable
            </span>
            <span style={{ fontSize: '0.75rem', maxWidth: '300px', lineHeight: 1.5 }}>
              The backend does not yet classify findings by OWASP category. Category distribution
              will appear here once the backend provides category data.
            </span>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={data}
              layout="vertical"
              margin={{ top: 5, right: 30, left: 40, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
              <XAxis
                type="number"
                stroke="#64748b"
                fontSize={11}
                tickLine={false}
                axisLine={false}
              />
              <YAxis
                type="category"
                dataKey="category"
                stroke="#94a3b8"
                fontSize={11}
                tickLine={false}
                axisLine={false}
                width={130}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#162034',
                  borderColor: '#1e293b',
                  borderRadius: '8px',
                  color: '#f8fafc',
                  fontSize: '12px',
                }}
              />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {data.map((entry, index) => (
                  <Cell key={`bar-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
};

export default CategoryBarChart;
