import type { ReactNode } from 'react';
import { ShieldX } from 'lucide-react';
import { useAuth } from './authContext';

export function RoleGuard({
  requiredRole,
  children,
}: {
  requiredRole: 'admin';
  children: ReactNode;
}) {
  const { user } = useAuth();

  if (user?.role !== requiredRole) {
    return (
      <section className="vs-role-denied" role="alert" aria-live="polite">
        <ShieldX size={34} aria-hidden="true" />
        <h2>Administrator access required</h2>
        <p>Your authenticated account does not have permission to open this area.</p>
      </section>
    );
  }

  return children;
}
