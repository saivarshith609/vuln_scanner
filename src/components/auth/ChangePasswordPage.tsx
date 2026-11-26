import { useState } from 'react';
import { KeyRound } from 'lucide-react';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';

export function ChangePasswordPage({
  onSubmit,
  error,
  isSubmitting,
}: {
  onSubmit: (currentPassword: string, newPassword: string, confirmPassword: string) => Promise<void>;
  error: string | null;
  isSubmitting: boolean;
}) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const localError = newPassword && confirmPassword && newPassword !== confirmPassword
    ? 'Password confirmation does not match.'
    : null;

  return (
    <main className="vs-auth-gate">
      <section className="vs-auth-card">
        <div className="vs-auth-card__icon"><KeyRound size={26} /></div>
        <h1>Change temporary password</h1>
        <p>An administrator reset this account. Choose a new private password before continuing.</p>
        <form onSubmit={(event) => { event.preventDefault(); if (!localError) void onSubmit(currentPassword, newPassword, confirmPassword); }}>
          <Input label="Temporary password" type="password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} />
          <Input label="New password" type="password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} helperText="Use 12-128 characters with upper/lowercase letters, a number, and a symbol." />
          <Input label="Confirm new password" type="password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} error={localError || undefined} />
          {(error || localError) && <div className="vs-auth-message vs-auth-message--error" role="alert">{error || localError}</div>}
          <Button type="submit" variant="primary" isLoading={isSubmitting} disabled={Boolean(localError) || !currentPassword || !newPassword || !confirmPassword}>Change password</Button>
        </form>
      </section>
    </main>
  );
}
