import { useState, type ChangeEvent, type FormEvent } from 'react';
import { Eye, EyeOff, ShieldCheck, UserPlus } from 'lucide-react';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import type { RegisterAccountInput } from '../../services/api';

interface RegisterPageProps {
  onSubmit: (payload: RegisterAccountInput) => Promise<void>;
  onLogin: () => void;
  error: string | null;
  isSubmitting: boolean;
}

export function RegisterPage({ onSubmit, onLogin, error, isSubmitting }: RegisterPageProps) {
  const [form, setForm] = useState<RegisterAccountInput>({ full_name: '', username: '', email: '', password: '', confirm_password: '' });
  const [showPassword, setShowPassword] = useState(false);
  const [validation, setValidation] = useState<string | null>(null);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email.trim())) return setValidation('Enter a valid email address.');
    if (form.password.length < 12 || !/[A-Z]/.test(form.password) || !/[a-z]/.test(form.password) || !/\d/.test(form.password) || !/[^A-Za-z0-9]/.test(form.password)) return setValidation('Use at least 12 characters with uppercase, lowercase, number, and special character.');
    if (form.password !== form.confirm_password) return setValidation('Password confirmation does not match.');
    setValidation(null);
    void onSubmit(form);
  };
  const update = (field: keyof RegisterAccountInput) => (event: ChangeEvent<HTMLInputElement>) => {
    setForm((current) => ({ ...current, [field]: event.target.value }));
    setValidation(null);
  };

  return (
    <main className="vs-auth-gate">
      <section className="vs-auth-card vs-auth-card--wide" aria-live="polite">
        <div className="vs-auth-card__icon"><ShieldCheck size={26} /></div>
        <h1>Create your VulnScanner account</h1>
        <p>Accounts are stored persistently and receive standard-user access. Administrator privileges cannot be requested here.</p>
        {(validation || error) && <div className="vs-auth-message vs-auth-message--error" role="alert">{validation || error}</div>}
        <form className="vs-auth-form" onSubmit={submit}>
          <div className="vs-auth-grid"><Input label="Full name" value={form.full_name} onChange={update('full_name')} autoComplete="name" required /><Input label="Username" value={form.username} onChange={update('username')} autoComplete="username" helperText="Lowercase letters, numbers, dots, dashes, or underscores." required /></div>
          <Input label="Email address" type="email" value={form.email} onChange={update('email')} autoComplete="email" required />
          <div className="vs-auth-grid">
            <Input label="Password" type={showPassword ? 'text' : 'password'} value={form.password} onChange={update('password')} autoComplete="new-password" required rightIcon={<button type="button" className="vs-auth-visibility" onClick={() => setShowPassword((value) => !value)} aria-label={showPassword ? 'Hide passwords' : 'Show passwords'}>{showPassword ? <EyeOff size={16} /> : <Eye size={16} />}</button>} />
            <Input label="Confirm password" type={showPassword ? 'text' : 'password'} value={form.confirm_password} onChange={update('confirm_password')} autoComplete="new-password" required />
          </div>
          <Button type="submit" leftIcon={<UserPlus size={16} />} isLoading={isSubmitting} disabled={isSubmitting}>Create Account</Button>
        </form>
        <div className="vs-auth-switch">Already registered? <button type="button" onClick={onLogin}>Sign in</button></div>
      </section>
    </main>
  );
}
