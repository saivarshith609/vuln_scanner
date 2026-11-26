import { useEffect, useMemo, useState, type ChangeEvent, type FocusEvent, type FormEvent } from 'react';
import { CheckCircle2, Circle, Eye, EyeOff, ShieldCheck, UserPlus } from 'lucide-react';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import type { RegisterAccountInput } from '../../services/api';
import {
  getPasswordChecklist,
  getUsernameChecklist,
  validatePasswordPolicy,
  validateUsernamePolicy,
  type ChecklistRequirement,
} from '../../utils/authValidation';

interface RegisterPageProps {
  onSubmit: (payload: RegisterAccountInput) => Promise<void>;
  onLogin: () => void;
  error: string | null;
  isSubmitting: boolean;
}

type ChecklistField = 'username' | 'password';

function ValidationChecklist({
  id,
  title,
  items,
}: {
  id: string;
  title: string;
  items: ChecklistRequirement[];
}) {
  return (
    <div id={id} className="vs-auth-checklist" role="region" aria-label={title}>
      <ul className="vs-auth-checklist__list">
        {items.map((item) => (
          <li
            key={item.id}
            className={`vs-auth-checklist__item ${item.met ? 'vs-auth-checklist__item--met' : ''}`}
          >
            <span className="vs-auth-checklist__icon" aria-hidden="true">
              {item.met ? <CheckCircle2 size={14} /> : <Circle size={14} />}
            </span>
            <span>{item.label}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function RegisterPage({ onSubmit, onLogin, error, isSubmitting }: RegisterPageProps) {
  const [form, setForm] = useState<RegisterAccountInput>({ full_name: '', username: '', email: '', password: '', confirm_password: '' });
  const [showPassword, setShowPassword] = useState(false);
  const [validation, setValidation] = useState<string | null>(null);
  const [activeChecklist, setActiveChecklist] = useState<ChecklistField | null>(null);

  useEffect(() => () => {
    setActiveChecklist(null);
  }, []);

  const usernameChecklist = useMemo(() => getUsernameChecklist(form.username), [form.username]);
  const passwordChecklist = useMemo(() => getPasswordChecklist(form.password), [form.password]);

  const isFormValid = useMemo(() => {
    const cleanName = form.full_name.trim().replace(/\s+/g, ' ');
    return (
      cleanName.length >= 2
      && validateUsernamePolicy(form.username) === null
      && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email.trim())
      && validatePasswordPolicy(form.password) === null
      && form.password === form.confirm_password
    );
  }, [form]);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const cleanName = form.full_name.trim().replace(/\s+/g, ' ');
    if (cleanName.length < 2) return setValidation('Full name is required.');
    const usernameError = validateUsernamePolicy(form.username);
    if (usernameError) return setValidation(usernameError);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email.trim())) return setValidation('Enter a valid email address.');
    const passwordError = validatePasswordPolicy(form.password);
    if (passwordError) return setValidation(passwordError);
    if (form.password !== form.confirm_password) return setValidation('Password confirmation does not match.');
    setValidation(null);
    void onSubmit(form);
  };

  const update = (field: keyof RegisterAccountInput) => (event: ChangeEvent<HTMLInputElement>) => {
    setForm((current) => ({ ...current, [field]: event.target.value }));
    setValidation(null);
  };

  const handleFieldBlur = (field: ChecklistField) => (event: FocusEvent<HTMLDivElement>) => {
    if (event.currentTarget.contains(event.relatedTarget as Node | null)) {
      return;
    }
    setActiveChecklist((current) => (current === field ? null : current));
  };

  return (
    <main className="vs-auth-gate">
      <section className="vs-auth-card vs-auth-card--wide" aria-live="polite">
        <div className="vs-auth-card__icon"><ShieldCheck size={26} /></div>
        <h1>Create your VulnScanner account</h1>
        <p>Accounts are stored persistently and receive standard-user access. Administrator privileges cannot be requested here.</p>
        {(validation || error) && <div className="vs-auth-message vs-auth-message--error" role="alert">{validation || error}</div>}
        <form className="vs-auth-form" onSubmit={submit}>
          <div className="vs-auth-grid">
            <Input
              label="Full name"
              value={form.full_name}
              onChange={update('full_name')}
              onFocus={() => setActiveChecklist(null)}
              autoComplete="name"
              required
            />
            <div
              className="vs-auth-field-wrap"
              onFocus={() => setActiveChecklist('username')}
              onBlur={handleFieldBlur('username')}
            >
              <Input
                label="Username"
                value={form.username}
                onChange={update('username')}
                autoComplete="username"
                aria-describedby={activeChecklist === 'username' ? 'username-requirements-checklist' : undefined}
                required
              />
              {activeChecklist === 'username' && (
                <ValidationChecklist
                  id="username-requirements-checklist"
                  title="Username requirements"
                  items={usernameChecklist}
                />
              )}
            </div>
          </div>
          <Input
            label="Email address"
            type="email"
            value={form.email}
            onChange={update('email')}
            onFocus={() => setActiveChecklist(null)}
            autoComplete="email"
            required
          />
          <div className="vs-auth-grid">
            <div
              className="vs-auth-field-wrap"
              onFocus={() => setActiveChecklist('password')}
              onBlur={handleFieldBlur('password')}
            >
              <Input
                label="Password"
                type={showPassword ? 'text' : 'password'}
                value={form.password}
                onChange={update('password')}
                autoComplete="new-password"
                aria-describedby={activeChecklist === 'password' ? 'password-requirements-checklist' : undefined}
                required
                rightIcon={(
                  <button
                    type="button"
                    className="vs-auth-visibility"
                    onClick={() => setShowPassword((value) => !value)}
                    aria-label={showPassword ? 'Hide passwords' : 'Show passwords'}
                  >
                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                )}
              />
              {activeChecklist === 'password' && (
                <ValidationChecklist
                  id="password-requirements-checklist"
                  title="Password requirements"
                  items={passwordChecklist}
                />
              )}
            </div>
            <Input
              label="Confirm password"
              type={showPassword ? 'text' : 'password'}
              value={form.confirm_password}
              onChange={update('confirm_password')}
              onFocus={() => setActiveChecklist(null)}
              autoComplete="new-password"
              required
            />
          </div>
          <Button type="submit" leftIcon={<UserPlus size={16} />} isLoading={isSubmitting} disabled={!isFormValid || isSubmitting}>
            Create Account
          </Button>
        </form>
        <div className="vs-auth-switch">
          Already registered?{' '}
          <button
            type="button"
            onClick={() => {
              setActiveChecklist(null);
              onLogin();
            }}
          >
            Sign in
          </button>
        </div>
      </section>
    </main>
  );
}
