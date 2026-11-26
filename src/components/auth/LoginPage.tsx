import { useState } from 'react';
import { motion } from 'framer-motion';
import { Eye, EyeOff, LogIn, ShieldCheck, UserRound, LockKeyhole, ArrowRight } from 'lucide-react';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';

interface LoginPageProps {
  onLogin: (identifier: string, password: string) => Promise<void>;
  onAdminLogin: (identifier: string, password: string) => Promise<void>;
  onRegister: () => void;
  error: string | null;
  userError: string | null;
  adminError: string | null;
  successMessage: string | null;
  isUserSubmitting: boolean;
  isAdminSubmitting: boolean;
}

const motionTransition = { duration: 0.45, ease: [0.16, 1, 0.3, 1] as const };

export function LoginPage({
  onLogin,
  onAdminLogin,
  onRegister,
  error,
  userError,
  adminError,
  successMessage,
  isUserSubmitting,
  isAdminSubmitting,
}: LoginPageProps) {
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [adminIdentifier, setAdminIdentifier] = useState('');
  const [adminPassword, setAdminPassword] = useState('');
  const [showAdminPassword, setShowAdminPassword] = useState(false);

  return (
    <main className="vs-auth-gate">
      <div className="vs-auth-orb vs-auth-orb--cyan" aria-hidden="true" />
      <div className="vs-auth-orb vs-auth-orb--blue" aria-hidden="true" />
      <motion.section
        className="vs-auth-shell"
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        transition={motionTransition}
        aria-live="polite"
      >
        <div className="vs-auth-brand">
          <div className="vs-auth-card__icon"><ShieldCheck size={25} strokeWidth={1.8} /></div>
          <div>
            <span className="vs-auth-eyebrow">SECURITY OPERATIONS</span>
            <strong>VulnScanner</strong>
          </div>
        </div>
        <div className="vs-auth-heading">
          <h1>Sign in to VulnScanner</h1>
          <p>Sign in to continue monitoring your attack surface.</p>
        </div>

        {successMessage && <div className="vs-auth-message vs-auth-message--success" role="status">{successMessage}</div>}
        {error && <div className="vs-auth-message vs-auth-message--error" role="alert">{error}</div>}

        <div className="vs-auth-modes">
          <motion.div className="vs-auth-mode" whileHover={{ y: -2 }} transition={{ duration: 0.2 }}>
            <div className="vs-auth-mode__heading">
              <span className="vs-auth-mode__icon"><UserRound size={17} /></span>
              <div><h2>User Login</h2><p>Access your security workspace</p></div>
            </div>
            <form className="vs-auth-form" onSubmit={(event) => { event.preventDefault(); void onLogin(identifier, password); }}>
              <Input label="Username or email" autoComplete="username" value={identifier} onChange={(event) => setIdentifier(event.target.value)} leftIcon={<UserRound size={16} />} required />
              <Input label="Password" type={showPassword ? 'text' : 'password'} autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} required rightIcon={<button type="button" className="vs-auth-visibility" onClick={() => setShowPassword((value) => !value)} aria-label={showPassword ? 'Hide password' : 'Show password'}>{showPassword ? <EyeOff size={16} /> : <Eye size={16} />}</button>} />
              {userError && <div className="vs-auth-message vs-auth-message--error" role="alert">{userError}</div>}
              <Button type="submit" leftIcon={<LogIn size={16} />} isLoading={isUserSubmitting} disabled={!identifier || !password}>Sign In <ArrowRight size={15} /></Button>
            </form>
            <div className="vs-auth-switch">New to VulnScanner? <button type="button" onClick={onRegister}>Create an account</button></div>
          </motion.div>

          <div className="vs-auth-divider" aria-hidden="true"><span>or</span></div>

          <motion.div className="vs-auth-mode vs-auth-mode--admin" whileHover={{ y: -2 }} transition={{ duration: 0.2 }}>
            <div className="vs-auth-mode__heading">
              <span className="vs-auth-mode__icon vs-auth-mode__icon--admin"><ShieldCheck size={17} /></span>
              <div><h2>Administrator sign in</h2><p>For verified platform administrators</p></div>
            </div>
            <form className="vs-auth-form" onSubmit={(event) => { event.preventDefault(); void onAdminLogin(adminIdentifier, adminPassword); }}>
              <Input label="Administrator username or email" autoComplete="username" value={adminIdentifier} onChange={(event) => setAdminIdentifier(event.target.value)} leftIcon={<UserRound size={16} />} required />
              <Input label="Administrator password" type={showAdminPassword ? 'text' : 'password'} autoComplete="current-password" value={adminPassword} onChange={(event) => setAdminPassword(event.target.value)} required rightIcon={<button type="button" className="vs-auth-visibility" onClick={() => setShowAdminPassword((value) => !value)} aria-label={showAdminPassword ? 'Hide administrator password' : 'Show administrator password'}>{showAdminPassword ? <EyeOff size={16} /> : <Eye size={16} />}</button>} />
              {adminError && <div className="vs-auth-message vs-auth-message--error" role="alert">{adminError}</div>}
              <Button type="submit" variant="outline" leftIcon={<LockKeyhole size={16} />} isLoading={isAdminSubmitting} disabled={!adminIdentifier || !adminPassword}>Sign In as Administrator <ArrowRight size={15} /></Button>
            </form>
          </motion.div>
        </div>
        <small className="vs-auth-footnote">Protected by server-managed sessions, CSRF safeguards, and role-verified access controls.</small>
      </motion.section>
    </main>
  );
}
