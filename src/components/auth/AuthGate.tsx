import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Loader } from 'lucide-react';
import {
  API_BASE_URL,
  changePassword,
  endAuthSession,
  getApiHealth,
  getAuthSession,
  loginAdministrator,
  loginUser,
  logoutUser,
  registerUser,
  type AuthSession,
  type AuthUser,
  type RegisterAccountInput,
} from '../../services/api';
import { LoginPage } from './LoginPage';
import { RegisterPage } from './RegisterPage';
import { ChangePasswordPage } from './ChangePasswordPage';
import { AuthContext } from './authContext';
import './AuthGate.css';

type AuthState = 'checking' | 'required' | 'password-change' | 'authenticated';
const INACTIVITY_TIMEOUT_MS = 300_000;
const LOGOUT_SYNC_KEY = 'vulnscanner:logout';

function errorStatus(error: unknown): number | null {
  return typeof error === 'object' && error !== null && 'status' in error && typeof error.status === 'number'
    ? error.status
    : null;
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

function verifiedSessionUser(session: AuthSession): AuthUser {
  const user = session.user;
  if (
    session.authenticated !== true
    || !user
    || user.is_active !== true
    || (user.role !== 'user' && user.role !== 'admin')
  ) {
    throw new Error('The authentication service returned an invalid session identity.');
  }
  return user;
}

export const AuthGate: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const initialPath = window.location.pathname;
  const requestedPath = useRef(!['/login', '/register'].includes(initialPath) ? initialPath : '/');
  const [path, setPath] = useState(initialPath);
  const [state, setState] = useState<AuthState>('checking');
  const [user, setUser] = useState<AuthUser | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [userLoginError, setUserLoginError] = useState<string | null>(null);
  const [adminLoginError, setAdminLoginError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isUserSubmitting, setIsUserSubmitting] = useState(false);
  const [isAdminSubmitting, setIsAdminSubmitting] = useState(false);
  const logoutInProgress = useRef(false);

  const navigate = useCallback((nextPath: string, replace = false) => {
    window.history[replace ? 'replaceState' : 'pushState']({}, '', nextPath);
    setPath(nextPath);
  }, []);

  useEffect(() => {
    let active = true;
    const onPopState = () => setPath(window.location.pathname);
    const requireAuthentication = () => {
      void endAuthSession().catch(() => undefined);
      setUser(null);
      setError('Your session is missing, expired, or revoked. Sign in again.');
      setUserLoginError(null);
      setAdminLoginError(null);
      setState('required');
      if (!['/login', '/register'].includes(window.location.pathname)) navigate('/login', true);
    };
    window.addEventListener('popstate', onPopState);
    window.addEventListener('vulnscanner:authentication-required', requireAuthentication);
    const restoreSession = async () => {
      try {
        await getApiHealth();
      } catch (healthError) {
        if (!active) return;
        const status = errorStatus(healthError);
        setError(status === 0
          ? `Unable to reach the VulnScanner API health endpoint at ${API_BASE_URL}/health. Start the FastAPI backend and verify the configured URL and CORS origin.`
          : `VulnScanner API health check failed: ${errorMessage(healthError, 'The service did not report a healthy status.')}`);
        setState('required');
        if (!['/login', '/register'].includes(window.location.pathname)) navigate('/login', true);
        return;
      }

      try {
        const session: AuthSession = await getAuthSession();
        if (!active) return;
        const restoredUser = verifiedSessionUser(session);
        setUser(restoredUser);
        setUserLoginError(null);
        setAdminLoginError(null);
        setState(restoredUser.credential_change_required ? 'password-change' : 'authenticated');
        if (restoredUser.credential_change_required) navigate('/change-password', true);
        if (['/login', '/register'].includes(window.location.pathname)) navigate('/', true);
      } catch (sessionError) {
        if (!active) return;
        setUser(null);
        if (errorStatus(sessionError) !== 401) {
          void endAuthSession().catch(() => undefined);
          setError(`The API health check passed, but session validation failed: ${errorMessage(sessionError, 'Unable to validate the current session.')}`);
        }
        setState('required');
        if (!['/login', '/register'].includes(window.location.pathname)) navigate('/login', true);
      }
    };
    void restoreSession();
    return () => {
      active = false;
      window.removeEventListener('popstate', onPopState);
      window.removeEventListener('vulnscanner:authentication-required', requireAuthentication);
    };
  }, [navigate]);

  const acceptSession = (session: AuthSession, successPath?: string) => {
    const authenticatedUser = verifiedSessionUser(session);
    setUser(authenticatedUser);
    setError(null);
    setSuccessMessage(null);
    setUserLoginError(null);
    setAdminLoginError(null);
    if (authenticatedUser.credential_change_required) {
      setState('password-change');
      navigate('/change-password', true);
    } else {
      setState('authenticated');
      const destination = successPath
        || (requestedPath.current.startsWith('/') && !requestedPath.current.startsWith('//') ? requestedPath.current : '/');
      navigate(destination, true);
    }
  };

  const clearLocalSession = useCallback((message?: string, broadcast = false) => {
    setUser(null);
    setState('required');
    setError(null);
    setUserLoginError(null);
    setAdminLoginError(null);
    if (message) setSuccessMessage(message);
    requestedPath.current = '/';
    navigate('/login', true);
    if (broadcast && typeof window !== 'undefined') {
      try { window.localStorage.setItem(LOGOUT_SYNC_KEY, String(Date.now())); } catch { /* storage may be unavailable */ }
    }
  }, [navigate]);

  const secureLogout = useCallback(async (reason?: string): Promise<boolean> => {
    if (logoutInProgress.current) return false;
    logoutInProgress.current = true;
    try {
      await logoutUser();
      clearLocalSession(reason, true);
      return true;
    } catch (logoutError) {
      // A server-side idle expiry is already a definitive logout.  The
      // unauthenticated DELETE endpoint clears the browser cookies and is
      // idempotent, so it is safe to use only for that 401 race.
      if (errorStatus(logoutError) === 401) {
        try {
          await endAuthSession();
          clearLocalSession(reason, true);
          return true;
        } catch {
          setError('The session could not be ended safely. Check your connection and try again.');
          return false;
        }
      }
      setError('The session could not be ended safely. Check your connection and try again.');
      return false;
    } finally {
      logoutInProgress.current = false;
    }
  }, [clearLocalSession]);

  useEffect(() => {
    if (state !== 'authenticated' || !user) return undefined;

    let timer: number | undefined;
    let lastActivity = 0;
    const resetTimer = () => {
      const now = Date.now();
      // Mousemove can fire hundreds of times per second.  A one-second
      // debounce keeps the timer accurate without causing render churn.
      if (now - lastActivity < 1000) return;
      lastActivity = now;
      if (timer !== undefined) window.clearTimeout(timer);
      timer = window.setTimeout(() => {
        void secureLogout('You were logged out due to 5 minutes of inactivity.');
      }, INACTIVITY_TIMEOUT_MS);
    };
    const activityEvents = ['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart', 'pointerdown'] as const;
    activityEvents.forEach((eventName) => window.addEventListener(eventName, resetTimer, { passive: true }));
    resetTimer();

    return () => {
      if (timer !== undefined) window.clearTimeout(timer);
      activityEvents.forEach((eventName) => window.removeEventListener(eventName, resetTimer));
    };
  }, [secureLogout, state, user]);

  useEffect(() => {
    if (typeof window === 'undefined') return undefined;
    const onStorage = (event: StorageEvent) => {
      if (event.key === LOGOUT_SYNC_KEY && event.newValue) clearLocalSession();
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, [clearLocalSession]);
  const performLogin = async (
    loginKind: 'user' | 'admin',
    action: () => Promise<AuthSession>,
    requestPath: string,
    credentialName: string,
    successPath?: string,
  ) => {
    if (isSubmitting || isUserSubmitting || isAdminSubmitting) return;
    const setSubmitting = loginKind === 'admin' ? setIsAdminSubmitting : setIsUserSubmitting;
    const setLoginError = loginKind === 'admin' ? setAdminLoginError : setUserLoginError;
    setSubmitting(true);
    setLoginError(null);
    setError(null);
    try { acceptSession(await action(), successPath); }
    catch (requestError) {
      setLoginError(errorStatus(requestError) === 0
        ? `The ${credentialName} request could not reach ${API_BASE_URL}${requestPath}. Your credentials were not validated.`
        : errorMessage(requestError, 'Authentication failed.'));
    } finally { setSubmitting(false); }
  };
  const register = async (payload: RegisterAccountInput) => {
    if (isSubmitting) return;
    setIsSubmitting(true);
    setError(null);
    try {
      await registerUser(payload);
      setSuccessMessage('Account created successfully. Sign in with your new credentials.');
      navigate('/login', true);
    } catch (requestError) {
      setError(errorStatus(requestError) === 0
        ? `The registration request could not reach ${API_BASE_URL}/auth/register. Your account was not created.`
        : errorMessage(requestError, 'Registration failed.'));
    } finally { setIsSubmitting(false); }
  };
  const logout = useCallback(async () => {
    await secureLogout();
  }, [secureLogout]);

  const completeForcedPasswordChange = async (currentPassword: string, newPassword: string, confirmPassword: string) => {
    setIsSubmitting(true);
    setError(null);
    try {
      await changePassword(currentPassword, newPassword, confirmPassword);
      setUser(null);
      setState('required');
      setSuccessMessage('Password changed. Sign in again with your new password.');
      navigate('/login', true);
    } catch (requestError) {
      setError(errorMessage(requestError, 'Password change failed.'));
    } finally {
      setIsSubmitting(false);
    }
  };

  if (state === 'checking') {
    return <main className="vs-auth-gate"><section className="vs-auth-card"><div className="vs-auth-card__icon"><Loader size={26} className="vs-auth-card__spinner" /></div><h1>Checking secure session</h1><p>Verifying the server-managed session…</p></section></main>;
  }
  if (state === 'required') {
    if (path === '/register') return <RegisterPage onSubmit={register} onLogin={() => navigate('/login')} error={error} isSubmitting={isSubmitting} />;
    return <LoginPage
      onLogin={(identifier, password) => performLogin('user', () => loginUser(identifier, password), '/auth/login', 'login')}
      onAdminLogin={(identifier, password) => performLogin('admin', () => loginAdministrator(identifier, password), '/auth/admin/login', 'administrator login', '/admin')}
      onRegister={() => { setError(null); setUserLoginError(null); setAdminLoginError(null); navigate('/register'); }}
      error={error}
      userError={userLoginError}
      adminError={adminLoginError}
      successMessage={successMessage}
      isUserSubmitting={isUserSubmitting}
      isAdminSubmitting={isAdminSubmitting}
    />;
  }
  if (state === 'password-change') {
    return <ChangePasswordPage onSubmit={completeForcedPasswordChange} error={error} isSubmitting={isSubmitting} />;
  }

  return <AuthContext.Provider value={{ user, logout }}>{children}</AuthContext.Provider>;
};
