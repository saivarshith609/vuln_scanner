import React, { useState, useCallback, useEffect, useRef } from 'react';
import { X } from 'lucide-react';
import './Toast.css';

interface ToastMessage {
  id: string;
  type: 'success' | 'error' | 'info' | 'warning';
  message: string;
}

interface ToastContextType {
  showToast: (type: ToastMessage['type'], message: string) => void;
}

const ToastContext = React.createContext<ToastContextType>({ showToast: () => {} });

export const useToast = () => React.useContext(ToastContext);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const timers = useRef(new Map<string, ReturnType<typeof setTimeout>>());

  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  const dismissToast = useCallback((id: string) => {
    const timer = timers.current.get(id);
    if (timer) clearTimeout(timer);
    timers.current.delete(id);
    setToasts((previous) => previous.filter((toast) => toast.id !== id));
  }, []);

  const showToast = useCallback((type: ToastMessage['type'], message: string) => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    setToasts((prev) => [...prev, { id, type, message }]);
    const timer = setTimeout(() => dismissToast(id), 3500);
    timers.current.set(id, timer);
  }, [dismissToast]);

  return (
    <ToastContext.Provider value={{ showToast }}>
      {children}
      <div className="vs-toast-region" aria-label="Notifications">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`vs-toast vs-toast--${t.type}`}
            role={t.type === 'error' ? 'alert' : 'status'}
            aria-live={t.type === 'error' ? 'assertive' : 'polite'}
            aria-atomic="true"
          >
            <span className="vs-toast__message">{t.message}</span>
            <button
              type="button"
              className="vs-toast__dismiss"
              onClick={() => dismissToast(t.id)}
              aria-label="Dismiss notification"
            >
              <X size={16} aria-hidden="true" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
};
