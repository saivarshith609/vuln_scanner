import { createContext, useContext } from 'react';
import type { AuthUser } from '../../services/api';

export interface AuthContextValue {
  user: AuthUser | null;
  logout: () => Promise<void>;
}

export const AuthContext = createContext<AuthContextValue>({ user: null, logout: async () => undefined });
export const useAuth = () => useContext(AuthContext);
