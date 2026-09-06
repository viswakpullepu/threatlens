import React, { createContext, useContext, useState, useEffect } from 'react';
import { getOrCreateSessionId } from '../components/LiveEmailInterceptor';

export interface UserProfile {
  id?: string;
  email: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  verified_email?: boolean;
}

export interface AuthContextType {
  user: UserProfile | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  provider: string | null;
  sessionId: string;
  loginWithGoogle: () => void;
  logout: () => Promise<void>;
  refreshAuth: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const USER_STORAGE_KEY = 'threatlens_auth_user_profile';

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserProfile | null>(() => {
    try {
      const cached = localStorage.getItem(USER_STORAGE_KEY);
      return cached ? JSON.parse(cached) : null;
    } catch (_) {
      return null;
    }
  });
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => {
    try {
      return !!localStorage.getItem(USER_STORAGE_KEY);
    } catch (_) {
      return false;
    }
  });
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [provider, setProvider] = useState<string | null>('gmail');
  const sessionId = getOrCreateSessionId();

  const refreshAuth = async () => {
    try {
      const sid = getOrCreateSessionId();
      const res = await fetch(`/api/auth/status?session_id=${encodeURIComponent(sid)}`, {
        headers: { 'x-session-id': sid }
      });
      const data = await res.json();
      
      if (data.connected && data.user) {
        setUser(data.user);
        setIsAuthenticated(true);
        setProvider(data.provider || 'gmail');
        try {
          localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(data.user));
        } catch (_) {}
      } else {
        if (!data.connected) {
          setUser(null);
          setIsAuthenticated(false);
          try {
            localStorage.removeItem(USER_STORAGE_KEY);
          } catch (_) {}
        }
      }
    } catch (err) {
      console.warn('[AuthContext] Could not refresh auth status:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    refreshAuth();

    const params = new URLSearchParams(window.location.search);
    if (params.get('connected') === 'gmail' || params.get('session_id')) {
      refreshAuth();
    }
  }, []);

  const loginWithGoogle = () => {
    const sid = getOrCreateSessionId();
    window.location.href = `/api/auth/google/login?session_id=${encodeURIComponent(sid)}`;
  };

  const logout = async () => {
    try {
      const sid = getOrCreateSessionId();
      await fetch(`/api/auth/disconnect?session_id=${encodeURIComponent(sid)}`, {
        method: 'POST',
        headers: { 'x-session-id': sid }
      });
    } catch (_) {}
    
    setUser(null);
    setIsAuthenticated(false);
    try {
      localStorage.removeItem(USER_STORAGE_KEY);
      localStorage.removeItem('threatlens_device_session_id');
      document.cookie = 'tl_session=; path=/; max-age=0; SameSite=Lax';
    } catch (_) {}
    
    window.location.href = window.location.pathname;
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated,
        isLoading,
        provider,
        sessionId,
        loginWithGoogle,
        logout,
        refreshAuth
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
