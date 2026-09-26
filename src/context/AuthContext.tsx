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

const getScopedStorageKey = (sid: string) => `threatlens_auth_user_${sid}`;

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const sessionId = typeof window !== 'undefined' ? getOrCreateSessionId() : 'ssr_client_session';

  const [user, setUser] = useState<UserProfile | null>(() => {
    try {
      if (typeof window !== 'undefined') {
        const sid = getOrCreateSessionId();
        const params = new URLSearchParams(window.location.search);
        const urlSid = params.get('session_id') || params.get('sessionId');
        if (params.get('connected') === 'gmail' && params.get('user') && (!urlSid || urlSid === sid)) {
          const email = params.get('user')!;
          const initUser: UserProfile = {
            email,
            name: email.split('@')[0],
            verified_email: true
          };
          localStorage.setItem(getScopedStorageKey(sid), JSON.stringify(initUser));
          return initUser;
        }
        const cached = localStorage.getItem(getScopedStorageKey(sid));
        return cached ? JSON.parse(cached) : null;
      }
      return null;
    } catch (_) {
      return null;
    }
  });

  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => {
    try {
      if (typeof window !== 'undefined') {
        const sid = getOrCreateSessionId();
        const params = new URLSearchParams(window.location.search);
        const urlSid = params.get('session_id') || params.get('sessionId');
        if (params.get('connected') === 'gmail' && (!urlSid || urlSid === sid)) return true;
        return !!localStorage.getItem(getScopedStorageKey(sid));
      }
      return false;
    } catch (_) {
      return false;
    }
  });

  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [provider, setProvider] = useState<string | null>('gmail');

  const refreshAuth = async () => {
    try {
      const sid = getOrCreateSessionId();
      const res = await fetch(`/api/auth/status?session_id=${encodeURIComponent(sid)}`, {
        headers: { 'x-session-id': sid }
      });
      if (!res.ok) return;
      const data = await res.json();
      
      if (data.connected && data.user) {
        setUser(data.user);
        setIsAuthenticated(true);
        setProvider(data.provider || 'gmail');
        try {
          localStorage.setItem(getScopedStorageKey(sid), JSON.stringify(data.user));
          // Clean legacy unscoped key
          localStorage.removeItem('threatlens_auth_user_profile');
        } catch (_) {}
      } else {
        // Explicitly disconnected: clear all local credentials for this session
        setUser(null);
        setIsAuthenticated(false);
        try {
          localStorage.removeItem(getScopedStorageKey(sid));
          localStorage.removeItem('threatlens_auth_user_profile');
        } catch (_) {}
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
    const sid = getOrCreateSessionId();
    try {
      await fetch(`/api/auth/disconnect?session_id=${encodeURIComponent(sid)}`, {
        method: 'POST',
        headers: { 'x-session-id': sid }
      });
    } catch (_) {}
    
    setUser(null);
    setIsAuthenticated(false);
    try {
      localStorage.removeItem(getScopedStorageKey(sid));
      localStorage.removeItem('threatlens_auth_user_profile');
      localStorage.removeItem('threatlens_device_session_id');
      document.cookie = 'tl_session=; path=/; max-age=0; SameSite=Lax';
      document.cookie = 'tl_auth_token=; path=/; max-age=0; SameSite=Lax';
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
