import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { authAPI, clearAuth, saveTokens } from '../services/api';

const AuthContext = createContext(null);

const wait = ms => new Promise(r => setTimeout(r, ms));

export function AuthProvider({ children }) {
  const [user,    setUser]    = useState(null);
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);

  // Loads the profile. Only a real 401 signs the user out; network errors and
  // 5xx (e.g. the backend waking up) are retried, then shown as "offline".
  const loadUser = useCallback(async () => {
    if (!localStorage.getItem('access_token')) { setUser(null); setLoading(false); return; }
    setLoading(true);
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const { data } = await authAPI.me();
        setUser(data); setOffline(false); setLoading(false);
        return data;
      } catch (err) {
        if (err.response?.status === 401) { clearAuth(); setUser(null); setLoading(false); return null; }
        await wait(1500 * (attempt + 1));
      }
    }
    setOffline(true); setLoading(false);
    return null;
  }, []);

  useEffect(() => { loadUser(); }, [loadUser]);

  const login = async (username, password) => {
    const { data } = await authAPI.login(username, password);
    saveTokens(data);
    setUser(data.user || { username });
    return data;
  };

  const register = async (username, email, password) => {
    const { data } = await authAPI.register(username, email, password);
    saveTokens(data);
    setUser(data.user);
    return data;
  };

  const logout = async () => {
    setUser(null);
    await authAPI.logout();
  };

  return (
    <AuthContext.Provider value={{ user, loading, offline, login, register, logout,
                                   refreshUser: loadUser, setUser, saveTokens }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
