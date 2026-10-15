import React, { createContext, useContext, useState, useEffect } from 'react';
import { authAPI, clearAuth } from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user,    setUser]    = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (token) {
      authAPI.me()
        .then(r => setUser(r.data))
        .catch(() => clearAuth())
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  const login = async (username, password) => {
    const { data } = await authAPI.login(username, password);
    localStorage.setItem('access_token',  data.access_token);
    if (data.refresh_token)
      localStorage.setItem('refresh_token', data.refresh_token);
    setUser(data.user || { username });
    return data;
  };

  const register = async (username, email, password) => {
    const { data } = await authAPI.register(username, email, password);
    localStorage.setItem('access_token',  data.access_token);
    if (data.refresh_token)
      localStorage.setItem('refresh_token', data.refresh_token);
    setUser(data.user);
    return data;
  };

  const logout = () => {
    authAPI.logout();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
