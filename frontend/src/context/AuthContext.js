import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { authAPI, clearAuth, saveTokens, WORKSPACE_KEY } from '../services/api';

// In a team workspace, plan, quota and workspace settings come from it; identity stays the person's.
const WORKSPACE_FIELDS = ['plan', 'scans_count', 'scans_this_month', 'scan_limit', 'full_scans', 'webhook_url',
                          'has_webhook_secret', 'has_billing', 'report_brand'];
function withWorkspace(me) {
  if (!me?.workspace) return me;
  return { ...me, ...Object.fromEntries(WORKSPACE_FIELDS.map(k => [k, me.workspace[k]])) };
}

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
        const chosen = localStorage.getItem(WORKSPACE_KEY);
        if (chosen && !data.workspace) localStorage.removeItem(WORKSPACE_KEY);   // left it, or was removed
        const merged = withWorkspace(data);
        setUser(merged); setOffline(false); setLoading(false);
        return merged;
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

  // A full reload, so nothing loaded for the previous workspace stays on screen
  const switchWorkspace = id => {
    if (!id || id === user?.id) localStorage.removeItem(WORKSPACE_KEY);
    else localStorage.setItem(WORKSPACE_KEY, id);
    window.location.assign('/');
  };

  const logout = async () => {
    setUser(null);
    await authAPI.logout();
  };

  return (
    <AuthContext.Provider value={{ user, loading, offline, login, register, logout,
                                   refreshUser: loadUser, setUser, saveTokens, switchWorkspace,
                                   role: user?.workspace?.role || 'owner' }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
