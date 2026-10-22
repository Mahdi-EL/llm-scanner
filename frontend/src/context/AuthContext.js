import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { authAPI, clearAuth, saveTokens, getWorkspace, setWorkspace } from '../services/api';

// In a team workspace, plan, quota and workspace settings come from it; identity stays the person's.
const WORKSPACE_FIELDS = ['plan', 'scans_count', 'scans_this_month', 'scan_limit', 'full_scans', 'webhook_url',
                          'has_webhook_secret', 'has_billing', 'report_brand'];
function withWorkspace(me) {
  if (!me?.workspace) return me;
  return { ...me, ...Object.fromEntries(WORKSPACE_FIELDS.map(k => [k, me.workspace[k]])) };
}

const AuthContext = createContext(null);

// Links in emails and webhooks name the workspace their scan belongs to (?workspace=<account id>): remember it
// so the scan opens there, also after signing in, and drop it from the address. /auth/me forgets it if it isn't
// theirs. Runs on the provider's first render, before the router inside it reads the address.
function takeWorkspaceFromLink() {
  const params = new URLSearchParams(window.location.search);
  const linked = params.get('workspace');
  if (!linked) return;
  setWorkspace(linked);
  params.delete('workspace');
  const rest = params.toString();
  window.history.replaceState(window.history.state, '', window.location.pathname + (rest ? `?${rest}` : '') + window.location.hash);
}

const wait = ms => new Promise(r => setTimeout(r, ms));

export function AuthProvider({ children }) {
  useState(takeWorkspaceFromLink);            // once, before the first render of the routes
  const [user,    setUser]    = useState(null);
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);
  const shown = useRef(false);        // a profile is on screen, so a reload happens behind it

  // Loads the profile. Only a real 401 signs the user out; network errors and
  // 5xx (e.g. the backend waking up) are retried, then shown as "offline".
  // Only the first load shows the loading screen: a refresh after saving a setting or confirming the
  // email keeps the page mounted, or the page would lose what it shows (a webhook secret shown once,
  // say) and run its effects again.
  const loadUser = useCallback(async () => {
    if (!localStorage.getItem('access_token')) { shown.current = false; setUser(null); setLoading(false); return; }
    const background = shown.current;
    if (!background) setLoading(true);
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const { data } = await authAPI.me();
        if (getWorkspace() && !data.workspace) setWorkspace(null);   // left it, or was removed
        const merged = withWorkspace(data);
        shown.current = true;
        setUser(merged); setOffline(false); setLoading(false);
        return merged;
      } catch (err) {
        if (err.response?.status === 401) {
          shown.current = false; clearAuth(); setUser(null); setLoading(false);
          return null;
        }
        await wait(1500 * (attempt + 1));
      }
    }
    if (!background) setOffline(true);    // a failed refresh keeps what's on screen
    setLoading(false);
    return null;
  }, []);

  useEffect(() => { loadUser(); }, [loadUser]);

  const login = async (username, password) => {
    const { data } = await authAPI.login(username, password);
    saveTokens(data);
    // a workspace picked up from a link: load it, so its plan and the person's role there apply
    if (getWorkspace()) await loadUser();
    else { shown.current = true; setUser(data.user || { username }); }
    return data;
  };

  const register = async (username, email, password) => {
    const { data } = await authAPI.register(username, email, password);
    saveTokens(data);
    shown.current = true;
    setUser(data.user);
    return data;
  };

  // A full reload, so nothing loaded for the previous workspace stays on screen
  const switchWorkspace = id => {
    setWorkspace(!id || id === user?.id ? null : id);
    window.location.assign('/');
  };

  const logout = async () => {
    shown.current = false;
    setUser(null);
    await authAPI.logout();
  };

  // The person's role in the selected workspace (their own: owner). Viewers read; members and up change things.
  const role = user?.workspace?.role || 'owner';
  return (
    <AuthContext.Provider value={{ user, loading, offline, login, register, logout,
                                   refreshUser: loadUser, setUser, saveTokens, switchWorkspace,
                                   role, canEdit: role !== 'viewer', canAdmin: role === 'owner' || role === 'admin' }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
