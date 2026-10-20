import React, { createContext, useContext, useState, useCallback } from 'react';

const Ctx = createContext(null);

const IcoCheck = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="20 6 9 17 4 12"/>
  </svg>
);
const IcoX = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
  </svg>
);
const IcoInfo = () => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>
  </svg>
);

const STYLES = {
  success: { bg:'rgba(34,197,94,0.12)',  border:'rgba(34,197,94,0.3)',  color:'#16a34a',       Icon: IcoCheck },
  error  : { bg:'rgba(240,68,56,0.12)',  border:'rgba(240,68,56,0.3)',  color:'#dc2626',       Icon: IcoX     },
  info   : { bg:'rgba(37,99,235,0.12)', border:'rgba(37,99,235,0.3)', color:'var(--blue)',   Icon: IcoInfo  },
  warning: { bg:'rgba(251,146,60,0.12)', border:'rgba(251,146,60,0.3)', color:'var(--orange)', Icon: IcoInfo  },
};

function ToastItem({ id, msg, type, onClose }) {
  const s = STYLES[type] || STYLES.info;
  return (
    <div className="toast-item" style={{ '--tb': s.bg, '--tbo': s.border, '--tc': s.color }}>
      <div className="toast-icon-wrap" style={{ color: s.color }}><s.Icon /></div>
      <div className="toast-msg">{msg}</div>
      <button className="toast-close-btn" onClick={() => onClose(id)} aria-label="Dismiss notification">
        <IcoX />
      </button>
    </div>
  );
}

export function ToastProvider({ children }) {
  const [list, setList] = useState([]);

  const show = useCallback((msg, type = 'info', ms = 3800) => {
    const id = Date.now() + Math.random();
    setList(p => [...p, { id, msg, type }]);
    setTimeout(() => setList(p => p.filter(t => t.id !== id)), ms);
  }, []);

  const remove = useCallback(id => setList(p => p.filter(t => t.id !== id)), []);

  return (
    <Ctx.Provider value={show}>
      {children}
      {/* a labelled live region: a landmark, and screen readers announce each toast */}
      <section className="toast-root" aria-label="Notifications" aria-live="polite">
        {list.map(t => <ToastItem key={t.id} {...t} onClose={remove} />)}
      </section>
    </Ctx.Provider>
  );
}

export const useToast = () => useContext(Ctx);
