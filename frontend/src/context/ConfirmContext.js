import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';

const Ctx = createContext(null);

/* Asks before something that can't be undone, in the app's own dialog instead of the browser's:
   if (!(await confirm({ title, body, confirmLabel }))) return;
   Focus starts on Cancel, stays in the dialog, and Escape or a click outside cancels. */
export function ConfirmProvider({ children }) {
  const [ask, setAsk] = useState(null);
  const confirm = useCallback(options => new Promise(resolve => {
    setAsk({ confirmLabel: 'Confirm', cancelLabel: 'Cancel', danger: true, ...options, resolve });
  }), []);
  const close = answer => {
    ask?.resolve(answer);
    setAsk(null);
  };
  return (
    <Ctx.Provider value={confirm}>
      {children}
      {ask && <ConfirmDialog {...ask} onClose={close} />}
    </Ctx.Provider>
  );
}

function ConfirmDialog({ title, body, confirmLabel, cancelLabel, danger, onClose }) {
  const dialogRef = useRef(null);
  const cancelRef = useRef(null);
  useEffect(() => {
    const returnTo = document.activeElement;
    cancelRef.current?.focus();
    return () => returnTo?.focus?.();
  }, []);

  const onKeyDown = e => {
    if (e.key === 'Escape') {
      e.preventDefault();
      onClose(false);
    } else if (e.key === 'Tab') {           // keep focus on the dialog's buttons
      const buttons = [...dialogRef.current.querySelectorAll('button')];
      const at = buttons.indexOf(document.activeElement);
      e.preventDefault();
      buttons[(at + (e.shiftKey ? -1 : 1) + buttons.length) % buttons.length].focus();
    }
  };

  return (
    <div className="confirm-backdrop" onMouseDown={e => { if (e.target === e.currentTarget) onClose(false); }}>
      <div ref={dialogRef} className="confirm-dialog" role="alertdialog" aria-modal="true"
        aria-labelledby="confirm-title" aria-describedby={body ? 'confirm-body' : undefined} onKeyDown={onKeyDown}>
        <h2 id="confirm-title" className="confirm-title">{title}</h2>
        {body && <p id="confirm-body" className="confirm-body">{body}</p>}
        <div className="confirm-actions">
          <button ref={cancelRef} type="button" className="btn-outline" onClick={() => onClose(false)}>{cancelLabel}</button>
          <button type="button" className={danger ? 'btn-confirm-danger' : 'btn-primary'} onClick={() => onClose(true)}>
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

export const useConfirm = () => useContext(Ctx);
