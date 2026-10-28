import { useState, useEffect, useRef } from 'react';
import { scansAPI } from '../services/api';

/* ── The attack library's counts, from GET /categories ─────────
   { attacks, categories, quick, leakCheck }, or null until they load (or if they can't). Copy quotes
   these instead of numbers typed into it, which go stale when the library changes, and is worded
   without a number while they're null. */
export function useLibrary() {
  const [counts, setCounts] = useState(null);
  useEffect(() => {
    let live = true;
    Promise.resolve().then(() => scansAPI.categories()).then(({ data }) => {
      const cats = data.categories || [];
      if (live && cats.length) setCounts({
        attacks   : data.total_attacks ?? cats.reduce((n, c) => n + c.attacks, 0),
        categories: data.total_categories ?? cats.length,
        quick     : data.total_quick_attacks ?? null,
        leakCheck : data.leak_check_attacks ?? null,
      });
    }).catch(() => {});
    return () => { live = false; };
  }, []);
  return counts;
}

/* ── Animated counter (easeOut cubic) ──────────────────────── */
export function useCountUp(target, duration = 1100, delay = 0) {
  const [count, setCount] = useState(0);
  const durationRef = useRef(duration);
  const delayRef    = useRef(delay);

  useEffect(() => {
    if (!target) return;
    let raf;
    let start = null;
    const d   = durationRef.current;
    const dl  = delayRef.current;
    const easeOut = t => 1 - Math.pow(1 - t, 3);
    const tick = ts => {
      if (!start) start = ts + dl;
      if (ts < start) { raf = requestAnimationFrame(tick); return; }
      const p = Math.min((ts - start) / d, 1);
      setCount(Math.round(easeOut(p) * target));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target]);

  return count;
}

/* ── Polling that pauses when it isn't needed ─────────────────
   Calls fn every `ms` while `enabled` is true and the tab is visible,
   and once more when the tab becomes visible again. */
export function usePolling(fn, ms, enabled) {
  const fnRef = useRef(fn);
  fnRef.current = fn;

  useEffect(() => {
    if (!enabled) return undefined;
    let timer = null;
    const tick = () => { if (document.visibilityState === 'visible') fnRef.current(); };
    const startTimer = () => { if (!timer) timer = setInterval(tick, ms); };
    const stopTimer = () => { clearInterval(timer); timer = null; };
    const onVisibility = () => {
      if (document.visibilityState === 'visible') { fnRef.current(); startTimer(); }
      else stopTimer();
    };
    startTimer();
    document.addEventListener('visibilitychange', onVisibility);
    return () => { stopTimer(); document.removeEventListener('visibilitychange', onVisibility); };
  }, [ms, enabled]);
}

/* ── Intersection observer — triggers once ─────────────────── */
export function useInView(threshold = 0.12) {
  const ref       = useRef(null);
  const threshRef = useRef(threshold);
  const [inView, setInView] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (typeof IntersectionObserver === 'undefined') { setInView(true); return; }  // old browsers, tests
    const obs = new IntersectionObserver(
      ([e]) => { if (e.isIntersecting) { setInView(true); obs.disconnect(); } },
      { threshold: threshRef.current }
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, []);

  return [ref, inView];
}
