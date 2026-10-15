// Open a separate top-level tab during the user's click. Never navigate the
// Streamlit document: Community Cloud may host it inside its own shell/frame.
const tabs = globalThis[Symbol.for('vulnscan.stripeTabs')] ||= new Map();
const attempts = globalThis[Symbol.for('vulnscan.stripeAttempts')] ||= new Map();
const checkoutTabs = globalThis[Symbol.for('vulnscan.checkoutTabs')] ||= new Map();
const returnWatchers = globalThis[Symbol.for('vulnscan.returnWatchers')] ||= new Map();
export function watchReturn(tab, checkout) {
  if (!/^cs_[A-Za-z0-9_]{1,252}$/.test(checkout || '') || returnWatchers.has(checkout)) return;
  const deadline = Date.now() + 3600000;
  const timer = setInterval(() => {
    if (tab.closed || Date.now() > deadline) {
      clearInterval(timer); returnWatchers.delete(checkout); checkoutTabs.delete(checkout); return;
    }
    try {
      // Cross-origin Stripe URLs are inaccessible and simply keep waiting.
      // Read only our own popup once it returns to the application's origin.
      const returned = new URL(tab.location.href);
      const outcome = returned.searchParams.get('pago');
      if (returned.origin !== location.origin || !['exitoso', 'cancelado'].includes(outcome)) return;
      if (outcome === 'exitoso' && returned.searchParams.get('session_id') !== checkout) return;
      clearInterval(timer); returnWatchers.delete(checkout); checkoutTabs.delete(checkout);
      window.top.focus();
      tab.close();
      // No authentication or billing mutation: the original tab already polls
      // the server, and remains the only authenticated Streamlit session.
    } catch { /* Stripe is cross-origin; never bypass the browser boundary. */ }
  }, 250);
  returnWatchers.set(checkout, timer);
}
export default function ({data, setStateValue, setTriggerValue}) {
  const selector = data.button_key ? `.st-key-${CSS.escape(data.button_key)}` : null;
  const progress = active => {
    const button = selector && document.querySelector?.(`${selector} button`);
    if (!button) return;
    button.querySelector('[data-billing-progress]')?.remove();
    button.removeAttribute('aria-busy');
    if (active) {
      const marker = document.createElement('span');
      marker.dataset.billingProgress = 'true'; marker.textContent = ' \u23f3';
      marker.setAttribute('aria-hidden', 'true');
      button.setAttribute('aria-busy', 'true'); button.append(marker);
    }
  };
  const fail = () => { progress(false); setTriggerValue('redirect_error', true); };
  try {
    if (data.failed) {
      attempts.delete(data.scope); progress(false); return;
    }
    const storageKey = `vulnscan-stripe-intent:${data.scope}`;
    let intent = sessionStorage.getItem(storageKey);
    if (!intent || data.rotate) {
      intent = data.rotate || crypto.randomUUID();
      sessionStorage.setItem(storageKey, intent);
    }
    // Readiness never reruns the panel or disables a purchase control.
    // Send the stable browser attempt only on an explicit native click.
    const seen = `vulnscan-stripe-navigation:${data.scope}`;
    let target;
    if (data.url && data.navigation) {
      target = new URL(data.url);
      if (target.protocol !== 'https:' || target.username || target.password ||
          target.port || !['checkout.stripe.com', 'billing.stripe.com'].includes(target.hostname)) {
        throw new Error('Unapproved destination');
      }
    }
    const openReady = () => {
      // Open only the validated hosted page. The authenticated source stays alive.
      const tab = window.open(target.href, '_blank');
      if (!tab) { fail(); return false; }
      tab.opener = null; tabs.set(data.scope, tab);
      if (/^cs_[A-Za-z0-9_]{1,252}$/.test(data.checkout || '')) checkoutTabs.set(data.checkout, tab);
      watchReturn(tab, data.checkout);
      tab.focus(); sessionStorage.setItem(seen, data.navigation);
      attempts.delete(data.scope); progress(false);
      setStateValue('navigation_done', data.navigation);
      return true;
    };
    const attempt = attempts.get(data.scope);
    if (target && sessionStorage.getItem(seen) !== data.navigation && attempt && !attempt.delivered) {
      attempt.delivered = true;
      openReady();
    }
    if (!selector) return;
    const click = event => {
      const button = event.target.closest?.('button');
      if (!button || button.disabled || !button.closest(selector)) return;
      const stop = () => { event.preventDefault(); event.stopImmediatePropagation(); };
      if (target && sessionStorage.getItem(seen) !== data.navigation) {
        // A blocked popup or interrupted response retries this SAME Checkout,
        // synchronously under the new user gesture. No second server operation.
        stop(); openReady(); return;
      }
      const previous = attempts.get(data.scope);
      if (previous && !previous.delivered && Date.now() - previous.started < 120000) {
        stop(); return;
      }
      stop();
      attempts.set(data.scope, {started: Date.now(), delivered: false});
      setTriggerValue('purchase', intent);
      queueMicrotask(() => progress(true));
    };
    document.addEventListener('click', click, true);
    return () => document.removeEventListener('click', click, true);
  } catch { fail(); }
}
