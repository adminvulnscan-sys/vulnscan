// Open a separate top-level tab during the user's click. Never navigate the
// Streamlit document: Community Cloud may host it inside its own shell/frame.
const tabs = new Map();
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
  const fail = () => setTriggerValue('redirect_error', true);
  try {
    if (data.failed) {
      const tab = tabs.get(data.scope);
      if (tab && !tab.closed) tab.close();
      tabs.delete(data.scope);
      return;
    }
    const storageKey = `vulnscan-stripe-intent:${data.scope}`;
    let intent = sessionStorage.getItem(storageKey);
    if (!intent || data.rotate) {
      intent = data.rotate || crypto.randomUUID();
      sessionStorage.setItem(storageKey, intent);
    }
    if (data.known_intent !== intent) {
      setStateValue('intent', intent);
    }
    if (data.url && data.navigation) {
      const target = new URL(data.url);
      if (target.protocol !== 'https:' || target.username || target.password ||
          target.port || !['checkout.stripe.com', 'billing.stripe.com'].includes(target.hostname)) {
        throw new Error('Unapproved destination');
      }
      const seen = `vulnscan-stripe-navigation:${data.scope}`;
      if (sessionStorage.getItem(seen) !== data.navigation) {
        const tab = tabs.get(data.scope);
        if (!tab || tab.closed) throw new Error('Payment tab unavailable');
        if (/^cs_[A-Za-z0-9_]{1,252}$/.test(data.checkout || '')) checkoutTabs.set(data.checkout, tab);
        tab.location.replace(target.href);
        watchReturn(tab, data.checkout);
        tab.focus();
        sessionStorage.setItem(seen, data.navigation);
      }
    }

    if (!data.button_key) return;
    const selector = `.st-key-${CSS.escape(data.button_key)}`;
    const click = event => {
      const button = event.target.closest?.('button');
      if (!button || button.disabled || !button.closest(selector)) return;
      let tab = tabs.get(data.scope);
      // The native button still runs all server checks. No Stripe request here.
      if (!tab || tab.closed) {
        tab = window.open('about:blank', '_blank');
        if (!tab) {
          event.preventDefault();
          event.stopImmediatePropagation();
          fail();
          return;
        }
        tab.opener = null;
        tabs.set(data.scope, tab);
      }
      // Reserve the script-closable tab during the click, but keep the existing
      // UI visible while the server creates Checkout. No intermediate document.
      try { window.top.focus(); } catch { /* Browser controls focus. */ }
      queueMicrotask(() => {
        if (button.isConnected && !button.querySelector('[data-billing-progress]')) {
          const progress = document.createElement('span');
          progress.dataset.billingProgress = 'true';
          progress.textContent = ' ⏳';
          progress.setAttribute('aria-hidden', 'true');
          button.setAttribute('aria-busy', 'true');
          button.append(progress);
        }
      });
    };
    // Capture the actual native click, including keyboard activation. No parent
    // DOM access and no additional control or second confirmation link.
    document.addEventListener('click', click, true);
    return () => document.removeEventListener('click', click, true);
  } catch {
    fail();
  }
}
