// Open a separate top-level tab during the user's click. Never navigate the
// Streamlit document: Community Cloud may host it inside its own shell/frame.
const tabs = new Map();
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
        tab.location.replace(target.href);
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
        tab.document.title = 'VulnScan — Stripe';
        tab.document.body.textContent = data.language === 'en'
          ? 'Opening secure Stripe checkout…' : 'Abriendo el pago seguro de Stripe…';
        tabs.set(data.scope, tab);
      }
      tab.focus();
    };
    // Capture the actual native click, including keyboard activation. No parent
    // DOM access and no additional control or second confirmation link.
    document.addEventListener('click', click, true);
    return () => document.removeEventListener('click', click, true);
  } catch {
    fail();
  }
}
