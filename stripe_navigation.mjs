// Component v2 runs in the app page: no parent-document access or popup required.
export default function ({data, setStateValue, setTriggerValue}) {
  try {
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
        window.location.assign(target.href);
        sessionStorage.setItem(seen, data.navigation);
      }
    }
  } catch {
    setTriggerValue('redirect_error', true);
  }
}
