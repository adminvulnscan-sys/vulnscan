// A return notification only. No auth tokens, email or session credentials.
export default function ({data, setTriggerValue}) {
  if (!globalThis.BroadcastChannel || !/^cs_[A-Za-z0-9_]{1,252}$/.test(data.checkout || '')) {
    if (data.role === 'return') setTriggerValue('unavailable', true);
    return;
  }
  let channel;
  try { channel = new BroadcastChannel('vulnscan-payment-return-v1'); }
  catch {
    if (data.role === 'return') setTriggerValue('unavailable', true);
    return;
  }
  let retry, timeout;
  const nonce = crypto.randomUUID();
  if (data.role === 'source') {
    channel.onmessage = ({data: msg}) => {
      if (msg?.type !== 'return' || msg.checkout !== data.checkout || typeof msg.nonce !== 'string') return;
      // This listener is mounted only in the already authenticated tab.
      // Matching a Checkout can focus that tab; it never authenticates another.
      setTriggerValue('returned', msg.nonce);
      // WindowProxy.focus/close are permitted across origins. No parent DOM
      // reads, navigation or changes to iframe sandbox restrictions.
      try { window.top.focus(); } catch { /* Browser may deny focus. */ }
      channel.postMessage({type: 'ack', checkout: data.checkout, nonce: msg.nonce});
    };
  } else if (data.role === 'return') {
    const notify = () => channel.postMessage({type: 'return', checkout: data.checkout, nonce});
    channel.onmessage = ({data: msg}) => {
      if (msg?.type !== 'ack' || msg.checkout !== data.checkout || msg.nonce !== nonce) return;
      clearInterval(retry); clearTimeout(timeout);
      setTriggerValue('resumed', true);
      // Checkout was opened by script. If the browser refuses to close it,
      // the UI tells the user to continue in the original authenticated tab.
      try { window.top.close(); } catch { /* The fallback stays visible. */ }
    };
    notify();
    retry = setInterval(notify, 500);
    timeout = setTimeout(() => {
      clearInterval(retry);
      setTriggerValue('unavailable', true);
    }, 5000);
  }
  return () => {clearInterval(retry); clearTimeout(timeout); channel.close();};
}
