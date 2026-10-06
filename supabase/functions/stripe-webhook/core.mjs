// No clients, secrets or network operations at import. Also runs in offline Node tests.
export async function verifySignature(body, header, secret, now = Date.now() / 1000) {
  if (!secret || !header) return false;
  const parts = header.split(',').map(part => part.trim().split('='));
  const timestamps = parts.filter(([key]) => key === 't');
  if (timestamps.length !== 1 || !/^\d+$/.test(timestamps[0][1])) return false;
  const timestamp = timestamps[0][1];
  if (Math.abs(now - Number(timestamp)) > 300) return false;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
    {name: 'HMAC', hash: 'SHA-256'}, false, ['verify']);
  const payload = new TextEncoder().encode(`${timestamp}.${body}`);
  for (const [name, hex] of parts) {
    if (name !== 'v1' || !/^[a-fA-F0-9]{64}$/.test(hex)) continue;
    const bytes = Uint8Array.from(hex.match(/../g), pair => parseInt(pair, 16));
    if (await crypto.subtle.verify('HMAC', key, bytes, payload)) return true;
  }
  return false;
}

const supported = new Set(['checkout.session.completed', 'checkout.session.async_payment_succeeded',
  'customer.subscription.created', 'customer.subscription.updated', 'customer.subscription.deleted',
  'customer.subscription.paused', 'customer.subscription.resumed',
  'invoice.paid', 'invoice.payment_succeeded', 'invoice.payment_failed', 'invoice.payment_action_required']);
const idOf = value => typeof value === 'string' ? value : value?.id;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function subscriptionState(sub, catalog, now) {
  if (!sub.id || !idOf(sub.customer) || !Number.isSafeInteger(sub.created))
    throw new Error('Missing subscription identity');
  const items = sub.items?.data || [];
  if (items.length !== 1 || items[0].quantity !== 1) throw new Error('Invalid subscription items');
  const item = items[0];
  const entry = Object.values(catalog).find(c => c.mode === 'subscription' && c.price === idOf(item.price));
  if (!entry || !item.price?.recurring) throw new Error('Unknown recurring price');
  const end = sub.current_period_end ?? item.current_period_end;
  if (!Number.isSafeInteger(end)) throw new Error('Missing billing period');
  const entitled = sub.status === 'active' && sub.latest_invoice?.paid === true && end > now;
  return {subscription_id: sub.id, customer_id: idOf(sub.customer),
    subscription_created: sub.created, status: sub.status,
    plan: entitled ? entry.plan : 'Basic', period_end: end,
    cancel_at_period_end: Boolean(sub.cancel_at_period_end)};
}

export async function processEvent(event, {stripe, store, catalog, liveMode = false, now = () => Date.now() / 1000}) {
  if (!event?.id || !Number.isSafeInteger(event.created) || event.livemode !== liveMode)
    throw new Error('Invalid event or mode');
  if (!supported.has(event.type)) return {ignored: true};
  const object = event.data?.object;
  if (!object?.id) throw new Error('Missing event object');
  let session, subId, owner;
  if (event.type.startsWith('checkout.session.')) {
    session = await stripe.session(object.id);
    owner = session.metadata?.user_id;
    subId = idOf(session.subscription);
  } else if (event.type.startsWith('customer.subscription.')) {
    subId = object.id;
  } else {
    subId = idOf(object.subscription ?? object.parent?.subscription_details?.subscription);
    if (!subId) return {ignored: true};
  }
  if (subId) {
    const sub = await stripe.subscription(subId);
    if (owner && owner !== sub.metadata?.user_id) throw new Error('Owner mismatch');
    owner = sub.metadata?.user_id;
  }
  if (!uuid.test(owner || '')) throw new Error('Missing trusted user identity; reconcile legacy account');
  const claim = await store.claim(owner, event.id);
  if (claim.duplicate) return {duplicate: true};
  if (!claim.token) throw new Error('Billing account busy; retry');
  try {
    const update = {user_id: owner, event_id: event.id, event_created: event.created,
      token: claim.token, checkout_id: null, credit: null, subscription: null, customer_id: null};
    // Read canonical state AFTER acquiring the account lease, never old event snapshots.
    if (session) {
      session = await stripe.session(object.id);
      if (session.livemode !== liveMode || session.metadata?.user_id !== owner)
        throw new Error('Checkout identity/mode mismatch');
      if (session.status !== 'complete' || session.payment_status !== 'paid') {
        await store.release(owner, claim.token);
        return {pending: true};
      }
      const lines = session.line_items?.data || [];
      if (lines.length !== 1 || session.line_items?.has_more || lines[0].quantity !== 1)
        throw new Error('Invalid Checkout items');
      const entry = catalog[session.metadata?.tipo];
      const price = lines[0].price;
      if (!entry || entry.price !== idOf(price) || entry.mode !== session.mode)
        throw new Error('Unknown Checkout price or mode');
      if (session.mode === 'payment' && (price?.recurring || !entry.credit))
        throw new Error('Invalid one-off price');
      if (session.mode === 'payment' &&
          (!Number.isSafeInteger(price.unit_amount) || price.unit_amount <= 0 ||
           session.amount_total !== price.unit_amount || session.currency !== price.currency))
        throw new Error('Invalid paid amount/currency');
      update.checkout_id = session.id;
      update.customer_id = idOf(session.customer);
      if (!update.customer_id) throw new Error('Missing customer');
      if (session.mode === 'payment') update.credit = entry.credit;
      else if (!subId || idOf(session.subscription) !== subId) throw new Error('Subscription mismatch');
    }
    if (subId) {
      const sub = await stripe.subscription(subId);
      if (sub.livemode !== liveMode || sub.metadata?.user_id !== owner)
        throw new Error('Subscription identity/mode mismatch');
      update.subscription = subscriptionState(sub, catalog, now());
      if (update.customer_id && update.customer_id !== update.subscription.customer_id)
        throw new Error('Customer mismatch');
      update.customer_id = update.subscription.customer_id;
    }
    return await store.apply(update);
  } catch (error) {
    await store.release(owner, claim.token).catch(() => {});
    throw error;
  }
}

export function stripeReader(secret, fetcher = fetch) {
  async function get(path) {
    const response = await fetcher(`https://api.stripe.com/v1/${path}`, {
      headers: {Authorization: `Bearer ${secret}`, 'Stripe-Version': '2025-03-31.basil'},
      signal: AbortSignal.timeout(15000)});
    if (!response.ok) throw new Error('Stripe read failed');
    return response.json();
  }
  return {
    session: id => get(`checkout/sessions/${encodeURIComponent(id)}?expand[]=line_items.data.price`),
    subscription: id => get(`subscriptions/${encodeURIComponent(id)}?expand[]=latest_invoice`),
  };
}
