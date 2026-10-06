import test from 'node:test';
import assert from 'node:assert/strict';
import {createHmac, randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {verifySignature, processEvent, subscriptionState, stripeReader} from '../supabase/functions/stripe-webhook/core.mjs';

globalThis.fetch = async () => { throw new Error('Network forbidden in tests'); };
const user = '11111111-1111-4111-8111-111111111111';
const catalog = JSON.parse(readFileSync(new URL('../supabase/functions/_shared/billing_catalog.json', import.meta.url)));
const now = 1800000000;
function event(id, type = 'checkout.session.completed', object = {id: 'cs_test'}, created = now) {
  return {id, type, created, livemode: false, data: {object}};
}
function session(type = 'pdf_unico', id = 'cs_test') {
  const entry = catalog[type];
  return {id, livemode: false, customer: 'cus_test', metadata: {user_id: user, tipo: type},
    status: 'complete', payment_status: 'paid', mode: entry.mode, amount_total: 999, currency: 'eur',
    subscription: entry.mode === 'subscription' ? 'sub_test' : null,
    line_items: {data: [{quantity: 1, price: {id: entry.price, unit_amount: 999, currency: 'eur',
      recurring: entry.mode === 'subscription' ? {interval: 'month'} : null}}]}};
}
function subscription(overrides = {}) {
  return {id: 'sub_test', customer: 'cus_test', livemode: false, created: now - 100,
    metadata: {user_id: user}, status: 'active', cancel_at_period_end: false,
    latest_invoice: {paid: true}, items: {data: [{quantity: 1, current_period_end: now + 1000,
      price: {id: catalog.pro_recurrente.price, recurring: {interval: 'month'}}}]}, ...overrides};
}

// In-memory RPC contract simulator, NOT a PostgreSQL/RLS test.
class Store {
  events = new Set(); purchases = new Set(); tokens = 0; account = {}; lease = null;
  fail = false;
  async claim(owner, id) {
    if (this.events.has(id)) return {duplicate: true};
    if (this.lease) return {busy: true};
    this.lease = randomUUID();
    return {token: this.lease};
  }
  async release(owner, token) { if (this.lease === token) this.lease = null; }
  async apply(update) {
    assert.equal(update.token, this.lease);
    if (this.fail) throw new Error('Database failed before commit');
    if (this.account.customer_id && this.account.customer_id !== update.customer_id)
      throw new Error('Customer mismatch');
    const granted = update.credit && !this.purchases.has(update.checkout_id);
    const sub = update.subscription;
    if (sub && (!this.account.subscription_id || sub.subscription_id === this.account.subscription_id ||
      sub.subscription_created > this.account.subscription_created)) Object.assign(this.account, sub);
    this.account.customer_id = update.customer_id;
    if (update.checkout_id) this.purchases.add(update.checkout_id);
    if (granted) this.tokens++;
    this.events.add(update.event_id); this.lease = null;
    return {applied: true, credited: Boolean(granted)};
  }
}
function fixture() {
  const store = new Store();
  const data = {session: session(), sub: subscription()};
  const deps = {store, catalog, now: () => now, liveMode: false, stripe: {
    session: async id => structuredClone({...data.session, id}),
    subscription: async () => structuredClone(data.sub)}};
  return {store, data, deps};
}

test('signature: valid, rotated v1, invalid, expired, future and tampered body', async () => {
  const body = '{"id":"evt_test"}';
  const sign = time => createHmac('sha256', 'test_secret').update(`${time}.${body}`).digest('hex');
  assert.equal(await verifySignature(body, `t=${now},v1=${sign(now)}`, 'test_secret', now), true);
  assert.equal(await verifySignature(body, `t=${now},v1=${'0'.repeat(64)},v1=${sign(now)}`, 'test_secret', now), true);
  for (const time of [now - 301, now + 301])
    assert.equal(await verifySignature(body, `t=${time},v1=${sign(time)}`, 'test_secret', now), false);
  assert.equal(await verifySignature(body + ' ', `t=${now},v1=${sign(now)}`, 'test_secret', now), false);
  assert.equal(await verifySignature(body, `t=${now},t=${now},v1=${sign(now)}`, 'test_secret', now), false);
  assert.equal(await verifySignature(body, '', 'test_secret', now), false);
});

test('duplicate event and different events for same Checkout credit only once', async () => {
  const {store, deps} = fixture();
  await processEvent(event('evt_1'), deps);
  assert.deepEqual(await processEvent(event('evt_1'), deps), {duplicate: true});
  await processEvent(event('evt_2', 'checkout.session.async_payment_succeeded'), deps);
  assert.equal(store.tokens, 1); assert.equal(store.events.size, 2);
});

test('simultaneous deliveries retry busy accounts without losing or duplicating grants', async () => {
  const {store, deps} = fixture();
  const events = Array.from({length: 12}, (_, i) => event(`evt_${i}`, undefined, {id: `cs_${i % 4}`}));
  const outcomes = await Promise.allSettled(events.map(e => processEvent(e, deps)));
  assert.ok(outcomes.some(o => o.status === 'rejected'));
  for (let i = 0; i < events.length; i++)
    if (outcomes[i].status === 'rejected') await processEvent(events[i], deps);
  assert.equal(store.tokens, 4); assert.equal(store.events.size, 12);
});

test('unpaid Checkout is pending, then async payment grants', async () => {
  const {store, deps, data} = fixture();
  data.session.payment_status = 'unpaid';
  assert.deepEqual(await processEvent(event('evt_1'), deps), {pending: true});
  assert.equal(store.tokens, 0); assert.equal(store.events.size, 0);
  data.session.payment_status = 'paid';
  await processEvent(event('evt_2', 'checkout.session.async_payment_succeeded'), deps);
  assert.equal(store.tokens, 1);
});

test('unknown prices, quantity, currency, amount and identity never grant', async () => {
  const changes = [s => s.line_items.data[0].price.id = 'price_unknown',
    s => s.line_items.data[0].quantity = 2, s => s.currency = 'usd',
    s => s.amount_total = 1, s => s.metadata.user_id = undefined,
    s => s.mode = 'subscription', s => s.livemode = true];
  for (const change of changes) {
    const {store, deps, data} = fixture(); change(data.session);
    await assert.rejects(processEvent(event('evt_bad'), deps));
    assert.equal(store.tokens, 0); assert.equal(store.events.size, 0);
  }
});

test('failure before commit releases lease and retry grants exactly once', async () => {
  const {store, deps} = fixture(); store.fail = true;
  await assert.rejects(processEvent(event('evt_1'), deps));
  assert.equal(store.tokens, 0); assert.equal(store.events.size, 0); assert.equal(store.lease, null);
  store.fail = false;
  await processEvent(event('evt_1'), deps);
  assert.equal(store.tokens, 1);
});

test('purchase, paid renewal, failed renewal, recovery, cancel at period end and deletion', async () => {
  const {store, deps, data} = fixture(); data.session = session('pro_recurrente');
  await processEvent(event('evt_checkout'), deps);
  assert.equal(store.account.plan, 'Pro'); assert.equal(store.account.subscription_id, 'sub_test');
  data.sub.items.data[0].current_period_end = now + 2000;
  await processEvent(event('evt_renew', 'invoice.paid', {id: 'in_test', parent: {subscription_details: {subscription: 'sub_test'}}}), deps);
  assert.equal(store.account.period_end, now + 2000);
  data.sub.status = 'past_due'; data.sub.latest_invoice.paid = false;
  await processEvent(event('evt_failed', 'invoice.payment_failed', {id: 'in_test', subscription: 'sub_test'}), deps);
  assert.equal(store.account.plan, 'Basic');
  data.sub.status = 'active'; data.sub.latest_invoice.paid = true;
  data.sub.cancel_at_period_end = true;
  await processEvent(event('evt_cancel', 'customer.subscription.updated', {id: 'sub_test'}), deps);
  assert.equal(store.account.plan, 'Pro'); assert.equal(store.account.cancel_at_period_end, true);
  data.sub.status = 'canceled';
  await processEvent(event('evt_deleted', 'customer.subscription.deleted', {id: 'sub_test'}), deps);
  assert.equal(store.account.plan, 'Basic'); assert.equal(store.tokens, 0);
});

test('out of order update cannot restore canceled subscription, including equal timestamps', async () => {
  const {store, deps, data} = fixture(); data.sub.status = 'canceled';
  await processEvent(event('evt_deleted', 'customer.subscription.deleted', {id: 'sub_test'}, now), deps);
  for (const timestamp of [now - 3000, now]) {
    await processEvent(event(`evt_old_${timestamp}`, 'customer.subscription.updated',
      {id: 'sub_test', status: 'active'}, timestamp), deps);
    assert.equal(store.account.plan, 'Basic');
  }
});

test('older subscription event cannot replace newer subscription', async () => {
  const {store, deps, data} = fixture();
  data.sub = subscription({id: 'sub_new', created: now});
  await processEvent(event('evt_new', 'customer.subscription.updated', {id: 'sub_new'}), deps);
  data.sub = subscription({status: 'canceled'});
  await processEvent(event('evt_old', 'customer.subscription.deleted', {id: 'sub_test'}), deps);
  assert.equal(store.account.subscription_id, 'sub_new'); assert.equal(store.account.plan, 'Pro');
});

test('canonical snapshot is read again after claim', async () => {
  const {store, deps, data} = fixture();
  const claim = store.claim.bind(store);
  store.claim = async (...args) => { data.sub.status = 'canceled'; return claim(...args); };
  await processEvent(event('evt_1', 'customer.subscription.updated', {id: 'sub_test'}), deps);
  assert.equal(store.account.plan, 'Basic');
});

test('expired period and unpaid active subscription never grant premium access', () => {
  assert.equal(subscriptionState(subscription({current_period_end: now - 1}), catalog, now).plan, 'Basic');
  assert.equal(subscriptionState(subscription({latest_invoice: {paid: false}}), catalog, now).plan, 'Basic');
});

test('legacy email alone and live events are rejected', async () => {
  const {deps, data, store} = fixture();
  data.sub.metadata = {email: 'a@example.test'};
  await assert.rejects(processEvent(event('evt_legacy', 'customer.subscription.updated', {id: 'sub_test'}), deps));
  await assert.rejects(processEvent({...event('evt_live'), livemode: true}, deps));
  assert.equal(store.events.size, 0);
});

test('Stripe read adapter uses only fixed host and handles errors with mocked fetch', async () => {
  const calls = [];
  const reader = stripeReader('sk_test_fake', async (url, options) => {
    calls.push({url, options}); return {ok: true, json: async () => ({id: 'test'})};
  });
  await reader.session('cs_test'); await reader.subscription('sub_test');
  assert.ok(calls.every(call => call.url.startsWith('https://api.stripe.com/v1/')));
  await assert.rejects(stripeReader('fake', async () => ({ok: false})).session('cs_test'));
});

test('all one-off products use validated catalog and Enterprise subscription is assigned', async () => {
  for (const type of ['pdf_unico', 'pro_unico', 'enterprise_unico']) {
    const {store, deps, data} = fixture(); data.session = session(type);
    let applied;
    const apply = store.apply.bind(store);
    store.apply = async update => { applied = update; return apply(update); };
    await processEvent(event('evt_product'), deps);
    assert.equal(applied.credit, catalog[type].credit); assert.equal(store.tokens, 1);
  }
  const {store, deps, data} = fixture();
  data.session = session('enterprise_recurrente');
  data.sub.items.data[0].price.id = catalog.enterprise_recurrente.price;
  await processEvent(event('evt_enterprise'), deps);
  assert.equal(store.account.plan, 'Enterprise');
});

test('superseded lease cannot commit and cannot release newer worker lease', async () => {
  const {store, deps} = fixture();
  const apply = store.apply.bind(store);
  store.apply = async update => { store.lease = 'new-worker-token'; return apply(update); };
  await assert.rejects(processEvent(event('evt_1'), deps));
  assert.equal(store.lease, 'new-worker-token'); assert.equal(store.tokens, 0);
  assert.equal(store.events.size, 0);
});
